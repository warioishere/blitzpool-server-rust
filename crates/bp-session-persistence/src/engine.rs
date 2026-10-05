// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine handle exposing the hook impls and their background flush loops.
//! Nothing writes a statement per event: row births are debounced and every
//! share-path write is batched, because a statement per share would dominate
//! the DB write budget.

use std::sync::Arc;

use sqlx::PgPool;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::warn;

use redis::aio::ConnectionManager;

use crate::config::SessionPersistenceConfig;
use crate::error::SessionPersistenceError;
use crate::hooks::{ClientRowTouchSink, SessionPersistenceHook};
use crate::live_store::LiveSessionStore;
use crate::row_debounce::{run_birth_loop, RowDebounce};
use crate::touch_buffer::{run_flush_loop, TouchBuffer};

pub struct SessionPersistenceEngine {
    pool: PgPool,
    config: SessionPersistenceConfig,
    touch_buffer: Arc<TouchBuffer>,
    row_debounce: Arc<RowDebounce>,
    live_store: Option<Arc<LiveSessionStore>>,
}

impl SessionPersistenceEngine {
    /// Build the engine without spawning a background task ([`Self::spawn`]
    /// is the production path). Without `redis` the live session stats are
    /// dropped with a warning rather than buffered unboundedly.
    pub fn new(
        config: SessionPersistenceConfig,
        pool: PgPool,
        redis: Option<ConnectionManager>,
    ) -> Result<Self, SessionPersistenceError> {
        config.validate()?;
        if redis.is_none() {
            warn!(
                "session-persistence: no Redis handle — live session stats will not be published"
            );
        }
        let live_store = redis.map(|conn| Arc::new(LiveSessionStore::new(conn, config.live_ttl)));
        Ok(Self {
            pool,
            config,
            touch_buffer: Arc::new(TouchBuffer::default()),
            row_debounce: Arc::new(RowDebounce::default()),
            live_store,
        })
    }

    /// Build the engine and spawn its background loops.
    pub async fn spawn(
        config: SessionPersistenceConfig,
        pool: PgPool,
        redis: Option<ConnectionManager>,
    ) -> Result<SessionPersistenceEngineHandle, SessionPersistenceError> {
        let engine = Self::new(config, pool, redis)?;
        Ok(engine.spawn_internal())
    }

    /// Construct a handle without the background task (tests).
    pub fn into_handle(self) -> SessionPersistenceEngineHandle {
        SessionPersistenceEngineHandle {
            pool: self.pool,
            touch_buffer: self.touch_buffer,
            row_debounce: self.row_debounce,
            row_debounce_age: self.config.row_debounce,
            live_store: self.live_store,
            shutdown: Arc::new(std::sync::Mutex::new(ShutdownState::default())),
        }
    }

    fn spawn_internal(self) -> SessionPersistenceEngineHandle {
        let (birth_tx, birth_rx) = oneshot::channel();
        let birth_join = tokio::spawn(run_birth_loop(
            self.row_debounce.clone(),
            self.pool.clone(),
            self.config.row_debounce,
            self.config.row_flush_interval,
            birth_rx,
        ));

        let (touch_tx, touch_rx) = oneshot::channel();
        let touch_join = tokio::spawn(run_flush_loop(
            self.touch_buffer.clone(),
            self.pool.clone(),
            self.live_store.clone(),
            self.config.touch_flush_interval,
            touch_rx,
        ));

        SessionPersistenceEngineHandle {
            pool: self.pool,
            touch_buffer: self.touch_buffer,
            row_debounce: self.row_debounce,
            row_debounce_age: self.config.row_debounce,
            live_store: self.live_store,
            shutdown: Arc::new(std::sync::Mutex::new(ShutdownState {
                txs: vec![birth_tx, touch_tx],
                joins: vec![birth_join, touch_join],
            })),
        }
    }
}

/// Behind a `Mutex` so the handle stays `Clone`; only the first
/// `shutdown()` signals and joins.
#[derive(Default)]
struct ShutdownState {
    txs: Vec<oneshot::Sender<()>>,
    joins: Vec<JoinHandle<()>>,
}

/// Shared handle cloned into the SV1/SV2 server hooks. The row debounce is
/// not drained on shutdown: its pending sessions die with the sockets.
#[derive(Clone)]
pub struct SessionPersistenceEngineHandle {
    pool: PgPool,
    touch_buffer: Arc<TouchBuffer>,
    row_debounce: Arc<RowDebounce>,
    row_debounce_age: Duration,
    live_store: Option<Arc<LiveSessionStore>>,
    shutdown: Arc<std::sync::Mutex<ShutdownState>>,
}

impl SessionPersistenceEngineHandle {
    /// Hook for `ServerHooks::session_persistence`; all clones share one
    /// debounce, so SV1 and SV2 sessions pend into the same map.
    pub fn session_persistence_hook(&self) -> SessionPersistenceHook {
        SessionPersistenceHook::new(self.pool.clone(), self.row_debounce.clone())
    }

    /// One birth pass over every pending session, debounce age ignored
    /// (deterministic drain for tests).
    pub async fn flush_births_now(&self) -> u64 {
        crate::row_debounce::flush_once(&self.row_debounce, &self.pool, Duration::ZERO).await
    }

    /// Number of sessions currently pending birth.
    pub fn pending_births(&self) -> usize {
        self.row_debounce.pending_len()
    }

    /// One birth pass honouring the debounce age, exactly like a tick.
    pub async fn flush_due_births(&self) -> u64 {
        crate::row_debounce::flush_once(&self.row_debounce, &self.pool, self.row_debounce_age).await
    }

    /// One touch-flush pass (row bests + `client:live:*` hashes), exactly like a tick.
    pub async fn flush_touches_now(&self) -> u64 {
        crate::touch_buffer::flush_once(&self.touch_buffer, &self.pool, self.live_store.as_deref())
            .await
    }

    /// Hook that touches the session's `client:live:*` hash on every
    /// accepted share, buffered until the next touch flush.
    pub fn client_row_touch_sink(&self) -> ClientRowTouchSink {
        ClientRowTouchSink::new(self.touch_buffer.clone())
    }

    /// Signal every loop and join them; idempotent across handle clones.
    pub async fn shutdown(&self) {
        let (txs, joins) = {
            let mut guard = match self.shutdown.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            (
                std::mem::take(&mut guard.txs),
                std::mem::take(&mut guard.joins),
            )
        };
        // Signal all first so the loops drain concurrently.
        for tx in txs {
            let _ = tx.send(());
        }
        for join in joins {
            if let Err(e) = join.await {
                warn!(error = %e, "session-persistence background task panicked");
            }
        }
    }
}
