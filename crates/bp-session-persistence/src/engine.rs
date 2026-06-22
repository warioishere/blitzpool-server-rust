// SPDX-License-Identifier: AGPL-3.0-or-later

//! Composite handle exposing the cache + the hook impls + the
//! buffered share-touch flusher.
//!
//! `SessionPersistenceHook` (authorize/disconnect), `BestDifficultySink`
//! (per-share best-diff write-through), and `ClientDifficultyStatisticsSink`
//! (per-hour diff samples) all write through synchronously — there's
//! nothing to buffer there. `ClientRowTouchSink` is the exception:
//! every accepted share would otherwise issue one `UPDATE client_entity`
//! statement, which at ~250 shares/s on a busy pool dominates the DB
//! write budget. We collapse those into a [`TouchBuffer`] and flush
//! it every `touch_flush_interval` (default 30 s) via a single bulk
//! `UPDATE … FROM unnest(...)` statement.

use std::sync::Arc;

use sqlx::PgPool;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::warn;

use crate::address_settings_cache::InMemoryAddressSettingsCache;
use crate::config::SessionPersistenceConfig;
use crate::error::SessionPersistenceError;
use crate::hooks::{
    BestDifficultySink, ClientDifficultyStatisticsSink, ClientRowTouchSink, SessionPersistenceHook,
};
use crate::touch_buffer::{run_flush_loop, TouchBuffer};

pub struct SessionPersistenceEngine {
    pool: PgPool,
    cache: Arc<InMemoryAddressSettingsCache>,
    config: SessionPersistenceConfig,
    touch_buffer: Arc<TouchBuffer>,
}

impl SessionPersistenceEngine {
    /// Build the engine without spawning any background task. Use
    /// [`Self::spawn`] for the production path; this is for unit tests
    /// that wire the hooks but don't need the flusher.
    pub fn new(
        config: SessionPersistenceConfig,
        pool: PgPool,
    ) -> Result<Self, SessionPersistenceError> {
        config.validate()?;
        Ok(Self {
            pool,
            cache: Arc::new(InMemoryAddressSettingsCache::new(
                config.address_cache_capacity,
            )),
            config,
            touch_buffer: Arc::new(TouchBuffer::default()),
        })
    }

    /// Build the engine + spawn the touch-buffer flush loop. Returns
    /// a handle whose [`SessionPersistenceEngineHandle::shutdown`]
    /// drains the residual buffer before returning.
    pub async fn spawn(
        config: SessionPersistenceConfig,
        pool: PgPool,
    ) -> Result<SessionPersistenceEngineHandle, SessionPersistenceError> {
        let engine = Self::new(config, pool)?;
        Ok(engine.spawn_internal())
    }

    /// Construct a handle without the background task (tests).
    pub fn into_handle(self) -> SessionPersistenceEngineHandle {
        SessionPersistenceEngineHandle {
            pool: self.pool,
            cache: self.cache,
            touch_buffer: self.touch_buffer,
            shutdown: Arc::new(std::sync::Mutex::new(ShutdownState::default())),
        }
    }

    fn spawn_internal(self) -> SessionPersistenceEngineHandle {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let buffer = self.touch_buffer.clone();
        let pool = self.pool.clone();
        let interval = self.config.touch_flush_interval;
        let join = tokio::spawn(run_flush_loop(buffer, pool, interval, shutdown_rx));

        SessionPersistenceEngineHandle {
            pool: self.pool,
            cache: self.cache,
            touch_buffer: self.touch_buffer,
            shutdown: Arc::new(std::sync::Mutex::new(ShutdownState {
                tx: Some(shutdown_tx),
                join: Some(join),
            })),
        }
    }
}

/// Shutdown plumbing held behind a `Mutex` so the handle can stay
/// `Clone` (the SV1 and SV2 servers each clone the handle into their
/// hook wiring at startup). Only the first `shutdown()` actually
/// signals + joins; subsequent calls are no-ops.
#[derive(Default)]
struct ShutdownState {
    tx: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

/// Shared handle. `bin/blitzpool` clones it into the SV1 / SV2 server
/// hooks at startup. Implements `shutdown()` — calling it on any clone
/// drains the touch buffer once and joins the flush task.
#[derive(Clone)]
pub struct SessionPersistenceEngineHandle {
    pool: PgPool,
    cache: Arc<InMemoryAddressSettingsCache>,
    touch_buffer: Arc<TouchBuffer>,
    shutdown: Arc<std::sync::Mutex<ShutdownState>>,
}

impl SessionPersistenceEngineHandle {
    /// Hook impl for `bp_stratum_v1::SessionPersistence`. Wire into
    /// `ServerHooks::session_persistence`.
    pub fn session_persistence_hook(&self) -> SessionPersistenceHook {
        SessionPersistenceHook::new(self.pool.clone())
    }

    /// Hook impl for `bp_stratum_v1::AcceptedShareSink`. Wire into the
    /// composite alongside `ShareStatsAcceptedSink`,
    /// `PplnsAcceptedShareSink`, etc.
    pub fn best_difficulty_sink(&self) -> BestDifficultySink<InMemoryAddressSettingsCache> {
        BestDifficultySink::new(self.pool.clone(), self.cache.clone())
    }

    /// Hook impl that touches the per-session `client_entity` row on
    /// every accepted share. Writes are buffered and flushed every
    /// `touch_flush_interval` (default 30s) by the engine's background
    /// task.
    pub fn client_row_touch_sink(&self) -> ClientRowTouchSink {
        ClientRowTouchSink::new(self.touch_buffer.clone())
    }

    /// Hook impl that records the per-`(address, worker, hour-slot)` max
    /// share difficulty for the diff-scores chart.
    pub fn client_difficulty_statistics_sink(&self) -> ClientDifficultyStatisticsSink {
        ClientDifficultyStatisticsSink::new(self.pool.clone())
    }

    /// Cache handle — read-only access from the admin endpoints + tests.
    pub fn cache(&self) -> Arc<InMemoryAddressSettingsCache> {
        self.cache.clone()
    }

    /// Signal the flush loop, wait for the final drain, and join the
    /// task. Idempotent across handle clones — only the first call
    /// actually signals; subsequent calls are no-ops.
    pub async fn shutdown(&self) {
        let (tx, join) = {
            let mut guard = match self.shutdown.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            (guard.tx.take(), guard.join.take())
        };
        if let Some(tx) = tx {
            let _ = tx.send(());
        }
        if let Some(join) = join {
            if let Err(e) = join.await {
                warn!(error = %e, "session-persistence touch flush task panicked");
            }
        }
    }
}
