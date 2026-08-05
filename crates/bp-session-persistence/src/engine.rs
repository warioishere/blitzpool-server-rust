// SPDX-License-Identifier: AGPL-3.0-or-later

//! Composite handle exposing the hook impls + the buffered share-touch
//! flusher.
//!
//! `SessionPersistenceHook` (authorize/disconnect) writes through
//! synchronously — one statement per connection event, nothing to batch.
//! Everything on the SHARE path is buffered, because at ~250 shares/s a
//! statement per share dominates the DB write budget:
//!
//! - [`TouchBuffer`] → one bulk `UPDATE client_entity … FROM unnest(...)`
//!   every `touch_flush_interval` (default 30 s).
//! - [`HashrateSampler`] → one bulk `UPDATE client_entity` per
//!   `hashrate_sample_interval` (default 60 s).
//! - [`DiffStatBuffer`] → one bulk upsert into
//!   `client_difficulty_statistics_entity` every
//!   `diff_stat_flush_interval` (default 30 s). Batched since 2026-08-05;
//!   the inline version burst at every restart and hour rollover.

use std::sync::Arc;

use sqlx::PgPool;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::warn;

use crate::config::SessionPersistenceConfig;
use crate::diff_stat_buffer::{run_flush_loop as run_diff_stat_flush_loop, DiffStatBuffer};
use crate::error::SessionPersistenceError;
use crate::hashrate_sampler::{run_sample_loop, HashrateSampler};
use crate::hooks::{ClientDifficultyStatisticsSink, ClientRowTouchSink, SessionPersistenceHook};
use crate::touch_buffer::{run_flush_loop, TouchBuffer};

pub struct SessionPersistenceEngine {
    pool: PgPool,
    config: SessionPersistenceConfig,
    touch_buffer: Arc<TouchBuffer>,
    hashrate_sampler: Arc<HashrateSampler>,
    diff_stat_buffer: Arc<DiffStatBuffer>,
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
            config,
            touch_buffer: Arc::new(TouchBuffer::default()),
            hashrate_sampler: Arc::new(HashrateSampler::default()),
            diff_stat_buffer: Arc::new(DiffStatBuffer::default()),
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
            touch_buffer: self.touch_buffer,
            hashrate_sampler: self.hashrate_sampler,
            diff_stat_buffer: self.diff_stat_buffer,
            shutdown: Arc::new(std::sync::Mutex::new(ShutdownState::default())),
        }
    }

    fn spawn_internal(self) -> SessionPersistenceEngineHandle {
        // Three background loops: the 30s touch-buffer flush, the 60s
        // live-hashrate sampler, and the 30s diff-stat flush. Each gets its
        // own shutdown channel; the handle joins all of them on `shutdown()`.
        let (touch_tx, touch_rx) = oneshot::channel();
        let touch_join = tokio::spawn(run_flush_loop(
            self.touch_buffer.clone(),
            self.pool.clone(),
            self.config.touch_flush_interval,
            touch_rx,
        ));

        let (sampler_tx, sampler_rx) = oneshot::channel();
        let sampler_join = tokio::spawn(run_sample_loop(
            self.hashrate_sampler.clone(),
            self.pool.clone(),
            self.config.hashrate_sample_interval,
            self.config.reconcile_hashrate_on_boot,
            sampler_rx,
        ));

        let (diff_tx, diff_rx) = oneshot::channel();
        let diff_join = tokio::spawn(run_diff_stat_flush_loop(
            self.diff_stat_buffer.clone(),
            self.pool.clone(),
            self.config.diff_stat_flush_interval,
            diff_rx,
        ));

        SessionPersistenceEngineHandle {
            pool: self.pool,
            touch_buffer: self.touch_buffer,
            hashrate_sampler: self.hashrate_sampler,
            diff_stat_buffer: self.diff_stat_buffer,
            shutdown: Arc::new(std::sync::Mutex::new(ShutdownState {
                txs: vec![touch_tx, sampler_tx, diff_tx],
                joins: vec![touch_join, sampler_join, diff_join],
            })),
        }
    }
}

/// Shutdown plumbing held behind a `Mutex` so the handle can stay
/// `Clone` (the SV1 and SV2 servers each clone the handle into their
/// hook wiring at startup). Only the first `shutdown()` actually
/// signals + joins; subsequent calls are no-ops. Holds one entry per
/// background loop (touch flush + hashrate sampler + diff-stat flush).
#[derive(Default)]
struct ShutdownState {
    txs: Vec<oneshot::Sender<()>>,
    joins: Vec<JoinHandle<()>>,
}

/// Shared handle. `bin/blitzpool` clones it into the SV1 / SV2 server
/// hooks at startup. Implements `shutdown()` — calling it on any clone
/// drains the touch buffer once and joins the flush task.
#[derive(Clone)]
pub struct SessionPersistenceEngineHandle {
    pool: PgPool,
    touch_buffer: Arc<TouchBuffer>,
    hashrate_sampler: Arc<HashrateSampler>,
    diff_stat_buffer: Arc<DiffStatBuffer>,
    shutdown: Arc<std::sync::Mutex<ShutdownState>>,
}

impl SessionPersistenceEngineHandle {
    /// Hook impl for `bp_stratum_v1::SessionPersistence`. Wire into
    /// `ServerHooks::session_persistence`.
    pub fn session_persistence_hook(&self) -> SessionPersistenceHook {
        SessionPersistenceHook::new(self.pool.clone())
    }

    /// Hook impl that touches the per-session `client_entity` row on
    /// every accepted share. Writes are buffered and flushed every
    /// `touch_flush_interval` (default 30s) by the engine's background
    /// task.
    pub fn client_row_touch_sink(&self) -> ClientRowTouchSink {
        ClientRowTouchSink::new(self.touch_buffer.clone(), self.hashrate_sampler.clone())
    }

    /// Hook impl that records the per-`(address, worker, hour-slot)` max
    /// share difficulty for the diff-scores chart. Buffered and flushed by
    /// the engine's background task every `diff_stat_flush_interval`.
    pub fn client_difficulty_statistics_sink(&self) -> ClientDifficultyStatisticsSink {
        ClientDifficultyStatisticsSink::new(self.diff_stat_buffer.clone())
    }

    /// Signal the flush loop, wait for the final drain, and join the
    /// task. Idempotent across handle clones — only the first call
    /// actually signals; subsequent calls are no-ops.
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
        // Signal all loops first, then await each — so they drain
        // concurrently rather than serially.
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
