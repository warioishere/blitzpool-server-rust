// SPDX-License-Identifier: AGPL-3.0-or-later

//! Top-level coordinator: spawn background flush task, expose
//! [`ReaderView`] for the API surface, propagate shutdown.

use std::sync::Arc;
use std::time::Duration;

use bp_stats::{FlushHealthMonitor, TimeSlot};
use sqlx::PgPool;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, info, instrument, warn};

use crate::config::StatsSinkConfig;
use crate::error::SinkError;
use crate::flush::{flush_once, Accumulators, Flusher};
use crate::reader::ReaderView;
use crate::seed::seed_if_empty;

/// Shared state. The accumulators are mutated by the share-path hooks
/// from many threads (Stratum-server tasks); the health monitor is
/// updated by the cron task only. Both live behind `Arc` so the
/// `ReaderView` can borrow without touching the engine handle.
pub struct ShareStatsEngine {
    config: StatsSinkConfig,
    pool: PgPool,
    accumulators: Arc<Accumulators>,
    health: Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
}

impl ShareStatsEngine {
    /// Build the engine WITHOUT starting the cron task. Hook impls can
    /// be wired up against the returned engine; call
    /// [`Self::spawn`] when the share path is ready.
    pub fn new(config: StatsSinkConfig, pool: PgPool) -> Result<Self, SinkError> {
        config.validate()?;
        Ok(Self {
            config,
            pool,
            accumulators: Arc::new(Accumulators::default()),
            health: Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default())),
        })
    }

    /// Construct the engine and spawn the background flush task. Runs
    /// the one-shot `seedIfEmpty` migration on entry if
    /// `config.seed_on_spawn` is true. Returns a handle whose
    /// [`ShareStatsEngineHandle::shutdown`] drains residuals before
    /// stopping.
    #[instrument(skip(pool), fields(flush_interval = ?config.flush_interval), name = "stats_sink.spawn")]
    pub async fn spawn(
        config: StatsSinkConfig,
        pool: PgPool,
    ) -> Result<ShareStatsEngineHandle, SinkError> {
        let engine = Self::new(config, pool)?;
        if engine.config.seed_on_spawn {
            if let Some(rows) = seed_if_empty(&engine.pool).await? {
                debug!(rows, "stats_sink: seed_if_empty bootstrapped worker_shares");
            }
        }
        Ok(engine.spawn_internal())
    }

    /// Cheap-to-clone read-only handle.
    pub fn reader(&self) -> ReaderView {
        ReaderView {
            accumulators: self.accumulators.clone(),
            health: self.health.clone(),
        }
    }

    /// Public accessor for the shared accumulators — hook impls clone
    /// this `Arc` into the share path.
    pub fn accumulators(&self) -> Arc<Accumulators> {
        self.accumulators.clone()
    }

    fn spawn_internal(self) -> ShareStatsEngineHandle {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let pool = self.pool.clone();
        let accs = self.accumulators.clone();
        let health = self.health.clone();
        let reader = self.reader();
        let cfg = self.config.clone();

        let join = tokio::spawn(run_flush_loop(pool, accs, health, cfg, shutdown_rx));

        ShareStatsEngineHandle {
            reader,
            shutdown_tx: Some(shutdown_tx),
            join: Some(join),
        }
    }
}

/// Handle returned by [`ShareStatsEngine::spawn`]. Drop to abort the
/// task without final-drain; call [`Self::shutdown`] for a clean stop
/// that flushes residuals before returning.
pub struct ShareStatsEngineHandle {
    reader: ReaderView,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl ShareStatsEngineHandle {
    pub fn reader(&self) -> ReaderView {
        self.reader.clone()
    }

    pub fn accumulators(&self) -> Arc<Accumulators> {
        self.reader.accumulators.clone()
    }

    /// Signal shutdown and await final drain. Returns when the
    /// background task has flushed residuals and exited.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            if let Err(e) = join.await {
                warn!(error = %e, "stats sink flush task panicked");
            }
        }
    }
}

#[instrument(skip_all, name = "stats_sink.flush_loop")]
async fn run_flush_loop(
    pool: PgPool,
    accs: Arc<Accumulators>,
    health: Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
    cfg: StatsSinkConfig,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    info!("stats_sink flush loop started");
    let start = tokio::time::Instant::now() + cfg.flush_interval + cfg.startup_offset;
    let mut ticker = tokio::time::interval_at(start, cfg.flush_interval);
    // `interval_at` with `start = now + flush_interval + offset` skips
    // the t=0 firing AND staggers the loop relative to other 60 s crons
    // so PG / disk load doesn't all hit on the same instant.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut last_slot = TimeSlot::current();
    loop {
        // Slot-aligned spot flush: if the slot changed since the last
        // wake-up, flush immediately so the just-ended slot's residuals
        // commit before the chart-visibility cutoff.
        if cfg.slot_aligned_flush {
            let current = TimeSlot::current();
            if current != last_slot {
                debug!(prev = ?last_slot, current = ?current, "slot transition — spot flush");
                flush_once(&pool, &accs, &health, cfg.client_stats_batch_size).await;
                last_slot = current;
                continue;
            }
        }

        tokio::select! {
            _ = ticker.tick() => {
                flush_once(&pool, &accs, &health, cfg.client_stats_batch_size).await;
                last_slot = TimeSlot::current();
            }
            _ = &mut shutdown_rx => {
                debug!("stats_sink received shutdown");
                break;
            }
        }
    }

    // Final drain — flush any residuals before exiting.
    info!("stats_sink final drain");
    flush_once(&pool, &accs, &health, cfg.client_stats_batch_size).await;

    // Brief wait for slot-aligned spot flush window to elapse if a
    // tick was in-flight (defensive, kept short).
    let _ = tokio::time::sleep(Duration::from_millis(10)).await;
}
