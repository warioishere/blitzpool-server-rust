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
use crate::flush::{flush_once, Accumulators, FlushScope, Flusher};
use crate::reader::ReaderView;
use crate::seed::seed_if_empty;

/// Accumulators are written by the share hooks from many tasks, the health
/// monitor only by the flush task; both sit behind `Arc` for `ReaderView`.
pub struct ShareStatsEngine {
    config: StatsSinkConfig,
    pool: PgPool,
    accumulators: Arc<Accumulators>,
    health: Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
}

impl ShareStatsEngine {
    /// Builds the engine without starting the flush task, so hooks can be
    /// wired first.
    pub fn new(config: StatsSinkConfig, pool: PgPool) -> Self {
        Self {
            config,
            pool,
            accumulators: Arc::new(Accumulators::default()),
            health: Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default())),
        }
    }

    /// Builds the engine, runs `seed_if_empty` when `config.seed_on_spawn`,
    /// and spawns the flush task.
    #[instrument(skip(pool), fields(flush_interval = ?config.flush_interval), name = "stats_sink.spawn")]
    pub async fn spawn(
        config: StatsSinkConfig,
        pool: PgPool,
    ) -> Result<ShareStatsEngineHandle, SinkError> {
        let engine = Self::new(config, pool);
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

    /// Hook impls clone this `Arc` into the share path.
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

/// [`Self::shutdown`] waits for the final drain; dropping the handle only
/// detaches the task, which then drains on its own.
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

    /// Returns once the flush task has drained residuals and exited.
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
    loop {
        let wait = until_next_tick(bp_common::now_ms(), cfg.flush_interval, cfg.tick_offset);
        tokio::select! {
            _ = tokio::time::sleep(wait) => {
                let scope = FlushScope::Before(TimeSlot::current());
                flush_once(&pool, &accs, &health, cfg.client_stats_batch_size, scope).await;
            }
            _ = &mut shutdown_rx => {
                debug!("stats_sink received shutdown");
                break;
            }
        }
    }

    info!("stats_sink final drain");
    flush_once(
        &pool,
        &accs,
        &health,
        cfg.client_stats_batch_size,
        FlushScope::All,
    )
    .await;
}

/// Time until the next tick: `offset` past each wall-clock multiple of
/// `period`. Wall clock, not process start, so an ended slot is written at
/// its end plus `offset` whenever the process came up.
fn until_next_tick(now_ms: i64, period: Duration, offset: Duration) -> Duration {
    let period = (period.as_millis() as i64).max(1);
    let offset = offset.as_millis() as i64 % period;
    let next = (now_ms - offset).div_euclid(period) * period + period + offset;
    Duration::from_millis((next - now_ms) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);
    const OFFSET: Duration = Duration::from_secs(17);

    #[test]
    fn the_tick_lands_offset_past_the_next_minute() {
        let minute = 60_000_i64;
        // On a minute boundary.
        let t0 = 1_790_000_000_000 / minute * minute;
        // Just past the boundary: wait until :17 of this minute.
        assert_eq!(
            until_next_tick(t0 + 1_000, MIN, OFFSET),
            Duration::from_secs(16)
        );
        // Exactly on :17: the tick just fired, the next one is a period away.
        assert_eq!(until_next_tick(t0 + 17_000, MIN, OFFSET), MIN);
        // Past :17: wait into the next minute.
        assert_eq!(
            until_next_tick(t0 + 30_000, MIN, OFFSET),
            Duration::from_secs(47)
        );
    }

    #[test]
    fn an_ended_slot_is_written_inside_the_chart_visibility_buffer() {
        let slot_end = bp_stats::TimeSlot::current().as_millis();
        let wait = until_next_tick(slot_end, MIN, OFFSET);
        assert!(wait < bp_stats::CHART_VISIBILITY_BUFFER, "{wait:?}");
    }
}
