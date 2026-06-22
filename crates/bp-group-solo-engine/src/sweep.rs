// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daily 03:00 UTC group-dust-sweep for `pplns_group_balance`.
//!
//! Single-sided absorption (Group-Solo never goes negative, so no
//! pair-cancel like PPLNS). Candidates:
//! `pendingSats > 0 AND pendingSats < min_payout AND
//! lastAcceptedShareAt < cutoff_ms`.
//!
//! Per-row TX: insert audit row (`rowType = "dust-sweep"`) into
//! `pplns_group_block_history` + DELETE the balance row.
//! `BlockHeightGen` from `bp-cron-utils` keeps the
//! `(groupId, blockHeight, address)` UNIQUE-index happy on
//! sub-second re-triggers.
//!
//! Default cutoff: `DUST_SWEEP_DORMANT_DAYS = 30` (shorter than
//! PPLNS's 90d because group balances are all-positive and have no
//! counterparty to wait for).

use std::sync::Arc;
use std::time::Duration;

use bp_common::Sats;
use bp_cron_utils::{next_3am_utc, BlockHeightGen, Clock};
use bp_db::{
    bulk_insert_pplns_group_block_history, delete_pplns_group_balance,
    find_pplns_group_balances_dormant, DbError, GroupPayoutHistoryInsert, PplnsGroupBalanceRow,
};
use chrono::DateTime;
use chrono::Utc;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Wire string for the sweep-emitted `rowType` column.
pub const ROW_TYPE_SWEEP: &str = "dust-sweep";

#[derive(Debug, Error)]
pub enum SweepError {
    #[error("db: {0}")]
    Db(#[from] DbError),
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Result of one sweep run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SweepStats {
    /// Number of balance rows absorbed this run.
    pub rows_absorbed: u32,
    /// Σ absorbed `pendingSats` (always non-negative for Group-Solo).
    pub sats_absorbed: i64,
}

/// Daily-sweep orchestrator for Group-Solo. Cheap-clone (each field
/// is an `Arc` or `Clone`-cheap config).
#[derive(Clone)]
pub struct GroupDustSweepRunner<C: Clock> {
    pool: PgPool,
    clock: Arc<C>,
    /// Threshold below which a `pendingSats` row counts as
    /// "sub-payout dust". From `GroupSoloEngineConfig::min_payout_sats`.
    min_payout_sats: Sats,
    /// Days of inactivity before a row becomes sweep-eligible.
    dormant_days: u32,
    block_height_gen: Arc<BlockHeightGen>,
}

impl<C: Clock> GroupDustSweepRunner<C> {
    pub fn new(pool: PgPool, clock: Arc<C>, min_payout_sats: Sats, dormant_days: u32) -> Self {
        Self {
            pool,
            clock,
            min_payout_sats,
            dormant_days,
            block_height_gen: Arc::new(BlockHeightGen::new()),
        }
    }

    /// Run one sweep. Public so tests + admin endpoints can trigger
    /// without waiting for the daily cron.
    pub async fn sweep(&self) -> Result<SweepStats, SweepError> {
        let now = self.clock.now();
        let now_ms = now.timestamp_millis();
        let cutoff_ms = now_ms - (self.dormant_days as i64) * 86_400_000;

        let candidates =
            find_pplns_group_balances_dormant(&self.pool, self.min_payout_sats.to_i64(), cutoff_ms)
                .await?;
        self.absorb_candidates(candidates, now_ms, now).await
    }

    /// Single-sided absorption: each candidate gets an audit row + a
    /// DELETE on the balance, atomically per row. Failures are
    /// logged + skipped (the same row gets retried next sweep).
    async fn absorb_candidates(
        &self,
        candidates: Vec<PplnsGroupBalanceRow>,
        now_ms: i64,
        now: DateTime<Utc>,
    ) -> Result<SweepStats, SweepError> {
        let mut stats = SweepStats::default();
        for row in candidates {
            let block_height = self.block_height_gen.next(now);
            match self.absorb_row_tx(&row, block_height, now_ms).await {
                Ok(()) => {
                    stats.rows_absorbed += 1;
                    stats.sats_absorbed += row.pending_sats.0;
                    debug!(
                        address = row.address.as_str(),
                        group_id = %row.group_id,
                        amount = row.pending_sats.0,
                        "group-dust-sweep absorbed"
                    );
                }
                Err(e) => {
                    warn!(
                        address = row.address.as_str(),
                        group_id = %row.group_id,
                        error = %e,
                        "group-dust-sweep row tx failed; skipping for next sweep"
                    );
                }
            }
        }
        Ok(stats)
    }

    /// One absorption TX: insert audit row + DELETE balance row.
    async fn absorb_row_tx(
        &self,
        row: &PplnsGroupBalanceRow,
        block_height: i32,
        now_ms: i64,
    ) -> Result<(), SweepError> {
        let mut tx = self.pool.begin().await?;

        bulk_insert_pplns_group_block_history(
            &mut *tx,
            &[GroupPayoutHistoryInsert {
                group_id: row.group_id,
                block_height,
                address: row.address.as_str().to_string(),
                paid_sats: row.pending_sats.0,
                percent: 0.0,
                shares_in_round: 0,
                total_shares_in_round: 0,
                row_type: ROW_TYPE_SWEEP.to_string(),
                created_at_ms: now_ms,
            }],
        )
        .await?;

        delete_pplns_group_balance(&mut *tx, &row.address, row.group_id).await?;

        tx.commit().await?;
        Ok(())
    }
}

// ── Daily 03:00-UTC loop ───────────────────────────────────────────

/// Spawn the daily group-dust-sweep background task.
///
/// Wall-clock sleep until `next_3am_utc`; on cancel, drops without a
/// final sweep (next process-start picks up at the next tick).
pub fn spawn_daily_task<C: Clock>(
    runner: GroupDustSweepRunner<C>,
    enabled: bool,
    mut cancel_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if !enabled {
            info!("group-solo dust-sweep disabled by config");
            return;
        }
        loop {
            let now = runner.clock.now();
            let next = next_3am_utc(now);
            let wait = (next - now).to_std().unwrap_or(Duration::from_secs(60));

            tokio::select! {
                _ = tokio::time::sleep(wait) => {
                    match runner.sweep().await {
                        Ok(stats) if stats.rows_absorbed > 0 => info!(
                            rows_absorbed = stats.rows_absorbed,
                            sats_absorbed = stats.sats_absorbed,
                            "group-dust-sweep ok",
                        ),
                        Ok(_) => debug!("group-dust-sweep ok (no rows to absorb)"),
                        Err(e) => warn!(error = %e, "group-dust-sweep failed"),
                    }
                }
                changed = cancel_rx.changed() => {
                    if changed.is_err() || *cancel_rx.borrow() {
                        info!("group-solo dust-sweep task cancelled");
                        return;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_stats_default_is_zero() {
        let s = SweepStats::default();
        assert_eq!(s.rows_absorbed, 0);
        assert_eq!(s.sats_absorbed, 0);
    }

    #[test]
    fn sweep_stats_clone_equality() {
        let a = SweepStats {
            rows_absorbed: 3,
            sats_absorbed: 1500,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
