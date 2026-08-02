// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daily 03:00 UTC group sweep for `pplns_group_balance`.
//!
//! Two passes over the dormant rows (`pendingSats <> 0 AND
//! lastAcceptedShareAt < cutoff_ms`), in this order:
//!
//! 1. **Pair-cancel**, per group. The Group-Solo ledger became SIGNED
//!    with the weight model — a member the coinbase overpaid owes the
//!    pool — so a dormant debit has a dormant credit somewhere as its
//!    counterparty, and retiring them together is the only way that
//!    keeps `Σ pendingSats` where it was. This pass used not to exist:
//!    the sweep absorbed dormant credits and left dormant debits
//!    standing forever, so the two sides of the same movement were
//!    retired on different schedules.
//! 2. **Dust absorption** of what the pairing leaves: a still-positive
//!    row below `min_payout`. An unpaired DEBIT is left alone — the
//!    pool deleting it would forgive money the other members are owed,
//!    and nothing about the row being old makes that right.
//!
//! Pairing is scoped to ONE group. `pplns_group_balance` is keyed
//! `(address, groupId)` and each group's coinbase pays only its own
//! members, so cancelling across groups would move satoshis between
//! two ledgers that never traded.
//!
//! Per-TX: audit rows (`rowType = "dust-sweep"`) into
//! `pplns_group_block_history` + the balance UPDATE/DELETE, committed
//! together. `BlockHeightGen` from `bp-cron-utils` keeps the
//! `(groupId, blockHeight, address)` UNIQUE-index happy on
//! sub-second re-triggers.
//!
//! Default cutoff: `DUST_SWEEP_DORMANT_DAYS = 30`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bp_common::{AddressId, Sats};
use bp_cron_utils::{next_3am_utc, BlockHeightGen, Clock};
use bp_db::{
    bulk_insert_pplns_group_block_history, delete_pplns_group_balance,
    find_pplns_group_balances_dormant, update_pplns_group_balance_pending_sats, DbError,
    GroupPayoutHistoryInsert, PplnsGroupBalanceRow,
};
use chrono::DateTime;
use chrono::Utc;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use uuid::Uuid;

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
    /// Σ absorbed `pendingSats` (non-negative — only credits are
    /// absorbed; an unpaired debit is left standing).
    pub sats_absorbed: i64,
    /// Rows that took part in a successful pair-cancel (2 per pair).
    pub pairs_closed: u32,
    /// Σ paired amount in sats, counted once per pair.
    pub sats_paired: i64,
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

        let candidates = find_pplns_group_balances_dormant(&self.pool, cutoff_ms).await?;

        // Grouped, because the ledger only balances inside a group.
        // Sorted so a run is reproducible — `HashMap` order is not.
        let mut by_group: HashMap<Uuid, Vec<PplnsGroupBalanceRow>> = HashMap::new();
        for row in candidates {
            by_group.entry(row.group_id).or_default().push(row);
        }
        let mut group_ids: Vec<Uuid> = by_group.keys().copied().collect();
        group_ids.sort();

        let mut stats = SweepStats::default();
        for group_id in group_ids {
            let rows = by_group.remove(&group_id).unwrap_or_default();
            let left = self
                .cancel_pairs(group_id, rows, now_ms, now, &mut stats)
                .await;
            self.absorb_candidates(left, now_ms, now, &mut stats).await;
        }
        Ok(stats)
    }

    /// Pair-cancel dormant credits against dormant debits inside ONE
    /// group, greedily largest-first. Returns every row with the
    /// balance the pairing left on it, so the dust pass sees the
    /// post-cancel value rather than the one it started with.
    ///
    /// `Σ pendingSats` is unchanged by construction: each pair moves
    /// `+X` and `−X` to zero together. That is the whole point — the
    /// pool is non-custodial, the satoshis already live on chain, and a
    /// sweep that retired one side alone would invent a claim.
    async fn cancel_pairs(
        &self,
        group_id: Uuid,
        rows: Vec<PplnsGroupBalanceRow>,
        now_ms: i64,
        now: DateTime<Utc>,
        stats: &mut SweepStats,
    ) -> Vec<PplnsGroupBalanceRow> {
        let (mut credits, mut debits): (Vec<_>, Vec<_>) =
            rows.into_iter().partition(|r| r.pending_sats.0 > 0);
        credits.sort_by_key(|r| std::cmp::Reverse(r.pending_sats.0));
        debits.sort_by_key(|r| r.pending_sats.0); // most-negative first

        let (mut i, mut j) = (0usize, 0usize);
        while i < credits.len() && j < debits.len() {
            let amount = credits[i].pending_sats.0.min(-debits[j].pending_sats.0);
            if amount <= 0 {
                break;
            }
            let new_credit = credits[i].pending_sats.0 - amount;
            let new_debit = debits[j].pending_sats.0 + amount;
            let block_height = self.block_height_gen.next(now);
            let credit_addr = credits[i].address.clone();
            let debit_addr = debits[j].address.clone();

            match self
                .apply_pair_tx(
                    group_id,
                    &credit_addr,
                    &debit_addr,
                    Sats(new_credit),
                    Sats(new_debit),
                    amount,
                    block_height,
                    now_ms,
                )
                .await
            {
                Ok(()) => {
                    credits[i].pending_sats = Sats(new_credit);
                    debits[j].pending_sats = Sats(new_debit);
                    stats.pairs_closed += 2;
                    stats.sats_paired += amount;
                    debug!(
                        %group_id,
                        credit = credit_addr.as_str(),
                        debit = debit_addr.as_str(),
                        amount,
                        "group-sweep paired"
                    );
                }
                Err(e) => {
                    warn!(
                        %group_id,
                        credit = credit_addr.as_str(),
                        debit = debit_addr.as_str(),
                        error = %e,
                        "group-sweep pair tx failed; advancing past"
                    );
                    i += 1;
                    j += 1;
                    continue;
                }
            }
            if credits[i].pending_sats.0 == 0 {
                i += 1;
            }
            if debits[j].pending_sats.0 == 0 {
                j += 1;
            }
        }
        credits.into_iter().chain(debits).collect()
    }

    /// One pair-cancel TX: 2 audit rows + update-or-delete both balance
    /// rows, committed together or not at all.
    #[allow(clippy::too_many_arguments)] // scalar args are tightly coupled; grouping struct adds boilerplate
    async fn apply_pair_tx(
        &self,
        group_id: Uuid,
        credit_addr: &AddressId,
        debit_addr: &AddressId,
        new_credit: Sats,
        new_debit: Sats,
        amount: i64,
        block_height: i32,
        now_ms: i64,
    ) -> Result<(), SweepError> {
        let mut tx = self.pool.begin().await?;

        bulk_insert_pplns_group_block_history(
            &mut *tx,
            &[
                GroupPayoutHistoryInsert {
                    group_id,
                    block_height,
                    address: credit_addr.as_str().to_string(),
                    paid_sats: amount,
                    percent: 0.0,
                    shares_in_round: 0,
                    total_shares_in_round: 0,
                    row_type: ROW_TYPE_SWEEP.to_string(),
                    created_at_ms: now_ms,
                },
                GroupPayoutHistoryInsert {
                    group_id,
                    block_height,
                    address: debit_addr.as_str().to_string(),
                    paid_sats: amount,
                    percent: 0.0,
                    shares_in_round: 0,
                    total_shares_in_round: 0,
                    row_type: ROW_TYPE_SWEEP.to_string(),
                    created_at_ms: now_ms,
                },
            ],
        )
        .await?;

        for (addr, new_value) in [(credit_addr, new_credit), (debit_addr, new_debit)] {
            if new_value.0 == 0 {
                delete_pplns_group_balance(&mut *tx, addr, group_id).await?;
            } else {
                update_pplns_group_balance_pending_sats(&mut *tx, addr, group_id, new_value)
                    .await?;
            }
        }

        tx.commit().await?;
        Ok(())
    }

    /// Absorb what the pairing left: a still-positive row below
    /// `min_payout`. Each gets an audit row + a DELETE on the balance,
    /// atomically per row. Failures are logged + skipped (the same row
    /// gets retried next sweep).
    ///
    /// Only CREDITS. A dormant debit with no counterparty stays on the
    /// books: deleting it would forgive satoshis the other members are
    /// owed, and age is not a reason to hand them over. It costs
    /// nothing to leave — a debtor with no score is floored out of the
    /// weight projection anyway, so the row is inert until they mine
    /// again.
    async fn absorb_candidates(
        &self,
        candidates: Vec<PplnsGroupBalanceRow>,
        now_ms: i64,
        now: DateTime<Utc>,
        stats: &mut SweepStats,
    ) {
        let min_payout = self.min_payout_sats.to_i64();
        let candidates = candidates
            .into_iter()
            .filter(|r| r.pending_sats.0 > 0 && r.pending_sats.0 < min_payout);
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
        assert_eq!(s.pairs_closed, 0);
        assert_eq!(s.sats_paired, 0);
    }

    #[test]
    fn sweep_stats_clone_equality() {
        let a = SweepStats {
            rows_absorbed: 3,
            sats_absorbed: 1500,
            pairs_closed: 2,
            sats_paired: 9_000,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
