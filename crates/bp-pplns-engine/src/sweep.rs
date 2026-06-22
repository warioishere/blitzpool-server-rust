// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daily 03:00 UTC dust-sweep — pair-cancel abandoned credits against
//! abandoned debits in the PPLNS signed ledger.
//!
//! Algorithm:
//!
//! 1. Load all `pplns_balance` rows whose `balanceSats != 0` and
//!    whose `lastAcceptedShareAt < now - abandoned_days × 86400s`.
//! 2. Split: credits (balance > 0, desc) ↔ debits (balance < 0, by
//!    absolute value desc).
//! 3. Walk greedy: for each pair `amount = min(credit, |debit|)`.
//!    Write 2 audit rows to `pplns_payout_history` (same `blockHeight`
//!    so an operator can group them) + update-or-delete both balance
//!    rows. All inside one PG transaction per pair — on failure, skip
//!    and let the next sweep retry.
//! 4. Σ balances stays 0: each pair cancels `+X` ↔ `-X`. No silent
//!    drift toward fee or other miners — the pool is non-custodial,
//!    the physical sats already live on-chain.
//!
//! `blockHeight` slot: synthetic `-Math.floor(now_unix_seconds)`. Two
//! reasons:
//! - audit rows aren't associated with a real block; a negative value
//!   can't be confused with a real block height
//! - the `UNIQUE(blockHeight, address)` index would otherwise reject
//!   the second pair-cancel of the same address (e.g. if a debit pairs
//!   against two smaller credits across iterations). Sweep keeps a
//!   monotonic counter so sub-second re-triggers stay unique too.
//!
//! Group-Solo dust absorption lives in the future `bp-group-solo-engine`
//! crate — the architecture-decision splits them by crate so the
//! engines stay independent.
//!
//! Clock abstraction lets `TestClock` step time deterministically in
//! unit tests, same pattern as `bp-vardiff::Clock`.

use std::sync::Arc;
use std::time::Duration;

use bp_common::{AddressId, Sats};
use bp_cron_utils::BlockHeightGen;
use bp_db::{
    bulk_insert_pplns_payout_history, delete_pplns_balance, find_pplns_balances_abandoned,
    update_pplns_balance_sats, DbError, PayoutHistoryInsert, PplnsBalanceRow,
};
use chrono::DateTime;
use chrono::Utc;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

// Re-export the cron primitives so existing call sites that imported
// from `bp_pplns_engine::sweep::*` keep working.
pub use bp_cron_utils::{next_3am_utc, Clock, SystemClock, TestClock};

/// Wire string for the `rowType` column on sweep-emitted history rows.
pub const ROW_TYPE_SWEEP: &str = "dust-sweep";

// ── Errors + stats ──────────────────────────────────────────────────

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
    /// Number of balance rows that participated in a successful pair
    /// (typically 2 × number of pairs; 1 per side).
    pub pairs_closed: u32,
    /// Σ paired amount in sats (one side, not double-counted).
    pub sats_paired: i64,
    /// Remaining credit rows that didn't find a counterparty this run.
    pub unpaired_credits: u32,
    /// Remaining debit rows.
    pub unpaired_debits: u32,
}

// ── Runner ──────────────────────────────────────────────────────────

/// Daily-sweep orchestrator. Cheap-clone (each field is an `Arc` or
/// `Clone`-cheap config).
#[derive(Clone)]
pub struct DustSweepRunner<C: Clock> {
    pool: PgPool,
    clock: Arc<C>,
    abandoned_days: u32,
    block_height_gen: Arc<BlockHeightGen>,
}

impl<C: Clock> DustSweepRunner<C> {
    pub fn new(pool: PgPool, clock: Arc<C>, abandoned_days: u32) -> Self {
        Self {
            pool,
            clock,
            abandoned_days,
            block_height_gen: Arc::new(BlockHeightGen::new()),
        }
    }

    /// Run one sweep. Public so tests + admin endpoints can trigger
    /// without waiting for the daily cron.
    pub async fn sweep(&self) -> Result<SweepStats, SweepError> {
        let now = self.clock.now();
        let now_ms = now.timestamp_millis();
        let cutoff_ms = now_ms - (self.abandoned_days as i64) * 86_400_000;

        let candidates = find_pplns_balances_abandoned(&self.pool, cutoff_ms).await?;
        self.sweep_pairs(candidates, now_ms, now).await
    }

    /// Algorithm split out so tests can feed synthetic candidates
    /// without seeding PG (the integration tests still exercise the
    /// full PG path).
    async fn sweep_pairs(
        &self,
        candidates: Vec<PplnsBalanceRow>,
        now_ms: i64,
        now: DateTime<Utc>,
    ) -> Result<SweepStats, SweepError> {
        let (mut credits, mut debits): (Vec<PplnsBalanceRow>, Vec<PplnsBalanceRow>) = candidates
            .into_iter()
            .filter(|r| r.balance_sats.0 != 0)
            .partition(|r| r.balance_sats.0 > 0);

        // credits desc by balance, debits asc by balance (most-negative first).
        credits.sort_by_key(|r| std::cmp::Reverse(r.balance_sats.0));
        debits.sort_by_key(|r| r.balance_sats.0);

        if credits.is_empty() || debits.is_empty() {
            return Ok(SweepStats {
                pairs_closed: 0,
                sats_paired: 0,
                unpaired_credits: credits.len() as u32,
                unpaired_debits: debits.len() as u32,
            });
        }

        let mut stats = SweepStats::default();
        let mut i = 0usize;
        let mut j = 0usize;

        while i < credits.len() && j < debits.len() {
            let credit_balance = credits[i].balance_sats.0;
            let debit_balance = debits[j].balance_sats.0;

            let amount = credit_balance.min(-debit_balance);
            if amount <= 0 {
                break;
            }
            let new_credit = credit_balance - amount;
            let new_debit = debit_balance + amount;

            let block_height = self.block_height_gen.next(now);
            let credit_addr = credits[i].address.clone();
            let debit_addr = debits[j].address.clone();

            match self
                .apply_pair_tx(
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
                    credits[i].balance_sats = Sats(new_credit);
                    debits[j].balance_sats = Sats(new_debit);
                    stats.pairs_closed += 2;
                    stats.sats_paired += amount;
                    debug!(
                        credit = credit_addr.as_str(),
                        debit = debit_addr.as_str(),
                        amount,
                        "pplns-sweep paired"
                    );
                }
                Err(e) => {
                    warn!(
                        credit = credit_addr.as_str(),
                        debit = debit_addr.as_str(),
                        error = %e,
                        "pplns-sweep pair tx failed; advancing past"
                    );
                    i += 1;
                    j += 1;
                    continue;
                }
            }

            if credits[i].balance_sats.0 == 0 {
                i += 1;
            }
            if debits[j].balance_sats.0 == 0 {
                j += 1;
            }
        }

        stats.unpaired_credits = (credits.len() - i) as u32;
        stats.unpaired_debits = (debits.len() - j) as u32;
        Ok(stats)
    }

    /// One pair-cancel TX: insert 2 audit rows + update-or-delete both
    /// balance rows. Both writes commit or both roll back.
    #[allow(clippy::too_many_arguments)] // scalar args are tightly coupled; grouping struct adds boilerplate
    async fn apply_pair_tx(
        &self,
        credit_addr: &AddressId,
        debit_addr: &AddressId,
        new_credit: Sats,
        new_debit: Sats,
        amount: i64,
        block_height: i32,
        now_ms: i64,
    ) -> Result<(), SweepError> {
        let mut tx = self.pool.begin().await?;

        bulk_insert_pplns_payout_history(
            &mut *tx,
            &[
                PayoutHistoryInsert {
                    block_height,
                    address: credit_addr.as_str().to_string(),
                    paid_sats: amount,
                    percent: 0.0,
                    row_type: ROW_TYPE_SWEEP.to_string(),
                    created_at_ms: now_ms,
                },
                PayoutHistoryInsert {
                    block_height,
                    address: debit_addr.as_str().to_string(),
                    paid_sats: amount,
                    percent: 0.0,
                    row_type: ROW_TYPE_SWEEP.to_string(),
                    created_at_ms: now_ms,
                },
            ],
        )
        .await?;

        if new_credit.0 == 0 {
            delete_pplns_balance(&mut *tx, credit_addr).await?;
        } else {
            update_pplns_balance_sats(&mut *tx, credit_addr, new_credit).await?;
        }
        if new_debit.0 == 0 {
            delete_pplns_balance(&mut *tx, debit_addr).await?;
        } else {
            update_pplns_balance_sats(&mut *tx, debit_addr, new_debit).await?;
        }

        tx.commit().await?;
        Ok(())
    }
}

// ── Daily 03:00-UTC loop ────────────────────────────────────────────

/// Spawn the daily-sweep background task.
///
/// Loop body:
/// 1. compute `next_3am_utc` from the clock's current `now()`
/// 2. `tokio::time::sleep_until(next_3am)` (or watch the cancel
///    channel — whichever fires first)
/// 3. run `runner.sweep()`; log result; loop
///
/// On cancel: drops without running a final sweep. The next process
/// start will pick up at the next 3am tick.
///
/// Note: this uses wall-clock sleep, NOT clock-trait sleep. The
/// `Clock` parameter only feeds the *cutoff math* inside `sweep()`.
/// For tests that want to step the cron tick, call `runner.sweep()`
/// directly with a `TestClock`. Spawning the real background task is
/// covered by an `--ignored`-or-skip integration test.
pub fn spawn_daily_task<C: Clock>(
    runner: DustSweepRunner<C>,
    enabled: bool,
    mut cancel_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if !enabled {
            info!("pplns dust-sweep disabled by config");
            return;
        }
        loop {
            let now = runner.clock.now();
            let next = next_3am_utc(now);
            let wait = (next - now).to_std().unwrap_or(Duration::from_secs(60));

            tokio::select! {
                _ = tokio::time::sleep(wait) => {
                    match runner.sweep().await {
                        Ok(stats) if stats.pairs_closed > 0 => info!(
                            pairs_closed = stats.pairs_closed,
                            sats_paired = stats.sats_paired,
                            unpaired_credits = stats.unpaired_credits,
                            unpaired_debits = stats.unpaired_debits,
                            "pplns dust-sweep ok",
                        ),
                        Ok(_) => debug!("pplns dust-sweep ok (no pairs to close)"),
                        Err(e) => warn!(error = %e, "pplns dust-sweep failed"),
                    }
                }
                changed = cancel_rx.changed() => {
                    if changed.is_err() || *cancel_rx.borrow() {
                        info!("pplns dust-sweep task cancelled");
                        return;
                    }
                }
            }
        }
    })
}

// Clock / TestClock / next_3am_utc / BlockHeightGen tests live with
// their extracted crate `bp-cron-utils`; the re-exports above keep
// existing call sites working. Sweep-specific behaviour is exercised
// via the runner's own unit + integration tests further up in this
// module.
