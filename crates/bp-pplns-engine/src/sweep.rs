// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daily 03:00 UTC dust-sweep: pair-cancel abandoned PPLNS credits against open
//! debits, one transaction per pair, so Σ balances stays 0 and nothing drifts
//! to the fee or other miners. Audit rows get a synthetic negative, unique
//! `blockHeight`. PPLNS only: Group-Solo keeps no ledger.

use std::sync::Arc;
use std::time::Duration;

use bp_common::{AddressId, Sats};
use bp_cron_utils::BlockHeightGen;
use bp_db::{
    bulk_insert_pplns_payout_history, find_pplns_balances_with_open_balance,
    update_pplns_balance_sats_if_unchanged, DbError, PayoutHistoryInsert, PplnsBalanceRow,
};
use chrono::DateTime;
use chrono::Utc;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::ledger::PayoutRowType;

pub use bp_cron_utils::{next_3am_utc, Clock, SystemClock, TestClock};

// ── Errors + stats ──────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SweepError {
    #[error("db: {0}")]
    Db(#[from] DbError),
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SweepStats {
    /// Balance rows touched by a successful pair: two per pair.
    pub pairs_closed: u32,
    /// Counted on one side only.
    pub sats_paired: i64,
    pub unpaired_credits: u32,
    pub unpaired_debits: u32,
}

// ── Runner ──────────────────────────────────────────────────────────

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

    /// Epoch-ms before which a balance row's owner counts as abandoned.
    fn cutoff_ms(&self, now_ms: i64) -> i64 {
        crate::config::abandoned_cutoff_ms(now_ms, self.abandoned_days)
    }

    pub async fn sweep(&self) -> Result<SweepStats, SweepError> {
        let now = self.clock.now();
        let now_ms = now.timestamp_millis();

        let candidates = find_pplns_balances_with_open_balance(&self.pool).await?;
        self.sweep_pairs(candidates, now_ms, now).await
    }

    /// Public so a test can feed a candidate list that is already stale.
    pub async fn sweep_pairs(
        &self,
        candidates: Vec<PplnsBalanceRow>,
        now_ms: i64,
        now: DateTime<Utc>,
    ) -> Result<SweepStats, SweepError> {
        let (mut credits, mut debits): (Vec<PplnsBalanceRow>, Vec<PplnsBalanceRow>) = candidates
            .into_iter()
            .filter(|r| r.balance_sats.0 != 0)
            .partition(|r| r.balance_sats.0 > 0);

        credits.sort_by_key(|r| std::cmp::Reverse(r.balance_sats.0));
        // Abandoned debits first, so a credit closes a dead debit before a
        // live miner's; a live debit is still used when needed, it is owed anyway.
        let cutoff_ms = self.cutoff_ms(now_ms);
        let is_abandoned = |r: &PplnsBalanceRow| {
            r.last_accepted_share_at
                .is_some_and(|last| last < cutoff_ms)
        };
        debits.sort_by_key(|r| (!is_abandoned(r), r.balance_sats.0));

        // The ONE place the owner of a written-off credit is checked to be
        // gone; the read returns live credits too. Debits are the counterparty.
        credits.retain(is_abandoned);

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
                    Sats(credit_balance),
                    Sats(debit_balance),
                    Sats(new_credit),
                    Sats(new_debit),
                    amount,
                    block_height,
                    now_ms,
                )
                .await
            {
                // A row moved since the read; the next run sees fresh values.
                Ok(false) => {
                    warn!(
                        credit = credit_addr.as_str(),
                        debit = debit_addr.as_str(),
                        "pplns-sweep: a balance moved since the run started — pair skipped"
                    );
                    i += 1;
                    j += 1;
                    continue;
                }
                Ok(true) => {
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

    /// One pair-cancel: two audit rows plus both balances, all or nothing.
    /// `Ok(false)` if a row moved since the read: a stale write would undo a
    /// settlement or drive a credit negative. Rows are locked smallest address
    /// first, like `bp_db::find_pplns_balances_for_addresses_locked`, so no deadlock.
    #[allow(clippy::too_many_arguments)] // scalar args are tightly coupled; grouping struct adds boilerplate
    async fn apply_pair_tx(
        &self,
        credit_addr: &AddressId,
        debit_addr: &AddressId,
        old_credit: Sats,
        old_debit: Sats,
        new_credit: Sats,
        new_debit: Sats,
        amount: i64,
        block_height: i32,
        now_ms: i64,
    ) -> Result<bool, SweepError> {
        let mut tx = self.pool.begin().await?;

        bulk_insert_pplns_payout_history(
            &mut *tx,
            &[
                PayoutHistoryInsert {
                    block_height,
                    address: credit_addr.as_str().to_string(),
                    paid_sats: amount,
                    percent: 0.0,
                    row_type: PayoutRowType::DustSweep.as_wire().to_string(),
                    created_at_ms: now_ms,
                },
                PayoutHistoryInsert {
                    block_height,
                    address: debit_addr.as_str().to_string(),
                    paid_sats: amount,
                    percent: 0.0,
                    row_type: PayoutRowType::DustSweep.as_wire().to_string(),
                    created_at_ms: now_ms,
                },
            ],
        )
        .await?;

        let mut sides = [
            (credit_addr, old_credit, new_credit),
            (debit_addr, old_debit, new_debit),
        ];
        sides.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        for (addr, expected, new_balance) in sides {
            // UPDATE to 0, never DELETE: the row is the only home of
            // `totalPaidSats` and `lastAcceptedShareAt`; a zero row is inert.
            let applied =
                update_pplns_balance_sats_if_unchanged(&mut *tx, addr, expected, new_balance)
                    .await?;
            if !applied {
                // Roll back the audit rows too: the cancel did not happen.
                drop(tx);
                return Ok(false);
            }
        }

        tx.commit().await?;
        Ok(true)
    }
}

// ── Daily 03:00-UTC loop ────────────────────────────────────────────

/// Spawn the daily-sweep task. It sleeps on the wall clock; the `Clock` only
/// feeds the cutoff math, so tests call `runner.sweep()` with a `TestClock`.
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
