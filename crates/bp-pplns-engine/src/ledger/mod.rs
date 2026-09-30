// SPDX-License-Identifier: AGPL-3.0-or-later

//! Postgres-backed signed credit/debit ledger.
//!
//! Two tables, written atomically inside one PG transaction per block:
//!
//! - `pplns_balance` — keyed by `address`, signed `balanceSats`
//!   (> 0 = credit owed to miner, < 0 = debit owed by miner,
//!   = 0 = settled), lifetime `totalPaidSats`, last-accepted-share
//!   timestamp. Writes are *absolute* (upsert-style), idempotent on
//!   replay.
//! - `pplns_payout_history` — one row per `(block_height, address)`.
//!   `UNIQUE(blockHeight, address)` gates double-write replays.
//!
//! Primitives live in `bp-db` (`bulk_upsert_pplns_balances` +
//! `bulk_insert_pplns_payout_history`). This module composes them into
//! the [`apply_distribution`] TX-orchestrator that block-found uses.
//!
//! Submodule [`touch_buffer`] coalesces hot-path `markTouch` writes
//! into one bulk UPDATE every 60s.

pub mod touch_buffer;

use bp_common::{AddressId, Sats};
use bp_db::{
    bulk_insert_pplns_payout_history, bulk_upsert_pplns_balances, BalanceUpsert,
    PayoutHistoryInsert,
};

pub use bp_db::TouchUpdate;
// Shared with Group-Solo — one source of truth for the rowType wire
// strings + apply-distribution result / error shapes.
pub use bp_coinbase_snapshot::{ApplyDistributionResult, LedgerError, PayoutRowType};

/// One row in the apply-distribution audit log.
///
/// The engine builds these from the block's own coinbase settled against
/// the weight snapshot: one row per address the coinbase paid, one row per
/// ledger debit/credit that didn't land on-chain, and one zero row per
/// "late arrival" observed between snapshot and block-found.
#[derive(Clone, Debug)]
pub struct AuditRow {
    pub address: AddressId,
    pub paid_sats: Sats,
    pub percent: f32,
    pub row_type: PayoutRowType,
}

/// Convenience constructor: a pending ledger row (signed delta, no
/// on-chain output). Percent is 0.0 by convention since pending rows
/// don't represent a coinbase fraction.
pub fn pending_row(address: AddressId, delta_sats: Sats) -> AuditRow {
    AuditRow {
        address,
        paid_sats: delta_sats,
        percent: 0.0,
        row_type: PayoutRowType::Pending,
    }
}

// ── apply_distribution — the block-found TX ─────────────────────────

/// Atomically:
/// 1. Refuse outright if this block already has payout history — see
///    below.
/// 2. Insert audit rows into `pplns_payout_history`.
/// 3. Upsert absolute new `balanceSats` + `totalPaidSats` + `updatedAt`
///    into `pplns_balance`.
///
/// On any error the transaction rolls back — neither write lands.
///
/// **Why step 1 asks the block rather than counting inserted rows.** The
/// `(blockHeight, address)` UNIQUE only swallows a replay while the row set
/// is identical, and it is not: the caller appends one row per "late
/// arriver" (live in the window at apply time, absent from the snapshot),
/// and the window moves between attempts. A replay would then report
/// progress and re-apply the ABSOLUTE balance write (`current + delta`)
/// against a `current` that already includes the first booking, paying a
/// credit twice at the other miners' expense.
///
/// Sequential replay happens when the confirmation watcher's post-apply
/// `remove_pending_block` fails (its error is ignored) or the process dies
/// in that window. Concurrent duplicates are handled by the row locks the
/// caller takes before this runs, see below.
///
/// **Takes the caller's transaction rather than opening one.** The
/// balance write is absolute (`current + delta`), so the `current` it was
/// computed from has to be read UNDER `FOR UPDATE` in this same
/// transaction — see
/// [`bp_db::find_pplns_balances_for_addresses_locked`]. A caller that
/// reads outside it hands the daily dust sweep a window in which its
/// write is silently undone.
///
/// That ordering also hardens the gate below: locking the block's rows
/// first means a second, concurrent apply of the same block blocks on
/// them, and by the time it proceeds the first has committed its history
/// rows — so the `SELECT` sees them. A plain read-committed `SELECT`
/// alone would not.
///
/// Caller (typically [`crate::engine::PplnsEngine::on_block_found`]) is
/// responsible for:
/// - reading the snapshot persisted at template-build time
/// - opening the transaction, locking the balance rows, and mapping the
///   snapshot to the audit-row list and absolute-balance list
/// - committing, and calling all of it inside the block-found
///   re-entrancy lock
pub async fn apply_distribution(
    tx: &mut sqlx::PgConnection,
    block_height: i32,
    rows: &[AuditRow],
    balances: &[BalanceWrite],
    now_ms: i64,
) -> Result<ApplyDistributionResult, LedgerError> {
    // Height is the only identity a booked block has here (no `blockHash`
    // column, UNIQUE on `(blockHeight, address)`). Existing history is
    // either a redelivery of the same block, which must pass silently, or a
    // different block at the same height after a reorg, whose settlement
    // must not be skipped silently. They are told apart by the booking
    // itself: if the recorded value-bearing rows match what this apply
    // would write, replaying moves nothing, even for a different block that
    // paid the same coinbase.
    let booked = bp_db::pplns_booked_value_rows_at_height(&mut *tx, block_height).await?;
    if !booked.is_empty() {
        let mut want: Vec<(String, i64)> = rows
            .iter()
            .filter(|r| r.paid_sats.0 != 0)
            .map(|r| (r.address.as_str().to_string(), r.paid_sats.0))
            .collect();
        want.sort();
        if booked == want {
            // The ordinary replay: the confirmation watcher's post-apply
            // `remove_pending_block` failed, or the process died in that
            // window. Nothing to do.
            return Ok(ApplyDistributionResult {
                history_inserted: 0,
                balances_affected: 0,
            });
        }
        return Err(LedgerError::HeightBookedByAnotherBlock {
            block_height,
            booked_rows: booked.len(),
            incoming_rows: want.len(),
        });
    }

    let history_rows: Vec<PayoutHistoryInsert> = rows
        .iter()
        .map(|r| PayoutHistoryInsert {
            block_height,
            address: r.address.as_str().to_string(),
            paid_sats: r.paid_sats.0,
            percent: r.percent,
            row_type: r.row_type.as_wire().to_string(),
            created_at_ms: now_ms,
        })
        .collect();

    let balance_rows: Vec<BalanceUpsert> = balances
        .iter()
        .map(|b| BalanceUpsert {
            address: b.address.as_str().to_string(),
            balance_sats: b.balance_sats.0,
            total_paid_sats: b.total_paid_sats.0,
            updated_at_ms: now_ms,
        })
        .collect();

    // Past the gate above this block has no history, so both writes are
    // this apply's first and only ones. The `ON CONFLICT DO NOTHING` on
    // the insert is a constraint-level backstop.
    let history_inserted = bulk_insert_pplns_payout_history(&mut *tx, &history_rows).await?;
    let balances_affected = bulk_upsert_pplns_balances(&mut *tx, &balance_rows).await?;

    Ok(ApplyDistributionResult {
        history_inserted,
        balances_affected,
    })
}

/// Absolute new balance state for one address after applying the
/// distribution. Distinct from [`AuditRow`] because one block can
/// touch a balance without writing a history row (a "fully settled"
/// miner) and vice versa.
#[derive(Clone, Debug)]
pub struct BalanceWrite {
    pub address: AddressId,
    pub balance_sats: Sats,
    pub total_paid_sats: Sats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payout_row_type_wire_strings_are_correct() {
        assert_eq!(PayoutRowType::Coinbase.as_wire(), "coinbase");
        assert_eq!(PayoutRowType::Pending.as_wire(), "pending");
        assert_eq!(PayoutRowType::DustSweep.as_wire(), "dust-sweep");
    }

    #[test]
    fn pending_row_marks_zero_percent() {
        let row = pending_row(AddressId::new("bc1qbar").unwrap(), Sats(-2_500));
        assert_eq!(row.percent, 0.0);
        assert_eq!(row.paid_sats.0, -2_500);
        assert_eq!(row.row_type, PayoutRowType::Pending);
    }
}
