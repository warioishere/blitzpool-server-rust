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
use bp_pplns::CoinbaseDistributionEntry;
use sqlx::PgPool;

pub use bp_db::TouchUpdate;
// Shared with Group-Solo — one source of truth for the rowType wire
// strings + apply-distribution result / error shapes.
pub use bp_coinbase_snapshot::{ApplyDistributionResult, LedgerError, PayoutRowType};

/// One row in the apply-distribution audit log.
///
/// The engine builds these from the 5-phase `bp_pplns::build_coinbase_distribution`
/// output: one row per coinbase entry, one row per ledger debit/credit
/// that didn't land on-chain, optionally one row per "late arrival"
/// observed between snapshot and block-found.
#[derive(Clone, Debug)]
pub struct AuditRow {
    pub address: AddressId,
    pub paid_sats: Sats,
    pub percent: f32,
    pub row_type: PayoutRowType,
}

/// Convenience constructor: a coinbase output (positive sats, the
/// percent slot the entry takes in the block reward).
pub fn coinbase_row(entry: &CoinbaseDistributionEntry) -> AuditRow {
    AuditRow {
        address: entry.address.clone(),
        paid_sats: entry.sats,
        percent: entry.percent as f32,
        row_type: PayoutRowType::Coinbase,
    }
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
/// 1. Insert audit rows into `pplns_payout_history` (idempotent via
///    `(blockHeight, address)` UNIQUE).
/// 2. Upsert absolute new `balanceSats` + `totalPaidSats` + `updatedAt`
///    into `pplns_balance`.
///
/// On any error the transaction rolls back — neither write lands. On
/// replay (same `block_height`), the history insert silently dedupes
/// via the UNIQUE constraint and the balance upsert converges to the
/// same absolute state.
///
/// Caller (typically [`crate::hooks::PplnsBlockSubmissionSink`]) is
/// responsible for:
/// - reading the snapshot persisted at template-build time
/// - mapping it to the audit-row list and absolute-balance list
/// - calling this function inside the block-found re-entrancy lock
pub async fn apply_distribution(
    pool: &PgPool,
    block_height: i32,
    rows: &[AuditRow],
    balances: &[BalanceWrite],
    now_ms: i64,
) -> Result<ApplyDistributionResult, LedgerError> {
    let mut tx = pool.begin().await?;

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

    let history_inserted = bulk_insert_pplns_payout_history(&mut *tx, &history_rows).await?;
    // Idempotency gate. The history table dedupes a replayed / duplicate
    // block-found via its UNIQUE (blockHeight, address). The balance upsert
    // accumulates `totalPaidSats`, so only run it when the history rows were
    // actually inserted — a 0-insert means this block already booked (stream
    // redelivery, or a duplicate block-found re-frozen at the same height) and
    // re-applying would double-count the balance.
    let balances_affected = if history_inserted > 0 {
        bulk_upsert_pplns_balances(&mut *tx, &balance_rows).await?
    } else {
        0
    };

    tx.commit().await?;
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
    fn coinbase_row_carries_entry_fields() {
        let entry = CoinbaseDistributionEntry {
            address: AddressId::new("bc1qfoo").unwrap(),
            percent: 42.5,
            sats: Sats(1_000_000),
        };
        let row = coinbase_row(&entry);
        assert_eq!(row.address.as_str(), "bc1qfoo");
        assert!((row.percent - 42.5).abs() < 1e-4);
        assert_eq!(row.paid_sats.0, 1_000_000);
        assert_eq!(row.row_type, PayoutRowType::Coinbase);
    }

    #[test]
    fn pending_row_marks_zero_percent() {
        let row = pending_row(AddressId::new("bc1qbar").unwrap(), Sats(-2_500));
        assert_eq!(row.percent, 0.0);
        assert_eq!(row.paid_sats.0, -2_500);
        assert_eq!(row.row_type, PayoutRowType::Pending);
    }
}
