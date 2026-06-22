// SPDX-License-Identifier: AGPL-3.0-or-later

//! Postgres-backed unsigned-pending ledger.
//!
//! Two tables, written atomically inside one PG transaction per
//! block-found via [`apply_distribution`]:
//!
//! - `pplns_group_balance` — composite PK `(address, groupId)`,
//!   unsigned `pendingSats ≥ 0`, lifetime `totalPaidSats`,
//!   per-group last-share timestamp.
//! - `pplns_group_block_history` — auto-id rows with UNIQUE
//!   `(groupId, blockHeight, address)`. Includes
//!   `sharesInRound` + `totalSharesInRound` (Group-Solo PROP-round
//!   audit detail that PPLNS doesn't have).
//!
//! Bulk primitives live in `bp-db` (`bulk_upsert_pplns_group_balances`
//! and `bulk_insert_pplns_group_block_history`). This module composes
//! them into the `apply_distribution` TX-orchestrator.
//!
//! Group-Solo never goes negative, so there's no pair-cancel sweep
//! like PPLNS. Sub-dust pending balances are absorbed single-sided
//! by `bp-group-solo-engine::sweep`.

use bp_common::{AddressId, Sats};
use bp_db::{
    bulk_insert_pplns_group_block_history, bulk_upsert_pplns_group_balances, GroupBalanceUpsert,
    GroupPayoutHistoryInsert,
};
use bp_pplns::CoinbaseDistributionEntry;
use sqlx::PgPool;
use uuid::Uuid;

// Shared with PPLNS — one source of truth for the rowType wire strings
// + apply-distribution result / error shapes. Group-Solo's audit rows
// add `sharesInRound` fields (see [`AuditRow`]) but the discriminator
// itself is identical, so we alias the shared enum.
pub use bp_coinbase_snapshot::{
    ApplyDistributionResult, LedgerError, PayoutRowType as GroupPayoutRowType,
};

/// One row in the apply-distribution audit log. Group-Solo's
/// `sharesInRound` + `totalSharesInRound` slots are preserved here
/// so the audit log reflects the PROP-round split exactly.
#[derive(Clone, Debug)]
pub struct AuditRow {
    pub address: AddressId,
    pub paid_sats: Sats,
    pub percent: f32,
    pub shares_in_round: i64,
    pub total_shares_in_round: i64,
    pub row_type: GroupPayoutRowType,
}

/// Convenience constructor: a coinbase output.
pub fn coinbase_row(
    entry: &CoinbaseDistributionEntry,
    shares_in_round: i64,
    total_shares_in_round: i64,
) -> AuditRow {
    AuditRow {
        address: entry.address.clone(),
        paid_sats: entry.sats,
        percent: entry.percent as f32,
        shares_in_round,
        total_shares_in_round,
        row_type: GroupPayoutRowType::Coinbase,
    }
}

/// Convenience constructor: a pending ledger row (sub-dust /
/// late-arriver / kick-redistribution). Percent and share counts are
/// 0 by convention.
pub fn pending_row(address: AddressId, delta_sats: Sats) -> AuditRow {
    AuditRow {
        address,
        paid_sats: delta_sats,
        percent: 0.0,
        shares_in_round: 0,
        total_shares_in_round: 0,
        row_type: GroupPayoutRowType::Pending,
    }
}

/// Absolute new balance state for one (address, groupId) after
/// applying the distribution.
#[derive(Clone, Debug)]
pub struct BalanceWrite {
    pub address: AddressId,
    /// Always `≥ 0` for Group-Solo. The `Sats` newtype accepts
    /// negative values for PPLNS-symmetry; callers must enforce the
    /// non-negative invariant.
    pub pending_sats: Sats,
    pub total_paid_sats: Sats,
}

/// Atomically write one block's audit log + balance updates for one
/// group inside a single PG transaction. Idempotent on replay via
/// the `(groupId, blockHeight, address)` UNIQUE constraint.
pub async fn apply_distribution(
    pool: &PgPool,
    group_id: Uuid,
    block_height: i32,
    rows: &[AuditRow],
    balances: &[BalanceWrite],
    now_ms: i64,
) -> Result<ApplyDistributionResult, LedgerError> {
    let mut tx = pool.begin().await?;

    let history_rows: Vec<GroupPayoutHistoryInsert> = rows
        .iter()
        .map(|r| GroupPayoutHistoryInsert {
            group_id,
            block_height,
            address: r.address.as_str().to_string(),
            paid_sats: r.paid_sats.0,
            percent: r.percent,
            shares_in_round: r.shares_in_round,
            total_shares_in_round: r.total_shares_in_round,
            row_type: r.row_type.as_wire().to_string(),
            created_at_ms: now_ms,
        })
        .collect();

    let balance_rows: Vec<GroupBalanceUpsert> = balances
        .iter()
        .map(|b| GroupBalanceUpsert {
            address: b.address.as_str().to_string(),
            group_id,
            pending_sats: b.pending_sats.0,
            total_paid_sats: b.total_paid_sats.0,
            updated_at_ms: now_ms,
            // Stamp last-accepted on the upsert so block-found
            // touches the dormancy clock without a separate UPDATE
            // (lastAcceptedShareAt = now on every touched row).
            last_accepted_share_at_ms: Some(now_ms),
        })
        .collect();

    let history_inserted = bulk_insert_pplns_group_block_history(&mut *tx, &history_rows).await?;
    // Idempotency gate. The history table dedupes a replayed / duplicate
    // block-found via its UNIQUE (groupId, blockHeight, address). The balance
    // upsert is NOT idempotent — it accumulates `totalPaidSats` — so only run it
    // when the history rows were actually inserted. A 0-insert means this block
    // already booked (stream redelivery, or a duplicate block-found from a stale
    // candidate at the same height); re-applying would double-count the balance.
    let balances_affected = if history_inserted > 0 {
        bulk_upsert_pplns_group_balances(&mut *tx, &balance_rows).await?
    } else {
        0
    };

    tx.commit().await?;
    Ok(ApplyDistributionResult {
        history_inserted,
        balances_affected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payout_row_type_wire_strings_match_ts() {
        assert_eq!(GroupPayoutRowType::Coinbase.as_wire(), "coinbase");
        assert_eq!(GroupPayoutRowType::Pending.as_wire(), "pending");
        assert_eq!(GroupPayoutRowType::DustSweep.as_wire(), "dust-sweep");
    }

    #[test]
    fn coinbase_row_carries_entry_fields_and_share_counts() {
        let entry = CoinbaseDistributionEntry {
            address: AddressId::new("bc1qfoo").unwrap(),
            percent: 33.33,
            sats: Sats(1_000_000),
        };
        let row = coinbase_row(&entry, 333, 1_000);
        assert_eq!(row.address.as_str(), "bc1qfoo");
        assert!((row.percent - 33.33).abs() < 1e-3);
        assert_eq!(row.paid_sats.0, 1_000_000);
        assert_eq!(row.shares_in_round, 333);
        assert_eq!(row.total_shares_in_round, 1_000);
        assert_eq!(row.row_type, GroupPayoutRowType::Coinbase);
    }

    #[test]
    fn pending_row_marks_zero_share_counts() {
        let row = pending_row(AddressId::new("bc1qbar").unwrap(), Sats(1_500));
        assert_eq!(row.percent, 0.0);
        assert_eq!(row.shares_in_round, 0);
        assert_eq!(row.total_shares_in_round, 0);
        assert_eq!(row.row_type, GroupPayoutRowType::Pending);
        assert_eq!(row.paid_sats.0, 1_500);
    }
}
