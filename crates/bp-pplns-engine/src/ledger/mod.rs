// SPDX-License-Identifier: AGPL-3.0-or-later

//! Postgres signed ledger: `pplns_balance` (> 0 owed to the miner, < 0 owed
//! by the miner, absolute writes) and `pplns_payout_history`, both written in
//! one transaction per block by [`apply_distribution`]. [`touch_buffer`]
//! batches the hot-path `lastAcceptedShareAt` writes.

pub mod touch_buffer;

use bp_common::{AddressId, Sats};
use bp_db::{
    bulk_insert_pplns_payout_history, bulk_upsert_pplns_balances, BalanceUpsert,
    PayoutHistoryInsert,
};

pub use bp_db::TouchUpdate;
// Shared with Group-Solo.
pub use bp_coinbase_snapshot::{ApplyDistributionResult, LedgerError, PayoutRowType};

/// One audit row, built from the block's own coinbase settled against the
/// snapshot: per address paid, and per ledger delta that stayed off-chain.
/// Every row moves value; an address the block left untouched gets none.
#[derive(Clone, Debug)]
pub struct AuditRow {
    pub address: AddressId,
    pub paid_sats: Sats,
    pub percent: f32,
    pub row_type: PayoutRowType,
}

/// A signed ledger delta with no on-chain output, hence 0 percent.
pub fn pending_row(address: AddressId, delta_sats: Sats) -> AuditRow {
    AuditRow {
        address,
        paid_sats: delta_sats,
        percent: 0.0,
        row_type: PayoutRowType::Pending,
    }
}

// ── apply_distribution — the block-found TX ─────────────────────────

/// Book one block: audit rows plus absolute balances. An already-booked height
/// writes nothing, since a replay would re-apply `current + delta` and pay twice.
/// Runs in the caller's transaction, which must hold
/// [`bp_db::take_pplns_settlement_lock`] and the rows under
/// [`bp_db::find_pplns_balances_for_addresses_locked`].
pub async fn apply_distribution(
    tx: &mut sqlx::PgConnection,
    block_height: i32,
    rows: &[AuditRow],
    balances: &[BalanceWrite],
    now_ms: i64,
) -> Result<ApplyDistributionResult, LedgerError> {
    // Height is the only identity of a booked block. Existing history is a
    // redelivery (passes silently) or a reorged block (must not be skipped
    // silently); identical rows mean replaying moves nothing.
    let booked = bp_db::pplns_booked_rows_at_height(&mut *tx, block_height).await?;
    if !booked.is_empty() {
        let mut want: Vec<(String, i64)> = rows
            .iter()
            .map(|r| (r.address.as_str().to_string(), r.paid_sats.0))
            .collect();
        want.sort();
        if booked == want {
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

    // Past the gate the height has no history; `ON CONFLICT DO NOTHING` is
    // only a backstop.
    let history_inserted = bulk_insert_pplns_payout_history(&mut *tx, &history_rows).await?;
    let balances_affected = bulk_upsert_pplns_balances(&mut *tx, &balance_rows).await?;

    Ok(ApplyDistributionResult {
        history_inserted,
        balances_affected,
    })
}

/// Absolute new balance for one address. Separate from [`AuditRow`]: a block
/// can touch a balance without a history row and vice versa.
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
    fn pending_row_marks_zero_percent() {
        let row = pending_row(AddressId::new("bc1qbar").unwrap(), Sats(-2_500));
        assert_eq!(row.percent, 0.0);
        assert_eq!(row.paid_sats.0, -2_500);
        assert_eq!(row.row_type, PayoutRowType::Pending);
    }
}
