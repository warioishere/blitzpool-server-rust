// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-Solo payout history (`pplns_group_block_history`). Group-Solo owes
//! nothing after the coinbase, so these rows are a record, never an obligation,
//! and a redelivered block-found is a no-op via the UNIQUE
//! `(groupId, blockHeight, address)` index.

use bp_common::{AddressId, Sats};
use bp_db::{bulk_insert_pplns_group_block_history, GroupPayoutHistoryInsert};
use sqlx::PgPool;
use uuid::Uuid;

use bp_coinbase_snapshot::PayoutRowType;
pub use bp_coinbase_snapshot::{ApplyDistributionResult, LedgerError};

/// One row in the payout history, always a coinbase payment: Group-Solo books
/// nothing besides what the coinbase paid. `sharesInRound` +
/// `totalSharesInRound` record the round split the coinbase was built from.
#[derive(Clone, Debug)]
pub struct AuditRow {
    pub address: AddressId,
    pub paid_sats: Sats,
    pub percent: f32,
    pub shares_in_round: i64,
    pub total_shares_in_round: i64,
}

/// Write one block's payout history for one group in one transaction. A
/// redelivered block-found inserts nothing and reports `history_inserted == 0`.
pub async fn apply_distribution(
    pool: &PgPool,
    group_id: Uuid,
    block_height: i32,
    rows: &[AuditRow],
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
            row_type: PayoutRowType::Coinbase.as_wire().to_string(),
            created_at_ms: now_ms,
        })
        .collect();

    let history_inserted = bulk_insert_pplns_group_block_history(&mut *tx, &history_rows).await?;

    tx.commit().await?;
    Ok(ApplyDistributionResult {
        history_inserted,
        balances_affected: 0,
    })
}
