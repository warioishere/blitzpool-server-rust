// SPDX-License-Identifier: AGPL-3.0-or-later

//! PPLNS signed ledger (`pplns_balance`: positive = pool owes, negative =
//! miner owes) and the idempotent payout history.

use bp_common::{AddressId, Sats};
use sqlx::{postgres::PgPool, FromRow};

use crate::DbError;

#[derive(Clone, Debug, FromRow)]
pub struct PplnsBalanceRow {
    pub address: AddressId,
    #[sqlx(rename = "balanceSats")]
    pub balance_sats: Sats,
    #[sqlx(rename = "totalPaidSats")]
    pub total_paid_sats: Sats,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    #[sqlx(rename = "lastAcceptedShareAt")]
    pub last_accepted_share_at: Option<i64>,
}

/// Writes `new_balance` only if the row still holds `expected`; `false` means
/// the row moved and the absolute write would undo that change. The dust
/// sweep reads its candidates once per run, so its view goes stale; locking
/// them for the whole run would be worse than this compare-and-set.
pub async fn update_pplns_balance_sats_if_unchanged<'e, E>(
    executor: E,
    address: &AddressId,
    expected: Sats,
    new_balance: Sats,
) -> Result<bool, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE pplns_balance SET "balanceSats" = $1
           WHERE address = $2 AND "balanceSats" = $3"#,
        new_balance.0,
        address.as_str(),
        expected.0,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected() > 0)
}

/// All `pplns_balance` rows with an open claim (non-zero `balanceSats`), read
/// by both the distribution builder and the dust sweep. Deliberately not
/// filtered by `lastAcceptedShareAt`: "abandoned" is judged only in
/// `bp-pplns-engine::sweep`, so that test has one implementation.
pub async fn find_pplns_balances_with_open_balance(
    pool: &PgPool,
) -> Result<Vec<PplnsBalanceRow>, DbError> {
    sqlx::query_as!(
        PplnsBalanceRow,
        r#"SELECT
            address AS "address!: AddressId",
            "balanceSats" AS "balance_sats!: Sats",
            "totalPaidSats" AS "total_paid_sats!: Sats",
            "updatedAt" AS "updated_at!",
            "lastAcceptedShareAt" AS "last_accepted_share_at?"
           FROM pplns_balance WHERE "balanceSats" <> 0"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

pub async fn find_pplns_balance(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Option<PplnsBalanceRow>, DbError> {
    sqlx::query_as!(
        PplnsBalanceRow,
        r#"SELECT
            address AS "address!: AddressId",
            "balanceSats" AS "balance_sats!: Sats",
            "totalPaidSats" AS "total_paid_sats!: Sats",
            "updatedAt" AS "updated_at!",
            "lastAcceptedShareAt" AS "last_accepted_share_at?"
           FROM pplns_balance WHERE address = $1 LIMIT 1"#,
        address.as_str()
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// Advisory lock serialising PPLNS settlements across processes. A settlement
/// writes absolute balances, and `FOR UPDATE` cannot lock the row of an
/// address that has none yet, so two settlements crediting the same new miner
/// would otherwise keep only one of the credits.
pub const PPLNS_SETTLEMENT_LOCK: i64 = 0x7070_6c6e_7373; // "pplnss"

/// Take [`PPLNS_SETTLEMENT_LOCK`] for the rest of `tx`. Every settlement takes
/// it before reading balances.
pub async fn take_pplns_settlement_lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), DbError> {
    crate::pool::take_xact_lock(tx, PPLNS_SETTLEMENT_LOCK).await
}

/// Load balances `FOR UPDATE` inside the settlement's transaction: it writes
/// back absolute sums, so an unlocked read would undo a concurrent dust sweep.
/// `ORDER BY address` fixes lock acquisition order to avoid deadlocks; every
/// other locker of this table must lock in ascending-address order too.
pub async fn find_pplns_balances_for_addresses_locked<'e, E>(
    executor: E,
    addresses: &[String],
) -> Result<Vec<PplnsBalanceRow>, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        PplnsBalanceRow,
        r#"SELECT
            address AS "address!: AddressId",
            "balanceSats" AS "balance_sats!: Sats",
            "totalPaidSats" AS "total_paid_sats!: Sats",
            "updatedAt" AS "updated_at!",
            "lastAcceptedShareAt" AS "last_accepted_share_at?"
           FROM pplns_balance
           WHERE address = ANY($1::text[])
           ORDER BY address
           FOR UPDATE"#,
        addresses
    )
    .fetch_all(executor)
    .await
    .map_err(DbError::from)
}

/// Aggregate roll-up of the `pplns_balance` table — credits, debits,
/// row counts, abandoned-bucket subtotals and lifetime payout — all
/// in one PG round-trip, so no balance rows cross the wire.
#[derive(Clone, Copy, Debug, Default)]
pub struct PplnsBalanceAggregate {
    pub credit_sats: i64,
    pub debit_sats: i64,
    pub credit_row_count: i64,
    pub debit_row_count: i64,
    /// Credit whose owner has been silent past the cutoff — what the next
    /// sweep tries to close.
    pub abandoned_credit_sats: i64,
    /// Debit whose owner has been silent past the cutoff. Not what the sweep
    /// can pair against: that is [`Self::debit_sats`], since the sweep judges
    /// only the credit side.
    pub abandoned_debit_sats: i64,
    pub lifetime_paid_sats: i64,
}

pub async fn aggregate_pplns_balances(
    pool: &PgPool,
    abandoned_cutoff_ms: i64,
) -> Result<PplnsBalanceAggregate, DbError> {
    let row = sqlx::query!(
        r#"SELECT
             COALESCE(SUM(CASE WHEN "balanceSats" > 0
                               THEN "balanceSats" END), 0)::bigint
               AS "credit!",
             COALESCE(SUM(CASE WHEN "balanceSats" < 0
                               THEN -"balanceSats" END), 0)::bigint
               AS "debit!",
             COUNT(*) FILTER (WHERE "balanceSats" > 0)::bigint
               AS "credit_rows!",
             COUNT(*) FILTER (WHERE "balanceSats" < 0)::bigint
               AS "debit_rows!",
             COALESCE(SUM(CASE WHEN "balanceSats" > 0
                                AND "lastAcceptedShareAt" IS NOT NULL
                                AND "lastAcceptedShareAt" < $1
                               THEN "balanceSats" END), 0)::bigint
               AS "abandoned_credit!",
             COALESCE(SUM(CASE WHEN "balanceSats" < 0
                                AND "lastAcceptedShareAt" IS NOT NULL
                                AND "lastAcceptedShareAt" < $1
                               THEN -"balanceSats" END), 0)::bigint
               AS "abandoned_debit!",
             COALESCE(SUM("totalPaidSats"), 0)::bigint
               AS "lifetime_paid!"
           FROM pplns_balance"#,
        abandoned_cutoff_ms,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)?;

    Ok(PplnsBalanceAggregate {
        credit_sats: row.credit,
        debit_sats: row.debit,
        credit_row_count: row.credit_rows,
        debit_row_count: row.debit_rows,
        abandoned_credit_sats: row.abandoned_credit,
        abandoned_debit_sats: row.abandoned_debit,
        lifetime_paid_sats: row.lifetime_paid,
    })
}

// ── Bulk writes ──────────────────────────────────────────────────────
// Primitives the ledger apply composes inside one PG transaction.

/// Absolute upsert of `balanceSats`/`totalPaidSats`, so a replay converges.
/// Callers compute the values from the locked current row plus the block's
/// delta.
#[derive(Clone, Debug)]
pub struct BalanceUpsert {
    pub address: String,
    pub balance_sats: i64,
    pub total_paid_sats: i64,
    pub updated_at_ms: i64,
}

pub async fn bulk_upsert_pplns_balances<'e, E>(
    executor: E,
    rows: &[BalanceUpsert],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(0);
    }
    let addresses: Vec<String> = rows.iter().map(|r| r.address.clone()).collect();
    let balances: Vec<i64> = rows.iter().map(|r| r.balance_sats).collect();
    let totals: Vec<i64> = rows.iter().map(|r| r.total_paid_sats).collect();
    let updated: Vec<i64> = rows.iter().map(|r| r.updated_at_ms).collect();

    let result = sqlx::query!(
        r#"INSERT INTO pplns_balance (address, "balanceSats", "totalPaidSats", "updatedAt")
           SELECT * FROM UNNEST($1::text[], $2::bigint[], $3::bigint[], $4::bigint[])
           ON CONFLICT (address) DO UPDATE
           SET "balanceSats"  = EXCLUDED."balanceSats",
               "totalPaidSats" = EXCLUDED."totalPaidSats",
               "updatedAt"     = EXCLUDED."updatedAt""#,
        &addresses,
        &balances,
        &totals,
        &updated,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Bulk UPDATE of `lastAcceptedShareAt`. A missing row is not created: the
/// sweep has nothing to act on for a miner without a balance.
#[derive(Clone, Debug)]
pub struct TouchUpdate {
    pub address: String,
    pub last_accepted_share_at_ms: i64,
}

pub async fn bulk_update_pplns_last_accepted_share_at<'e, E>(
    executor: E,
    rows: &[TouchUpdate],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(0);
    }
    let addresses: Vec<String> = rows.iter().map(|r| r.address.clone()).collect();
    let stamps: Vec<i64> = rows.iter().map(|r| r.last_accepted_share_at_ms).collect();

    let result = sqlx::query!(
        r#"UPDATE pplns_balance AS t
           SET "lastAcceptedShareAt" = u.ts
           FROM (SELECT UNNEST($1::text[]) AS address,
                        UNNEST($2::bigint[]) AS ts) AS u
           WHERE t.address = u.address"#,
        &addresses,
        &stamps,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Non-zero payout rows at `block_height`, sorted, to tell a replay from a
/// different block at the same height (the table has no `blockHash`). Zero
/// "late arriver" rows depend on the moving window, so they are excluded;
/// the rest follows from the block's own coinbase.
pub async fn pplns_booked_value_rows_at_height<'e, E>(
    executor: E,
    block_height: i32,
) -> Result<Vec<(String, i64)>, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows = sqlx::query!(
        r#"SELECT address, "paidSats" AS paid_sats
             FROM pplns_payout_history
            WHERE "blockHeight" = $1 AND "paidSats" <> 0
            ORDER BY address"#,
        block_height,
    )
    .fetch_all(executor)
    .await
    .map_err(DbError::from)?;
    Ok(rows.into_iter().map(|r| (r.address, r.paid_sats)).collect())
}

/// Payout-history rows for one block; `ON CONFLICT DO NOTHING` makes a replay
/// harmless. The dust sweep uses synthetic negative heights so its rows never
/// collide with real blocks.
#[derive(Clone, Debug)]
pub struct PayoutHistoryInsert {
    pub block_height: i32,
    pub address: String,
    pub paid_sats: i64,
    pub percent: f32,
    pub row_type: String,
    pub created_at_ms: i64,
}

pub async fn bulk_insert_pplns_payout_history<'e, E>(
    executor: E,
    rows: &[PayoutHistoryInsert],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(0);
    }
    let heights: Vec<i32> = rows.iter().map(|r| r.block_height).collect();
    let addresses: Vec<String> = rows.iter().map(|r| r.address.clone()).collect();
    let paid: Vec<i64> = rows.iter().map(|r| r.paid_sats).collect();
    let percents: Vec<f32> = rows.iter().map(|r| r.percent).collect();
    let row_types: Vec<String> = rows.iter().map(|r| r.row_type.clone()).collect();
    let created: Vec<i64> = rows.iter().map(|r| r.created_at_ms).collect();

    let result = sqlx::query!(
        r#"INSERT INTO pplns_payout_history
             ("blockHeight", address, "paidSats", percent, "rowType", "createdAt")
           SELECT * FROM UNNEST(
             $1::int[], $2::text[], $3::bigint[], $4::real[], $5::text[], $6::bigint[]
           )
           ON CONFLICT ("blockHeight", address) DO NOTHING"#,
        &heights,
        &addresses,
        &paid,
        &percents,
        &row_types,
        &created,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}
