// SPDX-License-Identifier: AGPL-3.0-or-later

//! PPLNS signed-ledger and payout history.
//!
//! - `pplns_balance` — signed `balanceSats` ledger (positive = pool-owes; negative = miner-owes)
//! - `pplns_payout_history` — idempotent block-payout audit log (UNIQUE blockHeight+address)

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

/// Abandoned-balance candidate rows for the dust-sweep cron.
///
/// Selects rows where:
/// - `balanceSats != 0` (open claim, credit or debit)
/// - `lastAcceptedShareAt IS NOT NULL` (NULL means pre-migration row
///   with no signal — treated as "active until proven otherwise")
/// - `lastAcceptedShareAt < cutoff_ms` (older than abandoned-days)
///
/// Consumer: `bp-pplns-engine::sweep::DustSweepRunner`.
pub async fn find_pplns_balances_abandoned(
    pool: &PgPool,
    cutoff_ms: i64,
) -> Result<Vec<PplnsBalanceRow>, DbError> {
    sqlx::query_as!(
        PplnsBalanceRow,
        r#"SELECT
            address AS "address!: AddressId",
            "balanceSats" AS "balance_sats!: Sats",
            "totalPaidSats" AS "total_paid_sats!: Sats",
            "updatedAt" AS "updated_at!",
            "lastAcceptedShareAt" AS "last_accepted_share_at?"
           FROM pplns_balance
           WHERE "balanceSats" <> 0
             AND "lastAcceptedShareAt" IS NOT NULL
             AND "lastAcceptedShareAt" < $1"#,
        cutoff_ms,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// DELETE one `pplns_balance` row by address. Returns the affected
/// row count (0 if missing, 1 on success). Used by the dust-sweep
/// when a pair-cancel zeros the balance — the row is fully removed
/// from the ledger.
pub async fn delete_pplns_balance<'e, E>(executor: E, address: &AddressId) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"DELETE FROM pplns_balance WHERE address = $1"#,
        address.as_str(),
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Single-column UPDATE of `balanceSats` for one address.
///
/// Distinct from [`bulk_upsert_pplns_balances`] because the dust-sweep
/// reduces a balance toward zero (or the remainder side of a pair)
/// without touching `totalPaidSats` or `updatedAt` — those are
/// preserved at their existing values.
pub async fn update_pplns_balance_sats<'e, E>(
    executor: E,
    address: &AddressId,
    new_balance_sats: Sats,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE pplns_balance SET "balanceSats" = $1 WHERE address = $2"#,
        new_balance_sats.to_i64(),
        address.as_str(),
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// All `pplns_balance` rows with a non-zero `balanceSats` (open
/// claim — credit or debit). Consumed by
/// `bp-pplns-engine::distribution::DistributionBuilder` so it can
/// factor open claims in either direction into the next block's
/// distribution.
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

/// Bulk-load `pplns_balance` rows for a set of addresses in one round
/// trip (`address = ANY(...)`). Used by `apply_distribution`'s
/// snapshot→writes mapping on the block-found path to replace a
/// per-address `find_pplns_balance` N+1. Addresses with no row are
/// simply absent from the result; order is unspecified (callers index
/// by address).
pub async fn find_pplns_balances_for_addresses(
    pool: &PgPool,
    addresses: &[String],
) -> Result<Vec<PplnsBalanceRow>, DbError> {
    sqlx::query_as!(
        PplnsBalanceRow,
        r#"SELECT
            address AS "address!: AddressId",
            "balanceSats" AS "balance_sats!: Sats",
            "totalPaidSats" AS "total_paid_sats!: Sats",
            "updatedAt" AS "updated_at!",
            "lastAcceptedShareAt" AS "last_accepted_share_at?"
           FROM pplns_balance WHERE address = ANY($1::text[])"#,
        addresses
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Aggregate roll-up of the `pplns_balance` table — credits, debits,
/// row counts, abandoned-bucket subtotals and lifetime payout — all
/// in one PG round-trip. Replaces the previous pattern of fetching
/// every non-zero balance row into Rust and aggregating client-side
/// (which moved ~5-15 MB across the wire per call on a pool with
/// accumulated historical addresses).
#[derive(Clone, Copy, Debug, Default)]
pub struct PplnsBalanceAggregate {
    pub credit_sats: i64,
    pub debit_sats: i64,
    pub credit_row_count: i64,
    pub debit_row_count: i64,
    pub abandoned_credit_sats: i64,
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

#[derive(Clone, Debug, FromRow)]
pub struct PplnsPayoutHistoryRow {
    pub id: i32,
    #[sqlx(rename = "blockHeight")]
    pub block_height: i32,
    pub address: AddressId,
    #[sqlx(rename = "paidSats")]
    pub paid_sats: Sats,
    pub percent: f32,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    /// Discriminator for the row-source: `"coinbase"`, `"fee"`, `"bonus"`,
    /// `"trim"`, `"sub-dust"`, …  (kept as raw `String` because the value
    /// set evolves with PPLNS distribution phases — not worth a typed enum
    /// at the data layer).
    #[sqlx(rename = "rowType")]
    pub row_type: String,
}

pub async fn find_pplns_payout_history(
    pool: &PgPool,
    id: i32,
) -> Result<Option<PplnsPayoutHistoryRow>, DbError> {
    sqlx::query_as!(
        PplnsPayoutHistoryRow,
        r#"SELECT
            id AS "id!",
            "blockHeight" AS "block_height!",
            address AS "address!: AddressId",
            "paidSats" AS "paid_sats!: Sats",
            percent AS "percent!",
            "createdAt" AS "created_at!",
            "rowType" AS "row_type!"
           FROM pplns_payout_history WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

// ── Bulk writes ──────────────────────────────────────────────────────
//
// Consumer: `bp-pplns-engine::ledger::apply_distribution` writes both
// `pplns_payout_history` (audit log) and `pplns_balance` (signed ledger)
// inside one PG transaction. The functions below are the primitives;
// the engine composes them with `pool.begin()` / `tx.commit()`.

/// Absolute upsert into `pplns_balance` — sets each row's
/// `balanceSats`, `totalPaidSats`, and `updatedAt` to the caller-
/// provided value. Idempotent: running the same input twice converges
/// to the same row state.
///
/// Idempotency contract: callers compute `balance_sats` and
/// `total_paid_sats` from the *current* row state plus the block's
/// per-address delta, then call this with those absolute values. The
/// signed-ledger guarantee (Σ balanceSats ≈ 0 in a steady pool) holds
/// across the write because nothing else mutates these columns on the
/// hot path.
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

/// Bulk UPDATE of `lastAcceptedShareAt` for the rows whose addresses
/// match the input. Rows that don't exist yet are left alone — the
/// abandoned-balance sweep has nothing to act on for a miner without a
/// balance row, so a missing row is a no-op.
///
/// Consumer: the 60-second touch-buffer flush in
/// `bp-pplns-engine::ledger::touch_buffer`.
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

/// Bulk-insert payout-history rows for one block. `ON CONFLICT
/// ("blockHeight", address) DO NOTHING` guards against double-write on
/// replay — a partial-success / restart-mid-processing scenario won't
/// duplicate audit rows.
///
/// The dust-sweep cron reuses this with synthetic negative `blockHeight`
/// values (e.g. `-unix_seconds`) so audit rows for sweep pair-cancels
/// share the same UNIQUE-constraint protection without colliding with
/// real block heights.
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
