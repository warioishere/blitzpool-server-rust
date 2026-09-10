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

/// Candidate rows for the dust-sweep cron: abandoned credits, plus
/// every debit as a possible counterparty.
///
/// **The cutoff is a property of the CREDIT side only.** A debit is not
/// judged for abandonment — it is the other half of a pair-cancel, and
/// requiring it to be silent too is what kept the sweep from ever
/// firing. A credit exists because a miner was withheld (below
/// `min_payout`, or folded by the blockspace cut); §4 hands that value
/// to the miners who ARE published in the same block, and they carry
/// the matching debit. The counterparty is therefore, by construction,
/// someone who was mining at the time — and usually still is. Filtering
/// both sides by the same inactivity window excluded exactly the rows
/// that owe the credit.
///
/// Selects rows where `balanceSats != 0` and either:
/// - `balanceSats < 0` — any debit, any age, `lastAcceptedShareAt` may
///   be NULL (it is not a claim about the debit's owner), or
/// - `lastAcceptedShareAt IS NOT NULL AND < cutoff_ms` — a credit whose
///   owner has been silent past the abandoned-days window. NULL stays
///   excluded on this side: no signal means "active until proven
///   otherwise", and writing off a claim needs proof.
///
/// Pairing keeps `Σ balanceSats` at 0 whichever rows meet, so widening
/// the counterparty set cannot make the ledger drift.
///
/// Consumer: `bp-pplns-engine::sweep::DustSweepRunner`.
pub async fn find_pplns_sweep_candidates(
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
             AND ("balanceSats" < 0
                  OR ("lastAcceptedShareAt" IS NOT NULL
                      AND "lastAcceptedShareAt" < $1))"#,
        cutoff_ms,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Guarded single-column UPDATE of `balanceSats`: writes `new_balance`
/// **only if** the row still holds `expected`. Returns `false` when it
/// does not — the row moved since the caller read it, and the absolute
/// value it computed would silently undo whatever moved it.
///
/// The dust sweep needs this because it reads its whole candidate set
/// ONCE per run and then commits pair by pair, so its view of every
/// not-yet-processed row is stale from the start of the run. The other
/// writer is the block-found settlement, which locks the rows it settles
/// (`find_pplns_balances_for_addresses_locked`); this is the matching
/// half from the sweep's side, where locking the whole candidate set for
/// the length of a run would be worse than the race.
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

/// Bulk-load `pplns_balance` rows for a set of addresses **inside a
/// transaction, with the rows locked** (`FOR UPDATE`).
///
/// The block-found settlement is a read-modify-write: it reads
/// `balanceSats`, adds its delta and writes the sum back absolutely. With
/// the read outside the writing transaction, anything that touched the row
/// in between is silently undone — and there IS another writer, the daily
/// dust sweep, whose target set (open balance, no recent shares) is
/// exactly the balance-only entries every distribution carries.
///
/// `ORDER BY address` is not cosmetic. `FOR UPDATE` locks rows as the plan
/// emits them, and the `LockRows` node sits above the `Sort`, so the
/// ordering fixes the lock ACQUISITION order. Without it two transactions
/// touching the same two rows from different directions deadlock, and
/// Postgres aborts one of them. Every other locker of this table must take
/// its rows in the same ascending-address order.
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

/// Bulk-load `pplns_balance` rows for a set of addresses in one round
/// trip (`address = ANY(...)`), UNLOCKED. Addresses with no row are simply
/// absent from the result; order is unspecified (callers index by address).
///
/// Read-only callers only. Anything that reads a balance in order to write
/// it back must use [`find_pplns_balances_for_addresses_locked`] inside the
/// writing transaction.
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
    /// Credit whose owner has been silent past the cutoff — what the next
    /// sweep tries to close.
    pub abandoned_credit_sats: i64,
    /// Debit whose owner has been silent past the cutoff.
    ///
    /// ⚠️ **Not** the sweep's counterparty pool — that is
    /// [`Self::debit_sats`], every open debit regardless of age. Keeping the
    /// cutoff on this side is deliberate: the figure answers "how much of the
    /// debt is itself abandoned", which is worth seeing, but it must not be
    /// read as "how much the sweep can pair". See
    /// [`find_pplns_sweep_candidates`] for why the two differ.
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

/// The VALUE-BEARING payout rows already recorded at `block_height`, as
/// `(address, paidSats)` sorted for comparison.
///
/// This is what tells a harmless replay apart from a second, DIFFERENT
/// block at the same height. `pplns_payout_history` has no `blockHash`
/// column and is UNIQUE on `(blockHeight, address)`, so height is the only
/// identity a booked block has, so a plain `EXISTS` on the height cannot
/// say WHICH block it saw. That is what this replaces.
///
/// Rows with `paidSats = 0` are excluded on purpose: those are the
/// "late arriver" rows the apply writes for addresses live in the window
/// but absent from the distribution, and the window moves between attempts.
/// Including them would make every legitimate replay look like a different
/// block. What remains is block-determined — the coinbase payments and the
/// non-zero settlement deltas both follow from the found block's own
/// coinbase and its frozen snapshot — so it is identical on a replay of the
/// same block and differs for another one.
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
