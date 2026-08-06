// SPDX-License-Identifier: AGPL-3.0-or-later

//! Block-found history and RPC block-hex cache.
//!
//! - `blocks_entity` — append-only block-find log
//! - `rpc_block_entity` — block-hex cache keyed by height with optional `lockedBy`

use bp_common::AddressId;
use sqlx::{postgres::PgPool, FromRow};

use crate::DbError;

#[derive(Clone, Debug, FromRow)]
pub struct BlocksRow {
    #[sqlx(rename = "deletedAt")]
    pub deleted_at: Option<i64>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    pub id: i32,
    pub height: i64,
    #[sqlx(rename = "minerAddress")]
    pub miner_address: AddressId,
    pub worker: String,
    #[sqlx(rename = "sessionId")]
    pub session_id: String,
    #[sqlx(rename = "blockData")]
    pub block_data: String,
}

/// Subset of `blocks_entity` columns surfaced by `/api/info` →
/// `blockData`. Selects the four fields the pool-info endpoint needs
/// so the wire shape stays stable.
#[derive(Clone, Debug, FromRow)]
pub struct FoundBlockRow {
    pub height: i64,
    #[sqlx(rename = "minerAddress")]
    pub miner_address: String,
    pub worker: String,
    #[sqlx(rename = "sessionId")]
    pub session_id: String,
}

/// Append a found-block record. Called once per accepted block after
/// the solution is submitted to bitcoin-core. `block_data` stores the
/// 80-byte header hex (little-endian); the column is append-only and
/// not surfaced via any public API endpoint.
pub async fn insert_found_block<'e, E>(
    executor: E,
    height: i64,
    miner_address: &str,
    worker: &str,
    session_id: &str,
    block_data: &str,
) -> Result<(), DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        r#"INSERT INTO blocks_entity
             (height, "minerAddress", worker, "sessionId", "blockData")
           VALUES ($1, $2, $3, $4, $5)"#,
        height,
        miner_address,
        worker,
        session_id,
        block_data,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

/// The miner address the pool recorded for the block at `height`, or `None`
/// when it has no record of one.
///
/// The chain→ledger reconciliation asks this about a block whose coinbase
/// pays the pool: `None` means the pool mined it and never registered it, and
/// the address it returns resolves the payout mode, which decides whether a
/// missing payout row is a fault or normal (Solo keeps no ledger).
/// Dev-seed rows are excluded for the same reason `find_found_blocks`
/// excludes them — a bootstrap fixture is not evidence of a real block.
pub async fn found_block_miner_at_height(
    pool: &PgPool,
    height: i64,
) -> Result<Option<String>, DbError> {
    sqlx::query_scalar!(
        r#"SELECT "minerAddress" AS "miner_address!"
           FROM blocks_entity
           WHERE height = $1 AND "minerAddress" NOT LIKE 'synthseed%'
           LIMIT 1"#,
        height,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// `true` when some payout ledger recorded a distribution for `height`.
///
/// Distinct from [`found_block_miner_at_height`], and the distinction is the
/// point: `blocks_entity` is written by the front the moment a block is
/// found, *before* any ledger applies. A block whose distribution then fails
/// to book has the `blocks_entity` row and no payout rows — the exact shape of
/// a miss. Only the payout tables are evidence that miners were credited.
///
/// Solo blocks legitimately have no row here: they pay directly in the
/// coinbase and keep no ledger. Callers must not treat their absence as a
/// miss without first checking that the coinbase paid nobody else.
///
/// **A row is not an accounting.** Every clause requires a row that moved
/// VALUE, because a block can produce rows that account for nothing. The
/// PPLNS apply writes a 0-sat `pending` row for every address that is live
/// in the window but absent from the block's distribution ("late
/// arrivers"), so a distribution that paid nobody at all still leaves rows
/// behind — measured on a block whose coinbase paid 100 % to the pool
/// output: no miner claim, no miner payment, and a `history_inserted`
/// greater than zero. Under a plain `EXISTS` that block reads as booked
/// and this check, which exists to find exactly that, stays silent.
pub async fn payout_recorded_at_height(pool: &PgPool, height: i32) -> Result<bool, DbError> {
    let found = sqlx::query_scalar!(
        r#"SELECT (
             EXISTS (
               SELECT 1 FROM pplns_payout_history
               WHERE "blockHeight" = $1 AND "paidSats" <> 0
             )
             OR EXISTS (
               SELECT 1 FROM pplns_group_block_history
               WHERE "blockHeight" = $1 AND "paidSats" <> 0
             )
             OR EXISTS (
               SELECT 1 FROM blockparty_block_history
               WHERE "blockHeight" = $1 AND "coinbaseValueSats" <> 0
             )
           ) AS "exists!""#,
        height,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)?;
    Ok(found)
}

/// All rows from `blocks_entity` projected down to
/// `{height, minerAddress, worker, sessionId}`. No WHERE, no ORDER BY —
/// Uses `query_as` (no `.sqlx` metadata required for the untyped
/// projection).
pub async fn find_found_blocks(pool: &PgPool) -> Result<Vec<FoundBlockRow>, DbError> {
    // Filter out dev-seed rows (`synthseed*` miner addresses from
    // bootstrap fixtures); they have no payout value and would
    // leak into /api/info blockData / /api/pool blocksFound tiles
    // on a fresh test database.
    sqlx::query_as!(
        FoundBlockRow,
        r#"SELECT height AS "height!",
                  "minerAddress" AS "miner_address!",
                  worker AS "worker!",
                  "sessionId" AS "session_id!"
           FROM blocks_entity
           WHERE "minerAddress" NOT LIKE 'synthseed%'"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

pub async fn find_block(pool: &PgPool, id: i32) -> Result<Option<BlocksRow>, DbError> {
    sqlx::query_as!(
        BlocksRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            height AS "height!",
            "minerAddress" AS "miner_address!: AddressId",
            worker AS "worker!",
            "sessionId" AS "session_id!",
            "blockData" AS "block_data!"
           FROM blocks_entity WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct RpcBlockRow {
    #[sqlx(rename = "blockHeight")]
    pub block_height: i64,
    #[sqlx(rename = "lockedBy")]
    pub locked_by: Option<String>,
    pub data: Option<String>,
}

/// Hard-delete all `rpc_block_entity` rows except the one with the
/// highest `blockHeight`. The table is a short-lived block-hex cache;
/// only the current tip is ever needed, so older entries are pruned
/// on the daily cleanup cron.
pub async fn delete_old_rpc_blocks<'e, E>(executor: E) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query!(
        r#"DELETE FROM rpc_block_entity
           WHERE "blockHeight" < (SELECT MAX("blockHeight") FROM rpc_block_entity)"#
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(r.rows_affected())
}

pub async fn find_rpc_block(
    pool: &PgPool,
    block_height: i64,
) -> Result<Option<RpcBlockRow>, DbError> {
    sqlx::query_as!(
        RpcBlockRow,
        r#"SELECT
            "blockHeight" AS "block_height!",
            "lockedBy" AS "locked_by?",
            data AS "data?"
           FROM rpc_block_entity WHERE "blockHeight" = $1 LIMIT 1"#,
        block_height
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}
