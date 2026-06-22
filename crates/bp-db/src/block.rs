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
