// SPDX-License-Identifier: AGPL-3.0-or-later

//! Block-found history: `blocks_entity`, an append-only block-find log.

use sqlx::{postgres::PgPool, FromRow};

use crate::DbError;

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

/// Append a found-block record once the solution is submitted. `block_data`
/// is the 80-byte header hex and is never exposed by the API.
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
/// when it has no record of one. The chain-to-ledger reconciliation uses the
/// address to resolve the payout mode (Solo keeps no ledger). Dev-seed rows
/// are excluded: a bootstrap fixture is not evidence of a real block.
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

/// `true` when a payout ledger booked value for `height`; unlike
/// [`found_block_miner_at_height`] this proves miners were credited. Only rows
/// that moved value count. Solo blocks keep no ledger, so their absence here
/// is not a miss.
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
/// `{height, minerAddress, worker, sessionId}`, unordered.
pub async fn find_found_blocks(pool: &PgPool) -> Result<Vec<FoundBlockRow>, DbError> {
    // Dev-seed rows (`synthseed*`) are bootstrap fixtures and must not show
    // up as found blocks in the API.
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
