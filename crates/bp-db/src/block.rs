// SPDX-License-Identifier: AGPL-3.0-or-later

//! Block-found history: `blocks_entity`, an append-only block-find log.

use bp_common::MiningMode;
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

/// One found block as the front records it.
#[derive(Clone, Copy, Debug)]
pub struct FoundBlockInsert<'a> {
    pub height: i64,
    pub miner_address: &'a str,
    pub worker: &'a str,
    pub session_id: &'a str,
    /// The 80-byte header hex; never exposed by the API.
    pub block_data: &'a str,
    /// The payout mode the block was mined in; `None` when it is not known.
    pub mode: Option<MiningMode>,
}

/// Append a found-block record once the solution is submitted. Idempotent per
/// block (height and header): a redelivered find writes no second row.
pub async fn insert_found_block<'e, E>(
    executor: E,
    found: FoundBlockInsert<'_>,
) -> Result<(), DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        r#"INSERT INTO blocks_entity
             (height, "minerAddress", worker, "sessionId", "blockData", mode)
           SELECT $1::bigint, $2::varchar, $3::varchar, $4::varchar, $5::varchar,
                  $6::varchar
           WHERE NOT EXISTS (
             SELECT 1 FROM blocks_entity WHERE height = $1 AND "blockData" = $5
           )"#,
        found.height,
        found.miner_address,
        found.worker,
        found.session_id,
        found.block_data,
        found.mode.map(MiningMode::as_str),
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

/// What the pool recorded for the block at `height`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundBlockAtHeight {
    pub miner_address: String,
    /// `None` for a row without a mode the build knows.
    pub mode: Option<MiningMode>,
}

/// The pool's record of the block at `height`, or `None` when it has none.
/// The chain-to-ledger reconciliation reads the mode from it (Solo keeps no
/// ledger). Dev-seed rows are excluded: a bootstrap fixture is not evidence of
/// a real block.
pub async fn found_block_at_height(
    pool: &PgPool,
    height: i64,
) -> Result<Option<FoundBlockAtHeight>, DbError> {
    let row = sqlx::query!(
        r#"SELECT "minerAddress" AS "miner_address!", mode
           FROM blocks_entity
           WHERE height = $1
           LIMIT 1"#,
        height,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)?;
    Ok(row.map(|r| FoundBlockAtHeight {
        miner_address: r.miner_address,
        // A mode this build does not know reads as unknown, like a row
        // without one.
        mode: r.mode.and_then(|m| m.parse().ok()),
    }))
}

/// `true` when a payout ledger booked value for `height`; unlike
/// [`found_block_at_height`] this proves miners were credited. Only rows
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

/// When the pool's latest block was found, in Unix ms; `None` before the first.
pub async fn last_found_block_at(pool: &PgPool) -> Result<Option<i64>, DbError> {
    sqlx::query_scalar!(r#"SELECT MAX("createdAt") FROM blocks_entity"#)
        .fetch_one(pool)
        .await
        .map_err(DbError::from)
}

/// All rows from `blocks_entity` projected down to
/// `{height, minerAddress, worker, sessionId}`, unordered.
pub async fn find_found_blocks(pool: &PgPool) -> Result<Vec<FoundBlockRow>, DbError> {
    sqlx::query_as!(
        FoundBlockRow,
        r#"SELECT height AS "height!",
                  "minerAddress" AS "miner_address!",
                  worker AS "worker!",
                  "sessionId" AS "session_id!"
           FROM blocks_entity"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}
