// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shares originating from external pools / solo-miners (`/api/external-share`).

use bp_common::AddressId;
use sqlx::{postgres::PgPool, FromRow};

use crate::DbError;

#[derive(Clone, Debug, FromRow)]
pub struct ExternalSharesRow {
    #[sqlx(rename = "deletedAt")]
    pub deleted_at: Option<i64>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    pub id: i32,
    pub address: AddressId,
    #[sqlx(rename = "clientName")]
    pub client_name: String,
    pub time: i64,
    pub difficulty: f32,
    #[sqlx(rename = "userAgent")]
    pub user_agent: Option<String>,
    #[sqlx(rename = "externalPoolName")]
    pub external_pool_name: Option<String>,
    /// Block-header hex of the share submission, used when promoting an
    /// external share to a block-find (rare, but supported).
    pub header: String,
}

pub async fn find_external_share(
    pool: &PgPool,
    id: i32,
) -> Result<Option<ExternalSharesRow>, DbError> {
    sqlx::query_as!(
        ExternalSharesRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            "time" AS "time!",
            difficulty AS "difficulty!",
            "userAgent" AS "user_agent?",
            "externalPoolName" AS "external_pool_name?",
            header AS "header!"
           FROM external_shares_entity WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

// ── Writes for `/api/share` POST ────────────────────────────────────

/// Insert one external-share row. Returns the inserted row including
/// the server-side `createdAt` / `updatedAt`.
#[allow(clippy::too_many_arguments)]
pub async fn insert_external_share(
    pool: &PgPool,
    address: &AddressId,
    client_name: &str,
    time_ms: i64,
    difficulty: f32,
    user_agent: Option<&str>,
    external_pool_name: Option<&str>,
    header: &str,
) -> Result<ExternalSharesRow, DbError> {
    sqlx::query_as!(
        ExternalSharesRow,
        r#"INSERT INTO external_shares_entity
             (address, "clientName", "time", difficulty,
              "userAgent", "externalPoolName", header)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            "time" AS "time!",
            difficulty AS "difficulty!",
            "userAgent" AS "user_agent?",
            "externalPoolName" AS "external_pool_name?",
            header AS "header!""#,
        address.as_str(),
        client_name,
        time_ms,
        difficulty,
        user_agent,
        external_pool_name,
        header,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// Per-address top-10 external-share leaderboard. Groups by address,
/// returns each address's max(difficulty) along with the userAgent /
/// externalPoolName / time of the share that achieved that max.
/// Ordered by max-difficulty descending, 10 entries cap.
#[derive(Clone, Debug)]
pub struct ExternalShareTopDifficulty {
    pub user_agent: Option<String>,
    pub time: i64,
    pub external_pool_name: Option<String>,
    pub difficulty: f32,
}

pub async fn find_external_share_top_difficulties(
    pool: &PgPool,
) -> Result<Vec<ExternalShareTopDifficulty>, DbError> {
    // Groups by address and returns the tuple per group with the highest
    // difficulty, along with its per-row metadata columns. Uses a
    // window-style `DISTINCT ON (address)` ordered by difficulty so PG
    // picks the single row per address with the highest difficulty.
    sqlx::query_as!(
        ExternalShareTopDifficulty,
        r#"SELECT
            "userAgent" AS user_agent,
            "time" AS "time!",
            "externalPoolName" AS external_pool_name,
            difficulty AS "difficulty!"
           FROM (
             SELECT DISTINCT ON (address)
                address,
                "userAgent",
                "time",
                "externalPoolName",
                difficulty
             FROM external_shares_entity
             WHERE "deletedAt" IS NULL
             ORDER BY address, difficulty DESC
           ) t
           ORDER BY difficulty DESC
           LIMIT 10"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}
