// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-wide statistics and difficulty tracking.
//!
//! - `pool_share_statistics_entity` — 10-min pool-aggregate (UNIQUE time)
//! - `pool_rejected_statistics_entity` — pool-aggregate rejects (UNIQUE time+reason)
//! - `pool_mode_hashrate` — per-mode hashrate buckets (UNIQUE mode+time)
//! - `network_difficulty_tracker_entity` — singleton via `CHECK (id = 1)`

use bp_common::MiningMode;
use sqlx::{postgres::PgPool, FromRow};

use crate::DbError;

// ── Time-range readers ───────────────────────────────────────────────
//
// Consumed by `bp-api`'s chart / accepted / rejected / workers
// endpoints. Each function returns the raw rows filtered to
// `time >= since_ms`; the API layer does slot-bucket aggregation in
// memory because the right bucket size + format is endpoint-specific.

/// All `pool_share_statistics_entity` rows from `since_ms` onward,
/// ordered by `time ASC`. Drives `/api/info/accepted` and
/// `/api/info/shares`.
pub async fn find_pool_share_statistics_since(
    pool: &PgPool,
    since_ms: i64,
) -> Result<Vec<PoolShareStatisticsRow>, DbError> {
    sqlx::query_as!(
        PoolShareStatisticsRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            "time" AS "time!",
            accepted AS "accepted!",
            rejected AS "rejected!"
           FROM pool_share_statistics_entity
           WHERE "deletedAt" IS NULL AND "time" >= $1
           ORDER BY "time" ASC"#,
        since_ms,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// All `pool_rejected_statistics_entity` rows from `since_ms` onward.
/// Drives `/api/info/rejected` (per-reason aggregation done in bp-api).
pub async fn find_pool_rejected_statistics_since(
    pool: &PgPool,
    since_ms: i64,
) -> Result<Vec<PoolRejectedStatisticsRow>, DbError> {
    sqlx::query_as!(
        PoolRejectedStatisticsRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            "time" AS "time!",
            reason AS "reason!",
            count AS "count!"
           FROM pool_rejected_statistics_entity
           WHERE "deletedAt" IS NULL AND "time" >= $1
           ORDER BY "time" ASC"#,
        since_ms,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// All `pool_mode_hashrate` rows for one mining mode from `since_ms`
/// onward. Drives `/api/pplns/chart` and `/api/info/chart/mode/:mode`.
pub async fn find_pool_mode_hashrate_since(
    pool: &PgPool,
    mode: MiningMode,
    since_ms: i64,
) -> Result<Vec<PoolModeHashrateRow>, DbError> {
    // `pool_mode_hashrate.mode` is a varchar; bind the kebab-case
    // string form rather than the typed enum so sqlx's macro stays
    // happy without a custom Encode path.
    let mode_str = mode.as_str();
    sqlx::query_as!(
        PoolModeHashrateRow,
        r#"SELECT
            id AS "id!",
            mode AS "mode!: MiningMode",
            "time" AS "time!",
            diff AS "diff!"
           FROM pool_mode_hashrate
           WHERE mode = $1 AND "time" >= $2
           ORDER BY "time" ASC"#,
        mode_str,
        since_ms,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct PoolShareStatisticsRow {
    #[sqlx(rename = "deletedAt")]
    pub deleted_at: Option<i64>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    pub id: i32,
    pub time: i64,
    pub accepted: f32,
    pub rejected: f32,
}

pub async fn find_pool_share_statistics(
    pool: &PgPool,
    id: i32,
) -> Result<Option<PoolShareStatisticsRow>, DbError> {
    sqlx::query_as!(
        PoolShareStatisticsRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            "time" AS "time!",
            accepted AS "accepted!",
            rejected AS "rejected!"
           FROM pool_share_statistics_entity WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct PoolRejectedStatisticsRow {
    #[sqlx(rename = "deletedAt")]
    pub deleted_at: Option<i64>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    pub id: i32,
    pub time: i64,
    pub reason: String,
    pub count: f32,
}

pub async fn find_pool_rejected_statistics(
    pool: &PgPool,
    id: i32,
) -> Result<Option<PoolRejectedStatisticsRow>, DbError> {
    sqlx::query_as!(
        PoolRejectedStatisticsRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            "time" AS "time!",
            reason AS "reason!",
            count AS "count!"
           FROM pool_rejected_statistics_entity WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct PoolModeHashrateRow {
    pub id: i32,
    pub mode: MiningMode,
    pub time: i64,
    pub diff: f32,
}

pub async fn find_pool_mode_hashrate(
    pool: &PgPool,
    id: i32,
) -> Result<Option<PoolModeHashrateRow>, DbError> {
    sqlx::query_as!(
        PoolModeHashrateRow,
        r#"SELECT
            id AS "id!",
            mode AS "mode!: MiningMode",
            "time" AS "time!",
            diff AS "diff!"
           FROM pool_mode_hashrate WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct NetworkDifficultyTrackerRow {
    #[sqlx(rename = "deletedAt")]
    pub deleted_at: Option<i64>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    /// Always `1` — table is constrained to a single row via `CHECK (id = 1)`.
    pub id: i32,
    #[sqlx(rename = "currentDifficulty")]
    pub current_difficulty: f64,
    #[sqlx(rename = "previousDifficulty")]
    pub previous_difficulty: Option<f64>,
    #[sqlx(rename = "lastCheckedAt")]
    pub last_checked_at: i64,
    #[sqlx(rename = "lastChangedAt")]
    pub last_changed_at: Option<i64>,
}

/// Returns the singleton `network_difficulty_tracker_entity` row (constrained
/// to `id = 1` by a CHECK in the schema).
pub async fn find_network_difficulty_tracker(
    pool: &PgPool,
) -> Result<Option<NetworkDifficultyTrackerRow>, DbError> {
    sqlx::query_as!(
        NetworkDifficultyTrackerRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            "currentDifficulty" AS "current_difficulty!",
            "previousDifficulty" AS "previous_difficulty?",
            "lastCheckedAt" AS "last_checked_at!",
            "lastChangedAt" AS "last_changed_at?"
           FROM network_difficulty_tracker_entity WHERE id = 1 LIMIT 1"#,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// Upsert the singleton network-difficulty tracker (`id = 1`).
/// Called by the 10-min cron after fetching the latest difficulty
/// from mempool.space. `previous_difficulty` is rotated from the
/// existing `currentDifficulty` whenever the value changes;
/// `last_changed_at` is stamped only on a real change so the bot
/// can suppress no-op pings.
pub async fn upsert_network_difficulty_tracker(
    pool: &PgPool,
    new_current: f64,
    now_ms: i64,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"INSERT INTO network_difficulty_tracker_entity
           (id, "currentDifficulty", "previousDifficulty",
            "lastCheckedAt", "lastChangedAt", "createdAt", "updatedAt")
           VALUES (1, $1, NULL, $2, $2, $2, $2)
           ON CONFLICT (id) DO UPDATE SET
             "previousDifficulty" = CASE
                 WHEN network_difficulty_tracker_entity."currentDifficulty" <> EXCLUDED."currentDifficulty"
                 THEN network_difficulty_tracker_entity."currentDifficulty"
                 ELSE network_difficulty_tracker_entity."previousDifficulty"
             END,
             "currentDifficulty" = EXCLUDED."currentDifficulty",
             "lastCheckedAt" = EXCLUDED."lastCheckedAt",
             "lastChangedAt" = CASE
                 WHEN network_difficulty_tracker_entity."currentDifficulty" <> EXCLUDED."currentDifficulty"
                 THEN EXCLUDED."lastCheckedAt"
                 ELSE network_difficulty_tracker_entity."lastChangedAt"
             END,
             "updatedAt" = EXCLUDED."updatedAt""#,
        new_current,
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(())
}
