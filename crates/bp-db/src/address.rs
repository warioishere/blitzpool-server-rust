// SPDX-License-Identifier: AGPL-3.0-or-later

//! Address-level configuration and best-difficulty tracking.
//!
//! - `address_settings_entity` — per-address shares, best-difficulty, coinbase-script payload (PK address)
//! - `best_difficulty_tracker_entity` — push-notification baseline (PK address)

use bp_common::AddressId;
use sqlx::{postgres::PgPool, FromRow};

use crate::DbError;

#[derive(Clone, Debug, FromRow)]
pub struct AddressSettingsRow {
    #[sqlx(rename = "deletedAt")]
    pub deleted_at: Option<i64>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    pub address: AddressId,
    pub shares: f64,
    #[sqlx(rename = "bestDifficulty")]
    pub best_difficulty: f64,
    #[sqlx(rename = "miscCoinbaseScriptData")]
    pub misc_coinbase_script_data: Option<String>,
    #[sqlx(rename = "bestDifficultyUserAgent")]
    pub best_difficulty_user_agent: Option<String>,
}

pub async fn find_address_settings(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Option<AddressSettingsRow>, DbError> {
    sqlx::query_as!(
        AddressSettingsRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            address AS "address!: AddressId",
            shares AS "shares!",
            "bestDifficulty" AS "best_difficulty!",
            "miscCoinbaseScriptData" AS "misc_coinbase_script_data?",
            "bestDifficultyUserAgent" AS "best_difficulty_user_agent?"
           FROM address_settings_entity WHERE address = $1 LIMIT 1"#,
        address.as_str()
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct BestDifficultyTrackerRow {
    #[sqlx(rename = "deletedAt")]
    pub deleted_at: Option<i64>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    pub address: AddressId,
    #[sqlx(rename = "bestDifficulty")]
    pub best_difficulty: f64,
    #[sqlx(rename = "lastCheckedAt")]
    pub last_checked_at: i64,
}

pub async fn find_best_difficulty_tracker(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Option<BestDifficultyTrackerRow>, DbError> {
    sqlx::query_as!(
        BestDifficultyTrackerRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            address AS "address!: AddressId",
            "bestDifficulty" AS "best_difficulty!",
            "lastCheckedAt" AS "last_checked_at!"
           FROM best_difficulty_tracker_entity WHERE address = $1 LIMIT 1"#,
        address.as_str()
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// Bulk-read tracker rows for many addresses in one round-trip. Missing
/// addresses are simply absent from the result; the caller treats
/// "absent" as "no baseline yet" (initialise silently).
pub async fn find_best_difficulty_trackers_for_addresses(
    pool: &PgPool,
    addresses: &[String],
) -> Result<Vec<BestDifficultyTrackerRow>, DbError> {
    sqlx::query_as!(
        BestDifficultyTrackerRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            address AS "address!: AddressId",
            "bestDifficulty" AS "best_difficulty!",
            "lastCheckedAt" AS "last_checked_at!"
           FROM best_difficulty_tracker_entity WHERE address = ANY($1)"#,
        addresses
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Bulk-upsert tracker rows in one statement. `addresses[i]` pairs with
/// `best_difficulties[i]`; `now_ms` is written to `lastCheckedAt` (and,
/// for new rows, `createdAt`/`updatedAt`). On conflict the best, the
/// check-timestamp, and `updatedAt` are overwritten — `createdAt` is
/// preserved.
pub async fn upsert_best_difficulty_trackers(
    pool: &PgPool,
    addresses: &[String],
    best_difficulties: &[f64],
    now_ms: i64,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"INSERT INTO best_difficulty_tracker_entity
             (address, "bestDifficulty", "lastCheckedAt", "createdAt", "updatedAt")
           SELECT a, d, $3, $3, $3
           FROM unnest($1::text[], $2::float8[]) AS u(a, d)
           ON CONFLICT (address) DO UPDATE SET
             "bestDifficulty" = EXCLUDED."bestDifficulty",
             "lastCheckedAt" = EXCLUDED."lastCheckedAt",
             "updatedAt" = EXCLUDED."updatedAt""#,
        addresses,
        best_difficulties,
        now_ms
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

/// One entry of the top-10 best-difficulty leaderboard surfaced by
/// `/api/info` → `highScores`. Ordered by `bestDifficulty DESC` LIMIT 10,
/// and `updatedAt` is rendered as an ISO string at the boundary.
#[derive(Clone, Debug)]
pub struct HighScoreRow {
    /// ISO-8601 timestamp built from the epoch-ms `updatedAt` column.
    pub updated_at: Option<String>,
    pub best_difficulty: f64,
    pub best_difficulty_user_agent: Option<String>,
}

/// Top-10 by `bestDifficulty DESC` from `address_settings_entity`.
/// Boundary conversion of `updatedAt` (bigint epoch-ms) to ISO matches
/// the shape consumed by the dashboard.
pub async fn find_high_scores(pool: &PgPool) -> Result<Vec<HighScoreRow>, DbError> {
    #[derive(FromRow)]
    struct Raw {
        #[sqlx(rename = "updatedAt")]
        updated_at: i64,
        #[sqlx(rename = "bestDifficulty")]
        best_difficulty: f64,
        #[sqlx(rename = "bestDifficultyUserAgent")]
        best_difficulty_user_agent: Option<String>,
    }
    let rows = sqlx::query_as::<_, Raw>(
        r#"SELECT "updatedAt", "bestDifficulty", "bestDifficultyUserAgent"
           FROM address_settings_entity
           ORDER BY "bestDifficulty" DESC
           LIMIT 10"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)?;
    Ok(rows
        .into_iter()
        .map(|r| HighScoreRow {
            updated_at: epoch_ms_to_iso(r.updated_at),
            best_difficulty: r.best_difficulty,
            best_difficulty_user_agent: r.best_difficulty_user_agent,
        })
        .collect())
}

fn epoch_ms_to_iso(ms: i64) -> Option<String> {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_millis_opt(ms)
        .single()
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

/// Reset `address_settings_entity.bestDifficulty` (and the user-agent
/// hint) to zero — `/bestdiff_reset` bot command. Idempotent: missing
/// row returns `affected = 0`.
pub async fn reset_address_settings_best_difficulty(
    pool: &PgPool,
    address: &AddressId,
) -> Result<u64, DbError> {
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let result = sqlx::query!(
        r#"UPDATE address_settings_entity
           SET "bestDifficulty" = 0,
               "bestDifficultyUserAgent" = NULL,
               "updatedAt" = $2
           WHERE address = $1"#,
        address.as_str(),
        now_ms,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}
