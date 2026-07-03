// SPDX-License-Identifier: AGPL-3.0-or-later

//! Client sessions + per-share statistics tables (hot-path).
//!
//! - `client_entity` — active mining sessions (composite PK address+clientName+sessionId, soft-deleted)
//! - `client_statistics_entity` — per-share counters, time-slotted (UNIQUE address+clientName+sessionId+time)
//! - `client_difficulty_statistics_entity` — per-10-min max-difficulty (UNIQUE address+clientName+slotTime)
//! - `client_rejected_statistics_entity` — per-reject reason counters (UNIQUE address+time+reason)
//! - `worker_shares_entity` — cumulative per-worker counts (composite PK address+clientName)

use bp_common::AddressId;
use sqlx::{postgres::PgPool, FromRow};

use crate::DbError;

#[derive(Clone, Debug, FromRow)]
pub struct ClientRow {
    #[sqlx(rename = "deletedAt")]
    pub deleted_at: Option<i64>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    pub address: AddressId,
    #[sqlx(rename = "clientName")]
    pub client_name: String,
    #[sqlx(rename = "sessionId")]
    pub session_id: String,
    #[sqlx(rename = "userAgent")]
    pub user_agent: Option<String>,
    #[sqlx(rename = "startTime")]
    pub start_time: i64,
    #[sqlx(rename = "firstSeen")]
    pub first_seen: Option<i64>,
    #[sqlx(rename = "bestDifficulty")]
    pub best_difficulty: f32,
    #[sqlx(rename = "hashRate")]
    pub hash_rate: f64,
    #[sqlx(rename = "currentDifficulty")]
    pub current_difficulty: Option<f32>,
    /// Number of mining channels on this session's connection. `1` for a
    /// direct miner; `> 1` when a rental proxy bundles several same-rig
    /// devices onto one connection — the UI flags the difficulty as
    /// aggregated in that case.
    #[sqlx(rename = "channelCount")]
    pub channel_count: i32,
}

pub async fn find_client(
    pool: &PgPool,
    address: &AddressId,
    client_name: &str,
    session_id: &str,
) -> Result<Option<ClientRow>, DbError> {
    sqlx::query_as!(
        ClientRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            "sessionId" AS "session_id!",
            "userAgent" AS "user_agent?",
            "startTime" AS "start_time!",
            "firstSeen" AS "first_seen?",
            "bestDifficulty" AS "best_difficulty!",
            "hashRate" AS "hash_rate!",
            "currentDifficulty" AS "current_difficulty?",
            "channelCount" AS "channel_count!"
           FROM client_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3 LIMIT 1"#,
        address.as_str(),
        client_name,
        session_id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// All active (non-soft-deleted) client sessions for an address. Used
/// by `/stats` to enumerate workers + sum hashrate per address.
pub async fn find_clients_by_address(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Vec<ClientRow>, DbError> {
    sqlx::query_as!(
        ClientRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            "sessionId" AS "session_id!",
            "userAgent" AS "user_agent?",
            "startTime" AS "start_time!",
            "firstSeen" AS "first_seen?",
            "bestDifficulty" AS "best_difficulty!",
            "hashRate" AS "hash_rate!",
            "currentDifficulty" AS "current_difficulty?",
            "channelCount" AS "channel_count!"
           FROM client_entity
           WHERE address = $1 AND "deletedAt" IS NULL
           ORDER BY "clientName", "sessionId""#,
        address.as_str(),
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Time-decay window (ms) for the live-hashrate sums. `client_entity.hashRate`
/// is a snapshot frozen at a session's last accepted share, so a departed miner
/// keeps its last value until the dead-client sweep (minutes later) — summing
/// raw snapshots over-counts miners that just left, badly when marketplace
/// proxies churn sessions. Instead each session is weighted by how fresh its
/// last share is, fading linearly to zero over this window, so a session that
/// goes quiet drops out of the number smoothly instead of lingering at full.
pub const HASHRATE_DECAY_WINDOW_MS: i64 = 2 * 60 * 1000;

/// Staleness-decayed sum of `hashRate` across active client rows — powers the
/// `/api/pool` `totalHashRate` field. Each session is weighted
/// `max(0, 1 - (now_ms - updatedAt)/window_ms)` so a miner that just went
/// offline fades out over `window_ms` instead of counting at full until swept.
pub async fn sum_active_pool_hashrate<'e, E>(
    executor: E,
    now_ms: i64,
    window_ms: i64,
) -> Result<f64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query!(
        r#"SELECT COALESCE(SUM(
               "hashRate" * GREATEST(0.0, LEAST(1.0, 1.0 - (($1 - "updatedAt")::float8 / $2::float8)))
           ), 0.0)::float8 AS "total!"
           FROM client_entity
           WHERE "deletedAt" IS NULL"#,
        now_ms,
        window_ms as f64,
    )
    .fetch_one(executor)
    .await
    .map_err(DbError::from)?;
    Ok(row.total)
}

/// One row of the user-agent aggregation surfaced by `/api/info` →
/// `userAgents` (`userAgent`, `count`, `bestDifficulty`, `totalHashRate`).
#[derive(Clone, Debug, FromRow)]
pub struct UserAgentAggRow {
    #[sqlx(rename = "userAgent")]
    pub user_agent: Option<String>,
    pub count: i64,
    #[sqlx(rename = "bestDifficulty")]
    pub best_difficulty: Option<f32>,
    #[sqlx(rename = "totalHashRate")]
    pub total_hash_rate: Option<f64>,
}

/// GROUP BY `userAgent` over the **active** rows in `client_entity`
/// — `deletedAt IS NULL` filter so an idle pool with only soft-deleted
/// sessions doesn't emit a ghost `{userAgent: null, count: 0}` entry.
/// Ordered by `count DESC`. `totalHashRate` is staleness-decayed like
/// [`sum_active_pool_hashrate`] so the per-agent hashrate agrees with the pool
/// total; `count` stays a raw session count.
pub async fn find_user_agents(
    pool: &PgPool,
    now_ms: i64,
    window_ms: i64,
) -> Result<Vec<UserAgentAggRow>, DbError> {
    sqlx::query_as::<_, UserAgentAggRow>(
        r#"SELECT
            "userAgent",
            COUNT("userAgent") AS count,
            MAX("bestDifficulty") AS "bestDifficulty",
            SUM("hashRate" * GREATEST(0.0, LEAST(1.0, 1.0 - (($1 - "updatedAt")::float8 / $2::float8)))) AS "totalHashRate"
           FROM client_entity
           WHERE "deletedAt" IS NULL
           GROUP BY "userAgent"
           ORDER BY COUNT("userAgent") DESC"#,
    )
    .bind(now_ms)
    .bind(window_ms)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

// ── Time-range readers ───────────────────────────────────────────────
//
// Consumed by `bp-api`'s chart / accepted / workers / rejected
// endpoints. Each returns the raw rows filtered to `time >= since_ms`;
// the API layer does slot-bucket aggregation in-memory because the
// right bucket size + format is endpoint-specific.

/// Pool-wide `client_statistics_entity` rows from `since_ms` onward,
/// ordered by `time ASC`. Drives `/api/info/chart` (pool hashrate),
/// `/api/info/workers` (worker + session counts).
pub async fn find_client_statistics_since(
    pool: &PgPool,
    since_ms: i64,
) -> Result<Vec<ClientStatisticsRow>, DbError> {
    sqlx::query_as!(
        ClientStatisticsRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            "sessionId" AS "session_id!",
            "time" AS "time!",
            shares AS "shares!",
            "acceptedCount" AS "accepted_count!",
            "rejectedCount" AS "rejected_count!",
            "rejectedJobNotFoundCount" AS "rejected_job_not_found_count!",
            "rejectedJobNotFoundDiff1" AS "rejected_job_not_found_diff1!",
            "rejectedDuplicateShareCount" AS "rejected_duplicate_share_count!",
            "rejectedDuplicateShareDiff1" AS "rejected_duplicate_share_diff1!",
            "rejectedLowDifficultyShareCount" AS "rejected_low_difficulty_share_count!",
            "rejectedLowDifficultyShareDiff1" AS "rejected_low_difficulty_share_diff1!"
           FROM client_statistics_entity
           WHERE "deletedAt" IS NULL AND "time" >= $1
           ORDER BY "time" ASC"#,
        since_ms,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Minimal projection for `/api/info/workers`: only the slot time + identity
/// columns needed to count DISTINCT addresses / (address, worker) per slot.
/// Selecting three columns instead of the full 17-column stats row cuts the
/// transferred payload ~4× for the same row set, and there's no `ORDER BY`
/// (the caller buckets into a map, order is irrelevant) so PG skips a sort.
#[derive(Clone, Debug, FromRow)]
pub struct PoolWorkerRow {
    pub time: i64,
    pub address: String,
    #[sqlx(rename = "clientName")]
    pub client_name: String,
}

pub async fn find_pool_worker_rows_since<'e, E>(
    executor: E,
    since_ms: i64,
) -> Result<Vec<PoolWorkerRow>, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        PoolWorkerRow,
        r#"SELECT "time" AS "time!", address AS "address!", "clientName" AS "client_name!"
             FROM client_statistics_entity
            WHERE "deletedAt" IS NULL AND "time" >= $1"#,
        since_ms,
    )
    .fetch_all(executor)
    .await
    .map_err(DbError::from)
}

/// Same as [`find_client_statistics_since`] but restricted to one
/// address. Drives `/api/client/:address/chart`, `/api/client/:address/
/// workers`, `/api/client/:address/accepted`.
pub async fn find_client_statistics_since_for_address(
    pool: &PgPool,
    address: &AddressId,
    since_ms: i64,
) -> Result<Vec<ClientStatisticsRow>, DbError> {
    sqlx::query_as!(
        ClientStatisticsRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            "sessionId" AS "session_id!",
            "time" AS "time!",
            shares AS "shares!",
            "acceptedCount" AS "accepted_count!",
            "rejectedCount" AS "rejected_count!",
            "rejectedJobNotFoundCount" AS "rejected_job_not_found_count!",
            "rejectedJobNotFoundDiff1" AS "rejected_job_not_found_diff1!",
            "rejectedDuplicateShareCount" AS "rejected_duplicate_share_count!",
            "rejectedDuplicateShareDiff1" AS "rejected_duplicate_share_diff1!",
            "rejectedLowDifficultyShareCount" AS "rejected_low_difficulty_share_count!",
            "rejectedLowDifficultyShareDiff1" AS "rejected_low_difficulty_share_diff1!"
           FROM client_statistics_entity
           WHERE "deletedAt" IS NULL AND address = $1 AND "time" >= $2
           ORDER BY "time" ASC"#,
        address.as_str(),
        since_ms,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// `client_rejected_statistics_entity` rows for one address from
/// `since_ms` onward. Drives `/api/client/:address/rejected` (per-
/// reason aggregation done in bp-api).
pub async fn find_client_rejected_statistics_since_for_address(
    pool: &PgPool,
    address: &AddressId,
    since_ms: i64,
) -> Result<Vec<ClientRejectedStatisticsRow>, DbError> {
    sqlx::query_as!(
        ClientRejectedStatisticsRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            "time" AS "time!",
            reason AS "reason!",
            count AS "count!",
            shares AS "shares!"
           FROM client_rejected_statistics_entity
           WHERE "deletedAt" IS NULL AND address = $1 AND "time" >= $2
           ORDER BY "time" ASC"#,
        address.as_str(),
        since_ms,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Sum of `hashRate` across non-soft-deleted clients whose `address`
/// is in the input list. Used by `/pplns_status` (sum across the
/// PPLNS distribution) + `/group_status` (sum across group members).
/// Empty input returns `0.0` without hitting PG.
pub async fn sum_hashrate_for_addresses(
    pool: &PgPool,
    addresses: &[AddressId],
) -> Result<f64, DbError> {
    if addresses.is_empty() {
        return Ok(0.0);
    }
    let addr_strs: Vec<&str> = addresses.iter().map(|a| a.as_str()).collect();
    let row = sqlx::query!(
        r#"SELECT COALESCE(SUM("hashRate"), 0.0)::float8 AS "total!"
           FROM client_entity
           WHERE "deletedAt" IS NULL
             AND address = ANY($1)"#,
        &addr_strs as &[&str],
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::from)?;
    Ok(row.total)
}

#[derive(Clone, Debug, FromRow)]
pub struct ClientStatisticsRow {
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
    #[sqlx(rename = "sessionId")]
    pub session_id: String,
    pub time: i64,
    pub shares: f32,
    #[sqlx(rename = "acceptedCount")]
    pub accepted_count: i32,
    #[sqlx(rename = "rejectedCount")]
    pub rejected_count: i32,
    #[sqlx(rename = "rejectedJobNotFoundCount")]
    pub rejected_job_not_found_count: i32,
    #[sqlx(rename = "rejectedJobNotFoundDiff1")]
    pub rejected_job_not_found_diff1: f32,
    #[sqlx(rename = "rejectedDuplicateShareCount")]
    pub rejected_duplicate_share_count: i32,
    #[sqlx(rename = "rejectedDuplicateShareDiff1")]
    pub rejected_duplicate_share_diff1: f32,
    #[sqlx(rename = "rejectedLowDifficultyShareCount")]
    pub rejected_low_difficulty_share_count: i32,
    #[sqlx(rename = "rejectedLowDifficultyShareDiff1")]
    pub rejected_low_difficulty_share_diff1: f32,
}

pub async fn find_client_statistics(
    pool: &PgPool,
    id: i32,
) -> Result<Option<ClientStatisticsRow>, DbError> {
    sqlx::query_as!(
        ClientStatisticsRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            "sessionId" AS "session_id!",
            "time" AS "time!",
            shares AS "shares!",
            "acceptedCount" AS "accepted_count!",
            "rejectedCount" AS "rejected_count!",
            "rejectedJobNotFoundCount" AS "rejected_job_not_found_count!",
            "rejectedJobNotFoundDiff1" AS "rejected_job_not_found_diff1!",
            "rejectedDuplicateShareCount" AS "rejected_duplicate_share_count!",
            "rejectedDuplicateShareDiff1" AS "rejected_duplicate_share_diff1!",
            "rejectedLowDifficultyShareCount" AS "rejected_low_difficulty_share_count!",
            "rejectedLowDifficultyShareDiff1" AS "rejected_low_difficulty_share_diff1!"
           FROM client_statistics_entity WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct ClientDifficultyStatisticsRow {
    #[sqlx(rename = "deletedAt")]
    pub deleted_at: Option<i64>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    pub id: i32,
    pub address: AddressId,
    #[sqlx(rename = "clientName")]
    pub client_name: Option<String>,
    #[sqlx(rename = "slotTime")]
    pub slot_time: i64,
    #[sqlx(rename = "maxDifficulty")]
    pub max_difficulty: f32,
}

pub async fn find_client_difficulty_statistics(
    pool: &PgPool,
    id: i32,
) -> Result<Option<ClientDifficultyStatisticsRow>, DbError> {
    sqlx::query_as!(
        ClientDifficultyStatisticsRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            "clientName" AS "client_name?",
            "slotTime" AS "slot_time!",
            "maxDifficulty" AS "max_difficulty!"
           FROM client_difficulty_statistics_entity WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// Upsert the per-`(address, clientName, slotTime)` maximum share
/// difficulty into `client_difficulty_statistics_entity` (keeps the
/// GREATEST). Feeds the `/api/client/:address/diff-scores` chart. The
/// unique index
/// `IDX_client_difficulty_statistics_unique (address, clientName, slotTime)`
/// backs the `ON CONFLICT`; `id` is sequence-generated. `max_difficulty`
/// is stored in the `real` column, so it's bound as `f32`.
pub async fn upsert_client_difficulty_statistic(
    pool: &PgPool,
    address: &str,
    client_name: &str,
    slot_time: i64,
    max_difficulty: f32,
    now_ms: i64,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"INSERT INTO client_difficulty_statistics_entity
               (address, "clientName", "slotTime", "maxDifficulty", "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $4, $5, $5)
           ON CONFLICT (address, "clientName", "slotTime") DO UPDATE SET
               "maxDifficulty" = GREATEST(
                   EXCLUDED."maxDifficulty",
                   client_difficulty_statistics_entity."maxDifficulty"
               ),
               "updatedAt" = EXCLUDED."updatedAt""#,
        address,
        client_name,
        slot_time,
        max_difficulty,
        now_ms,
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct ClientRejectedStatisticsRow {
    #[sqlx(rename = "deletedAt")]
    pub deleted_at: Option<i64>,
    #[sqlx(rename = "createdAt")]
    pub created_at: i64,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: i64,
    pub id: i32,
    pub address: AddressId,
    pub time: i64,
    pub reason: String,
    pub count: f32,
    pub shares: f32,
}

pub async fn find_client_rejected_statistics(
    pool: &PgPool,
    id: i32,
) -> Result<Option<ClientRejectedStatisticsRow>, DbError> {
    sqlx::query_as!(
        ClientRejectedStatisticsRow,
        r#"SELECT
            "deletedAt" AS "deleted_at?",
            "createdAt" AS "created_at!",
            "updatedAt" AS "updated_at!",
            id AS "id!",
            address AS "address!: AddressId",
            "time" AS "time!",
            reason AS "reason!",
            count AS "count!",
            shares AS "shares!"
           FROM client_rejected_statistics_entity WHERE id = $1 LIMIT 1"#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Clone, Debug, FromRow)]
pub struct WorkerSharesRow {
    pub address: AddressId,
    #[sqlx(rename = "clientName")]
    pub client_name: String,
    pub shares: f64,
    #[sqlx(rename = "rejectedShares")]
    pub rejected_shares: f64,
}

pub async fn find_worker_shares(
    pool: &PgPool,
    address: &AddressId,
    client_name: &str,
) -> Result<Option<WorkerSharesRow>, DbError> {
    sqlx::query_as!(
        WorkerSharesRow,
        r#"SELECT
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            shares AS "shares!",
            "rejectedShares" AS "rejected_shares!"
           FROM worker_shares_entity
           WHERE address = $1 AND "clientName" = $2 LIMIT 1"#,
        address.as_str(),
        client_name
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

// ── Session-persistence writes (consumer: bp-session-persistence) ───

/// One client-row to insert / upsert — register the session on
/// authorize. `firstSeen` is set to `start_time_ms` on INSERT (the
/// authorize timestamp) and left unchanged on re-register conflicts.
/// `bestDifficulty` stays NULL until the first accepted share.
#[derive(Clone, Debug)]
pub struct ClientUpsert {
    pub address: String,
    pub client_name: String,
    pub session_id: String,
    pub user_agent: Option<String>,
    pub start_time_ms: i64,
    pub current_difficulty: Option<f32>,
}

/// INSERT or UPDATE a `client_entity` row keyed on the composite PK
/// `(address, clientName, sessionId)`. ON CONFLICT path covers
/// defensive re-register with the same sessionId — refreshes
/// `userAgent`, `startTime`, `currentDifficulty`, and clears
/// `deletedAt` so a previously soft-deleted session can be reactivated
/// without leaking the soft-delete flag.
pub async fn upsert_client<'e, E>(executor: E, row: &ClientUpsert) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"INSERT INTO client_entity
             (address, "clientName", "sessionId", "userAgent", "startTime", "firstSeen",
              "currentDifficulty", "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $4, $5, $5, $6,
                   (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint,
                   (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint)
           ON CONFLICT (address, "clientName", "sessionId") DO UPDATE
           SET "userAgent"         = EXCLUDED."userAgent",
               "startTime"         = EXCLUDED."startTime",
               "currentDifficulty" = EXCLUDED."currentDifficulty",
               "updatedAt"         = EXCLUDED."updatedAt",
               "deletedAt"         = NULL"#,
        &row.address,
        &row.client_name,
        &row.session_id,
        row.user_agent.as_deref(),
        row.start_time_ms,
        row.current_difficulty,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Soft-delete every `client_entity` row matching `sessionId`. Sets
/// `deletedAt = now()`. Returns the number of rows touched — typically
/// 1 (sessionId is 8 chars + per-authorize unique in practice), but the
/// composite PK does NOT constrain sessionId-only-uniqueness so this
/// filters by sessionId alone.
pub async fn delete_client_for_session<'e, E>(executor: E, session_id: &str) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE client_entity
           SET "deletedAt" = (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint,
               "updatedAt" = (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint
           WHERE "sessionId" = $1 AND "deletedAt" IS NULL"#,
        session_id
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Soft-delete every `client_entity` row whose `updatedAt` is older
/// than `cutoff_ms` and which isn't already soft-deleted. The periodic
/// cleanup pass run on a 60s interval that catches sessions whose
/// disconnect path didn't fire properly (network drop without a clean FIN).
/// Returns the number of rows soft-deleted.
///
/// The 60s cron orchestration that drives this lands in `bin/blitzpool`.
/// This function is the leaf bp-db primitive — same shape as
/// `delete_client_for_session`, just keyed on the staleness predicate
/// rather than a specific session-id.
pub async fn kill_dead_clients<'e, E>(executor: E, cutoff_ms: i64) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE client_entity
           SET "deletedAt" = (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint,
               "updatedAt" = (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint
           WHERE "updatedAt" < $1 AND "deletedAt" IS NULL"#,
        cutoff_ms
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Refine the `userAgent` for every active session belonging to
/// `address` whose current `userAgent` is a JDP-placeholder
/// (`jd-client/sv2` or `/sv2`). Called from the downstream-report
/// POST handler once the JDP miner reports its downstream device
/// vendors. Returns the number of rows updated.
pub async fn update_sv2_user_agent_by_address<'e, E>(
    executor: E,
    address: &str,
    new_user_agent: &str,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    // updatedAt is bumped explicitly here: there's no implicit
    // "updated-at" trigger, so every UPDATE that should refresh the
    // row's freshness must set it.
    let result = sqlx::query(
        r#"UPDATE client_entity
           SET "userAgent" = $2,
               "updatedAt" = (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint
           WHERE address = $1
             AND "userAgent" IN ('jd-client/sv2', '/sv2')"#,
    )
    .bind(address)
    .bind(new_user_agent)
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Hard-delete every `client_entity` row whose `deletedAt` is older
/// than `cutoff_ms`. Runs hourly alongside `delete_old_statistics`
/// so the soft-deleted backlog doesn't grow unbounded.
pub async fn delete_old_clients<'e, E>(executor: E, cutoff_ms: i64) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query(
        r#"DELETE FROM client_entity
           WHERE "deletedAt" IS NOT NULL AND "deletedAt" < $1"#,
    )
    .bind(cutoff_ms)
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Hard-delete rows from `client_statistics_entity` /
/// `client_rejected_statistics_entity` /
/// `client_difficulty_statistics_entity` / `pool_mode_hashrate`
/// whose time column is older than the supplied cutoff. The UI only
/// renders 1d / 3d / 7d charts from these so anything past 14 d is
/// dead weight.
pub async fn delete_old_client_statistics<'e, E>(
    executor: E,
    cutoff_ms: i64,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query(r#"DELETE FROM client_statistics_entity WHERE "time" < $1"#)
        .bind(cutoff_ms)
        .execute(executor)
        .await
        .map_err(DbError::from)?;
    Ok(r.rows_affected())
}

pub async fn delete_old_client_rejected_statistics<'e, E>(
    executor: E,
    cutoff_ms: i64,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query(r#"DELETE FROM client_rejected_statistics_entity WHERE "time" < $1"#)
        .bind(cutoff_ms)
        .execute(executor)
        .await
        .map_err(DbError::from)?;
    Ok(r.rows_affected())
}

pub async fn delete_old_client_difficulty_statistics<'e, E>(
    executor: E,
    cutoff_ms: i64,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query(r#"DELETE FROM client_difficulty_statistics_entity WHERE "slotTime" < $1"#)
        .bind(cutoff_ms)
        .execute(executor)
        .await
        .map_err(DbError::from)?;
    Ok(r.rows_affected())
}

pub async fn delete_old_pool_mode_hashrate<'e, E>(
    executor: E,
    cutoff_ms: i64,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query(r#"DELETE FROM pool_mode_hashrate WHERE "time" < $1"#)
        .bind(cutoff_ms)
        .execute(executor)
        .await
        .map_err(DbError::from)?;
    Ok(r.rows_affected())
}

/// Per-share touch of a session's `client_entity` row. Called from the
/// share-accept hook so the row stays alive (kill_dead_clients
/// otherwise sweeps it after a few minutes of no UPDATE), reflects
/// the best difficulty the session has ever solved, sets `firstSeen`
/// on the first share, exposes a recent hashrate estimate, and keeps
/// `currentDifficulty` in step with the vardiff target the miner is
/// currently working at.
///
/// `share_diff` is the share-accepted difficulty (the all-time best
/// uses GREATEST). `current_diff` is the difficulty currently assigned
/// to the session (vardiff target) — pass `None` to leave the column
/// unchanged. `hash_rate_est` is the caller-computed hashrate in H/s
/// (pass `None` to leave the column unchanged). `now_ms` is wall-clock
/// epoch-ms.
#[allow(clippy::too_many_arguments)]
pub async fn touch_client_for_share<'e, E>(
    executor: E,
    address: &str,
    client_name: &str,
    session_id: &str,
    share_diff: f64,
    current_diff: Option<f64>,
    hash_rate_est: Option<f64>,
    channel_count: i32,
    now_ms: i64,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE client_entity
           SET "bestDifficulty"    = GREATEST("bestDifficulty", $4::real),
               "currentDifficulty" = COALESCE($7::real, "currentDifficulty"),
               "firstSeen"         = COALESCE("firstSeen", $5),
               "hashRate"          = COALESCE($6, "hashRate"),
               "channelCount"      = $8,
               "updatedAt"         = $5,
               "deletedAt"         = NULL
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#,
        address,
        client_name,
        session_id,
        share_diff as f32,
        now_ms,
        hash_rate_est,
        current_diff.map(|d| d as f32),
        channel_count,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Latest known `firstSeen` (falling back to `startTime`) for an
/// `(address, clientName)` pair, but only when the row's `lastActive`
/// (defined as `deletedAt ?? updatedAt`) is no older than `cutoff_ms`.
/// Powers the device-online notification's "returning" wording — the
/// caller renders the message differently when the device was here
/// within the last 30 min vs a cold first connect.
///
/// Returns `None` when no row matches, when the most-recent row is
/// older than the cutoff, or when both `firstSeen` and `startTime`
/// are NULL.
pub async fn find_client_recent_first_seen(
    pool: &PgPool,
    address: &str,
    client_name: &str,
    cutoff_ms: i64,
) -> Result<Option<i64>, DbError> {
    let row = sqlx::query!(
        r#"SELECT "deletedAt", "updatedAt", "firstSeen", "startTime"
           FROM client_entity
           WHERE address = $1 AND "clientName" = $2
           ORDER BY "updatedAt" DESC NULLS LAST
           LIMIT 1"#,
        address,
        client_name,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)?;
    let Some(row) = row else { return Ok(None) };
    let last_active = row.deletedAt.unwrap_or(row.updatedAt);
    if last_active < cutoff_ms {
        return Ok(None);
    }
    Ok(row.firstSeen.or(Some(row.startTime)))
}

/// Bulk variant of [`touch_client_for_share`] — collapses N per-session
/// updates into a single `UPDATE … FROM unnest(...)`. Same column
/// semantics as the per-row form: `bestDifficulty` takes `GREATEST`,
/// `currentDifficulty`/`hashRate` `COALESCE` (NULL preserves existing),
/// `firstSeen` only fills when NULL, `updatedAt` overwrites, `deletedAt`
/// clears. Caller is responsible for collapsing duplicates per
/// `(address, clientName, sessionId)` key (a buffered flusher keeps
/// only the latest sample per key).
#[allow(clippy::too_many_arguments)]
pub async fn bulk_touch_clients_for_share(
    pool: &PgPool,
    addresses: &[String],
    client_names: &[String],
    session_ids: &[String],
    share_diffs: &[f32],
    current_diffs: &[Option<f32>],
    hash_rates: &[Option<f64>],
    channel_counts: &[i32],
    updated_ats: &[i64],
) -> Result<u64, DbError> {
    let result = sqlx::query!(
        r#"UPDATE client_entity AS t
           SET "bestDifficulty"    = GREATEST(t."bestDifficulty", u.share_diff),
               "currentDifficulty" = COALESCE(u.current_diff, t."currentDifficulty"),
               "firstSeen"         = COALESCE(t."firstSeen", u.updated_at),
               "hashRate"          = COALESCE(u.hash_rate, t."hashRate"),
               "channelCount"      = u.channel_count,
               "updatedAt"         = u.updated_at,
               "deletedAt"         = NULL
           FROM (
               SELECT
                   unnest($1::text[])     AS address,
                   unnest($2::text[])     AS "clientName",
                   unnest($3::text[])     AS "sessionId",
                   unnest($4::real[])     AS share_diff,
                   unnest($5::real[])     AS current_diff,
                   unnest($6::float8[])   AS hash_rate,
                   unnest($7::int[])      AS channel_count,
                   unnest($8::bigint[])   AS updated_at
           ) AS u
           WHERE t.address      = u.address
             AND t."clientName" = u."clientName"
             AND t."sessionId"  = u."sessionId""#,
        addresses,
        client_names,
        session_ids,
        share_diffs,
        current_diffs as &[Option<f32>],
        hash_rates as &[Option<f64>],
        channel_counts,
        updated_ats,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Atomic compare-and-set on `address_settings_entity.bestDifficulty`.
/// INSERTs a fresh row if the address has none yet (cold-path on the
/// very first share); on conflict, only UPDATEs when the candidate
/// strictly exceeds the stored value. Returns the rows-affected count
/// — 1 if the row was inserted/updated, 0 if the candidate was ≤ stored.
pub async fn upsert_address_best_difficulty<'e, E>(
    executor: E,
    address: &str,
    candidate_difficulty: f64,
    user_agent: Option<&str>,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"INSERT INTO address_settings_entity
             (address, "bestDifficulty", "bestDifficultyUserAgent", "createdAt", "updatedAt")
           VALUES ($1, $2, $3,
                   (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint,
                   (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint)
           ON CONFLICT (address) DO UPDATE
           SET "bestDifficulty"          = EXCLUDED."bestDifficulty",
               "bestDifficultyUserAgent" = EXCLUDED."bestDifficultyUserAgent",
               "updatedAt"               = EXCLUDED."updatedAt"
           WHERE EXCLUDED."bestDifficulty" > address_settings_entity."bestDifficulty""#,
        address,
        candidate_difficulty,
        user_agent,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}
