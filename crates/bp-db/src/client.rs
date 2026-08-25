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

/// The birth half of a session. The live half (`hashRate`,
/// `currentDifficulty`, `channelCount`, per-session `bestDifficulty`,
/// last-seen) lives in the `client:live:*` Redis hashes — consumers
/// compose it via `bp_client_live::live_fields_for_sessions`, keyed by
/// the same `(address, client_name, session_id)` triple.
#[derive(Clone, Debug, FromRow)]
pub struct ClientRow {
    pub address: AddressId,
    #[sqlx(rename = "clientName")]
    pub client_name: String,
    #[sqlx(rename = "sessionId")]
    pub session_id: String,
    #[sqlx(rename = "userAgent")]
    pub user_agent: Option<String>,
    #[sqlx(rename = "startTime")]
    pub start_time: i64,
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
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            "sessionId" AS "session_id!",
            "userAgent" AS "user_agent?",
            "startTime" AS "start_time!"
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
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            "sessionId" AS "session_id!",
            "userAgent" AS "user_agent?",
            "startTime" AS "start_time!"
           FROM client_entity
           WHERE address = $1 AND "deletedAt" IS NULL
           ORDER BY "clientName", "sessionId""#,
        address.as_str(),
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Every **active** session's `(userAgent, key triple)` — the PG half
/// of the `/api/info` `userAgents` aggregation; the numbers come from
/// the `client:live:*` hashes via
/// `bp_client_live::aggregate_by_user_agent`. The `deletedAt IS NULL`
/// filter keeps an idle pool from emitting a ghost
/// `{userAgent: null, count: 0}` entry.
pub async fn find_active_session_keys(pool: &PgPool) -> Result<Vec<ClientRow>, DbError> {
    sqlx::query_as!(
        ClientRow,
        r#"SELECT
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            "sessionId" AS "session_id!",
            "userAgent" AS "user_agent?",
            "startTime" AS "start_time!"
           FROM client_entity
           WHERE "deletedAt" IS NULL"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Session `(userAgent, key triple)` rows for an address list — the PG
/// half of `/api/pplns`'s `userAgents` aggregation. ⚠️ Deliberately NO
/// `deletedAt` filter: the inline SQL this replaces never had one, and
/// tightening it is a display decision, not a refactor side effect.
pub async fn find_session_keys_for_addresses(
    pool: &PgPool,
    addresses: &[String],
) -> Result<Vec<ClientRow>, DbError> {
    if addresses.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as!(
        ClientRow,
        r#"SELECT
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            "sessionId" AS "session_id!",
            "userAgent" AS "user_agent?",
            "startTime" AS "start_time!"
           FROM client_entity
           WHERE address = ANY($1)"#,
        addresses,
    )
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
            "rejectedLowDifficultyShareDiff1" AS "rejected_low_difficulty_share_diff1!",
            "rejectedVersionRollingCount" AS "rejected_version_rolling_count!",
            "rejectedVersionRollingDiff1" AS "rejected_version_rolling_diff1!",
            "rejectedStaleCount" AS "rejected_stale_count!",
            "rejectedStaleDiff1" AS "rejected_stale_diff1!"
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
/// Selecting three columns instead of the full 19-column stats row cuts the
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
            "rejectedLowDifficultyShareDiff1" AS "rejected_low_difficulty_share_diff1!",
            "rejectedVersionRollingCount" AS "rejected_version_rolling_count!",
            "rejectedVersionRollingDiff1" AS "rejected_version_rolling_diff1!",
            "rejectedStaleCount" AS "rejected_stale_count!",
            "rejectedStaleDiff1" AS "rejected_stale_diff1!"
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
    #[sqlx(rename = "rejectedVersionRollingCount")]
    pub rejected_version_rolling_count: i32,
    #[sqlx(rename = "rejectedVersionRollingDiff1")]
    pub rejected_version_rolling_diff1: f32,
    #[sqlx(rename = "rejectedStaleCount")]
    pub rejected_stale_count: i32,
    #[sqlx(rename = "rejectedStaleDiff1")]
    pub rejected_stale_diff1: f32,
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
            "rejectedLowDifficultyShareDiff1" AS "rejected_low_difficulty_share_diff1!",
            "rejectedVersionRollingCount" AS "rejected_version_rolling_count!",
            "rejectedVersionRollingDiff1" AS "rejected_version_rolling_diff1!",
            "rejectedStaleCount" AS "rejected_stale_count!",
            "rejectedStaleDiff1" AS "rejected_stale_diff1!"
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

/// N per-slot maxima in one `INSERT … SELECT unnest(...) … ON CONFLICT DO
/// UPDATE`. Sole writer of the table's upsert path — the per-row variant it
/// replaced went with the inline sink.
///
/// `maxDifficulty` takes `GREATEST` against what is already stored (a lower
/// share in the same batch must not lower the slot's max), `updatedAt`
/// overwrites, and `createdAt` is only set on the insert so an existing row
/// keeps its original.
///
/// ⚠️ **The caller MUST collapse duplicates per `(address, clientName,
/// slotTime)`.** Postgres rejects a multi-row `ON CONFLICT DO UPDATE` that
/// would touch the same row twice with "cannot affect row a second time" —
/// which is a hard error, not a merge. The buffer that feeds this is keyed by
/// exactly that triple, so duplicates are impossible by construction; anything
/// else calling it has to guarantee the same.
///
/// No advisory lock here, unlike the `client_entity` pair: that one exists
/// because TWO loops write the same rows concurrently, a deadlock that was
/// actually measured. Here a single flush loop is the only writer, so there is
/// nothing to serialise against. ⚠️ Splitting `payout` and `stats` into two
/// processes would create a second writer — then this needs its own lock, on
/// its own key.
pub async fn bulk_upsert_client_difficulty_statistics(
    pool: &PgPool,
    addresses: &[String],
    client_names: &[String],
    slot_times: &[i64],
    max_difficulties: &[f32],
    updated_ats: &[i64],
) -> Result<u64, DbError> {
    let result = sqlx::query!(
        r#"INSERT INTO client_difficulty_statistics_entity
               (address, "clientName", "slotTime", "maxDifficulty", "createdAt", "updatedAt")
           SELECT
               unnest($1::text[]),
               unnest($2::text[]),
               unnest($3::bigint[]),
               unnest($4::real[]),
               unnest($5::bigint[]),
               unnest($5::bigint[])
           ON CONFLICT (address, "clientName", "slotTime") DO UPDATE SET
               "maxDifficulty" = GREATEST(
                   EXCLUDED."maxDifficulty",
                   client_difficulty_statistics_entity."maxDifficulty"
               ),
               "updatedAt" = EXCLUDED."updatedAt""#,
        addresses,
        client_names,
        slot_times,
        max_difficulties,
        updated_ats,
    )
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
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

/// One client-row to insert / upsert. Production rows are written by the
/// row-birth debounce in `bp-session-persistence`: a session earns its
/// row by surviving the debounce window, so a probe that authorizes and
/// hangs up right away never reaches this type. `firstSeen` is set to
/// `start_time_ms` (the authorize timestamp) on INSERT and left
/// unchanged on re-register conflicts. The live per-share values live
/// in the session's `client:live:*` Redis hash, not in this table.
#[derive(Clone, Debug)]
pub struct ClientUpsert {
    pub address: String,
    pub client_name: String,
    pub session_id: String,
    pub user_agent: Option<String>,
    pub start_time_ms: i64,
}

/// The one INSERT … ON CONFLICT statement behind [`upsert_client`] and
/// [`bulk_upsert_clients`] — keyed on the composite PK
/// `(address, clientName, sessionId)`. The conflict arm covers a
/// re-register with the same sessionId: refreshes `userAgent`,
/// `startTime`, and clears `deletedAt` so a previously soft-deleted
/// session is reactivated without leaking the soft-delete flag.
///
/// `rows` must be unique per `(address, clientName, sessionId)` —
/// `ON CONFLICT DO UPDATE` rejects a statement that hits the same row
/// twice. Both callers hold that by construction (a map keyed on the
/// triple / a single row).
async fn upsert_clients_stmt<'e, E>(executor: E, rows: &[ClientUpsert]) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let mut addresses = Vec::with_capacity(rows.len());
    let mut client_names = Vec::with_capacity(rows.len());
    let mut session_ids = Vec::with_capacity(rows.len());
    let mut user_agents: Vec<Option<String>> = Vec::with_capacity(rows.len());
    let mut start_times = Vec::with_capacity(rows.len());
    for row in rows {
        addresses.push(row.address.clone());
        client_names.push(row.client_name.clone());
        session_ids.push(row.session_id.clone());
        user_agents.push(row.user_agent.clone());
        start_times.push(row.start_time_ms);
    }
    let result = sqlx::query!(
        r#"INSERT INTO client_entity
             (address, "clientName", "sessionId", "userAgent", "startTime", "firstSeen",
              "createdAt", "updatedAt")
           SELECT u.address, u.client_name, u.session_id, u.user_agent,
                  u.start_time, u.start_time,
                  (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint,
                  (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint
           FROM (
               SELECT
                   unnest($1::text[])   AS address,
                   unnest($2::text[])   AS client_name,
                   unnest($3::text[])   AS session_id,
                   unnest($4::text[])   AS user_agent,
                   unnest($5::bigint[]) AS start_time
           ) AS u
           ON CONFLICT (address, "clientName", "sessionId") DO UPDATE
           SET "userAgent"         = EXCLUDED."userAgent",
               "startTime"         = EXCLUDED."startTime",
               "updatedAt"         = EXCLUDED."updatedAt",
               "deletedAt"         = NULL"#,
        &addresses,
        &client_names,
        &session_ids,
        &user_agents as &[Option<String>],
        &start_times,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Single-row convenience over `upsert_clients_stmt`. Executor-generic
/// so a test can run it inside its rollback transaction; production
/// writes go through [`bulk_upsert_clients`], which takes the bulk-write
/// lock.
pub async fn upsert_client<'e, E>(executor: E, row: &ClientUpsert) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    upsert_clients_stmt(executor, std::slice::from_ref(row)).await
}

/// Insert / upsert N client rows in one statement — the row-birth flush
/// of the session-persistence debounce. The sole bulk writer of
/// `client_entity` since the live fields moved to the `client:live:*`
/// Redis hashes; the advisory lock that once serialised it against the
/// touch/hashrate bulk UPDATEs went with them (one writer needs no
/// serialisation, and a single statement is atomic on its own).
pub async fn bulk_upsert_clients(pool: &PgPool, rows: &[ClientUpsert]) -> Result<u64, DbError> {
    upsert_clients_stmt(pool, rows).await
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

/// Active sessions whose `updatedAt` is older than `cutoff_ms` — the
/// CANDIDATES of the dead-session sweep, not its verdict. `updatedAt`
/// is only stamped at birth, re-register, and soft-delete now, so age
/// alone no longer means "silent": the cron in `bin/blitzpool` checks
/// each candidate's `client:live:*` key and soft-deletes (via
/// [`soft_delete_sessions`]) only those whose live hash is gone. The
/// age predicate survives purely as the birth grace period — a session
/// younger than the cutoff may not have flushed its first touch yet.
pub async fn find_stale_active_sessions<'e, E>(
    executor: E,
    cutoff_ms: i64,
) -> Result<Vec<ClientRow>, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        ClientRow,
        r#"SELECT
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            "sessionId" AS "session_id!",
            "userAgent" AS "user_agent?",
            "startTime" AS "start_time!"
           FROM client_entity
           WHERE "updatedAt" < $1 AND "deletedAt" IS NULL"#,
        cutoff_ms
    )
    .fetch_all(executor)
    .await
    .map_err(DbError::from)
}

/// Soft-delete the given sessions (parallel key arrays), skipping any
/// that were re-registered or soft-deleted in the meantime. The verdict
/// half of the dead-session sweep — see [`find_stale_active_sessions`].
pub async fn soft_delete_sessions<'e, E>(
    executor: E,
    addresses: &[String],
    client_names: &[String],
    session_ids: &[String],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"UPDATE client_entity AS t
           SET "deletedAt" = (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint,
               "updatedAt" = (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint
           FROM (
               SELECT
                   unnest($1::text[]) AS address,
                   unnest($2::text[]) AS "clientName",
                   unnest($3::text[]) AS "sessionId"
           ) AS u
           WHERE t.address      = u.address
             AND t."clientName" = u."clientName"
             AND t."sessionId"  = u."sessionId"
             AND t."deletedAt" IS NULL"#,
        addresses,
        client_names,
        session_ids,
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

/// When the pool first saw one `(address, clientName)` pair —
/// see [`device_first_seen`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceFirstSeenRow {
    pub address: String,
    pub client_name: String,
    /// Earliest `COALESCE("firstSeen", "startTime")` across **all** rows
    /// for the pair, soft-deleted ones included — when the pool first saw
    /// this worker.
    ///
    /// `startTime` alone is NOT this value: [`upsert_client`]'s
    /// `ON CONFLICT` refreshes it on every re-register, so a device that
    /// has been connected for days can carry a `startTime` of minutes ago.
    /// `firstSeen` is deliberately absent from that SET list and is the
    /// stable column.
    pub first_seen_ms: i64,
}

/// Liveness + first-seen for each requested `(address, clientName)`.
/// Pairs with no row at all are absent from the result.
///
/// This is the authoritative connectivity answer for the device-status
/// debounce: `deletedAt` is cleared by [`upsert_client`] on register,
/// stamped by [`delete_client_for_session`] on disconnect, and swept by
/// the dead-session cron (via [`soft_delete_sessions`]) when a session
/// dies without a clean FIN. Asking
/// the table at notification time — rather than counting connect and
/// disconnect events in memory — is what makes the debounce survive a
/// process restart and stay correct across several Stratum fronts.
///
/// Batched over both key columns so one sweep costs one round-trip
/// regardless of how many devices are due. The `(address, clientName)`
/// prefix of the primary key carries the scan.
pub async fn device_first_seen(
    pool: &PgPool,
    addresses: &[String],
    client_names: &[String],
) -> Result<Vec<DeviceFirstSeenRow>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT address AS "address!", "clientName" AS "client_name!",
                  MIN(COALESCE("firstSeen", "startTime")) AS "first_seen_ms!"
           FROM client_entity
           WHERE (address, "clientName") IN (
                   SELECT * FROM UNNEST($1::text[], $2::text[])
                 )
           GROUP BY address, "clientName""#,
        addresses,
        client_names,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)?;
    Ok(rows
        .into_iter()
        .map(|r| DeviceFirstSeenRow {
            address: r.address,
            client_name: r.client_name,
            first_seen_ms: r.first_seen_ms,
        })
        .collect())
}

/// Every `(address, clientName, userAgent)` under `addresses` whose state
/// could still be in flight: either a session is connected right now, or
/// its most recent session was soft-deleted no longer ago than
/// `deleted_since_ms`.
///
/// This is what the device-status gate seeds its watch list from after a
/// restart. Without it the gate would only ever learn about a device from
/// a Stratum event, so a miner that died just before the restart — and
/// will therefore never emit another event — could never be reported.
///
/// ⚠️ Since the live fields moved to Redis, `updatedAt` is no longer
/// touched per share — the `ORDER BY "updatedAt"` inside the aggregate
/// now picks the user agent of the most recently born or soft-deleted
/// session rather than the most recently *touched* one. Accepted drift:
/// this only seasons the seed's user-agent string, never liveness.
pub async fn device_watch_seed(
    pool: &PgPool,
    addresses: &[String],
    deleted_since_ms: i64,
) -> Result<Vec<(String, String, Option<String>)>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT address AS "address!", "clientName" AS "client_name!",
                  (ARRAY_AGG("userAgent" ORDER BY "updatedAt" DESC))[1] AS user_agent
           FROM client_entity
           WHERE address = ANY($1::text[])
             AND ("deletedAt" IS NULL OR "deletedAt" >= $2)
           GROUP BY address, "clientName""#,
        addresses,
        deleted_since_ms,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)?;
    Ok(rows
        .into_iter()
        .map(|r| (r.address, r.client_name, r.user_agent))
        .collect())
}
