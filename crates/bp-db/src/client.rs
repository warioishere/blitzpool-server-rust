// SPDX-License-Identifier: AGPL-3.0-or-later

//! Client sessions (`client_entity`, soft-deleted) and the per-share
//! statistics tables on the hot path.

use bp_common::AddressId;
use sqlx::{postgres::PgPool, FromRow};

use crate::DbError;

/// The birth half of a session. The live half (hashrate, difficulty,
/// last-seen) is in the `client:live:*` Redis hashes, joined on the same
/// triple via `bp_client_live::live_fields_for_sessions`.
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
    /// Best accepted share of this session; survives pauses with the row.
    #[sqlx(rename = "bestDifficulty")]
    pub best_difficulty: f64,
}

impl bp_common::live_client_key::SessionKey for ClientRow {
    fn address(&self) -> &str {
        self.address.as_str()
    }
    fn worker(&self) -> &str {
        &self.client_name
    }
    fn session_id(&self) -> &str {
        &self.session_id
    }
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
            "startTime" AS "start_time!",
            "bestDifficulty" AS "best_difficulty!"
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

/// All active (non-soft-deleted) client sessions for an address.
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
            "startTime" AS "start_time!",
            "bestDifficulty" AS "best_difficulty!"
           FROM client_entity
           WHERE address = $1 AND "deletedAt" IS NULL
           ORDER BY "clientName", "sessionId""#,
        address.as_str(),
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Every active session's key and user agent: the PG half of the
/// `/api/info` `userAgents` aggregation. Filtering on `deletedAt IS NULL`
/// keeps an idle pool from emitting a ghost `{userAgent: null}` entry.
pub async fn find_active_session_keys(pool: &PgPool) -> Result<Vec<ClientRow>, DbError> {
    sqlx::query_as!(
        ClientRow,
        r#"SELECT
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            "sessionId" AS "session_id!",
            "userAgent" AS "user_agent?",
            "startTime" AS "start_time!",
            "bestDifficulty" AS "best_difficulty!"
           FROM client_entity
           WHERE "deletedAt" IS NULL"#,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Active session rows for an address list. Only active rows: the numbers
/// come from the live hashes, which a retired session no longer has, so
/// counting it would mix two populations.
pub async fn find_active_sessions_for_addresses(
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
            "startTime" AS "start_time!",
            "bestDifficulty" AS "best_difficulty!"
           FROM client_entity
           WHERE address = ANY($1) AND "deletedAt" IS NULL"#,
        addresses,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

// ── Time-range readers ───────────────────────────────────────────────
// Raw rows only: bucketing is endpoint-specific, so the API layer does it.

/// Distinct miners of one slot: addresses, and `(address, worker)` pairs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolWorkerCounts {
    pub time: i64,
    pub addresses: i64,
    pub workers: i64,
}

/// Distinct addresses and workers per slot from `since_ms` on, counted in
/// Postgres so one row per slot crosses the wire instead of one per session.
pub async fn find_pool_worker_counts_since<'e, E>(
    executor: E,
    since_ms: i64,
) -> Result<Vec<PoolWorkerCounts>, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        PoolWorkerCounts,
        r#"SELECT "time" AS "time!",
                  COUNT(DISTINCT address) AS "addresses!",
                  COUNT(DISTINCT (address, "clientName")) AS "workers!"
             FROM client_statistics_entity
            WHERE "deletedAt" IS NULL AND "time" >= $1
            GROUP BY "time""#,
        since_ms,
    )
    .fetch_all(executor)
    .await
    .map_err(DbError::from)
}

/// One address's `client_statistics_entity` rows from `since_ms` on, by time.
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
            "rejectedStaleDiff1" AS "rejected_stale_diff1!",
            "maxDifficulty" AS "max_difficulty!"
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

/// Highest share difficulty per slot across `addresses` from `since_ms` on,
/// in one query rather than one per member.
pub async fn find_max_difficulty_since_for_addresses<'e, E>(
    executor: E,
    addresses: &[AddressId],
    since_ms: i64,
) -> Result<Vec<(i64, f32)>, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let addresses: Vec<String> = addresses.iter().map(|a| a.as_str().to_string()).collect();
    let rows = sqlx::query!(
        r#"SELECT "time" AS "time!", MAX("maxDifficulty") AS "max_difficulty!"
           FROM client_statistics_entity
           WHERE "deletedAt" IS NULL AND address = ANY($1) AND "time" >= $2
           GROUP BY "time""#,
        &addresses,
        since_ms,
    )
    .fetch_all(executor)
    .await
    .map_err(DbError::from)?;
    Ok(rows
        .into_iter()
        .map(|r| (r.time, r.max_difficulty))
        .collect())
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
    /// Highest single share difficulty of the slot.
    #[sqlx(rename = "maxDifficulty")]
    pub max_difficulty: f32,
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

/// Every `worker_shares_entity` row of one address.
pub async fn find_worker_shares_for_address(
    pool: &PgPool,
    address: &AddressId,
) -> Result<Vec<WorkerSharesRow>, DbError> {
    sqlx::query_as!(
        WorkerSharesRow,
        r#"SELECT
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            shares AS "shares!",
            "rejectedShares" AS "rejected_shares!"
           FROM worker_shares_entity
           WHERE address = $1"#,
        address.as_str()
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

// ── Session-persistence writes (consumer: bp-session-persistence) ───

/// One client row to upsert, written once a session survives the row-birth
/// debounce, so a connect-and-hang-up probe never gets a row. `firstSeen`
/// is set from `start_time_ms` on insert only.
#[derive(Clone, Debug)]
pub struct ClientUpsert {
    pub address: String,
    pub client_name: String,
    pub session_id: String,
    pub user_agent: Option<String>,
    pub start_time_ms: i64,
}

/// The statement behind [`upsert_client`] and [`bulk_upsert_clients`]. A
/// re-register clears `deletedAt`, reviving a soft-deleted session; `firstSeen`
/// is left alone. `rows` must be unique per key triple, since
/// `ON CONFLICT DO UPDATE` rejects hitting one row twice.
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

/// Single-row upsert without the bulk-write lock, so a test can run it in
/// its rollback transaction; production writes use [`bulk_upsert_clients`].
pub async fn upsert_client<'e, E>(executor: E, row: &ClientUpsert) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    upsert_clients_stmt(executor, std::slice::from_ref(row)).await
}

/// Advisory lock serialising the multi-row `client_entity` writers, which run
/// in two processes and would otherwise deadlock on shared rows. Sorting the
/// inputs does not help: the planner decides lock order.
/// Any multi-row writer of `client_entity` MUST take this lock.
const CLIENT_ENTITY_BULK_WRITE_LOCK: i64 = 0x636c_6e74_6277; // "clntbw"

/// Take [`CLIENT_ENTITY_BULK_WRITE_LOCK`] for the rest of `tx`; the `_xact_`
/// variant releases on rollback too, so an error cannot leak the lock.
pub(crate) async fn take_client_entity_bulk_write_lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), DbError> {
    sqlx::query!(
        "SELECT pg_advisory_xact_lock($1)",
        CLIENT_ENTITY_BULK_WRITE_LOCK
    )
    .execute(&mut **tx)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

/// Insert / upsert N client rows in one statement — the row-birth flush
/// of the session-persistence debounce.
pub async fn bulk_upsert_clients(pool: &PgPool, rows: &[ClientUpsert]) -> Result<u64, DbError> {
    let mut tx = pool.begin().await.map_err(DbError::from)?;
    take_client_entity_bulk_write_lock(&mut tx).await?;
    let n = upsert_clients_stmt(&mut *tx, rows).await?;
    tx.commit().await.map_err(DbError::from)?;
    Ok(n)
}

/// Raise each session's `bestDifficulty` to its flushed best where that beats
/// the stored value (parallel key arrays). Rows already at or above it are not
/// written, so writes follow new records, not shares. A session whose row is
/// not born yet matches nothing.
pub async fn raise_client_best_difficulties(
    pool: &PgPool,
    addresses: &[String],
    client_names: &[String],
    session_ids: &[String],
    bests: &[f64],
) -> Result<u64, DbError> {
    if addresses.is_empty() {
        return Ok(0);
    }
    let mut tx = pool.begin().await.map_err(DbError::from)?;
    take_client_entity_bulk_write_lock(&mut tx).await?;
    let result = sqlx::query!(
        r#"UPDATE client_entity AS c
           SET "bestDifficulty" = u.best
           FROM unnest($1::varchar[], $2::varchar[], $3::varchar[], $4::float8[])
                AS u(address, client_name, session_id, best)
           WHERE c.address = u.address
             AND c."clientName" = u.client_name
             AND c."sessionId" = u.session_id
             AND c."bestDifficulty" < u.best"#,
        addresses,
        client_names,
        session_ids,
        bests,
    )
    .execute(&mut *tx)
    .await
    .map_err(DbError::from)?;
    tx.commit().await.map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Soft-delete every active row with this `sessionId`. The PK does not make
/// `sessionId` unique on its own, so more than one row may be touched.
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

/// Candidates (not verdicts) of the dead-session sweep: `updatedAt` is not
/// touched per share, so age alone does not mean silent. The cron soft-deletes
/// via [`soft_delete_sessions`] only those whose live hash is gone; the cutoff
/// is the birth grace period.
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
            "startTime" AS "start_time!",
            "bestDifficulty" AS "best_difficulty!"
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
pub async fn soft_delete_sessions(
    pool: &PgPool,
    addresses: &[String],
    client_names: &[String],
    session_ids: &[String],
) -> Result<u64, DbError> {
    let mut tx = pool.begin().await.map_err(DbError::from)?;
    take_client_entity_bulk_write_lock(&mut tx).await?;
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
    .execute(&mut *tx)
    .await
    .map_err(DbError::from)?;
    tx.commit().await.map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// One soft-deleted session, for the sweep's repair half.
#[derive(Clone, Debug, FromRow)]
pub struct DeletedSessionRow {
    pub address: AddressId,
    #[sqlx(rename = "clientName")]
    pub client_name: String,
    #[sqlx(rename = "sessionId")]
    pub session_id: String,
    #[sqlx(rename = "deletedAt")]
    pub deleted_at: i64,
}

impl bp_common::live_client_key::SessionKey for DeletedSessionRow {
    fn address(&self) -> &str {
        self.address.as_str()
    }
    fn worker(&self) -> &str {
        &self.client_name
    }
    fn session_id(&self) -> &str {
        &self.session_id
    }
}

/// Sessions soft-deleted since `since_ms`, input to [`revive_sessions`].
/// Nothing on the share path clears `deletedAt`, so a session wrongly
/// soft-deleted (e.g. its live key was lost) would otherwise stay hidden for
/// the rest of its connection.
pub async fn find_recently_deleted_sessions(
    pool: &PgPool,
    since_ms: i64,
) -> Result<Vec<DeletedSessionRow>, DbError> {
    sqlx::query_as!(
        DeletedSessionRow,
        r#"SELECT
            address AS "address!: AddressId",
            "clientName" AS "client_name!",
            "sessionId" AS "session_id!",
            "deletedAt" AS "deleted_at!"
           FROM client_entity
           WHERE "deletedAt" IS NOT NULL AND "deletedAt" >= $1"#,
        since_ms,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Clear `deletedAt` for the given sessions — the repair half of the
/// dead-session sweep. The caller decides who qualifies; the rule is
/// "its live hash has been written SINCE the soft-delete", which only a
/// session that kept mining can satisfy.
pub async fn revive_sessions(
    pool: &PgPool,
    addresses: &[String],
    client_names: &[String],
    session_ids: &[String],
) -> Result<u64, DbError> {
    let mut tx = pool.begin().await.map_err(DbError::from)?;
    take_client_entity_bulk_write_lock(&mut tx).await?;
    let result = sqlx::query!(
        r#"UPDATE client_entity AS t
           SET "deletedAt" = NULL,
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
             AND t."deletedAt" IS NOT NULL"#,
        addresses,
        client_names,
        session_ids,
    )
    .execute(&mut *tx)
    .await
    .map_err(DbError::from)?;
    tx.commit().await.map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// Replace the JDP placeholder `userAgent` (`jd-client/sv2`, `/sv2`) of an
/// address's sessions once the miner reports its downstream devices.
pub async fn update_sv2_user_agent_by_address<'e, E>(
    executor: E,
    address: &str,
    new_user_agent: &str,
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    // No updated-at trigger exists, so every UPDATE must set it.
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

/// Hard-delete rows soft-deleted before `cutoff_ms`, so the backlog stays
/// bounded.
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

/// Hard-delete `client_statistics_entity` rows older than `cutoff_ms`; the
/// charts read only recent days.
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
    /// Earliest `COALESCE("firstSeen", "startTime")` over all rows of the pair,
    /// soft-deleted included. Not `startTime` alone: [`upsert_client`]
    /// refreshes that on every re-register, while `firstSeen` stays put.
    pub first_seen_ms: i64,
}

/// First-seen time for each requested `(address, clientName)`; pairs with no
/// row are absent. Batched so one device-status pass is one round-trip,
/// served by the primary key's `(address, clientName)` prefix.
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

/// Devices under `addresses` that are connected or were soft-deleted since
/// `deleted_since_ms`: the device-status watch list after a restart, so a
/// miner that died just before it is still reported. The user agent is from
/// the most recently born or deleted session, not the most active one.
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
