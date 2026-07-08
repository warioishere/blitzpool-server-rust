// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bulk-write primitives consumed by the share-stats coordinator
//! (`bp-share-stats-sink`).
//!
//! UNNEST-based bulk upserts — every write is **increment-semantic**
//! (`col = table.col + EXCLUDED.col` on conflict), so partial / retried
//! flushes are idempotent against the accumulator drain/confirm contract:
//! a flush that succeeded in PG but never confirmed gets re-included on
//! the next tick, and `+= snapshot` on both sides keeps the totals
//! eventually consistent.
//!
//! The 9 functions in this file split into three groups:
//!
//! 1. **Slot-bucketed stats** (5 tables, 10-minute slot granularity):
//!    `pool_share_statistics_entity`, `pool_mode_hashrate`,
//!    `pool_rejected_statistics_entity`, `client_statistics_entity`,
//!    `client_rejected_statistics_entity`. All use UNNEST + ON CONFLICT
//!    DO UPDATE with `+ EXCLUDED.col` accumulation.
//! 2. **Lifetime totals** (2 tables, no slot dim):
//!    `address_settings_entity.shares` (UPDATE FROM UNNEST — row already
//!    exists, no insert) and `worker_shares_entity` (composite-PK INSERT
//!    … ON CONFLICT DO UPDATE — may need to create the row).
//! 3. **Seed bootstrap** (2 funcs): `count_worker_shares` +
//!    `seed_worker_shares_from_client_statistics` for the one-shot boot
//!    one-shot boot migration that seeds worker-share rows from accumulated client statistics.

use crate::pool::DbError;

// ── 1. Slot-bucketed stats ──────────────────────────────────────────

/// One row in a `pool_share_statistics_entity` bulk-upsert. `accepted`
/// and `rejected` are diff sums (NOT share counts) for the 10-minute
/// slot whose end aligns with `time_ms`.
#[derive(Clone, Debug)]
pub struct PoolShareStatsUpsert {
    pub time_ms: i64,
    pub accepted: f32,
    pub rejected: f32,
}

/// Bulk-upsert pool-wide share statistics. `ON CONFLICT ("time") DO
/// UPDATE` adds `EXCLUDED` to the current values so two flushes with
/// the same slot sum cleanly. Updates `updatedAt` to current epoch ms.
pub async fn bulk_upsert_pool_share_statistics<'e, E>(
    executor: E,
    rows: &[PoolShareStatsUpsert],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(0);
    }
    let times: Vec<i64> = rows.iter().map(|r| r.time_ms).collect();
    let accepted: Vec<f32> = rows.iter().map(|r| r.accepted).collect();
    let rejected: Vec<f32> = rows.iter().map(|r| r.rejected).collect();

    let result = sqlx::query!(
        r#"INSERT INTO pool_share_statistics_entity ("time", accepted, rejected, "updatedAt")
           SELECT u.t, u.a, u.r, (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint
           FROM UNNEST($1::bigint[], $2::real[], $3::real[]) AS u(t, a, r)
           ON CONFLICT ("time") DO UPDATE
           SET accepted   = pool_share_statistics_entity.accepted  + EXCLUDED.accepted,
               rejected   = pool_share_statistics_entity.rejected  + EXCLUDED.rejected,
               "updatedAt" = EXCLUDED."updatedAt""#,
        &times,
        &accepted,
        &rejected,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// One row in a `pool_mode_hashrate` bulk-upsert. `diff` is the
/// accepted-share diff sum for `(mode, slot)`.
#[derive(Clone, Debug)]
pub struct PoolModeHashrateUpsert {
    pub mode: String,
    pub time_ms: i64,
    pub diff: f32,
}

/// Bulk-upsert per-mode hashrate samples. UNIQUE (mode, "time") drives
/// the conflict path.
pub async fn bulk_upsert_pool_mode_hashrate<'e, E>(
    executor: E,
    rows: &[PoolModeHashrateUpsert],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(0);
    }
    let modes: Vec<String> = rows.iter().map(|r| r.mode.clone()).collect();
    let times: Vec<i64> = rows.iter().map(|r| r.time_ms).collect();
    let diffs: Vec<f32> = rows.iter().map(|r| r.diff).collect();

    let result = sqlx::query!(
        r#"INSERT INTO pool_mode_hashrate (mode, "time", diff)
           SELECT * FROM UNNEST($1::varchar[], $2::bigint[], $3::real[])
           ON CONFLICT (mode, "time") DO UPDATE
           SET diff = pool_mode_hashrate.diff + EXCLUDED.diff"#,
        &modes,
        &times,
        &diffs,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// One row in a `pool_rejected_statistics_entity` bulk-upsert. `count`
/// is the rejected-share count (integer-valued real) for `(slot, reason)`.
#[derive(Clone, Debug)]
pub struct PoolRejectedStatsUpsert {
    pub time_ms: i64,
    pub reason: String,
    pub count: f32,
}

pub async fn bulk_upsert_pool_rejected_statistics<'e, E>(
    executor: E,
    rows: &[PoolRejectedStatsUpsert],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(0);
    }
    let times: Vec<i64> = rows.iter().map(|r| r.time_ms).collect();
    let reasons: Vec<String> = rows.iter().map(|r| r.reason.clone()).collect();
    let counts: Vec<f32> = rows.iter().map(|r| r.count).collect();

    let result = sqlx::query!(
        r#"INSERT INTO pool_rejected_statistics_entity ("time", reason, count, "updatedAt")
           SELECT u.t, u.r, u.c, (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint
           FROM UNNEST($1::bigint[], $2::varchar[], $3::real[]) AS u(t, r, c)
           ON CONFLICT ("time", reason) DO UPDATE
           SET count      = pool_rejected_statistics_entity.count + EXCLUDED.count,
               "updatedAt" = EXCLUDED."updatedAt""#,
        &times,
        &reasons,
        &counts,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// One row in a `client_statistics_entity` bulk-upsert — the big
/// 9-field-per-key bucket. Counts are `i32`; diff fields are `f32`.
#[derive(Clone, Debug)]
pub struct ClientStatsUpsert {
    pub address: String,
    pub client_name: String,
    pub session_id: String,
    pub time_ms: i64,
    pub shares: f32,
    pub accepted_count: i32,
    pub rejected_count: i32,
    pub rejected_job_not_found_count: i32,
    pub rejected_job_not_found_diff1: f32,
    pub rejected_duplicate_share_count: i32,
    pub rejected_duplicate_share_diff1: f32,
    pub rejected_low_difficulty_share_count: i32,
    pub rejected_low_difficulty_share_diff1: f32,
}

/// Bulk-upsert client-statistics rows. UNIQUE (address, clientName,
/// sessionId, "time") drives ON CONFLICT; all 9 numeric fields
/// accumulate via `+ EXCLUDED.col`.
///
/// **Caller responsibility**: batch in chunks ≤ 1000 to stay under
/// the PG parameter limit (each batch sends 13 arrays of length N;
/// the limit is 65 535 parameters but `UNNEST` itself counts each
/// inner element). 1000 rows = 13 000 conceptual elements; well safe.
pub async fn bulk_upsert_client_statistics_entity<'e, E>(
    executor: E,
    rows: &[ClientStatsUpsert],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(0);
    }
    let addresses: Vec<String> = rows.iter().map(|r| r.address.clone()).collect();
    let client_names: Vec<String> = rows.iter().map(|r| r.client_name.clone()).collect();
    let session_ids: Vec<String> = rows.iter().map(|r| r.session_id.clone()).collect();
    let times: Vec<i64> = rows.iter().map(|r| r.time_ms).collect();
    let shares: Vec<f32> = rows.iter().map(|r| r.shares).collect();
    let accepted: Vec<i32> = rows.iter().map(|r| r.accepted_count).collect();
    let rejected: Vec<i32> = rows.iter().map(|r| r.rejected_count).collect();
    let r_jnf_count: Vec<i32> = rows
        .iter()
        .map(|r| r.rejected_job_not_found_count)
        .collect();
    let r_jnf_diff: Vec<f32> = rows
        .iter()
        .map(|r| r.rejected_job_not_found_diff1)
        .collect();
    let r_dup_count: Vec<i32> = rows
        .iter()
        .map(|r| r.rejected_duplicate_share_count)
        .collect();
    let r_dup_diff: Vec<f32> = rows
        .iter()
        .map(|r| r.rejected_duplicate_share_diff1)
        .collect();
    let r_low_count: Vec<i32> = rows
        .iter()
        .map(|r| r.rejected_low_difficulty_share_count)
        .collect();
    let r_low_diff: Vec<f32> = rows
        .iter()
        .map(|r| r.rejected_low_difficulty_share_diff1)
        .collect();

    let result = sqlx::query!(
        r#"INSERT INTO client_statistics_entity
             (address, "clientName", "sessionId", "time", shares,
              "acceptedCount", "rejectedCount",
              "rejectedJobNotFoundCount",      "rejectedJobNotFoundDiff1",
              "rejectedDuplicateShareCount",   "rejectedDuplicateShareDiff1",
              "rejectedLowDifficultyShareCount","rejectedLowDifficultyShareDiff1",
              "updatedAt")
           SELECT
             u.addr, u.cname, u.sid, u.t, u.sh,
             u.ac,  u.rc,
             u.rjc, u.rjd,
             u.rdc, u.rdd,
             u.rlc, u.rld,
             (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint
           FROM UNNEST(
             $1::varchar[], $2::varchar[], $3::varchar[], $4::bigint[], $5::real[],
             $6::int[], $7::int[],
             $8::int[], $9::real[],
             $10::int[], $11::real[],
             $12::int[], $13::real[]
           ) AS u(addr, cname, sid, t, sh, ac, rc, rjc, rjd, rdc, rdd, rlc, rld)
           ON CONFLICT (address, "clientName", "sessionId", "time") DO UPDATE
           SET shares                              = client_statistics_entity.shares                              + EXCLUDED.shares,
               "acceptedCount"                     = client_statistics_entity."acceptedCount"                     + EXCLUDED."acceptedCount",
               "rejectedCount"                     = client_statistics_entity."rejectedCount"                     + EXCLUDED."rejectedCount",
               "rejectedJobNotFoundCount"          = client_statistics_entity."rejectedJobNotFoundCount"          + EXCLUDED."rejectedJobNotFoundCount",
               "rejectedJobNotFoundDiff1"          = client_statistics_entity."rejectedJobNotFoundDiff1"          + EXCLUDED."rejectedJobNotFoundDiff1",
               "rejectedDuplicateShareCount"       = client_statistics_entity."rejectedDuplicateShareCount"       + EXCLUDED."rejectedDuplicateShareCount",
               "rejectedDuplicateShareDiff1"       = client_statistics_entity."rejectedDuplicateShareDiff1"       + EXCLUDED."rejectedDuplicateShareDiff1",
               "rejectedLowDifficultyShareCount"   = client_statistics_entity."rejectedLowDifficultyShareCount"   + EXCLUDED."rejectedLowDifficultyShareCount",
               "rejectedLowDifficultyShareDiff1"   = client_statistics_entity."rejectedLowDifficultyShareDiff1"   + EXCLUDED."rejectedLowDifficultyShareDiff1",
               "updatedAt"                         = EXCLUDED."updatedAt""#,
        &addresses,
        &client_names,
        &session_ids,
        &times,
        &shares,
        &accepted,
        &rejected,
        &r_jnf_count,
        &r_jnf_diff,
        &r_dup_count,
        &r_dup_diff,
        &r_low_count,
        &r_low_diff,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// One row in a `client_rejected_statistics_entity` bulk-upsert.
/// `count` is the share count (integer-valued real); `shares` is the
/// diff sum.
#[derive(Clone, Debug)]
pub struct ClientRejectedStatsUpsert {
    pub address: String,
    pub time_ms: i64,
    pub reason: String,
    pub count: f32,
    pub shares: f32,
}

pub async fn bulk_upsert_client_rejected_statistics_entity<'e, E>(
    executor: E,
    rows: &[ClientRejectedStatsUpsert],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(0);
    }
    let addresses: Vec<String> = rows.iter().map(|r| r.address.clone()).collect();
    let times: Vec<i64> = rows.iter().map(|r| r.time_ms).collect();
    let reasons: Vec<String> = rows.iter().map(|r| r.reason.clone()).collect();
    let counts: Vec<f32> = rows.iter().map(|r| r.count).collect();
    let share_sums: Vec<f32> = rows.iter().map(|r| r.shares).collect();

    let result = sqlx::query!(
        r#"INSERT INTO client_rejected_statistics_entity
             (address, "time", reason, count, shares, "updatedAt")
           SELECT
             u.a, u.t, u.r, u.c, u.s,
             (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint
           FROM UNNEST($1::varchar[], $2::bigint[], $3::varchar[], $4::real[], $5::real[])
             AS u(a, t, r, c, s)
           ON CONFLICT (address, "time", reason) DO UPDATE
           SET count      = client_rejected_statistics_entity.count  + EXCLUDED.count,
               shares     = client_rejected_statistics_entity.shares + EXCLUDED.shares,
               "updatedAt" = EXCLUDED."updatedAt""#,
        &addresses,
        &times,
        &reasons,
        &counts,
        &share_sums,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

// ── 2. Lifetime totals ──────────────────────────────────────────────

/// One row in a `address_settings_entity.shares` bulk-update.
/// `delta_shares` is added to the existing value (not absolute).
#[derive(Clone, Debug)]
pub struct AddressSharesUpdate {
    pub address: String,
    pub delta_shares: f64,
}

/// Bulk-increment lifetime per-address share totals. Address rows must
/// already exist (created on first authorize via `bp-session-persistence`);
/// missing rows are silently skipped. `updatedAt` is intentionally NOT
/// touched: it tracks the moment a miner set a new best difficulty
/// (surfaced as the timestamp next to each entry on /api/info).
/// Bumping it on every share-flush would destroy that semantic — the UI
/// would show "updated just now" for every actively mining address.
pub async fn bulk_update_address_settings_shares<'e, E>(
    executor: E,
    rows: &[AddressSharesUpdate],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(0);
    }
    let addresses: Vec<String> = rows.iter().map(|r| r.address.clone()).collect();
    let deltas: Vec<f64> = rows.iter().map(|r| r.delta_shares).collect();

    let result = sqlx::query!(
        r#"UPDATE address_settings_entity AS t
           SET shares = t.shares + u.d
           FROM (SELECT UNNEST($1::varchar[]) AS address,
                        UNNEST($2::double precision[]) AS d) AS u
           WHERE t.address = u.address"#,
        &addresses,
        &deltas,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// One row in an `address_settings_entity."bestDifficulty"` bulk-upsert.
/// `best_difficulty` is the window's MAX candidate for the address (folded
/// in via `GREATEST`, not added).
#[derive(Clone, Debug)]
pub struct AddressBestDifficultyUpsert {
    pub address: String,
    pub best_difficulty: f64,
    pub user_agent: Option<String>,
}

/// Fold each address's window-max best difficulty into
/// `address_settings_entity."bestDifficulty"` via `GREATEST` — the
/// all-time record only grows. Idempotent: re-applying the same batch is a
/// no-op. `"bestDifficultyUserAgent"` + `"updatedAt"` move only when the
/// value actually grows (so `/api/info` keeps showing when the best was
/// last set). Inserts the row if the address has none yet.
pub async fn bulk_upsert_address_best_difficulty<'e, E>(
    executor: E,
    rows: &[AddressBestDifficultyUpsert],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(0);
    }
    let addresses: Vec<String> = rows.iter().map(|r| r.address.clone()).collect();
    let bests: Vec<f64> = rows.iter().map(|r| r.best_difficulty).collect();
    let user_agents: Vec<Option<String>> = rows.iter().map(|r| r.user_agent.clone()).collect();

    let result = sqlx::query!(
        r#"INSERT INTO address_settings_entity
             (address, "bestDifficulty", "bestDifficultyUserAgent", "createdAt", "updatedAt")
           SELECT u.address, u.bd, u.ua,
                  (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint,
                  (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint
           FROM UNNEST($1::varchar[], $2::double precision[], $3::varchar[])
                AS u(address, bd, ua)
           ON CONFLICT (address) DO UPDATE SET
             "bestDifficultyUserAgent" = CASE
                 WHEN EXCLUDED."bestDifficulty" > address_settings_entity."bestDifficulty"
                 THEN EXCLUDED."bestDifficultyUserAgent"
                 ELSE address_settings_entity."bestDifficultyUserAgent" END,
             "updatedAt" = CASE
                 WHEN EXCLUDED."bestDifficulty" > address_settings_entity."bestDifficulty"
                 THEN EXCLUDED."updatedAt"
                 ELSE address_settings_entity."updatedAt" END,
             "bestDifficulty" = GREATEST(
                 address_settings_entity."bestDifficulty", EXCLUDED."bestDifficulty")"#,
        &addresses,
        &bests,
        &user_agents as &[Option<String>],
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

/// One row in a `worker_shares_entity` bulk-upsert. Both deltas add to
/// existing values; missing rows are inserted with the delta as the
/// initial value.
#[derive(Clone, Debug)]
pub struct WorkerSharesUpsert {
    pub address: String,
    pub client_name: String,
    pub delta_shares: f64,
    pub delta_rejected_shares: f64,
}

/// Bulk-upsert lifetime per-worker share + rejected-share totals.
/// Composite PK `(address, clientName)`. On conflict, both fields
/// accumulate.
pub async fn bulk_upsert_worker_shares_entity<'e, E>(
    executor: E,
    rows: &[WorkerSharesUpsert],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(0);
    }
    let addresses: Vec<String> = rows.iter().map(|r| r.address.clone()).collect();
    let client_names: Vec<String> = rows.iter().map(|r| r.client_name.clone()).collect();
    let shares: Vec<f64> = rows.iter().map(|r| r.delta_shares).collect();
    let rejected: Vec<f64> = rows.iter().map(|r| r.delta_rejected_shares).collect();

    let result = sqlx::query!(
        r#"INSERT INTO worker_shares_entity (address, "clientName", shares, "rejectedShares")
           SELECT * FROM UNNEST($1::varchar[], $2::varchar[], $3::double precision[], $4::double precision[])
           ON CONFLICT (address, "clientName") DO UPDATE
           SET shares          = worker_shares_entity.shares          + EXCLUDED.shares,
               "rejectedShares" = worker_shares_entity."rejectedShares" + EXCLUDED."rejectedShares""#,
        &addresses,
        &client_names,
        &shares,
        &rejected,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

// ── 3. Seed bootstrap ──────────────────────────────────────────────

/// Count of rows in `worker_shares_entity`. Used by
/// `bp-share-stats-sink::seed::seed_if_empty` to detect a fresh-DB
/// setup that needs the one-shot bootstrap migration.
pub async fn count_worker_shares<'e, E>(executor: E) -> Result<i64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query!(r#"SELECT COUNT(*) AS "count!" FROM worker_shares_entity"#)
        .fetch_one(executor)
        .await
        .map_err(DbError::from)?;
    Ok(row.count)
}

/// One-shot bootstrap: aggregate `client_statistics_entity` into
/// initial `worker_shares_entity` rows. Idempotent: ON CONFLICT DO
/// NOTHING — if rows exist already (concurrent seed by another
/// instance), the second call is harmless.
///
/// Aggregates `shares` (accepted-diff sum) and the three
/// `rejected*Diff1` columns into `rejectedShares` (`rejectedShares` is
/// the diff sum across all reject reasons).
pub async fn seed_worker_shares_from_client_statistics<'e, E>(executor: E) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"INSERT INTO worker_shares_entity (address, "clientName", shares, "rejectedShares")
           SELECT address,
                  "clientName",
                  SUM(shares)::double precision,
                  SUM("rejectedJobNotFoundDiff1"
                      + "rejectedDuplicateShareDiff1"
                      + "rejectedLowDifficultyShareDiff1")::double precision
           FROM client_statistics_entity
           GROUP BY address, "clientName"
           ON CONFLICT (address, "clientName") DO NOTHING"#,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}
