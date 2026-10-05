// SPDX-License-Identifier: AGPL-3.0-or-later

//! UNNEST bulk upserts for the share-stats sink. Every write adds onto the
//! stored row (`col + EXCLUDED.col` on conflict, maxima via `GREATEST`), so a
//! second process can finish a slot the first one started. Sending the same
//! delta twice counts it twice.

use crate::pool::DbError;

// ── 1. Slot-bucketed stats ──────────────────────────────────────────

/// One row in a `pool_share_statistics_entity` bulk-upsert. `accepted`
/// and `rejected` are diff sums (NOT share counts) for the 10-minute
/// slot whose end aligns with `time_ms`; `max_difficulty` is the highest
/// single share difficulty in it.
#[derive(Clone, Debug)]
pub struct PoolShareStatsUpsert {
    pub time_ms: i64,
    pub accepted: f32,
    pub rejected: f32,
    pub max_difficulty: f32,
}

/// Bulk-upsert pool-wide share statistics. `ON CONFLICT ("time") DO
/// UPDATE` adds `EXCLUDED` to the current sums so two flushes with the
/// same slot sum cleanly, and keeps the greater `maxDifficulty`. Updates
/// `updatedAt` to current epoch ms.
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
    let max_difficulty: Vec<f32> = rows.iter().map(|r| r.max_difficulty).collect();

    let result = sqlx::query!(
        r#"INSERT INTO pool_share_statistics_entity ("time", accepted, rejected, "maxDifficulty", "updatedAt")
           SELECT u.t, u.a, u.r, u.m, (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint
           FROM UNNEST($1::bigint[], $2::real[], $3::real[], $4::real[]) AS u(t, a, r, m)
           ON CONFLICT ("time") DO UPDATE
           SET accepted        = pool_share_statistics_entity.accepted  + EXCLUDED.accepted,
               rejected        = pool_share_statistics_entity.rejected  + EXCLUDED.rejected,
               "maxDifficulty" = GREATEST(pool_share_statistics_entity."maxDifficulty", EXCLUDED."maxDifficulty"),
               "updatedAt"     = EXCLUDED."updatedAt""#,
        &times,
        &accepted,
        &rejected,
        &max_difficulty,
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

/// One row in a `pool_rejected_statistics_entity` bulk-upsert. `count` is
/// the difficulty sum of the slot's rejects for `reason`, not their number.
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

/// One row in a `client_statistics_entity` bulk-upsert. Counts are `i32`;
/// diff fields are `f32`.
#[derive(Clone, Debug)]
pub struct ClientStatsUpsert {
    pub address: String,
    pub client_name: String,
    pub session_id: String,
    pub time_ms: i64,
    pub shares: f32,
    pub rejected_job_not_found_count: i32,
    pub rejected_job_not_found_diff1: f32,
    pub rejected_duplicate_share_count: i32,
    pub rejected_duplicate_share_diff1: f32,
    pub rejected_low_difficulty_share_count: i32,
    pub rejected_low_difficulty_share_diff1: f32,
    pub rejected_version_rolling_count: i32,
    pub rejected_version_rolling_diff1: f32,
    pub rejected_stale_count: i32,
    pub rejected_stale_diff1: f32,
    pub max_difficulty: f32,
}

/// Bulk-upsert client-statistics rows. UNIQUE (address, clientName,
/// sessionId, "time") drives ON CONFLICT; numeric fields accumulate, the
/// slot maximum through `GREATEST`. The columns travel as arrays, so the
/// row count adds no bind parameters.
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
    let r_vr_count: Vec<i32> = rows
        .iter()
        .map(|r| r.rejected_version_rolling_count)
        .collect();
    let r_vr_diff: Vec<f32> = rows
        .iter()
        .map(|r| r.rejected_version_rolling_diff1)
        .collect();
    let r_stale_count: Vec<i32> = rows.iter().map(|r| r.rejected_stale_count).collect();
    let r_stale_diff: Vec<f32> = rows.iter().map(|r| r.rejected_stale_diff1).collect();
    let max_difficulty: Vec<f32> = rows.iter().map(|r| r.max_difficulty).collect();

    let result = sqlx::query!(
        r#"INSERT INTO client_statistics_entity
             (address, "clientName", "sessionId", "time", shares,
              "rejectedJobNotFoundCount",      "rejectedJobNotFoundDiff1",
              "rejectedDuplicateShareCount",   "rejectedDuplicateShareDiff1",
              "rejectedLowDifficultyShareCount","rejectedLowDifficultyShareDiff1",
              "rejectedVersionRollingCount",   "rejectedVersionRollingDiff1",
              "rejectedStaleCount",            "rejectedStaleDiff1",
              "maxDifficulty",
              "updatedAt")
           SELECT
             u.addr, u.cname, u.sid, u.t, u.sh,
             u.rjc, u.rjd,
             u.rdc, u.rdd,
             u.rlc, u.rld,
             u.rvc, u.rvd,
             u.rsc, u.rsd,
             u.mx,
             (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint
           FROM UNNEST(
             $1::varchar[], $2::varchar[], $3::varchar[], $4::bigint[], $5::real[],
             $6::int[], $7::real[],
             $8::int[], $9::real[],
             $10::int[], $11::real[],
             $12::int[], $13::real[],
             $14::int[], $15::real[],
             $16::real[]
           ) AS u(addr, cname, sid, t, sh, rjc, rjd, rdc, rdd, rlc, rld, rvc, rvd, rsc, rsd, mx)
           ON CONFLICT (address, "clientName", "sessionId", "time") DO UPDATE
           SET shares                              = client_statistics_entity.shares                              + EXCLUDED.shares,
               "rejectedJobNotFoundCount"          = client_statistics_entity."rejectedJobNotFoundCount"          + EXCLUDED."rejectedJobNotFoundCount",
               "rejectedJobNotFoundDiff1"          = client_statistics_entity."rejectedJobNotFoundDiff1"          + EXCLUDED."rejectedJobNotFoundDiff1",
               "rejectedDuplicateShareCount"       = client_statistics_entity."rejectedDuplicateShareCount"       + EXCLUDED."rejectedDuplicateShareCount",
               "rejectedDuplicateShareDiff1"       = client_statistics_entity."rejectedDuplicateShareDiff1"       + EXCLUDED."rejectedDuplicateShareDiff1",
               "rejectedLowDifficultyShareCount"   = client_statistics_entity."rejectedLowDifficultyShareCount"   + EXCLUDED."rejectedLowDifficultyShareCount",
               "rejectedLowDifficultyShareDiff1"   = client_statistics_entity."rejectedLowDifficultyShareDiff1"   + EXCLUDED."rejectedLowDifficultyShareDiff1",
               "rejectedVersionRollingCount"       = client_statistics_entity."rejectedVersionRollingCount"       + EXCLUDED."rejectedVersionRollingCount",
               "rejectedVersionRollingDiff1"       = client_statistics_entity."rejectedVersionRollingDiff1"       + EXCLUDED."rejectedVersionRollingDiff1",
               "rejectedStaleCount"                = client_statistics_entity."rejectedStaleCount"                + EXCLUDED."rejectedStaleCount",
               "rejectedStaleDiff1"                = client_statistics_entity."rejectedStaleDiff1"                + EXCLUDED."rejectedStaleDiff1",
               "maxDifficulty"                     = GREATEST(client_statistics_entity."maxDifficulty", EXCLUDED."maxDifficulty"),
               "updatedAt"                         = EXCLUDED."updatedAt""#,
        &addresses,
        &client_names,
        &session_ids,
        &times,
        &shares,
        &r_jnf_count,
        &r_jnf_diff,
        &r_dup_count,
        &r_dup_diff,
        &r_low_count,
        &r_low_diff,
        &r_vr_count,
        &r_vr_diff,
        &r_stale_count,
        &r_stale_diff,
        &max_difficulty,
    )
    .execute(executor)
    .await
    .map_err(DbError::from)?;
    Ok(result.rows_affected())
}

// ── 2. Lifetime totals ──────────────────────────────────────────────

/// One row in an `address_settings_entity` bulk-upsert. `delta_shares` is
/// ADDED to the stored total; `best_difficulty` is the window MAX, folded
/// via `GREATEST`; `user_agent` is the firmware of the share that set it.
#[derive(Clone, Debug)]
pub struct AddressSettingsUpsert {
    pub address: String,
    pub delta_shares: f64,
    pub best_difficulty: f64,
    pub user_agent: Option<String>,
}

/// Bulk-upsert the per-address lifetime row. The user agent and
/// `"updatedAt"` move only when the best grows; Postgres evaluates every SET
/// RHS against the pre-update row, so clause order does not matter. The
/// `"allTime*"` columns survive `/bestdiff_reset` and must never be lowered.
pub async fn bulk_upsert_address_settings<'e, E>(
    executor: E,
    rows: &[AddressSettingsUpsert],
) -> Result<u64, DbError>
where
    E: sqlx::PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(0);
    }
    let addresses: Vec<String> = rows.iter().map(|r| r.address.clone()).collect();
    let deltas: Vec<f64> = rows.iter().map(|r| r.delta_shares).collect();
    let bests: Vec<f64> = rows.iter().map(|r| r.best_difficulty).collect();
    let user_agents: Vec<Option<String>> = rows.iter().map(|r| r.user_agent.clone()).collect();

    let result = sqlx::query!(
        r#"INSERT INTO address_settings_entity
             (address, shares, "bestDifficulty", "bestDifficultyUserAgent",
              "allTimeBestDifficulty", "allTimeBestDifficultyUserAgent",
              "allTimeBestDifficultyAt", "createdAt", "updatedAt")
           SELECT u.address, u.dshares, u.bd, u.ua, u.bd, u.ua,
                  (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint,
                  (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint,
                  (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint
           FROM UNNEST($1::varchar[], $2::double precision[], $3::double precision[], $4::varchar[])
                AS u(address, dshares, bd, ua)
           ON CONFLICT (address) DO UPDATE SET
             shares = address_settings_entity.shares + EXCLUDED.shares,
             "bestDifficultyUserAgent" = CASE
                 WHEN EXCLUDED."bestDifficulty" > address_settings_entity."bestDifficulty"
                 THEN EXCLUDED."bestDifficultyUserAgent"
                 ELSE address_settings_entity."bestDifficultyUserAgent" END,
             "updatedAt" = CASE
                 WHEN EXCLUDED."bestDifficulty" > address_settings_entity."bestDifficulty"
                 THEN EXCLUDED."updatedAt"
                 ELSE address_settings_entity."updatedAt" END,
             "bestDifficulty" = GREATEST(
                 address_settings_entity."bestDifficulty", EXCLUDED."bestDifficulty"),
             "allTimeBestDifficultyUserAgent" = CASE
                 WHEN EXCLUDED."bestDifficulty" > address_settings_entity."allTimeBestDifficulty"
                 THEN EXCLUDED."bestDifficultyUserAgent"
                 ELSE address_settings_entity."allTimeBestDifficultyUserAgent" END,
             "allTimeBestDifficultyAt" = CASE
                 WHEN EXCLUDED."bestDifficulty" > address_settings_entity."allTimeBestDifficulty"
                 THEN EXCLUDED."updatedAt"
                 ELSE address_settings_entity."allTimeBestDifficultyAt" END,
             "allTimeBestDifficulty" = GREATEST(
                 address_settings_entity."allTimeBestDifficulty", EXCLUDED."bestDifficulty")"#,
        &addresses,
        &deltas,
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
