// SPDX-License-Identifier: AGPL-3.0-or-later

//! Periodic best-effort backup of the live PPLNS + Group-Solo Redis state
//! (`redis_state_backup`), for MANUAL operator-triggered reconstruction after a
//! Redis wipe / corruption / bad deploy. One row per Redis key (verbatim `DUMP`
//! payload) per backup run, all sharing a `captured_at` (epoch ms). There is no
//! automatic restore — see `bin/blitzpool/src/redis_backup.rs`.

use sqlx::postgres::PgPool;

use crate::DbError;

/// One backed-up Redis key from a snapshot.
#[derive(Clone, Debug)]
pub struct RedisBackupRow {
    pub scope: String,
    pub redis_key: String,
    pub dump: Vec<u8>,
}

/// One snapshot's summary (for the restore tool's `--list`).
#[derive(Clone, Debug)]
pub struct RedisBackupSnapshot {
    pub captured_at: i64,
    pub key_count: i64,
}

/// Insert all keys of one backup run under a shared `captured_at` (epoch ms).
/// Batched via `unnest` so a whole snapshot is one round-trip. Returns rows
/// written.
pub async fn insert_redis_backup(
    pool: &PgPool,
    captured_at: i64,
    scopes: &[String],
    keys: &[String],
    dumps: &[Vec<u8>],
) -> Result<u64, DbError> {
    let res = sqlx::query!(
        r#"INSERT INTO redis_state_backup (captured_at, scope, redis_key, dump)
           SELECT $1, s, k, d
           FROM unnest($2::text[], $3::text[], $4::bytea[]) AS u(s, k, d)"#,
        captured_at,
        scopes,
        keys,
        dumps,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Delete snapshots strictly older than `cutoff` (epoch ms). Returns rows removed.
pub async fn prune_redis_backups_before(pool: &PgPool, cutoff: i64) -> Result<u64, DbError> {
    let res = sqlx::query!(
        r#"DELETE FROM redis_state_backup WHERE captured_at < $1"#,
        cutoff,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// The newest snapshot's `captured_at`, or `None` if no backups exist.
pub async fn latest_redis_backup_captured_at(pool: &PgPool) -> Result<Option<i64>, DbError> {
    let row = sqlx::query!(r#"SELECT max(captured_at) AS "max" FROM redis_state_backup"#)
        .fetch_one(pool)
        .await?;
    Ok(row.max)
}

/// All keys of the snapshot taken at `captured_at`.
pub async fn fetch_redis_backup(
    pool: &PgPool,
    captured_at: i64,
) -> Result<Vec<RedisBackupRow>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT scope, redis_key, dump
           FROM redis_state_backup WHERE captured_at = $1"#,
        captured_at,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| RedisBackupRow {
            scope: r.scope,
            redis_key: r.redis_key,
            dump: r.dump,
        })
        .collect())
}

/// The most recent `limit` snapshots, newest first, with their key counts.
pub async fn list_redis_backup_snapshots(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<RedisBackupSnapshot>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT captured_at, count(*) AS "key_count!"
           FROM redis_state_backup
           GROUP BY captured_at
           ORDER BY captured_at DESC
           LIMIT $1"#,
        limit,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| RedisBackupSnapshot {
            captured_at: r.captured_at,
            key_count: r.key_count,
        })
        .collect())
}
