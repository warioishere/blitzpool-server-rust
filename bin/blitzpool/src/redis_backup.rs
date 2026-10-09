// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Periodic backup of the PPLNS window and Group-Solo rounds, which live only
//! in Redis (AOF survives a crash, not a logical wipe), to Postgres. Restore
//! is manual only and an APPROXIMATION: keys are dumped one after another, so
//! aggregate and buckets can differ by the shares of one SCAN+DUMP pass.

use std::time::Duration;

use redis::aio::ConnectionManager;
use sqlx::postgres::PgPool;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

/// Default snapshot cadence.
pub(crate) const DEFAULT_INTERVAL: Duration = Duration::from_secs(600);
/// Default retention — older snapshots are pruned each run.
pub(crate) const DEFAULT_RETENTION: Duration = Duration::from_secs(48 * 3600);

/// `(scope, SCAN MATCH pattern)` for every backed-up state.
const SCOPES: &[(&str, &str)] = &[("pplns", "pplns:*"), ("groupsolo", "groupsolo:*")];

/// Keys that describe the running process rather than restorable state: the
/// per-job PPLNS distribution snapshots, which nothing looks up after a Redis
/// loss, the published-output count, which a restore would bring back without
/// its TTL and so freeze at a stale value, and the cold-start rebuild's temp key.
fn is_job_state(key: &str) -> bool {
    key.starts_with("pplns:snapshot:")
        || key == bp_pplns_engine::window::KEY_PUBLISHED_OUTPUTS
        || key == bp_pplns_engine::window::KEY_WINDOW_REBUILD
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum BackupError {
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("db: {0}")]
    Db(#[from] bp_db::DbError),
    #[error("no backup snapshots found in redis_state_backup")]
    NoSnapshots,
}

/// Which scopes a restore touches.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ScopeFilter {
    All,
    Pplns,
    GroupSolo,
}

impl ScopeFilter {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "all" => Some(Self::All),
            "pplns" => Some(Self::Pplns),
            "groupsolo" | "group-solo" => Some(Self::GroupSolo),
            _ => None,
        }
    }

    fn matches(&self, scope: &str) -> bool {
        matches!(
            (self, scope),
            (Self::All, _) | (Self::Pplns, "pplns") | (Self::GroupSolo, "groupsolo")
        )
    }
}

// ─── Backup ─────────────────────────────────────────────────────────

/// Spawn the periodic backup task. Owns a dedicated Redis connection so its
/// `SCAN`/`DUMP` burst never queues behind the share hot-path on the shared
/// multiplexed connection. The first tick fires immediately (a snapshot at
/// boot). Best-effort: a failed run logs + retries next tick, never panics.
pub(crate) fn spawn_backup_task(
    mut redis: ConnectionManager,
    pool: PgPool,
    interval: Duration,
    retention: Duration,
) -> JoinHandle<()> {
    let retention_ms = retention.as_millis() as i64;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        info!(
            interval_secs = interval.as_secs(),
            retention_hours = retention.as_secs() / 3600,
            "redis-state-backup: task live (PPLNS + Group-Solo → Postgres)"
        );
        loop {
            tick.tick().await;
            match run_backup_once(&mut redis, &pool, retention_ms).await {
                Ok(0) => debug!("redis-state-backup: nothing to snapshot"),
                Ok(n) => debug!(keys = n, "redis-state-backup: snapshot written"),
                Err(err) => {
                    warn!(%err, "redis-state-backup: snapshot failed; retry next tick")
                }
            }
        }
    })
}

/// Capture one snapshot: `DUMP` every in-scope key, write it under a shared
/// `captured_at`, prune snapshots older than the retention window.
pub(crate) async fn run_backup_once(
    redis: &mut ConnectionManager,
    pool: &PgPool,
    retention_ms: i64,
) -> Result<usize, BackupError> {
    let captured_at = chrono::Utc::now().timestamp_millis();

    let mut scopes: Vec<String> = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    let mut dumps: Vec<Vec<u8>> = Vec::new();

    for (scope, pattern) in SCOPES {
        for key in scan_keys(redis, pattern).await? {
            if is_job_state(&key) {
                continue;
            }
            // `Option`: the key may vanish between SCAN and DUMP (trim/reset).
            if let Some(dump) = dump_key(redis, &key).await? {
                scopes.push((*scope).to_string());
                keys.push(key);
                dumps.push(dump);
            }
        }
    }

    if keys.is_empty() {
        // Still prune so a long-idle pool doesn't keep stale snapshots forever.
        bp_db::prune_redis_backups_before(pool, captured_at - retention_ms).await?;
        return Ok(0);
    }

    bp_db::insert_redis_backup(pool, captured_at, &scopes, &keys, &dumps).await?;
    bp_db::prune_redis_backups_before(pool, captured_at - retention_ms).await?;
    Ok(keys.len())
}

/// Non-blocking cursor SCAN for every key matching `pattern`.
async fn scan_keys(
    redis: &mut ConnectionManager,
    pattern: &str,
) -> Result<Vec<String>, redis::RedisError> {
    let mut cursor: u64 = 0;
    let mut out = Vec::new();
    loop {
        let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(512)
            .query_async(redis)
            .await?;
        out.extend(batch);
        cursor = next;
        if cursor == 0 {
            break;
        }
    }
    Ok(out)
}

/// `DUMP key` → verbatim serialized value, or `None` if the key is gone.
async fn dump_key(
    redis: &mut ConnectionManager,
    key: &str,
) -> Result<Option<Vec<u8>>, redis::RedisError> {
    redis::cmd("DUMP").arg(key).query_async(redis).await
}

// ─── Restore (manual) ───────────────────────────────────────────────

/// Manually restore a snapshot into Redis. Default is a dry-run (prints the
/// plan); `force` actually `RESTORE`s. Overwrites the listed keys (`REPLACE`);
/// keys not in the snapshot are left untouched.
pub(crate) async fn run_restore(
    pool: &PgPool,
    redis: &mut ConnectionManager,
    at: Option<i64>,
    scope: ScopeFilter,
    force: bool,
) -> Result<(), BackupError> {
    let captured_at = match at {
        Some(t) => t,
        None => bp_db::latest_redis_backup_captured_at(pool)
            .await?
            .ok_or(BackupError::NoSnapshots)?,
    };

    let rows: Vec<bp_db::RedisBackupRow> = bp_db::fetch_redis_backup(pool, captured_at)
        .await?
        .into_iter()
        .filter(|r| scope.matches(&r.scope))
        .collect();

    eprintln!(
        "snapshot captured_at={captured_at} ({}), scope={scope:?}: {} key(s)",
        fmt_ms(captured_at),
        rows.len()
    );
    if rows.is_empty() {
        eprintln!("  (nothing to restore for this snapshot/scope)");
        return Ok(());
    }
    for r in &rows {
        eprintln!("  [{}] {} ({} bytes)", r.scope, r.redis_key, r.dump.len());
    }

    if !force {
        eprintln!(
            "\nDRY RUN — nothing written. Re-run with --restore-force to RESTORE \
             (this OVERWRITES the current Redis state for these keys)."
        );
        return Ok(());
    }

    for r in &rows {
        redis::cmd("RESTORE")
            .arg(&r.redis_key)
            .arg(0i64) // no TTL
            .arg(r.dump.as_slice())
            .arg("REPLACE")
            .query_async::<()>(redis)
            .await?;
    }
    eprintln!(
        "\nRESTORED {} key(s) from captured_at={captured_at}.",
        rows.len()
    );
    Ok(())
}

/// Print the most recent snapshots so an operator can pick a `--restore-at`.
pub(crate) async fn list_snapshots(pool: &PgPool) -> Result<(), BackupError> {
    let snaps = bp_db::list_redis_backup_snapshots(pool, 50).await?;
    if snaps.is_empty() {
        eprintln!("no redis_state_backup snapshots yet");
        return Ok(());
    }
    eprintln!("captured_at (epoch ms)   when                       keys");
    for s in snaps {
        eprintln!(
            "{:<24} {:<26} {}",
            s.captured_at,
            fmt_ms(s.captured_at),
            s.key_count
        );
    }
    Ok(())
}

fn fmt_ms(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| "?".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::AsyncCommands;

    const PG_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";
    const RETENTION_MS: i64 = 48 * 3600 * 1000;

    /// Job state (per-job snapshots, the published-output count, the rebuild
    /// temp key) is skipped,
    /// window and round state are not.
    #[test]
    fn job_state_is_classified_apart_from_restorable_state() {
        let fp = "ab".repeat(32);
        assert!(is_job_state(&format!("pplns:snapshot:{fp}")));
        assert!(is_job_state("pplns:published_outputs"));
        assert!(is_job_state("pplns:window:by-address:rebuild"));

        assert!(!is_job_state("pplns:window:by-address"));
        assert!(!is_job_state("pplns:window:total"));
        assert!(!is_job_state("pplns:buckets"));
        assert!(!is_job_state("groupsolo:g1:shares"));
        assert!(!is_job_state("groupsolo:g1:by-address"));
    }

    async fn pg_or_skip() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| PG_URL.to_string());
        let db = tokio::time::timeout(Duration::from_secs(2), bp_db::Db::connect(&url))
            .await
            .ok()?
            .ok()?;
        Some(db.pool().clone())
    }

    /// Backup, wipe, restore returns every key byte-for-byte; skips and `--scope` hold.
    #[tokio::test]
    async fn backup_then_restore_roundtrip_restores_exact_state() {
        // Index 0 of the second range: the first one is full.
        let Some(mut redis) = bp_test_support::connect_redis_in_range_or_skip(
            bp_test_support::redis_db::BLITZPOOL_BIN_2,
            0,
        )
        .await
        else {
            eprintln!("redis unreachable — skipping redis-state-backup roundtrip");
            return;
        };
        let Some(pool) = pg_or_skip().await else {
            eprintln!("pg unreachable — skipping redis-state-backup roundtrip");
            return;
        };

        // PPLNS aggregate (hash) + total (string), a Group-Solo round (zset +
        // by-address hash), and a transient rebuild temp that MUST be skipped.
        let _: () = redis
            .hset("pplns:window:by-address", "bc1qa", "100")
            .await
            .unwrap();
        let _: () = redis
            .hset("pplns:window:by-address", "bc1qb", "50")
            .await
            .unwrap();
        let _: () = redis.set("pplns:window:total", "150").await.unwrap();
        let _: () = redis
            .zadd("groupsolo:test-g:shares", "bc1qa:5:1700000000000", 1i64)
            .await
            .unwrap();
        let _: () = redis
            .hset("groupsolo:test-g:by-address", "bc1qa", "5")
            .await
            .unwrap();
        let _: () = redis
            .hset("pplns:window:by-address:rebuild", "x", "1")
            .await
            .unwrap();
        // A per-job coinbase snapshot, which the backup must leave alone.
        let _: () = redis
            .hset(format!("pplns:snapshot:{}", "ab".repeat(32)), "reward", "1")
            .await
            .unwrap();

        let n = run_backup_once(&mut redis, &pool, RETENTION_MS)
            .await
            .expect("backup");
        assert_eq!(
            n, 4,
            "4 keys backed up (rebuild temp + per-job snapshot skipped)"
        );

        let captured = bp_db::latest_redis_backup_captured_at(&pool)
            .await
            .unwrap()
            .expect("a snapshot exists");

        // Simulate the wipe the whole feature defends against.
        let _: () = redis::cmd("FLUSHDB").query_async(&mut redis).await.unwrap();
        assert!(!redis
            .exists::<_, bool>("pplns:window:by-address")
            .await
            .unwrap());

        run_restore(&pool, &mut redis, Some(captured), ScopeFilter::All, true)
            .await
            .expect("restore");

        let by_addr: std::collections::HashMap<String, String> =
            redis.hgetall("pplns:window:by-address").await.unwrap();
        assert_eq!(by_addr.get("bc1qa").map(String::as_str), Some("100"));
        assert_eq!(by_addr.get("bc1qb").map(String::as_str), Some("50"));
        assert_eq!(
            redis.get::<_, String>("pplns:window:total").await.unwrap(),
            "150"
        );
        assert_eq!(
            redis
                .hget::<_, _, String>("groupsolo:test-g:by-address", "bc1qa")
                .await
                .unwrap(),
            "5"
        );
        assert_eq!(
            redis
                .zscore::<_, _, f64>("groupsolo:test-g:shares", "bc1qa:5:1700000000000")
                .await
                .unwrap(),
            1.0
        );
        assert!(
            !redis
                .exists::<_, bool>("pplns:window:by-address:rebuild")
                .await
                .unwrap(),
            "transient rebuild temp was not backed up, so not restored"
        );

        // Scope filter: restoring only `groupsolo` after a wipe brings back just
        // that scope's keys.
        let _: () = redis::cmd("FLUSHDB").query_async(&mut redis).await.unwrap();
        run_restore(
            &pool,
            &mut redis,
            Some(captured),
            ScopeFilter::GroupSolo,
            true,
        )
        .await
        .expect("restore groupsolo-only");
        assert!(redis
            .exists::<_, bool>("groupsolo:test-g:by-address")
            .await
            .unwrap());
        assert!(
            !redis.exists::<_, bool>("pplns:window:total").await.unwrap(),
            "pplns keys not restored under --scope groupsolo"
        );

        // Cleanup so the shared test DB / redis db don't accumulate.
        let _ = bp_db::prune_redis_backups_before(&pool, captured + 1).await;
        let _: () = redis::cmd("FLUSHDB").query_async(&mut redis).await.unwrap();
    }
}
