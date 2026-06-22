// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `bp-group-solo-engine::reset::GroupResetRunner`
//! against docker-Redis + docker-PG. Each test uses a fresh group
//! (UUID-generated) so cross-test interference is impossible.

use std::sync::Arc;

use bp_cron_utils::TestClock;
use bp_group_solo_engine::reset::{GroupResetRunner, ResetError, RESET_DEBOUNCE_MS};
use bp_group_solo_engine::round::{snapshot, GroupRoundStore};
use redis::{aio::ConnectionManager, Client};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

const REDIS_URL: &str = "redis://127.0.0.1:16379";
const PG_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

async fn connect_or_skip(redis_db: u8) -> Option<(PgPool, ConnectionManager)> {
    let pg_url = std::env::var("BP_PG_URL").unwrap_or_else(|_| PG_URL.to_string());
    let redis_base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_URL.to_string());
    let redis_url = format!("{redis_base}/{redis_db}");

    let pool = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&pg_url),
    )
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            eprintln!("PG connect failed: {e} — skipping");
            return None;
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            return None;
        }
    };
    let client = match Client::open(redis_url.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Redis client failed: {e} — skipping");
            return None;
        }
    };
    let mut conn = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        ConnectionManager::new(client),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            eprintln!("Redis connect failed: {e} — skipping");
            return None;
        }
        Err(_) => {
            eprintln!("redis connect timed out (>2s) — skipping integration test");
            return None;
        }
    };
    if let Err(e) = redis::cmd("FLUSHDB").query_async::<()>(&mut conn).await {
        eprintln!("FLUSHDB failed: {e} — skipping");
        return None;
    }
    Some((pool, conn))
}

async fn seed_group(pool: &PgPool, group_id: Uuid, last_reset_at_ms: Option<i64>) {
    sqlx::query(
        r#"INSERT INTO pplns_group
             (id, name, "creatorAddress", "adminTokenHash", active,
              "createdAt", "updatedAt", "isPublic", "lastRoundResetAt",
              "roundResetPreset", "roundResetTimezone", "roundResetIntervalDays")
           VALUES ($1, $2, $3, $4, true, 0, 0, false, $5, 'daily', 'UTC', NULL)"#,
    )
    .bind(group_id)
    .bind(format!("test-group-{group_id}"))
    .bind(format!("test_grp_reset_creator_{group_id}"))
    .bind(format!("hash-{group_id}"))
    .bind(last_reset_at_ms)
    .execute(pool)
    .await
    .expect("seed group");
}

async fn seed_group_custom(
    pool: &PgPool,
    group_id: Uuid,
    last_reset_at_ms: Option<i64>,
    interval_days: i32,
) {
    sqlx::query(
        r#"INSERT INTO pplns_group
             (id, name, "creatorAddress", "adminTokenHash", active,
              "createdAt", "updatedAt", "isPublic", "lastRoundResetAt",
              "roundResetPreset", "roundResetTimezone", "roundResetIntervalDays")
           VALUES ($1, $2, $3, $4, true, 0, 0, false, $5, 'custom', 'UTC', $6)"#,
    )
    .bind(group_id)
    .bind(format!("test-group-{group_id}"))
    .bind(format!("test_grp_reset_creator_{group_id}"))
    .bind(format!("hash-{group_id}"))
    .bind(last_reset_at_ms)
    .bind(interval_days)
    .execute(pool)
    .await
    .expect("seed group");
}

async fn seed_balance(pool: &PgPool, group_id: Uuid, address: &str, pending: i64) {
    sqlx::query(
        r#"INSERT INTO pplns_group_balance (address, "groupId", "pendingSats", "totalPaidSats", "updatedAt")
           VALUES ($1, $2, $3, 0, 0)"#,
    )
    .bind(address)
    .bind(group_id)
    .bind(pending)
    .execute(pool)
    .await
    .expect("seed balance");
}

async fn cleanup_group(pool: &PgPool, group_id: Uuid) {
    let _ = sqlx::query(r#"DELETE FROM pplns_group_block_history WHERE "groupId" = $1"#)
        .bind(group_id)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM pplns_group_balance WHERE "groupId" = $1"#)
        .bind(group_id)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM pplns_group WHERE id = $1"#)
        .bind(group_id)
        .execute(pool)
        .await;
}

fn clock_at_ms(ms: i64) -> Arc<TestClock> {
    Arc::new(TestClock::new(
        chrono::Utc
            .timestamp_millis_opt(ms)
            .single()
            .expect("valid timestamp"),
    ))
}

use chrono::TimeZone;

// ── Test 1 — reset fires + wipes everything ────────────────────────

#[tokio::test]
async fn reset_scheduled_wipes_redis_pg_state_and_stamps() {
    let (pool, conn) = match connect_or_skip(0).await {
        Some(x) => x,
        None => return,
    };
    let group_id = Uuid::new_v4();
    seed_group(&pool, group_id, None).await;
    seed_balance(&pool, group_id, "test_reset_a", 5_000).await;

    let round = GroupRoundStore::new(conn);
    let group_key = group_id.to_string();
    // Pre-state: shares + snapshot.
    round
        .record_share(None, &group_key, "test_reset_a", 100.0, 1)
        .await
        .unwrap();
    let mut snap_conn = round.connection_for_snapshot();
    snapshot::write_snapshot(
        &mut snap_conn,
        &group_key,
        "test_reset_finder",
        &snapshot::StoredSnapshot {
            distribution: vec![],
            block_reward_sats: 100,
            considered_addresses: vec![],
            balance_after: vec![],
        },
        60,
    )
    .await
    .unwrap();

    let clock = clock_at_ms(1_700_000_000_000);
    let runner = GroupResetRunner::new(pool.clone(), round.clone(), clock);
    let fired = runner.reset_scheduled(group_id).await.expect("ok");
    assert!(fired);

    // Redis state wiped.
    assert!(round.read_by_address(&group_key).await.unwrap().is_empty());
    let mut snap_conn = round.connection_for_snapshot();
    assert!(
        snapshot::read_snapshot(&mut snap_conn, &group_key, "test_reset_finder")
            .await
            .unwrap()
            .is_none()
    );

    // PG balance wiped.
    let bal_count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_group_balance WHERE "groupId" = $1"#)
            .bind(group_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bal_count.0, 0);

    // lastRoundResetAt stamped to clock's now_ms.
    let last: (Option<i64>,) =
        sqlx::query_as(r#"SELECT "lastRoundResetAt" FROM pplns_group WHERE id = $1"#)
            .bind(group_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(last.0, Some(1_700_000_000_000));

    cleanup_group(&pool, group_id).await;
}

// ── Test 2 — debounce skips reset within 60s ───────────────────────

#[tokio::test]
async fn reset_debounce_skips_within_60_seconds() {
    let (pool, conn) = match connect_or_skip(1).await {
        Some(x) => x,
        None => return,
    };
    let group_id = Uuid::new_v4();
    // Last reset 30s ago.
    seed_group(&pool, group_id, Some(1_700_000_000_000 - 30_000)).await;

    let round = GroupRoundStore::new(conn);
    let clock = clock_at_ms(1_700_000_000_000);
    let runner = GroupResetRunner::new(pool.clone(), round, clock);
    let fired = runner.reset_scheduled(group_id).await.expect("ok");
    assert!(!fired, "debounce skipped the reset");

    // lastRoundResetAt unchanged.
    let last: (Option<i64>,) =
        sqlx::query_as(r#"SELECT "lastRoundResetAt" FROM pplns_group WHERE id = $1"#)
            .bind(group_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(last.0, Some(1_700_000_000_000 - 30_000));

    cleanup_group(&pool, group_id).await;
}

// ── Test 3 — debounce window boundary fires past 60s ──────────────

#[tokio::test]
async fn reset_fires_past_debounce_window() {
    let (pool, conn) = match connect_or_skip(2).await {
        Some(x) => x,
        None => return,
    };
    let group_id = Uuid::new_v4();
    // Last reset 61s ago — past the debounce window.
    seed_group(&pool, group_id, Some(1_700_000_000_000 - 61_000)).await;

    let round = GroupRoundStore::new(conn);
    let clock = clock_at_ms(1_700_000_000_000);
    let runner = GroupResetRunner::new(pool.clone(), round, clock);
    let fired = runner.reset_scheduled(group_id).await.expect("ok");
    assert!(
        fired,
        "elapsed > debounce window ({RESET_DEBOUNCE_MS}ms) — must fire"
    );

    cleanup_group(&pool, group_id).await;
}

// ── Test 4 — custom-elapsed gate prevents premature reset ──────────

#[tokio::test]
async fn reset_custom_preset_skips_if_interval_not_elapsed() {
    let (pool, conn) = match connect_or_skip(3).await {
        Some(x) => x,
        None => return,
    };
    let group_id = Uuid::new_v4();
    // Custom preset, 7d interval, last reset 2 days ago.
    let two_days_ago = 1_700_000_000_000 - 2 * 86_400_000;
    seed_group_custom(&pool, group_id, Some(two_days_ago), 7).await;

    let round = GroupRoundStore::new(conn);
    let clock = clock_at_ms(1_700_000_000_000);
    let runner = GroupResetRunner::new(pool.clone(), round, clock);
    let fired = runner.reset_scheduled(group_id).await.expect("ok");
    assert!(
        !fired,
        "custom-preset 7d interval skips when only 2d elapsed"
    );

    cleanup_group(&pool, group_id).await;
}

// ── Test 5 — custom-elapsed gate fires when threshold crossed ──────

#[tokio::test]
async fn reset_custom_preset_fires_when_interval_elapsed() {
    let (pool, conn) = match connect_or_skip(4).await {
        Some(x) => x,
        None => return,
    };
    let group_id = Uuid::new_v4();
    // 8 days ago — past the 7-day interval (with 12h DST tolerance).
    let eight_days_ago = 1_700_000_000_000 - 8 * 86_400_000;
    seed_group_custom(&pool, group_id, Some(eight_days_ago), 7).await;

    let round = GroupRoundStore::new(conn);
    let clock = clock_at_ms(1_700_000_000_000);
    let runner = GroupResetRunner::new(pool.clone(), round, clock);
    let fired = runner.reset_scheduled(group_id).await.expect("ok");
    assert!(fired);

    cleanup_group(&pool, group_id).await;
}

// ── Test 6 — nonexistent group returns GroupNotFound ───────────────

#[tokio::test]
async fn reset_nonexistent_group_returns_error() {
    let (pool, conn) = match connect_or_skip(5).await {
        Some(x) => x,
        None => return,
    };
    let round = GroupRoundStore::new(conn);
    let clock = clock_at_ms(1_700_000_000_000);
    let runner = GroupResetRunner::new(pool, round, clock);
    let missing = Uuid::new_v4();
    let err = runner.reset_scheduled(missing).await.unwrap_err();
    assert!(matches!(
        err,
        ResetError::GroupNotFound { group_id } if group_id == missing
    ));
}

// ── Test 7 — multiple groups isolated ──────────────────────────────

#[tokio::test]
async fn reset_one_group_does_not_affect_another() {
    let (pool, conn) = match connect_or_skip(6).await {
        Some(x) => x,
        None => return,
    };
    let group_a = Uuid::new_v4();
    let group_b = Uuid::new_v4();
    seed_group(&pool, group_a, None).await;
    seed_group(&pool, group_b, None).await;
    seed_balance(&pool, group_a, "test_iso_a", 1_000).await;
    seed_balance(&pool, group_b, "test_iso_b", 2_000).await;

    let round = GroupRoundStore::new(conn);
    round
        .record_share(None, &group_a.to_string(), "test_iso_a", 50.0, 1)
        .await
        .unwrap();
    round
        .record_share(None, &group_b.to_string(), "test_iso_b", 50.0, 2)
        .await
        .unwrap();

    let clock = clock_at_ms(1_700_000_000_000);
    let runner = GroupResetRunner::new(pool.clone(), round.clone(), clock);
    runner.reset_scheduled(group_a).await.expect("ok");

    // Group A: wiped.
    assert!(round
        .read_by_address(&group_a.to_string())
        .await
        .unwrap()
        .is_empty());
    let bal_a: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_group_balance WHERE "groupId" = $1"#)
            .bind(group_a)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bal_a.0, 0);

    // Group B: untouched.
    assert_eq!(
        round
            .read_by_address(&group_b.to_string())
            .await
            .unwrap()
            .len(),
        1
    );
    let bal_b: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_group_balance WHERE "groupId" = $1"#)
            .bind(group_b)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bal_b.0, 1);

    cleanup_group(&pool, group_a).await;
    cleanup_group(&pool, group_b).await;
}
