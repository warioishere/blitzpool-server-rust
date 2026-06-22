// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `bp-group-solo-engine::sweep` against
//! docker-PG. Suite-wide mutex serializes tests because sweep
//! operates over the whole `pplns_group_balance` table.

use std::sync::Arc;

use bp_common::Sats;
use bp_cron_utils::TestClock;
use bp_group_solo_engine::sweep::{GroupDustSweepRunner, ROW_TYPE_SWEEP};
use chrono::{TimeZone, Utc};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::Mutex;
use uuid::Uuid;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

static SWEEP_TEST_LOCK: Mutex<()> = Mutex::const_new(());

async fn connect_or_skip() -> Option<PgPool> {
    let url = std::env::var("BP_PG_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&url),
    )
    .await
    {
        Ok(Ok(p)) => Some(p),
        Ok(Err(e)) => {
            eprintln!("PG connect failed for {url}: {e} — skipping");
            return None;
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            return None;
        }
    }
}

async fn seed_group(pool: &PgPool, group_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO pplns_group
             (id, name, "creatorAddress", "adminTokenHash", active,
              "createdAt", "updatedAt", "isPublic")
           VALUES ($1, $2, $3, $4, true, 0, 0, false)"#,
    )
    .bind(group_id)
    .bind(format!("test-group-{group_id}"))
    .bind(format!("test_grp_sweep_creator_{group_id}"))
    .bind(format!("hash-{group_id}"))
    .execute(pool)
    .await
    .expect("seed group");
}

async fn seed_balance(
    pool: &PgPool,
    group_id: Uuid,
    address: &str,
    pending_sats: i64,
    last_accepted_share_at_ms: Option<i64>,
) {
    sqlx::query(
        r#"INSERT INTO pplns_group_balance
             (address, "groupId", "pendingSats", "totalPaidSats",
              "updatedAt", "lastAcceptedShareAt")
           VALUES ($1, $2, $3, 0, 0, $4)"#,
    )
    .bind(address)
    .bind(group_id)
    .bind(pending_sats)
    .bind(last_accepted_share_at_ms)
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

fn clock_at(year: i32, month: u32, day: u32) -> Arc<TestClock> {
    Arc::new(TestClock::new(
        Utc.with_ymd_and_hms(year, month, day, 12, 0, 0).unwrap(),
    ))
}

/// Wipe any leftover `test-group-{uuid}` rows from a previously-aborted
/// run. Scoped wide because group_id is per-test UUID; this catches
/// orphans from crashes.
async fn wipe_leftover_test_state(pool: &PgPool) {
    let _ = sqlx::query(
        r#"DELETE FROM pplns_group_block_history
           WHERE "groupId" IN (SELECT id FROM pplns_group WHERE name LIKE 'test-group-%')"#,
    )
    .execute(pool)
    .await;
    let _ = sqlx::query(
        r#"DELETE FROM pplns_group_balance
           WHERE "groupId" IN (SELECT id FROM pplns_group WHERE name LIKE 'test-group-%')"#,
    )
    .execute(pool)
    .await;
    let _ = sqlx::query(r#"DELETE FROM pplns_group WHERE name LIKE 'test-group-%'"#)
        .execute(pool)
        .await;
}

// ── Test 1 — single dormant dust row gets absorbed ─────────────────

#[tokio::test]
async fn sweep_absorbs_single_dormant_dust_row() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_leftover_test_state(&pool).await;

    let group_id = Uuid::new_v4();
    seed_group(&pool, group_id).await;
    let stale = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();
    seed_balance(&pool, group_id, "test_grpsw_dust", 500, Some(stale)).await;

    let clock = clock_at(2026, 5, 16);
    let runner = GroupDustSweepRunner::new(pool.clone(), clock, Sats(5_000), 30);
    let stats = runner.sweep().await.expect("ok");
    assert_eq!(stats.rows_absorbed, 1);
    assert_eq!(stats.sats_absorbed, 500);

    // Balance row deleted.
    let bal_count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_group_balance WHERE "groupId" = $1"#)
            .bind(group_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bal_count.0, 0);

    // Audit row written with rowType='dust-sweep' and negative blockHeight.
    let audit: (i32, i64, String) = sqlx::query_as(
        r#"SELECT "blockHeight", "paidSats", "rowType"
           FROM pplns_group_block_history WHERE "groupId" = $1"#,
    )
    .bind(group_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(audit.0 < 0, "blockHeight is synthetic-negative");
    assert_eq!(audit.1, 500);
    assert_eq!(audit.2, ROW_TYPE_SWEEP);

    cleanup_group(&pool, group_id).await;
}

// ── Test 2 — multiple dormant rows in same group absorbed ──────────

#[tokio::test]
async fn sweep_absorbs_multiple_dormant_rows() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_leftover_test_state(&pool).await;

    let group_id = Uuid::new_v4();
    seed_group(&pool, group_id).await;
    let stale = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();
    seed_balance(&pool, group_id, "test_grpsw_a", 100, Some(stale)).await;
    seed_balance(&pool, group_id, "test_grpsw_b", 200, Some(stale)).await;
    seed_balance(&pool, group_id, "test_grpsw_c", 300, Some(stale)).await;

    let clock = clock_at(2026, 5, 16);
    let runner = GroupDustSweepRunner::new(pool.clone(), clock, Sats(5_000), 30);
    let stats = runner.sweep().await.expect("ok");
    assert_eq!(stats.rows_absorbed, 3);
    assert_eq!(stats.sats_absorbed, 600);

    // All balance rows deleted, all audit rows have unique blockHeights.
    let bal_count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_group_balance WHERE "groupId" = $1"#)
            .bind(group_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bal_count.0, 0);

    let distinct_heights: (i64,) = sqlx::query_as(
        r#"SELECT count(DISTINCT "blockHeight") FROM pplns_group_block_history
           WHERE "groupId" = $1"#,
    )
    .bind(group_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(distinct_heights.0, 3);

    cleanup_group(&pool, group_id).await;
}

// ── Test 3 — active rows (within cutoff) skipped ──────────────────

#[tokio::test]
async fn sweep_skips_active_rows_within_cutoff() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_leftover_test_state(&pool).await;

    let group_id = Uuid::new_v4();
    seed_group(&pool, group_id).await;
    let stale = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();
    let fresh = Utc
        .with_ymd_and_hms(2026, 5, 14, 0, 0, 0)
        .unwrap()
        .timestamp_millis();

    seed_balance(&pool, group_id, "test_grpsw_dormant", 500, Some(stale)).await;
    seed_balance(&pool, group_id, "test_grpsw_active", 500, Some(fresh)).await;

    let clock = clock_at(2026, 5, 16);
    let runner = GroupDustSweepRunner::new(pool.clone(), clock, Sats(5_000), 30);
    let stats = runner.sweep().await.expect("ok");
    assert_eq!(stats.rows_absorbed, 1, "only the dormant row swept");

    let remaining: Vec<(String,)> =
        sqlx::query_as(r#"SELECT address FROM pplns_group_balance WHERE "groupId" = $1"#)
            .bind(group_id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].0, "test_grpsw_active");

    cleanup_group(&pool, group_id).await;
}

// ── Test 4 — NULL lastAcceptedShareAt skipped ─────────────────────

#[tokio::test]
async fn sweep_skips_null_last_accepted_share_at() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_leftover_test_state(&pool).await;

    let group_id = Uuid::new_v4();
    seed_group(&pool, group_id).await;
    seed_balance(&pool, group_id, "test_grpsw_null", 500, None).await;

    let clock = clock_at(2026, 5, 16);
    let runner = GroupDustSweepRunner::new(pool.clone(), clock, Sats(5_000), 30);
    let stats = runner.sweep().await.expect("ok");
    assert_eq!(stats.rows_absorbed, 0);

    let bal_count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_group_balance WHERE "groupId" = $1"#)
            .bind(group_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bal_count.0, 1, "NULL-timestamp row survives sweep");

    cleanup_group(&pool, group_id).await;
}

// ── Test 5 — above-min-payout rows skipped (not dust) ──────────────

#[tokio::test]
async fn sweep_skips_above_min_payout_rows() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_leftover_test_state(&pool).await;

    let group_id = Uuid::new_v4();
    seed_group(&pool, group_id).await;
    let stale = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();
    seed_balance(&pool, group_id, "test_grpsw_dust", 500, Some(stale)).await;
    seed_balance(&pool, group_id, "test_grpsw_above", 10_000, Some(stale)).await;

    let clock = clock_at(2026, 5, 16);
    let runner = GroupDustSweepRunner::new(pool.clone(), clock, Sats(5_000), 30);
    let stats = runner.sweep().await.expect("ok");
    assert_eq!(stats.rows_absorbed, 1, "above-min-payout row not swept");

    let remaining: Vec<(String,)> =
        sqlx::query_as(r#"SELECT address FROM pplns_group_balance WHERE "groupId" = $1"#)
            .bind(group_id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].0, "test_grpsw_above");

    cleanup_group(&pool, group_id).await;
}

// ── Test 6 — empty candidates returns zero stats ───────────────────

#[tokio::test]
async fn sweep_empty_returns_zero_stats() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_leftover_test_state(&pool).await;

    let group_id = Uuid::new_v4();
    seed_group(&pool, group_id).await;
    let clock = clock_at(2026, 5, 16);
    let runner = GroupDustSweepRunner::new(pool.clone(), clock, Sats(5_000), 30);
    let stats = runner.sweep().await.expect("ok");
    assert_eq!(stats.rows_absorbed, 0);

    cleanup_group(&pool, group_id).await;
}

// ── Test 7 — replay safe (no double-processing) ────────────────────

#[tokio::test]
async fn sweep_replay_safe_after_absorption() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_leftover_test_state(&pool).await;

    let group_id = Uuid::new_v4();
    seed_group(&pool, group_id).await;
    let stale = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();
    seed_balance(&pool, group_id, "test_grpsw_x", 1_000, Some(stale)).await;

    let clock = clock_at(2026, 5, 16);
    let runner = GroupDustSweepRunner::new(pool.clone(), clock, Sats(5_000), 30);
    let first = runner.sweep().await.expect("ok");
    assert_eq!(first.rows_absorbed, 1);

    // Second run: no candidates left.
    let second = runner.sweep().await.expect("ok");
    assert_eq!(second.rows_absorbed, 0);

    // First sweep's audit row still present.
    let audit_count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_group_block_history WHERE "groupId" = $1"#)
            .bind(group_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(audit_count.0, 1);

    cleanup_group(&pool, group_id).await;
}
