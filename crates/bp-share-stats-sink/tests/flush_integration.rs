// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `flush_once` against docker-PG. Drives the
//! whole drain → bulk-upsert → confirm pipeline for one tick at a time.
//!
//! Each test wraps the multi-table assertions in a suite-wide mutex
//! plus prefix-based cleanup — `flush_once` takes a `PgPool` (not a
//! transaction), so TX-rollback isolation doesn't fit.

use std::sync::Arc;

use bp_common::{AddressId, MiningMode};
use bp_share_stats_sink::flush::{flush_once, Accumulators, Flusher};
use bp_stats::{
    ClientRejectedKey, ClientStatisticsKey, ClientStatisticsRecord, FlushHealth,
    FlushHealthMonitor, RejectedReason, TimeSlot,
};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tokio::sync::Mutex;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

static FLUSH_TEST_LOCK: Mutex<()> = Mutex::const_new(());

async fn connect_or_skip() -> Option<PgPool> {
    let url = std::env::var("BP_PG_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&url),
    )
    .await
    {
        Ok(Ok(p)) => Some(p),
        Ok(Err(e)) => {
            eprintln!("PG connect failed for {url}: {e} — skipping integration test");
            return None;
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            return None;
        }
    }
}

fn fixture_slot() -> TimeSlot {
    // Year 3000-ish — far past any real fixture data.
    TimeSlot::from_millis(32_503_680_000_000 + 1)
}

async fn cleanup(pool: &PgPool, slot_time_ms: i64, addr_prefix: &str) {
    let _ = sqlx::query(r#"DELETE FROM pool_share_statistics_entity WHERE "time" = $1"#)
        .bind(slot_time_ms)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM pool_mode_hashrate WHERE "time" = $1"#)
        .bind(slot_time_ms)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM pool_rejected_statistics_entity WHERE "time" = $1"#)
        .bind(slot_time_ms)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM client_statistics_entity WHERE address LIKE $1"#)
        .bind(format!("{addr_prefix}%"))
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM client_rejected_statistics_entity WHERE address LIKE $1"#)
        .bind(format!("{addr_prefix}%"))
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM worker_shares_entity WHERE address LIKE $1"#)
        .bind(format!("{addr_prefix}%"))
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM address_settings_entity WHERE address LIKE $1"#)
        .bind(format!("{addr_prefix}%"))
        .execute(pool)
        .await;
}

fn addr(s: &str) -> AddressId {
    AddressId::new(s.to_string()).unwrap()
}

#[tokio::test]
async fn flush_once_drains_all_seven_tables_to_pg() {
    let _guard = FLUSH_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let slot = fixture_slot();
    let prefix = "test_flush_e2e_";
    cleanup(&pool, slot.as_millis(), prefix).await;

    // Seed an address_settings row for the address — `address_settings`
    // bulk-update only touches existing rows (silent no-op for missing
    // ones), and we want to assert the increment landed.
    sqlx::query(
        r#"INSERT INTO address_settings_entity (address, shares, "bestDifficulty")
           VALUES ($1, $2, 0)"#,
    )
    .bind(format!("{prefix}alice"))
    .bind(100.0_f64)
    .execute(&pool)
    .await
    .expect("seed addr row");

    // Drive accumulators: pretend one accepted + one rejected share.
    let accs = Arc::new(Accumulators::default());
    accs.pool_shares.add_accepted(slot, 10.0);
    accs.pool_shares.add_rejected(slot, 1.0);
    accs.pool_mode_hashrate.add(slot, MiningMode::Pplns, 10.0);
    accs.pool_rejected
        .add(slot, RejectedReason::LowDifficulty, 1.0);
    accs.client_statistics.add(
        ClientStatisticsKey {
            address: addr(&format!("{prefix}alice")),
            client_name: "worker1".to_string(),
            session_id: "sess0001".to_string(),
            slot,
        },
        &ClientStatisticsRecord {
            shares: 10.0,
            accepted_count: 1.0,
            ..Default::default()
        },
    );
    accs.client_rejected.add(
        ClientRejectedKey {
            address: addr(&format!("{prefix}alice")),
            slot,
            reason: RejectedReason::LowDifficulty,
        },
        1.0,
        1.0,
    );
    accs.share_totals
        .add(addr(&format!("{prefix}alice")), "worker1".to_string(), 10.0);

    let health = Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default()));
    flush_once(&pool, &accs, &health, 1000).await;

    // Pool-shares row exists with the right values.
    let row = sqlx::query(
        r#"SELECT accepted, rejected FROM pool_share_statistics_entity WHERE "time" = $1"#,
    )
    .bind(slot.as_millis())
    .fetch_one(&pool)
    .await
    .expect("pool_share row");
    let accepted: f32 = row.get("accepted");
    let rejected: f32 = row.get("rejected");
    assert!((accepted - 10.0).abs() < 0.01);
    assert!((rejected - 1.0).abs() < 0.01);

    // Pool-mode hashrate.
    let diff: f32 = sqlx::query_scalar(
        r#"SELECT diff FROM pool_mode_hashrate WHERE "time" = $1 AND mode = $2"#,
    )
    .bind(slot.as_millis())
    .bind("pplns")
    .fetch_one(&pool)
    .await
    .expect("pool_mode_hashrate row");
    assert!((diff - 10.0).abs() < 0.01);

    // Pool-rejected.
    let count: f32 = sqlx::query_scalar(
        r#"SELECT count FROM pool_rejected_statistics_entity
           WHERE "time" = $1 AND reason = $2"#,
    )
    .bind(slot.as_millis())
    .bind("LowDifficultyShare")
    .fetch_one(&pool)
    .await
    .expect("pool_rejected row");
    assert!((count - 1.0).abs() < 0.01);

    // Client-statistics: 1 row for the accepted share.
    let cs: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM client_statistics_entity WHERE address = $1 AND "time" = $2"#,
    )
    .bind(format!("{prefix}alice"))
    .bind(slot.as_millis())
    .fetch_one(&pool)
    .await
    .expect("count cs rows");
    assert!(cs >= 1);

    // Client-rejected.
    let cr_count: f32 = sqlx::query_scalar(
        r#"SELECT count FROM client_rejected_statistics_entity
           WHERE address = $1 AND "time" = $2 AND reason = $3"#,
    )
    .bind(format!("{prefix}alice"))
    .bind(slot.as_millis())
    .bind("LowDifficultyShare")
    .fetch_one(&pool)
    .await
    .expect("client_rejected row");
    assert!((cr_count - 1.0).abs() < 0.01);

    // Address settings — incremented from 100.0 to 110.0.
    let addr_shares: f64 =
        sqlx::query_scalar(r#"SELECT shares FROM address_settings_entity WHERE address = $1"#)
            .bind(format!("{prefix}alice"))
            .fetch_one(&pool)
            .await
            .expect("address_settings row");
    assert!((addr_shares - 110.0).abs() < 0.01);

    // Worker shares — composite-PK insert (row didn't exist before).
    let worker_shares: f64 = sqlx::query_scalar(
        r#"SELECT shares FROM worker_shares_entity WHERE address = $1 AND "clientName" = $2"#,
    )
    .bind(format!("{prefix}alice"))
    .bind("worker1")
    .fetch_one(&pool)
    .await
    .expect("worker_shares row");
    assert!((worker_shares - 10.0).abs() < 0.01);

    // All flushers report Healthy (success) after one clean tick.
    {
        let h = health.lock().expect("health lock");
        for flusher in [
            Flusher::PoolShares,
            Flusher::PoolModeHashrate,
            Flusher::PoolRejected,
            Flusher::ClientStatistics,
            Flusher::ClientRejected,
            Flusher::AddressSettings,
            Flusher::WorkerTotals,
        ] {
            assert_eq!(h.consecutive_failures(&flusher), 0, "flusher: {flusher:?}");
        }
    }

    cleanup(&pool, slot.as_millis(), prefix).await;
}

/// The best-difficulty accumulator folds the window max into
/// `address_settings_entity."bestDifficulty"` via GREATEST at flush time —
/// end-to-end (accumulator → `flush_once` → PG), no per-share write, no
/// pre-existing row required.
#[tokio::test]
async fn flush_once_folds_best_difficulty_via_greatest() {
    let _guard = FLUSH_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_flush_bd_";
    let address = format!("{prefix}octaxe");
    let _ = sqlx::query(r#"DELETE FROM address_settings_entity WHERE address LIKE $1"#)
        .bind(format!("{prefix}%"))
        .execute(&pool)
        .await;

    let health = Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default()));

    // No row yet: the flush inserts it at the window max.
    let accs = Arc::new(Accumulators::default());
    accs.best_difficulty.add(&addr(&address), 100.0, Some("bitaxe"));
    accs.best_difficulty.add(&addr(&address), 623_932_928.0, Some("octaxe")); // window max
    accs.best_difficulty.add(&addr(&address), 40.0, Some("worker")); // lower — ignored
    flush_once(&pool, &accs, &health, 1000).await;

    let (best, ua): (f64, Option<String>) = {
        let row = sqlx::query(
            r#"SELECT "bestDifficulty", "bestDifficultyUserAgent"
               FROM address_settings_entity WHERE address = $1"#,
        )
        .bind(&address)
        .fetch_one(&pool)
        .await
        .expect("row inserted by flush");
        (row.get("bestDifficulty"), row.get("bestDifficultyUserAgent"))
    };
    assert_eq!(best, 623_932_928.0, "flush persisted the window max");
    assert_eq!(ua.as_deref(), Some("octaxe"));

    // A later window with a LOWER max leaves the stored all-time best alone.
    let accs2 = Arc::new(Accumulators::default());
    accs2.best_difficulty.add(&addr(&address), 1_000.0, Some("bitaxe"));
    flush_once(&pool, &accs2, &health, 1000).await;
    let best_after: f64 =
        sqlx::query_scalar(r#"SELECT "bestDifficulty" FROM address_settings_entity WHERE address = $1"#)
            .bind(&address)
            .fetch_one(&pool)
            .await
            .expect("read");
    assert_eq!(best_after, 623_932_928.0, "GREATEST keeps the all-time high");

    let _ = sqlx::query(r#"DELETE FROM address_settings_entity WHERE address LIKE $1"#)
        .bind(format!("{prefix}%"))
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn empty_accumulators_no_op_all_flushers() {
    let _guard = FLUSH_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let accs = Arc::new(Accumulators::default());
    let health = Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default()));
    flush_once(&pool, &accs, &health, 1000).await;

    // Nothing crashed; nothing in PG, all healthy.
    let h = health.lock().expect("health lock");
    assert_eq!(h.consecutive_failures(&Flusher::PoolShares), 0);
    assert_eq!(h.consecutive_failures(&Flusher::WorkerTotals), 0);
}

#[tokio::test]
async fn replay_idempotency_double_flush_doubles_counts() {
    let _guard = FLUSH_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let slot = TimeSlot::from_millis(32_503_680_001_234);
    let prefix = "test_flush_replay_";
    cleanup(&pool, slot.as_millis(), prefix).await;

    // Two consecutive flushes of the same accepted-share batch ⇒
    // counts should be 2× (INCREMENT semantics). Models the situation
    // where the coordinator restarted after PG succeeded but the
    // accumulator never confirmed, and a new tick re-includes the
    // same snapshot.
    let accs1 = Arc::new(Accumulators::default());
    accs1.pool_shares.add_accepted(slot, 5.0);
    let health1 = Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default()));
    flush_once(&pool, &accs1, &health1, 1000).await;

    let accs2 = Arc::new(Accumulators::default());
    accs2.pool_shares.add_accepted(slot, 5.0);
    let health2 = Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default()));
    flush_once(&pool, &accs2, &health2, 1000).await;

    let accepted: f32 = sqlx::query_scalar(
        r#"SELECT accepted FROM pool_share_statistics_entity WHERE "time" = $1"#,
    )
    .bind(slot.as_millis())
    .fetch_one(&pool)
    .await
    .expect("read");
    assert!(
        (accepted - 10.0).abs() < 0.01,
        "expected 10 from 2×5: {accepted}"
    );

    cleanup(&pool, slot.as_millis(), prefix).await;
}

#[tokio::test]
async fn health_monitor_tracks_success_after_single_clean_flush() {
    // Sanity that the FlushHealth surface is wired — single-flush, no
    // failures, no degraded state.
    let _guard = FLUSH_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let slot = TimeSlot::from_millis(32_503_680_002_345);
    let prefix = "test_flush_health_";
    cleanup(&pool, slot.as_millis(), prefix).await;

    let accs = Arc::new(Accumulators::default());
    accs.pool_shares.add_accepted(slot, 1.0);
    let health = Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default()));
    flush_once(&pool, &accs, &health, 1000).await;

    {
        let mut h = health.lock().expect("health");
        let outcome = h.record_failure(Flusher::PoolShares);
        assert!(matches!(outcome, FlushHealth::Healthy { .. }));
    }

    cleanup(&pool, slot.as_millis(), prefix).await;
}
