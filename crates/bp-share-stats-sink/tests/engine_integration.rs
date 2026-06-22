// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! End-to-end orchestration test: spawn `ShareStatsEngine` with a tight
//! flush interval, push data via the shared `Accumulators` handle (the
//! same handle the SV1 hooks would mutate), wait for the cron task to
//! tick, verify PG, then shutdown and confirm final-drain.
//!
//! This is the "Stratum→Stats-flow" test the migration plan calls for
//! (user-confirmed scope 2026-05-16): it drives the full lifecycle
//! (spawn → tick → flush → shutdown → final drain) end-to-end through
//! the public engine API. The actual SV1 hook impls (which translate
//! `record_accepted` / `record_rejected` into accumulator deltas) are
//! covered separately by `hooks_unit.rs` and `flush_integration.rs`.

use std::time::Duration;

use bp_common::AddressId;
use bp_share_stats_sink::config::StatsSinkConfig;
use bp_share_stats_sink::engine::ShareStatsEngine;
use bp_stats::{ClientStatisticsKey, ClientStatisticsRecord, RejectedReason, TimeSlot, WorkerKey};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::Mutex;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

static ENGINE_TEST_LOCK: Mutex<()> = Mutex::const_new(());

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

fn addr(s: &str) -> AddressId {
    AddressId::new(s.to_string()).unwrap()
}

async fn cleanup(pool: &PgPool, slot_time_ms: i64, prefix: &str) {
    for sql in [
        r#"DELETE FROM pool_share_statistics_entity WHERE "time" = $1"#,
        r#"DELETE FROM pool_mode_hashrate WHERE "time" = $1"#,
        r#"DELETE FROM pool_rejected_statistics_entity WHERE "time" = $1"#,
    ] {
        let _ = sqlx::query(sql).bind(slot_time_ms).execute(pool).await;
    }
    for sql in [
        r#"DELETE FROM client_statistics_entity WHERE address LIKE $1"#,
        r#"DELETE FROM client_rejected_statistics_entity WHERE address LIKE $1"#,
        r#"DELETE FROM worker_shares_entity WHERE address LIKE $1"#,
        r#"DELETE FROM address_settings_entity WHERE address LIKE $1"#,
    ] {
        let _ = sqlx::query(sql)
            .bind(format!("{prefix}%"))
            .execute(pool)
            .await;
    }
}

#[tokio::test]
async fn engine_spawn_tick_flushes_to_pg_then_shutdown_drains() {
    let _guard = ENGINE_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let slot = TimeSlot::from_millis(32_503_680_010_001);
    let prefix = "test_engine_e2e_";
    cleanup(&pool, slot.as_millis(), prefix).await;

    // Spawn engine with tight interval. `seed_on_spawn=false` because
    // the seed migration touches the whole table and would conflict
    // with parallel tests — covered separately by seed_integration.
    let cfg = StatsSinkConfig {
        flush_interval: Duration::from_millis(80),
        client_stats_batch_size: 1000,
        slot_aligned_flush: false,
        seed_on_spawn: false,
        startup_offset: Duration::ZERO,
    };
    let handle = ShareStatsEngine::spawn(cfg, pool.clone())
        .await
        .expect("spawn engine");

    // Push data via the shared accumulators handle — same path SV1 hooks
    // would take when a real Stratum server is wired up.
    let accs = handle.accumulators();
    accs.pool_shares.add_accepted(slot, 50.0);
    accs.pool_rejected
        .add(slot, RejectedReason::DuplicateShare, 1.0);
    accs.client_statistics.add(
        ClientStatisticsKey {
            address: addr(&format!("{prefix}miner")),
            client_name: "wkr".to_string(),
            session_id: "sessE2E".to_string(),
            slot,
        },
        &ClientStatisticsRecord {
            shares: 50.0,
            accepted_count: 1.0,
            ..Default::default()
        },
    );
    accs.share_totals.add_worker(
        WorkerKey {
            address: addr(&format!("{prefix}miner")),
            client_name: "wkr".to_string(),
        },
        50.0,
    );

    // Wait for at least 2 ticks to give the loop time to flush.
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Verify PG has the accepted-share row.
    let accepted: f32 = sqlx::query_scalar(
        r#"SELECT accepted FROM pool_share_statistics_entity WHERE "time" = $1"#,
    )
    .bind(slot.as_millis())
    .fetch_one(&pool)
    .await
    .expect("read pool_share row");
    assert!(
        (accepted - 50.0).abs() < 0.01,
        "engine tick should have flushed: {accepted}"
    );

    // Drop more data, then signal shutdown — final-drain should commit it.
    accs.pool_shares.add_accepted(slot, 10.0);
    handle.shutdown().await;

    let accepted_after: f32 = sqlx::query_scalar(
        r#"SELECT accepted FROM pool_share_statistics_entity WHERE "time" = $1"#,
    )
    .bind(slot.as_millis())
    .fetch_one(&pool)
    .await
    .expect("read post-shutdown");
    assert!(
        (accepted_after - 60.0).abs() < 0.01,
        "shutdown drain must have flushed the residual 10.0: got {accepted_after}"
    );

    cleanup(&pool, slot.as_millis(), prefix).await;
}

#[tokio::test]
async fn engine_reader_exposes_pending_residuals_before_flush() {
    let _guard = ENGINE_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };

    let cfg = StatsSinkConfig {
        flush_interval: Duration::from_secs(3600), // never tick in this test
        client_stats_batch_size: 1000,
        slot_aligned_flush: false,
        seed_on_spawn: false,
        startup_offset: Duration::ZERO,
    };
    // Construct without spawning so we can mutate accumulators before
    // verifying the reader's view.
    let engine = ShareStatsEngine::new(cfg, pool).expect("new engine");
    let reader = engine.reader();
    let accs = engine.accumulators();

    assert_eq!(reader.pending_pool_shares(), 0);
    accs.pool_shares
        .add_accepted(TimeSlot::from_millis(32_503_680_011_001), 25.0);
    assert_eq!(reader.pending_pool_shares(), 1);
    // Cheap clone semantics: clones see the same backing state.
    let reader_clone = reader.clone();
    assert_eq!(reader_clone.pending_pool_shares(), 1);
}

#[tokio::test]
async fn engine_handle_shutdown_is_idempotent_against_dropped_handle() {
    // Smoke test: dropping the handle without explicit shutdown does not
    // panic. The background task aborts cleanly once its JoinHandle goes
    // out of scope; this verifies that drop-without-shutdown is safe in
    // call sites that don't go through the explicit drain.
    let _guard = ENGINE_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    {
        let _handle = ShareStatsEngine::spawn(
            StatsSinkConfig {
                flush_interval: Duration::from_millis(100),
                client_stats_batch_size: 1000,
                slot_aligned_flush: false,
                seed_on_spawn: false,
                startup_offset: Duration::ZERO,
            },
            pool,
        )
        .await
        .expect("spawn");
        // Drop scope exits here — handle.shutdown_tx and handle.join
        // are still set, but Drop is a no-op on this type. The
        // background task continues until something else cancels it.
    }
    // Give the dropped task a moment to be reclaimed; if it had
    // panicked tokio would log it. We just want this to not crash.
    tokio::time::sleep(Duration::from_millis(50)).await;
}

#[tokio::test]
async fn engine_with_invalid_config_fails_validation() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let bad = StatsSinkConfig {
        flush_interval: Duration::ZERO,
        ..Default::default()
    };
    let result = ShareStatsEngine::spawn(bad, pool).await;
    assert!(result.is_err(), "zero flush interval must reject");
}
