// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Spec-vector ports of statistics-coordinator scenarios not already covered
//! by the generic `stats_writes_integration` / `flush_integration` /
//! `engine_integration` suites:
//!
//! - Scenario: 1500 client-statistics rows split correctly across batches
//!   (`batch_size = 1000`).
//! - Scenario: special-character escaping in `clientName` (commas, quotes,
//!   braces, backslashes) roundtrips cleanly through the UNNEST array codec.
//! - Scenario: per-worker rejected-diff fan-out from `client_statistics`
//!   lands in `worker_shares_entity.rejectedShares` correctly summed across
//!   sessions.
//! - Scenario: all-zero rejected diffs don't trigger a `worker_shares` write
//!   (no-op pass-through).

use std::sync::Arc;
use std::time::Duration;

use bp_common::AddressId;
use bp_share_stats_sink::config::StatsSinkConfig;
use bp_share_stats_sink::engine::ShareStatsEngine;
use bp_share_stats_sink::flush::{flush_once, Accumulators};
use bp_stats::{ClientStatisticsKey, ClientStatisticsRecord, FlushHealthMonitor, TimeSlot};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::Mutex;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

static SPEC_PORT_LOCK: Mutex<()> = Mutex::const_new(());

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

async fn cleanup(pool: &PgPool, prefix: &str) {
    for sql in [
        r#"DELETE FROM client_statistics_entity WHERE address LIKE $1"#,
        r#"DELETE FROM worker_shares_entity WHERE address LIKE $1"#,
    ] {
        let _ = sqlx::query(sql)
            .bind(format!("{prefix}%"))
            .execute(pool)
            .await;
    }
}

// ── 1500 rows split across batch_size=1000 ───────────────────────────

#[tokio::test]
async fn client_statistics_1500_rows_split_across_batches() {
    let _guard = SPEC_PORT_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_spec_batch_";
    cleanup(&pool, prefix).await;

    // Build 1500 client-statistics keys. Use 1500 distinct addresses to
    // skirt the UNIQUE constraint. The batch logic must produce a
    // 1000-row + 500-row pair under `batch_size=1000`.
    let slot = TimeSlot::from_millis(32_503_680_100_000);
    let accs = Arc::new(Accumulators::default());
    for i in 0..1500u32 {
        accs.client_statistics.add(
            ClientStatisticsKey {
                address: addr(&format!("{prefix}{i:04}")),
                client_name: "w".to_string(),
                session_id: "s".to_string(),
                slot,
            },
            &ClientStatisticsRecord {
                shares: 1.0,
                accepted_count: 1.0,
                ..Default::default()
            },
        );
    }

    let health = Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default()));
    flush_once(&pool, &accs, &health, 1000).await;

    let count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM client_statistics_entity WHERE address LIKE $1"#,
    )
    .bind(format!("{prefix}%"))
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(
        count, 1500,
        "all 1500 rows must land — 1000-row first batch + 500-row second"
    );

    cleanup(&pool, prefix).await;
}

// ── special chars in clientName ──────────────────────────────────────

#[tokio::test]
async fn client_name_with_special_chars_roundtrips_through_unnest() {
    let _guard = SPEC_PORT_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_spec_special_";
    cleanup(&pool, prefix).await;

    // Each of these clientName values stresses a different PG-text-array
    // escape rule. Empty/whitespace/large-quoted ones can throw off
    // hand-rolled arrays — sqlx's UNNEST binding handles all four cases.
    let stress_names = [
        r#"worker,with,commas"#,
        r#"worker"with"quotes"#,
        r#"worker{with}braces"#,
        r#"worker\with\backslashes"#,
    ];

    let slot = TimeSlot::from_millis(32_503_680_200_000);
    let accs = Arc::new(Accumulators::default());
    for (i, name) in stress_names.iter().enumerate() {
        accs.client_statistics.add(
            ClientStatisticsKey {
                address: addr(&format!("{prefix}{i}")),
                client_name: (*name).to_string(),
                session_id: "s".to_string(),
                slot,
            },
            &ClientStatisticsRecord {
                shares: 1.0,
                accepted_count: 1.0,
                ..Default::default()
            },
        );
        accs.share_totals.add_worker(
            bp_stats::WorkerKey {
                address: addr(&format!("{prefix}{i}")),
                client_name: (*name).to_string(),
            },
            1.0,
        );
    }

    let health = Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default()));
    flush_once(&pool, &accs, &health, 1000).await;

    // Each stress-named row landed both in client_statistics and in
    // worker_shares_entity with the same byte-identical clientName.
    for (i, name) in stress_names.iter().enumerate() {
        let cs: String = sqlx::query_scalar(
            r#"SELECT "clientName" FROM client_statistics_entity WHERE address = $1"#,
        )
        .bind(format!("{prefix}{i}"))
        .fetch_one(&pool)
        .await
        .expect("read cs");
        assert_eq!(&cs, name, "client_statistics roundtrip: {name:?}");

        let ws: String = sqlx::query_scalar(
            r#"SELECT "clientName" FROM worker_shares_entity WHERE address = $1"#,
        )
        .bind(format!("{prefix}{i}"))
        .fetch_one(&pool)
        .await
        .expect("read ws");
        assert_eq!(&ws, name, "worker_shares roundtrip: {name:?}");
    }

    cleanup(&pool, prefix).await;
}

// ── rejected fan-out per worker ──────────────────────────────────────

#[tokio::test]
async fn rejected_diff_fanout_per_worker_aggregates_across_sessions() {
    let _guard = SPEC_PORT_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_spec_fanout_";
    cleanup(&pool, prefix).await;

    // Same (address, clientName), 3 different sessions, with rejected
    // diffs split across the 3 reason buckets. The post-flush fan-out
    // must sum to (jnf + dup + low) across all 3 sessions and land in
    // worker_shares_entity.rejectedShares as one combined delta.
    let slot = TimeSlot::from_millis(32_503_680_300_000);
    let accs = Arc::new(Accumulators::default());
    let address = format!("{prefix}alice");
    let client_name = "wkr".to_string();

    let mk = |_session: &str, jnf: f64, dup: f64, low: f64| ClientStatisticsRecord {
        rejected_count: 1.0,
        rejected_job_not_found_diff1: jnf,
        rejected_duplicate_share_diff1: dup,
        rejected_low_difficulty_share_diff1: low,
        ..Default::default()
    };

    for (session, jnf, dup, low) in [
        ("sA", 10.0, 0.0, 0.0),
        ("sB", 0.0, 20.0, 0.0),
        ("sC", 0.0, 0.0, 30.0),
    ] {
        accs.client_statistics.add(
            ClientStatisticsKey {
                address: addr(&address),
                client_name: client_name.clone(),
                session_id: session.to_string(),
                slot,
            },
            &mk(session, jnf, dup, low),
        );
    }

    let health = Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default()));
    flush_once(&pool, &accs, &health, 1000).await;

    let rejected: f64 = sqlx::query_scalar(
        r#"SELECT "rejectedShares" FROM worker_shares_entity
           WHERE address = $1 AND "clientName" = $2"#,
    )
    .bind(&address)
    .bind(&client_name)
    .fetch_one(&pool)
    .await
    .expect("read");
    assert!(
        (rejected - 60.0).abs() < 0.01,
        "rejected fan-out = 10 + 20 + 30 = 60: got {rejected}"
    );

    cleanup(&pool, prefix).await;
}

// ── all-zero fan-out is a no-op for worker_shares ────────────────────

#[tokio::test]
async fn rejected_fanout_skips_zero_rejected_diffs() {
    // When every confirmed client-statistics row has zero rejected
    // diffs (i.e. all accepted shares), the worker_shares write fires
    // for the accepted-side totals but the `rejectedShares` field stays
    // at zero. No phantom row created if there are no accepted totals
    // either.
    let _guard = SPEC_PORT_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_spec_zero_fanout_";
    cleanup(&pool, prefix).await;

    let slot = TimeSlot::from_millis(32_503_680_400_000);
    let accs = Arc::new(Accumulators::default());
    accs.client_statistics.add(
        ClientStatisticsKey {
            address: addr(&format!("{prefix}alice")),
            client_name: "w".to_string(),
            session_id: "s".to_string(),
            slot,
        },
        &ClientStatisticsRecord {
            shares: 10.0,
            accepted_count: 1.0,
            ..Default::default()
        },
    );

    let health = Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default()));
    flush_once(&pool, &accs, &health, 1000).await;

    let row = sqlx::query_scalar::<_, Option<f64>>(
        r#"SELECT "rejectedShares" FROM worker_shares_entity
           WHERE address = $1 AND "clientName" = $2"#,
    )
    .bind(format!("{prefix}alice"))
    .bind("w")
    .fetch_optional(&pool)
    .await
    .expect("read");

    // No worker_totals row exists at all (accepted-side share_totals
    // accumulator was never `.add`ed, so flush_worker_totals had only
    // an empty fan-out + empty snapshot → no-op). This is the
    // "all-zeros → no call" assertion.
    assert!(
        row.is_none(),
        "no worker_shares row expected with empty share_totals + zero rejected fan-out"
    );

    cleanup(&pool, prefix).await;
}

// ── engine spawn with seed_on_spawn = false survives multiple ticks ──

#[tokio::test]
async fn engine_handles_repeated_empty_ticks_without_error() {
    // Coordinator-level robustness: with nothing in the accumulators,
    // multiple ticks back-to-back stay healthy. Models the very small
    // pool with long idle stretches.
    let _guard = SPEC_PORT_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };

    let handle = ShareStatsEngine::spawn(
        StatsSinkConfig {
            flush_interval: Duration::from_millis(50),
            client_stats_batch_size: 1000,
            slot_aligned_flush: false,
            seed_on_spawn: false,
            startup_offset: Duration::ZERO,
        },
        pool,
    )
    .await
    .expect("spawn");

    // Wait for ≥ 3 ticks.
    tokio::time::sleep(Duration::from_millis(220)).await;

    // Reader still reports healthy across all 7 flushers.
    let reader = handle.reader();
    for f in [
        bp_share_stats_sink::flush::Flusher::PoolShares,
        bp_share_stats_sink::flush::Flusher::PoolModeHashrate,
        bp_share_stats_sink::flush::Flusher::PoolRejected,
        bp_share_stats_sink::flush::Flusher::ClientStatistics,
        bp_share_stats_sink::flush::Flusher::ClientRejected,
        bp_share_stats_sink::flush::Flusher::AddressSettings,
        bp_share_stats_sink::flush::Flusher::WorkerTotals,
    ] {
        assert_eq!(
            reader.consecutive_failures(f),
            0,
            "flusher {f:?} should be healthy after empty ticks"
        );
    }

    handle.shutdown().await;
}
