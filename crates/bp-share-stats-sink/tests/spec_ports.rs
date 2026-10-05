// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Statistics-coordinator edge cases: a large flush, special characters in
//! `clientName`, and the per-worker rejected difficulty in
//! `worker_shares_entity`.

use std::sync::Arc;

use bp_common::AddressId;
use bp_share_hook::{RejectedReason, SharedRejectedShare, SharedRejectedShareSink};
use bp_share_stats_sink::flush::{flush_once, Accumulators, FlushScope};
use bp_share_stats_sink::ShareStatsRejectedSink;
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

// ── 1500 rows in one statement ───────────────────────────────────────

#[tokio::test]
async fn client_statistics_1500_rows_land_in_one_statement() {
    let _guard = SPEC_PORT_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_spec_batch_";
    cleanup(&pool, prefix).await;

    // The columns travel as arrays, so 1500 rows add no bind parameters.
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
                ..Default::default()
            },
        );
    }

    let health = Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default()));
    flush_once(&pool, &accs, &health, FlushScope::All).await;

    let count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM client_statistics_entity WHERE address LIKE $1"#,
    )
    .bind(format!("{prefix}%"))
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(count, 1500, "all 1500 rows land in one upsert");

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

    // Each name stresses a different PG text-array escape rule.
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
    flush_once(&pool, &accs, &health, FlushScope::All).await;

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

// ── rejected difficulty per worker ───────────────────────────────────

/// Empties the pool-wide accumulators: the sink books every reject into the
/// current real slot, and only the worker row is under test here.
fn drop_pool_rows(accs: &Accumulators) {
    accs.pool_shares.take();
    accs.pool_rejected.take();
}

/// One reject from `session` through the sink, as the stream consumer feeds it.
async fn reject(
    accs: &Arc<Accumulators>,
    address: &str,
    session: &str,
    reason: RejectedReason,
    diff: f64,
) {
    ShareStatsRejectedSink::new(accs.clone())
        .record_rejected(SharedRejectedShare {
            address: Some(address),
            worker: Some("wkr"),
            session_id: session,
            reason,
            difficulty: diff,
            group_id: None,
        })
        .await;
}

#[tokio::test]
async fn rejected_diff_per_worker_aggregates_across_sessions() {
    let _guard = SPEC_PORT_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_spec_fanout_";
    cleanup(&pool, prefix).await;

    // One worker on three sessions, one reject reason each: the worker row
    // carries the sum as one delta.
    let accs = Arc::new(Accumulators::default());
    let address = format!("{prefix}alice");
    reject(&accs, &address, "sA", RejectedReason::JobNotFound, 10.0).await;
    reject(&accs, &address, "sB", RejectedReason::DuplicateShare, 20.0).await;
    reject(&accs, &address, "sC", RejectedReason::LowDifficulty, 30.0).await;
    drop_pool_rows(&accs);

    let health = Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default()));
    flush_once(&pool, &accs, &health, FlushScope::All).await;

    let rejected: f64 = sqlx::query_scalar(
        r#"SELECT "rejectedShares" FROM worker_shares_entity
           WHERE address = $1 AND "clientName" = 'wkr'"#,
    )
    .bind(&address)
    .fetch_one(&pool)
    .await
    .expect("read");
    assert!(
        (rejected - 60.0).abs() < 0.01,
        "rejected = 10 + 20 + 30 = 60: got {rejected}"
    );

    cleanup(&pool, prefix).await;
}

#[tokio::test]
async fn a_zero_difficulty_reject_writes_no_worker_row() {
    let _guard = SPEC_PORT_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let prefix = "test_spec_zero_fanout_";
    cleanup(&pool, prefix).await;

    let accs = Arc::new(Accumulators::default());
    let address = format!("{prefix}alice");
    reject(&accs, &address, "s", RejectedReason::Stale, 0.0).await;
    drop_pool_rows(&accs);

    let health = Arc::new(std::sync::Mutex::new(FlushHealthMonitor::default()));
    flush_once(&pool, &accs, &health, FlushScope::All).await;

    let row = sqlx::query_scalar::<_, Option<f64>>(
        r#"SELECT "rejectedShares" FROM worker_shares_entity
           WHERE address = $1 AND "clientName" = 'wkr'"#,
    )
    .bind(&address)
    .fetch_optional(&pool)
    .await
    .expect("read");
    assert!(row.is_none(), "a zero-difficulty reject writes nothing");

    cleanup(&pool, prefix).await;
}
