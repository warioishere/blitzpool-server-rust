// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `seed_if_empty_with_executor` against docker-PG.
//! Uses TX-rollback via the `_with_executor` variant — no suite-wide
//! mutex needed since each test owns its own transaction.

use bp_db::{bulk_upsert_client_statistics_entity, ClientStatsUpsert};
use bp_share_stats_sink::seed::seed_if_empty_with_executor;
use sqlx::{postgres::PgPoolOptions, PgPool};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

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
            eprintln!("PG connect failed for {url}: {e} — skipping integration test");
            return None;
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            return None;
        }
    }
}

#[tokio::test]
async fn seed_is_noop_when_worker_shares_already_populated() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");

    // Don't truncate — the real DB has worker_shares rows (or fixtures
    // do); seed must observe non-empty and skip. Pre-condition check.
    let n_before: i64 = sqlx::query_scalar(r#"SELECT COUNT(*) FROM worker_shares_entity"#)
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    if n_before == 0 {
        // Insert a placeholder so the test premise holds even on a fresh DB.
        sqlx::query(
            r#"INSERT INTO worker_shares_entity (address, "clientName", shares, "rejectedShares")
               VALUES ($1, $2, 0, 0)"#,
        )
        .bind("test_seed_noop_placeholder")
        .bind("w")
        .execute(&mut *tx)
        .await
        .expect("seed placeholder");
    }

    let outcome = seed_if_empty_with_executor(&mut tx)
        .await
        .expect("seed noop");
    assert!(outcome.is_none(), "non-empty table must short-circuit");

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn seed_fires_when_worker_shares_empty_and_client_stats_present() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");

    // Wipe both tables inside the tx — rollback will undo.
    sqlx::query("TRUNCATE worker_shares_entity")
        .execute(&mut *tx)
        .await
        .expect("truncate ws");
    sqlx::query("TRUNCATE client_statistics_entity")
        .execute(&mut *tx)
        .await
        .expect("truncate cs");

    // Seed client_statistics rows the migration should aggregate.
    let stats = vec![
        ClientStatsUpsert {
            address: "test_seed_fire_alice".to_string(),
            client_name: "w1".to_string(),
            session_id: "s1".to_string(),
            time_ms: 1,
            shares: 100.0,
            accepted_count: 1,
            rejected_count: 0,
            rejected_job_not_found_count: 0,
            rejected_job_not_found_diff1: 0.0,
            rejected_duplicate_share_count: 0,
            rejected_duplicate_share_diff1: 0.0,
            rejected_low_difficulty_share_count: 1,
            rejected_low_difficulty_share_diff1: 0.5,
        },
        ClientStatsUpsert {
            address: "test_seed_fire_bob".to_string(),
            client_name: "w2".to_string(),
            session_id: "s2".to_string(),
            time_ms: 2,
            shares: 50.0,
            accepted_count: 1,
            rejected_count: 0,
            rejected_job_not_found_count: 0,
            rejected_job_not_found_diff1: 0.0,
            rejected_duplicate_share_count: 0,
            rejected_duplicate_share_diff1: 0.0,
            rejected_low_difficulty_share_count: 0,
            rejected_low_difficulty_share_diff1: 0.0,
        },
    ];
    bulk_upsert_client_statistics_entity(&mut *tx, &stats)
        .await
        .expect("seed cs");

    let outcome = seed_if_empty_with_executor(&mut tx)
        .await
        .expect("seed fire");
    let inserted = outcome.expect("seed should fire on empty table");
    assert_eq!(inserted, 2, "two aggregated rows (one per worker)");

    let alice_shares: f64 =
        sqlx::query_scalar(r#"SELECT shares FROM worker_shares_entity WHERE address = $1"#)
            .bind("test_seed_fire_alice")
            .fetch_one(&mut *tx)
            .await
            .expect("alice");
    assert!((alice_shares - 100.0).abs() < 0.01);

    let bob_shares: f64 =
        sqlx::query_scalar(r#"SELECT shares FROM worker_shares_entity WHERE address = $1"#)
            .bind("test_seed_fire_bob")
            .fetch_one(&mut *tx)
            .await
            .expect("bob");
    assert!((bob_shares - 50.0).abs() < 0.01);

    tx.rollback().await.expect("rollback");
}
