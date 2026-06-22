// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! Integration tests for the best-difficulty tracker write/read
//! primitives consumed by the best-difficulty cron:
//! `upsert_best_difficulty_trackers` (bulk INSERT ... ON CONFLICT) and
//! `find_best_difficulty_trackers_for_addresses` (bulk read). Test rows
//! use a dedicated address prefix and are deleted before and after each
//! test for isolation against the shared local PG.

use std::collections::HashMap;

use bp_db::{find_best_difficulty_trackers_for_addresses, upsert_best_difficulty_trackers};
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
            None
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            None
        }
    }
}

async fn cleanup(pool: &PgPool, addrs: &[String]) {
    sqlx::query("DELETE FROM best_difficulty_tracker_entity WHERE address = ANY($1)")
        .bind(addrs.to_vec())
        .execute(pool)
        .await
        .expect("cleanup delete");
}

#[tokio::test]
async fn upsert_initialises_then_overwrites_in_either_direction() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    const ADDR_A: &str = "bc1qbptrackeroverwritea1";
    const ADDR_B: &str = "bc1qbptrackeroverwriteb2";
    let addrs = vec![ADDR_A.to_string(), ADDR_B.to_string()];
    cleanup(&pool, &addrs).await;
    let first_ts: i64 = 1_700_000_000_000;

    // Initialise both trackers.
    upsert_best_difficulty_trackers(&pool, &addrs, &[100.0, 200.0], first_ts)
        .await
        .expect("first upsert");

    let rows = find_best_difficulty_trackers_for_addresses(&pool, &addrs)
        .await
        .expect("read after init");
    let by_addr: HashMap<String, _> = rows
        .into_iter()
        .map(|r| (r.address.as_str().to_string(), r))
        .collect();
    assert_eq!(by_addr.len(), 2, "both rows present after init");
    assert_eq!(by_addr[ADDR_A].best_difficulty, 100.0);
    assert_eq!(by_addr[ADDR_B].best_difficulty, 200.0);
    assert_eq!(by_addr[ADDR_A].last_checked_at, first_ts);
    let created_a = by_addr[ADDR_A].created_at;

    // Second tick: A increases, B is synced down. Both are overwritten
    // unconditionally (the cron, not the SQL, decides direction).
    let second_ts: i64 = 1_700_000_900_000;
    upsert_best_difficulty_trackers(&pool, &addrs, &[500.0, 50.0], second_ts)
        .await
        .expect("second upsert");

    let rows = find_best_difficulty_trackers_for_addresses(&pool, &addrs)
        .await
        .expect("read after overwrite");
    let by_addr: HashMap<String, _> = rows
        .into_iter()
        .map(|r| (r.address.as_str().to_string(), r))
        .collect();
    assert_eq!(by_addr[ADDR_A].best_difficulty, 500.0, "increase persisted");
    assert_eq!(by_addr[ADDR_B].best_difficulty, 50.0, "decrease persisted");
    assert_eq!(
        by_addr[ADDR_A].last_checked_at, second_ts,
        "checkpoint moved"
    );
    assert_eq!(
        by_addr[ADDR_A].created_at, created_a,
        "createdAt preserved across conflict"
    );

    cleanup(&pool, &addrs).await;
}

#[tokio::test]
async fn read_omits_addresses_without_a_tracker_row() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    const ADDR_A: &str = "bc1qbptrackeromitsa1";
    const ADDR_B: &str = "bc1qbptrackeromitsb2";
    let addrs = vec![ADDR_A.to_string(), ADDR_B.to_string()];
    cleanup(&pool, &addrs).await;

    // Only A has a row; B must be absent from the result (caller treats
    // "absent" as "initialise silently").
    upsert_best_difficulty_trackers(&pool, &[ADDR_A.to_string()], &[42.0], 1_700_000_000_000)
        .await
        .expect("upsert A");

    let rows = find_best_difficulty_trackers_for_addresses(&pool, &addrs)
        .await
        .expect("read");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].address.as_str(), ADDR_A);

    cleanup(&pool, &addrs).await;
}
