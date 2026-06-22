// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! End-to-end integration tests for `bp-pplns-engine::distribution`.
//!
//! Exercises the full hot path: Redis window read → PG open-balance
//! read → pure-math distribution build → Redis snapshot write. Plus
//! in-flight dedup of concurrent callers.
//!
//! Gated on both docker-Redis (Port 16379) and docker-PG (Port 15433);
//! tests skip cleanly via `eprintln!` if either is missing. PG state
//! is cleaned by per-test prefix DELETE; Redis state isolated by
//! per-test DB number (0..=15).

use std::sync::Arc;

use bp_common::AddressId;
use bp_pplns_engine::config::PplnsEngineConfig;
use bp_pplns_engine::distribution::{DistributionBuilder, DistributionConfig, DistributionResult};
use bp_pplns_engine::window::{NetworkDifficulty, WindowStore};
use redis::{aio::ConnectionManager, Client};
use sqlx::{postgres::PgPoolOptions, PgPool};

const REDIS_URL: &str = "redis://127.0.0.1:16379";
const PG_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

struct Harness {
    pool: PgPool,
    builder: DistributionBuilder,
    address_prefix: String,
}

async fn connect_or_skip(redis_db: u8, address_prefix: &str) -> Option<Harness> {
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
            eprintln!("PG connect failed for {pg_url}: {e} — skipping");
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
            eprintln!("Redis client failed for {redis_url}: {e} — skipping");
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
            eprintln!("Redis connect failed for {redis_url}: {e} — skipping");
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

    // Cleanup any leftover rows from previous test runs.
    let _ = sqlx::query("DELETE FROM pplns_balance WHERE address LIKE $1")
        .bind(format!("{address_prefix}%"))
        .execute(&pool)
        .await;

    let net_diff = NetworkDifficulty::new(1_000_000.0);
    let window = WindowStore::new(
        conn, /*factor=*/ 4.0, /*bucket_shares=*/ 100, net_diff,
    );
    let cfg = DistributionConfig::from_engine_config(&PplnsEngineConfig::default());
    let builder = DistributionBuilder::new(pool.clone(), window, cfg);

    Some(Harness {
        pool,
        builder,
        address_prefix: address_prefix.to_string(),
    })
}

async fn seed_share(window: &WindowStore, address: &str, diff: f64, ts: u64) {
    window
        .record_share(None, address, diff, ts)
        .await
        .expect("record_share");
}

async fn seed_open_balance(pool: &PgPool, address: &str, balance_sats: i64, total_paid: i64) {
    sqlx::query(
        r#"INSERT INTO pplns_balance (address, "balanceSats", "totalPaidSats", "updatedAt")
           VALUES ($1, $2, $3, 0)"#,
    )
    .bind(address)
    .bind(balance_sats)
    .bind(total_paid)
    .execute(pool)
    .await
    .expect("seed balance");
}

async fn cleanup(pool: &PgPool, prefix: &str) {
    let _ = sqlx::query("DELETE FROM pplns_balance WHERE address LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(pool)
        .await;
}

async fn cleanup_addresses(pool: &PgPool, addresses: &[&str]) {
    for addr in addresses {
        let _ = sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
            .bind(*addr)
            .execute(pool)
            .await;
    }
}

// ── Test 1 — end-to-end build returns payouts + writes snapshot ────

#[tokio::test]
async fn build_with_shares_only_returns_payouts_and_writes_snapshot() {
    let h = match connect_or_skip(8, "test_dist_e2e_").await {
        Some(h) => h,
        None => return,
    };

    // Use valid Bitcoin addresses so they survive the payout-address
    // sanitisation filter applied before distribution math.
    const ADDR_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const ADDR_B: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;

    let window = build_window(&h).await;
    seed_share(&window, ADDR_A, 60.0, 1_700_000_000_001).await;
    seed_share(&window, ADDR_B, 40.0, 1_700_000_000_002).await;

    let result = h.builder.build(312_500_000).await.expect("build ok");
    assert_eq!(result.block_reward_sats, 312_500_000);
    assert!(!result.payouts.is_empty(), "expected non-empty payouts");
    let addr_a_id = AddressId::new(ADDR_A).unwrap();
    let addr_b_id = AddressId::new(ADDR_B).unwrap();
    assert!(result.considered_addresses.contains(&addr_a_id));
    assert!(result.considered_addresses.contains(&addr_b_id));

    // Snapshot must be readable from Redis.
    let snapshot = window.read_snapshot().await.expect("read snapshot ok");
    let parsed = snapshot.expect("snapshot persisted");
    assert_eq!(parsed.block_reward_sats, 312_500_000);
    assert_eq!(parsed.distribution.len(), result.payouts.len());

    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;
}

// ── Test 2 — open-balance ledger is folded into the distribution ────

#[tokio::test]
async fn build_folds_open_balances_into_distribution() {
    let h = match connect_or_skip(9, "test_dist_ledger_").await {
        Some(h) => h,
        None => return,
    };

    // Use valid Bitcoin addresses so they survive the payout-address filter.
    const ADDR_MINER: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const ADDR_DEBTOR: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    cleanup_addresses(&h.pool, &[ADDR_MINER, ADDR_DEBTOR]).await;

    let window = build_window(&h).await;
    seed_share(&window, ADDR_MINER, 100.0, 1_700_000_000_001).await;

    // Debtor has a -5_000 balance (owes the pool from a previous trim
    // bonus). When debtor is NOT in the current window, the distribution
    // should still consider them.
    seed_open_balance(&h.pool, ADDR_DEBTOR, -5_000, 0).await;

    let result = h.builder.build(312_500_000).await.expect("build ok");
    let debtor_id = AddressId::new(ADDR_DEBTOR).unwrap();
    assert!(
        result.considered_addresses.contains(&debtor_id),
        "open-balance debtor must be in considered set"
    );

    cleanup_addresses(&h.pool, &[ADDR_MINER, ADDR_DEBTOR]).await;
}

// ── Test 3 — concurrent callers dedup via inflight cache ────────────

#[tokio::test]
async fn concurrent_builds_for_same_reward_share_one_compute() {
    let h = match connect_or_skip(10, "test_dist_dedup_").await {
        Some(h) => h,
        None => return,
    };

    let window = build_window(&h).await;
    seed_share(
        &window,
        &format!("{}solo", h.address_prefix),
        100.0,
        1_700_000_000_001,
    )
    .await;

    let builder = Arc::new(h.builder.clone());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let b = builder.clone();
        handles.push(tokio::spawn(async move { b.build(312_500_000).await }));
    }

    let mut shared_result: Option<Arc<DistributionResult>> = None;
    for handle in handles {
        let result = handle.await.unwrap().expect("ok");
        if let Some(ref prev) = shared_result {
            assert!(
                Arc::ptr_eq(prev, &result),
                "concurrent callers should share the same Arc (in-flight dedup)"
            );
        } else {
            shared_result = Some(result);
        }
    }
    assert!(shared_result.is_some());

    cleanup(&h.pool, &h.address_prefix).await;
}

// ── Test 4 — invalidate_all triggers fresh compute on next call ─────

#[tokio::test]
async fn invalidate_all_triggers_fresh_compute() {
    let h = match connect_or_skip(11, "test_dist_inval_").await {
        Some(h) => h,
        None => return,
    };

    let window = build_window(&h).await;
    seed_share(
        &window,
        &format!("{}foo", h.address_prefix),
        100.0,
        1_700_000_000_001,
    )
    .await;

    let r1 = h.builder.build(312_500_000).await.expect("ok");
    let r2 = h.builder.build(312_500_000).await.expect("ok");
    assert!(
        Arc::ptr_eq(&r1, &r2),
        "cached call returns the same Arc as the first"
    );

    h.builder.invalidate_all();
    let r3 = h.builder.build(312_500_000).await.expect("ok");
    assert!(
        !Arc::ptr_eq(&r1, &r3),
        "post-invalidate, the cache returns a freshly-built result"
    );

    cleanup(&h.pool, &h.address_prefix).await;
}

// ── Test 5 — different rewards run independently ────────────────────

#[tokio::test]
async fn distinct_rewards_each_get_their_own_compute() {
    let h = match connect_or_skip(12, "test_dist_rew_").await {
        Some(h) => h,
        None => return,
    };

    let window = build_window(&h).await;
    seed_share(
        &window,
        &format!("{}foo", h.address_prefix),
        50.0,
        1_700_000_000_001,
    )
    .await;

    let r1 = h.builder.build(300_000_000).await.expect("ok");
    let r2 = h.builder.build(312_500_000).await.expect("ok");
    assert_eq!(r1.block_reward_sats, 300_000_000);
    assert_eq!(r2.block_reward_sats, 312_500_000);
    assert!(!Arc::ptr_eq(&r1, &r2));

    cleanup(&h.pool, &h.address_prefix).await;
}

// ── Test 6 — empty window with no balances → empty distribution ─────

#[tokio::test]
async fn empty_state_returns_fee_only_distribution() {
    let h = match connect_or_skip(13, "test_dist_empty_").await {
        Some(h) => h,
        None => return,
    };
    // No shares, no balances. Default config has fee_address=None so
    // the math returns an empty (or fee-only) distribution. We just
    // assert it doesn't crash and the result is consistent.
    let result = h.builder.build(312_500_000).await.expect("ok");
    assert_eq!(result.block_reward_sats, 312_500_000);

    // Snapshot still written (pre-condition for on-block-found
    // replay; even an "empty" pool block needs the snapshot).
    let window = build_window(&h).await;
    let snapshot = window.read_snapshot().await.expect("ok");
    assert!(snapshot.is_some());

    cleanup(&h.pool, &h.address_prefix).await;
}

// ── Helper — build a fresh WindowStore over the same connection ─────
//
// The Harness owns the WindowStore inside the DistributionBuilder, but
// tests need a separate handle to seed shares + read the snapshot
// directly. Constructing a parallel WindowStore against the same
// connection is fine (ConnectionManager is multiplexed).

async fn build_window(h: &Harness) -> WindowStore {
    // Tests need a parallel WindowStore against the same Redis DB the
    // harness chose so they can seed shares + inspect the snapshot
    // directly. The harness's builder owns its WindowStore internally;
    // making a sibling against the same DB is fine because
    // ConnectionManager is multiplexed.
    let redis_base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_URL.to_string());
    let db = redis_db_for_prefix(&h.address_prefix);
    let url = format!("{redis_base}/{db}");
    let client = Client::open(url).expect("client");
    let conn = ConnectionManager::new(client).await.expect("conn");
    let nd = NetworkDifficulty::new(1_000_000.0);
    WindowStore::new(conn, 4.0, 100, nd)
}

fn redis_db_for_prefix(prefix: &str) -> u8 {
    // Mirror the manual db assignments in `#[tokio::test]`s above.
    // Brittle but kept obvious — change this table if you renumber the
    // tests.
    match prefix {
        "test_dist_e2e_" => 8,
        "test_dist_ledger_" => 9,
        "test_dist_dedup_" => 10,
        "test_dist_inval_" => 11,
        "test_dist_rew_" => 12,
        "test_dist_empty_" => 13,
        other => panic!("unknown test prefix: {other}"),
    }
}
