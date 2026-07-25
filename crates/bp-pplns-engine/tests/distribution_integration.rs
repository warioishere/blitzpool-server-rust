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
    let snapshot = window
        .read_snapshot_for(&result.payouts_fingerprint)
        .await
        .expect("read snapshot ok");
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

// ── Test 7 — distinct rewards share ONE window+ledger load ──────────
//
// The ext-0x0003 burst shape: every JDC reports its own
// `available_payout_value`, so the reward differs per caller and the
// per-reward cache never hits. The reward-independent half — the Redis
// window read and the Postgres ledger query — is identical for all of
// them and must be loaded once, not once per caller.

#[tokio::test]
async fn concurrent_distinct_rewards_share_one_inputs_load() {
    let h = match connect_or_skip(14, "test_dist_inputs_").await {
        Some(h) => h,
        None => return,
    };

    // Valid Bitcoin addresses so they survive payout-address sanitisation.
    const ADDR_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const ADDR_B: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;

    let window = build_window(&h).await;
    seed_share(&window, ADDR_A, 100.0, 1_700_000_000_001).await;
    seed_share(&window, ADDR_B, 50.0, 1_700_000_000_002).await;

    let before = h.builder.inputs_loads();
    let builder = Arc::new(h.builder.clone());
    let mut handles = Vec::new();
    // 16 callers, 16 distinct rewards — no per-reward cache hit possible.
    for i in 0..16u64 {
        let b = builder.clone();
        handles.push(tokio::spawn(
            async move { b.build(312_500_000 + i * 137).await },
        ));
    }
    for (i, handle) in handles.into_iter().enumerate() {
        let r = handle.await.unwrap().expect("build ok");
        assert_eq!(r.block_reward_sats, 312_500_000 + i as u64 * 137);
        assert!(!r.payouts.is_empty());
    }

    let loads = h.builder.inputs_loads() - before;
    assert!(
        loads <= 2,
        "16 concurrent builds for distinct rewards should share the window+ledger \
         load (allowing one straggler that arrives after the leader published); \
         got {loads} loads"
    );

    // Sanity: a build after an invalidation must load fresh again.
    h.builder.invalidate_all();
    let _ = h.builder.build(999_000_000).await.expect("ok");
    assert!(
        h.builder.inputs_loads() - before > loads,
        "invalidate_all must force the next build to reload the inputs"
    );

    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;
    cleanup(&h.pool, &h.address_prefix).await;
}

// ── Test 8 — distinct rewards keep their own snapshot ───────────────
//
// The ext-0x0003 collision case. Every JDC reports its own payout value, so
// its build overwrites the shared `pplns:snapshot` key with a distribution
// that belongs to nobody's block. A block-found then finds a snapshot whose
// reward disagrees with the coinbase and refuses to apply.
//
// Under the payout-list fingerprint each build keeps its own copy, so the
// distribution a block was mined from is still there when the block is found.

#[tokio::test]
async fn distinct_rewards_keep_their_own_fingerprinted_snapshot() {
    let h = match connect_or_skip(15, "test_dist_fp_").await {
        Some(h) => h,
        None => return,
    };

    const ADDR_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const ADDR_B: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;

    let window = build_window(&h).await;
    seed_share(&window, ADDR_A, 70.0, 1_700_000_000_001).await;
    seed_share(&window, ADDR_B, 30.0, 1_700_000_000_002).await;

    // The pool's own template build...
    let pool_build = h.builder.build(312_500_000).await.expect("pool build ok");
    // ...then a JDC asking for its own payout value, which is what overwrites
    // the shared key today.
    let jdc_build = h.builder.build(312_499_137).await.expect("jdc build ok");

    assert_ne!(
        pool_build.payouts_fingerprint, jdc_build.payouts_fingerprint,
        "different payout values must produce different payout lists"
    );

    // Both snapshots survive, each under its own fingerprint.
    let pool_snap = window
        .read_snapshot_for(&pool_build.payouts_fingerprint)
        .await
        .expect("read ok")
        .expect("pool snapshot must survive the later build");
    assert_eq!(pool_snap.block_reward_sats, 312_500_000);

    let jdc_snap = window
        .read_snapshot_for(&jdc_build.payouts_fingerprint)
        .await
        .expect("read ok")
        .expect("jdc snapshot present");
    assert_eq!(jdc_snap.block_reward_sats, 312_499_137);

    // The shared last-writer-wins key is no longer written at all — the
    // fingerprinted keys are the only snapshots, so there is nothing left for
    // a block-found to accidentally read.
    assert!(
        window.read_snapshot().await.expect("read ok").is_none(),
        "the shared snapshot key must no longer be written"
    );

    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;
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
    // replay; even an "empty" pool block needs the snapshot) — under the
    // fingerprint of its payout list, the only key builds write.
    let window = build_window(&h).await;
    let snapshot = window
        .read_snapshot_for(&result.payouts_fingerprint)
        .await
        .expect("ok");
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
        "test_dist_inputs_" => 14,
        "test_dist_fp_" => 15,
        "test_dist_oom_" => 6,
        other => panic!("unknown test prefix: {other}"),
    }
}

// ── A failed snapshot write must not collapse the distribution ──────
//
// `pplns_payouts` turns any `build_distribution` error into `solo_payouts`,
// so a build that returns `Err` hands that miner a job whose coinbase pays
// 100 % of the block to itself. A Redis blip on the snapshot write must
// therefore not fail the build: the distribution is correct and is about to
// become a coinbase. Losing the snapshot costs a reprocess; losing the
// distribution costs the pool's miners the block, on-chain and irreversibly.
//
// Redis is made to reject writes for real (`maxmemory`), not mocked — reads
// still succeed under it, which is exactly the shape needed here.

/// Restores `maxmemory` even if the test panics — it is server-global, so
/// leaking it would break every later test against this Redis.
struct MaxMemoryGuard(redis::aio::ConnectionManager);

impl Drop for MaxMemoryGuard {
    fn drop(&mut self) {
        let mut conn = self.0.clone();
        // Best-effort: a blocking handle inside Drop is not available, so
        // spawn onto the current runtime.
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let _ = redis::cmd("CONFIG")
                    .arg("SET")
                    .arg("maxmemory")
                    .arg("0")
                    .query_async::<()>(&mut conn)
                    .await;
            })
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_write_failure_still_returns_the_pplns_distribution() {
    let h = match connect_or_skip(6, "test_dist_oom_").await {
        Some(h) => h,
        None => return,
    };
    const ADDR_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const ADDR_B: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;

    let window = build_window(&h).await;
    // Seed while writes still work.
    seed_share(&window, ADDR_A, 60.0, 1_700_000_000_001).await;
    seed_share(&window, ADDR_B, 40.0, 1_700_000_000_002).await;

    let redis_base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_URL.to_string());
    let client = Client::open(format!("{redis_base}/6")).expect("client");
    let mut admin = ConnectionManager::new(client).await.expect("admin conn");
    redis::cmd("CONFIG")
        .arg("SET")
        .arg("maxmemory-policy")
        .arg("noeviction")
        .query_async::<()>(&mut admin)
        .await
        .expect("policy");
    let _guard = MaxMemoryGuard(admin.clone());
    redis::cmd("CONFIG")
        .arg("SET")
        .arg("maxmemory")
        .arg("1")
        .query_async::<()>(&mut admin)
        .await
        .expect("maxmemory");

    // Window read + ledger read still work; only the snapshot write is
    // rejected. The build must survive it.
    let result = h
        .builder
        .build(312_500_000)
        .await
        .expect("a rejected snapshot write must not fail the distribution build");
    assert!(
        result.payouts.len() >= 2,
        "the real PPLNS distribution must come back, not a solo fallback: {:?}",
        result.payouts
    );
    assert!(
        result.payouts.iter().any(|p| p.address.as_str() == ADDR_B),
        "every miner in the window must still be paid — a solo fallback would \
         leave only the requesting address"
    );

    drop(_guard);
    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;
}
