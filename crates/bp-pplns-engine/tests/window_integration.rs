// SPDX-License-Identifier: AGPL-3.0-or-later

// Workspace denies print_stderr; the skip-when-no-Redis path is
// test-tooling output, not production logging, so the lint is
// genuinely off-target here.
#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `bp-pplns-engine::window` (count-bucket storage)
//! against a real Redis instance.
//!
//! Gated on a local docker-Redis at `redis://127.0.0.1:16379` (override
//! with `BP_REDIS_URL`). Tests skip cleanly via `eprintln!` + early
//! return if the instance isn't reachable, so CI without a Redis
//! container stays green.
//!
//! Each test runs against a *different* Redis logical DB (0..=15), so
//! cargo's default parallel test runner doesn't interleave their state.
//!
//! Spin up the container with:
//!
//! ```sh
//! docker run -d --name blitzpool-rust-redis -p 16379:6379 redis:7-alpine
//! ```

use std::collections::HashMap;

use bp_common::{AddressId, Sats};
use bp_pplns::CoinbaseDistributionEntry;
use bp_pplns_engine::window::{
    bucket_key, snapshot::StoredSnapshot, NetworkDifficulty, WindowStore, KEY_APPLIED, KEY_BUCKETS,
    KEY_WINDOW_BY_ADDRESS, KEY_WINDOW_TOTAL,
};
use redis::{aio::ConnectionManager, AsyncCommands, Client};

const DEFAULT_URL: &str = "redis://127.0.0.1:16379";

/// Connect to a fresh Redis DB and `FLUSHDB` so the test sees an empty
/// keyspace. Returns `None` (test should skip) if the URL is unreachable.
async fn connect_or_skip(test_db: u8) -> Option<ConnectionManager> {
    let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let url = format!("{base}/{test_db}");
    let client = match Client::open(url.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("redis client open failed for {url}: {e} — skipping integration test");
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
            eprintln!("redis connect failed for {url}: {e} — skipping integration test");
            return None;
        }
        Err(_) => {
            eprintln!("redis connect timed out at {url} — skipping integration test");
            return None;
        }
    };
    if redis::cmd("PING")
        .query_async::<String>(&mut conn)
        .await
        .is_err()
    {
        eprintln!("redis PING failed for {url} — skipping integration test");
        return None;
    }
    if let Err(e) = redis::cmd("FLUSHDB").query_async::<()>(&mut conn).await {
        eprintln!("redis FLUSHDB failed: {e} — skipping integration test");
        return None;
    }
    Some(conn)
}

/// Build a `WindowStore` with a given bucket size. `bucket_shares = 1` makes
/// each share its own bucket (finest trim, == per-share trim).
fn make_store(
    conn: ConnectionManager,
    net_diff: f64,
    bucket_shares: u64,
) -> (WindowStore, NetworkDifficulty) {
    let nd = NetworkDifficulty::new(net_diff);
    let store = WindowStore::new(conn, /*window_factor=*/ 4.0, bucket_shares, nd.clone());
    (store, nd)
}

/// Sum every live bucket into per-address totals — the bucketed source of
/// truth the by-address aggregate must track.
async fn sum_buckets(conn: &mut ConnectionManager) -> HashMap<String, f64> {
    let ids: Vec<String> = conn.zrange(KEY_BUCKETS, 0, -1).await.unwrap();
    let mut out: HashMap<String, f64> = HashMap::new();
    for id in &ids {
        let bucket: HashMap<String, String> = conn.hgetall(bucket_key(id)).await.unwrap();
        for (addr, d) in bucket {
            if let Ok(v) = d.parse::<f64>() {
                *out.entry(addr).or_insert(0.0) += v;
            }
        }
    }
    out
}

// ── Test 1 — record_share aggregates into a bucket + the by-address hash ─

#[tokio::test]
async fn record_share_writes_bucket_total_and_aggregate() {
    let conn = match connect_or_skip(0).await {
        Some(c) => c,
        None => return,
    };
    let (store, _) = make_store(conn.clone(), 1_000_000.0, 10_000);

    store
        .record_share(None, "bc1qfoo", 100.0, 1_700_000_000_000)
        .await
        .expect("record_share ok");

    let mut conn = conn;
    // Bucket 0 holds the per-address sum (default 10000 shares/bucket).
    let bucket: HashMap<String, String> = conn.hgetall(bucket_key("0")).await.unwrap();
    assert!((bucket["bc1qfoo"].parse::<f64>().unwrap() - 100.0).abs() < 1e-9);
    let bucket_ids: Vec<String> = conn.zrange(KEY_BUCKETS, 0, -1).await.unwrap();
    assert_eq!(bucket_ids, vec!["0".to_string()]);

    let total: f64 = conn
        .get::<_, String>(KEY_WINDOW_TOTAL)
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert!((total - 100.0).abs() < 1e-9, "window:total = {total}");

    let hash: HashMap<String, String> = conn.hgetall(KEY_WINDOW_BY_ADDRESS).await.unwrap();
    assert!((hash["bc1qfoo"].parse::<f64>().unwrap() - 100.0).abs() < 1e-9);
}

// ── Test 2 — multiple shares accumulate per-address ─────────────────

#[tokio::test]
async fn multiple_shares_same_address_accumulate() {
    let conn = match connect_or_skip(1).await {
        Some(c) => c,
        None => return,
    };
    let (store, _) = make_store(conn.clone(), 1_000_000.0, 10_000);

    for ts in 1..=5 {
        store
            .record_share(None, "bc1qfoo", 50.0, 1_700_000_000_000 + ts)
            .await
            .expect("record_share ok");
    }

    let mut conn = conn;
    let total: f64 = conn
        .get::<_, String>(KEY_WINDOW_TOTAL)
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert!((total - 250.0).abs() < 1e-9, "expected 250, got {total}");

    let by_addr: f64 = conn
        .hget::<_, _, String>(KEY_WINDOW_BY_ADDRESS, "bc1qfoo")
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert!((by_addr - 250.0).abs() < 1e-9);
}

// ── Test 3 — multiple miners get separate aggregate entries ─────────

#[tokio::test]
async fn multiple_miners_get_separate_aggregate_entries() {
    let conn = match connect_or_skip(2).await {
        Some(c) => c,
        None => return,
    };
    let (store, _) = make_store(conn.clone(), 1_000_000.0, 10_000);

    store
        .record_share(None, "bc1qa", 10.0, 1_700_000_000_001)
        .await
        .unwrap();
    store
        .record_share(None, "bc1qb", 20.0, 1_700_000_000_002)
        .await
        .unwrap();
    store
        .record_share(None, "bc1qa", 5.0, 1_700_000_000_003)
        .await
        .unwrap();

    let by_addr = store.read_window_by_address().await.unwrap();
    assert_eq!(by_addr.len(), 2);
    assert!((by_addr["bc1qa"] - 15.0).abs() < 1e-9);
    assert!((by_addr["bc1qb"] - 20.0).abs() < 1e-9);
}

// ── Test 4 — trim drops the oldest bucket when over window-size ─────

#[tokio::test]
async fn trim_window_drops_oldest_over_window_size() {
    let conn = match connect_or_skip(3).await {
        Some(c) => c,
        None => return,
    };
    // window_size = 4.0 × 1.0 = 4.0. 1 share/bucket → finest trim. The 5th
    // share (total 5.0 > 4.0) ages out the oldest miner (bc1q1).
    let (store, _) = make_store(conn.clone(), 1.0, 1);

    for i in 1..=5 {
        store
            .record_share(None, &format!("bc1q{i}"), 1.0, 1_700_000_000_000 + i)
            .await
            .unwrap();
    }

    let total = store.current_total().await.unwrap();
    assert!(
        total <= 4.0 + 1e-9,
        "total after trim = {total}, must be ≤ 4.0"
    );
    let by = store.read_window_by_address().await.unwrap();
    assert!(!by.contains_key("bc1q1"), "oldest miner aged out + cleaned");
    assert!((by["bc1q5"] - 1.0).abs() < 1e-9);
}

// ── Test 5 — read_window_by_address falls back to summing buckets ───

#[tokio::test]
async fn read_window_by_address_falls_back_to_buckets() {
    let conn = match connect_or_skip(4).await {
        Some(c) => c,
        None => return,
    };
    let (store, _) = make_store(conn.clone(), 1_000_000.0, 10_000);

    store
        .record_share(None, "bc1qfoo", 42.5, 1700)
        .await
        .unwrap();
    store
        .record_share(None, "bc1qbar", 17.5, 1701)
        .await
        .unwrap();
    store
        .record_share(None, "bc1qfoo", 8.0, 1702)
        .await
        .unwrap();

    // Wipe the by-address hash → read must rebuild from the live buckets.
    let mut conn_mut = conn.clone();
    let _: () = conn_mut.del(KEY_WINDOW_BY_ADDRESS).await.unwrap();

    let by_addr = store.read_window_by_address().await.unwrap();
    assert!((by_addr["bc1qfoo"] - 50.5).abs() < 1e-9);
    assert!((by_addr["bc1qbar"] - 17.5).abs() < 1e-9);
}

// ── Test 6 — record_share with zero network-diff is a no-op trim-wise ─

#[tokio::test]
async fn record_share_with_zero_network_difficulty_does_not_trim() {
    let conn = match connect_or_skip(5).await {
        Some(c) => c,
        None => return,
    };
    // window_size = 0 → trim must not execute (otherwise the first share
    // would be discarded immediately).
    let (store, _) = make_store(conn.clone(), 0.0, 1);

    for i in 1..=10 {
        store
            .record_share(None, "bc1qfoo", 1.0, 1_700_000_000_000 + i)
            .await
            .unwrap();
    }

    // Nothing trimmed: full 10.0 of work retained.
    let total = store.current_total().await.unwrap();
    assert!(
        (total - 10.0).abs() < 1e-9,
        "no shares trimmed, total={total}"
    );
}

// ── Test 7 — snapshot roundtrip ─────────────────────────────────────

#[tokio::test]
async fn snapshot_roundtrip_via_window_store() {
    let conn = match connect_or_skip(6).await {
        Some(c) => c,
        None => return,
    };
    let (store, _) = make_store(conn, 1_000_000.0, 10_000);

    let addr_a = AddressId::new("bc1qcredit0000000000000000000000").unwrap();
    let addr_b = AddressId::new("bc1qdebit00000000000000000000000".to_string()).unwrap();

    let snapshot = StoredSnapshot {
        distribution: vec![
            CoinbaseDistributionEntry {
                address: addr_a.clone(),
                percent: 60.0,
                sats: Sats(187_500_000),
            },
            CoinbaseDistributionEntry {
                address: addr_b.clone(),
                percent: 40.0,
                sats: Sats(125_000_000),
            },
        ],
        block_reward_sats: 312_500_000,
        considered_addresses: vec![
            "bc1qcredit0000000000000000000000".to_string(),
            "bc1qdebit00000000000000000000000".to_string(),
            "bc1qlatearrival00000000000000000".to_string(),
        ],
        balance_after: vec![
            ("bc1qcredit0000000000000000000000".to_string(), 5_000),
            ("bc1qdebit00000000000000000000000".to_string(), -5_000),
        ],
    };

    store.write_snapshot(&snapshot, 60).await.expect("write ok");

    let parsed = store
        .read_snapshot()
        .await
        .expect("read ok")
        .expect("snapshot present");

    assert_eq!(parsed.block_reward_sats, 312_500_000);
    assert_eq!(parsed.distribution.len(), 2);
    assert_eq!(parsed.distribution[0].sats.0, 187_500_000);
    assert_eq!(parsed.distribution[1].sats.0, 125_000_000);
    assert_eq!(parsed.considered_addresses.len(), 3);
    let credit = parsed.balance_after["bc1qcredit0000000000000000000000"];
    let debit = parsed.balance_after["bc1qdebit00000000000000000000000"];
    assert_eq!(credit + debit, 0, "signed-ledger pair must sum to zero");

    store.delete_snapshot().await.expect("delete ok");
    assert!(store.read_snapshot().await.unwrap().is_none());
}

// ── Test 8 — incremental aggregate stays in sync with the buckets ───

#[tokio::test]
async fn incremental_aggregate_matches_buckets_under_trim() {
    let conn = match connect_or_skip(7).await {
        Some(c) => c,
        None => return,
    };
    // Small window (factor 4 × net_diff 1 = 4) + 1 share/bucket so every
    // record_share also trims. record_share + the atomic trim must keep the
    // by-address aggregate exactly equal to the live buckets — no recalc.
    let (store, _) = make_store(conn.clone(), 1.0, 1);

    for i in 1..=10 {
        store
            .record_share(None, &format!("bc1q{}", i % 3), 1.0, 1_700_000_000_000 + i)
            .await
            .expect("record_share ok");
    }

    let aggregate = store.read_window_by_address().await.unwrap();
    let mut conn = conn;
    let by_buckets = sum_buckets(&mut conn).await;
    assert_eq!(
        aggregate, by_buckets,
        "aggregate kept in sync with the buckets"
    );
}

// ── Test 9 — cold-start bootstrap rebuilds an empty hash from buckets ─

#[tokio::test]
async fn bootstrap_rebuilds_empty_hash_from_buckets() {
    let conn = match connect_or_skip(8).await {
        Some(c) => c,
        None => return,
    };
    let (store, _) = make_store(conn.clone(), 1_000_000.0, 10_000);

    // Seed buckets directly (no by-address hash), as if cold-started after a
    // deploy that bucketed the window but lost the aggregate hash.
    let mut seed = conn.clone();
    let _: f64 = seed.hincr(bucket_key("0"), "bc1qa", 10.0).await.unwrap();
    let _: f64 = seed.hincr(bucket_key("0"), "bc1qb", 20.0).await.unwrap();
    let _: f64 = seed.hincr(bucket_key("1"), "bc1qa", 5.0).await.unwrap();
    let _: () = seed.zadd(KEY_BUCKETS, "0", 0u64).await.unwrap();
    let _: () = seed.zadd(KEY_BUCKETS, "1", 1u64).await.unwrap();
    // A stale, wrong cached total — the bootstrap must recompute it.
    let _: () = seed.set(KEY_WINDOW_TOTAL, "999.999").await.unwrap();

    store.bootstrap_window_if_needed().await.unwrap();

    // Truth: a = 10 + 5 = 15, b = 20; total = 35.
    let total = store.current_total().await.unwrap();
    assert!((total - 35.0).abs() < 1e-9, "total={total}, expected 35");

    let by = store.read_window_by_address().await.unwrap();
    assert_eq!(by.len(), 2, "exactly 2 addresses, got {by:?}");
    assert!((by["bc1qa"] - 15.0).abs() < 1e-9);
    assert!((by["bc1qb"] - 20.0).abs() < 1e-9);
}

// ── Test 9b — bootstrap is a no-op when the hash is already populated ─

#[tokio::test]
async fn bootstrap_is_noop_when_hash_populated() {
    let conn = match connect_or_skip(11).await {
        Some(c) => c,
        None => return,
    };
    let (store, _) = make_store(conn.clone(), 1_000_000.0, 10_000);

    let mut seed = conn.clone();
    // Buckets say one thing...
    let _: f64 = seed.hincr(bucket_key("0"), "bc1qa", 10.0).await.unwrap();
    let _: () = seed.zadd(KEY_BUCKETS, "0", 0u64).await.unwrap();
    // ...but the live hash (maintained by the prior pool) says another.
    let _: () = seed
        .hset(KEY_WINDOW_BY_ADDRESS, "bc1qz", "42.0")
        .await
        .unwrap();

    store.bootstrap_window_if_needed().await.unwrap();

    let by = store.read_window_by_address().await.unwrap();
    assert_eq!(by.len(), 1, "hash must be left as-is, got {by:?}");
    assert!((by["bc1qz"] - 42.0).abs() < 1e-9);
    assert!(
        !by.contains_key("bc1qa"),
        "bootstrap must not rebuild over a live hash"
    );
}

// ── Test 10 — concurrent shares + trims keep total consistent ───────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_shares_keep_total_consistent_with_buckets() {
    let conn = match connect_or_skip(9).await {
        Some(c) => c,
        None => return,
    };
    // Small window so trims fire constantly; small bucket so the trim is
    // exercised under concurrency. Invariant: cached total AND by-address
    // both equal the Σ over the live buckets.
    let (store, _) = make_store(conn.clone(), 10.0, 4); // window_size = 40

    let mut handles = Vec::new();
    for t in 0..8u64 {
        let s = store.clone();
        handles.push(tokio::spawn(async move {
            for i in 0..50u64 {
                let addr = format!("bc1q{}", t % 4);
                s.record_share(None, &addr, 1.0, 1_700_000_000_000 + t * 100 + i)
                    .await
                    .unwrap();
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    let cached_total = store.current_total().await.unwrap();
    let mut c = conn.clone();
    let buckets_total: f64 = sum_buckets(&mut c).await.values().sum();
    assert!(
        (cached_total - buckets_total).abs() < 1e-6,
        "cached total {cached_total} drifted from bucket sum {buckets_total}"
    );
    let by = store.read_window_by_address().await.unwrap();
    let by_total: f64 = by.values().sum();
    assert!(
        (by_total - buckets_total).abs() < 1e-6,
        "by-address sum {by_total} != bucket sum {buckets_total}"
    );
}

// ── Test 11 — record_share is idempotent per share_id ───────────────

#[tokio::test]
async fn record_share_is_idempotent_per_share_id() {
    let conn = match connect_or_skip(10).await {
        Some(c) => c,
        None => return,
    };
    let (store, _) = make_store(conn.clone(), 1_000_000.0, 10_000); // big window, no trim

    let applied = store
        .record_share(Some("ep1:0"), "bc1qfoo", 100.0, 1_700_000_000_000)
        .await
        .expect("record_share ok");
    assert!(applied, "first apply must append");

    let replay = store
        .record_share(Some("ep1:0"), "bc1qfoo", 100.0, 1_700_000_000_000)
        .await
        .expect("record_share ok");
    assert!(!replay, "redelivered share_id must be a deduped no-op");

    let applied2 = store
        .record_share(Some("ep1:1"), "bc1qfoo", 100.0, 1_700_000_000_001)
        .await
        .expect("record_share ok");
    assert!(applied2, "a fresh share_id must append");

    // The window counted exactly two shares (200), not three — the dedup
    // marker zset keeps the redelivery out of the aggregate.
    let mut conn = conn;
    let applied_card: u64 = conn.zcard(KEY_APPLIED).await.unwrap();
    assert_eq!(applied_card, 2, "two distinct share_ids in the dedup set");

    let total: f64 = conn
        .get::<_, String>(KEY_WINDOW_TOTAL)
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert!((total - 200.0).abs() < 1e-9, "total={total}, expected 200");

    let by: f64 = conn
        .hget::<_, _, String>(KEY_WINDOW_BY_ADDRESS, "bc1qfoo")
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (by - 200.0).abs() < 1e-9,
        "by-address must also exclude the dup"
    );
}

// ── Test 12 — EQUIVALENCE: bucketed window ≈ exact per-share window ──
//
// The whole point of bucketing is to produce the SAME payout as per-share
// storage. Replay one deterministic share stream through the bucketed store
// AND an independent exact per-share FIFO sliding window trimmed to the same
// windowSize, then assert per-miner proportions match within a fraction of a
// percent — the only divergence is the bucket-granular trim boundary.
#[tokio::test]
async fn bucketed_window_matches_exact_per_share_window() {
    let conn = match connect_or_skip(12).await {
        Some(c) => c,
        None => return,
    };
    let bucket_shares = 10u64;
    let net_diff = 30_000.0;
    let window = 4.0 * net_diff; // 120_000
    let (store, _) = make_store(conn.clone(), net_diff, bucket_shares);

    // Deterministic LCG stream: 5 miners, varied difficulty.
    let miners = ["bc1qa", "bc1qb", "bc1qc", "bc1qd", "bc1qe"];
    let mut seed: u64 = 1_234_567;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as f64 / (1u64 << 31) as f64
    };
    let mut shares: Vec<(&str, f64)> = Vec::new();
    for _ in 0..3000 {
        let addr = miners[(next() * miners.len() as f64) as usize % miners.len()];
        let diff = 50.0 + (next() * 200.0).floor();
        shares.push((addr, diff));
    }

    for (i, (addr, diff)) in shares.iter().enumerate() {
        store
            .record_share(None, addr, *diff, 1_700_000_000_000 + i as u64)
            .await
            .unwrap();
    }
    let svc = store.read_window_by_address().await.unwrap();
    let svc_total: f64 = svc.values().sum();

    // Reference: exact per-share FIFO, trimmed to the same window.
    let mut fifo: std::collections::VecDeque<(&str, f64)> = std::collections::VecDeque::new();
    let mut ref_total = 0.0_f64;
    for (addr, diff) in &shares {
        fifo.push_back((addr, *diff));
        ref_total += *diff;
        while ref_total > window {
            if let Some((_, d)) = fifo.pop_front() {
                ref_total -= d;
            }
        }
    }
    let mut reference: HashMap<&str, f64> = HashMap::new();
    for (addr, diff) in &fifo {
        *reference.entry(addr).or_insert(0.0) += diff;
    }
    let ref_tot: f64 = reference.values().sum();

    // Trimming actually happened (window << total work fed in).
    let fed: f64 = shares.iter().map(|(_, d)| d).sum();
    assert!(
        svc_total < fed * 0.8,
        "expected heavy trimming: svc {svc_total} vs fed {fed}"
    );

    let mut max_pct_diff = 0.0_f64;
    for m in miners {
        let svc_pct = svc.get(m).copied().unwrap_or(0.0) / svc_total * 100.0;
        let ref_pct = reference.get(m).copied().unwrap_or(0.0) / ref_tot * 100.0;
        max_pct_diff = max_pct_diff.max((svc_pct - ref_pct).abs());
    }
    eprintln!("[PPLNS equivalence] max per-miner proportion diff = {max_pct_diff:.4} pct points");
    assert!(
        max_pct_diff < 1.0,
        "proportion drift {max_pct_diff} pct points too large"
    );
}
