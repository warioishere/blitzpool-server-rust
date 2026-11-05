// SPDX-License-Identifier: AGPL-3.0-or-later

// The skip-when-no-Redis path is test output, not production logging.
#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for the PPLNS window against a real Redis (`BP_REDIS_URL`),
//! skipping when it is unreachable. Each test owns a logical DB.

use std::collections::HashMap;

use bp_pplns_engine::window::{
    bucket_key, NetworkDifficulty, WindowStore, KEY_APPLIED, KEY_BUCKETS, KEY_WINDOW_BY_ADDRESS,
    KEY_WINDOW_LAST_SHARE, KEY_WINDOW_TOTAL,
};
use redis::{aio::ConnectionManager, AsyncCommands, Client};

const DEFAULT_URL: &str = "redis://127.0.0.1:16379";

/// A flushed Redis logical DB, or `None` to skip when unreachable.
async fn connect_or_skip(test_db: u8) -> Option<ConnectionManager> {
    let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    // This binary's own DB range, so binaries do not flush each other's.
    let test_db =
        bp_test_support::redis_db_in_range(bp_test_support::redis_db::PPLNS_WINDOW, test_db).await;
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
        bp_test_support::connection_manager(client),
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

/// Inactivity period for tests not about it: longer than any timestamp gap here.
const INACTIVITY_OFF: u32 = 3650;

/// `bucket_shares = 1` makes each share its own bucket (per-share trim).
fn make_store(
    conn: ConnectionManager,
    net_diff: f64,
    bucket_shares: u64,
) -> (WindowStore, NetworkDifficulty) {
    let nd = NetworkDifficulty::new(net_diff);
    let store = WindowStore::new(
        conn,
        /*window_factor=*/ 4.0,
        bucket_shares,
        nd.clone(),
        INACTIVITY_OFF,
    );
    (store, nd)
}

/// Share timestamp near now for tests not about inactivity. The offset keeps
/// the relative order.
fn ts(offset: u64) -> u64 {
    (bp_common::now_ms() as u64) - 1_000_000 + offset
}

/// Per-address sums over the live buckets, which the aggregate must track.
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
        .record_share(None, "bc1qfoo", 100.0, ts(0))
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

    for i in 1..=5 {
        store
            .record_share(None, "bc1qfoo", 50.0, ts(i))
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
        .record_share(None, "bc1qa", 10.0, ts(1))
        .await
        .unwrap();
    store
        .record_share(None, "bc1qb", 20.0, ts(2))
        .await
        .unwrap();
    store.record_share(None, "bc1qa", 5.0, ts(3)).await.unwrap();

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
    // share (total 5.0 > 4.0) trims the oldest miner (bc1q1) out.
    let (store, _) = make_store(conn.clone(), 1.0, 1);

    for i in 1..=5 {
        store
            .record_share(None, &format!("bc1q{i}"), 1.0, ts(i))
            .await
            .unwrap();
    }

    let total = store.current_total().await.unwrap();
    assert!(
        total <= 4.0 + 1e-9,
        "total after trim = {total}, must be ≤ 4.0"
    );
    let by = store.read_window_by_address().await.unwrap();
    assert!(
        !by.contains_key("bc1q1"),
        "oldest miner trimmed out + cleaned"
    );
    assert!((by["bc1q5"] - 1.0).abs() < 1e-9);
}

// ── The snapshot write ──────────────────────────────────────────────

/// A snapshot round-trips through Redis, a rewrite replaces it whole, and
/// it carries the TTL that bounds the keyspace.
#[tokio::test]
async fn a_rewritten_snapshot_replaces_the_old_one_and_keeps_its_ttl() {
    use bp_pplns_engine::window::snapshot::{
        read_weight_snapshot, write_weight_snapshot, StoredWeightSnapshot, WeightSnapshotEntry,
    };

    let mut conn = match connect_or_skip(14).await {
        Some(c) => c,
        None => return,
    };
    let key = "pplns:snapshot:fp:test_atomic_rewrite";
    let _: () = conn.del(key).await.unwrap();

    let entry = |addr: &str, score: u64| WeightSnapshotEntry {
        address: addr.to_string(),
        score_weight: score,
        balance_sats: 0,
    };
    let mut snap = StoredWeightSnapshot {
        entries: vec![
            entry("bc1qaaa", 500_000_000_000),
            entry("bc1qbbb", 300_000_000_000),
            entry("bc1qccc", 200_000_000_000),
        ],
        fee_ppm: 15_000,
        fee_address: "bc1qfee".to_string(),
        reference_revenue_sats: 312_500_000,
        score_total: 1_000_000_000_000,
    };
    write_weight_snapshot(&mut conn, key, &snap, 600)
        .await
        .unwrap();
    assert_eq!(
        read_weight_snapshot(&mut conn, key).await.unwrap().as_ref(),
        Some(&snap)
    );

    // Rewrite with ONE entry.
    snap.entries.truncate(1);
    snap.score_total = 500_000_000_000;
    write_weight_snapshot(&mut conn, key, &snap, 600)
        .await
        .unwrap();

    let back = read_weight_snapshot(&mut conn, key)
        .await
        .unwrap()
        .expect("the rewritten snapshot is readable");
    assert_eq!(
        back, snap,
        "the shorter rewrite must replace the snapshot, not overlay it"
    );
    // Without the TTL the key would outlive its job forever.
    let ttl: i64 = conn.ttl(key).await.unwrap();
    assert!(ttl > 0 && ttl <= 600, "ttl = {ttl}");

    let _: () = conn.del(key).await.unwrap();
}

// ── An aggregate/bucket skew must not leave a NEGATIVE window entry ─
// A per-key backup restore can leave a bucket ahead of the aggregate; the
// trim then removes the field instead of stranding a negative.

#[tokio::test]
async fn a_bucket_ahead_of_the_aggregate_does_not_strand_a_negative_entry() {
    let mut conn = match connect_or_skip(13).await {
        Some(c) => c,
        None => return,
    };
    // window_size = 4.0 × 1.0 = 4.0, one share per bucket.
    let (store, _) = make_store(conn.clone(), 1.0, 1);

    for i in 1..=4 {
        store
            .record_share(None, &format!("bc1q{i}"), 1.0, ts(i))
            .await
            .unwrap();
    }
    // Forge the skew: the aggregate holds less for bc1q1 than its bucket.
    let _: () = conn
        .hset(KEY_WINDOW_BY_ADDRESS, "bc1q1", "0.25")
        .await
        .unwrap();
    let before = store.read_window_by_address().await.unwrap();
    assert!(
        (before["bc1q1"] - 0.25).abs() < 1e-9,
        "precondition: the aggregate must be BEHIND the bucket's 1.0"
    );

    // A fifth share trims bc1q1's bucket (1.0 > the aggregate's 0.25).
    store.record_share(None, "bc1q5", 1.0, ts(5)).await.unwrap();

    // Gone, not sitting at -0.75.
    let raw: Option<String> = conn.hget(KEY_WINDOW_BY_ADDRESS, "bc1q1").await.unwrap();
    assert!(
        raw.is_none(),
        "the underflowed entry must be removed, found {raw:?} — a negative field \
         reads as absent to the payout path anyway, so leaving it only hides the skew"
    );
    let by = store.read_window_by_address().await.unwrap();
    assert!(!by.contains_key("bc1q1"));
    assert!(
        (by["bc1q5"] - 1.0).abs() < 1e-9,
        "the fresh share survives: {by:?}"
    );
}

// ── Test 6 — record_share with zero network-diff is a no-op trim-wise ─

#[tokio::test]
async fn record_share_with_zero_network_difficulty_does_not_trim() {
    let conn = match connect_or_skip(5).await {
        Some(c) => c,
        None => return,
    };
    // window_size = 0 must not trim, or the first share would be discarded.
    let (store, _) = make_store(conn.clone(), 0.0, 1);

    for i in 1..=10 {
        store
            .record_share(None, "bc1qfoo", 1.0, ts(i))
            .await
            .unwrap();
    }

    let total = store.current_total().await.unwrap();
    assert!(
        (total - 10.0).abs() < 1e-9,
        "no shares trimmed, total={total}"
    );
}

// ── Test 8 — incremental aggregate stays in sync with the buckets ───

#[tokio::test]
async fn incremental_aggregate_matches_buckets_under_trim() {
    let conn = match connect_or_skip(7).await {
        Some(c) => c,
        None => return,
    };
    // window_size 4 and one share per bucket, so every record_share trims.
    let (store, _) = make_store(conn.clone(), 1.0, 1);

    for i in 1..=10 {
        store
            .record_share(None, &format!("bc1q{}", i % 3), 1.0, ts(i))
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

    // Buckets survived, the aggregate key was lost.
    let mut seed = conn.clone();
    let _: f64 = seed.hincr(bucket_key("0"), "bc1qa", 10.0).await.unwrap();
    let _: f64 = seed.hincr(bucket_key("0"), "bc1qb", 20.0).await.unwrap();
    let _: f64 = seed.hincr(bucket_key("1"), "bc1qa", 5.0).await.unwrap();
    let _: () = seed.zadd(KEY_BUCKETS, "0", 0u64).await.unwrap();
    let _: () = seed.zadd(KEY_BUCKETS, "1", 1u64).await.unwrap();
    // A wrong cached total the bootstrap must recompute.
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
    // ...but the live hash says another.
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
    // Small window and buckets so trims fire constantly under concurrency.
    let (store, _) = make_store(conn.clone(), 10.0, 4); // window_size = 40

    let mut handles = Vec::new();
    for t in 0..8u64 {
        let s = store.clone();
        handles.push(tokio::spawn(async move {
            for i in 0..50u64 {
                let addr = format!("bc1q{}", t % 4);
                s.record_share(None, &addr, 1.0, ts(t * 100 + i))
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
        .record_share(Some("ep1:0"), "bc1qfoo", 100.0, ts(0))
        .await
        .expect("record_share ok");
    assert!(applied, "first apply must append");

    let replay = store
        .record_share(Some("ep1:0"), "bc1qfoo", 100.0, ts(0))
        .await
        .expect("record_share ok");
    assert!(!replay, "redelivered share_id must be a deduped no-op");

    let applied2 = store
        .record_share(Some("ep1:1"), "bc1qfoo", 100.0, ts(1))
        .await
        .expect("record_share ok");
    assert!(applied2, "a fresh share_id must append");

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
// Bucketing must pay the same as per-share storage: one share stream through
// both, per-miner proportions within a fraction of a percent.
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
            .record_share(None, addr, *diff, ts(i as u64))
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

    // Trimming must actually have happened.
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

// ── Test 13 + 14 — bucket_shares is not a live knob ──────────────────
// Both directions of a change: new work must sort after the live set and the
// trim must take the oldest bucket.

/// Fill until the trim is active with several live buckets; returns their ids.
async fn fill_until_trimming(
    conn: &mut ConnectionManager,
    store: &WindowStore,
    shares: usize,
) -> Vec<i64> {
    for i in 0..shares {
        store
            .record_share(None, "bc1qfiller", 100.0, ts(i as u64))
            .await
            .unwrap();
    }
    let ids: Vec<String> = conn.zrange(KEY_BUCKETS, 0, -1).await.unwrap();
    let ids: Vec<i64> = ids.iter().map(|s| s.parse().unwrap()).collect();
    assert!(
        ids.len() > 1 && ids[0] > 0,
        "precondition: need several live buckets and an already-trimmed head, got {ids:?}"
    );
    ids
}

/// A raised `bucket_shares` puts the new id below every live id, yet the
/// wall-clock score still sorts new work last.
#[tokio::test]
async fn raising_bucket_shares_no_longer_strands_new_work() {
    let mut conn = match connect_or_skip(6).await {
        Some(c) => c,
        None => return,
    };
    // window = 4 × 1250 = 5000, buckets of 10 × diff 100 = 1000 each, so the
    // live set settles at ~5 buckets while the counter runs to 200.
    let (store, _) = make_store(conn.clone(), 1250.0, 10);
    let live = fill_until_trimming(&mut conn, &store, 200).await;
    let live_min = *live.first().unwrap();

    // Same counter, bigger divisor: a restart with an edited config.
    let (raised, raised_nd) = make_store(conn.clone(), 1250.0, 20);
    let appended = raised
        .record_share(None, "bc1qvictim", 100.0, ts(999_000))
        .await
        .unwrap();
    assert!(appended, "must be a real append, not a dedup no-op");

    let new_id = 201 / 20;
    let index: Vec<String> = conn.zrange(KEY_BUCKETS, 0, -1).await.unwrap();
    let index: Vec<i64> = index.iter().map(|s| s.parse().unwrap()).collect();
    assert!(
        new_id < live_min,
        "precondition: the raised divisor still places the new id below the \
         live set — {new_id} vs live min {live_min}. The hazard is the id, \
         and it is unchanged; what follows is that it no longer matters."
    );
    assert_eq!(
        index.first().copied(),
        Some(live_min),
        "the OLDEST bucket must be the FIFO head, not the new work — \
         index is {index:?}"
    );

    // Shrink the window so trims fire.
    raised_nd.set(100.0);
    raised
        .record_share(None, "bc1qvictim", 100.0, ts(999_001))
        .await
        .unwrap();

    let after: Vec<String> = conn.zrange(KEY_BUCKETS, 0, -1).await.unwrap();
    let after: Vec<i64> = after.iter().map(|s| s.parse().unwrap()).collect();
    assert!(
        !after.contains(&live_min),
        "the trim must take the oldest bucket {live_min}, index is {after:?}"
    );
    assert!(
        after.contains(&new_id),
        "the newest work {new_id} must survive it, index is {after:?}"
    );
    let victim: Option<String> = conn
        .hget(KEY_WINDOW_BY_ADDRESS, "bc1qvictim")
        .await
        .unwrap();
    assert!(
        victim.is_some(),
        "the new work must still count in the aggregate"
    );
}

#[tokio::test]
async fn lowering_bucket_shares_keeps_new_work_above_the_live_window() {
    let mut conn = match connect_or_skip(15).await {
        Some(c) => c,
        None => return,
    };
    // Control for the test above: only the direction of the change differs.
    let (store, _) = make_store(conn.clone(), 1250.0, 10);
    let live = fill_until_trimming(&mut conn, &store, 200).await;
    let live_min = *live.first().unwrap();
    let live_max = *live.last().unwrap();

    let (lowered, lowered_nd) = make_store(conn.clone(), 1250.0, 5);
    let appended = lowered
        .record_share(None, "bc1qsurvivor", 100.0, ts(999_000))
        .await
        .unwrap();
    assert!(appended, "must be a real append, not a dedup no-op");

    let new_id = 201 / 5;
    let index: Vec<String> = conn.zrange(KEY_BUCKETS, 0, -1).await.unwrap();
    let index: Vec<i64> = index.iter().map(|s| s.parse().unwrap()).collect();
    assert!(
        new_id > live_max,
        "the lowered divisor must place the new id above the live set: \
         {new_id} vs live max {live_max}"
    );
    assert_eq!(
        index.last().copied(),
        Some(new_id),
        "the new work must be the TAIL of the FIFO, index is {index:?}"
    );

    lowered_nd.set(100.0);
    lowered
        .record_share(None, "bc1qsurvivor", 100.0, ts(999_001))
        .await
        .unwrap();

    let after: Vec<String> = conn.zrange(KEY_BUCKETS, 0, -1).await.unwrap();
    let after: Vec<i64> = after.iter().map(|s| s.parse().unwrap()).collect();
    assert!(
        !after.contains(&live_min),
        "the trim should have taken the genuinely OLDEST bucket {live_min}, \
         index is {after:?}"
    );
    let survivor: String = conn
        .hget(KEY_WINDOW_BY_ADDRESS, "bc1qsurvivor")
        .await
        .unwrap();
    assert!(
        (survivor.parse::<f64>().unwrap() - 200.0).abs() < 1e-9,
        "the same two shares must still count here, got {survivor}"
    );
}

// ── Inactivity rule ─────────────────────────────────────────────────
// The size rule never fires on a pool far below its cap, so the inactivity rule
// is what removes a miner that stopped. It judges the address, not the share:
// an address that keeps mining keeps every share, however old.

/// Makes the size cap unreachable, so only the inactivity rule can drop anything.
const UNREACHABLE_SIZE_DIFF: f64 = 1e12;
const DAY_MS: u64 = 86_400_000;

fn make_inactivity_store(
    conn: ConnectionManager,
    bucket_shares: u64,
    inactive_days: u32,
) -> (WindowStore, NetworkDifficulty) {
    let nd = NetworkDifficulty::new(UNREACHABLE_SIZE_DIFF);
    let store = WindowStore::new(conn, 4.0, bucket_shares, nd.clone(), inactive_days);
    (store, nd)
}

fn ms_ago(days: u64) -> u64 {
    (bp_common::now_ms() as u64) - days * DAY_MS
}

async fn aggregate(conn: &mut ConnectionManager) -> HashMap<String, f64> {
    let raw: HashMap<String, String> = conn.hgetall(KEY_WINDOW_BY_ADDRESS).await.unwrap();
    raw.into_iter()
        .map(|(a, v)| (a, v.parse::<f64>().unwrap()))
        .collect()
}

async fn total(conn: &mut ConnectionManager) -> f64 {
    let raw: String = conn.get(KEY_WINDOW_TOTAL).await.unwrap();
    raw.parse().unwrap()
}

/// Buckets, aggregate and total agree.
async fn assert_lockstep(conn: &mut ConnectionManager) {
    let agg = aggregate(conn).await;
    let summed = sum_buckets(conn).await;
    assert_eq!(
        summed.len(),
        agg.len(),
        "buckets {summed:?} vs aggregate {agg:?}"
    );
    for (address, weight) in &agg {
        assert!(
            (summed[address] - weight).abs() < 1e-9,
            "{address}: buckets {} vs aggregate {weight}",
            summed[address]
        );
    }
    let agg_sum: f64 = agg.values().sum();
    assert!((total(conn).await - agg_sum).abs() < 1e-9);
}

#[tokio::test]
async fn an_address_without_a_share_for_the_inactivity_period_leaves_with_all_its_weight() {
    let Some(mut conn) = connect_or_skip(16).await else {
        return;
    };
    let (store, _nd) = make_inactivity_store(conn.clone(), /*bucket_shares=*/ 1, 60);

    // addr_b / addr_c mine now; addr_gone's two shares, the latest 61 days
    // ago, are replayed after them, within the share path's check interval.
    for (addr, diff, at) in [
        ("addr_b", 200.0, ms_ago(0)),
        ("addr_c", 300.0, ms_ago(0)),
        ("addr_gone", 100.0, ms_ago(70)),
        ("addr_gone", 150.0, ms_ago(61)),
    ] {
        store.record_share(None, addr, diff, at).await.unwrap();
    }
    let before = aggregate(&mut conn).await;
    assert_eq!(
        before.get("addr_gone").copied(),
        Some(250.0),
        "precondition: the replayed old shares are in the window before the check"
    );

    store.forget_inactive(ms_ago(0)).await.unwrap();

    let after = aggregate(&mut conn).await;
    assert!(
        !after.contains_key("addr_gone"),
        "an address with no share for 60 days leaves completely, got {after:?}"
    );
    assert_eq!(after.get("addr_b").copied(), Some(200.0));
    assert_eq!(after.get("addr_c").copied(), Some(300.0));
    assert!(
        (total(&mut conn).await - 500.0).abs() < 1e-9,
        "total drops by exactly the address's weight"
    );
    let summed = sum_buckets(&mut conn).await;
    assert!(
        !summed.contains_key("addr_gone"),
        "no bucket keeps any of it"
    );
    let seen: Option<String> = conn.hget(KEY_WINDOW_LAST_SHARE, "addr_gone").await.unwrap();
    assert!(seen.is_none(), "its last-share entry leaves with it");
    let index: Vec<String> = conn.zrange(KEY_BUCKETS, 0, -1).await.unwrap();
    assert_eq!(
        index.len(),
        2,
        "the buckets it emptied leave the index, got {index:?}"
    );
    assert_lockstep(&mut conn).await;
}

/// The rule is per address: shares far older than the period stay while the
/// address still mines. A per-share age trim fails this.
#[tokio::test]
async fn an_address_that_keeps_mining_keeps_its_old_shares() {
    let Some(mut conn) = connect_or_skip(17).await else {
        return;
    };
    let (store, _nd) = make_inactivity_store(conn.clone(), /*bucket_shares=*/ 1, 60);

    for (addr, diff, at) in [
        ("addr_steady", 100.0, ms_ago(150)),
        ("addr_steady", 100.0, ms_ago(90)),
        ("addr_steady", 100.0, ms_ago(1)),
        ("addr_other", 50.0, ms_ago(0)),
        ("addr_other", 50.0, ms_ago(0)),
    ] {
        store.record_share(None, addr, diff, at).await.unwrap();
    }
    store.forget_inactive(ms_ago(0)).await.unwrap();

    let after = aggregate(&mut conn).await;
    assert_eq!(
        after.get("addr_steady").copied(),
        Some(300.0),
        "all three shares stay, the 150- and 90-day-old ones too, got {after:?}"
    );
    assert!((total(&mut conn).await - 400.0).abs() < 1e-9);
    assert_eq!(
        sum_buckets(&mut conn).await.get("addr_steady"),
        Some(&300.0)
    );
}

/// The prod window: many old buckets carrying one opening time, no last-share
/// entries yet. Seeding takes each address's newest bucket; past the period only
/// the addresses with nothing newer leave, and one that mined since keeps its old
/// weight too.
#[tokio::test]
async fn seeded_from_buckets_with_one_opening_time_only_the_stopped_addresses_leave() {
    let Some(mut conn) = connect_or_skip(19).await else {
        return;
    };
    let (store, _nd) = make_inactivity_store(conn.clone(), /*bucket_shares=*/ 1, 60);
    let stamped = ms_ago(61);

    // Twelve old buckets, all opened at the same instant.
    for i in 0..12u64 {
        let addr = if i % 2 == 0 {
            "addr_stopped"
        } else {
            "addr_back"
        };
        store.record_share(None, addr, 10.0, stamped).await.unwrap();
    }
    // addr_back mined again since; addr_new only since.
    store
        .record_share(None, "addr_back", 10.0, ms_ago(5))
        .await
        .unwrap();
    store
        .record_share(None, "addr_new", 10.0, ms_ago(5))
        .await
        .unwrap();
    // The state before this rule existed: no last-share entries.
    let _: () = conn.del(KEY_WINDOW_LAST_SHARE).await.unwrap();

    store.bootstrap_window_if_needed().await.unwrap();
    let seeded: HashMap<String, String> = conn.hgetall(KEY_WINDOW_LAST_SHARE).await.unwrap();
    assert_eq!(seeded.len(), 3, "every address gets a time, got {seeded:?}");
    assert_eq!(
        seeded["addr_stopped"].parse::<u64>().unwrap(),
        stamped,
        "an address only in the old buckets gets their opening time"
    );
    assert!(
        seeded["addr_back"].parse::<u64>().unwrap() > stamped,
        "an address in a newer bucket gets that bucket's time"
    );

    store.forget_inactive(ms_ago(0)).await.unwrap();

    let after = aggregate(&mut conn).await;
    assert!(!after.contains_key("addr_stopped"), "got {after:?}");
    assert_eq!(
        after.get("addr_back").copied(),
        Some(70.0),
        "its six old shares stay with the new one"
    );
    assert_eq!(after.get("addr_new").copied(), Some(10.0));
    assert!((total(&mut conn).await - 80.0).abs() < 1e-9);
    assert_lockstep(&mut conn).await;
}

/// Seeding never lowers a time a share wrote.
#[tokio::test]
async fn seeding_keeps_a_recorded_last_share() {
    let Some(mut conn) = connect_or_skip(20).await else {
        return;
    };
    let (store, _nd) = make_inactivity_store(conn.clone(), /*bucket_shares=*/ 10, 60);
    let opened = ms_ago(30);
    store
        .record_share(None, "addr_a", 10.0, opened)
        .await
        .unwrap();
    let latest = ms_ago(1);
    store
        .record_share(None, "addr_a", 10.0, latest)
        .await
        .unwrap();
    let index: Vec<(String, f64)> = conn.zrange_withscores(KEY_BUCKETS, 0, -1).await.unwrap();
    assert_eq!(
        index,
        vec![("0".to_string(), opened as f64)],
        "precondition: both shares in one bucket opened at {opened}"
    );

    store.bootstrap_window_if_needed().await.unwrap();

    let seen: String = conn.hget(KEY_WINDOW_LAST_SHARE, "addr_a").await.unwrap();
    assert_eq!(
        seen.parse::<u64>().unwrap(),
        latest,
        "the share's own time, not the bucket's opening time {opened}"
    );
}

/// An entry older than the work the window holds for its address, as a writer
/// that kept no last-share times leaves it, is raised at startup, so the
/// address is not taken for gone while it mines.
#[tokio::test]
async fn seeding_raises_a_stale_entry_to_the_newest_bucket() {
    let Some(mut conn) = connect_or_skip(26).await else {
        return;
    };
    let (store, _nd) = make_inactivity_store(conn.clone(), /*bucket_shares=*/ 1, 60);
    store
        .record_share(None, "addr_back", 10.0, ms_ago(70))
        .await
        .unwrap();
    let recent = ms_ago(5);
    store
        .record_share(None, "addr_back", 10.0, recent)
        .await
        .unwrap();
    let _: () = conn
        .hset(KEY_WINDOW_LAST_SHARE, "addr_back", ms_ago(70))
        .await
        .unwrap();

    store.bootstrap_window_if_needed().await.unwrap();

    let seen: String = conn.hget(KEY_WINDOW_LAST_SHARE, "addr_back").await.unwrap();
    assert_eq!(seen.parse::<u64>().unwrap(), recent);
    store.forget_inactive(ms_ago(0)).await.unwrap();
    assert_eq!(
        aggregate(&mut conn).await.get("addr_back").copied(),
        Some(20.0),
        "it mined five days ago and keeps both shares"
    );
}

/// An address in the aggregate but in no bucket gets the current time.
#[tokio::test]
async fn seeding_gives_an_address_in_no_bucket_the_current_time() {
    let Some(mut conn) = connect_or_skip(27).await else {
        return;
    };
    let (store, _nd) = make_inactivity_store(conn.clone(), /*bucket_shares=*/ 1, 60);
    store
        .record_share(None, "addr_a", 10.0, ms_ago(1))
        .await
        .unwrap();
    let _: () = conn
        .hset(KEY_WINDOW_BY_ADDRESS, "addr_orphan", "5")
        .await
        .unwrap();
    let before = bp_common::now_ms() as u64;

    store.bootstrap_window_if_needed().await.unwrap();

    let seen: String = conn
        .hget(KEY_WINDOW_LAST_SHARE, "addr_orphan")
        .await
        .unwrap();
    assert!(seen.parse::<u64>().unwrap() >= before);
}

/// A replayed older share does not move the last-share time back.
#[tokio::test]
async fn a_replayed_older_share_does_not_lower_the_last_share_time() {
    let Some(mut conn) = connect_or_skip(22).await else {
        return;
    };
    let (store, _nd) = make_inactivity_store(conn.clone(), /*bucket_shares=*/ 1, 60);
    let latest = ms_ago(1);
    store
        .record_share(None, "addr_a", 10.0, latest)
        .await
        .unwrap();
    store
        .record_share(None, "addr_a", 10.0, ms_ago(80))
        .await
        .unwrap();

    let seen: String = conn.hget(KEY_WINDOW_LAST_SHARE, "addr_a").await.unwrap();
    assert_eq!(seen.parse::<u64>().unwrap(), latest);
}

/// The check runs off the share path in share time: a backlog replayed long
/// after it was mined does not drop an address whose newer shares follow.
#[tokio::test]
async fn the_share_path_judges_inactivity_in_share_time() {
    let Some(mut conn) = connect_or_skip(23).await else {
        return;
    };
    let (store, _nd) = make_inactivity_store(conn.clone(), /*bucket_shares=*/ 1, 60);

    // A backlog from 100 days ago: addr_a's last share there is followed by
    // addr_b's 10 minutes later, inside the period in share time.
    store
        .record_share(None, "addr_a", 10.0, ms_ago(100))
        .await
        .unwrap();
    store
        .record_share(None, "addr_b", 10.0, ms_ago(100) + 600_000)
        .await
        .unwrap();
    assert!(
        aggregate(&mut conn).await.contains_key("addr_a"),
        "share time says addr_a mined 10 minutes ago"
    );

    // A share 61 days after addr_a's last one runs the check and takes it out.
    store
        .record_share(None, "addr_b", 10.0, ms_ago(39))
        .await
        .unwrap();
    let after = aggregate(&mut conn).await;
    assert!(!after.contains_key("addr_a"), "got {after:?}");
    assert_eq!(after.get("addr_b").copied(), Some(20.0));
    assert_lockstep(&mut conn).await;
}

/// The share path checks at most once per minute of share time.
#[tokio::test]
async fn the_share_path_checks_at_most_once_a_minute() {
    let Some(mut conn) = connect_or_skip(28).await else {
        return;
    };
    let (store, _nd) = make_inactivity_store(conn.clone(), /*bucket_shares=*/ 1, 60);
    let t0 = ms_ago(1);
    // The first share runs the check, before addr_gone is in the window.
    store.record_share(None, "addr_b", 10.0, t0).await.unwrap();
    store
        .record_share(None, "addr_gone", 10.0, t0 - 61 * DAY_MS)
        .await
        .unwrap();

    store
        .record_share(None, "addr_b", 10.0, t0 + 30_000)
        .await
        .unwrap();
    assert!(
        aggregate(&mut conn).await.contains_key("addr_gone"),
        "30 s after the last check: no check yet"
    );

    store
        .record_share(None, "addr_b", 10.0, t0 + 61_000)
        .await
        .unwrap();
    assert!(
        !aggregate(&mut conn).await.contains_key("addr_gone"),
        "61 s after it: checked and gone"
    );
}

/// A size trim that takes an address's last weight takes its last-share entry.
#[tokio::test]
async fn a_size_trim_that_empties_an_address_drops_its_last_share_entry() {
    let Some(mut conn) = connect_or_skip(24).await else {
        return;
    };
    // window = 4 × 1 = 4: the second share pushes the first bucket out.
    let (store, _) = make_store(conn.clone(), 1.0, 1);
    store
        .record_share(None, "addr_a", 10.0, ts(0))
        .await
        .unwrap();
    let seen: Option<String> = conn.hget(KEY_WINDOW_LAST_SHARE, "addr_a").await.unwrap();
    assert!(seen.is_some(), "precondition: the share wrote its entry");
    store
        .record_share(None, "addr_b", 10.0, ts(1))
        .await
        .unwrap();

    assert!(!aggregate(&mut conn).await.contains_key("addr_a"));
    let seen: Option<String> = conn.hget(KEY_WINDOW_LAST_SHARE, "addr_a").await.unwrap();
    assert!(seen.is_none());
}

/// A later share into the same bucket does not move its opening score (`NX`),
/// which keeps FIFO order for the size rule and bounds the seeded time.
#[tokio::test]
async fn a_second_share_does_not_move_its_buckets_opening_time() {
    let Some(mut conn) = connect_or_skip(25).await else {
        return;
    };
    let (store, _nd) = make_inactivity_store(conn.clone(), /*bucket_shares=*/ 10, 90);

    store
        .record_share(None, "addr_old", 100.0, ms_ago(100))
        .await
        .unwrap();
    let opened: Vec<(String, f64)> = conn.zrange_withscores(KEY_BUCKETS, 0, -1).await.unwrap();
    assert_eq!(opened.len(), 1, "precondition: one bucket so far");
    let opened_score = opened[0].1;

    store
        .record_share(None, "addr_new", 100.0, ms_ago(0))
        .await
        .unwrap();

    let after: Vec<(String, f64)> = conn.zrange_withscores(KEY_BUCKETS, 0, -1).await.unwrap();
    assert_eq!(after.len(), 1, "still the same single bucket");
    assert!(
        (after[0].1 - opened_score).abs() < 1e-9,
        "the bucket kept its opening time: {} vs {}",
        after[0].1,
        opened_score
    );
}

/// The bucket still taking shares is never dropped by the size rule, wherever
/// it sorts. The active bucket here sorts FIRST, so a rule that merely spared
/// the last entry would drop `addr_b` and keep `addr_a`.
#[tokio::test]
async fn the_currently_filling_bucket_is_never_dropped() {
    let Some(mut conn) = connect_or_skip(21).await else {
        return;
    };
    // window = 4 × 1 = 4, one share per bucket, so every share is over size.
    let (store, _nd) = make_store(conn.clone(), 1.0, 1);

    let later = ts(1_000);
    let earlier = later - 1_000;
    // Bucket 1: over size, but active, so its own append keeps it.
    store
        .record_share(None, "addr_a", 10.0, later)
        .await
        .unwrap();
    let index: Vec<String> = conn.zrange(KEY_BUCKETS, 0, -1).await.unwrap();
    assert_eq!(
        index,
        vec!["1"],
        "precondition: the over-size bucket is active and stays"
    );

    // Bucket 2, now active, opened by a replayed older share, so it is the
    // index head; the completed bucket 1 is the one that has to go.
    store
        .record_share(None, "addr_b", 10.0, earlier)
        .await
        .unwrap();

    let index: Vec<String> = conn.zrange(KEY_BUCKETS, 0, -1).await.unwrap();
    assert_eq!(
        index,
        vec!["2"],
        "the completed bucket 1 is dropped and the active bucket 2 stays \
         although it sorts first — got {index:?}"
    );
    let score: f64 = conn.zscore(KEY_BUCKETS, "2").await.unwrap();
    assert!(
        score < later as f64,
        "the survivor is the one that sorted FIRST, score {score}"
    );

    let by_addr = aggregate(&mut conn).await;
    assert!(!by_addr.contains_key("addr_a"), "got {by_addr:?}");
    assert!(by_addr.contains_key("addr_b"), "got {by_addr:?}");
    assert!((total(&mut conn).await - 10.0).abs() < 1e-9);
}
