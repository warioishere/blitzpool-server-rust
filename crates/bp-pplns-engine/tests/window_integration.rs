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

use bp_pplns_engine::window::{
    bucket_key, NetworkDifficulty, WindowStore, KEY_APPLIED, KEY_BUCKETS, KEY_WINDOW_BY_ADDRESS,
    KEY_WINDOW_TOTAL, LEGACY_SCORE_CEILING,
};
use redis::{aio::ConnectionManager, AsyncCommands, Client};

const DEFAULT_URL: &str = "redis://127.0.0.1:16379";

/// Connect to a fresh Redis DB and `FLUSHDB` so the test sees an empty
/// keyspace. Returns `None` (test should skip) if the URL is unreachable.
async fn connect_or_skip(test_db: u8) -> Option<ConnectionManager> {
    let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    // Fold this binary's local number into its own DB range — see
    // `bp_test_support::redis_db`. Without it every binary's 0..15
    // land on the same 16 databases and FLUSHDB each other mid-run.
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
    let store = WindowStore::new(
        conn,
        /*window_factor=*/ 4.0,
        bucket_shares,
        nd.clone(),
        0,
    );
    (store, nd)
}

/// Share timestamp for tests that are NOT about ageing, anchored near now.
///
/// These used to pass a hardcoded `ts(0)` (Nov 2023) as a value
/// `record_share` ignored. It does not ignore it any more — it is the bucket's
/// index score — so the constant would now mean "every bucket is three years
/// old" and the age rule would empty the window out from under tests that are
/// about weight trimming. The offset keeps their relative order.
fn ts(offset: u64) -> u64 {
    (bp_common::now_ms() as u64) - 1_000_000 + offset
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
    // share (total 5.0 > 4.0) ages out the oldest miner (bc1q1).
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
    assert!(!by.contains_key("bc1q1"), "oldest miner aged out + cleaned");
    assert!((by["bc1q5"] - 1.0).abs() < 1e-9);
}

// ── The snapshot write is all-or-nothing ────────────────────────────
//
// It used to be three round trips — `DEL`, `HSET`, `EXPIRE` — and between the
// first two the snapshot DID NOT EXIST. That window is the one case
// `read_weight_snapshot_with_retry` deliberately does not retry: it takes
// `Ok(None)` at face value because "a genuinely missing snapshot will not
// appear", which is true of an expired key and false of this one. Both sides
// run on the front — the template build writes, the Stratum block-found path
// reads — so a block found in that window is parked with no settlement
// inputs. A single script closes it.
//
// The race itself cannot be pinned in a test that is not flaky; atomicity is
// structural (one `Script` invocation). What IS deterministic is the reason
// the `DEL` has to stay inside it, and that is what this asserts: a rewrite
// with FEWER entries must not leave the longer one's fields behind, or the
// parser reads a truncated entry list as a longer one.

#[tokio::test]
async fn rewriting_a_snapshot_with_fewer_entries_leaves_no_stale_fields() {
    use bp_coinbase_snapshot::{
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
        wire_weight: score,
        dust_limit: 546,
    };
    let mut snap = StoredWeightSnapshot {
        entries: vec![
            entry("bc1qaaa", 500_000_000_000),
            entry("bc1qbbb", 300_000_000_000),
            entry("bc1qccc", 200_000_000_000),
        ],
        weight_p: 15_228_426_395,
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

    // Rewrite with ONE entry. `e1_*` / `e2_*` must be gone.
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
    let leftover: Option<String> = conn.hget(key, "e1_addr").await.unwrap();
    assert!(
        leftover.is_none(),
        "field from the longer snapshot survived: {leftover:?} — with entry_count \
         back at 1 the parser would not read it, but the next LONGER rewrite \
         would inherit it"
    );
    // And the TTL landed, or the key would outlive its job forever.
    let ttl: i64 = conn.ttl(key).await.unwrap();
    assert!(ttl > 0 && ttl <= 600, "ttl = {ttl}");

    let _: () = conn.del(key).await.unwrap();
}

// ── An aggregate/bucket skew must not leave a NEGATIVE window entry ─
//
// MONEY. The aggregate is a sum of non-negative difficulties, so a trim can
// only decrement past zero if a bucket holds more for an address than the
// aggregate ever received. The `DUMP`-per-key Redis backup produces exactly
// that: it captures `window:by-address` and the `bucket:*` hashes at
// DIFFERENT instants, so a restore can hand the trim a bucket that is ahead
// of the aggregate.
//
// The old trim only `HDEL`ed a field within 1e-9 of zero, so a materially
// negative one was left sitting there — and `read_window_by_address` filters
// `diff > 0`, which drops that address out of the window ENTIRELY. Silently
// unpaid until it earns its way back in. The field is removed either way now
// (a negative is unpayable), but the trim counts the underflows so the
// operator hears about the skew instead of it passing as a clean trim.

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
    // Forge the restore skew: the aggregate holds LESS for bc1q1 than its
    // bucket does. This is the state a per-key restore can produce.
    let _: () = conn
        .hset(KEY_WINDOW_BY_ADDRESS, "bc1q1", "0.25")
        .await
        .unwrap();
    let before = store.read_window_by_address().await.unwrap();
    assert!(
        (before["bc1q1"] - 0.25).abs() < 1e-9,
        "precondition: the aggregate must be BEHIND the bucket's 1.0"
    );

    // A fifth share pushes the window over and trims bc1q1's bucket, whose
    // 1.0 exceeds the 0.25 the aggregate holds.
    store.record_share(None, "bc1q5", 1.0, ts(5)).await.unwrap();

    // The field must be GONE, not sitting at -0.75.
    let raw: Option<String> = conn.hget(KEY_WINDOW_BY_ADDRESS, "bc1q1").await.unwrap();
    assert!(
        raw.is_none(),
        "the underflowed entry must be removed, found {raw:?} — a negative field \
         reads as absent to the payout path anyway, so leaving it only hides the skew"
    );
    let by = store.read_window_by_address().await.unwrap();
    assert!(!by.contains_key("bc1q1"));
    // And the trim did not take anyone else down with it.
    assert!(
        (by["bc1q5"] - 1.0).abs() < 1e-9,
        "the fresh share survives: {by:?}"
    );
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
            .record_share(None, "bc1qfoo", 1.0, ts(i))
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

// ── Test 13 + 14 — bucket_shares is not a live knob ──────────────────
//
// The bucket id is `floor(pplns:counter / bucket_shares)` over a counter
// nothing resets, so the divisor decides where new work lands relative to
// the buckets already in the FIFO index. These two pin both directions, so
// the doc on `WindowStore::bucket_shares` is an executable claim and not a
// comment: raising it strands new shares BELOW the live set (where the trim
// eats them), lowering it does not.

/// Fill a window until the trim is active and several buckets are live,
/// then return the live bucket ids.
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

/// Raising `bucket_shares` used to strand new work: ids are `floor(counter /
/// bucket_shares)`, so a bigger divisor puts the next share BELOW every live
/// id, and while the index was scored by id that made it the FIFO head — the
/// next thing the trim took, ahead of buckets months older. This test used to
/// assert exactly that, as documented behaviour.
///
/// Scoring the index by wall-clock removes the defect rather than guarding
/// against it: new work is always the most recent, so it always sorts last,
/// whatever its id. The id arithmetic below is unchanged — only its
/// consequence is gone.
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

    // Same Redis, same counter — only the divisor is bigger, as a restart
    // with an edited config would do.
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

    // Shrink the window hard so trims fire, and check they eat the old end.
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
    // Identical to the test above except for the direction of the change, so
    // the pair is a control: same fill, same shrink, same two shares.
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

// ── Age rule ────────────────────────────────────────────────────────
//
// The size rule (`total > window_factor × difficulty`) cannot fire on a pool
// whose window sits far below its cap — measured on prod at 0.15 % of it — so
// a miner that stops mining keeps its weight indefinitely. These cover the age
// rule that fixes it, the control that it does not fire early, and the score
// conversion that starts the clock on a pre-existing window.

/// `net_diff` high enough that `4 × net_diff` is unreachable, so only the age
/// rule can drop anything — the prod situation, in miniature.
const UNREACHABLE_SIZE_DIFF: f64 = 1e12;
const DAY_MS: u64 = 86_400_000;

fn make_aged_store(
    conn: ConnectionManager,
    bucket_shares: u64,
    max_age_days: u32,
) -> (WindowStore, NetworkDifficulty) {
    let nd = NetworkDifficulty::new(UNREACHABLE_SIZE_DIFF);
    let store = WindowStore::new(conn, 4.0, bucket_shares, nd.clone(), max_age_days);
    (store, nd)
}

fn ms_ago(days: u64) -> u64 {
    (bp_common::now_ms() as u64) - days * DAY_MS
}

#[tokio::test]
async fn an_old_bucket_is_dropped_by_age_even_far_below_the_size_cap() {
    let Some(mut conn) = connect_or_skip(16).await else {
        return;
    };
    let (store, _nd) = make_aged_store(conn.clone(), /*bucket_shares=*/ 1, 90);

    // One share per bucket. A's carries a 100-day-old accept time, which is
    // what the index scores it with — no test backdoor needed, this is the
    // ordinary path.
    store
        .record_share(None, "addr_a", 100.0, ms_ago(100))
        .await
        .unwrap();
    for (addr, diff) in [("addr_b", 200.0), ("addr_c", 300.0)] {
        store
            .record_share(None, addr, diff, ms_ago(0))
            .await
            .unwrap();
    }

    // Any further share runs the trim.
    store
        .record_share(None, "addr_d", 400.0, ms_ago(0))
        .await
        .unwrap();

    let by_addr: HashMap<String, String> = conn.hgetall(KEY_WINDOW_BY_ADDRESS).await.unwrap();
    assert!(
        !by_addr.contains_key("addr_a"),
        "the 100-day-old bucket must be gone, got {by_addr:?}"
    );
    for still_here in ["addr_b", "addr_c", "addr_d"] {
        assert!(
            by_addr.contains_key(still_here),
            "{still_here} is inside the window and must stay"
        );
    }

    // The aggregate is decremented by exactly what left: 200+300+400.
    let total: String = conn.get(KEY_WINDOW_TOTAL).await.unwrap();
    assert!(
        (total.parse::<f64>().unwrap() - 900.0).abs() < 1e-9,
        "total must drop by exactly the removed bucket, got {total}"
    );
    let summed = sum_buckets(&mut conn).await;
    assert!(!summed.contains_key("addr_a"));
}

/// Control: a bucket inside the window is not touched. Same fixture, same
/// rule, only the age differs — so a change that dropped buckets for some
/// unrelated reason cannot pass both this and the test above.
#[tokio::test]
async fn a_bucket_inside_the_age_window_is_left_alone() {
    let Some(mut conn) = connect_or_skip(17).await else {
        return;
    };
    let (store, _nd) = make_aged_store(conn.clone(), /*bucket_shares=*/ 1, 90);

    // One day old against a 90-day rule.
    store
        .record_share(None, "addr_a", 100.0, ms_ago(1))
        .await
        .unwrap();
    for (addr, diff) in [("addr_b", 200.0), ("addr_c", 300.0), ("addr_d", 400.0)] {
        store
            .record_share(None, addr, diff, ms_ago(0))
            .await
            .unwrap();
    }

    let by_addr: HashMap<String, String> = conn.hgetall(KEY_WINDOW_BY_ADDRESS).await.unwrap();
    assert!(
        by_addr.contains_key("addr_a"),
        "a one-day-old bucket is inside a 90-day window, got {by_addr:?}"
    );
    let total: String = conn.get(KEY_WINDOW_TOTAL).await.unwrap();
    assert!((total.parse::<f64>().unwrap() - 1000.0).abs() < 1e-9);
}

/// The score is written once, when the bucket opens, and a later share into
/// the same id must not move it. Without `NX` a re-used id — a raised
/// `bucket_shares`, or a counter rewound by a Redis state restore — would
/// hand a months-old bucket a fresh 90-day lease.
#[tokio::test]
async fn a_second_share_does_not_refresh_its_buckets_age() {
    let Some(mut conn) = connect_or_skip(19).await else {
        return;
    };
    // bucket_shares = 10 so both shares land in the same bucket.
    let (store, _nd) = make_aged_store(conn.clone(), /*bucket_shares=*/ 10, 90);

    store
        .record_share(None, "addr_old", 100.0, ms_ago(100))
        .await
        .unwrap();
    let opened: Vec<(String, f64)> = conn.zrange_withscores(KEY_BUCKETS, 0, -1).await.unwrap();
    assert_eq!(opened.len(), 1, "precondition: one bucket so far");
    let opened_score = opened[0].1;

    // A fresh share into the SAME bucket.
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

/// The conversion must keep the live window intact AND keep FIFO order, and a
/// trim right after it must not eat what it just stamped.
///
/// Order is the subtle half. Ids are zset members as text, so a shared
/// timestamp would order them lexicographically — `"10"` ahead of `"2"` —
/// and the next trims would drop buckets out of sequence. Eleven buckets is
/// the smallest set that exposes it.
#[tokio::test]
async fn restamping_legacy_scores_keeps_the_window_and_its_order() {
    let Some(mut conn) = connect_or_skip(18).await else {
        return;
    };
    let (store, _nd) = make_aged_store(conn.clone(), /*bucket_shares=*/ 1, 90);

    for i in 1..=11 {
        store
            .record_share(None, &format!("addr_{i}"), 10.0, ms_ago(0))
            .await
            .unwrap();
    }
    // Rewrite the index the way a pre-timestamp window looks: score == id.
    for i in 1..=11 {
        let _: () = conn
            .zadd(KEY_BUCKETS, i.to_string(), i as f64)
            .await
            .unwrap();
    }

    let converted = store.restamp_legacy_bucket_scores().await.unwrap();
    assert_eq!(converted, 11, "every legacy score must be converted");

    let scored: Vec<(String, f64)> = conn.zrange_withscores(KEY_BUCKETS, 0, -1).await.unwrap();
    assert_eq!(scored.len(), 11, "conversion must not drop a bucket");
    for (member, score) in &scored {
        assert!(
            *score >= LEGACY_SCORE_CEILING,
            "bucket {member} still carries a legacy score {score}"
        );
    }
    let order: Vec<&str> = scored.iter().map(|(m, _)| m.as_str()).collect();
    assert_eq!(
        order,
        vec!["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"],
        "FIFO order must survive — lexicographic order would put 10 before 2"
    );

    // Now actually run the rule against the converted index. Asserting the
    // zset alone proved nothing about the trim; this is the claim that
    // matters — freshly stamped buckets are young and must all survive.
    store
        .record_share(None, "addr_trigger", 10.0, ms_ago(0))
        .await
        .unwrap();
    let after: Vec<String> = conn.zrange(KEY_BUCKETS, 0, -1).await.unwrap();
    assert_eq!(
        after.len(),
        12,
        "the converted buckets are young; the trim must leave every one, got {after:?}"
    );

    // Idempotent: a second run finds nothing left to convert.
    assert_eq!(store.restamp_legacy_bucket_scores().await.unwrap(), 0);
}

/// An index entry whose score is not a timestamp is inert, whenever it shows
/// up. The boot conversion cannot cover an entry written after it ran — an old
/// binary still draining shares, a `RESTORE` into a live pool — so the floor
/// lives in the trim itself.
#[tokio::test]
async fn an_unconverted_score_is_never_aged_out() {
    let Some(mut conn) = connect_or_skip(20).await else {
        return;
    };
    let (store, _nd) = make_aged_store(conn.clone(), /*bucket_shares=*/ 1, 90);

    for i in 1..=3 {
        store
            .record_share(None, &format!("addr_{i}"), 10.0, ms_ago(0))
            .await
            .unwrap();
    }
    // An id-scored entry appears AFTER startup — no conversion pass follows.
    let _: () = conn.zadd(KEY_BUCKETS, "1", 1.0).await.unwrap();

    store
        .record_share(None, "addr_trigger", 10.0, ms_ago(0))
        .await
        .unwrap();

    let after: Vec<String> = conn.zrange(KEY_BUCKETS, 0, -1).await.unwrap();
    assert!(
        after.contains(&"1".to_string()),
        "a score below the floor reads as no timestamp, not as 1970, got {after:?}"
    );
    let by_addr: HashMap<String, String> = conn.hgetall(KEY_WINDOW_BY_ADDRESS).await.unwrap();
    assert!(
        by_addr.contains_key("addr_1"),
        "and its contribution stays in the aggregate"
    );
}
