// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `bp-group-solo-engine::round` against Redis; each
//! test uses its own logical DB and skips when Redis is unreachable.

use bp_group_mgmt::group::PayoutMode;
use bp_group_solo_engine::round::{
    key_applied, key_best_share, key_by_address, key_counter, key_last_accepted_share_at,
    key_rejected_shares, key_total, key_window_buckets, key_window_by_address, snapshot,
    GroupRoundStore, WindowLane, WINDOW_BUCKET_MS,
};
use redis::{aio::ConnectionManager, AsyncCommands, Client};

const DEFAULT_URL: &str = "redis://127.0.0.1:16379";

async fn connect_or_skip(test_db: u8) -> Option<ConnectionManager> {
    let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    // Fold this binary's local number into its own DB range (see
    // `bp_test_support::redis_db`) so binaries do not FLUSHDB each other.
    let test_db =
        bp_test_support::redis_db_in_range(bp_test_support::redis_db::GS_ROUND, test_db).await;
    let url = format!("{base}/{test_db}");
    let client = match Client::open(url.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("redis client open failed for {url}: {e} — skipping");
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
            eprintln!("redis connect failed for {url}: {e} — skipping");
            return None;
        }
        Err(_) => {
            eprintln!("redis connect timed out (>2s) — skipping integration test");
            return None;
        }
    };
    if redis::cmd("PING")
        .query_async::<String>(&mut conn)
        .await
        .is_err()
    {
        eprintln!("redis PING failed — skipping");
        return None;
    }
    if let Err(e) = redis::cmd("FLUSHDB").query_async::<()>(&mut conn).await {
        eprintln!("FLUSHDB failed: {e} — skipping");
        return None;
    }
    Some(conn)
}

// ── Test 1 — record_share writes the aggregate keys atomically ─────

#[tokio::test]
async fn record_share_writes_all_keys() {
    let conn = match connect_or_skip(0).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_record1";
    let addr = "bc1qfoo";

    store
        .record_share(None, group, addr, 100.0, 1_700_000_000_000)
        .await
        .expect("ok");

    let mut conn = conn;
    let total_str: String = conn.get(key_total(group)).await.unwrap();
    assert!((total_str.parse::<f64>().unwrap() - 100.0).abs() < 1e-9);
    let by_addr: f64 = conn
        .hget::<_, _, String>(key_by_address(group), addr)
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert!((by_addr - 100.0).abs() < 1e-9);
    let last_at: i64 = conn
        .hget::<_, _, String>(key_last_accepted_share_at(group), addr)
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(last_at, 1_700_000_000_000);
    // The counter key is unused and must stay unwritten.
    let counter_exists: bool = conn.exists(key_counter(group)).await.unwrap();
    assert!(
        !counter_exists,
        "the per-group counter is legacy and must no longer be written"
    );
}

// ── Test 2 — record_reject increments per-address rejected ─────────

#[tokio::test]
async fn record_reject_increments_per_address() {
    let conn = match connect_or_skip(1).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_reject1";

    store.record_reject(group, "bc1qfoo", 1.0).await.unwrap();
    store.record_reject(group, "bc1qfoo", 2.0).await.unwrap();
    store.record_reject(group, "bc1qbar", 5.0).await.unwrap();

    let rejected = store.read_rejected(group).await.unwrap();
    assert!((rejected["bc1qfoo"] - 3.0).abs() < 1e-9);
    assert!((rejected["bc1qbar"] - 5.0).abs() < 1e-9);
}

// ── Test 3 — read_by_address returns the maintained aggregate ──────

#[tokio::test]
async fn read_by_address_returns_aggregate() {
    let conn = match connect_or_skip(2).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_fallback1";

    store
        .record_share(None, group, "bc1qfoo", 30.0, 1700)
        .await
        .unwrap();
    store
        .record_share(None, group, "bc1qbar", 20.0, 1701)
        .await
        .unwrap();
    store
        .record_share(None, group, "bc1qfoo", 50.0, 1702)
        .await
        .unwrap();

    let result = store.read_by_address(group).await.unwrap();
    assert!((result["bc1qfoo"] - 80.0).abs() < 1e-9);
    assert!((result["bc1qbar"] - 20.0).abs() < 1e-9);
}

// ── Test 4 — reset_for_block_found preserves last-accepted-share-at

#[tokio::test]
async fn reset_for_block_found_preserves_last_accepted_share_at() {
    let conn = match connect_or_skip(3).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_reset_blockfound";

    // A share_id populates the dedup zset, which the reset must keep.
    store
        .record_share(Some("ep1:0"), group, "bc1qfoo", 50.0, 1_700_000_000_001)
        .await
        .unwrap();
    store
        .update_best_share_if_better(group, "bc1qfoo", 50.0, 1_700_000_000_001)
        .await
        .unwrap();

    store.reset_for_block_found(group).await.unwrap();

    let mut conn = conn;
    let total_exists: bool = conn.exists(key_total(group)).await.unwrap();
    let by_addr_exists: bool = conn.exists(key_by_address(group)).await.unwrap();
    let counter_exists: bool = conn.exists(key_counter(group)).await.unwrap();
    let best_exists: bool = conn.exists(key_best_share(group)).await.unwrap();
    let applied_exists: bool = conn.exists(key_applied(group)).await.unwrap();
    let last_at_exists: bool = conn
        .exists(key_last_accepted_share_at(group))
        .await
        .unwrap();

    assert!(!total_exists, "total wiped");
    assert!(!by_addr_exists, "by-address wiped");
    assert!(!counter_exists, "the legacy counter key is cleared");
    assert!(!best_exists, "best-share wiped");
    assert!(
        last_at_exists,
        "last-accepted-share-at preserved across block-found reset"
    );
    // MONEY: without the markers, a batch redelivered after the reset would
    // credit the wiped round's work a second time into the fresh round.
    assert!(
        applied_exists,
        "the dedup zset must survive a round reset, or an un-ACKed satellite \
         batch is reapplied into the fresh round"
    );
}

// ── Test 5 — reset_full wipes including last-accepted-share-at ─────

#[tokio::test]
async fn reset_full_wipes_everything_including_last_accepted() {
    let conn = match connect_or_skip(4).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_reset_full";

    store
        .record_share(Some("ep1:0"), group, "bc1qfoo", 10.0, 1_700_000_000_001)
        .await
        .unwrap();
    store.record_reject(group, "bc1qfoo", 1.0).await.unwrap();
    store.reset_full(group).await.unwrap();

    let mut conn = conn;
    let last_at_exists: bool = conn
        .exists(key_last_accepted_share_at(group))
        .await
        .unwrap();
    let rejected_exists: bool = conn.exists(key_rejected_shares(group)).await.unwrap();
    let applied_exists: bool = conn.exists(key_applied(group)).await.unwrap();
    assert!(!last_at_exists, "last-accepted-share-at wiped");
    assert!(!rejected_exists, "rejected-shares wiped");
    // Reapplying an un-ACKed batch would hand those miners an unearned start.
    assert!(
        applied_exists,
        "the dedup zset must survive a full reset too"
    );
}

// ── Test 6 — best-share only updates on improvement ────────────────

#[tokio::test]
async fn update_best_share_only_replaces_on_improvement() {
    let conn = match connect_or_skip(5).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_best1";

    assert!(store
        .update_best_share_if_better(group, "bc1qa", 100.0, 1_700_000_000_001)
        .await
        .unwrap());

    // Lower difficulty — no replacement.
    assert!(!store
        .update_best_share_if_better(group, "bc1qb", 50.0, 1_700_000_000_002)
        .await
        .unwrap());

    // Higher difficulty — replaces.
    assert!(store
        .update_best_share_if_better(group, "bc1qc", 200.0, 1_700_000_000_003)
        .await
        .unwrap());

    let best = store.read_best_share(group).await.unwrap().unwrap();
    assert_eq!(best.address, "bc1qc");
    assert!((best.difficulty - 200.0).abs() < 1e-9);
}

// ── Test 7 — forget_member subtracts contribution + cleans state ───

#[tokio::test]
async fn forget_member_subtracts_contribution() {
    let conn = match connect_or_skip(6).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_forget1";

    store
        .record_share(None, group, "bc1qa", 30.0, 1_700_000_000_001)
        .await
        .unwrap();
    store
        .record_share(None, group, "bc1qa", 20.0, 1_700_000_000_002)
        .await
        .unwrap();
    store
        .record_share(None, group, "bc1qb", 40.0, 1_700_000_000_003)
        .await
        .unwrap();

    let removed = store
        .forget_member(group, "bc1qa", PayoutMode::Prop)
        .await
        .unwrap();
    assert!((removed - 50.0).abs() < 1e-9);

    let by_addr = store.read_by_address(group).await.unwrap();
    assert!(!by_addr.contains_key("bc1qa"), "removed from aggregate");
    assert!((by_addr["bc1qb"] - 40.0).abs() < 1e-9);

    let mut conn = conn;
    let last_at_has_a: bool = conn
        .hexists(key_last_accepted_share_at(group), "bc1qa")
        .await
        .unwrap();
    assert!(!last_at_has_a, "last-accepted-share-at slot deleted");

    let total = store.read_total(group).await.unwrap();
    assert!((total - 40.0).abs() < 1e-9, "total decremented");
}

// ── Test 8 — round_stats composes per-address + rejected ───────────

#[tokio::test]
async fn read_round_stats_returns_per_address_and_rejected() {
    let conn = match connect_or_skip(7).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_stats1";

    store
        .record_share(None, group, "bc1qa", 30.0, 1)
        .await
        .unwrap();
    store
        .record_share(None, group, "bc1qb", 70.0, 2)
        .await
        .unwrap();
    store.record_reject(group, "bc1qa", 5.0).await.unwrap();

    let stats = store
        .read_round_stats_for(group, PayoutMode::Prop, 0, 0)
        .await
        .unwrap();
    assert!((stats.total_shares - 100.0).abs() < 1e-9);
    assert!((stats.total_rejected - 5.0).abs() < 1e-9);
    assert_eq!(stats.per_address.len(), 2);
}

// ── Test 9 — snapshot roundtrip per (group, finder) ────────────────

#[tokio::test]
async fn snapshot_roundtrip_per_group_and_finder() {
    let mut conn = match connect_or_skip(8).await {
        Some(c) => c,
        None => return,
    };
    let group = "g_snap1";
    let finder = "bc1qfinder";
    let snap = bp_coinbase_snapshot::StoredWeightSnapshot {
        entries: vec![bp_coinbase_snapshot::WeightSnapshotEntry {
            address: "bc1qminer".to_string(),
            score_weight: 1_000_000_000_000,
            balance_sats: 0,
            wire_weight: 1_000_000_000_000,
            dust_limit: 546,
        }],
        score_total: 1_000_000_000_000,
        weight_p: 15_228_426_395,
        fee_ppm: 15_000,
        fee_address: "bc1qfee".to_string(),
        reference_revenue_sats: 312_500_000,
    };

    snapshot::write_weight_snapshot(&mut conn, group, finder, &snap, 60)
        .await
        .expect("write ok");
    let parsed = snapshot::read_weight_snapshot(&mut conn, group, finder)
        .await
        .expect("read ok")
        .expect("present");
    assert_eq!(parsed.reference_revenue_sats, 312_500_000);
    assert_eq!(parsed.entries.len(), 1);

    snapshot::delete_snapshot(&mut conn, group, finder)
        .await
        .expect("delete ok");
    assert!(snapshot::read_weight_snapshot(&mut conn, group, finder)
        .await
        .unwrap()
        .is_none());
}

// ── Test 10 — delete_all_for_group via SCAN+DEL ────────────────────

#[tokio::test]
async fn delete_all_snapshots_for_group_scans_and_deletes() {
    let mut conn = match connect_or_skip(9).await {
        Some(c) => c,
        None => return,
    };
    let group = "g_snap_del";
    let snap = bp_coinbase_snapshot::StoredWeightSnapshot {
        entries: vec![bp_coinbase_snapshot::WeightSnapshotEntry {
            address: "bc1qminer".to_string(),
            score_weight: 1_000_000_000_000,
            balance_sats: 0,
            wire_weight: 1_000_000_000_000,
            dust_limit: 546,
        }],
        score_total: 1_000_000_000_000,
        weight_p: 15_228_426_395,
        fee_ppm: 15_000,
        fee_address: "bc1qfee".to_string(),
        reference_revenue_sats: 312_500_000,
    };
    // Write snapshots for 3 different finders.
    for finder in &["bc1qf1", "bc1qf2", "bc1qf3"] {
        snapshot::write_weight_snapshot(&mut conn, group, finder, &snap, 60)
            .await
            .unwrap();
    }
    // Plus one snapshot for an UNRELATED group — must survive.
    snapshot::write_weight_snapshot(&mut conn, "g_other", "bc1qf1", &snap, 60)
        .await
        .unwrap();

    let deleted = snapshot::delete_all_for_group(&mut conn, group)
        .await
        .expect("scan+del ok");
    assert_eq!(deleted, 3);

    // Confirm: target group's snapshots gone, other group's survives.
    for finder in &["bc1qf1", "bc1qf2", "bc1qf3"] {
        assert!(snapshot::read_weight_snapshot(&mut conn, group, finder)
            .await
            .unwrap()
            .is_none());
    }
    assert!(
        snapshot::read_weight_snapshot(&mut conn, "g_other", "bc1qf1")
            .await
            .unwrap()
            .is_some()
    );
}

// ── Test 11 — multiple groups are isolated ─────────────────────────

#[tokio::test]
async fn multiple_groups_redis_state_is_isolated() {
    let conn = match connect_or_skip(10).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());

    store
        .record_share(None, "g_iso_a", "bc1qfoo", 100.0, 1_700_000_000_001)
        .await
        .unwrap();
    store
        .record_share(None, "g_iso_b", "bc1qbar", 50.0, 1_700_000_000_002)
        .await
        .unwrap();

    let a_by_addr = store.read_by_address("g_iso_a").await.unwrap();
    let b_by_addr = store.read_by_address("g_iso_b").await.unwrap();
    assert_eq!(a_by_addr.len(), 1);
    assert_eq!(b_by_addr.len(), 1);
    assert!(a_by_addr.contains_key("bc1qfoo"));
    assert!(b_by_addr.contains_key("bc1qbar"));

    // Reset group A doesn't touch group B.
    store.reset_full("g_iso_a").await.unwrap();
    assert!(store.read_by_address("g_iso_a").await.unwrap().is_empty());
    assert_eq!(store.read_by_address("g_iso_b").await.unwrap().len(), 1);
}

// ── Test 12 — record_share is idempotent per share_id ───────────────
#[tokio::test]
async fn record_share_is_idempotent_per_share_id() {
    let conn = match connect_or_skip(11).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_idem";
    let addr = "bc1qfoo";

    let applied = store
        .record_share(Some("ep1:0"), group, addr, 100.0, 1_700_000_000_000)
        .await
        .expect("ok");
    assert!(applied, "first apply must append");

    let replay = store
        .record_share(Some("ep1:0"), group, addr, 100.0, 1_700_000_000_000)
        .await
        .expect("ok");
    assert!(!replay, "redelivered share_id must be a deduped no-op");

    let applied2 = store
        .record_share(Some("ep1:1"), group, addr, 100.0, 1_700_000_000_001)
        .await
        .expect("ok");
    assert!(applied2, "a fresh share_id must append");

    let mut conn = conn;
    let applied_card: u64 = conn.zcard(key_applied(group)).await.unwrap();
    assert_eq!(
        applied_card, 2,
        "two distinct share_ids recorded in the dedup set"
    );

    let total: f64 = conn
        .get::<_, String>(key_total(group))
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert!((total - 200.0).abs() < 1e-9, "total={total}, expected 200");

    let by: f64 = conn
        .hget::<_, _, String>(key_by_address(group), addr)
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (by - 200.0).abs() < 1e-9,
        "by-address must also exclude the dup"
    );

    // Scored by the share's own accept time, so the set can outlive a reset.
    let score: f64 = conn
        .zscore(key_applied(group), "ep1:0")
        .await
        .expect("marker present");
    assert_eq!(score, 1_700_000_000_000.0);
}

// ── The dedup marker must outlive a round reset ────────────────────
// MONEY: a share redelivered after a reset must still be deduped, or the
// wiped round's work is credited again into the fresh round.

#[tokio::test]
async fn a_redelivered_share_is_still_deduped_across_a_round_reset() {
    let conn = match connect_or_skip(16).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_dedup_reset";
    let addr = "bc1qfoo";

    // The satellite applies a share…
    assert!(store
        .record_share(Some("ep9:7"), group, addr, 100.0, 1_700_000_000_000)
        .await
        .expect("ok"));
    // …a block is found for the group and the round is wiped…
    store.reset_for_block_found(group).await.unwrap();
    // …and only now does the batch get redelivered (the ack never landed).
    let replay = store
        .record_share(Some("ep9:7"), group, addr, 100.0, 1_700_000_000_000)
        .await
        .expect("ok");
    assert!(
        !replay,
        "a share redelivered after a reset must STILL be a deduped no-op"
    );

    let mut conn = conn;
    let total_exists: bool = conn.exists(key_total(group)).await.unwrap();
    assert!(
        !total_exists,
        "the redelivery must not resurrect the wiped round's total"
    );
    let by_exists: bool = conn.exists(key_by_address(group)).await.unwrap();
    assert!(
        !by_exists,
        "nor its by-address aggregate — that is the double credit"
    );

    store.reset_full(group).await.unwrap();
    assert!(
        !store
            .record_share(Some("ep9:7"), group, addr, 100.0, 1_700_000_000_000)
            .await
            .expect("ok"),
        "a full reset must not re-open the redelivery either"
    );

    // A genuinely new share still lands, so this is dedup and not a freeze.
    assert!(store
        .record_share(Some("ep9:8"), group, addr, 42.0, 1_700_000_000_001)
        .await
        .expect("ok"));
    let by: f64 = conn
        .hget::<_, _, String>(key_by_address(group), addr)
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (by - 42.0).abs() < 1e-9,
        "only the new share counts, got {by}"
    );
}

// ── Test 13 — windowed record aggregates into time buckets ──────────
#[tokio::test]
async fn windowed_record_aggregates_into_buckets() {
    let conn = match connect_or_skip(12).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_win_record";
    let bkt = WINDOW_BUCKET_MS;
    // Two shares for foo in bucket 100, one for bar in bucket 102.
    store
        .record_share_windowed(None, group, "bc1qfoo", 30.0, 100 * bkt)
        .await
        .expect("ok");
    store
        .record_share_windowed(None, group, "bc1qfoo", 20.0, 100 * bkt + 5)
        .await
        .expect("ok");
    store
        .record_share_windowed(None, group, "bc1qbar", 70.0, 102 * bkt)
        .await
        .expect("ok");

    let agg = store.read_window_by_address(group).await.unwrap();
    assert!((agg["bc1qfoo"] - 50.0).abs() < 1e-9, "foo summed in-bucket");
    assert!((agg["bc1qbar"] - 70.0).abs() < 1e-9);

    // The member list reads `last-accepted-share-at`, so window mode stamps it too.
    let foo_last = store
        .read_last_accepted_share_at(group, "bc1qfoo")
        .await
        .unwrap();
    assert_eq!(
        foo_last,
        Some(100 * bkt + 5),
        "foo last-accepted is the later of its two shares"
    );
    let bar_last = store
        .read_last_accepted_share_at(group, "bc1qbar")
        .await
        .unwrap();
    assert_eq!(bar_last, Some(102 * bkt));

    let mut conn = conn;
    let buckets: Vec<i64> = conn.zrange(key_window_buckets(group), 0, -1).await.unwrap();
    assert_eq!(buckets, vec![100, 102], "FIFO-ordered bucket ids");

    let timeline = store
        .read_window_timeline(group, 102 * bkt, 30 * bkt)
        .await
        .unwrap();
    assert_eq!(timeline.len(), 2, "two live buckets");
    assert_eq!(timeline[0].0, 100);
    assert!((timeline[0].1["bc1qfoo"] - 50.0).abs() < 1e-9);
    assert_eq!(timeline[1].0, 102);
    assert!((timeline[1].1["bc1qbar"] - 70.0).abs() < 1e-9);
}

/// MONEY: a trim that drives an address below zero must remove the field;
/// a negative value would swallow the address's next shares.
#[tokio::test]
async fn windowed_trim_does_not_strand_a_negative_entry() {
    let conn = match connect_or_skip(21).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_win_underflow";
    let bkt = WINDOW_BUCKET_MS;
    store
        .record_share_windowed(None, group, "bc1qold", 40.0, 0)
        .await
        .unwrap();
    store
        .record_share_windowed(None, group, "bc1qfresh", 60.0, 5 * bkt)
        .await
        .unwrap();
    // Forge a restore skew: the aggregate holds less than the bucket.
    let mut conn = conn;
    let _: () = conn
        .hset(key_window_by_address(group), "bc1qold", "10")
        .await
        .unwrap();
    assert!(
        (store.read_window_by_address(group).await.unwrap()["bc1qold"] - 10.0).abs() < 1e-9,
        "precondition: the aggregate must be BEHIND the bucket's 40"
    );

    store.trim_window(group, 5 * bkt, 2 * bkt).await.unwrap();

    let raw: Option<String> = conn
        .hget(key_window_by_address(group), "bc1qold")
        .await
        .unwrap();
    assert!(
        raw.is_none(),
        "the underflowed entry must be removed, found {raw:?}"
    );
    store
        .record_share_windowed(None, group, "bc1qold", 20.0, 5 * bkt)
        .await
        .unwrap();
    let after = store.read_window_by_address(group).await.unwrap();
    assert!(
        (after["bc1qold"] - 20.0).abs() < 1e-9,
        "new work counts in full after the trim: {after:?}"
    );
    assert!(
        (after["bc1qfresh"] - 60.0).abs() < 1e-9,
        "the trim took no one else down: {after:?}"
    );
}

#[tokio::test]
async fn windowed_trim_drops_aged_buckets() {
    let conn = match connect_or_skip(13).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_win_trim";
    let bkt = WINDOW_BUCKET_MS;
    // Old share in bucket 0, fresh share in bucket 5.
    store
        .record_share_windowed(None, group, "bc1qold", 40.0, 0)
        .await
        .unwrap();
    store
        .record_share_windowed(None, group, "bc1qfresh", 60.0, 5 * bkt)
        .await
        .unwrap();
    assert_eq!(store.read_window_by_address(group).await.unwrap().len(), 2);

    // now = bucket 5, window = 2 buckets → drop bucket 0.
    store.trim_window(group, 5 * bkt, 2 * bkt).await.unwrap();

    let after = store.read_window_by_address(group).await.unwrap();
    assert!(!after.contains_key("bc1qold"), "aged-out addr dropped");
    assert!((after["bc1qfresh"] - 60.0).abs() < 1e-9, "fresh addr kept");

    let mut conn = conn;
    let buckets: Vec<i64> = conn.zrange(key_window_buckets(group), 0, -1).await.unwrap();
    assert_eq!(buckets, vec![5]);
    let old_exists: bool = conn.exists("groupsolo:g_win_trim:wbucket:0").await.unwrap();
    assert!(!old_exists, "dropped bucket hash deleted");
}

// ── Test 15 — read_payout_shares(Window) trims on read (idle group) ─
#[tokio::test]
async fn read_payout_shares_window_trims_on_read() {
    let conn = match connect_or_skip(14).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_win_read";
    let bkt = WINDOW_BUCKET_MS;
    // Window shares: stale bucket 0 + fresh bucket 10.
    store
        .record_share_windowed(None, group, "bc1qstale", 10.0, 0)
        .await
        .unwrap();
    store
        .record_share_windowed(None, group, "bc1qfresh", 20.0, 10 * bkt)
        .await
        .unwrap();
    // A PROP-keyspace share for the SAME group, to prove the branch separates them.
    store
        .record_share(None, group, "bc1qprop", 99.0, 1)
        .await
        .unwrap();

    let win = store
        .read_payout_shares(group, PayoutMode::Window, 10 * bkt, 2 * bkt)
        .await
        .unwrap();
    assert!(
        !win.contains_key("bc1qstale"),
        "idle-group stale share trimmed on read"
    );
    assert!((win["bc1qfresh"] - 20.0).abs() < 1e-9);
    assert!(
        !win.contains_key("bc1qprop"),
        "window read ignores PROP keyspace"
    );

    let prop = store
        .read_payout_shares(group, PayoutMode::Prop, 10 * bkt, 2 * bkt)
        .await
        .unwrap();
    assert!((prop["bc1qprop"] - 99.0).abs() < 1e-9);
    assert!(
        !prop.contains_key("bc1qfresh"),
        "PROP read ignores window keyspace"
    );
}

// ── Test 16 — windowed record is idempotent per share_id ────────────
#[tokio::test]
async fn windowed_record_is_idempotent_per_share_id() {
    let conn = match connect_or_skip(15).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_win_idem";
    let bkt = WINDOW_BUCKET_MS;

    let applied = store
        .record_share_windowed(Some("ep1:0"), group, "bc1qfoo", 100.0, 7 * bkt)
        .await
        .expect("ok");
    assert!(applied, "first windowed apply must append");

    let replay = store
        .record_share_windowed(Some("ep1:0"), group, "bc1qfoo", 100.0, 7 * bkt)
        .await
        .expect("ok");
    assert!(
        !replay,
        "redelivered windowed share_id must be a deduped no-op"
    );

    let agg = store.read_window_by_address(group).await.unwrap();
    assert!(
        (agg["bc1qfoo"] - 100.0).abs() < 1e-9,
        "window aggregate counts the share once, not twice"
    );

    store.reset_full(group).await.unwrap();
    assert!(
        store
            .read_window_by_address(group)
            .await
            .unwrap()
            .is_empty(),
        "reset_full clears the window aggregate"
    );
    let mut conn = conn;
    let buckets: Vec<i64> = conn.zrange(key_window_buckets(group), 0, -1).await.unwrap();
    assert!(buckets.is_empty(), "reset_full drops the window index zset");
}

// ── Test 18 — a windowed reject lands in its bucket, not in the tally ─
// The PROP tally never shrinks, so against a windowed denominator it would
// not be a rate of anything.
#[tokio::test]
async fn windowed_reject_lands_in_its_bucket_and_window_aggregate() {
    let conn = match connect_or_skip(17).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_wrej_record";
    let bkt = WINDOW_BUCKET_MS;
    store
        .record_reject_windowed(group, "bc1qfoo", 3.0, 100 * bkt)
        .await
        .expect("ok");
    store
        .record_reject_windowed(group, "bc1qfoo", 2.0, 100 * bkt + 5)
        .await
        .expect("ok");
    store
        .record_reject_windowed(group, "bc1qbar", 7.0, 102 * bkt)
        .await
        .expect("ok");

    let agg = store.read_window_rejected(group).await.unwrap();
    assert!((agg["bc1qfoo"] - 5.0).abs() < 1e-9, "foo summed in-bucket");
    assert!((agg["bc1qbar"] - 7.0).abs() < 1e-9);

    let mut conn = conn;
    let buckets: Vec<i64> = conn
        .zrange(WindowLane::Rejected.index_key(group), 0, -1)
        .await
        .unwrap();
    assert_eq!(buckets, vec![100, 102], "FIFO-ordered reject bucket ids");
    let in_bucket: Option<String> = conn
        .hget(WindowLane::Rejected.bucket_key(group, 100), "bc1qfoo")
        .await
        .unwrap();
    assert_eq!(
        in_bucket.as_deref().and_then(|v| v.parse::<f64>().ok()),
        Some(5.0)
    );

    // Negative control: neither the PROP tally nor the accepted lane saw it.
    assert!(store.read_rejected(group).await.unwrap().is_empty());
    assert!(store
        .read_window_by_address(group)
        .await
        .unwrap()
        .is_empty());
}

// ── Test 19 — one trim sheds both lanes; reset drops both lanes ────
#[tokio::test]
async fn windowed_trim_and_reset_cover_the_reject_lane() {
    let conn = match connect_or_skip(18).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_wrej_trim";
    let bkt = WINDOW_BUCKET_MS;
    // Both lanes: an old bucket 0 and a fresh bucket 5.
    store
        .record_share_windowed(None, group, "bc1qold", 40.0, 0)
        .await
        .unwrap();
    store
        .record_share_windowed(None, group, "bc1qfresh", 60.0, 5 * bkt)
        .await
        .unwrap();
    store
        .record_reject_windowed(group, "bc1qold", 4.0, 0)
        .await
        .unwrap();
    store
        .record_reject_windowed(group, "bc1qfresh", 6.0, 5 * bkt)
        .await
        .unwrap();
    assert_eq!(store.read_window_rejected(group).await.unwrap().len(), 2);

    // now = bucket 5, window = 2 buckets → drop bucket 0 in BOTH lanes.
    store.trim_window(group, 5 * bkt, 2 * bkt).await.unwrap();

    let rejected = store.read_window_rejected(group).await.unwrap();
    assert!(!rejected.contains_key("bc1qold"), "aged-out reject dropped");
    assert!(
        (rejected["bc1qfresh"] - 6.0).abs() < 1e-9,
        "fresh reject kept"
    );
    let accepted = store.read_window_by_address(group).await.unwrap();
    assert!(!accepted.contains_key("bc1qold"));
    assert!((accepted["bc1qfresh"] - 60.0).abs() < 1e-9);

    let mut conn = conn;
    let buckets: Vec<i64> = conn
        .zrange(WindowLane::Rejected.index_key(group), 0, -1)
        .await
        .unwrap();
    assert_eq!(buckets, vec![5]);
    let old_exists: bool = conn
        .exists(WindowLane::Rejected.bucket_key(group, 0))
        .await
        .unwrap();
    assert!(!old_exists, "dropped reject bucket hash deleted");

    // A full reset leaves no reject-lane key behind either.
    store.reset_full(group).await.unwrap();
    for key in [
        WindowLane::Rejected.index_key(group),
        WindowLane::Rejected.aggregate_key(group),
        WindowLane::Rejected.bucket_key(group, 5),
        WindowLane::Accepted.aggregate_key(group),
    ] {
        let exists: bool = conn.exists(&key).await.unwrap();
        assert!(!exists, "{key} survived reset_full");
    }
}

// ── Test 20 — round stats: Window reads the windowed rejects, PROP the tally ─
// Tally 999, lane 5 fresh + 4 aged: Window must answer 5 and PROP 999.
#[tokio::test]
async fn round_stats_window_reads_the_reject_lane_not_the_running_tally() {
    let conn = match connect_or_skip(19).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_wrej_stats";
    let bkt = WINDOW_BUCKET_MS;
    store
        .record_share_windowed(None, group, "bc1qa", 20.0, 10 * bkt)
        .await
        .unwrap();
    store.record_reject(group, "bc1qa", 999.0).await.unwrap();
    store
        .record_reject_windowed(group, "bc1qa", 4.0, 0)
        .await
        .unwrap();
    store
        .record_reject_windowed(group, "bc1qa", 5.0, 10 * bkt)
        .await
        .unwrap();

    let win = store
        .read_round_stats_for(group, PayoutMode::Window, 10 * bkt, 2 * bkt)
        .await
        .unwrap();
    assert!((win.total_shares - 20.0).abs() < 1e-9);
    assert!(
        (win.total_rejected - 5.0).abs() < 1e-9,
        "window: fresh reject only, tally and aged bucket ignored (got {})",
        win.total_rejected
    );
    assert!((win.rejected_per_address["bc1qa"] - 5.0).abs() < 1e-9);

    let prop = store
        .read_round_stats_for(group, PayoutMode::Prop, 10 * bkt, 2 * bkt)
        .await
        .unwrap();
    assert!(
        (prop.total_rejected - 999.0).abs() < 1e-9,
        "prop: the running tally, lane ignored (got {})",
        prop.total_rejected
    );
}

// ── Test 21 — forget_member is mode-aware: a kick leaves the window too ─
// PROP forget leaves the window lanes alone; Window forget clears every
// bucket of both lanes, since `window:by-address` is the coinbase source.
#[tokio::test]
async fn forget_member_window_removes_the_address_from_both_lanes() {
    let conn = match connect_or_skip(20).await {
        Some(c) => c,
        None => return,
    };
    let store = GroupRoundStore::new(conn.clone());
    let group = "g_forget_win";
    let bkt = WINDOW_BUCKET_MS;
    // Window: bc1qa in buckets 3 and 5, bc1qb in bucket 5; rejects for bc1qa.
    store
        .record_share_windowed(None, group, "bc1qa", 30.0, 3 * bkt)
        .await
        .unwrap();
    store
        .record_share_windowed(None, group, "bc1qa", 20.0, 5 * bkt)
        .await
        .unwrap();
    store
        .record_share_windowed(None, group, "bc1qb", 40.0, 5 * bkt)
        .await
        .unwrap();
    store
        .record_reject_windowed(group, "bc1qa", 7.0, 5 * bkt)
        .await
        .unwrap();
    // And a PROP-keyspace share for bc1qa in the same group.
    store
        .record_share(None, group, "bc1qa", 99.0, 1)
        .await
        .unwrap();

    // Direction 1: a PROP forget leaves the window lanes alone.
    let removed_prop = store
        .forget_member(group, "bc1qa", PayoutMode::Prop)
        .await
        .unwrap();
    assert!((removed_prop - 99.0).abs() < 1e-9);
    assert!(store.read_by_address(group).await.unwrap().is_empty());
    let win = store.read_window_by_address(group).await.unwrap();
    assert!(
        (win["bc1qa"] - 50.0).abs() < 1e-9,
        "PROP forget must not touch the window lane"
    );

    // Direction 2: a Window forget removes bc1qa from buckets + aggregates.
    let removed_win = store
        .forget_member(group, "bc1qa", PayoutMode::Window)
        .await
        .unwrap();
    assert!(
        (removed_win - 50.0).abs() < 1e-9,
        "window contribution returned"
    );

    let payout = store
        .read_payout_shares(group, PayoutMode::Window, 5 * bkt, 24 * bkt)
        .await
        .unwrap();
    assert!(
        !payout.contains_key("bc1qa"),
        "kicked member left the payout source"
    );
    assert!(
        (payout["bc1qb"] - 40.0).abs() < 1e-9,
        "the rest is unchanged"
    );
    assert!(
        !store
            .read_window_rejected(group)
            .await
            .unwrap()
            .contains_key("bc1qa"),
        "reject lane forgets the member too"
    );

    let mut conn = conn;
    for lane in [WindowLane::Accepted, WindowLane::Rejected] {
        for bid in [3, 5] {
            let present: bool = conn
                .hexists(lane.bucket_key(group, bid), "bc1qa")
                .await
                .unwrap();
            assert!(!present, "{lane:?} bucket {bid} still holds bc1qa");
        }
    }
    let last_at_has_a: bool = conn
        .hexists(key_last_accepted_share_at(group), "bc1qa")
        .await
        .unwrap();
    assert!(!last_at_has_a, "inactivity clock slot deleted");
    // The other member's bucket entries survive.
    let b_in_5: bool = conn
        .hexists(WindowLane::Accepted.bucket_key(group, 5), "bc1qb")
        .await
        .unwrap();
    assert!(b_in_5);
}
