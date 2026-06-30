// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `bp-group-solo-engine::round` (state + snapshot)
//! against docker-Redis.
//!
//! Each test uses a distinct Redis logical DB (0–15); tests skip
//! cleanly via `eprintln!` if the URL is unreachable. Group-ids are
//! kept unique per test so within-DB tests don't interfere either.

use bp_common::{AddressId, Sats};
use bp_group_mgmt::group::PayoutMode;
use bp_group_solo_engine::round::{
    key_applied, key_best_share, key_by_address, key_counter, key_last_accepted_share_at,
    key_rejected_shares, key_total, key_window_buckets, snapshot, GroupRoundStore,
    WINDOW_BUCKET_MS,
};
use bp_pplns::CoinbaseDistributionEntry;
use redis::{aio::ConnectionManager, AsyncCommands, Client};

const DEFAULT_URL: &str = "redis://127.0.0.1:16379";

async fn connect_or_skip(test_db: u8) -> Option<ConnectionManager> {
    let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
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
    // No per-share zset — round state is the per-address aggregate.
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
    let counter_v: u64 = conn
        .get::<_, String>(key_counter(group))
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(counter_v, 1);
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

    // record_share maintains the by-address aggregate directly (no per-share
    // zset). Two shares for foo, one for bar.
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

    // Use a share_id so the dedup zset (`key_applied`) gets populated — the
    // reset must wipe it too, else stale markers break exactly-once next round.
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
    assert!(!counter_exists, "counter wiped");
    assert!(!best_exists, "best-share wiped");
    assert!(!applied_exists, "dedup zset wiped with the round");
    assert!(
        last_at_exists,
        "last-accepted-share-at preserved across block-found reset"
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
    assert!(!applied_exists, "dedup zset wiped on full reset");
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

    let removed = store.forget_member(group, "bc1qa").await.unwrap();
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

    let stats = store.read_round_stats(group).await.unwrap();
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
    let snap = snapshot::StoredSnapshot {
        distribution: vec![CoinbaseDistributionEntry {
            address: AddressId::new("bc1qminer").unwrap(),
            percent: 100.0,
            sats: Sats(312_500_000),
        }],
        block_reward_sats: 312_500_000,
        considered_addresses: vec!["bc1qminer".to_string()],
        balance_after: vec![("bc1qminer".to_string(), 0)],
    };

    snapshot::write_snapshot(&mut conn, group, finder, &snap, 60)
        .await
        .expect("write ok");
    let parsed = snapshot::read_snapshot(&mut conn, group, finder)
        .await
        .expect("read ok")
        .expect("present");
    assert_eq!(parsed.block_reward_sats, 312_500_000);
    assert_eq!(parsed.distribution.len(), 1);

    snapshot::delete_snapshot(&mut conn, group, finder)
        .await
        .expect("delete ok");
    assert!(snapshot::read_snapshot(&mut conn, group, finder)
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
    let snap = snapshot::StoredSnapshot {
        distribution: vec![],
        block_reward_sats: 100,
        considered_addresses: vec![],
        balance_after: vec![],
    };
    // Write snapshots for 3 different finders.
    for finder in &["bc1qf1", "bc1qf2", "bc1qf3"] {
        snapshot::write_snapshot(&mut conn, group, finder, &snap, 60)
            .await
            .unwrap();
    }
    // Plus one snapshot for an UNRELATED group — must survive.
    snapshot::write_snapshot(&mut conn, "g_other", "bc1qf1", &snap, 60)
        .await
        .unwrap();

    let deleted = snapshot::delete_all_for_group(&mut conn, group)
        .await
        .expect("scan+del ok");
    assert_eq!(deleted, 3);

    // Confirm: target group's snapshots gone, other group's survives.
    for finder in &["bc1qf1", "bc1qf2", "bc1qf3"] {
        assert!(snapshot::read_snapshot(&mut conn, group, finder)
            .await
            .unwrap()
            .is_none());
    }
    assert!(snapshot::read_snapshot(&mut conn, "g_other", "bc1qf1")
        .await
        .unwrap()
        .is_some());
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
//
// Group-Solo's half of the exactly-once foundation: a redelivered share
// (same share_id) is a no-op against the round, while distinct ids
// accumulate normally. Exercises RECORD_SHARE_LUA's dedup path.
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

    // The round counted exactly two shares (200), not three — the dedup
    // marker zset keeps the redelivery out of the aggregate.
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
}

// ── Test 13 — windowed record aggregates into time buckets ──────────
//
// `record_share_windowed` aggregates per (time-bucket, address) and keeps the
// `window:by-address` aggregate + the `wbuckets` index lock-step. Two shares
// for the same address in the same hour bucket sum; a share in a later bucket
// registers a second bucket id.
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

    // The windowed record also stamps the live `last-accepted-share-at` hash on
    // every accepted share (the source the member-list view reads, Redis-first,
    // so active miners aren't shown "never mined" before the group's first
    // block-found). It holds each address's MOST RECENT share timestamp.
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

    // Two distinct time buckets registered in the index zset.
    let mut conn = conn;
    let buckets: Vec<i64> = conn.zrange(key_window_buckets(group), 0, -1).await.unwrap();
    assert_eq!(buckets, vec![100, 102], "FIFO-ordered bucket ids");
}

// ── Test 14 — trim_window drops aged-out buckets ────────────────────
//
// Buckets older than `window_ms` relative to `now_ms` are dropped, and the
// `window:by-address` aggregate is decremented by exactly the dropped bucket's
// per-address contribution (hDel-ing addresses that hit zero).
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

    // now = bucket 5, window = 2 buckets → cutoff bucket 3 → drop bucket 0.
    store.trim_window(group, 5 * bkt, 2 * bkt).await.unwrap();

    let after = store.read_window_by_address(group).await.unwrap();
    assert!(!after.contains_key("bc1qold"), "aged-out addr dropped");
    assert!((after["bc1qfresh"] - 60.0).abs() < 1e-9, "fresh addr kept");

    // The old bucket's hash + index entry are gone; only bucket 5 remains.
    let mut conn = conn;
    let buckets: Vec<i64> = conn.zrange(key_window_buckets(group), 0, -1).await.unwrap();
    assert_eq!(buckets, vec![5]);
    let old_exists: bool = conn.exists("groupsolo:g_win_trim:wbucket:0").await.unwrap();
    assert!(!old_exists, "dropped bucket hash deleted");
}

// ── Test 15 — read_payout_shares(Window) trims on read (idle group) ─
//
// The dispatcher trims before reading, so even a group that went idle after
// recording sees a fenster-current distribution at payout-build time. PROP
// mode reads the independent per-round aggregate — the branch picks the right
// keyspace.
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

    // Window read at now=bucket 10, window=2 buckets → stale bucket 0 trimmed.
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

    // PROP read of the same group returns only the PROP aggregate.
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
//
// Same exactly-once contract as the PROP path: a redelivered windowed share
// (same share_id) is a no-op against the window aggregate.
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

    // reset_full (the dissolve / scheduled-wipe path) clears the dynamic
    // window keyspace too via delete_window_keys.
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
