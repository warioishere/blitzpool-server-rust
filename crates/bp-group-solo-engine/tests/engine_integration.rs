// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! End-to-end integration tests for `GroupSoloEngine` against
//! docker-Redis + docker-PG.

use bp_common::AddressId;
use bp_group_solo_engine::config::GroupSoloEngineConfig;
use bp_group_solo_engine::engine::{EngineError, GroupSoloEngine};
use redis::{aio::ConnectionManager, Client};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

const REDIS_URL: &str = "redis://127.0.0.1:16379";
const PG_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

struct Harness {
    engine: GroupSoloEngine,
    pool: PgPool,
    group_id: Uuid,
}

async fn spawn_or_skip(redis_db: u8, finder_bonus_sats: Option<i64>) -> Option<Harness> {
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
            eprintln!("PG connect failed: {e} — skipping");
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
            eprintln!("Redis client failed: {e} — skipping");
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
            eprintln!("Redis connect failed: {e} — skipping");
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

    let group_id = Uuid::new_v4();
    seed_group(&pool, group_id, finder_bonus_sats).await;

    // dust_sweep + per-group reset crons run in background — we
    // disable dust_sweep to avoid interference; per-group reset
    // crons load none (no preset on seeded group).
    let config = GroupSoloEngineConfig {
        dust_sweep_enabled: false,
        ..GroupSoloEngineConfig::default()
    };
    let engine = match GroupSoloEngine::spawn(config, conn, pool.clone()).await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("engine spawn failed: {e} — skipping");
            return None;
        }
    };

    Some(Harness {
        engine,
        pool,
        group_id,
    })
}

async fn seed_group(pool: &PgPool, group_id: Uuid, finder_bonus_sats: Option<i64>) {
    // Seed with resetRoundOnBlock = true so the existing tests that assert the
    // round wipes after a block keep exercising that path. The default-false
    // (no-reset) behavior has its own dedicated test.
    sqlx::query(
        r#"INSERT INTO pplns_group
             (id, name, "creatorAddress", "adminTokenHash", active,
              "createdAt", "updatedAt", "isPublic", "finderBonusSats", "resetRoundOnBlock")
           VALUES ($1, $2, 'test_eng_creator', $3, true, 0, 0, false, $4, true)"#,
    )
    .bind(group_id)
    .bind(format!("test-group-{group_id}"))
    .bind(format!("hash-{group_id}"))
    .bind(finder_bonus_sats)
    .execute(pool)
    .await
    .expect("seed group");
}

async fn cleanup_group(pool: &PgPool, group_id: Uuid) {
    let _ = sqlx::query(r#"DELETE FROM pplns_group_block_history WHERE "groupId" = $1"#)
        .bind(group_id)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM pplns_group_balance WHERE "groupId" = $1"#)
        .bind(group_id)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM pplns_group WHERE id = $1"#)
        .bind(group_id)
        .execute(pool)
        .await;
}

async fn drop_harness(h: Harness) {
    h.engine.shutdown();
    cleanup_group(&h.pool, h.group_id).await;
}

// ── Test 1 — record_share appears in reader.round_stats ─────────────

#[tokio::test]
async fn record_share_then_round_stats_sees_it() {
    let h = match spawn_or_skip(0, None).await {
        Some(h) => h,
        None => return,
    };
    h.engine
        .record_share(None, h.group_id, "test_eng_a", 75.0, 1_700_000_000_001)
        .await
        .expect("ok");

    let stats = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert!((stats.total_shares - 75.0).abs() < 1e-9);
    assert!((stats.per_address["test_eng_a"] - 75.0).abs() < 1e-9);

    drop_harness(h).await;
}

// ── Test 2 — build_distribution returns payouts ────────────────────

#[tokio::test]
async fn build_distribution_returns_payouts_after_shares() {
    let h = match spawn_or_skip(1, None).await {
        Some(h) => h,
        None => return,
    };
    let a = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let b = AddressId::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
    h.engine
        .record_share(None, h.group_id, a.as_str(), 60.0, 1_700_000_000_001)
        .await
        .unwrap();
    h.engine
        .record_share(None, h.group_id, b.as_str(), 40.0, 1_700_000_000_002)
        .await
        .unwrap();

    let result = h
        .engine
        .build_distribution(h.group_id, 312_500_000, &a)
        .await
        .expect("ok");
    assert_eq!(result.block_reward_sats, 312_500_000);
    assert!(!result.payouts.is_empty());
    assert!(result.considered_addresses.contains(&a));
    assert!(result.considered_addresses.contains(&b));

    drop_harness(h).await;
}

// ── Test 3 — on_block_found applies + resets round ─────────────────

#[tokio::test]
async fn on_block_found_applies_distribution_and_resets_round() {
    let h = match spawn_or_skip(2, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1_700_000_000_001)
        .await
        .unwrap();
    let _result = h
        .engine
        .build_distribution(h.group_id, 312_500_000, &finder)
        .await
        .expect("ok");

    let block_height = 9_995_001;
    let outcome = h
        .engine
        .on_block_found(h.group_id, block_height, 312_500_000, &finder)
        .await
        .expect("ok");
    assert!(outcome.history_inserted >= 1);

    // History row in PG.
    let count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = $2"#,
    )
    .bind(h.group_id)
    .bind(block_height)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert!(count.0 >= 1);

    // Round reset (block-found variant) — by-address empty.
    let stats = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert_eq!(stats.total_shares, 0.0, "round wiped on block-found");
    assert!(stats.per_address.is_empty());

    drop_harness(h).await;
}

// ── Test 3b — snapshot-carried apply survives a Redis snapshot overwrite ──
//
// The Core/Satellite split race: the per-(group, finder) Redis snapshot is
// overwritten by continuous template rebuilds before the async apply runs. The
// fix carries the exact snapshot in the block-found event and applies it via
// `on_block_found_with_snapshot`, never re-reading Redis. This test freezes a
// snapshot, then simulates the churn (a later `build_distribution` with a
// DIFFERENT reward overwrites the Redis key) — the old `on_block_found` would
// hit `SnapshotRewardMismatch`, but the snapshot-carried apply still succeeds
// against the frozen distribution.
#[tokio::test]
async fn on_block_found_with_snapshot_survives_redis_overwrite() {
    let h = match spawn_or_skip(11, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let reward = 312_500_000;

    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1_700_000_000_001)
        .await
        .unwrap();

    // Core freezes the snapshot at the block-found instant.
    let frozen = h
        .engine
        .snapshot_for_block_found(h.group_id, reward, &finder)
        .await
        .expect("freeze snapshot ok");
    assert_eq!(frozen.block_reward_sats, reward);

    // Template churn: more shares + a DIFFERENT reward rebuild overwrites the
    // per-(group, finder) Redis snapshot key with a stale (for this block)
    // reward — exactly what breaks the old Redis-read apply in the split.
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 50.0, 1_700_000_000_002)
        .await
        .unwrap();
    h.engine
        .build_distribution(h.group_id, reward + 999_999, &finder)
        .await
        .expect("churn rebuild ok");

    // The snapshot-carried apply ignores Redis and applies the frozen one.
    let block_height = 9_995_010;
    let outcome = h
        .engine
        .on_block_found_with_snapshot(h.group_id, block_height, reward, &finder, frozen.into())
        .await
        .expect("snapshot-carried apply must succeed despite the Redis overwrite");
    assert!(outcome.history_inserted >= 1);

    // History row landed at the frozen reward, and the round reset.
    let count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = $2"#,
    )
    .bind(h.group_id)
    .bind(block_height)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert!(count.0 >= 1);

    let stats = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert_eq!(stats.total_shares, 0.0, "round wiped on block-found");

    drop_harness(h).await;
}

// ── Test 3c — resetRoundOnBlock=false leaves the round intact ──────
//
// The production default: a block-found does NOT wipe the round, so shares
// accumulate across blocks until a calendar preset / manual reset fires.
#[tokio::test]
async fn on_block_found_keeps_round_when_reset_flag_false() {
    let h = match spawn_or_skip(14, None).await {
        Some(h) => h,
        None => return,
    };
    // Flip to the production default (seed_group sets it true).
    sqlx::query(r#"UPDATE pplns_group SET "resetRoundOnBlock" = false WHERE id = $1"#)
        .bind(h.group_id)
        .execute(&h.pool)
        .await
        .expect("flag off");

    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1)
        .await
        .unwrap();
    h.engine
        .build_distribution(h.group_id, 312_500_000, &finder)
        .await
        .expect("ok");
    h.engine
        .on_block_found(h.group_id, 9_997_001, 312_500_000, &finder)
        .await
        .expect("ok");

    // Ledger still booked the block...
    let count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = $2"#,
    )
    .bind(h.group_id)
    .bind(9_997_001)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert!(count.0 >= 1, "block still booked");

    // ...but the round was NOT wiped — shares persist for the next block.
    let stats = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert_eq!(
        stats.total_shares, 100.0,
        "round must persist when resetRoundOnBlock=false"
    );

    drop_harness(h).await;
}

// ── Test 3d — duplicate block-found does not double-count the balance ──
//
// A replayed / duplicate block-found for the same height (stream redelivery or
// a stale candidate at the same height) must not inflate `totalPaidSats`. The
// history dedupes via its UNIQUE; the balance apply is gated on a non-zero
// history insert so the second apply is a no-op on the balance.
#[tokio::test]
async fn duplicate_block_found_does_not_double_balance() {
    let h = match spawn_or_skip(15, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let reward = 312_500_000;
    let height = 9_998_001;

    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1)
        .await
        .unwrap();
    let snap = h
        .engine
        .snapshot_for_block_found(h.group_id, reward, &finder)
        .await
        .expect("snapshot");

    // First apply.
    h.engine
        .on_block_found_with_snapshot(h.group_id, height, reward, &finder, snap.clone().into())
        .await
        .expect("apply 1");
    let after_first = h
        .engine
        .reader()
        .balance(h.group_id, finder.as_str())
        .await
        .expect("ok")
        .expect("row")
        .total_paid_sats;
    assert!(after_first > 0);

    // Replay the SAME block-found (duplicate event).
    h.engine
        .on_block_found_with_snapshot(h.group_id, height, reward, &finder, snap.into())
        .await
        .expect("apply 2 (replay) must not error");
    let after_replay = h
        .engine
        .reader()
        .balance(h.group_id, finder.as_str())
        .await
        .expect("ok")
        .expect("row")
        .total_paid_sats;

    assert_eq!(
        after_first, after_replay,
        "replayed block-found must not double-count totalPaidSats"
    );

    // Exactly one history row for the (group, height) survived.
    let count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = $2 AND address = $3"#,
    )
    .bind(h.group_id)
    .bind(height)
    .bind(finder.as_str())
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(count.0, 1, "history deduped the replay");

    drop_harness(h).await;
}

// ── Test 4 — re-entrancy guard per group ───────────────────────────

#[tokio::test]
async fn on_block_found_re_entrancy_guard_per_group() {
    let h = match spawn_or_skip(3, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1)
        .await
        .unwrap();
    h.engine
        .build_distribution(h.group_id, 312_500_000, &finder)
        .await
        .expect("ok");

    let engine1 = h.engine.clone();
    let engine2 = h.engine.clone();
    let gid = h.group_id;
    let finder1 = finder.clone();
    let finder2 = finder.clone();
    let task1 = tokio::spawn(async move {
        engine1
            .on_block_found(gid, 9_995_002, 312_500_000, &finder1)
            .await
    });
    let task2 = tokio::spawn(async move {
        engine2
            .on_block_found(gid, 9_995_002, 312_500_000, &finder2)
            .await
    });

    let (r1, r2) = tokio::join!(task1, task2);
    let r1 = r1.unwrap();
    let r2 = r2.unwrap();
    let succeeded = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    let in_flight = [&r1, &r2]
        .iter()
        .filter(|r| matches!(r, Err(EngineError::BlockFoundInProgress { .. })))
        .count();
    // Either: one succeeded + one in-flight, OR one succeeded + one
    // got SnapshotMissing (the first call deleted the snapshot
    // before the second's lock-check raced). Both are acceptable
    // outcomes of "only one succeeds per (group_id, block_height)".
    assert_eq!(succeeded, 1, "exactly one call succeeds");
    let other_handled = in_flight == 1
        || matches!(&r1, Err(EngineError::SnapshotMissing { .. }))
        || matches!(&r2, Err(EngineError::SnapshotMissing { .. }));
    assert!(
        other_handled,
        "second call is either re-entrancy-blocked or sees a cleared snapshot"
    );

    drop_harness(h).await;
}

// ── Test 5 — reader.balance reads PG row ───────────────────────────

#[tokio::test]
async fn reader_balance_returns_row_after_block_found() {
    let h = match spawn_or_skip(4, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1)
        .await
        .unwrap();
    h.engine
        .build_distribution(h.group_id, 312_500_000, &finder)
        .await
        .expect("ok");
    h.engine
        .on_block_found(h.group_id, 9_995_003, 312_500_000, &finder)
        .await
        .expect("ok");

    let bal = h
        .engine
        .reader()
        .balance(h.group_id, finder.as_str())
        .await
        .expect("ok")
        .expect("balance row exists");
    assert!(bal.total_paid_sats > 0, "finder received coinbase output");

    drop_harness(h).await;
}

// ── Test 5b — totalPaidSats accumulates across blocks ──────────────
//
// A member fully paid on-chain has `pendingSats = 0`. The block-found apply
// must still see their prior `totalPaidSats` to accumulate it — earlier it
// read balances filtered on `pendingSats > 0`, so a paid member was invisible
// and their lifetime total got overwritten with the latest block instead of
// summed. Two finder-only blocks must leave `totalPaidSats == 2x` one block.
#[tokio::test]
async fn total_paid_sats_accumulates_across_blocks() {
    let h = match spawn_or_skip(13, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let reward = 312_500_000;

    // Block 1.
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 1)
        .await
        .unwrap();
    h.engine
        .build_distribution(h.group_id, reward, &finder)
        .await
        .expect("ok");
    h.engine
        .on_block_found(h.group_id, 9_996_001, reward, &finder)
        .await
        .expect("block 1 ok");
    let after_one = h
        .engine
        .reader()
        .balance(h.group_id, finder.as_str())
        .await
        .expect("ok")
        .expect("balance row")
        .total_paid_sats;
    assert!(after_one > 0, "finder paid on block 1");

    // Block 2 — round was reset by block 1, so re-seed a share. The finder's
    // pending is now 0, so the pending-filtered read would have hidden them.
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 100.0, 2)
        .await
        .unwrap();
    h.engine
        .build_distribution(h.group_id, reward, &finder)
        .await
        .expect("ok");
    h.engine
        .on_block_found(h.group_id, 9_996_002, reward, &finder)
        .await
        .expect("block 2 ok");
    let after_two = h
        .engine
        .reader()
        .balance(h.group_id, finder.as_str())
        .await
        .expect("ok")
        .expect("balance row")
        .total_paid_sats;

    assert_eq!(
        after_two,
        after_one * 2,
        "totalPaidSats must accumulate (block1 + block2), not overwrite with the latest block"
    );

    drop_harness(h).await;
}

// ── Test 6 — manual_reset triggers full wipe ───────────────────────

#[tokio::test]
async fn manual_reset_wipes_group_state() {
    let h = match spawn_or_skip(5, None).await {
        Some(h) => h,
        None => return,
    };
    // Seed via PG so the balance row outlives the round (Variant-B
    // semantics: scheduled reset wipes balance rows too).
    sqlx::query(
        r#"INSERT INTO pplns_group_balance
             (address, "groupId", "pendingSats", "totalPaidSats", "updatedAt")
           VALUES ('test_eng_reset_a', $1, 5_000, 0, 0)"#,
    )
    .bind(h.group_id)
    .execute(&h.pool)
    .await
    .unwrap();
    h.engine
        .record_share(None, h.group_id, "test_eng_reset_a", 50.0, 1)
        .await
        .unwrap();

    let fired = h.engine.manual_reset(h.group_id).await.expect("ok");
    assert!(fired);

    // Round + balance both wiped.
    let stats = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert_eq!(stats.total_shares, 0.0);

    let bal_count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_group_balance WHERE "groupId" = $1"#)
            .bind(h.group_id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(bal_count.0, 0);

    drop_harness(h).await;
}

// ── Test 7 — record_reject is reflected in round_stats ─────────────

#[tokio::test]
async fn record_reject_updates_round_rejected_total() {
    let h = match spawn_or_skip(6, None).await {
        Some(h) => h,
        None => return,
    };
    h.engine
        .record_reject(h.group_id, "test_eng_rej", 3.0)
        .await
        .unwrap();
    h.engine
        .record_reject(h.group_id, "test_eng_rej", 2.0)
        .await
        .unwrap();

    let stats = h.engine.reader().round_stats(h.group_id).await.expect("ok");
    assert!((stats.total_rejected - 5.0).abs() < 1e-9);

    drop_harness(h).await;
}

// ── Test 9 — finder bonus + finder shares merge into one row ───────
//
// Regression guard. When a group has `finderBonusSats` set AND the
// finder also has shares this round, `build_coinbase_distribution`
// emits the finder address twice — a dedicated bonus output plus the
// finder's proportional share output (both valid on-chain TxOuts). The
// ledger write keys on `(address, groupId)`, so it must MERGE the two
// into a single upsert row; otherwise Postgres aborts the whole
// `apply_distribution` TX with "ON CONFLICT DO UPDATE command cannot
// affect row a second time", leaving the on-chain payout unrecorded in
// the pool's books. Pre-fix this test fails at `on_block_found`.
#[tokio::test]
async fn on_block_found_with_finder_bonus_merges_duplicate_outputs() {
    let bonus: i64 = 5_000_000;
    let h = match spawn_or_skip(8, Some(bonus)).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let other = AddressId::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
    // Finder + a second miner both contribute, so the finder earns a
    // proportional share ON TOP OF the bonus — the duplicate-emit case.
    h.engine
        .record_share(None, h.group_id, finder.as_str(), 70.0, 1_700_000_000_001)
        .await
        .unwrap();
    h.engine
        .record_share(None, h.group_id, other.as_str(), 30.0, 1_700_000_000_002)
        .await
        .unwrap();

    let reward = 312_500_000;
    let result = h
        .engine
        .build_distribution(h.group_id, reward, &finder)
        .await
        .expect("build_distribution ok");

    // Sanity: the raw distribution lists the finder more than once
    // (bonus + proportional) — the exact condition the merge guards.
    let finder_entries = result
        .payouts
        .iter()
        .filter(|p| p.address == finder)
        .count();
    assert!(
        finder_entries >= 2,
        "expected finder as bonus + proportional output, got {finder_entries}"
    );
    // The summed sats the ledger must credit the finder.
    let expected_finder_sats: i64 = result
        .payouts
        .iter()
        .filter(|p| p.address == finder)
        .map(|p| p.sats.0)
        .sum();

    let block_height = 9_995_008;
    let outcome = h
        .engine
        .on_block_found(h.group_id, block_height, reward, &finder)
        .await
        .expect("on_block_found must not abort on duplicate finder output");
    assert!(outcome.history_inserted >= 1);

    // Exactly one balance row for the finder, carrying the SUMMED sats.
    let bal = h
        .engine
        .reader()
        .balance(h.group_id, finder.as_str())
        .await
        .expect("ok")
        .expect("finder balance row exists");
    assert_eq!(
        bal.total_paid_sats, expected_finder_sats,
        "finder totalPaidSats must equal bonus + proportional share merged"
    );

    // Exactly one history coinbase row for the finder for this block.
    let finder_history_rows: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = $2 AND address = $3"#,
    )
    .bind(h.group_id)
    .bind(block_height)
    .bind(finder.as_str())
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(
        finder_history_rows.0, 1,
        "finder must have exactly one merged coinbase history row"
    );

    drop_harness(h).await;
}

// ── Test 8 — reader.best_difficulty after share ────────────────────

#[tokio::test]
async fn reader_best_difficulty_after_shares() {
    let h = match spawn_or_skip(7, None).await {
        Some(h) => h,
        None => return,
    };
    h.engine
        .record_share(None, h.group_id, "test_eng_best_a", 50.0, 1)
        .await
        .unwrap();
    h.engine
        .record_share(None, h.group_id, "test_eng_best_b", 200.0, 2)
        .await
        .unwrap();

    let best = h
        .engine
        .reader()
        .best_difficulty(h.group_id)
        .await
        .expect("ok")
        .expect("some");
    assert_eq!(best.address, "test_eng_best_b");
    assert!((best.difficulty - 200.0).abs() < 1e-9);

    drop_harness(h).await;
}

// ── Test — reschedule_group arms / re-arms / tears down the reset cron ──

/// Build a `PplnsGroupRow` carrying only the fields `reschedule_group` reads.
fn reset_row(
    id: Uuid,
    active: bool,
    dissolved_at: Option<i64>,
    preset: Option<&str>,
    interval_days: Option<i32>,
    timezone: Option<&str>,
) -> bp_db::PplnsGroupRow {
    bp_db::PplnsGroupRow {
        id,
        name: format!("reset-{id}"),
        creator_address: AddressId::new("test_eng_creator".to_string()).unwrap(),
        admin_token_hash: "hash".to_string(),
        active,
        created_at: 0,
        updated_at: 0,
        dissolved_at,
        round_reset_interval_days: interval_days,
        round_reset_hour_local: None,
        round_reset_timezone: timezone.map(str::to_string),
        last_round_reset_at: None,
        finder_bonus_sats: None,
        round_reset_preset: preset.map(str::to_string),
        is_public: false,
        reset_round_on_block: false,
        max_members: None,
        payout_mode: "prop".to_string(),
    }
}

#[tokio::test]
async fn reschedule_group_arms_and_tears_down_reset_cron() {
    let h = match spawn_or_skip(9, None).await {
        Some(h) => h,
        None => return,
    };
    let id = h.group_id;

    // Seeded group has no preset → startup arms nothing.
    assert_eq!(h.engine.reset_task_count(), 0);

    // A valid preset arms exactly one cron.
    h.engine
        .reschedule_group(&reset_row(id, true, None, Some("daily"), None, Some("UTC")));
    assert_eq!(h.engine.reset_task_count(), 1);

    // A second valid config re-arms in place (old task torn down, one remains).
    h.engine.reschedule_group(&reset_row(
        id,
        true,
        None,
        Some("custom"),
        Some(7),
        Some("UTC"),
    ));
    assert_eq!(h.engine.reset_task_count(), 1);

    // Clearing the preset leaves the group unscheduled.
    h.engine
        .reschedule_group(&reset_row(id, true, None, None, None, None));
    assert_eq!(h.engine.reset_task_count(), 0);

    // Re-arm, then dissolve → torn down again.
    h.engine
        .reschedule_group(&reset_row(id, true, None, Some("daily"), None, Some("UTC")));
    assert_eq!(h.engine.reset_task_count(), 1);
    h.engine.reschedule_group(&reset_row(
        id,
        true,
        Some(123),
        Some("daily"),
        None,
        Some("UTC"),
    ));
    assert_eq!(h.engine.reset_task_count(), 0);

    // Re-arm, then deactivate → torn down.
    h.engine
        .reschedule_group(&reset_row(id, true, None, Some("daily"), None, Some("UTC")));
    assert_eq!(h.engine.reset_task_count(), 1);
    h.engine.reschedule_group(&reset_row(
        id,
        false,
        None,
        Some("daily"),
        None,
        Some("UTC"),
    ));
    assert_eq!(h.engine.reset_task_count(), 0);

    drop_harness(h).await;
}

// ── Core-mode spawn — no startup reset crons, read path intact ─────
//
// Contract B slice 1: `spawn_core` wires the same round-store +
// distribution builder but skips the dust-sweep + per-group reset
// crons (both mutate the ledger / round, which is the Satellite's
// job). Proven as a differential: a group seeded with a valid `daily`
// reset preset makes the *full* engine arm one reset cron at startup,
// while the *core* engine arms none. `build_distribution` (the Core's
// actual job) still works on the core engine.
#[tokio::test]
async fn spawn_core_skips_startup_reset_crons() {
    let pool = match connect_pg_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let full_conn = match connect_redis_or_skip(10).await {
        Some(c) => c,
        None => return,
    };
    let core_conn = match connect_redis_or_skip(11).await {
        Some(c) => c,
        None => return,
    };

    let group_id = Uuid::new_v4();
    cleanup_group(&pool, group_id).await;
    seed_group_with_daily_reset(&pool, group_id).await;

    let config = || GroupSoloEngineConfig {
        dust_sweep_enabled: false,
        ..GroupSoloEngineConfig::default()
    };

    // Full engine: startup arms the seeded group's reset cron.
    let full = GroupSoloEngine::spawn(config(), full_conn, pool.clone())
        .await
        .expect("full spawn");
    assert!(
        full.reset_task_count() >= 1,
        "full engine arms the seeded group's daily reset cron at startup"
    );

    // Core engine: same group, startup arms nothing.
    let core = GroupSoloEngine::spawn_core(config(), core_conn, pool.clone())
        .await
        .expect("core spawn");
    assert_eq!(
        core.reset_task_count(),
        0,
        "core mode ran no startup reset crons"
    );

    // The Core's read path still produces a distribution.
    let addr = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    core.record_share(None, group_id, addr.as_str(), 100.0, 1_700_000_000_000)
        .await
        .expect("record_share ok");
    let result = core
        .build_distribution(group_id, 312_500_000, &addr)
        .await
        .expect("build_distribution ok");
    assert_eq!(result.block_reward_sats, 312_500_000);
    assert!(!result.payouts.is_empty());
    assert!(result.considered_addresses.contains(&addr));

    full.shutdown();
    core.shutdown();
    cleanup_group(&pool, group_id).await;
}

async fn connect_pg_or_skip() -> Option<PgPool> {
    let pg_url = std::env::var("BP_PG_URL").unwrap_or_else(|_| PG_URL.to_string());
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&pg_url),
    )
    .await
    {
        Ok(Ok(p)) => Some(p),
        _ => {
            eprintln!("PG connect failed/timed out — skipping");
            None
        }
    }
}

/// Connect a flushed Redis logical DB, or `None` to skip.
async fn connect_redis_or_skip(redis_db: u8) -> Option<ConnectionManager> {
    let redis_base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_URL.to_string());
    let client = Client::open(format!("{redis_base}/{redis_db}")).ok()?;
    let mut conn = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        ConnectionManager::new(client),
    )
    .await
    {
        Ok(Ok(c)) => c,
        _ => {
            eprintln!("redis connect failed/timed out — skipping");
            return None;
        }
    };
    if redis::cmd("FLUSHDB")
        .query_async::<()>(&mut conn)
        .await
        .is_err()
    {
        eprintln!("FLUSHDB failed — skipping");
        return None;
    }
    Some(conn)
}

async fn seed_group_with_daily_reset(pool: &PgPool, group_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO pplns_group
             (id, name, "creatorAddress", "adminTokenHash", active,
              "createdAt", "updatedAt", "isPublic", "finderBonusSats",
              "roundResetPreset", "roundResetTimezone")
           VALUES ($1, $2, 'test_core_creator', $3, true, 0, 0, false, NULL,
                   'daily', 'UTC')"#,
    )
    .bind(group_id)
    .bind(format!("test-core-group-{group_id}"))
    .bind(format!("hash-core-{group_id}"))
    .execute(pool)
    .await
    .expect("seed group with daily reset");
}

// ── Window mode — engine record path trims aged-out buckets ─────────
//
// Drives the real `GroupSoloEngine::record_share` entry point for a
// window-mode group: a 30h-old share and a fresh share, with a 1-day window.
// The watermark guard lets the fresh share's bucket-boundary crossing fire the
// trim, and the mode-aware round-stats read (which trims with real wall-clock)
// confirms the old share has aged out while the fresh one remains. Uses
// now-relative timestamps so the record-path and read-path trims agree.
#[tokio::test]
async fn window_mode_record_path_trims_aged_buckets() {
    let h = match spawn_or_skip(12, None).await {
        Some(h) => h,
        None => return,
    };
    // Flip the seeded group to window mode. The mode is immutable in prod (no
    // edit path), but the engine resolves it fresh on the first record, so this
    // test-only UPDATE before any share takes effect. No preset → 1-day window.
    sqlx::query(r#"UPDATE pplns_group SET "payoutMode" = 'window' WHERE id = $1"#)
        .bind(h.group_id)
        .execute(&h.pool)
        .await
        .expect("set window mode");

    let bkt = 3_600_000_i64; // 1h, matches WINDOW_BUCKET_MS
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let t_old = now - 30 * bkt; // 30h ago → outside the 24h window
    let t_new = now;

    h.engine
        .record_share(None, h.group_id, "bc1qold", 40.0, t_old)
        .await
        .expect("record old share");
    h.engine
        .record_share(None, h.group_id, "bc1qnew", 60.0, t_new)
        .await
        .expect("record fresh share");

    // round_stats is window-aware + trims with real wall-clock now.
    let stats = h
        .engine
        .reader()
        .round_stats(h.group_id)
        .await
        .expect("round stats");
    assert!(
        !stats.per_address.contains_key("bc1qold"),
        "30h-old share aged out of the 1-day window"
    );
    assert!(
        (stats.per_address.get("bc1qnew").copied().unwrap_or(0.0) - 60.0).abs() < 1e-9,
        "fresh share retained in the window"
    );

    drop_harness(h).await;
}
