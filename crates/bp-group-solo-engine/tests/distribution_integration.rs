// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! End-to-end integration tests for
//! `bp-group-solo-engine::distribution::DistributionBuilder` against
//! docker-Redis + docker-PG.
//!
//! Each test uses a fresh group (UUID-generated) and a distinct
//! Redis logical DB (0–15) to avoid cross-test interference.

use std::sync::Arc;

use bp_common::AddressId;
use bp_group_solo_engine::config::GroupSoloEngineConfig;
use bp_group_solo_engine::distribution::{
    DistributionBuilder, DistributionConfig, DistributionError,
};
use bp_group_solo_engine::round::GroupRoundStore;
use redis::{aio::ConnectionManager, Client};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

const REDIS_URL: &str = "redis://127.0.0.1:16379";
const PG_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

struct Harness {
    pool: PgPool,
    builder: DistributionBuilder,
    round: GroupRoundStore,
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

    let round = GroupRoundStore::new(conn);
    let dist_cfg = DistributionConfig::from_engine_config(&GroupSoloEngineConfig::default());
    let builder = DistributionBuilder::new(pool.clone(), round.clone(), dist_cfg);

    Some(Harness {
        pool,
        builder,
        round,
        group_id,
    })
}

async fn seed_group(pool: &PgPool, group_id: Uuid, finder_bonus_sats: Option<i64>) {
    sqlx::query(
        r#"INSERT INTO pplns_group
             (id, name, "creatorAddress", "adminTokenHash", active,
              "createdAt", "updatedAt", "isPublic", "finderBonusSats")
           VALUES ($1, $2, 'test_dist_creator', $3, true, 0, 0, false, $4)"#,
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

// ── Test 1 — end-to-end build returns payouts + writes snapshot ────

#[tokio::test]
async fn build_with_shares_returns_payouts_and_writes_snapshot() {
    let h = match spawn_or_skip(0, None).await {
        Some(h) => h,
        None => return,
    };
    let addr_a = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let addr_b = AddressId::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();

    h.round
        .record_share(None, &h.group_id.to_string(), addr_a.as_str(), 60.0, 1)
        .await
        .unwrap();
    h.round
        .record_share(None, &h.group_id.to_string(), addr_b.as_str(), 40.0, 2)
        .await
        .unwrap();

    let result = h
        .builder
        .build(h.group_id, 312_500_000, &addr_a)
        .await
        .expect("ok");
    assert_eq!(result.block_reward_sats, 312_500_000);
    assert_eq!(result.finder_address, addr_a);
    assert!(!result.payouts.is_empty());
    assert!(result.considered_addresses.contains(&addr_a));
    assert!(result.considered_addresses.contains(&addr_b));

    // Snapshot written keyed by (group_id, finder=addr_a).
    let mut conn = h.round.connection_for_snapshot();
    let snap = bp_group_solo_engine::round::snapshot::read_snapshot(
        &mut conn,
        &h.group_id.to_string(),
        addr_a.as_str(),
    )
    .await
    .expect("snapshot read ok")
    .expect("snapshot persisted");
    assert_eq!(snap.block_reward_sats, 312_500_000);

    cleanup_group(&h.pool, h.group_id).await;
}

// ── Test 2 — group not found returns specific error ────────────────

#[tokio::test]
async fn build_for_nonexistent_group_returns_group_not_found() {
    let pg_url = std::env::var("BP_PG_URL").unwrap_or_else(|_| PG_URL.to_string());
    let redis_base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_URL.to_string());
    let pool = match PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect(&pg_url)
        .await
    {
        Ok(p) => p,
        Err(_) => return,
    };
    let client = match Client::open(format!("{redis_base}/1")) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut conn = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        ConnectionManager::new(client),
    )
    .await
    {
        Ok(Ok(c)) => c,
        _ => return,
    };
    let _ = redis::cmd("FLUSHDB").query_async::<()>(&mut conn).await;

    let round = GroupRoundStore::new(conn);
    let cfg = DistributionConfig::from_engine_config(&GroupSoloEngineConfig::default());
    let builder = DistributionBuilder::new(pool, round, cfg);

    let nonexistent = Uuid::new_v4();
    let addr = AddressId::new("bc1qfoo").unwrap();
    let err = builder.build(nonexistent, 100, &addr).await.unwrap_err();
    assert!(matches!(
        &*err,
        DistributionError::GroupNotFound { group_id } if *group_id == nonexistent
    ));
}

// ── Test 3 — finder bonus from DB row is applied ───────────────────

#[tokio::test]
async fn finder_bonus_from_db_row_is_applied() {
    // 1M sats bonus configured for the group.
    let h = match spawn_or_skip(2, Some(1_000_000)).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let other = AddressId::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
    h.round
        .record_share(None, &h.group_id.to_string(), finder.as_str(), 50.0, 1)
        .await
        .unwrap();
    h.round
        .record_share(None, &h.group_id.to_string(), other.as_str(), 50.0, 2)
        .await
        .unwrap();

    let result = h
        .builder
        .build(h.group_id, 312_500_000, &finder)
        .await
        .expect("ok");

    // The bp_pplns math emits a dedicated bonus output AND a
    // proportional share for the finder, so the finder can appear in
    // `payouts` more than once. Sum across entries for each address
    // and assert the finder's TOTAL receipt exceeds the equal
    // share-holder by ~1M sats (the configured bonus).
    let finder_total: i64 = result
        .payouts
        .iter()
        .filter(|e| e.address == finder)
        .map(|e| e.sats.0)
        .sum();
    let other_total: i64 = result
        .payouts
        .iter()
        .filter(|e| e.address == other)
        .map(|e| e.sats.0)
        .sum();
    assert!(
        finder_total > other_total,
        "finder total receipt exceeds peer's ({} vs {})",
        finder_total,
        other_total
    );
    // Configured bonus is 1M sats; tolerance is loose because the
    // proportional split is on `block_reward - bonus`.
    let diff = finder_total - other_total;
    assert!(
        diff >= 500_000,
        "finder bonus visible in receipt diff ({})",
        diff
    );

    cleanup_group(&h.pool, h.group_id).await;
}

// ── Test 4 — per-finder snapshot isolation ─────────────────────────

#[tokio::test]
async fn per_finder_snapshots_are_isolated() {
    let h = match spawn_or_skip(3, None).await {
        Some(h) => h,
        None => return,
    };
    let finder1 = AddressId::new("bc1qfinder1").unwrap();
    let finder2 = AddressId::new("bc1qfinder2").unwrap();
    h.round
        .record_share(None, &h.group_id.to_string(), finder1.as_str(), 50.0, 1)
        .await
        .unwrap();
    h.round
        .record_share(None, &h.group_id.to_string(), finder2.as_str(), 50.0, 2)
        .await
        .unwrap();

    h.builder
        .build(h.group_id, 312_500_000, &finder1)
        .await
        .expect("ok");
    h.builder
        .build(h.group_id, 312_500_000, &finder2)
        .await
        .expect("ok");

    let mut conn = h.round.connection_for_snapshot();
    let s1 = bp_group_solo_engine::round::snapshot::read_snapshot(
        &mut conn,
        &h.group_id.to_string(),
        finder1.as_str(),
    )
    .await
    .unwrap();
    let s2 = bp_group_solo_engine::round::snapshot::read_snapshot(
        &mut conn,
        &h.group_id.to_string(),
        finder2.as_str(),
    )
    .await
    .unwrap();
    assert!(s1.is_some());
    assert!(s2.is_some());

    cleanup_group(&h.pool, h.group_id).await;
}

// ── Test 5 — concurrent same-finder dedup ──────────────────────────

#[tokio::test]
async fn concurrent_same_finder_builds_share_one_compute() {
    let h = match spawn_or_skip(4, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qfinder").unwrap();
    h.round
        .record_share(None, &h.group_id.to_string(), finder.as_str(), 100.0, 1)
        .await
        .unwrap();

    let builder = Arc::new(h.builder.clone());
    let group_id = h.group_id;
    let mut handles = Vec::new();
    for _ in 0..6 {
        let b = builder.clone();
        let f = finder.clone();
        handles.push(tokio::spawn(async move {
            b.build(group_id, 312_500_000, &f).await
        }));
    }
    let mut shared: Option<Arc<bp_group_solo_engine::distribution::DistributionResult>> = None;
    for h2 in handles {
        let r = h2.await.unwrap().expect("ok");
        if let Some(prev) = &shared {
            assert!(Arc::ptr_eq(prev, &r), "concurrent same-finder share Arc");
        } else {
            shared = Some(r);
        }
    }

    cleanup_group(&h.pool, h.group_id).await;
}

// ── Test 6 — invalidate_all triggers fresh compute ─────────────────

#[tokio::test]
async fn invalidate_all_triggers_fresh_compute() {
    let h = match spawn_or_skip(5, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qfinder").unwrap();
    h.round
        .record_share(None, &h.group_id.to_string(), finder.as_str(), 100.0, 1)
        .await
        .unwrap();

    let r1 = h
        .builder
        .build(h.group_id, 312_500_000, &finder)
        .await
        .expect("ok");
    let r2 = h
        .builder
        .build(h.group_id, 312_500_000, &finder)
        .await
        .expect("ok");
    assert!(Arc::ptr_eq(&r1, &r2), "cache hit");

    h.builder.invalidate_all();
    let r3 = h
        .builder
        .build(h.group_id, 312_500_000, &finder)
        .await
        .expect("ok");
    assert!(!Arc::ptr_eq(&r1, &r3), "post-invalidate fresh compute");

    cleanup_group(&h.pool, h.group_id).await;
}

// ── Test 7 — empty round still builds (fee-only fallback) ──────────

#[tokio::test]
async fn empty_round_builds_without_panic() {
    let h = match spawn_or_skip(6, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qfinder").unwrap();
    let result = h
        .builder
        .build(h.group_id, 312_500_000, &finder)
        .await
        .expect("ok");
    assert_eq!(result.block_reward_sats, 312_500_000);

    cleanup_group(&h.pool, h.group_id).await;
}

// ── Test 8 — different rewards run independently ───────────────────

#[tokio::test]
async fn distinct_rewards_for_same_group_finder_run_independently() {
    let h = match spawn_or_skip(7, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new("bc1qfinder").unwrap();
    h.round
        .record_share(None, &h.group_id.to_string(), finder.as_str(), 50.0, 1)
        .await
        .unwrap();
    let r1 = h
        .builder
        .build(h.group_id, 300_000_000, &finder)
        .await
        .expect("ok");
    let r2 = h
        .builder
        .build(h.group_id, 312_500_000, &finder)
        .await
        .expect("ok");
    assert_eq!(r1.block_reward_sats, 300_000_000);
    assert_eq!(r2.block_reward_sats, 312_500_000);
    assert!(!Arc::ptr_eq(&r1, &r2));

    cleanup_group(&h.pool, h.group_id).await;
}
