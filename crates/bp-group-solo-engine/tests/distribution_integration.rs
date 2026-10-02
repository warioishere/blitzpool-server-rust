// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `DistributionBuilder` against docker Redis + PG; each
//! test uses a fresh group and its own Redis DB.

use std::sync::Arc;

use bp_common::AddressId;
use bp_group_solo_engine::config::GroupSoloEngineConfig;
use bp_group_solo_engine::distribution::{
    DistributionBuilder, DistributionConfig, DistributionError,
};
use bp_group_solo_engine::round::GroupRoundStore;
use redis::Client;
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

const REDIS_URL: &str = "redis://127.0.0.1:16379";
const PG_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

/// Pool-output recipient, distinct from every miner address used here.
const FEE_ADDR: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";

/// Parseable addresses: a shape-only placeholder is dropped by the build's
/// sanitize pass and leaves an empty share map that proves nothing.
const FINDER_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

struct Harness {
    pool: PgPool,
    builder: DistributionBuilder,
    round: GroupRoundStore,
    group_id: Uuid,
}

async fn spawn_or_skip(redis_db: u8, finder_bonus_ppm: Option<i32>) -> Option<Harness> {
    let pg_url = std::env::var("BP_PG_URL").unwrap_or_else(|_| PG_URL.to_string());
    let redis_base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_URL.to_string());
    // Own DB range per binary, so binaries do not FLUSHDB each other.
    let redis_db =
        bp_test_support::redis_db_in_range(bp_test_support::redis_db::GS_DISTRIBUTION, redis_db)
            .await;
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
        bp_test_support::connection_manager(client),
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
    seed_group(&pool, group_id, finder_bonus_ppm).await;

    let round = GroupRoundStore::new(conn);
    let dist_cfg = DistributionConfig::from_engine_config(&GroupSoloEngineConfig {
        fee_address: Some(AddressId::new(FEE_ADDR).unwrap()),
        ..GroupSoloEngineConfig::default()
    });
    let builder = DistributionBuilder::new(pool.clone(), round.clone(), dist_cfg);

    Some(Harness {
        pool,
        builder,
        round,
        group_id,
    })
}

async fn seed_group(pool: &PgPool, group_id: Uuid, finder_bonus_ppm: Option<i32>) {
    sqlx::query(
        r#"INSERT INTO pplns_group
             (id, name, "creatorAddress", "adminTokenHash", active,
              "createdAt", "updatedAt", "isPublic", "finderBonusPpm")
           VALUES ($1, $2, 'test_dist_creator', $3, true, 0, 0, false, $4)"#,
    )
    .bind(group_id)
    .bind(format!("test-group-{group_id}"))
    .bind(format!("hash-{group_id}"))
    .bind(finder_bonus_ppm)
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
    assert_eq!(result.distribution.reference_revenue_sats, 312_500_000);
    assert!(
        result.distribution.published().count() > 0,
        "expected published payout weights"
    );
    for id in [&addr_a, &addr_b] {
        assert!(
            result.distribution.entries.iter().any(|e| &e.address == id),
            "share-holder must be in the distribution entries"
        );
    }
    // 60/40 share split → 60/40 score weights.
    let score_of = |id: &AddressId| {
        result
            .distribution
            .entries
            .iter()
            .find(|e| &e.address == id)
            .map(|e| e.score_weight)
            .unwrap_or(0)
    };
    assert!(score_of(&addr_a) > score_of(&addr_b));
    assert!(result.bookable, "a Group-Solo build is always bookable");

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
        bp_test_support::connection_manager(client),
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
    // 3 200 ppm (0.32 %), ~1M sats against a 3.125-BTC subsidy.
    let h = match spawn_or_skip(2, Some(3_200)).await {
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

    // §4 folds the bonus into the finder's single output.
    let entries = result
        .distribution
        .payout_entries_at(312_500_000)
        .expect("§4 payout vector");
    let outputs_of = |id: &AddressId| -> Vec<i64> {
        entries
            .iter()
            .filter(|(a, _)| a == id)
            .map(|(_, s)| *s as i64)
            .collect()
    };
    let finder_outputs = outputs_of(&finder);
    assert_eq!(
        finder_outputs.len(),
        1,
        "finder must appear in exactly one §4 output (bonus folded into the weight)"
    );
    let finder_total = finder_outputs[0];
    let other_total = outputs_of(&other)[0];
    assert!(
        finder_total > other_total,
        "finder receipt exceeds peer's ({} vs {})",
        finder_total,
        other_total
    );
    // Exact up to rounding, because the bonus is plain score weight.
    let diff = finder_total - other_total;
    let pot = bp_share::miner_pot_sats(result.distribution.fee_ppm, 312_500_000) as i64;
    let expected = pot * 3_200 / 1_000_000;
    assert!(
        (diff - expected).abs() <= 2,
        "finder bonus in the receipt diff: {diff}, expected {expected}"
    );

    cleanup_group(&h.pool, h.group_id).await;
}

// ── Test 5 — concurrent same-finder dedup ──────────────────────────

#[tokio::test]
async fn concurrent_same_finder_builds_share_one_compute() {
    let h = match spawn_or_skip(4, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new(FINDER_A).unwrap();
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
    let mut shared: Option<Arc<bp_coinbase_snapshot::BuiltDistribution>> = None;
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
    let finder = AddressId::new(FINDER_A).unwrap();
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

// ── Test 7 — empty round bootstraps to the finder, not the pool ─────

/// MONEY: an empty round pays the block to the finder and only the fee to the
/// pool, not the whole block as the §4 residual.
#[tokio::test]
async fn an_empty_round_pays_the_finder_not_the_whole_block_to_the_pool() {
    let h = match spawn_or_skip(6, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new(FINDER_A).unwrap();
    const T: u64 = 312_500_000;

    let result = h
        .builder
        .build(h.group_id, T, &finder)
        .await
        .expect("an empty round must still yield a servable distribution");

    // Precondition: the finder is here via the bootstrap, not a share.
    assert_eq!(
        result.distribution.entries.len(),
        1,
        "an empty round has exactly one claimant — the asking finder"
    );
    assert_eq!(result.distribution.entries[0].address, finder);

    let paid = result.distribution.payout_entries_at(T).expect("§4 vector");
    let of = |a: &str| -> u64 {
        paid.iter()
            .filter(|(addr, _)| addr.as_str() == a)
            .map(|(_, s)| *s)
            .sum()
    };
    let fee_only = T * u64::from(result.distribution.fee_ppm) / 1_000_000;
    assert!(
        of(FEE_ADDR).abs_diff(fee_only) <= 2,
        "pool took {} where its fee is {fee_only} — the old behaviour handed it all {T}",
        of(FEE_ADDR)
    );
    assert!(
        of(FINDER_A).abs_diff(T - fee_only) <= 2,
        "the finder got {} of the {} the pool does not keep",
        of(FINDER_A),
        T - fee_only
    );
    assert_eq!(paid.iter().map(|(_, s)| *s).sum::<u64>(), T, "Σ == T");

    // A bootstrap distribution is bookable like any other.
    assert!(
        result.bookable,
        "a bootstrap block must be bookable like any other"
    );

    cleanup_group(&h.pool, h.group_id).await;
}

// ── Test 8 — different rewards run independently ───────────────────

#[tokio::test]
async fn distinct_rewards_for_same_group_finder_run_independently() {
    let h = match spawn_or_skip(7, None).await {
        Some(h) => h,
        None => return,
    };
    let finder = AddressId::new(FINDER_A).unwrap();
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
    assert_eq!(r1.distribution.reference_revenue_sats, 300_000_000);
    assert_eq!(r2.distribution.reference_revenue_sats, 312_500_000);
    assert!(!Arc::ptr_eq(&r1, &r2));

    cleanup_group(&h.pool, h.group_id).await;
}
