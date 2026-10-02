// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! End-to-end tests for `bp-pplns-engine::distribution`: window read, ledger
//! read, build, snapshot write, and in-flight dedup. Need docker Redis
//! (16379) and PG (15433), skip otherwise; each test owns its addresses and
//! its Redis DB inside this binary's `bp_test_support::redis_db` range.

use std::sync::Arc;

use bp_common::AddressId;
use bp_pplns_engine::config::PplnsEngineConfig;
use bp_pplns_engine::distribution::{
    BuiltDistribution, DistributionBuilder, DistributionConfig, DistributionError,
};
use bp_pplns_engine::window::{NetworkDifficulty, WindowStore};

/// Pool-output recipient; the weight model has no distribution without one.
const FEE_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
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
    let redis_db =
        bp_test_support::redis_db_in_range(bp_test_support::redis_db::PPLNS_DISTRIBUTION, redis_db)
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
        bp_test_support::connection_manager(client),
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

    let _ = sqlx::query("DELETE FROM pplns_balance WHERE address LIKE $1")
        .bind(format!("{address_prefix}%"))
        .execute(&pool)
        .await;

    let net_diff = NetworkDifficulty::new(1_000_000.0);
    let window = WindowStore::new(
        conn,
        /*factor=*/ 4.0,
        /*bucket_shares=*/ 100,
        net_diff,
        AGE_RULE_OFF,
    );
    let cfg = DistributionConfig::from_engine_config(&PplnsEngineConfig {
        fee_address: Some(AddressId::new(FEE_ADDR).unwrap()),
        ..PplnsEngineConfig::default()
    });
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

/// `pplns_balance` is shared by every test here, so only distinct addresses
/// keep one test's cleanup off another's rows.
async fn cleanup_addresses(pool: &PgPool, addresses: &[&str]) {
    for addr in addresses {
        let _ = sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
            .bind(*addr)
            .execute(pool)
            .await;
    }
}

// ── Test 1 — end-to-end build returns payouts + writes snapshot ────

/// `max_age_days` for tests not about ageing. Not `0`: the constructor
/// floors it at one day, so `0` would mean 24 hours.
const AGE_RULE_OFF: u32 = 3650;

#[tokio::test]
async fn build_with_shares_only_returns_payouts_and_writes_snapshot() {
    let h = match connect_or_skip(8, "test_dist_e2e_").await {
        Some(h) => h,
        None => return,
    };

    // Real addresses, or the sanitize pass drops them.
    const ADDR_A: &str = "bc1qvzf0p407umrsaxmsnq62yudwf27lmsxd8sshzl";
    const ADDR_B: &str = "bc1q2a2z2q02mf38pjmtcfc926a52ssk2mw0ekmz6q";
    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;

    let window = build_window(&h).await;
    seed_share(&window, ADDR_A, 60.0, 1_700_000_000_001).await;
    seed_share(&window, ADDR_B, 40.0, 1_700_000_000_002).await;

    let result = h.builder.build(312_500_000).await.expect("build ok");
    assert_eq!(result.distribution.reference_revenue_sats, 312_500_000);
    assert!(
        result.distribution.published().count() > 0,
        "expected published payout weights"
    );
    let addr_a_id = AddressId::new(ADDR_A).unwrap();
    let addr_b_id = AddressId::new(ADDR_B).unwrap();
    for id in [&addr_a_id, &addr_b_id] {
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
    assert!(score_of(&addr_a_id) > score_of(&addr_b_id));

    let snapshot = window
        .read_weight_snapshot_for(&result.payouts_fingerprint())
        .await
        .expect("read snapshot ok");
    let parsed = snapshot.expect("snapshot persisted");
    assert_eq!(parsed.reference_revenue_sats, 312_500_000);
    assert_eq!(parsed.entries.len(), result.distribution.entries.len());

    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;
}

// ── Test 2 — open-balance ledger is folded into the distribution ────

#[tokio::test]
async fn build_folds_open_balances_into_distribution() {
    let h = match connect_or_skip(9, "test_dist_ledger_").await {
        Some(h) => h,
        None => return,
    };

    const ADDR_MINER: &str = "bc1qymzqcsak0z8zxlxyrqtdw0tvke9sma0gwfaplq";
    const ADDR_DEBTOR: &str = "bc1qhntpnmga5u3c96wqvtxx4a429u5l23unmde3g0";
    cleanup_addresses(&h.pool, &[ADDR_MINER, ADDR_DEBTOR]).await;

    let window = build_window(&h).await;
    seed_share(&window, ADDR_MINER, 100.0, 1_700_000_000_001).await;

    // The debtor is not in the window; the distribution must still carry it.
    seed_open_balance(&h.pool, ADDR_DEBTOR, -5_000, 0).await;

    let result = h.builder.build(312_500_000).await.expect("build ok");
    let debtor_id = AddressId::new(ADDR_DEBTOR).unwrap();
    let debtor = result
        .distribution
        .entries
        .iter()
        .find(|e| e.address == debtor_id)
        .expect("open-balance debtor must be in the distribution entries");
    assert_eq!(debtor.balance_sats, -5_000, "debt carried for settlement");
    assert_eq!(debtor.wire_weight, 0, "no shares + debt → no output");

    cleanup_addresses(&h.pool, &[ADDR_MINER, ADDR_DEBTOR]).await;
}

// ── Test 3 — concurrent callers dedup via inflight cache ────────────

#[tokio::test]
async fn concurrent_builds_for_same_reward_share_one_compute() {
    let h = match connect_or_skip(10, "test_dist_dedup_").await {
        Some(h) => h,
        None => return,
    };

    // A real address, or the sanitize pass leaves an EMPTY distribution.
    const ADDR: &str = "bc1q69dqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq4vkle";
    cleanup_addresses(&h.pool, &[ADDR]).await;

    let window = build_window(&h).await;
    seed_share(&window, ADDR, 100.0, 1_700_000_000_001).await;

    let builder = Arc::new(h.builder.clone());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let b = builder.clone();
        handles.push(tokio::spawn(async move { b.build(312_500_000).await }));
    }

    let mut shared_result: Option<Arc<BuiltDistribution>> = None;
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

    // A real address, or the sanitize pass leaves an EMPTY distribution.
    const ADDR: &str = "bc1q6fdqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz09s7u";
    cleanup_addresses(&h.pool, &[ADDR]).await;

    let window = build_window(&h).await;
    seed_share(&window, ADDR, 100.0, 1_700_000_000_001).await;

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

    // A real address, or the sanitize pass leaves an EMPTY distribution.
    const ADDR: &str = "bc1q6ddqqqqqqqqqqqqqqqqqqqqqqqqqqqqqm7zjxl";
    cleanup_addresses(&h.pool, &[ADDR]).await;

    let window = build_window(&h).await;
    seed_share(&window, ADDR, 50.0, 1_700_000_000_001).await;

    let r1 = h.builder.build(300_000_000).await.expect("ok");
    let r2 = h.builder.build(312_500_000).await.expect("ok");
    assert_eq!(r1.distribution.reference_revenue_sats, 300_000_000);
    assert_eq!(r2.distribution.reference_revenue_sats, 312_500_000);
    assert!(!Arc::ptr_eq(&r1, &r2));

    cleanup(&h.pool, &h.address_prefix).await;
}

// ── Test 7 — distinct references share ONE window+ledger load ───────

#[tokio::test]
async fn concurrent_distinct_rewards_share_one_inputs_load() {
    let h = match connect_or_skip(14, "test_dist_inputs_").await {
        Some(h) => h,
        None => return,
    };

    const ADDR_A: &str = "bc1q0fqgxscjqch5tmqvnf50e0uyfem9sr432z2zx9";
    const ADDR_B: &str = "bc1qvuv4q5jp34mlvc97fh0r4l00jrllmunezpl69k";
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
        assert_eq!(
            r.distribution.reference_revenue_sats,
            312_500_000 + i as u64 * 137
        );
        assert!(r.distribution.published().count() > 0);
    }

    let loads = h.builder.inputs_loads() - before;
    assert!(
        loads <= 2,
        "16 concurrent builds for distinct rewards should share the window+ledger \
         load (allowing one straggler that arrives after the leader published); \
         got {loads} loads"
    );

    h.builder.invalidate_all();
    let _ = h.builder.build(999_000_000).await.expect("ok");
    assert!(
        h.builder.inputs_loads() - before > loads,
        "invalidate_all must force the next build to reload the inputs"
    );

    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;
    cleanup(&h.pool, &h.address_prefix).await;
}

// ── Test 8 — distinct references share ONE fingerprint + snapshot ───
//
// The fingerprint hashes the settlement inputs, not the reference revenue,
// so one snapshot settles the pool's templates and every JDC's job alike.

#[tokio::test]
async fn distinct_references_share_one_fingerprinted_snapshot() {
    let h = match connect_or_skip(15, "test_dist_fp_").await {
        Some(h) => h,
        None => return,
    };

    const ADDR_A: &str = "bc1qcv9d0s4mrcpczumg8cr9tj34l0gw29scz552yd";
    const ADDR_B: &str = "bc1qy5jzxu2u6jeps9duq8fgdxuacjan93vy6yg4j8";
    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;

    let window = build_window(&h).await;
    seed_share(&window, ADDR_A, 70.0, 1_700_000_000_001).await;
    seed_share(&window, ADDR_B, 30.0, 1_700_000_000_002).await;

    let first = h.builder.build(312_500_000).await.expect("first build ok");
    let second = h.builder.build(312_499_137).await.expect("second build ok");

    assert_eq!(
        first.payouts_fingerprint(),
        second.payouts_fingerprint(),
        "same settlement inputs must share one snapshot identity"
    );

    let snap = window
        .read_weight_snapshot_for(&first.payouts_fingerprint())
        .await
        .expect("read ok")
        .expect("snapshot present");
    // Last writer wins; settlement never reads the reference as an amount.
    assert!(
        snap.reference_revenue_sats == 312_500_000 || snap.reference_revenue_sats == 312_499_137
    );
    assert_eq!(snap.entries.len(), first.distribution.entries.len());

    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;
    cleanup(&h.pool, &h.address_prefix).await;
}

// ── Test 6 — empty window: refused here, bootstrapped per-miner ──────

/// MONEY: the shared build refuses an empty window, which would otherwise pay
/// the WHOLE block to the fee address.
#[tokio::test]
async fn an_empty_window_is_refused_by_the_shared_build() {
    let h = match connect_or_skip(13, "test_dist_empty_").await {
        Some(h) => h,
        None => return,
    };
    let err = h
        .builder
        .build(312_500_000)
        .await
        .expect_err("an empty window must not yield a shared distribution");
    assert!(
        matches!(
            &*err,
            DistributionError::WeightBuild(bp_pplns::WeightBuildError::NoScoredMiners)
        ),
        "expected NoScoredMiners, got {err:?}"
    );

    cleanup(&h.pool, &h.address_prefix).await;
}

/// The per-miner bootstrap build answers an empty window and pays the asking
/// miner, not the pool, so a fresh pool can get its first shares.
#[tokio::test]
async fn the_bootstrap_build_pays_the_asking_miner() {
    let h = match connect_or_skip(4, "test_dist_boot_").await {
        Some(h) => h,
        None => return,
    };
    const ADDR: &str = "bc1q69dqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq4vkle";
    const T: u64 = 312_500_000;
    cleanup_addresses(&h.pool, &[ADDR]).await;
    let claimant = AddressId::new(ADDR).unwrap();

    // Precondition: the window is really empty.
    assert!(h.builder.build(T).await.is_err(), "window must be empty");

    let result = h
        .builder
        .build_bootstrap(T, &claimant)
        .await
        .expect("the bootstrap build must answer");
    // Other tests' open-balance rows may enter as balance-only entries, so
    // only the score space is pinned to the claimant.
    let entry = result
        .distribution
        .entries
        .iter()
        .find(|e| e.address == claimant)
        .expect("the claimant must be an entry");
    assert_eq!(
        entry.score_weight, result.distribution.score_total,
        "the claimant holds the entire score space"
    );
    assert!(entry.wire_weight > 0, "and is published");

    let paid = result.distribution.payout_entries_at(T).expect("§4 vector");
    let of = |a: &str| -> u64 {
        paid.iter()
            .filter(|(addr, _)| addr.as_str() == a)
            .map(|(_, s)| *s)
            .sum()
    };
    // The pool takes its fee and not the block; `weight_P` carries only the
    // fee, so leftover balance rows do not matter.
    let fee_only = T * u64::from(result.distribution.fee_ppm) / 1_000_000;
    assert!(
        of(FEE_ADDR).abs_diff(fee_only) <= 2 + paid.len() as u64,
        "pool took {} where its fee is {fee_only} — the old behaviour took all {T}",
        of(FEE_ADDR)
    );
    assert!(
        of(ADDR) > 0,
        "the asking miner must actually be paid, got {}",
        of(ADDR)
    );
    assert_eq!(paid.iter().map(|(_, s)| *s).sum::<u64>(), T, "Σ == T");

    // Bookable: the snapshot landed under its own fingerprint.
    assert!(result.bookable);
    let window = build_window(&h).await;
    assert!(window
        .read_weight_snapshot_for(&result.payouts_fingerprint())
        .await
        .expect("read ok")
        .is_some());

    cleanup_addresses(&h.pool, &[ADDR]).await;
    cleanup(&h.pool, &h.address_prefix).await;
}

/// MONEY: a share that lands after an empty-window build must reach the very
/// next build. On the front nothing invalidates this builder when a share
/// lands (the window is written by another process), so cached empty inputs
/// would keep bootstrapping every miner to the whole block.
#[tokio::test]
async fn a_share_after_an_empty_window_reaches_the_next_build() {
    let h = match connect_or_skip(16, "test_dist_late_").await {
        Some(h) => h,
        None => return,
    };
    const ADDR: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    const T: u64 = 312_500_000;
    cleanup_addresses(&h.pool, &[ADDR]).await;

    assert!(
        h.builder.build(T).await.is_err(),
        "precondition: the window is empty"
    );

    // Written by a second store, as the payout process does; the builder
    // is not told.
    let window = build_window(&h).await;
    seed_share(&window, ADDR, 50.0, 1).await;

    let result = h
        .builder
        .build(T)
        .await
        .expect("the share in the window must end the empty-window answer");
    assert!(
        result
            .distribution
            .entries
            .iter()
            .any(|e| e.address.as_str() == ADDR && e.score_weight > 0),
        "the miner with the window's only share must hold score weight"
    );

    cleanup_addresses(&h.pool, &[ADDR]).await;
    cleanup(&h.pool, &h.address_prefix).await;
}

// ── Helper: a sibling WindowStore on the harness's Redis DB ─────────

async fn build_window(h: &Harness) -> WindowStore {
    let redis_base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_URL.to_string());
    let db = redis_db_for_prefix(&h.address_prefix);
    let db =
        bp_test_support::redis_db_in_range(bp_test_support::redis_db::PPLNS_DISTRIBUTION, db).await;
    let url = format!("{redis_base}/{db}");
    let client = Client::open(url).expect("client");
    let conn = bp_test_support::connection_manager(client)
        .await
        .expect("conn");
    let nd = NetworkDifficulty::new(1_000_000.0);
    WindowStore::new(conn, 4.0, 100, nd, AGE_RULE_OFF)
}

fn redis_db_for_prefix(prefix: &str) -> u8 {
    // Must match the numbers the tests pass to `connect_or_skip`.
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
        "test_dist_nopg_" => 5,
        "test_dist_nowin_" => 7,
        "test_dist_boot_" => 4,
        "test_dist_late_" => 16,
        other => panic!("unknown test prefix: {other}"),
    }
}

// ── A failed snapshot write must not collapse the distribution ──────
//
// A build error means no job for any miner; a lost snapshot only a reprocess.
// The write fails via a read-only ACL user, scoped to this connection.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_write_failure_still_returns_the_pplns_distribution() {
    let h = match connect_or_skip(6, "test_dist_oom_").await {
        Some(h) => h,
        None => return,
    };
    const ADDR_A: &str = "bc1q5ndveg7ps2wulxxmsdlqgekduxcsys43pxlxjr";
    const ADDR_B: &str = "bc1qzlx2znc9s9cga7g8836gpej6p9pc94k3xgylrh";
    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;

    let window = build_window(&h).await;
    seed_share(&window, ADDR_A, 60.0, 1_700_000_000_001).await;
    seed_share(&window, ADDR_B, 40.0, 1_700_000_000_002).await;

    const ACL_USER: &str = "bp_test_readonly_snapshot";
    let redis_base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_URL.to_string());
    let db = redis_db_for_prefix(&h.address_prefix);
    let db =
        bp_test_support::redis_db_in_range(bp_test_support::redis_db::PPLNS_DISTRIBUTION, db).await;
    let client = Client::open(format!("{redis_base}/{db}")).expect("client");
    let mut admin = bp_test_support::connection_manager(client)
        .await
        .expect("admin conn");

    if redis::cmd("ACL")
        .arg("SETUSER")
        .arg(ACL_USER)
        .arg("on")
        .arg(">readonlypw")
        .arg("~*")
        .arg("&*")
        .arg("+@all")
        .arg("-@write")
        .query_async::<()>(&mut admin)
        .await
        .is_err()
    {
        eprintln!("redis ACL unavailable — skipping");
        cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;
        return;
    }

    let ro_url = redis_base.replacen("redis://", &format!("redis://{ACL_USER}:readonlypw@"), 1);
    let ro_client = Client::open(format!("{ro_url}/{db}")).expect("read-only client");
    let ro_conn = bp_test_support::connection_manager(ro_client)
        .await
        .expect("read-only conn");
    let ro_builder = DistributionBuilder::new(
        h.pool.clone(),
        WindowStore::new(
            ro_conn,
            4.0,
            100,
            NetworkDifficulty::new(1_000_000.0),
            AGE_RULE_OFF,
        ),
        DistributionConfig::from_engine_config(&PplnsEngineConfig {
            fee_address: Some(AddressId::new(FEE_ADDR).unwrap()),
            ..PplnsEngineConfig::default()
        }),
    );

    let result = ro_builder
        .build(312_500_000)
        .await
        .expect("a rejected snapshot write must not fail the distribution build");

    assert!(
        !result.bookable,
        "the read-only user must have rejected the snapshot write — without \
         that this test never exercises its subject"
    );
    assert!(
        result.distribution.published().count() >= 2,
        "the real PPLNS distribution must come back, not a solo fallback: {:?}",
        result.distribution.entries
    );
    assert!(
        result
            .distribution
            .published()
            .any(|e| e.address.as_str() == ADDR_B),
        "every miner in the window must still be paid — a solo fallback would \
         leave only the requesting address"
    );

    let _: () = redis::cmd("ACL")
        .arg("DELUSER")
        .arg(ACL_USER)
        .query_async(&mut admin)
        .await
        .expect("drop the read-only user");
    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;
}

// ── The two input reads must fail differently ───────────────────────
//
// An unreadable window fails the build; an unreadable ledger degrades it
// to score-only. Each half below has its own control.

/// A `PgPool` that never connects, so the ledger read fails for real.
fn unreachable_pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_millis(300))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/nope")
        .expect("a lazily-connected pool parses its url")
}

#[tokio::test]
async fn an_unreadable_ledger_degrades_to_a_score_only_distribution() {
    let h = match connect_or_skip(5, "test_dist_nopg_").await {
        Some(h) => h,
        None => return,
    };
    const ADDR_A: &str = "bc1q307hujcervvdfr73ntlam2f7w65j6gs9zcnf39";
    const ADDR_B: &str = "bc1qywnf55acqpxr0lekg2gmy2s46pzxqze99j0u9y";
    const REWARD: u64 = 312_500_000;
    const OWED: i64 = 1_000_000;
    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;

    let window = build_window(&h).await;
    seed_share(&window, ADDR_A, 60.0, 1_700_000_000_001).await;
    seed_share(&window, ADDR_B, 40.0, 1_700_000_000_002).await;
    seed_open_balance(&h.pool, ADDR_A, OWED, 0).await;

    // ── Control: with the ledger readable, the promise is IN the build ──
    let normal = h.builder.build(REWARD).await.expect("build with ledger");
    let a_id = AddressId::new(ADDR_A).unwrap();
    let a_normal = normal
        .distribution
        .entries
        .iter()
        .find(|e| e.address == a_id)
        .expect("the owed miner is in the distribution");
    assert_eq!(
        a_normal.balance_sats, OWED,
        "precondition: a readable ledger puts the promise in the snapshot inputs"
    );
    assert!(
        a_normal.wire_weight > a_normal.score_weight,
        "precondition: the promise BOOSTS the published weight ({} vs score {}) —          without this the degraded case below would be indistinguishable",
        a_normal.wire_weight,
        a_normal.score_weight
    );

    // ── Subject: same window, ledger unreachable ────────────────────
    let degraded_builder = DistributionBuilder::new(
        unreachable_pool(),
        build_window(&h).await,
        DistributionConfig::from_engine_config(&PplnsEngineConfig {
            fee_address: Some(AddressId::new(FEE_ADDR).unwrap()),
            ..PplnsEngineConfig::default()
        }),
    );
    let degraded = degraded_builder.build(REWARD).await.expect(
        "an unreadable ledger must NOT fail the build — every PPLNS miner \
                 would lose their job over a fault that costs one block of delay",
    );

    assert_eq!(
        degraded.distribution.extras_total, 0,
        "a score-only distribution promises nothing"
    );
    for entry in &degraded.distribution.entries {
        assert_eq!(
            entry.balance_sats,
            0,
            "{} must carry no promise when the ledger could not be read",
            entry.address.as_str()
        );
        assert_eq!(
            entry.wire_weight,
            entry.score_weight,
            "{} must be published at its pure score weight",
            entry.address.as_str()
        );
    }
    for addr in [ADDR_A, ADDR_B] {
        let id = AddressId::new(addr).unwrap();
        assert!(
            degraded.distribution.published().any(|e| e.address == id),
            "{addr} must still be paid by score"
        );
    }
    assert!(
        degraded.bookable,
        "the degraded distribution is bookable like any other"
    );

    let still_owed: (i64,) =
        sqlx::query_as(r#"SELECT "balanceSats" FROM pplns_balance WHERE address = $1"#)
            .bind(ADDR_A)
            .fetch_one(&h.pool)
            .await
            .expect("balance row");
    assert_eq!(
        still_owed.0, OWED,
        "the unread promise must survive — it is repaid from a later block"
    );

    cleanup_addresses(&h.pool, &[ADDR_A, ADDR_B]).await;
}

#[tokio::test]
async fn an_unreadable_window_fails_the_build_instead_of_degrading() {
    let h = match connect_or_skip(7, "test_dist_nowin_").await {
        Some(h) => h,
        None => return,
    };
    const ADDR: &str = "bc1qy5jzxu2u6jeps9duq8fgdxuacjan93vy6yg4j8";
    const REWARD: u64 = 312_500_000;
    cleanup_addresses(&h.pool, &[ADDR]).await;

    let window = build_window(&h).await;
    seed_share(&window, ADDR, 100.0, 1_700_000_000_001).await;

    h.builder
        .build(REWARD)
        .await
        .expect("precondition: the build works before the window is broken");

    // A STRING on the window key makes `HGETALL` answer WRONGTYPE, local to
    // this test's Redis DB.
    let mut raw = raw_conn(&h).await;
    let _: () = redis::cmd("SET")
        .arg(bp_pplns_engine::window::KEY_WINDOW_BY_ADDRESS)
        .arg("not-a-hash")
        .query_async(&mut raw)
        .await
        .expect("clobber the window key");
    h.builder.invalidate_all();

    let err = h.builder.build(REWARD).await.expect_err(
        "an unreadable window must FAIL the build — there are no shares \
                     to distribute, and inventing a distribution would pay the wrong \
                     miners",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("window read"),
        "the failure must name the window, not be some other error: {msg}"
    );

    let _: () = redis::cmd("DEL")
        .arg(bp_pplns_engine::window::KEY_WINDOW_BY_ADDRESS)
        .query_async(&mut raw)
        .await
        .expect("drop the clobbered key");
    cleanup_addresses(&h.pool, &[ADDR]).await;
}

/// A raw connection to the harness's Redis DB, for corrupting a key.
async fn raw_conn(h: &Harness) -> ConnectionManager {
    let redis_base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_URL.to_string());
    let db = redis_db_for_prefix(&h.address_prefix);
    let db =
        bp_test_support::redis_db_in_range(bp_test_support::redis_db::PPLNS_DISTRIBUTION, db).await;
    let client = Client::open(format!("{redis_base}/{db}")).expect("client");
    bp_test_support::connection_manager(client)
        .await
        .expect("conn")
}
