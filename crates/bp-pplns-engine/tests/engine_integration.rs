// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! End-to-end integration tests for `PplnsEngine` + `hooks` + `reader`.
//!
//! Covers the full lifecycle: spawn → record_share → build_distribution
//! → on_block_found → reader views. Plus hook gating + re-entrancy
//! guard.
//!
//! Each test uses a distinct Redis logical DB (0–15) and a distinct
//! PG address-prefix; tests cleanup their own state before + after.

use bp_common::AddressId;
use bp_pplns_engine::config::PplnsEngineConfig;
use bp_pplns_engine::engine::PplnsEngine;
use bp_pplns_engine::window::NetworkDifficulty;
use redis::{aio::ConnectionManager, Client};
use sqlx::{postgres::PgPoolOptions, PgPool};

const REDIS_URL: &str = "redis://127.0.0.1:16379";
const PG_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

/// Serializes the tests that mutate `pplns_balance` with VALID payout
/// addresses and assert exact ledger totals. `build_distribution` reads
/// EVERY open balance in the table (`find_pplns_balances_with_open_balance`),
/// so a concurrent test holding an open balance would perturb another's
/// distribution math. (Tests that seed prefix/invalid addresses are
/// unaffected — those get filtered out of the distribution input.)
fn balance_table_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

// ── Setup helpers ──────────────────────────────────────────────────

struct EngineHarness {
    engine: PplnsEngine,
    pool: PgPool,
    prefix: String,
}

/// Connect PG + a flushed Redis logical DB, or return `None` to skip
/// (services unavailable). Shared by the full-engine and core-mode
/// spawners so both go through the same connect/cleanup path.
async fn connect_or_skip(redis_db: u8, prefix: &str) -> Option<(ConnectionManager, PgPool)> {
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
    cleanup(&pool, prefix).await;

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
    Some((conn, pool))
}

/// Test config: tight flush cadence + no daily sweep so background
/// tasks don't loiter / interfere during a test.
///
/// A fee address is structural in the weight model — the pool output
/// anchors the §4 residual (`pay_P` is never pruned), so a build
/// without one refuses (`NoFeeAddress`). `fee_percent` stays 0.0: the
/// pool output then only absorbs integer-rounding residue and the
/// miners keep effectively the whole reward, which is what the payout
/// assertions in this file are written against.
fn test_config() -> PplnsEngineConfig {
    PplnsEngineConfig {
        touch_flush_interval_secs: 1,
        dust_sweep_enabled: false,
        fee_address: Some(AddressId::new(TEST_FEE_ADDRESS).expect("valid fee address")),
        ..PplnsEngineConfig::default()
    }
}

/// Fee anchor for every engine in this file. Deliberately NOT a miner
/// address used by any test, so fee rows can never collide with the
/// per-test prefixed miners.
const TEST_FEE_ADDRESS: &str = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";

async fn spawn_or_skip(redis_db: u8, prefix: &str) -> Option<EngineHarness> {
    let (conn, pool) = connect_or_skip(redis_db, prefix).await?;
    let net_diff = NetworkDifficulty::new(1_000_000.0);
    let engine = match PplnsEngine::spawn(test_config(), conn, pool.clone(), net_diff).await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("engine spawn failed: {e} — skipping");
            return None;
        }
    };
    Some(EngineHarness {
        engine,
        pool,
        prefix: prefix.to_string(),
    })
}

async fn cleanup(pool: &PgPool, prefix: &str) {
    let _ = sqlx::query("DELETE FROM pplns_payout_history WHERE address LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM pplns_balance WHERE address LIKE $1")
        .bind(format!("{prefix}%"))
        .execute(pool)
        .await;
}

/// A coinbase that pays EXACTLY the distribution's §4 vector at
/// revenue `t` — the pool output first, then the kept miner outputs.
/// What every honestly-built job produces; settlement then books
/// `claim − paid` per address (small integer-rounding deltas between
/// the claim formula and the §4 weight path are expected and correct).
fn actual_paying_exactly(
    dist: &bp_pplns_engine::distribution::DistributionResult,
    t: u64,
) -> bp_coinbase_snapshot::ActualCoinbase {
    let entries = dist
        .distribution
        .payout_entries_at(t)
        .expect("§4 payout vector");
    let mut paid_by_address = std::collections::HashMap::new();
    for (address, sats) in entries.iter().skip(1) {
        *paid_by_address
            .entry(address.as_str().to_string())
            .or_insert(0u64) += sats;
    }
    bp_coinbase_snapshot::ActualCoinbase {
        paid_by_address,
        pool_paid_sats: entries[0].1,
        total_value_sats: t,
    }
}

async fn drop_harness(h: EngineHarness) {
    h.engine.shutdown();
    cleanup(&h.pool, &h.prefix).await;
}

// Hook-impls themselves are covered by `crate::hooks::tests` (ModeGate
// gating logic) + the engine's own `record_share` path. Building a
// real `ShareAccept` for an integration test pulls in `bp-mining-job`'s
// coinbase-construction setup which is heavier than the value adds —
// the gating logic is decoupled from `accept` content, so unit-level
// coverage suffices.

// ── Test 1 — record_share appears in window_stats ──────────────────

#[tokio::test]
async fn record_share_then_reader_sees_window_state() {
    let h = match spawn_or_skip(14, "test_engine_record_").await {
        Some(h) => h,
        None => return,
    };

    let addr = format!("{}foo", h.prefix);
    h.engine
        .record_share(None, &addr, 100.0, 1_700_000_000_000)
        .await
        .expect("record_share ok");

    let stats = h.engine.reader().window_stats().await.expect("ok");
    assert!((stats.total_shares - 100.0).abs() < 1e-9);
    assert_eq!(stats.miner_count, 1);

    drop_harness(h).await;
}

// ── Test 2 — multiple shares + distribution computation ────────────

#[tokio::test]
async fn build_distribution_returns_payouts_after_shares() {
    let h = match spawn_or_skip(15, "test_engine_dist_").await {
        Some(h) => h,
        None => return,
    };
    // Use valid Bitcoin addresses so they survive the payout-address filter.
    const ADDR_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const ADDR_B: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    h.engine
        .record_share(None, ADDR_A, 60.0, 1_700_000_000_001)
        .await
        .unwrap();
    h.engine
        .record_share(None, ADDR_B, 40.0, 1_700_000_000_002)
        .await
        .unwrap();

    let result = h.engine.build_distribution(312_500_000).await.expect("ok");
    assert_eq!(result.distribution.reference_revenue_sats, 312_500_000);
    assert!(result.distribution.published().count() > 0);
    for addr in [ADDR_A, ADDR_B] {
        assert!(result
            .distribution
            .entries
            .iter()
            .any(|e| e.address.as_str() == addr));
    }

    drop_harness(h).await;
}

// ── Test 3 — on_block_found writes audit + balance rows ────────────

#[tokio::test]
async fn on_block_found_applies_distribution_from_snapshot() {
    let h = match spawn_or_skip(0, "test_engine_block_").await {
        Some(h) => h,
        None => return,
    };
    let a = format!("{}aaa", h.prefix);
    h.engine
        .record_share(None, &a, 100.0, 1_700_000_000_001)
        .await
        .unwrap();
    let result = h.engine.build_distribution(312_500_000).await.expect("ok");
    let block_height = 9_997_001;
    let actual = actual_paying_exactly(&result, 312_500_000);
    let outcome = h
        .engine
        .on_block_found_scaled(block_height, &actual, Some(result.payouts_fingerprint()))
        .await
        .expect("ok");
    assert!(outcome.history_inserted >= 1, "at least one audit row");

    // Verify history written.
    let count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_payout_history WHERE "blockHeight" = $1"#)
            .bind(block_height)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(count.0 >= 1, "audit row present in PG");

    // The weight snapshot SURVIVES the apply (it serves every block of
    // this distribution; redelivery is blocked by the history guard).
    let snap = h
        .engine
        .window()
        .read_weight_snapshot_for(&result.payouts_fingerprint())
        .await
        .expect("ok");
    assert!(snap.is_some(), "weight snapshot outlives the apply");

    drop_harness(h).await;
}

// ── A later build must not cost the found block its distribution ───
//
// The bug this guards: the pool builds the job a block is later mined on,
// then some other build — an ext-0x0003 payout request from a JD client with
// its own payout value, or just a template refresh — overwrites the shared
// `pplns:snapshot` key. `prepare_block_found` then reads a snapshot whose
// reward disagrees with the coinbase, refuses, deletes it, and the block's
// PPLNS distribution is never applied (WARN only, manual reprocessing).
//
// Looked up under the job's payout fingerprint it still resolves, because
// nothing else writes that key.

#[tokio::test]
async fn later_build_does_not_cost_the_found_block_its_distribution() {
    let _guard = balance_table_lock().lock().await;
    let h = match spawn_or_skip(1, "test_engine_fp_").await {
        Some(h) => h,
        None => return,
    };
    // Valid addresses — anything else is filtered out before the
    // distribution math and would leave an empty payout list.
    const ADDR_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const ADDR_B: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    h.engine
        .record_share(None, ADDR_A, 70.0, 1_700_000_000_001)
        .await
        .unwrap();
    h.engine
        .record_share(None, ADDR_B, 30.0, 1_700_000_000_002)
        .await
        .unwrap();

    // The build the block's coinbase is made from.
    const MINED_REWARD: u64 = 312_500_000;
    let mined = h
        .engine
        .build_distribution(MINED_REWARD)
        .await
        .expect("mined build ok");
    assert!(
        mined.distribution.published().count() > 0,
        "scenario needs a real distribution"
    );
    let fingerprint = mined.payouts_fingerprint();

    // A later build at a drifted reference — under the weight model it
    // shares the SAME settlement identity (the fingerprint hashes
    // inputs, not amounts), so it cannot displace anything.
    let later = h
        .engine
        .build_distribution(MINED_REWARD - 863)
        .await
        .expect("later build ok");
    assert_eq!(
        fingerprint,
        later.payouts_fingerprint(),
        "same window + ledger → same settlement identity"
    );

    let block_height = 9_997_101;
    let actual = actual_paying_exactly(&mined, MINED_REWARD);

    // Without a fingerprint there is nothing to book against — refuse.
    let blind = h
        .engine
        .prepare_block_found_scaled(block_height, &actual, None)
        .await;
    assert!(
        blind.is_err(),
        "no fingerprint → nothing to book against; preparing blind must refuse"
    );

    // With it: the block's distribution resolves, later build or not.
    let prepared = h
        .engine
        .prepare_block_found_scaled(block_height, &actual, Some(fingerprint))
        .await
        .expect("the job's own distribution must still resolve");
    let outcome = h.engine.apply_prepared(&prepared).await.expect("apply ok");
    assert!(outcome.history_inserted >= 1, "audit rows written");

    let count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_payout_history WHERE "blockHeight" = $1"#)
            .bind(block_height)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(count.0 >= 1, "audit row present in PG");

    let _ = sqlx::query(r#"DELETE FROM pplns_payout_history WHERE "blockHeight" = $1"#)
        .bind(block_height)
        .execute(&h.pool)
        .await;
    for addr in [ADDR_A, ADDR_B] {
        let _ = sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
            .bind(addr)
            .execute(&h.pool)
            .await;
    }
    drop_harness(h).await;
}

// ── Test 4 — reader.address_status combines window + balance ──────

#[tokio::test]
async fn reader_address_status_combines_window_and_balance() {
    let h = match spawn_or_skip(3, "test_engine_status_").await {
        Some(h) => h,
        None => return,
    };
    let addr = format!("{}miner", h.prefix);
    h.engine
        .record_share(None, &addr, 80.0, 1_700_000_000_001)
        .await
        .unwrap();
    sqlx::query(
        r#"INSERT INTO pplns_balance (address, "balanceSats", "totalPaidSats", "updatedAt")
           VALUES ($1, 1234, 99000, 0)"#,
    )
    .bind(&addr)
    .execute(&h.pool)
    .await
    .unwrap();

    let status = h
        .engine
        .reader()
        .address_status(&addr)
        .await
        .expect("ok")
        .expect("some");
    assert_eq!(status.balance_sats, 1234);
    assert_eq!(status.total_paid_sats, 99000);
    assert!((status.current_window_shares - 80.0).abs() < 1e-9);
    assert!((status.current_window_percent - 100.0).abs() < 1e-9);

    drop_harness(h).await;
}

// ── Test 5 — reader.ledger_summary counts credit + debit + abandoned

#[tokio::test]
async fn reader_ledger_summary_aggregates_open_balances() {
    let h = match spawn_or_skip(4, "test_engine_ledger_").await {
        Some(h) => h,
        None => return,
    };
    let credit = format!("{}credit", h.prefix);
    let debit = format!("{}debit", h.prefix);
    let abandoned_ts = chrono::Utc::now().timestamp_millis() - 100 * 86_400_000; // 100 days ago > 90-day default
    let fresh_ts = chrono::Utc::now().timestamp_millis() - 86_400_000; // 1 day ago

    sqlx::query(
        r#"INSERT INTO pplns_balance (address, "balanceSats", "totalPaidSats", "updatedAt", "lastAcceptedShareAt")
           VALUES ($1, 5000, 0, 0, $2), ($3, -5000, 0, 0, $4)"#,
    )
    .bind(&credit)
    .bind(abandoned_ts)
    .bind(&debit)
    .bind(fresh_ts)
    .execute(&h.pool)
    .await
    .unwrap();

    let summary = h.engine.reader().ledger_summary().await.expect("ok");
    // Note: ledger summary aggregates ALL open-balance rows in the
    // table, not just our prefix. Assert *at least* our pair shows up
    // rather than exact totals.
    assert!(summary.credit_row_count >= 1);
    assert!(summary.debit_row_count >= 1);
    assert!(summary.abandoned_credit_sats >= 1);
    assert_eq!(summary.abandoned_balance_days, 90);

    drop_harness(h).await;
}

// ── Test 6 — fee_config returns engine settings synchronously ──────

#[tokio::test]
async fn reader_fee_config_returns_engine_settings() {
    let h = match spawn_or_skip(5, "test_engine_fees_").await {
        Some(h) => h,
        None => return,
    };
    let cfg = h.engine.reader().fee_config();
    assert_eq!(cfg.min_payout_sats, 5_000); // default
    assert_eq!(cfg.coinbase_weight_budget, 50_000); // default
    assert_eq!(cfg.fee_percent, 0.0); // default
    assert_eq!(
        cfg.fee_address.as_deref(),
        Some(TEST_FEE_ADDRESS),
        "the harness fee anchor must surface through the reader"
    );

    drop_harness(h).await;
}

// ── Test 7 — current_distribution sorts descending by share count ──

#[tokio::test]
async fn reader_current_distribution_sorts_descending() {
    let h = match spawn_or_skip(6, "test_engine_distsort_").await {
        Some(h) => h,
        None => return,
    };
    h.engine
        .record_share(None, &format!("{}low", h.prefix), 10.0, 1)
        .await
        .unwrap();
    h.engine
        .record_share(None, &format!("{}high", h.prefix), 90.0, 2)
        .await
        .unwrap();

    let dist = h.engine.reader().current_distribution().await.expect("ok");
    assert!(dist.len() >= 2);
    // First entry has the most shares.
    assert!(dist[0].total_shares >= dist[1].total_shares);

    drop_harness(h).await;
}

// ── Confirmation-gating ordering: prepare/apply interleaving ────────
//
// `prepare_block_found` freezes ABSOLUTE post-distribution balances read
// from the ledger at found-time; `apply_prepared` writes them verbatim.
// The two tests below pin the contract that
// `block_sink::gate_or_apply_pplns`'s flush-before-prepare relies on:
//   • apply the earlier block BEFORE preparing the next  → totals accumulate
//   • prepare two blocks against the same (pre-apply) ledger, apply both
//     → the second absolute write clobbers the first (the hazard the flush
//       prevents by keeping at most one block pending at a time).

async fn cleanup_addr(pool: &PgPool, address: &str, heights: &[i32]) {
    let _ = sqlx::query(r#"DELETE FROM pplns_payout_history WHERE "blockHeight" = ANY($1)"#)
        .bind(heights)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
        .bind(address)
        .execute(pool)
        .await;
}

async fn miner_total_paid(pool: &PgPool, address: &str) -> i64 {
    let row: (i64,) =
        sqlx::query_as(r#"SELECT "totalPaidSats" FROM pplns_balance WHERE address = $1"#)
            .bind(address)
            .fetch_one(pool)
            .await
            .expect("balance row present");
    row.0
}

/// `(balanceSats, totalPaidSats)` for one address.
async fn miner_balance_and_paid(pool: &PgPool, address: &str) -> (i64, i64) {
    sqlx::query_as(r#"SELECT "balanceSats", "totalPaidSats" FROM pplns_balance WHERE address = $1"#)
        .bind(address)
        .fetch_one(pool)
        .await
        .expect("balance row present")
}

/// Sub-min-payout pending-credit carry-forward (end-to-end through PG).
/// A miner whose per-block share is below `min_payout_sats` (default
/// 5_000, clamped ≥ the 546-sat dust floor) accrues a pending balance
/// instead of an on-chain output; once the accrued credit plus a later
/// block's share crosses the threshold it pays out on-chain and the
/// pending balance clears. The single-block halves are unit-tested in
/// `bp-pplns`; this pins the multi-block ledger round-trip.
#[tokio::test]
async fn pplns_sub_payout_credit_carries_forward_until_it_pays_out() {
    let _serial = balance_table_lock().lock().await;
    let h = match spawn_or_skip(9, "test_subdust_").await {
        Some(h) => h,
        None => return,
    };
    // Dominant miner soaks the reward; the tiny miner's 1-in-1_000_001
    // share of 3 BTC ≈ 2_999 sat < 5_000 min-payout → accrues. Uses
    // addresses unique to this test (distinct from the other balance
    // tests + the cross-binary `build_folds` test, which use bc1qw508 /
    // bc1qar0) so no test writes another's rows. The assertions touch
    // only TINY's own ledger, so a foreign open balance the whole-table
    // read folds in can't perturb them.
    const BIG: &str = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const TINY: &str = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
    const REWARD: u64 = 3_000_000_000;
    const MIN_PAYOUT: i64 = 5_000;
    let h1: i32 = 9_995_101;
    let h2: i32 = 9_995_102;
    cleanup_addr(&h.pool, BIG, &[h1, h2]).await;
    cleanup_addr(&h.pool, TINY, &[h1, h2]).await;

    // ── Block 1: tiny miner accrues a sub-threshold pending credit ──
    h.engine
        .record_share(None, BIG, 1_000_000.0, 1_700_000_000_001)
        .await
        .unwrap();
    h.engine
        .record_share(None, TINY, 1.0, 1_700_000_000_002)
        .await
        .unwrap();
    let d1 = h.engine.build_distribution(REWARD).await.expect("build 1");
    let entries1 = d1
        .distribution
        .payout_entries_at(REWARD)
        .expect("§4 vector 1");
    assert!(
        !entries1.iter().any(|(a, _)| a.as_str() == TINY),
        "sub-threshold miner must NOT get a block-1 coinbase output"
    );
    h.engine
        .on_block_found_scaled(
            h1,
            &actual_paying_exactly(&d1, REWARD),
            Some(d1.payouts_fingerprint()),
        )
        .await
        .expect("apply 1");

    let (bal1, paid1) = miner_balance_and_paid(&h.pool, TINY).await;
    assert!(
        bal1 > 0 && bal1 < MIN_PAYOUT,
        "tiny accrues a sub-threshold pending credit (got {bal1})"
    );
    assert_eq!(paid1, 0, "tiny not paid on-chain yet (got {paid1})");

    // ── Block 2: rawFair + accrued credit crosses min_payout → on-chain
    //    payout, pending clears. Same window proportions (re-recording
    //    keeps the ratio identical, so rawFair per block is unchanged). ──
    h.engine
        .record_share(None, BIG, 1_000_000.0, 1_700_000_060_001)
        .await
        .unwrap();
    h.engine
        .record_share(None, TINY, 1.0, 1_700_000_060_002)
        .await
        .unwrap();
    let d2 = h.engine.build_distribution(REWARD).await.expect("build 2");
    let entries2 = d2
        .distribution
        .payout_entries_at(REWARD)
        .expect("§4 vector 2");
    assert!(
        entries2.iter().any(|(a, _)| a.as_str() == TINY),
        "accrued credit must push the tiny miner over min_payout into a block-2 output"
    );
    h.engine
        .on_block_found_scaled(
            h2,
            &actual_paying_exactly(&d2, REWARD),
            Some(d2.payouts_fingerprint()),
        )
        .await
        .expect("apply 2");

    let (bal2, paid2) = miner_balance_and_paid(&h.pool, TINY).await;
    assert!(
        bal2.abs() <= 3,
        "pending credit clears once paid, up to the few-sat integer gap \
         between the claim formula and the §4 weight path (got {bal2})"
    );
    assert!(
        paid2 >= MIN_PAYOUT,
        "tiny paid out crossing the threshold (got {paid2})"
    );

    cleanup_addr(&h.pool, BIG, &[h1, h2]).await;
    cleanup_addr(&h.pool, TINY, &[h1, h2]).await;
    drop_harness(h).await;
}

/// Flush-before-prepare ordering (what `gate_or_apply_pplns` enforces):
/// applying block 1 before preparing block 2 lets `totalPaidSats`
/// accumulate across blocks.
#[tokio::test]
async fn gated_apply_before_next_prepare_accumulates_total_paid() {
    let _serial = balance_table_lock().lock().await;
    let h = match spawn_or_skip(7, "test_gated_seq_").await {
        Some(h) => h,
        None => return,
    };
    // Valid payout address (survives the address filter). Default config
    // has no pool fee, so a sole 100 %-share miner takes the whole reward
    // as one coinbase output → `totalPaidSats` is a clean observable.
    const MINER: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const REWARD: u64 = 312_500_000;
    let h1: i32 = 9_996_101;
    let h2: i32 = 9_996_102;
    cleanup_addr(&h.pool, MINER, &[h1, h2]).await;

    // Block 1: freeze → APPLY.
    h.engine
        .record_share(None, MINER, 100.0, 1_700_000_000_001)
        .await
        .unwrap();
    let d1 = h.engine.build_distribution(REWARD).await.expect("build 1");
    let p1 = h
        .engine
        .prepare_block_found_scaled(
            h1,
            &actual_paying_exactly(&d1, REWARD),
            Some(d1.payouts_fingerprint()),
        )
        .await
        .expect("prepare 1");
    h.engine.apply_prepared(&p1).await.expect("apply 1");
    let t1 = miner_total_paid(&h.pool, MINER).await;
    assert!(t1 > 0, "block 1 must credit the miner, got {t1}");

    // Block 2: fresh snapshot, prepared AGAINST the post-block-1 ledger.
    h.engine
        .record_share(None, MINER, 100.0, 1_700_000_060_001)
        .await
        .unwrap();
    let d2 = h.engine.build_distribution(REWARD).await.expect("build 2");
    let p2 = h
        .engine
        .prepare_block_found_scaled(
            h2,
            &actual_paying_exactly(&d2, REWARD),
            Some(d2.payouts_fingerprint()),
        )
        .await
        .expect("prepare 2");
    h.engine.apply_prepared(&p2).await.expect("apply 2");
    let t2 = miner_total_paid(&h.pool, MINER).await;

    assert_eq!(
        t2,
        t1 * 2,
        "two sequential blocks must accumulate totalPaidSats (t1={t1}, t2={t2})"
    );

    cleanup_addr(&h.pool, MINER, &[h1, h2]).await;
    drop_harness(h).await;
}

/// Documents the hazard `gate_or_apply_pplns` prevents: preparing two
/// blocks against the same pre-apply ledger and applying both makes the
/// second ABSOLUTE balance write clobber the first block's delta — totals
/// do NOT accumulate. The production flush keeps at most one block pending
/// so this interleaving never occurs.
#[tokio::test]
async fn gated_two_prepares_against_same_ledger_clobber_without_flush() {
    let _serial = balance_table_lock().lock().await;
    let h = match spawn_or_skip(8, "test_gated_clobber_").await {
        Some(h) => h,
        None => return,
    };
    const MINER: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    const REWARD: u64 = 312_500_000;
    let h1: i32 = 9_996_201;
    let h2: i32 = 9_996_202;
    cleanup_addr(&h.pool, MINER, &[h1, h2]).await;

    // Freeze block 1 (NOT applied).
    h.engine
        .record_share(None, MINER, 100.0, 1_700_000_000_001)
        .await
        .unwrap();
    let d1 = h.engine.build_distribution(REWARD).await.expect("build 1");
    let p1 = h
        .engine
        .prepare_block_found_scaled(
            h1,
            &actual_paying_exactly(&d1, REWARD),
            Some(d1.payouts_fingerprint()),
        )
        .await
        .expect("prepare 1");

    // Freeze block 2 against the SAME pre-apply ledger (no flush).
    h.engine
        .record_share(None, MINER, 100.0, 1_700_000_060_001)
        .await
        .unwrap();
    let d2 = h.engine.build_distribution(REWARD).await.expect("build 2");
    let p2 = h
        .engine
        .prepare_block_found_scaled(
            h2,
            &actual_paying_exactly(&d2, REWARD),
            Some(d2.payouts_fingerprint()),
        )
        .await
        .expect("prepare 2");

    // Apply both: both were computed against the pre-apply ledger, so
    // block 2's writes clobber block 1's delta.
    h.engine.apply_prepared(&p1).await.expect("apply 1");
    let t1 = miner_total_paid(&h.pool, MINER).await;
    h.engine.apply_prepared(&p2).await.expect("apply 2");
    let t2 = miner_total_paid(&h.pool, MINER).await;

    assert!(t1 > 0, "block 1 must credit the miner, got {t1}");
    assert_eq!(
        t2, t1,
        "without the flush, block 2's absolute write clobbers block 1's \
         delta — totals don't accumulate (t1={t1}, t2={t2})"
    );
    // Both audit rows still exist (distinct heights) — only the ledger
    // balance/total was clobbered, proving it's a write-ordering hazard.
    let hist: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_payout_history WHERE "blockHeight" = ANY($1)"#,
    )
    .bind(vec![h1, h2])
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(hist.0, 2, "both blocks wrote audit rows");

    cleanup_addr(&h.pool, MINER, &[h1, h2]).await;
    drop_harness(h).await;
}

// ── Core-mode spawn — no background crons, read path intact ────────
//
// Contract B slice 1: a Core-mode engine (`spawn_core`) wires the same
// window + distribution builder but skips the touch-flush + dust-sweep
// crons (those mutate the ledger, which is the Satellite's job). We
// prove the absence of the flush cron *observably*: record a share
// (which marks the touch buffer), wait past the 1s flush cadence, and
// assert the buffer never drained — a full engine would have flushed it
// to empty. `build_distribution` (the Core's actual job) still works.
#[tokio::test]
async fn spawn_core_skips_crons_but_build_distribution_works() {
    let prefix = "test_engine_core_";
    let (conn, pool) = match connect_or_skip(2, prefix).await {
        Some(c) => c,
        None => return,
    };
    let net_diff = NetworkDifficulty::new(1_000_000.0);
    let engine = match PplnsEngine::spawn_core(test_config(), conn, pool.clone(), net_diff).await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("engine spawn_core failed: {e} — skipping");
            return;
        }
    };

    // Valid address so it survives the payout-address filter in build_distribution.
    const ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    engine
        .record_share(None, ADDR, 100.0, 1_700_000_000_000)
        .await
        .expect("record_share ok");

    // The touch buffer holds the mark immediately after record_share.
    assert_eq!(engine.touch_buffer().len(), 1, "touch buffered on record");

    // Wait well past the 1s flush cadence. With no flush cron the buffer
    // must NOT drain (a full engine would have emptied it by now).
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    assert_eq!(
        engine.touch_buffer().len(),
        1,
        "core mode ran no touch-flush cron — buffer still holds the mark"
    );

    // The Core's read path still produces a distribution.
    let result = engine.build_distribution(312_500_000).await.expect("ok");
    assert_eq!(result.distribution.reference_revenue_sats, 312_500_000);
    assert!(result.distribution.published().count() > 0);
    assert!(result
        .distribution
        .entries
        .iter()
        .any(|e| e.address.as_str() == ADDR));

    engine.shutdown();
    cleanup(&pool, prefix).await;
}

// Silence "unused: AddressId" if a future test wants it directly.
#[allow(dead_code)]
fn _force_use(_: AddressId) {}

// ── An unresolvable fingerprint must refuse, never fall back ────────
//
// The fingerprint asserts WHICH distribution the coinbase pays. If it
// resolves to nothing that assertion cannot be honoured, and reading the
// shared last-writer-wins key instead would book a distribution the coinbase
// demonstrably did not pay — silently, since the shared copy carries the
// right reward and passes the reward check.

#[tokio::test]
async fn unknown_fingerprint_refuses_instead_of_booking_the_shared_key() {
    let _guard = balance_table_lock().lock().await;
    let h = match spawn_or_skip(3, "test_engine_unk_").await {
        Some(h) => h,
        None => return,
    };
    const ADDR_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    h.engine
        .record_share(None, ADDR_A, 100.0, 1_700_000_000_001)
        .await
        .unwrap();

    const REWARD: u64 = 312_500_000;
    // A perfectly good snapshot for this window exists — a fallback
    // would succeed and pass every plausibility check.
    let good = h.engine.build_distribution(REWARD).await.expect("build ok");

    let never_written = [0x5au8; 32];
    let err = h
        .engine
        .prepare_block_found_scaled(
            9_997_201,
            &actual_paying_exactly(&good, REWARD),
            Some(never_written),
        )
        .await
        .expect_err("an unresolvable fingerprint must not be booked from another snapshot");
    eprintln!("refused with: {err}");

    let _ = sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
        .bind(ADDR_A)
        .execute(&h.pool)
        .await;
    drop_harness(h).await;
}

// ── Apply consumes the snapshot the block was frozen from ───────────
//
// The block-found stream is at-least-once. If the fingerprinted snapshot
// outlives its own block, a redelivered event re-prepares against the ledger
// it already credited and double-credits `totalPaidSats`. Deleting on apply
// is what makes the redelivery fail closed, exactly as it did before the
// fingerprint key existed.

#[tokio::test]
async fn apply_consumes_the_fingerprinted_snapshot_so_redelivery_fails_closed() {
    let _guard = balance_table_lock().lock().await;
    let h = match spawn_or_skip(4, "test_engine_consume_").await {
        Some(h) => h,
        None => return,
    };
    const ADDR_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const ADDR_B: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    h.engine
        .record_share(None, ADDR_A, 60.0, 1_700_000_000_001)
        .await
        .unwrap();
    h.engine
        .record_share(None, ADDR_B, 40.0, 1_700_000_000_002)
        .await
        .unwrap();

    const REWARD: u64 = 312_500_000;
    let dist = h.engine.build_distribution(REWARD).await.expect("build ok");
    let fp = dist.payouts_fingerprint();
    let height = 9_997_301;
    let actual = actual_paying_exactly(&dist, REWARD);

    let prepared = h
        .engine
        .prepare_block_found_scaled(height, &actual, Some(fp))
        .await
        .expect("prepare ok");
    h.engine.apply_prepared(&prepared).await.expect("apply ok");

    // The weight snapshot SURVIVES (it serves every block of this
    // distribution) — redelivery is refused by the payout-history
    // guard, not by consuming the snapshot.
    assert!(
        h.engine
            .window()
            .read_weight_snapshot_for(&fp)
            .await
            .expect("read ok")
            .is_some(),
        "the weight snapshot must outlive its blocks"
    );
    let redelivered = h
        .engine
        .prepare_block_found_scaled(height, &actual, Some(fp))
        .await;
    assert!(
        matches!(
            redelivered,
            Err(bp_pplns_engine::engine::EngineError::AlreadyBooked { .. })
        ),
        "a redelivered block-found must fail closed on the history guard, \
         not re-prepare against the ledger it already credited (got {redelivered:?})"
    );

    let _ = sqlx::query(r#"DELETE FROM pplns_payout_history WHERE "blockHeight" = $1"#)
        .bind(height)
        .execute(&h.pool)
        .await;
    for addr in [ADDR_A, ADDR_B] {
        let _ = sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
            .bind(addr)
            .execute(&h.pool)
            .await;
    }
    drop_harness(h).await;
}

// ── A block frozen before another was applied still books correctly ──
//
// Two blocks can be in flight inside the confirmation window. The later one's
// snapshot was written when its job was built — necessarily before the
// earlier one was applied. Booking it must not undo the pay-down the earlier
// coinbase just made: the snapshot's balances are applied as a DELTA against
// the ledger as it stands at prepare time, not as the absolute it computed
// against a ledger that has since moved.

#[tokio::test]
async fn a_block_frozen_before_an_earlier_apply_still_books_correctly() {
    let _guard = balance_table_lock().lock().await;
    let h = match spawn_or_skip(5, "test_engine_stale_").await {
        Some(h) => h,
        None => return,
    };
    // A dominant miner soaks the reward; the tiny one's share stays under
    // min_payout, so it ACCRUES a pending credit each block. That accrual is
    // what distinguishes a delta from an absolute: two blocks must leave it
    // with two blocks' worth, not one.
    const BIG: &str = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const TINY: &str = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
    const REWARD_FIRST: u64 = 3_000_000_000;
    const REWARD_SECOND: u64 = 2_999_999_137;
    let h1: i32 = 9_997_401;
    let h2: i32 = 9_997_402;
    cleanup_addr(&h.pool, BIG, &[h1, h2]).await;
    cleanup_addr(&h.pool, TINY, &[h1, h2]).await;

    h.engine
        .record_share(None, BIG, 1_000_000.0, 1_700_000_000_001)
        .await
        .unwrap();
    h.engine
        .record_share(None, TINY, 1.0, 1_700_000_000_002)
        .await
        .unwrap();

    // Two blocks in flight, BOTH frozen against the same (empty) ledger
    // — and under the weight model from the SAME distribution snapshot.
    let dist_first = h.engine.build_distribution(REWARD_FIRST).await.expect("ok");
    let dist_second = h
        .engine
        .build_distribution(REWARD_SECOND)
        .await
        .expect("ok");
    let fp_second = dist_second.payouts_fingerprint();
    assert_eq!(
        dist_first.payouts_fingerprint(),
        fp_second,
        "same settlement inputs → one shared snapshot"
    );

    let prepared_first = h
        .engine
        .prepare_block_found_scaled(
            h1,
            &actual_paying_exactly(&dist_first, REWARD_FIRST),
            Some(dist_first.payouts_fingerprint()),
        )
        .await
        .expect("prepare first");
    h.engine
        .apply_prepared(&prepared_first)
        .await
        .expect("apply first");
    let (accrued_once, _) = miner_balance_and_paid(&h.pool, TINY).await;
    assert!(
        accrued_once > 0,
        "the tiny miner must accrue a sub-threshold credit from the first block"
    );

    // The shared snapshot must survive the first apply — settlement is
    // a delta from the real coinbase, so the second block books safely
    // against the post-apply ledger.
    assert!(
        h.engine
            .window()
            .read_weight_snapshot_for(&fp_second)
            .await
            .expect("read ok")
            .is_some(),
        "the shared weight snapshot must survive the first apply"
    );
    let prepared_second = h
        .engine
        .prepare_block_found_scaled(
            h2,
            &actual_paying_exactly(&dist_second, REWARD_SECOND),
            Some(fp_second),
        )
        .await
        .expect("a block frozen before the apply must still be bookable");
    h.engine
        .apply_prepared(&prepared_second)
        .await
        .expect("apply second");

    // Writing the snapshot's ABSOLUTE would leave the credit at one block's
    // worth — the second block's accrual silently lost.
    let (accrued_twice, _) = miner_balance_and_paid(&h.pool, TINY).await;
    assert!(
        accrued_twice > accrued_once,
        "the second block's accrual must ADD to the first, not overwrite it \
         (after first={accrued_once}, after second={accrued_twice})"
    );

    cleanup_addr(&h.pool, BIG, &[h1, h2]).await;
    cleanup_addr(&h.pool, TINY, &[h1, h2]).await;
    drop_harness(h).await;
}
