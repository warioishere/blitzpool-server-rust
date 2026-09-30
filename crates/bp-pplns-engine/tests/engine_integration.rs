// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! End-to-end integration tests for `PplnsEngine` + `hooks` + `reader`.
//!
//! Covers the full lifecycle: spawn → record_share → build_distribution
//! → on_block_found → reader views.
//!
//! Each test uses a distinct Redis logical DB (inside this binary's
//! `bp_test_support::redis_db` range) and a distinct PG address prefix,
//! and cleans up its own state before and after.

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
/// distribution math. Invalid (prefix) addresses are filtered out of the
/// distribution input and need no lock.
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
    // Map into this binary's own DB range (`bp_test_support::redis_db`) so
    // binaries do not FLUSHDB each other's databases.
    let redis_db =
        bp_test_support::redis_db_in_range(bp_test_support::redis_db::PPLNS_ENGINE, redis_db).await;
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

/// Test config: tight flush cadence and no daily sweep, so background tasks
/// do not interfere with a test.
///
/// A fee address is required: the pool output anchors the §4 residual, so a
/// build without one refuses (`NoFeeAddress`). `fee_percent` stays 0.0, so
/// the pool output only absorbs rounding residue and the payout assertions
/// can treat the whole reward as the miners'.
fn test_config() -> PplnsEngineConfig {
    PplnsEngineConfig {
        touch_flush_interval_secs: 1,
        dust_sweep_enabled: false,
        fee_address: Some(AddressId::new(TEST_FEE_ADDRESS).expect("valid fee address")),
        ..PplnsEngineConfig::default()
    }
}

/// Fee anchor for every engine in this file. MUST NOT be an address any
/// test mines to: the builder excludes the fee address from the miner
/// entries entirely (it is paid via `weight_P`), so reusing one here
/// would silently delete that miner from the distribution.
const TEST_FEE_ADDRESS: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";

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

/// A coinbase that pays EXACTLY the distribution's §4 vector at revenue `t`,
/// pool output first. Settlement books `claim − paid` per address; small
/// rounding deltas between the claim formula and the §4 path are expected.
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

// Hook gating is covered by `crate::hooks::tests`; it does not depend on
// the `ShareAccept` content, so no integration test builds one here.

// ── Test 1 — record_share appears in window_stats ──────────────────

/// Share timestamp anchored near now.
///
/// The timestamp becomes the bucket's index score and the window ages
/// buckets out past `abandoned_balance_days`, so a fixed old timestamp would
/// empty the window mid-test. The offset keeps the relative order.
fn ts(offset: u64) -> u64 {
    (bp_common::now_ms() as u64) - 1_000_000 + offset
}

#[tokio::test]
async fn record_share_then_reader_sees_window_state() {
    let h = match spawn_or_skip(14, "test_engine_record_").await {
        Some(h) => h,
        None => return,
    };

    let addr = format!("{}foo", h.prefix);
    h.engine
        .record_share(None, &addr, 100.0, ts(0))
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
        .record_share(None, ADDR_A, 60.0, ts(1))
        .await
        .unwrap();
    h.engine
        .record_share(None, ADDR_B, 40.0, ts(2))
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
    // A real address: the distribution build drops anything
    // `bitcoin::Address` cannot parse, which would leave only a 0-sat
    // late-arriver row and never exercise a payout.
    const ADDR: &str = "bc1qvzf0p407umrsaxmsnq62yudwf27lmsxd8sshzl";
    h.engine
        .record_share(None, ADDR, 100.0, ts(1))
        .await
        .unwrap();
    let result = h.engine.build_distribution(312_500_000).await.expect("ok");
    // Precondition: the miner must be a published payout, or the assertions
    // below would pass on an empty distribution.
    assert!(
        result
            .distribution
            .published()
            .any(|e| e.address.as_str() == ADDR),
        "the miner must be a published coinbase output, not a late-arriver row"
    );
    let block_height = 9_997_001;
    // Clean this height first: the replay guard treats existing history at
    // this height as "already booked", and `cleanup` only deletes by address
    // prefix, which a real address does not match.
    let _ = sqlx::query(r#"DELETE FROM pplns_payout_history WHERE "blockHeight" = $1"#)
        .bind(block_height)
        .execute(&h.pool)
        .await;
    let actual = actual_paying_exactly(&result, 312_500_000);
    assert!(
        actual.paid_by_address.get(ADDR).copied().unwrap_or(0) > 0,
        "the coinbase must actually pay the miner"
    );
    let outcome = h
        .engine
        .on_block_found(
            block_height,
            &actual,
            None,
            Some(result.payouts_fingerprint()),
        )
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

    let _ = sqlx::query(r#"DELETE FROM pplns_payout_history WHERE "blockHeight" = $1"#)
        .bind(block_height)
        .execute(&h.pool)
        .await;
    let _ = sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
        .bind(ADDR)
        .execute(&h.pool)
        .await;
    drop_harness(h).await;
}

// ── The settlement inputs must outlive the snapshot TTL ────────────
//
// A confirmation-gated block applies `confirmation_depth` blocks after it
// was found, which can outlast `snapshot_ttl_secs` (counted from when the
// winning job was built). Per-job snapshot keys are not backed up, and the
// coinbase cannot say what the miners it did not pay were owed, so the Core
// resolves the inputs at block-found time and the parked blob carries them.
// This test deletes the key outright and pins both directions.

#[tokio::test]
async fn a_block_settles_from_its_parked_blob_after_the_snapshot_key_is_gone() {
    use redis::AsyncCommands as _;

    let _serial = balance_table_lock().lock().await;
    let h = match spawn_or_skip(12, "test_ttlgone_").await {
        Some(h) => h,
        None => return,
    };
    // Addresses unique to this test — real ones, because the builder drops
    // anything `bitcoin::Address` cannot parse and a prefix string would
    // leave the distribution empty.
    const BIG: &str = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const TINY: &str = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
    const REWARD: u64 = 3_000_000_000;
    let h_without: i32 = 9_997_101;
    let h_with: i32 = 9_997_102;
    cleanup_addr(&h.pool, BIG, &[h_without, h_with]).await;
    cleanup_addr(&h.pool, TINY, &[h_without, h_with]).await;

    // TINY's 1-in-1_000_001 share of 30 BTC ≈ 2_999 sat, under the
    // 5_000-sat `min_payout`, so it is WITHHELD from the coinbase and
    // settles as credit instead. That credit exists only in the snapshot,
    // so it is what the assertions key on.
    h.engine
        .record_share(None, BIG, 1_000_000.0, ts(1))
        .await
        .unwrap();
    h.engine.record_share(None, TINY, 1.0, ts(2)).await.unwrap();

    let result = h.engine.build_distribution(REWARD).await.expect("built");
    let fp = result.payouts_fingerprint();
    assert!(
        result.snapshot_written,
        "precondition: the build persisted its snapshot"
    );
    let actual = actual_paying_exactly(&result, REWARD);
    assert!(
        !actual.paid_by_address.contains_key(TINY),
        "precondition: the sub-min_payout miner gets no coinbase output, so \
         its claim exists only in the snapshot"
    );

    // What the Core stamps into the block-found event, resolved while the
    // key is still alive.
    let blob = h
        .engine
        .weight_snapshot_for_block_found(&fp)
        .await
        .expect("the Core resolves the winning job's inputs at found-time");

    // The TTL expires during the confirmation window.
    let mut conn = h.engine.window().connection_for_snapshot();
    let key = bp_pplns_engine::window::snapshot_key_for(&fp);
    let _: () = conn.del(&key).await.expect("drop the snapshot key");

    // Negative control first, so the positive case below cannot pass on a
    // key that was never actually gone: without the blob there is nothing
    // left to settle from.
    let without_blob = h
        .engine
        .on_block_found(h_without, &actual, None, Some(fp))
        .await;
    assert!(
        matches!(
            without_blob,
            Err(bp_pplns_engine::engine::EngineError::SnapshotMissing { .. })
        ),
        "with the key gone and no blob, the block cannot be booked at all \
         (got {without_blob:?})"
    );

    // With the blob, the same block settles normally.
    let outcome = h
        .engine
        .on_block_found(h_with, &actual, Some(blob), Some(fp))
        .await
        .expect("the parked blob is enough to settle from");
    assert!(outcome.history_inserted >= 1, "settlement wrote its rows");

    let credit = credit_of(&h.pool, TINY).await;
    assert!(
        credit > 0,
        "the withheld miner must be CREDITED what the coinbase did not pay \
         it (got {credit} sats) — that credit is exactly what an expired \
         snapshot destroys"
    );

    cleanup_addr(&h.pool, BIG, &[h_without, h_with]).await;
    cleanup_addr(&h.pool, TINY, &[h_without, h_with]).await;
    drop_harness(h).await;
}

// ── A booked block stays booked, whatever the row set does ─────────
//
// "Already booked" cannot be inferred from the history insert reporting new
// rows: the audit rows include one per late arriver (in the window at apply
// time, absent from the snapshot), so the row set can grow between two
// attempts while the balances must not move again. A second attempt happens
// when the confirmation watcher is interrupted between the apply commit and
// removing the parked entry.

#[tokio::test]
async fn a_second_apply_of_the_same_block_moves_no_money() {
    // Depends on Redis state surviving between two steps (the latecomer
    // must still be in the window), so it needs a logical DB no sibling
    // flushes — see `bp_test_support::redis_db`. The precondition assert
    // below is the backstop.
    let _serial = balance_table_lock().lock().await;
    let h = match spawn_or_skip(13, "test_reapply_").await {
        Some(h) => h,
        None => return,
    };
    const BIG: &str = "bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9";
    const TINY: &str = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    const LATECOMER: &str = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
    const REWARD: u64 = 3_000_000_000;
    let height: i32 = 9_997_201;
    for addr in [BIG, TINY, LATECOMER] {
        cleanup_addr(&h.pool, addr, &[height]).await;
    }

    // TINY is withheld (sub-`min_payout`) and therefore settles as a
    // CREDIT — a non-zero delta, which is what a double-apply doubles. A
    // fully-paid miner books ~0 and would not show it.
    h.engine
        .record_share(None, BIG, 1_000_000.0, ts(1))
        .await
        .unwrap();
    h.engine.record_share(None, TINY, 1.0, ts(2)).await.unwrap();

    let result = h.engine.build_distribution(REWARD).await.expect("built");
    let fp = result.payouts_fingerprint();
    let actual = actual_paying_exactly(&result, REWARD);

    let first = h
        .engine
        .on_block_found(height, &actual, None, Some(fp))
        .await
        .expect("first apply books");
    assert!(
        first.history_inserted >= 1,
        "the first apply wrote its rows"
    );
    let credit_after_first = credit_of(&h.pool, TINY).await;
    assert!(
        credit_after_first > 0,
        "precondition: the withheld miner carries a credit to double"
    );

    // A miner absent from the snapshot starts mining before the replay
    // runs, so the apply's row set GROWS by one late-arriver row.
    h.engine
        .record_share(None, LATECOMER, 50.0, ts(3))
        .await
        .unwrap();
    let window = h
        .engine
        .window()
        .read_window_by_address()
        .await
        .expect("window read");
    assert!(
        window.contains_key(LATECOMER),
        "precondition: the latecomer must be in the window the apply reads, \
         or the row set does not grow and this test proves nothing"
    );

    let second = h
        .engine
        .on_block_found(height, &actual, None, Some(fp))
        .await
        .expect("a replayed block-found is a no-op, not an error");

    let credit_after_second = credit_of(&h.pool, TINY).await;
    assert_eq!(
        credit_after_second, credit_after_first,
        "a replayed block must move NO money — the withheld miner's credit \
         went {credit_after_first} → {credit_after_second}, and a credit paid \
         out twice is satoshis the other miners fund"
    );
    assert_eq!(
        (second.history_inserted, second.balances_affected),
        (0, 0),
        "a replayed block must write nothing at all (got {second:?})"
    );

    for addr in [BIG, TINY, LATECOMER] {
        cleanup_addr(&h.pool, addr, &[height]).await;
    }
    drop_harness(h).await;
}

// ── A reorg replacement at the same height must not vanish ──────────
//
// MONEY. `pplns_payout_history` has no `blockHash` column and is UNIQUE on
// `(blockHeight, address)`, so the ledger identifies a booked block by its
// HEIGHT alone. A different block at a booked height (reorg) must be a
// terminal error, not an `Ok` no-op: the watcher then parks it in the
// unbookable store for a reprocess and `pool_blocks_unbookable` counts it,
// instead of treating it as a redelivery and dropping it.
//
// The same-block replay case is pinned by
// `a_second_apply_of_the_same_block_moves_no_money`.

#[tokio::test]
async fn a_different_block_at_the_same_height_is_refused_not_swallowed() {
    let _serial = balance_table_lock().lock().await;
    let h = match spawn_or_skip(20, "test_heightconflict_").await {
        Some(h) => h,
        None => return,
    };
    const BIG: &str = "bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9";
    const TINY: &str = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    const REWARD: u64 = 3_000_000_000;
    let height: i32 = 9_997_301;
    for addr in [BIG, TINY] {
        cleanup_addr(&h.pool, addr, &[height]).await;
    }

    // TINY is withheld and settles as a CREDIT — a non-zero delta, so a
    // second apply would visibly double it.
    h.engine
        .record_share(None, BIG, 1_000_000.0, ts(1))
        .await
        .unwrap();
    h.engine.record_share(None, TINY, 1.0, ts(2)).await.unwrap();

    let result = h.engine.build_distribution(REWARD).await.expect("built");
    let fp = result.payouts_fingerprint();

    // Block A confirms and books.
    let coinbase_a = actual_paying_exactly(&result, REWARD);
    let first = h
        .engine
        .on_block_found(height, &coinbase_a, None, Some(fp))
        .await
        .expect("first apply books");
    assert!(first.history_inserted >= 1);
    let credit_after_first = credit_of(&h.pool, TINY).await;
    assert!(
        credit_after_first > 0,
        "precondition: the withheld miner carries a credit a double-apply would move"
    );

    // A reorg replaces it with block B at the SAME height, paying a
    // different revenue — so a different coinbase and different deltas.
    let coinbase_b = actual_paying_exactly(&result, REWARD + 250_000_000);
    assert_ne!(
        coinbase_a.paid_by_address, coinbase_b.paid_by_address,
        "precondition: the two blocks must actually pay differently, or there \
         is nothing for the guard to tell apart"
    );

    let err = h
        .engine
        .on_block_found(height, &coinbase_b, None, Some(fp))
        .await
        .expect_err("a different block at a booked height must not report success");
    assert!(
        err.is_terminal(),
        "the recorded rows will not change on a retry, so retrying forever \
         hides the block behind a repeating warning: {err}"
    );
    assert!(
        matches!(
            err,
            bp_pplns_engine::engine::EngineError::Ledger(
                bp_coinbase_snapshot::LedgerError::HeightBookedByAnotherBlock { .. }
            )
        ),
        "expected the height-conflict verdict, got {err}"
    );

    // And nothing moved: the refusal rolls the whole transaction back.
    assert_eq!(
        credit_of(&h.pool, TINY).await,
        credit_after_first,
        "the refused apply must not have touched the ledger"
    );

    for addr in [BIG, TINY] {
        cleanup_addr(&h.pool, addr, &[height]).await;
    }
    drop_harness(h).await;
}

/// The signed ledger balance of one address, `0` when it has no row.
async fn credit_of(pool: &PgPool, address: &str) -> i64 {
    sqlx::query_as::<_, (i64,)>(r#"SELECT "balanceSats" FROM pplns_balance WHERE address = $1"#)
        .bind(address)
        .fetch_optional(pool)
        .await
        .expect("balance read")
        .map(|r| r.0)
        .unwrap_or(0)
}

// ── A later build must not cost the found block its distribution ───
//
// After the job a block is mined on is built, other builds (an ext 0x0003
// payout request with its own value, a template refresh) overwrite the
// shared `pplns:snapshot` key. The block's distribution is therefore looked
// up under the job's payout fingerprint, which nothing else writes.

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
        .record_share(None, ADDR_A, 70.0, ts(1))
        .await
        .unwrap();
    h.engine
        .record_share(None, ADDR_B, 30.0, ts(2))
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
        .on_block_found(block_height, &actual, None, None)
        .await;
    assert!(
        blind.is_err(),
        "no fingerprint → nothing to book against; preparing blind must refuse"
    );

    // With it: the block's distribution resolves, later build or not.
    let outcome = h
        .engine
        .on_block_found(block_height, &actual, None, Some(fingerprint))
        .await
        .expect("the job's own distribution must still resolve");
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
        .record_share(None, &addr, 80.0, ts(1))
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
    // The summary aggregates ALL open-balance rows in the table, not just
    // this prefix, so assert at least this pair shows up, not exact totals.
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

// ── Two blocks in sequence must both land ───────────────────────────
//
// The gated path parks a block's INPUTS and computes the balances at apply
// time, as deltas onto the ledger as it stands. The tests below pin that two
// blocks applied in sequence both accumulate.

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

/// Sub-min-payout credit carry-forward, end-to-end through PG: a miner below
/// `min_payout_sats` accrues a pending balance instead of an output; once
/// the credit plus a later block's share crosses the threshold it pays out
/// on-chain and the balance clears. Pins the multi-block ledger round-trip.
#[tokio::test]
async fn pplns_sub_payout_credit_carries_forward_until_it_pays_out() {
    let _serial = balance_table_lock().lock().await;
    let h = match spawn_or_skip(9, "test_subdust_").await {
        Some(h) => h,
        None => return,
    };
    // Dominant miner soaks the reward; the tiny miner's 1-in-1_000_001
    // share of 3 BTC ≈ 2_999 sat < 5_000 min-payout → accrues. Addresses
    // are unique to this test so no test writes another's rows, and the
    // assertions touch only TINY's own ledger.
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
        .record_share(None, BIG, 1_000_000.0, ts(1))
        .await
        .unwrap();
    h.engine.record_share(None, TINY, 1.0, ts(2)).await.unwrap();
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
        .on_block_found(
            h1,
            &actual_paying_exactly(&d1, REWARD),
            None,
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
    //    payout, pending clears. Re-recording keeps the ratio, so rawFair
    //    per block is unchanged. ──
    h.engine
        .record_share(None, BIG, 1_000_000.0, ts(60_001))
        .await
        .unwrap();
    h.engine
        .record_share(None, TINY, 1.0, ts(60_002))
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
        .on_block_found(
            h2,
            &actual_paying_exactly(&d2, REWARD),
            None,
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

/// Applying block 1 before building block 2 accumulates `totalPaidSats`
/// across blocks.
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

    // Block 1.
    h.engine
        .record_share(None, MINER, 100.0, ts(1))
        .await
        .unwrap();
    let d1 = h.engine.build_distribution(REWARD).await.expect("build 1");
    let _p1 = h
        .engine
        .on_block_found(
            h1,
            &actual_paying_exactly(&d1, REWARD),
            None,
            Some(d1.payouts_fingerprint()),
        )
        .await
        .expect("prepare 1");
    let t1 = miner_total_paid(&h.pool, MINER).await;
    assert!(t1 > 0, "block 1 must credit the miner, got {t1}");

    // Block 2: fresh snapshot, built against the post-block-1 ledger.
    h.engine
        .record_share(None, MINER, 100.0, ts(60_001))
        .await
        .unwrap();
    let d2 = h.engine.build_distribution(REWARD).await.expect("build 2");
    let _p2 = h
        .engine
        .on_block_found(
            h2,
            &actual_paying_exactly(&d2, REWARD),
            None,
            Some(d2.payouts_fingerprint()),
        )
        .await
        .expect("block 2");
    let t2 = miner_total_paid(&h.pool, MINER).await;

    assert_eq!(
        t2,
        t1 * 2,
        "two sequential blocks must accumulate totalPaidSats (t1={t1}, t2={t2})"
    );

    cleanup_addr(&h.pool, MINER, &[h1, h2]).await;
    drop_harness(h).await;
}

/// Two blocks applied back-to-back must both land — the second must not
/// clobber the first. Every write, `totalPaidSats` included, is a delta onto
/// the row as it stands at apply time.
#[tokio::test]
async fn two_blocks_in_sequence_both_accumulate() {
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

    // Block 1.
    h.engine
        .record_share(None, MINER, 100.0, ts(1))
        .await
        .unwrap();
    let d1 = h.engine.build_distribution(REWARD).await.expect("build 1");
    let _p1 = h
        .engine
        .on_block_found(
            h1,
            &actual_paying_exactly(&d1, REWARD),
            None,
            Some(d1.payouts_fingerprint()),
        )
        .await
        .expect("block 1");
    let t1 = miner_total_paid(&h.pool, MINER).await;

    // Block 2, against the ledger block 1 just moved.
    h.engine
        .record_share(None, MINER, 100.0, ts(60_001))
        .await
        .unwrap();
    let d2 = h.engine.build_distribution(REWARD).await.expect("build 2");
    let _p2 = h
        .engine
        .on_block_found(
            h2,
            &actual_paying_exactly(&d2, REWARD),
            None,
            Some(d2.payouts_fingerprint()),
        )
        .await
        .expect("block 2");

    let t2 = miner_total_paid(&h.pool, MINER).await;

    assert!(t1 > 0, "block 1 must credit the miner, got {t1}");
    assert_eq!(
        t2,
        t1 * 2,
        "both blocks must accumulate into totalPaidSats even without the \
         flush — block 2 must not revert block 1 (t1={t1}, t2={t2})"
    );
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
// A Core-mode engine (`spawn_core`) wires the same window + distribution
// builder but skips the touch-flush + dust-sweep crons, which mutate the
// ledger and belong to the Satellite. The missing flush cron shows as a
// touch buffer that does not drain past the 1s cadence;
// `build_distribution` (the Core's job) still works.
#[tokio::test]
async fn spawn_core_skips_crons_but_build_distribution_works() {
    let prefix = "test_engine_core_";
    let (conn, pool) = match connect_or_skip(11, prefix).await {
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
        .record_share(None, ADDR, 100.0, ts(0))
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
// The fingerprint names WHICH distribution the coinbase pays. Falling back
// to the shared last-writer-wins key would book a distribution the coinbase
// did not pay, and it would pass the reward check unnoticed.

#[tokio::test]
async fn unknown_fingerprint_refuses_instead_of_booking_the_shared_key() {
    let _guard = balance_table_lock().lock().await;
    let h = match spawn_or_skip(16, "test_engine_unk_").await {
        Some(h) => h,
        None => return,
    };
    const ADDR_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    h.engine
        .record_share(None, ADDR_A, 100.0, ts(1))
        .await
        .unwrap();

    const REWARD: u64 = 312_500_000;
    // A perfectly good snapshot for this window exists — a fallback
    // would succeed and pass every plausibility check.
    let good = h.engine.build_distribution(REWARD).await.expect("build ok");

    let never_written = [0x5au8; 32];
    let err = h
        .engine
        .on_block_found(
            9_997_201,
            &actual_paying_exactly(&good, REWARD),
            None,
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

// ── A redelivered block-found writes nothing ─────────────────────────
//
// The block-found stream is at-least-once. The weight snapshot outlives the
// apply (it serves every block of its distribution), so the payout-history
// guard is what turns a redelivery into a no-op.

#[tokio::test]
async fn apply_consumes_the_fingerprinted_snapshot_so_redelivery_fails_closed() {
    let _guard = balance_table_lock().lock().await;
    let h = match spawn_or_skip(17, "test_engine_consume_").await {
        Some(h) => h,
        None => return,
    };
    const ADDR_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const ADDR_B: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    h.engine
        .record_share(None, ADDR_A, 60.0, ts(1))
        .await
        .unwrap();
    h.engine
        .record_share(None, ADDR_B, 40.0, ts(2))
        .await
        .unwrap();

    const REWARD: u64 = 312_500_000;
    let dist = h.engine.build_distribution(REWARD).await.expect("build ok");
    let fp = dist.payouts_fingerprint();
    let height = 9_997_301;
    let actual = actual_paying_exactly(&dist, REWARD);

    let _prepared = h
        .engine
        .on_block_found(height, &actual, None, Some(fp))
        .await
        .expect("prepare ok");

    // The weight snapshot survives; redelivery is refused by the
    // payout-history guard.
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
        .on_block_found(height, &actual, None, Some(fp))
        .await
        .expect("a redelivered block-found is a no-op, not an error");
    assert_eq!(
        (redelivered.history_inserted, redelivered.balances_affected),
        (0, 0),
        "a redelivered block-found must write nothing: the payout-history \
         UNIQUE swallows the insert and the balance upsert is gated on it \
         (got {redelivered:?})"
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
// Two blocks can be in flight inside the confirmation window, and the later
// one's snapshot predates the earlier one's apply. Booking it must not undo
// the earlier block: settlement is a DELTA against the ledger as it stands
// at apply time, not an absolute computed against an older ledger.

#[tokio::test]
async fn a_block_frozen_before_an_earlier_apply_still_books_correctly() {
    let _guard = balance_table_lock().lock().await;
    let h = match spawn_or_skip(18, "test_engine_stale_").await {
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
        .record_share(None, BIG, 1_000_000.0, ts(1))
        .await
        .unwrap();
    h.engine.record_share(None, TINY, 1.0, ts(2)).await.unwrap();

    // Two blocks in flight, both built against the same (empty) ledger and
    // from the SAME distribution snapshot.
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

    let _prepared_first = h
        .engine
        .on_block_found(
            h1,
            &actual_paying_exactly(&dist_first, REWARD_FIRST),
            None,
            Some(dist_first.payouts_fingerprint()),
        )
        .await
        .expect("prepare first");
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
    let _prepared_second = h
        .engine
        .on_block_found(
            h2,
            &actual_paying_exactly(&dist_second, REWARD_SECOND),
            None,
            Some(fp_second),
        )
        .await
        .expect("a block frozen before the apply must still be bookable");

    // Two blocks' worth of accrual, not one.
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

// ── The settlement gate: subsidy, not the reference revenue ────────
//
// The distribution's `reference_revenue_sats` is only the base the
// wire weights were projected against. Settlement books `claim − paid`
// from the block's OWN coinbase, so it is right at any revenue; not booking
// would leave already-paid balances in the ledger to be paid again. Heights
// here sit in subsidy epoch 4 (312 500 000 sats) so the subsidy gate is
// really exercised, not passed on a height whose subsidy has decayed to 0.

/// A block whose coinbase pays far off the distribution's reference revenue
/// MUST still be booked: the claims come from that coinbase, and skipping it
/// would leave the paid-out credits standing to be paid again.
#[tokio::test]
async fn a_block_far_off_the_reference_revenue_is_still_booked() {
    let _serial = balance_table_lock().lock().await;
    let h = match spawn_or_skip(2, "test_offband_").await {
        Some(h) => h,
        None => return,
    };
    const BIG: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const TINY: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    const T_REF: u64 = 3_000_000_000;
    // 1.6 × the projection base — far outside the band, and still well
    // above the block subsidy, so only the alarm fires.
    const T_ACTUAL: u64 = 4_800_000_000;
    let h1: i32 = 840_601;
    let h2: i32 = 840_602;
    cleanup_addr(&h.pool, BIG, &[h1, h2]).await;
    cleanup_addr(&h.pool, TINY, &[h1, h2]).await;

    // Block 1 pays exactly, leaving TINY a sub-threshold credit.
    h.engine
        .record_share(None, BIG, 1_000_000.0, ts(1))
        .await
        .unwrap();
    h.engine.record_share(None, TINY, 1.0, ts(2)).await.unwrap();
    let d1 = h.engine.build_distribution(T_REF).await.expect("build 1");
    h.engine
        .on_block_found(
            h1,
            &actual_paying_exactly(&d1, T_REF),
            None,
            Some(d1.payouts_fingerprint()),
        )
        .await
        .expect("apply 1");
    let (credit, _) = miner_balance_and_paid(&h.pool, TINY).await;
    assert!(
        credit > 0,
        "block 1 must leave TINY a credit (got {credit})"
    );

    // Block 2 is built against T_REF but paid at T_ACTUAL — the case a
    // job-declaring client's own template produces.
    h.engine
        .record_share(None, BIG, 1_000_000.0, ts(60_001))
        .await
        .unwrap();
    h.engine
        .record_share(None, TINY, 1.0, ts(60_002))
        .await
        .unwrap();
    let d2 = h.engine.build_distribution(T_REF).await.expect("build 2");
    // T_ACTUAL must be FAR off the projection base, or the test would pass
    // on a block that never exercised the drift.
    const _: () = assert!(
        T_ACTUAL > T_REF + T_REF / 4,
        "the fixture must pay far off the revenue it was built against"
    );
    let actual2 = actual_paying_exactly(&d2, T_ACTUAL);
    assert!(
        actual2
            .paid_by_address
            .get(TINY)
            .is_some_and(|paid| *paid > 0),
        "the credit must buy TINY a real coinbase output, or this proves nothing"
    );

    h.engine
        .on_block_found(h2, &actual2, None, Some(d2.payouts_fingerprint()))
        .await
        .expect("a block off the reference revenue must still book");

    let booked: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_payout_history WHERE "blockHeight" = $1"#)
            .bind(h2)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(booked.0 >= 1, "the off-band block must leave audit rows");

    // And the credit is GONE rather than standing to be paid again. The
    // coinbase paid it at 1.6 × the projection, so TINY is left owing
    // the overshoot — signed, small, and the counterparties are booked
    // the matching credits.
    let (after, paid) = miner_balance_and_paid(&h.pool, TINY).await;
    assert!(paid > 0, "TINY was paid on chain (got {paid})");
    assert!(
        after < credit,
        "the credit must be consumed by the payment, not left standing \
         (before {credit}, after {after})"
    );
    assert!(
        after <= 0,
        "paid at 1.6× the promise, TINY should owe the overshoot (got {after})"
    );

    cleanup_addr(&h.pool, BIG, &[h1, h2]).await;
    cleanup_addr(&h.pool, TINY, &[h1, h2]).await;
    drop_harness(h).await;
}

/// Settlement refuses a coinbase paying less than the block's own subsidy:
/// it destroyed money it was entitled to, which no mempool drift or stale
/// projection base can produce.
#[tokio::test]
async fn a_coinbase_below_the_block_subsidy_is_refused() {
    let _serial = balance_table_lock().lock().await;
    let h = match spawn_or_skip(10, "test_burn_").await {
        Some(h) => h,
        None => return,
    };
    const MINER: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const T_REF: u64 = 3_000_000_000;
    // Height 840 701 is 4 halvings in: the subsidy is 312 500 000 sats.
    let height: i32 = 840_701;
    let subsidy = bp_share::block_subsidy_sats(height, bp_share::SUBSIDY_HALVING_INTERVAL);
    assert_eq!(subsidy, 312_500_000, "fixture height must be in epoch 4");
    cleanup_addr(&h.pool, MINER, &[height]).await;

    h.engine
        .record_share(None, MINER, 1_000.0, ts(1))
        .await
        .unwrap();
    let d = h.engine.build_distribution(T_REF).await.expect("build");

    // A §4-consistent coinbase — it just forfeits most of the block.
    let burned = actual_paying_exactly(&d, subsidy - 1);
    let err = h
        .engine
        .on_block_found(height, &burned, None, Some(d.payouts_fingerprint()))
        .await
        .expect_err("a coinbase below the subsidy must not book");
    assert!(
        matches!(
            err,
            bp_pplns_engine::engine::EngineError::RevenueBelowSubsidy { .. }
        ),
        "expected RevenueBelowSubsidy, got {err}"
    );
    assert!(err.is_terminal(), "the watcher must not retry this forever");

    let booked: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_payout_history WHERE "blockHeight" = $1"#)
            .bind(height)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(booked.0, 0, "nothing may be booked for a burned block");

    // One satoshi more and the same coinbase books fine — the gate is
    // the subsidy, nothing fuzzier.
    let honest = actual_paying_exactly(&d, subsidy);
    h.engine
        .on_block_found(height, &honest, None, Some(d.payouts_fingerprint()))
        .await
        .expect("a coinbase paying exactly the subsidy books");

    cleanup_addr(&h.pool, MINER, &[height]).await;
    drop_harness(h).await;
}

// ── The gated apply must not undo what moved underneath it ─────────
//
// A confirmation-gated block applies several blocks after it was found, and
// the daily dust sweep can change the ledger in between.

/// If the sweep cancels an abandoned credit between build and apply (here
/// simulated by removing the row), the apply must not restore it: the credit
/// was cancelled AND the coinbase paid it out, so the holder owes it back.
#[tokio::test]
async fn a_row_swept_between_freeze_and_apply_is_not_restored() {
    let _serial = balance_table_lock().lock().await;
    let h = match spawn_or_skip(19, "test_rebase_").await {
        Some(h) => h,
        None => return,
    };
    const MINER: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const DORMANT: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    const CREDIT: i64 = 50_000; // above the 5_000 min_payout → published
    const T: u64 = 312_500_000;
    let height: i32 = 840_901;
    cleanup_addr(&h.pool, MINER, &[height]).await;
    cleanup_addr(&h.pool, DORMANT, &[height]).await;

    h.engine
        .record_share(None, MINER, 1_000.0, ts(1))
        .await
        .unwrap();
    // A credit with no shares behind it — exactly what the sweep hunts.
    sqlx::query(
        r#"INSERT INTO pplns_balance (address, "balanceSats", "totalPaidSats", "updatedAt")
           VALUES ($1, $2, 0, 0)"#,
    )
    .bind(DORMANT)
    .bind(CREDIT)
    .execute(&h.pool)
    .await
    .unwrap();

    let d = h.engine.build_distribution(T).await.expect("build");
    let actual = actual_paying_exactly(&d, T);
    assert!(
        actual.paid_by_address.get(DORMANT).is_some_and(|p| *p > 0),
        "the credit must buy a real coinbase output, or this proves nothing"
    );

    // The credit is swept away BEFORE the block is applied.
    sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
        .bind(DORMANT)
        .execute(&h.pool)
        .await
        .unwrap();

    h.engine
        .on_block_found(height, &actual, None, Some(d.payouts_fingerprint()))
        .await
        .expect("apply");

    // Settlement reads the row as it stands at apply time and books a
    // delta onto it, so the swept credit is not restored.
    let (after, _) = miner_balance_and_paid(&h.pool, DORMANT).await;
    assert!(
        after < 0,
        "the sweep gave the credit away and the coinbase paid it too, so \
         the holder owes it back — got {after}"
    );

    cleanup_addr(&h.pool, MINER, &[height]).await;
    cleanup_addr(&h.pool, DORMANT, &[height]).await;

    h.engine
        .record_share(None, MINER, 1_000.0, ts(1))
        .await
        .unwrap();
    // A credit with no shares behind it — exactly what the sweep hunts.
    sqlx::query(
        r#"INSERT INTO pplns_balance (address, "balanceSats", "totalPaidSats", "updatedAt")
           VALUES ($1, $2, 0, 0)"#,
    )
    .bind(DORMANT)
    .bind(CREDIT)
    .execute(&h.pool)
    .await
    .unwrap();

    let d = h.engine.build_distribution(T).await.expect("build");
    let actual = actual_paying_exactly(&d, T);
    assert!(
        actual.paid_by_address.get(DORMANT).is_some_and(|p| *p > 0),
        "the credit must buy a real coinbase output, or this proves nothing"
    );

    // The credit is swept away BEFORE the block is applied.
    sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
        .bind(DORMANT)
        .execute(&h.pool)
        .await
        .unwrap();

    h.engine
        .on_block_found(height, &actual, None, Some(d.payouts_fingerprint()))
        .await
        .expect("apply");

    // Settlement reads the row as it stands at apply time and books a
    // delta onto it, so the swept credit is not restored.
    let (after, _) = miner_balance_and_paid(&h.pool, DORMANT).await;
    assert!(
        after < 0,
        "the sweep gave the credit away and the coinbase paid it too, so \
         the holder owes it back — got {after}"
    );

    cleanup_addr(&h.pool, MINER, &[height]).await;
    cleanup_addr(&h.pool, DORMANT, &[height]).await;
    drop_harness(h).await;
}
