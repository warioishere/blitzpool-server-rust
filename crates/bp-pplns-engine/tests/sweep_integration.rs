// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for the PPLNS dust-sweep against docker-PG.
//!
//! Each test seeds with a unique address-prefix so parallel runs
//! don't collide; cleanup wipes both `pplns_balance` and the
//! `pplns_payout_history` rows belonging to the prefix.
//!
//! TestClock fixes "now" so the abandoned-cutoff math is
//! deterministic regardless of when the test runs.

use std::sync::Arc;

use bp_common::{AddressId, Sats};
use bp_pplns_engine::sweep::{DustSweepRunner, SweepStats, TestClock, ROW_TYPE_SWEEP};
use chrono::{TimeZone, Utc};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::Mutex;

// The sweep operates over the entire `pplns_balance` table (it has no
// notion of test isolation), so concurrent tests would race each other's
// seeded rows. Serialise across the whole test binary via a single
// async mutex; each test acquires before seeding + releases after
// cleanup. Trades parallelism for correctness — the suite is small.
static SWEEP_TEST_LOCK: Mutex<()> = Mutex::const_new(());

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

async fn connect_or_skip() -> Option<PgPool> {
    let url = std::env::var("BP_PG_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&url),
    )
    .await
    {
        Ok(Ok(p)) => Some(p),
        Ok(Err(e)) => {
            eprintln!("PG connect failed for {url}: {e} — skipping integration test");
            return None;
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            return None;
        }
    }
}

async fn seed_balance(
    pool: &PgPool,
    address: &str,
    balance_sats: i64,
    last_accepted_share_at_ms: Option<i64>,
) {
    sqlx::query(
        r#"INSERT INTO pplns_balance (address, "balanceSats", "totalPaidSats",
                                      "updatedAt", "lastAcceptedShareAt")
           VALUES ($1, $2, 0, 0, $3)"#,
    )
    .bind(address)
    .bind(balance_sats)
    .bind(last_accepted_share_at_ms)
    .execute(pool)
    .await
    .expect("seed balance");
}

/// `seed_balance` with a lifetime payout on the row. The plain helper pins
/// `totalPaidSats` to 0, which is exactly the value that cannot show a row
/// being destroyed — every assertion about it holds trivially at 0.
async fn seed_balance_with_paid(
    pool: &PgPool,
    address: &str,
    balance_sats: i64,
    total_paid_sats: i64,
    last_accepted_share_at_ms: Option<i64>,
) {
    sqlx::query(
        r#"INSERT INTO pplns_balance (address, "balanceSats", "totalPaidSats",
                                      "updatedAt", "lastAcceptedShareAt")
           VALUES ($1, $2, $3, 0, $4)"#,
    )
    .bind(address)
    .bind(balance_sats)
    .bind(total_paid_sats)
    .bind(last_accepted_share_at_ms)
    .execute(pool)
    .await
    .expect("seed balance with paid");
}

async fn total_paid_of(pool: &PgPool, address: &str) -> Option<i64> {
    sqlx::query_as::<_, (i64,)>(r#"SELECT "totalPaidSats" FROM pplns_balance WHERE address = $1"#)
        .bind(address)
        .fetch_optional(pool)
        .await
        .expect("total paid read")
        .map(|r| r.0)
}

async fn cleanup(pool: &PgPool, prefix: &str) {
    let _ = sqlx::query(r#"DELETE FROM pplns_payout_history WHERE address LIKE $1"#)
        .bind(format!("{prefix}%"))
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM pplns_balance WHERE address LIKE $1"#)
        .bind(format!("{prefix}%"))
        .execute(pool)
        .await;
}

/// Wipe leftover state from any previous run of this suite.
///
/// Sweep operates over the entire `pplns_balance` table, so an aborted
/// previous run that left stale-timestamped rows behind would pollute
/// candidate selection. Scoped to `test_sweep_%` so sibling integration
/// tests (ledger, distribution) running in parallel against the same
/// docker-PG don't get their fixtures clobbered.
async fn wipe_all_test_state(pool: &PgPool) {
    let _ = sqlx::query(r#"DELETE FROM pplns_payout_history WHERE address LIKE 'test_sweep_%'"#)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM pplns_balance WHERE address LIKE 'test_sweep_%'"#)
        .execute(pool)
        .await;
}

fn clock_at(year: i32, month: u32, day: u32) -> Arc<TestClock> {
    Arc::new(TestClock::new(
        Utc.with_ymd_and_hms(year, month, day, 12, 0, 0).unwrap(),
    ))
}

// ── Test 1 — exact pair cancellation deletes both rows ─────────────

#[tokio::test]
async fn sweep_exact_pair_zeroes_both_balance_rows() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_all_test_state(&pool).await;
    let prefix = "test_sweep_exact_";
    cleanup(&pool, prefix).await;

    // Both rows older than 90 days from clock's "now" (2026-05-16).
    let stale_ts = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();
    seed_balance(&pool, &format!("{prefix}credit"), 5_000, Some(stale_ts)).await;
    seed_balance(&pool, &format!("{prefix}debit"), -5_000, Some(stale_ts)).await;

    let clock = clock_at(2026, 5, 16);
    let runner = DustSweepRunner::new(pool.clone(), clock, 90);
    let stats = runner.sweep().await.expect("sweep ok");

    assert_eq!(stats.pairs_closed, 2);
    assert_eq!(stats.sats_paired, 5_000);

    // Both balance rows survive at 0. They used to be DELETEd here; the row
    // carries `totalPaidSats`, so removing it destroys the address's lifetime
    // payout — see `apply_pair_tx`.
    let count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_balance WHERE address LIKE $1"#)
            .bind(format!("{prefix}%"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 2, "a cancelled row is zeroed, not removed");
    assert_eq!(balance_of(&pool, &format!("{prefix}credit")).await, Some(0));
    assert_eq!(balance_of(&pool, &format!("{prefix}debit")).await, Some(0));

    // 2 audit rows written with rowType='dust-sweep' and matching blockHeight.
    let audit: Vec<(String, i64, String, i32)> = sqlx::query_as(
        r#"SELECT address, "paidSats", "rowType", "blockHeight"
           FROM pplns_payout_history WHERE address LIKE $1 ORDER BY address"#,
    )
    .bind(format!("{prefix}%"))
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0].1, 5_000);
    assert_eq!(audit[0].2, ROW_TYPE_SWEEP);
    assert_eq!(
        audit[0].3, audit[1].3,
        "both audit rows share blockHeight (same pair)"
    );
    assert!(audit[0].3 < 0, "synthetic block-height is negative");

    cleanup(&pool, prefix).await;
}

// ── Test 2 — credit > debit leaves credit remainder ────────────────

#[tokio::test]
async fn sweep_unequal_amounts_keeps_remainder_side() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_all_test_state(&pool).await;
    let prefix = "test_sweep_partial_";
    cleanup(&pool, prefix).await;

    let stale_ts = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();
    seed_balance(&pool, &format!("{prefix}credit"), 8_000, Some(stale_ts)).await;
    seed_balance(&pool, &format!("{prefix}debit"), -3_000, Some(stale_ts)).await;

    let clock = clock_at(2026, 5, 16);
    let runner = DustSweepRunner::new(pool.clone(), clock, 90);
    let stats = runner.sweep().await.expect("sweep ok");

    assert_eq!(stats.pairs_closed, 2);
    assert_eq!(stats.sats_paired, 3_000);
    assert_eq!(stats.unpaired_credits, 1, "credit remainder waits");

    let rows: Vec<(String, i64)> = sqlx::query_as(
        r#"SELECT address, "balanceSats" FROM pplns_balance WHERE address LIKE $1 ORDER BY address"#,
    )
    .bind(format!("{prefix}%"))
    .fetch_all(&pool)
    .await
    .unwrap();
    // Both rows are here: the debit cancelled out and is zeroed rather than
    // removed, so its `totalPaidSats` survives. The subject of this test is
    // the remainder on the credit side, and that is unchanged.
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0, format!("{prefix}credit"));
    assert_eq!(rows[0].1, 5_000, "credit reduced by paired amount");
    assert_eq!(rows[1].0, format!("{prefix}debit"));
    assert_eq!(
        rows[1].1, 0,
        "the fully paired debit is zeroed, not deleted"
    );

    cleanup(&pool, prefix).await;
}

// ── Test 3 — ledger symmetry preserved across multi-pair sweep ─────

#[tokio::test]
async fn sweep_multi_pair_preserves_ledger_symmetry() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_all_test_state(&pool).await;
    let prefix = "test_sweep_symmetry_";
    cleanup(&pool, prefix).await;

    let stale_ts = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();

    // Σ = 10k + 7k - 8k - 9k = 0. After pair-cancel: 10k vs -9k → 1k credit
    // remainder; 7k vs -8k → 1k debit remainder. Sum still 0.
    seed_balance(&pool, &format!("{prefix}c1"), 10_000, Some(stale_ts)).await;
    seed_balance(&pool, &format!("{prefix}c2"), 7_000, Some(stale_ts)).await;
    seed_balance(&pool, &format!("{prefix}d1"), -8_000, Some(stale_ts)).await;
    seed_balance(&pool, &format!("{prefix}d2"), -9_000, Some(stale_ts)).await;

    let clock = clock_at(2026, 5, 16);
    let runner = DustSweepRunner::new(pool.clone(), clock, 90);
    let _ = runner.sweep().await.expect("sweep ok");

    let signed_sum: (Option<i64>,) = sqlx::query_as(
        r#"SELECT SUM("balanceSats")::bigint
           FROM pplns_balance WHERE address LIKE $1"#,
    )
    .bind(format!("{prefix}%"))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        signed_sum.0.unwrap_or(0),
        0,
        "ledger symmetry preserved (Σ balanceSats = 0)"
    );

    cleanup(&pool, prefix).await;
}

// ── Test 4 — active row (within cutoff) is not swept ───────────────

/// An abandoned credit pairs against a debit that is still ACTIVE.
///
/// This asserts the opposite of what it used to: the test previously
/// seeded exactly this pair and required `pairs_closed == 0`, because
/// the candidate query filtered both sides by the inactivity window.
/// That is what kept the sweep from ever firing on the real pool — a
/// credit exists because a miner was withheld and §4 handed the value
/// to the miners published in that same block, so the debit belongs by
/// construction to someone who was mining then, and usually still is.
/// Demanding 90 days of silence from them excluded every plausible
/// counterparty.
///
/// Fails against the pre-change query, which returns only the credit.
#[tokio::test]
async fn an_abandoned_credit_pairs_against_an_active_debit() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_all_test_state(&pool).await;
    let prefix = "test_sweep_active_";
    cleanup(&pool, prefix).await;

    let stale_ts = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();
    let active_ts = Utc
        .with_ymd_and_hms(2026, 5, 15, 0, 0, 0)
        .unwrap()
        .timestamp_millis();

    seed_balance(&pool, &format!("{prefix}credit"), 5_000, Some(stale_ts)).await;
    seed_balance(&pool, &format!("{prefix}active"), -5_000, Some(active_ts)).await; // 1d old

    let clock = clock_at(2026, 5, 16);
    let runner = DustSweepRunner::new(pool.clone(), clock, 90);
    let stats = runner.sweep().await.expect("sweep ok");

    assert_eq!(stats.pairs_closed, 2, "one pair, one row per side");
    assert_eq!(stats.sats_paired, 5_000);
    assert_eq!(stats.unpaired_credits, 0);
    assert_eq!(stats.unpaired_debits, 0);

    // The active miner keeps the sats it was already paid: its debt is
    // forgiven, not collected. Both rows stay, at 0.
    assert_eq!(balance_of(&pool, &format!("{prefix}credit")).await, Some(0));
    assert_eq!(balance_of(&pool, &format!("{prefix}active")).await, Some(0));

    cleanup(&pool, prefix).await;
}

/// Negative control for the change above: the cutoff must still bite on
/// the CREDIT side. Without this, widening the query to "every debit"
/// would look identical in the suite to dropping the window entirely.
///
/// Passes both before and after the change — that is the point.
#[tokio::test]
async fn an_active_credit_is_not_swept_even_with_an_abandoned_debit() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_all_test_state(&pool).await;
    let prefix = "test_sweep_activecredit_";
    cleanup(&pool, prefix).await;

    let stale_ts = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();
    let active_ts = Utc
        .with_ymd_and_hms(2026, 5, 15, 0, 0, 0)
        .unwrap()
        .timestamp_millis();

    // Roles swapped vs the test above: the CREDIT is the active one.
    seed_balance(&pool, &format!("{prefix}credit"), 5_000, Some(active_ts)).await;
    seed_balance(&pool, &format!("{prefix}debit"), -5_000, Some(stale_ts)).await;

    let clock = clock_at(2026, 5, 16);
    let runner = DustSweepRunner::new(pool.clone(), clock, 90);
    let stats = runner.sweep().await.expect("sweep ok");

    assert_eq!(
        stats.pairs_closed, 0,
        "a still-mining miner's claim is never written off"
    );
    assert_eq!(
        stats.unpaired_credits, 0,
        "the active credit is no candidate"
    );
    assert_eq!(stats.unpaired_debits, 1, "the debit is, and waits");

    let count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_balance WHERE address LIKE $1"#)
            .bind(format!("{prefix}%"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 2, "both rows survive");

    cleanup(&pool, prefix).await;
}

// ── Test 5 — NULL lastAcceptedShareAt is not abandoned ─────────────

#[tokio::test]
async fn sweep_skips_null_last_accepted_share() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_all_test_state(&pool).await;
    let prefix = "test_sweep_null_";
    cleanup(&pool, prefix).await;

    // NULL timestamp = "no signal". On the CREDIT side that still means
    // "active until proven otherwise" — writing off a claim needs proof,
    // so a NULL credit is no candidate. On the DEBIT side the timestamp
    // says nothing about eligibility (a debit is a counterparty, not a
    // claim being written off), so a NULL debit does enter the set.
    seed_balance(&pool, &format!("{prefix}credit_null"), 5_000, None).await;
    seed_balance(&pool, &format!("{prefix}debit_null"), -5_000, None).await;

    let clock = clock_at(2026, 5, 16);
    let runner = DustSweepRunner::new(pool.clone(), clock, 90);
    let stats = runner.sweep().await.expect("sweep ok");
    assert_eq!(
        stats,
        SweepStats {
            pairs_closed: 0,
            sats_paired: 0,
            unpaired_credits: 0,
            unpaired_debits: 1,
        },
        "the NULL credit is excluded, so nothing can pair"
    );

    let count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_balance WHERE address LIKE $1"#)
            .bind(format!("{prefix}%"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 2, "NULL-timestamp rows survive sweep");

    cleanup(&pool, prefix).await;
}

// ── Test 6 — no candidates → no-op ──────────────────────────────────

#[tokio::test]
async fn sweep_empty_returns_zero_stats() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_all_test_state(&pool).await;
    let prefix = "test_sweep_empty_";
    cleanup(&pool, prefix).await;

    let clock = clock_at(2026, 5, 16);
    let runner = DustSweepRunner::new(pool.clone(), clock, 90);
    let stats = runner.sweep().await.expect("sweep ok");
    assert_eq!(stats, SweepStats::default());
}

// ── Test 7 — sweep replay is idempotent across runs ────────────────

#[tokio::test]
async fn sweep_running_twice_is_safe() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_all_test_state(&pool).await;
    let prefix = "test_sweep_replay_";
    cleanup(&pool, prefix).await;

    let stale_ts = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();
    seed_balance(&pool, &format!("{prefix}credit"), 5_000, Some(stale_ts)).await;
    seed_balance(&pool, &format!("{prefix}debit"), -5_000, Some(stale_ts)).await;

    let clock = clock_at(2026, 5, 16);
    let runner = DustSweepRunner::new(pool.clone(), clock, 90);

    let first = runner.sweep().await.expect("first ok");
    assert_eq!(first.pairs_closed, 2);

    // Second run: balance rows are gone, so no candidates. No-op.
    let second = runner.sweep().await.expect("second ok");
    assert_eq!(second, SweepStats::default());

    // Audit rows from first run still present.
    let audit_count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_payout_history WHERE address LIKE $1"#)
            .bind(format!("{prefix}%"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(audit_count.0, 2);

    cleanup(&pool, prefix).await;
}

// ── Test 8 — runner accepts an address-id explicitly typed ─────────

#[tokio::test]
async fn sweep_works_with_typed_address_id() {
    // Defensive: ensures the AddressId-based call chain in the runner
    // accepts addresses up to the 62-char column limit.
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_all_test_state(&pool).await;
    let prefix = "test_sweep_addrid_";
    cleanup(&pool, prefix).await;

    let stale_ts = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();

    let long_addr = format!("{prefix}{}", "a".repeat(40));
    let _id = AddressId::new(long_addr.clone()).expect("address fits");
    seed_balance(&pool, &long_addr, 1_000, Some(stale_ts)).await;
    seed_balance(&pool, &format!("{prefix}d"), -1_000, Some(stale_ts)).await;

    let clock = clock_at(2026, 5, 16);
    let runner = DustSweepRunner::new(pool.clone(), clock, 90);
    let stats = runner.sweep().await.expect("sweep ok");
    assert_eq!(stats.pairs_closed, 2);
    assert_eq!(stats.sats_paired, 1_000);
    // Both balance rows zero → both deleted (signed-ledger Sats(1000) -
    // Sats(1000) = Sats(0)).
    let _ = Sats::ZERO; // import path sanity

    cleanup(&pool, prefix).await;
}

// ── The sweep must not write over a balance that moved under it ─────
//
// `sweep_pairs` reads its candidate set ONCE per run and then commits pair
// by pair, so its view of every not-yet-processed row is stale from the
// start of the run. The other writer is the block-found settlement, and
// its balance-only entries — open balance, no recent shares — ARE this
// sweep's target set, so the overlap is the rule rather than an oddity.
//
// Writing the computed absolute anyway would silently undo whatever moved
// the row, and `amount` (derived from the same stale read) would drive a
// shrunken credit negative: a credit row turned into a debit.

#[tokio::test]
async fn a_balance_that_moved_since_the_run_started_is_not_overwritten() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    wipe_all_test_state(&pool).await;

    const PREFIX: &str = "test_sweep_moved_";
    let credit = format!("{PREFIX}credit");
    let debit = format!("{PREFIX}debit");
    cleanup(&pool, PREFIX).await;

    let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let stale = now.timestamp_millis() - 200 * 86_400_000;
    seed_balance(&pool, &credit, 10_000, Some(stale)).await;
    seed_balance(&pool, &debit, -10_000, Some(stale)).await;

    let runner = DustSweepRunner::new(
        pool.clone(),
        Arc::new(TestClock::new(now)),
        /* abandoned_days = */ 90,
    );

    // Simulate the settlement landing between the sweep's read and its
    // write: move the credit AFTER the candidates would have been read.
    // (The runner re-reads per `run`, so moving it here reproduces the
    // stale-view state the guard exists for — the pair below is built
    // from 10_000 and the row now holds 4_000.)
    let stats_before = sweep_pairs_with_stale_credit(&runner, &pool, &credit, &debit, now).await;

    // Nothing may have been written: the pair rolled back whole.
    let credit_now = balance_of(&pool, &credit).await;
    assert_eq!(
        credit_now,
        Some(4_000),
        "the sweep must leave the moved row exactly as the other writer left it. \
         Measured with the guard removed: the pair computes new_credit = 0 from \
         the stale 10 000, so the row is DELETED and the 4 000 sat the \
         settlement had just written are gone"
    );
    let debit_now = balance_of(&pool, &debit).await;
    assert_eq!(
        debit_now,
        Some(-10_000),
        "the pair is atomic: if one side is refused, the other must not move"
    );
    assert_eq!(
        stats_before.pairs_closed, 0,
        "a refused pair must not be counted as closed"
    );
    // And no audit row may claim a cancel that did not happen.
    let rows: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_payout_history WHERE address LIKE $1 AND "rowType" = $2"#,
    )
    .bind(format!("{PREFIX}%"))
    .bind(ROW_TYPE_SWEEP)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows.0, 0, "a rolled-back pair must leave no sweep history");

    cleanup(&pool, PREFIX).await;
}

/// Drive one sweep run whose candidate view is deliberately stale: the
/// credit row is moved after the candidates are read, exactly as a
/// block-found settlement would.
async fn sweep_pairs_with_stale_credit(
    runner: &DustSweepRunner<TestClock>,
    pool: &PgPool,
    credit: &str,
    _debit: &str,
    now: chrono::DateTime<Utc>,
) -> SweepStats {
    let candidates =
        bp_db::find_pplns_sweep_candidates(pool, now.timestamp_millis() - 90 * 86_400_000)
            .await
            .expect("candidates");
    // The settlement commits here — between the read and the write.
    sqlx::query(r#"UPDATE pplns_balance SET "balanceSats" = 4000 WHERE address = $1"#)
        .bind(credit)
        .execute(pool)
        .await
        .expect("move the balance");
    runner
        .sweep_pairs(candidates, now.timestamp_millis(), now)
        .await
        .expect("sweep run")
}

async fn balance_of(pool: &PgPool, address: &str) -> Option<i64> {
    sqlx::query_as::<_, (i64,)>(r#"SELECT "balanceSats" FROM pplns_balance WHERE address = $1"#)
        .bind(address)
        .fetch_optional(pool)
        .await
        .expect("balance read")
        .map(|r| r.0)
}

/// The safeguard behind not deleting a fully-cancelled row: `pplns_balance`
/// is the only home of `totalPaidSats`, an address's lifetime on-chain
/// payout. A DELETE takes it with the row and nothing puts it back — the
/// reader then answers 0, the pool-wide `SUM("totalPaidSats")` drops by that
/// amount, and the next settlement's `prev_total_paid` restarts the counter.
///
/// This only became routine when debits of any age turned into sweep
/// candidates: before that the DELETE could reach nothing but rows already
/// silent for `abandoned_balance_days`.
///
/// Fails against the delete-on-zero code: both rows are gone, so both
/// lookups answer `None` instead of the seeded totals.
#[tokio::test]
async fn a_cancelled_pair_keeps_each_sides_lifetime_payout() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_all_test_state(&pool).await;
    let prefix = "test_sweep_lifetime_";
    cleanup(&pool, prefix).await;

    let stale_ts = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();
    let active_ts = Utc
        .with_ymd_and_hms(2026, 5, 15, 0, 0, 0)
        .unwrap()
        .timestamp_millis();

    // The abandoned credit, and an ACTIVE miner holding the matching debit —
    // the pairing this PR made possible, and the row that must not be lost.
    seed_balance_with_paid(
        &pool,
        &format!("{prefix}credit"),
        5_000,
        111_000,
        Some(stale_ts),
    )
    .await;
    seed_balance_with_paid(
        &pool,
        &format!("{prefix}active"),
        -5_000,
        2_000_000,
        Some(active_ts),
    )
    .await;

    let clock = clock_at(2026, 5, 16);
    let runner = DustSweepRunner::new(pool.clone(), clock, 90);
    let stats = runner.sweep().await.expect("sweep ok");
    assert_eq!(stats.pairs_closed, 2, "precondition: the pair must close");

    assert_eq!(
        total_paid_of(&pool, &format!("{prefix}active")).await,
        Some(2_000_000),
        "the active miner's lifetime payout must survive its debt being cancelled"
    );
    assert_eq!(
        total_paid_of(&pool, &format!("{prefix}credit")).await,
        Some(111_000),
        "and so must the abandoned side's"
    );

    // The pool-wide lifetime figure is a SUM over exactly these rows.
    let lifetime: (i64,) = sqlx::query_as(
        r#"SELECT COALESCE(SUM("totalPaidSats"), 0)::bigint FROM pplns_balance
           WHERE address LIKE $1"#,
    )
    .bind(format!("{prefix}%"))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        lifetime.0, 2_111_000,
        "pool-wide lifetime payout must not drop"
    );

    cleanup(&pool, prefix).await;
}

/// Dead debits are settled before live ones.
///
/// Sorting debits by magnitude alone put a still-mining miner's larger debt
/// ahead of a genuinely abandoned smaller one, so the credit paired against
/// the live row and the dead one stayed open — forever, since nothing else
/// ever comes to claim it. Only reachable since debits of any age became
/// candidates.
///
/// Fails against magnitude-only ordering: the abandoned debit is left at
/// -4000 while the active one absorbs the whole credit.
#[tokio::test]
async fn an_abandoned_debit_is_settled_before_an_active_one() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_all_test_state(&pool).await;
    let prefix = "test_sweep_order_";
    cleanup(&pool, prefix).await;

    let stale_ts = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();
    let active_ts = Utc
        .with_ymd_and_hms(2026, 5, 15, 0, 0, 0)
        .unwrap()
        .timestamp_millis();

    // The active debit is the LARGER one, so magnitude alone would take it
    // first. That is the whole fixture.
    seed_balance(&pool, &format!("{prefix}credit"), 5_000, Some(stale_ts)).await;
    seed_balance(&pool, &format!("{prefix}deaddebit"), -4_000, Some(stale_ts)).await;
    seed_balance(
        &pool,
        &format!("{prefix}livedebit"),
        -9_000,
        Some(active_ts),
    )
    .await;

    let clock = clock_at(2026, 5, 16);
    let runner = DustSweepRunner::new(pool.clone(), clock, 90);
    let stats = runner.sweep().await.expect("sweep ok");
    assert_eq!(stats.sats_paired, 5_000, "the whole credit is absorbed");

    assert_eq!(
        balance_of(&pool, &format!("{prefix}deaddebit")).await,
        Some(0),
        "the abandoned debit must be settled first and in full"
    );
    // The remaining 1000 has nowhere else to go, so the live row takes it —
    // correct, the debt is owed either way.
    assert_eq!(
        balance_of(&pool, &format!("{prefix}livedebit")).await,
        Some(-8_000),
        "the live row absorbs only what the dead one could not"
    );
    assert_eq!(
        balance_of(&pool, &format!("{prefix}credit")).await,
        Some(0),
        "and the credit is fully closed"
    );

    cleanup(&pool, prefix).await;
}

/// The abandoned-credit test lives in `sweep_pairs`, not only in the query
/// that feeds it.
///
/// `sweep_pairs` is `pub` and takes its candidates as an argument, so the SQL
/// predicate is not a guarantee — a future admin endpoint or a widened read
/// could hand it anything. Feed it an ACTIVE credit directly and it must
/// still refuse to write the claim off.
///
/// Fails without the `retain`: the pair closes and a still-mining miner's
/// credit is cancelled.
#[tokio::test]
async fn sweep_pairs_refuses_an_active_credit_handed_to_it_directly() {
    let _guard = SWEEP_TEST_LOCK.lock().await;
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    wipe_all_test_state(&pool).await;
    let prefix = "test_sweep_direct_";
    cleanup(&pool, prefix).await;

    let stale_ts = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .timestamp_millis();
    let active_ts = Utc
        .with_ymd_and_hms(2026, 5, 15, 0, 0, 0)
        .unwrap()
        .timestamp_millis();

    seed_balance(&pool, &format!("{prefix}credit"), 5_000, Some(active_ts)).await;
    seed_balance(&pool, &format!("{prefix}debit"), -5_000, Some(stale_ts)).await;

    let clock = clock_at(2026, 5, 16);
    let runner = DustSweepRunner::new(pool.clone(), clock, 90);

    // Bypass the query: hand it every row, exactly as a careless caller would.
    let candidates: Vec<bp_db::PplnsBalanceRow> = sqlx::query_as::<_, bp_db::PplnsBalanceRow>(
        r#"SELECT address, "balanceSats", "totalPaidSats", "updatedAt", "lastAcceptedShareAt"
           FROM pplns_balance WHERE address LIKE $1 ORDER BY address"#,
    )
    .bind(format!("{prefix}%"))
    .fetch_all(&pool)
    .await
    .expect("read candidates");
    assert_eq!(candidates.len(), 2, "precondition: both rows handed over");

    let now = Utc.with_ymd_and_hms(2026, 5, 16, 12, 0, 0).unwrap();
    let stats = runner
        .sweep_pairs(candidates, now.timestamp_millis(), now)
        .await
        .expect("sweep run");

    assert_eq!(
        stats.pairs_closed, 0,
        "an active miner's claim is never written off, whoever supplied the list"
    );
    assert_eq!(
        balance_of(&pool, &format!("{prefix}credit")).await,
        Some(5_000),
        "the active credit is untouched"
    );
    assert_eq!(
        balance_of(&pool, &format!("{prefix}debit")).await,
        Some(-5_000),
        "and so is the debit that had nothing to pair with"
    );

    cleanup(&pool, prefix).await;
}
