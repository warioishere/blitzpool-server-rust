// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! PPLNS dust-sweep against docker-PG. Each test owns an address prefix;
//! `TestClock` fixes "now" so the abandoned cutoff is deterministic.

use std::sync::Arc;

use bp_common::{AddressId, Sats};
use bp_pplns_engine::ledger::PayoutRowType;
use bp_pplns_engine::sweep::{DustSweepRunner, SweepStats, TestClock};
use chrono::{TimeZone, Utc};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::Mutex;

// The sweep reads the whole `pplns_balance` table, so the tests in this
// binary run one at a time, seeding through cleanup.
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

/// With a non-zero `totalPaidSats`, where a destroyed row would show.
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

/// Leftovers of an aborted run would enter the table-wide candidate set;
/// scoped to `test_sweep_%` so sibling suites keep their fixtures.
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

// ── Test 1 — exact pair cancellation zeroes both rows ──────────────

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

    // Both rows survive at 0: they carry `totalPaidSats`.
    let count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_balance WHERE address LIKE $1"#)
            .bind(format!("{prefix}%"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 2, "a cancelled row is zeroed, not removed");
    assert_eq!(balance_of(&pool, &format!("{prefix}credit")).await, Some(0));
    assert_eq!(balance_of(&pool, &format!("{prefix}debit")).await, Some(0));

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
    assert_eq!(audit[0].2, PayoutRowType::DustSweep.as_wire());
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

    // Σ = 0 before; leaves a 1k credit and a 1k debit remainder.
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

/// An abandoned credit pairs against a still-ACTIVE debit: only the credit
/// side is filtered by the inactivity window.
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

    // The active miner's debt is forgiven, not collected.
    assert_eq!(balance_of(&pool, &format!("{prefix}credit")).await, Some(0));
    assert_eq!(balance_of(&pool, &format!("{prefix}active")).await, Some(0));

    cleanup(&pool, prefix).await;
}

/// Negative control for the test above: an active CREDIT is never written off.
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

    // A NULL credit counts as active: a write-off needs proof of
    // abandonment. A NULL debit, the counterparty, does enter the set.
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

    let second = runner.sweep().await.expect("second ok");
    assert_eq!(second, SweepStats::default());

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
    // The runner accepts addresses up to the 62-char column limit.
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
    let _ = Sats::ZERO; // import path sanity

    cleanup(&pool, prefix).await;
}

// ── The sweep must not write over a balance that moved under it ─────
//
// Its candidate view is stale by the time later pairs commit, and the
// block-found settlement writes exactly those rows.

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

    // A settlement lands between the sweep's read and its write: the pair
    // is built from 10_000 while the row now holds 4_000.
    let stats_before = sweep_pairs_with_stale_credit(&runner, &pool, &credit, &debit, now).await;

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
    let rows: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_payout_history WHERE address LIKE $1 AND "rowType" = $2"#,
    )
    .bind(format!("{PREFIX}%"))
    .bind(PayoutRowType::DustSweep.as_wire())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows.0, 0, "a rolled-back pair must leave no sweep history");

    cleanup(&pool, PREFIX).await;
}

/// One sweep run whose credit row moves after the candidates are read.
async fn sweep_pairs_with_stale_credit(
    runner: &DustSweepRunner<TestClock>,
    pool: &PgPool,
    credit: &str,
    _debit: &str,
    now: chrono::DateTime<Utc>,
) -> SweepStats {
    let candidates = bp_db::find_pplns_balances_with_open_balance(pool)
        .await
        .expect("candidates");
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

/// A fully cancelled row is kept: it is the only home of `totalPaidSats`.
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

/// Dead debits settle before a live miner's larger one: nothing else ever
/// closes an abandoned debit.
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

    // The active debit is the LARGER one, so magnitude alone would take it first.
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
