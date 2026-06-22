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
async fn sweep_exact_pair_deletes_both_balance_rows() {
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

    // Both balance rows deleted.
    let count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_balance WHERE address LIKE $1"#)
            .bind(format!("{prefix}%"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 0);

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
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, format!("{prefix}credit"));
    assert_eq!(rows[0].1, 5_000, "credit reduced by paired amount");

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

#[tokio::test]
async fn sweep_skips_active_rows_within_cutoff() {
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

    // Active row not in candidates → credit has no counterparty.
    assert_eq!(stats.pairs_closed, 0);
    assert_eq!(stats.unpaired_credits, 1);
    assert_eq!(stats.unpaired_debits, 0);

    let count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_balance WHERE address LIKE $1"#)
            .bind(format!("{prefix}%"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        count.0, 2,
        "neither row swept — credit waits for counterparty"
    );

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

    // NULL timestamp = "no signal" — treated as active, not stale.
    seed_balance(&pool, &format!("{prefix}credit_null"), 5_000, None).await;
    seed_balance(&pool, &format!("{prefix}debit_null"), -5_000, None).await;

    let clock = clock_at(2026, 5, 16);
    let runner = DustSweepRunner::new(pool.clone(), clock, 90);
    let stats = runner.sweep().await.expect("sweep ok");
    assert_eq!(stats, SweepStats::default());

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
