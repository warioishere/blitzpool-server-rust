// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `bp-pplns-engine::ledger` against docker-PG.
//!
//! Gated on a local Postgres at
//! `postgres://postgres:postgres@localhost:15433/public_pool`
//! (override with `BP_PG_URL`). Tests skip cleanly via `eprintln!` +
//! early return if the instance isn't reachable.
//!
//! Each test seeds with a unique address-prefix (per-test-name) so
//! parallel runs don't collide on the shared `pplns_*` tables. Tests
//! clean up after themselves with a DELETE in a final block.

use bp_common::{AddressId, Sats};
use bp_pplns_engine::ledger::{
    apply_distribution, coinbase_row, pending_row, touch_buffer::flush_once,
    touch_buffer::TouchBuffer, AuditRow, BalanceWrite, PayoutRowType,
};
use sqlx::{postgres::PgPoolOptions, PgPool};

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

async fn cleanup(pool: &PgPool, address_prefix: &str, block_heights: &[i32]) {
    let like_pattern = format!("{address_prefix}%");
    let _ = sqlx::query("DELETE FROM pplns_payout_history WHERE \"blockHeight\" = ANY($1)")
        .bind(block_heights)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM pplns_balance WHERE address LIKE $1")
        .bind(&like_pattern)
        .execute(pool)
        .await;
}

// ── Test 1 — apply_distribution writes both tables atomically ──────

#[tokio::test]
async fn apply_distribution_writes_history_and_balance() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let block_height = 9_998_001;
    let prefix = "test_apply_dist_";
    cleanup(&pool, prefix, &[block_height]).await;

    let addr_a = AddressId::new(format!("{prefix}aaa")).unwrap();
    let addr_b = AddressId::new(format!("{prefix}bbb")).unwrap();

    let rows = vec![
        AuditRow {
            address: addr_a.clone(),
            paid_sats: Sats(150_000),
            percent: 60.0,
            row_type: PayoutRowType::Coinbase,
        },
        AuditRow {
            address: addr_b.clone(),
            paid_sats: Sats(100_000),
            percent: 40.0,
            row_type: PayoutRowType::Coinbase,
        },
    ];
    let balances = vec![
        BalanceWrite {
            address: addr_a.clone(),
            balance_sats: Sats(0),
            total_paid_sats: Sats(150_000),
        },
        BalanceWrite {
            address: addr_b.clone(),
            balance_sats: Sats(0),
            total_paid_sats: Sats(100_000),
        },
    ];

    let result = apply_distribution(&pool, block_height, &rows, &balances, 1_700_000_000_000)
        .await
        .expect("apply_distribution ok");
    assert_eq!(result.history_inserted, 2);
    assert_eq!(result.balances_affected, 2);

    // Verify both tables.
    let hist_count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_payout_history WHERE "blockHeight" = $1"#)
            .bind(block_height)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(hist_count.0, 2);

    let bal: Vec<(String, i64, i64)> = sqlx::query_as(
        r#"SELECT address, "balanceSats", "totalPaidSats"
           FROM pplns_balance WHERE address LIKE $1 ORDER BY address"#,
    )
    .bind(format!("{prefix}%"))
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(bal.len(), 2);
    assert_eq!(bal[0].2, 150_000);
    assert_eq!(bal[1].2, 100_000);

    cleanup(&pool, prefix, &[block_height]).await;
}

// ── Test 2 — apply_distribution replay is idempotent ────────────────

#[tokio::test]
async fn apply_distribution_replay_idempotent() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let block_height = 9_998_002;
    let prefix = "test_replay_";
    cleanup(&pool, prefix, &[block_height]).await;

    let addr = AddressId::new(format!("{prefix}miner")).unwrap();
    let rows = vec![AuditRow {
        address: addr.clone(),
        paid_sats: Sats(500_000),
        percent: 100.0,
        row_type: PayoutRowType::Coinbase,
    }];
    let balances = vec![BalanceWrite {
        address: addr.clone(),
        balance_sats: Sats(0),
        total_paid_sats: Sats(500_000),
    }];

    let first = apply_distribution(&pool, block_height, &rows, &balances, 1_700_000_000_000)
        .await
        .expect("first call ok");
    assert_eq!(first.history_inserted, 1);

    // Replay: same block_height + same address triggers the
    // (blockHeight, address) UNIQUE-collision-DO-NOTHING path. The balance
    // upsert is now SKIPPED (gated on a non-zero history insert), so a replay
    // can never double-count the accumulated totalPaidSats.
    let second = apply_distribution(&pool, block_height, &rows, &balances, 1_700_000_060_000)
        .await
        .expect("replay ok");
    assert_eq!(
        second.history_inserted, 0,
        "replay must not duplicate history rows"
    );
    assert_eq!(
        second.balances_affected, 0,
        "replay must skip the balance upsert (idempotency gate)"
    );

    // Verify exactly 1 history row, and totalPaidSats still 500k (not doubled).
    let hist_count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_payout_history WHERE "blockHeight" = $1"#)
            .bind(block_height)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(hist_count.0, 1);
    let total_paid: (i64,) =
        sqlx::query_as(r#"SELECT "totalPaidSats" FROM pplns_balance WHERE address = $1"#)
            .bind(addr.as_str())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        total_paid.0, 500_000,
        "replay must not inflate totalPaidSats"
    );

    cleanup(&pool, prefix, &[block_height]).await;
}

// ── Test 3 — apply_distribution with mixed audit row types ──────────

#[tokio::test]
async fn apply_distribution_mixed_row_types() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let block_height = 9_998_003;
    let prefix = "test_mixed_";
    cleanup(&pool, prefix, &[block_height]).await;

    let addr_a = AddressId::new(format!("{prefix}coinbase")).unwrap();
    let addr_b = AddressId::new(format!("{prefix}pending")).unwrap();
    let addr_c = AddressId::new(format!("{prefix}debit")).unwrap();

    let rows = vec![
        AuditRow {
            address: addr_a.clone(),
            paid_sats: Sats(80_000),
            percent: 80.0,
            row_type: PayoutRowType::Coinbase,
        },
        pending_row(addr_b.clone(), Sats(1_500)), // sub-dust credit
        pending_row(addr_c.clone(), Sats(-1_500)), // matching debit
    ];
    let balances = vec![
        BalanceWrite {
            address: addr_a.clone(),
            balance_sats: Sats(0),
            total_paid_sats: Sats(80_000),
        },
        BalanceWrite {
            address: addr_b.clone(),
            balance_sats: Sats(1_500),
            total_paid_sats: Sats(0),
        },
        BalanceWrite {
            address: addr_c.clone(),
            balance_sats: Sats(-1_500),
            total_paid_sats: Sats(0),
        },
    ];

    let result = apply_distribution(&pool, block_height, &rows, &balances, 1_700_000_000_000)
        .await
        .expect("apply ok");
    assert_eq!(result.history_inserted, 3);

    // Verify ledger symmetry holds in the persisted state.
    let signed_sum: (Option<i64>,) = sqlx::query_as(
        r#"SELECT SUM("balanceSats")::bigint FROM pplns_balance WHERE address LIKE $1"#,
    )
    .bind(format!("{prefix}%"))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        signed_sum.0.unwrap_or(0),
        0,
        "signed ledger Σ balanceSats must be 0 (credit ↔ debit pair)"
    );

    // Verify rowType wire strings match expected values.
    let row_types: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT address, "rowType" FROM pplns_payout_history
           WHERE "blockHeight" = $1 ORDER BY address"#,
    )
    .bind(block_height)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(row_types.len(), 3);
    // Sorted by address: coinbase, debit, pending
    let addr_a_str = addr_a.as_str().to_string();
    let addr_b_str = addr_b.as_str().to_string();
    let addr_c_str = addr_c.as_str().to_string();
    let lookup: std::collections::HashMap<String, String> = row_types.into_iter().collect();
    assert_eq!(lookup[&addr_a_str], "coinbase");
    assert_eq!(lookup[&addr_b_str], "pending");
    assert_eq!(lookup[&addr_c_str], "pending");

    cleanup(&pool, prefix, &[block_height]).await;
}

// ── Test 4 — coinbase_row constructor matches manual build ─────────

#[tokio::test]
async fn coinbase_row_constructor_roundtrips_via_apply_distribution() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let block_height = 9_998_004;
    let prefix = "test_cbrow_";
    cleanup(&pool, prefix, &[block_height]).await;

    let addr = AddressId::new(format!("{prefix}miner")).unwrap();
    let entry = bp_pplns::CoinbaseDistributionEntry {
        address: addr.clone(),
        percent: 33.33,
        sats: Sats(83_333),
    };
    let row = coinbase_row(&entry);

    let result = apply_distribution(
        &pool,
        block_height,
        &[row],
        &[BalanceWrite {
            address: addr.clone(),
            balance_sats: Sats(0),
            total_paid_sats: Sats(83_333),
        }],
        1_700_000_000_000,
    )
    .await
    .expect("apply ok");
    assert_eq!(result.history_inserted, 1);

    let row: (String, i64, f32, String) = sqlx::query_as(
        r#"SELECT address, "paidSats", percent, "rowType"
           FROM pplns_payout_history WHERE "blockHeight" = $1"#,
    )
    .bind(block_height)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, addr.as_str());
    assert_eq!(row.1, 83_333);
    assert!((row.2 - 33.33).abs() < 1e-3);
    assert_eq!(row.3, "coinbase");

    cleanup(&pool, prefix, &[block_height]).await;
}

// ── Test 5 — touch_buffer flush_once writes to PG ──────────────────

#[tokio::test]
async fn touch_buffer_flush_once_updates_existing_rows() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let prefix = "test_touch_flush_";
    cleanup(&pool, prefix, &[]).await;

    // Seed two balance rows so the flush has rows to touch.
    let seed_addr_a = format!("{prefix}aa");
    let seed_addr_b = format!("{prefix}bb");
    sqlx::query(
        r#"INSERT INTO pplns_balance (address, "balanceSats", "totalPaidSats", "updatedAt")
           VALUES ($1, 0, 0, 0), ($2, 0, 0, 0)"#,
    )
    .bind(&seed_addr_a)
    .bind(&seed_addr_b)
    .execute(&pool)
    .await
    .unwrap();

    let buf = TouchBuffer::new();
    buf.mark(&seed_addr_a, 1_700_000_500_000);
    buf.mark(&seed_addr_b, 1_700_000_600_000);
    buf.mark(&format!("{prefix}nonexistent"), 1_700_000_700_000);

    let n = flush_once(&pool, &buf).await.expect("flush ok");
    assert_eq!(
        n, 2,
        "expected 2 rows updated (nonexistent address silently skipped)"
    );
    assert!(buf.is_empty(), "buffer drained after successful flush");

    let stamps: Vec<(String, Option<i64>)> = sqlx::query_as(
        r#"SELECT address, "lastAcceptedShareAt"
           FROM pplns_balance WHERE address LIKE $1 ORDER BY address"#,
    )
    .bind(format!("{prefix}%"))
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(stamps[0].1, Some(1_700_000_500_000));
    assert_eq!(stamps[1].1, Some(1_700_000_600_000));

    cleanup(&pool, prefix, &[]).await;
}

// ── Test 6 — touch_buffer empty drain is noop ───────────────────────

#[tokio::test]
async fn touch_buffer_flush_once_empty_returns_zero() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let buf = TouchBuffer::new();
    let n = flush_once(&pool, &buf).await.expect("flush ok");
    assert_eq!(n, 0);
}
