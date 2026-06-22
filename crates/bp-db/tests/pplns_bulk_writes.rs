// SPDX-License-Identifier: AGPL-3.0-or-later

// Workspace denies print_stderr; the skip-when-no-PG path is
// test-tooling output, not production logging.
#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for the PPLNS bulk-write primitives.
//!
//! Gated on a local docker-PG at
//! `postgres://postgres:postgres@localhost:15433/public_pool` (override
//! with `BP_PG_URL`). Tests skip cleanly via `eprintln!` + early return
//! if the instance isn't reachable.
//!
//! Each test wraps its writes in a transaction it then ROLLBACKs, so
//! parallel test runs don't interfere and the production-schema-loaded
//! container stays clean.
//!
//! Spin up the container with:
//!
//! ```sh
//! docker run -d --name blitzpool-rust-pg --rm \
//!     -p 15433:5432 \
//!     -e POSTGRES_DB=public_pool \
//!     -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
//!     postgres:18
//! ```
//! and load `db/schema.sql` into it.

use bp_db::{
    bulk_insert_pplns_payout_history, bulk_update_pplns_last_accepted_share_at,
    bulk_upsert_pplns_balances, BalanceUpsert, PayoutHistoryInsert, TouchUpdate,
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

#[tokio::test]
async fn bulk_upsert_balances_inserts_then_updates_absolute() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");

    // First write — three new rows.
    let initial = vec![
        BalanceUpsert {
            address: "test_bulk_a".to_string(),
            balance_sats: 5_000,
            total_paid_sats: 100_000,
            updated_at_ms: 1_700_000_000_000,
        },
        BalanceUpsert {
            address: "test_bulk_b".to_string(),
            balance_sats: -2_000,
            total_paid_sats: 50_000,
            updated_at_ms: 1_700_000_000_000,
        },
        BalanceUpsert {
            address: "test_bulk_c".to_string(),
            balance_sats: 0,
            total_paid_sats: 0,
            updated_at_ms: 1_700_000_000_000,
        },
    ];
    let inserted = bulk_upsert_pplns_balances(&mut *tx, &initial)
        .await
        .expect("upsert ok");
    assert_eq!(inserted, 3, "expected 3 inserts on first call");

    // Second write — absolute overwrite, including a signed flip.
    let update = vec![
        BalanceUpsert {
            address: "test_bulk_a".to_string(),
            balance_sats: -1_500, // flip credit → debit
            total_paid_sats: 105_000,
            updated_at_ms: 1_700_000_060_000,
        },
        BalanceUpsert {
            address: "test_bulk_b".to_string(),
            balance_sats: 0, // settled
            total_paid_sats: 52_000,
            updated_at_ms: 1_700_000_060_000,
        },
    ];
    let affected = bulk_upsert_pplns_balances(&mut *tx, &update)
        .await
        .expect("update ok");
    assert_eq!(affected, 2, "expected 2 upserts on second call");

    // Verify final state via raw SELECT inside the same TX.
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        r#"SELECT address, "balanceSats", "totalPaidSats"
           FROM pplns_balance
           WHERE address IN ('test_bulk_a', 'test_bulk_b', 'test_bulk_c')
           ORDER BY address"#,
    )
    .fetch_all(&mut *tx)
    .await
    .expect("select ok");

    assert_eq!(rows.len(), 3);
    // a: flipped to -1500 / 105k paid
    assert_eq!(rows[0], ("test_bulk_a".to_string(), -1_500, 105_000));
    // b: settled to 0 / 52k paid
    assert_eq!(rows[1], ("test_bulk_b".to_string(), 0, 52_000));
    // c: untouched
    assert_eq!(rows[2], ("test_bulk_c".to_string(), 0, 0));

    tx.rollback().await.expect("rollback ok");
}

#[tokio::test]
async fn bulk_upsert_balances_empty_is_noop() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let affected = bulk_upsert_pplns_balances(&mut *tx, &[])
        .await
        .expect("empty ok");
    assert_eq!(affected, 0);
    tx.rollback().await.expect("rollback ok");
}

#[tokio::test]
async fn bulk_update_last_accepted_share_at_skips_missing_rows() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");

    // Seed one row; the second address is intentionally absent.
    let seed = vec![BalanceUpsert {
        address: "test_touch_a".to_string(),
        balance_sats: 1_000,
        total_paid_sats: 0,
        updated_at_ms: 1_700_000_000_000,
    }];
    bulk_upsert_pplns_balances(&mut *tx, &seed)
        .await
        .expect("seed ok");

    let touches = vec![
        TouchUpdate {
            address: "test_touch_a".to_string(),
            last_accepted_share_at_ms: 1_700_000_999_000,
        },
        TouchUpdate {
            address: "test_touch_nonexistent".to_string(),
            last_accepted_share_at_ms: 1_700_000_999_000,
        },
    ];
    let affected = bulk_update_pplns_last_accepted_share_at(&mut *tx, &touches)
        .await
        .expect("touch ok");
    // Only the existing row gets updated; the nonexistent address is a
    // silent no-op.
    assert_eq!(affected, 1);

    let row: (Option<i64>,) = sqlx::query_as(
        r#"SELECT "lastAcceptedShareAt" FROM pplns_balance WHERE address = 'test_touch_a'"#,
    )
    .fetch_one(&mut *tx)
    .await
    .expect("select ok");
    assert_eq!(row.0, Some(1_700_000_999_000));

    tx.rollback().await.expect("rollback ok");
}

#[tokio::test]
async fn bulk_insert_payout_history_idempotent_on_unique_collision() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");

    let rows = vec![
        PayoutHistoryInsert {
            block_height: 9_999_001,
            address: "test_hist_a".to_string(),
            paid_sats: 100_000,
            percent: 50.0,
            row_type: "coinbase".to_string(),
            created_at_ms: 1_700_000_000_000,
        },
        PayoutHistoryInsert {
            block_height: 9_999_001,
            address: "test_hist_b".to_string(),
            paid_sats: 50_000,
            percent: 25.0,
            row_type: "coinbase".to_string(),
            created_at_ms: 1_700_000_000_000,
        },
        PayoutHistoryInsert {
            block_height: 9_999_001,
            address: "test_hist_c".to_string(),
            paid_sats: 0,
            percent: 0.0,
            row_type: "pending".to_string(),
            created_at_ms: 1_700_000_000_000,
        },
    ];

    let first = bulk_insert_pplns_payout_history(&mut *tx, &rows)
        .await
        .expect("first insert ok");
    assert_eq!(first, 3, "all three rows inserted on first call");

    // Re-run the same batch — UNIQUE (blockHeight, address) collides
    // for all three. DO NOTHING means rows_affected is 0.
    let second = bulk_insert_pplns_payout_history(&mut *tx, &rows)
        .await
        .expect("second insert ok");
    assert_eq!(
        second, 0,
        "replay should insert nothing (idempotent on UNIQUE collision)"
    );

    // Verify exactly 3 rows actually landed in the table.
    let count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_payout_history WHERE "blockHeight" = $1"#)
            .bind(9_999_001_i32)
            .fetch_one(&mut *tx)
            .await
            .expect("count ok");
    assert_eq!(count.0, 3);

    tx.rollback().await.expect("rollback ok");
}

#[tokio::test]
async fn bulk_insert_payout_history_handles_negative_block_height_for_sweep() {
    // The dust-sweep cron writes audit rows with synthetic
    // `blockHeight = -unix_seconds` so the UNIQUE constraint catches
    // intra-sweep replays without colliding with real blocks. Verify the
    // primitive accepts negative heights.
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");

    let rows = vec![PayoutHistoryInsert {
        block_height: -1_700_000_000,
        address: "test_sweep_a".to_string(),
        paid_sats: -2_500,
        percent: 0.0,
        row_type: "dust-sweep".to_string(),
        created_at_ms: 1_700_000_000_000,
    }];
    let n = bulk_insert_pplns_payout_history(&mut *tx, &rows)
        .await
        .expect("ok");
    assert_eq!(n, 1);

    tx.rollback().await.expect("rollback ok");
}

#[tokio::test]
async fn apply_distribution_tx_atomicity_rollback_undoes_both_writes() {
    // Verifies the contract bp-pplns-engine will rely on: a TX that
    // wraps a balance-upsert + a history-insert rolls BOTH back if the
    // caller aborts.
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");

    bulk_upsert_pplns_balances(
        &mut *tx,
        &[BalanceUpsert {
            address: "test_tx_atomic".to_string(),
            balance_sats: 1234,
            total_paid_sats: 5678,
            updated_at_ms: 1_700_000_000_000,
        }],
    )
    .await
    .expect("upsert ok");

    bulk_insert_pplns_payout_history(
        &mut *tx,
        &[PayoutHistoryInsert {
            block_height: 9_999_999,
            address: "test_tx_atomic".to_string(),
            paid_sats: 1234,
            percent: 0.5,
            row_type: "coinbase".to_string(),
            created_at_ms: 1_700_000_000_000,
        }],
    )
    .await
    .expect("history ok");

    tx.rollback().await.expect("rollback ok");

    // Outside the TX: neither write should be visible.
    let balance_count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_balance WHERE address = 'test_tx_atomic'"#)
            .fetch_one(&pool)
            .await
            .expect("count ok");
    assert_eq!(balance_count.0, 0, "balance write was rolled back");

    let history_count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_payout_history WHERE "blockHeight" = 9999999"#,
    )
    .fetch_one(&pool)
    .await
    .expect("count ok");
    assert_eq!(history_count.0, 0, "history write was rolled back");
}
