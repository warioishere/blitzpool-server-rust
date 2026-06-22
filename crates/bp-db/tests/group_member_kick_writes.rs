// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for member-kick DB helpers:
//! - `add_pplns_group_balance_pending` (redistribute pending on kick)
//! - `delete_pplns_group_block_history_for_group` (dissolve cleanup)

use bp_common::AddressId;
use bp_db::{
    add_pplns_group_balance_pending, bulk_insert_pplns_group_block_history,
    bulk_upsert_pplns_group_balances, delete_pplns_group_block_history_for_group,
    find_group_balance, GroupBalanceUpsert, GroupPayoutHistoryInsert,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";
const ADDR_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const ADDR_B: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

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
            None
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            None
        }
    }
}

async fn seed_group_in_tx(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, group_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO pplns_group
             (id, name, "creatorAddress", "adminTokenHash", active,
              "createdAt", "updatedAt", "isPublic")
           VALUES ($1, $4, $2, $3, true, 0, 0, false)"#,
    )
    .bind(group_id)
    .bind(ADDR_A)
    .bind(format!("hash-{group_id}"))
    .bind(format!("test-kick-{group_id}"))
    .execute(&mut **tx)
    .await
    .expect("seed group");
}

// ── add_pplns_group_balance_pending ────────────────────────────────

#[tokio::test]
async fn add_pending_creates_row_when_none_exists() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_id = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_id).await;

    let addr = AddressId::new(ADDR_A.to_string()).unwrap();
    add_pplns_group_balance_pending(&mut *tx, &addr, group_id, 5000, 1_700_000_000_000)
        .await
        .expect("add_pending ok");

    let row = sqlx::query_as::<_, (i64,)>(
        r#"SELECT "pendingSats" FROM pplns_group_balance WHERE address = $1 AND "groupId" = $2"#,
    )
    .bind(ADDR_A)
    .bind(group_id)
    .fetch_one(&mut *tx)
    .await
    .expect("fetch ok");
    assert_eq!(row.0, 5000);

    tx.rollback().await.expect("rollback ok");
}

#[tokio::test]
async fn add_pending_increments_existing_row() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_id = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_id).await;

    // Seed initial balance of 10_000
    bulk_upsert_pplns_group_balances(
        &mut *tx,
        &[GroupBalanceUpsert {
            address: ADDR_B.to_string(),
            group_id,
            pending_sats: 10_000,
            total_paid_sats: 50_000,
            updated_at_ms: 1_700_000_000_000,
            last_accepted_share_at_ms: Some(1_700_000_000_000),
        }],
    )
    .await
    .expect("seed ok");

    let addr = AddressId::new(ADDR_B.to_string()).unwrap();
    add_pplns_group_balance_pending(&mut *tx, &addr, group_id, 3_000, 1_700_000_001_000)
        .await
        .expect("add_pending ok");

    let row = sqlx::query_as::<_, (i64, i64)>(
        r#"SELECT "pendingSats", "totalPaidSats" FROM pplns_group_balance
           WHERE address = $1 AND "groupId" = $2"#,
    )
    .bind(ADDR_B)
    .bind(group_id)
    .fetch_one(&mut *tx)
    .await
    .expect("fetch ok");
    assert_eq!(row.0, 13_000, "10_000 + 3_000 expected");
    assert_eq!(row.1, 50_000, "totalPaidSats unchanged");

    tx.rollback().await.expect("rollback ok");
}

// ── delete_pplns_group_block_history_for_group ────────────────────

#[tokio::test]
async fn delete_history_for_group_removes_all_rows() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_id = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_id).await;

    bulk_insert_pplns_group_block_history(
        &mut *tx,
        &[
            GroupPayoutHistoryInsert {
                group_id,
                block_height: 999_001,
                address: ADDR_A.to_string(),
                paid_sats: 100_000,
                percent: 50.0,
                shares_in_round: 100,
                total_shares_in_round: 200,
                row_type: "coinbase".to_string(),
                created_at_ms: 1_700_000_000_000,
            },
            GroupPayoutHistoryInsert {
                group_id,
                block_height: 999_002,
                address: ADDR_B.to_string(),
                paid_sats: 80_000,
                percent: 40.0,
                shares_in_round: 80,
                total_shares_in_round: 200,
                row_type: "coinbase".to_string(),
                created_at_ms: 1_700_000_000_001,
            },
        ],
    )
    .await
    .expect("insert history ok");

    let n = delete_pplns_group_block_history_for_group(&mut *tx, group_id)
        .await
        .expect("delete ok");
    assert!(n >= 2, "at least 2 rows should be deleted, got {n}");

    let count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_group_block_history WHERE "groupId" = $1"#)
            .bind(group_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(count.0, 0, "all history rows should be deleted");

    tx.rollback().await.expect("rollback ok");
}

#[tokio::test]
async fn delete_history_for_group_is_isolated_to_group() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_a = Uuid::new_v4();
    let group_b = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_a).await;
    seed_group_in_tx(&mut tx, group_b).await;

    bulk_insert_pplns_group_block_history(
        &mut *tx,
        &[GroupPayoutHistoryInsert {
            group_id: group_a,
            block_height: 888_001,
            address: ADDR_A.to_string(),
            paid_sats: 1_000,
            percent: 100.0,
            shares_in_round: 10,
            total_shares_in_round: 10,
            row_type: "coinbase".to_string(),
            created_at_ms: 1_700_000_000_000,
        }],
    )
    .await
    .expect("insert group_a ok");

    bulk_insert_pplns_group_block_history(
        &mut *tx,
        &[GroupPayoutHistoryInsert {
            group_id: group_b,
            block_height: 888_002,
            address: ADDR_B.to_string(),
            paid_sats: 2_000,
            percent: 100.0,
            shares_in_round: 10,
            total_shares_in_round: 10,
            row_type: "coinbase".to_string(),
            created_at_ms: 1_700_000_000_001,
        }],
    )
    .await
    .expect("insert group_b ok");

    delete_pplns_group_block_history_for_group(&mut *tx, group_a)
        .await
        .expect("delete group_a ok");

    let count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_group_block_history WHERE "groupId" = $1"#)
            .bind(group_b)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(count.0, 1, "group_b row should still exist");

    tx.rollback().await.expect("rollback ok");
}

// silence unused import warning if find_group_balance isn't used by all test paths
#[allow(dead_code)]
fn _ensure_imports_resolve(_: Option<bp_db::PplnsGroupBalanceRow>) {
    let _ = find_group_balance;
}
