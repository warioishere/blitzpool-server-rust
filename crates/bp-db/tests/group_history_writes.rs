// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `delete_pplns_group_block_history_for_group`
//! — the dissolve-cleanup helper.

use bp_db::{
    bulk_insert_pplns_group_block_history, delete_pplns_group_block_history_for_group,
    GroupPayoutHistoryInsert,
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
