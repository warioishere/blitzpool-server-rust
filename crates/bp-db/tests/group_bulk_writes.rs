// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::needless_return)]

//! Integration tests for the Group-Solo payout-history write path, against
//! the local test PG; each test rolls its transaction back.

use bp_db::{bulk_insert_pplns_group_block_history, GroupPayoutHistoryInsert};
use uuid::Uuid;

/// Each test seeds a `pplns_group` row inside its TX so the group-keyed
/// rows it writes satisfy their FK. The TX rolls back at end so the
/// seeded group disappears too.
async fn seed_group_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    group_id: Uuid,
    creator: &str,
) {
    sqlx::query(
        r#"INSERT INTO pplns_group
             (id, name, "creatorAddress", "adminTokenHash", active,
              "createdAt", "updatedAt", "isPublic")
           VALUES ($1, 'test-group', $2, $3, true, 0, 0, false)"#,
    )
    .bind(group_id)
    .bind(creator)
    .bind(format!("hash-{group_id}"))
    .execute(&mut **tx)
    .await
    .expect("seed group");
}

#[tokio::test]
async fn bulk_insert_group_block_history_idempotent_on_unique() {
    let pool = match bp_test_support::connect_pg_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_id = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_id, "test_grp_hist_c").await;

    let rows = vec![
        GroupPayoutHistoryInsert {
            group_id,
            block_height: 9_998_001,
            address: "test_grp_h1".to_string(),
            paid_sats: 100_000,
            percent: 100.0,
            shares_in_round: 1_000,
            total_shares_in_round: 1_000,
            row_type: "coinbase".to_string(),
            created_at_ms: 1_700_000_000_000,
        },
        GroupPayoutHistoryInsert {
            group_id,
            block_height: 9_998_001,
            address: "test_grp_h2".to_string(),
            paid_sats: 0,
            percent: 0.0,
            shares_in_round: 0,
            total_shares_in_round: 1_000,
            row_type: "pending".to_string(),
            created_at_ms: 1_700_000_000_000,
        },
    ];

    let first = bulk_insert_pplns_group_block_history(&mut *tx, &rows)
        .await
        .unwrap();
    assert_eq!(first, 2);

    // Replay — same (groupId, blockHeight, address) collides; DO NOTHING.
    let replay = bulk_insert_pplns_group_block_history(&mut *tx, &rows)
        .await
        .unwrap();
    assert_eq!(replay, 0, "replay deduped via UNIQUE constraint");

    let count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = $2"#,
    )
    .bind(group_id)
    .bind(9_998_001_i32)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(count.0, 2);

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn update_group_last_reset_at_stamps_timestamp() {
    let pool = match bp_test_support::connect_pg_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_id = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_id, "test_grp_reset_c").await;

    let affected = bp_db::update_pplns_group_last_reset_at(&mut *tx, group_id, 1_700_000_999_000)
        .await
        .unwrap();
    assert_eq!(affected, 1);

    let row: (Option<i64>,) =
        sqlx::query_as(r#"SELECT "lastRoundResetAt" FROM pplns_group WHERE id = $1"#)
            .bind(group_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(row.0, Some(1_700_000_999_000));

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn apply_distribution_rollback_undoes_the_history_write() {
    // The contract `bp_group_solo_engine::history::apply_distribution`
    // relies on: a block's payout history commits as one unit or not at
    // all, so a redelivery never finds a half-written block.
    let pool = match bp_test_support::connect_pg_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_id = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_id, "test_grp_atomic_c").await;

    bulk_insert_pplns_group_block_history(
        &mut *tx,
        &[GroupPayoutHistoryInsert {
            group_id,
            block_height: 9_999_998,
            address: "test_grp_atomic_a".to_string(),
            paid_sats: 1234,
            percent: 100.0,
            shares_in_round: 100,
            total_shares_in_round: 100,
            row_type: "coinbase".to_string(),
            created_at_ms: 0,
        }],
    )
    .await
    .unwrap();

    tx.rollback().await.unwrap();

    // Outside TX: nothing visible.
    let history_count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history WHERE "blockHeight" = 9999998"#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(history_count.0, 0);
}
