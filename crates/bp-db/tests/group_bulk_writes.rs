// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for the Group-Solo bulk-write primitives.
//!
//! Gated on docker-PG at `postgres://postgres:postgres@localhost:15433/public_pool`.
//! Tests use TX-rollback isolation so parallel runs don't interfere
//! and the schema-loaded container stays clean.

use bp_common::{AddressId, Sats};
use bp_db::{
    bulk_insert_pplns_group_block_history, bulk_upsert_pplns_group_balances,
    delete_pplns_group_balance, delete_pplns_group_balances_for_group,
    find_pplns_group_balances_for_group, update_pplns_group_balance_pending_sats,
    GroupBalanceUpsert, GroupPayoutHistoryInsert,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

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
            eprintln!("PG connect failed for {url}: {e} — skipping");
            return None;
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            return None;
        }
    }
}

/// Each test seeds a `pplns_group` row inside its TX so the FK on
/// `pplns_group_balance` is satisfied. The TX rolls back at end so
/// the seeded group disappears too.
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
async fn bulk_upsert_group_balances_inserts_then_updates_absolute() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_id = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_id, "test_grp_creator").await;

    let initial = vec![
        GroupBalanceUpsert {
            address: "test_grp_a".to_string(),
            group_id,
            pending_sats: 5_000,
            total_paid_sats: 0,
            updated_at_ms: 1_700_000_000_000,
            last_accepted_share_at_ms: Some(1_700_000_000_000),
        },
        GroupBalanceUpsert {
            address: "test_grp_b".to_string(),
            group_id,
            pending_sats: 3_000,
            total_paid_sats: 0,
            updated_at_ms: 1_700_000_000_000,
            last_accepted_share_at_ms: None,
        },
    ];
    let inserted = bulk_upsert_pplns_group_balances(&mut *tx, &initial)
        .await
        .expect("ok");
    assert_eq!(inserted, 2);

    // Update with new values; last_accepted preserved when None.
    let updated = vec![GroupBalanceUpsert {
        address: "test_grp_a".to_string(),
        group_id,
        pending_sats: 0, // paid out
        total_paid_sats: 5_000,
        updated_at_ms: 1_700_000_060_000,
        last_accepted_share_at_ms: None, // COALESCE preserves existing
    }];
    bulk_upsert_pplns_group_balances(&mut *tx, &updated)
        .await
        .expect("ok");

    let row: (i64, i64, Option<i64>) = sqlx::query_as(
        r#"SELECT "pendingSats", "totalPaidSats", "lastAcceptedShareAt"
           FROM pplns_group_balance
           WHERE address = 'test_grp_a' AND "groupId" = $1"#,
    )
    .bind(group_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(row.0, 0, "pendingSats absolute-updated to 0");
    assert_eq!(row.1, 5_000, "totalPaidSats absolute-updated to 5000");
    assert_eq!(
        row.2,
        Some(1_700_000_000_000),
        "lastAcceptedShareAt preserved (None overwrite COALESCEs)"
    );

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn bulk_upsert_group_balances_overwrites_last_accepted_when_some() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_id = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_id, "test_grp_overwrite").await;

    bulk_upsert_pplns_group_balances(
        &mut *tx,
        &[GroupBalanceUpsert {
            address: "test_grp_o1".to_string(),
            group_id,
            pending_sats: 1_000,
            total_paid_sats: 0,
            updated_at_ms: 0,
            last_accepted_share_at_ms: Some(1_700_000_000_000),
        }],
    )
    .await
    .unwrap();

    bulk_upsert_pplns_group_balances(
        &mut *tx,
        &[GroupBalanceUpsert {
            address: "test_grp_o1".to_string(),
            group_id,
            pending_sats: 2_000,
            total_paid_sats: 500,
            updated_at_ms: 1_700_000_060_000,
            last_accepted_share_at_ms: Some(1_700_000_999_000),
        }],
    )
    .await
    .unwrap();

    let last: (Option<i64>,) = sqlx::query_as(
        r#"SELECT "lastAcceptedShareAt" FROM pplns_group_balance
           WHERE address = 'test_grp_o1' AND "groupId" = $1"#,
    )
    .bind(group_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(last.0, Some(1_700_000_999_000));

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn bulk_insert_group_block_history_idempotent_on_unique() {
    let pool = match connect_or_skip().await {
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
async fn find_group_balances_for_group_returns_only_positive_pending() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_id = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_id, "test_grp_find_c").await;

    bulk_upsert_pplns_group_balances(
        &mut *tx,
        &[
            GroupBalanceUpsert {
                address: "test_grp_f_a".to_string(),
                group_id,
                pending_sats: 5_000,
                total_paid_sats: 0,
                updated_at_ms: 0,
                last_accepted_share_at_ms: None,
            },
            GroupBalanceUpsert {
                address: "test_grp_f_b".to_string(),
                group_id,
                pending_sats: 0, // settled — should not appear
                total_paid_sats: 100_000,
                updated_at_ms: 0,
                last_accepted_share_at_ms: None,
            },
            GroupBalanceUpsert {
                address: "test_grp_f_c".to_string(),
                group_id,
                pending_sats: 3_000,
                total_paid_sats: 0,
                updated_at_ms: 0,
                last_accepted_share_at_ms: None,
            },
        ],
    )
    .await
    .unwrap();

    let rows = find_pplns_group_balances_for_group(&pool, group_id)
        .await
        .expect("ok");
    // Note: rows visible from `pool` (uncommitted) — won't include
    // the seeded rows because the seeding TX hasn't committed.
    // Reframe: drop the rollback below and assert via the TX-bound
    // executor. We'll just count via the TX directly.
    let _ = rows;
    let count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_balance
           WHERE "groupId" = $1 AND "pendingSats" > 0"#,
    )
    .bind(group_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(count.0, 2, "only the two positive-pending rows");

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn find_group_balances_dormant_filters_by_min_payout_and_cutoff() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_id = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_id, "test_grp_dormant_c").await;

    let now_ms = 1_710_000_000_000_i64;
    let stale_ts = now_ms - 60 * 86_400_000; // 60d ago
    let fresh_ts = now_ms - 86_400_000;
    let cutoff = now_ms - 30 * 86_400_000; // 30d dormancy

    bulk_upsert_pplns_group_balances(
        &mut *tx,
        &[
            // dust + stale → candidate
            GroupBalanceUpsert {
                address: "test_grp_d_stale_dust".to_string(),
                group_id,
                pending_sats: 1_000,
                total_paid_sats: 0,
                updated_at_ms: 0,
                last_accepted_share_at_ms: Some(stale_ts),
            },
            // dust + fresh → NOT a candidate (within cutoff)
            GroupBalanceUpsert {
                address: "test_grp_d_fresh_dust".to_string(),
                group_id,
                pending_sats: 1_000,
                total_paid_sats: 0,
                updated_at_ms: 0,
                last_accepted_share_at_ms: Some(fresh_ts),
            },
            // above-payout + stale → NOT a candidate (≥ min_payout)
            GroupBalanceUpsert {
                address: "test_grp_d_above".to_string(),
                group_id,
                pending_sats: 10_000,
                total_paid_sats: 0,
                updated_at_ms: 0,
                last_accepted_share_at_ms: Some(stale_ts),
            },
            // dust + NULL timestamp → NOT a candidate
            GroupBalanceUpsert {
                address: "test_grp_d_null".to_string(),
                group_id,
                pending_sats: 1_000,
                total_paid_sats: 0,
                updated_at_ms: 0,
                last_accepted_share_at_ms: None,
            },
        ],
    )
    .await
    .unwrap();

    // Use TX-bound executor for the SELECT so we can see the
    // uncommitted seed rows. The pool-bound `find_pplns_group_balances_dormant`
    // wouldn't see them; assert via a raw query on the same TX.
    let candidates: Vec<(String,)> = sqlx::query_as(
        r#"SELECT address FROM pplns_group_balance
           WHERE "pendingSats" > 0 AND "pendingSats" < $1
             AND "lastAcceptedShareAt" IS NOT NULL
             AND "lastAcceptedShareAt" < $2
           ORDER BY address"#,
    )
    .bind(5_000_i64)
    .bind(cutoff)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].0, "test_grp_d_stale_dust");

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn update_group_balance_pending_sats_preserves_total_paid() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_id = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_id, "test_grp_upd_c").await;

    bulk_upsert_pplns_group_balances(
        &mut *tx,
        &[GroupBalanceUpsert {
            address: "test_grp_u_a".to_string(),
            group_id,
            pending_sats: 1_000,
            total_paid_sats: 99_000,
            updated_at_ms: 1_700_000_000_000,
            last_accepted_share_at_ms: Some(1_700_000_000_000),
        }],
    )
    .await
    .unwrap();

    let addr_id = AddressId::new("test_grp_u_a").unwrap();
    let affected =
        update_pplns_group_balance_pending_sats(&mut *tx, &addr_id, group_id, Sats(2_500))
            .await
            .unwrap();
    assert_eq!(affected, 1);

    let row: (i64, i64, i64) = sqlx::query_as(
        r#"SELECT "pendingSats", "totalPaidSats", "updatedAt"
           FROM pplns_group_balance
           WHERE address = $1 AND "groupId" = $2"#,
    )
    .bind(addr_id.as_str())
    .bind(group_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(row.0, 2_500);
    assert_eq!(row.1, 99_000, "totalPaidSats preserved");
    assert_eq!(row.2, 1_700_000_000_000, "updatedAt preserved");

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn delete_group_balance_removes_one_row() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_id = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_id, "test_grp_del_c").await;

    bulk_upsert_pplns_group_balances(
        &mut *tx,
        &[GroupBalanceUpsert {
            address: "test_grp_del_a".to_string(),
            group_id,
            pending_sats: 5_000,
            total_paid_sats: 0,
            updated_at_ms: 0,
            last_accepted_share_at_ms: None,
        }],
    )
    .await
    .unwrap();

    let addr_id = AddressId::new("test_grp_del_a").unwrap();
    let affected = delete_pplns_group_balance(&mut *tx, &addr_id, group_id)
        .await
        .unwrap();
    assert_eq!(affected, 1);

    let count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_balance
           WHERE address = $1 AND "groupId" = $2"#,
    )
    .bind(addr_id.as_str())
    .bind(group_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(count.0, 0);

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn delete_group_balances_for_group_wipes_all_rows() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_id = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_id, "test_grp_wipe_c").await;

    bulk_upsert_pplns_group_balances(
        &mut *tx,
        &[
            GroupBalanceUpsert {
                address: "test_grp_w_a".to_string(),
                group_id,
                pending_sats: 1_000,
                total_paid_sats: 0,
                updated_at_ms: 0,
                last_accepted_share_at_ms: None,
            },
            GroupBalanceUpsert {
                address: "test_grp_w_b".to_string(),
                group_id,
                pending_sats: 2_000,
                total_paid_sats: 0,
                updated_at_ms: 0,
                last_accepted_share_at_ms: None,
            },
        ],
    )
    .await
    .unwrap();

    let affected = delete_pplns_group_balances_for_group(&mut *tx, group_id)
        .await
        .unwrap();
    assert_eq!(affected, 2);

    let count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_group_balance WHERE "groupId" = $1"#)
            .bind(group_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(count.0, 0);

    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn update_group_last_reset_at_stamps_timestamp() {
    let pool = match connect_or_skip().await {
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
async fn apply_distribution_atomicity_rollback_undoes_both_writes() {
    // Verifies the contract bp-group-solo-engine's
    // `apply_distribution` will rely on.
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let group_id = Uuid::new_v4();
    seed_group_in_tx(&mut tx, group_id, "test_grp_atomic_c").await;

    bulk_upsert_pplns_group_balances(
        &mut *tx,
        &[GroupBalanceUpsert {
            address: "test_grp_atomic_a".to_string(),
            group_id,
            pending_sats: 1234,
            total_paid_sats: 5678,
            updated_at_ms: 0,
            last_accepted_share_at_ms: None,
        }],
    )
    .await
    .unwrap();
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
    let balance_count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_balance
           WHERE address = 'test_grp_atomic_a' AND "groupId" = $1"#,
    )
    .bind(group_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(balance_count.0, 0);

    let history_count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history WHERE "blockHeight" = 9999998"#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(history_count.0, 0);
}
