// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `bp-group-solo-engine::ledger::apply_distribution`
//! against docker-PG.
//!
//! Each test seeds + tears down its own `pplns_group` row so parallel
//! runs don't interfere. The engine's `apply_distribution` commits
//! through a TX, so cleanup uses DELETE-by-groupId at end (no TX-rollback
//! possible — engine commits internally).

use bp_common::{AddressId, Sats};
use bp_group_solo_engine::ledger::{
    apply_distribution, coinbase_row, pending_row, AuditRow, BalanceWrite, GroupPayoutRowType,
};
use bp_pplns::CoinbaseDistributionEntry;
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

async fn connect_or_skip() -> Option<PgPool> {
    let url = std::env::var("BP_PG_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(4)
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

async fn seed_group(pool: &PgPool, group_id: Uuid, prefix: &str) {
    let creator = format!("{prefix}creator");
    // Group `name` has a UNIQUE constraint pool-wide — include the
    // UUID so parallel tests don't collide.
    let name = format!("test-group-{group_id}");
    sqlx::query(
        r#"INSERT INTO pplns_group
             (id, name, "creatorAddress", "adminTokenHash", active,
              "createdAt", "updatedAt", "isPublic")
           VALUES ($1, $2, $3, $4, true, 0, 0, false)"#,
    )
    .bind(group_id)
    .bind(&name)
    .bind(&creator)
    .bind(format!("hash-{group_id}"))
    .execute(pool)
    .await
    .expect("seed group");
}

async fn cleanup_group(pool: &PgPool, group_id: Uuid) {
    let _ = sqlx::query(r#"DELETE FROM pplns_group_block_history WHERE "groupId" = $1"#)
        .bind(group_id)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM pplns_group_balance WHERE "groupId" = $1"#)
        .bind(group_id)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM pplns_group WHERE id = $1"#)
        .bind(group_id)
        .execute(pool)
        .await;
}

#[tokio::test]
async fn apply_distribution_writes_history_and_balance() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let group_id = Uuid::new_v4();
    let prefix = "test_grp_ledger_apply_";
    seed_group(&pool, group_id, prefix).await;

    let addr_a = AddressId::new(format!("{prefix}a")).unwrap();
    let addr_b = AddressId::new(format!("{prefix}b")).unwrap();
    let entry_a = CoinbaseDistributionEntry {
        address: addr_a.clone(),
        percent: 60.0,
        sats: Sats(187_500_000),
    };
    let entry_b = CoinbaseDistributionEntry {
        address: addr_b.clone(),
        percent: 40.0,
        sats: Sats(125_000_000),
    };
    let rows = vec![
        coinbase_row(&entry_a, 600, 1_000),
        coinbase_row(&entry_b, 400, 1_000),
    ];
    let balances = vec![
        BalanceWrite {
            address: addr_a.clone(),
            pending_sats: Sats(0),
            total_paid_sats: Sats(187_500_000),
        },
        BalanceWrite {
            address: addr_b.clone(),
            pending_sats: Sats(0),
            total_paid_sats: Sats(125_000_000),
        },
    ];

    let result = apply_distribution(
        &pool,
        group_id,
        9_996_001,
        &rows,
        &balances,
        1_700_000_000_000,
    )
    .await
    .expect("ok");
    assert_eq!(result.history_inserted, 2);
    assert_eq!(result.balances_affected, 2);

    let h_count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = 9996001"#,
    )
    .bind(group_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(h_count.0, 2);

    let bal_count: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM pplns_group_balance WHERE "groupId" = $1"#)
            .bind(group_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bal_count.0, 2);

    cleanup_group(&pool, group_id).await;
}

#[tokio::test]
async fn apply_distribution_replay_idempotent_via_unique() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let group_id = Uuid::new_v4();
    let prefix = "test_grp_ledger_replay_";
    seed_group(&pool, group_id, prefix).await;

    let addr = AddressId::new(format!("{prefix}miner")).unwrap();
    let entry = CoinbaseDistributionEntry {
        address: addr.clone(),
        percent: 100.0,
        sats: Sats(312_500_000),
    };
    let rows = vec![coinbase_row(&entry, 1_000, 1_000)];
    let balances = vec![BalanceWrite {
        address: addr.clone(),
        pending_sats: Sats(0),
        total_paid_sats: Sats(312_500_000),
    }];

    let first = apply_distribution(
        &pool,
        group_id,
        9_996_002,
        &rows,
        &balances,
        1_700_000_000_000,
    )
    .await
    .unwrap();
    assert_eq!(first.history_inserted, 1);

    let replay = apply_distribution(
        &pool,
        group_id,
        9_996_002,
        &rows,
        &balances,
        1_700_000_060_000,
    )
    .await
    .unwrap();
    assert_eq!(
        replay.history_inserted, 0,
        "replay deduped via UNIQUE constraint"
    );
    // Replay must NOT re-touch balances: the engine computes
    // totalPaidSats = existing + this-block, so re-applying a duplicate
    // block would double-count. apply_distribution gates the upsert behind
    // history_inserted > 0 (see 72d927f), returning 0 on a replay.
    assert_eq!(
        replay.balances_affected, 0,
        "replay skips the balance upsert (anti-double-count)"
    );

    let h_count: (i64,) = sqlx::query_as(
        r#"SELECT count(*) FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = 9996002"#,
    )
    .bind(group_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(h_count.0, 1);

    cleanup_group(&pool, group_id).await;
}

#[tokio::test]
async fn apply_distribution_mixed_coinbase_and_pending_rows() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let group_id = Uuid::new_v4();
    let prefix = "test_grp_ledger_mixed_";
    seed_group(&pool, group_id, prefix).await;

    let addr_paid = AddressId::new(format!("{prefix}paid")).unwrap();
    let addr_sub_dust = AddressId::new(format!("{prefix}sub_dust")).unwrap();
    let entry = CoinbaseDistributionEntry {
        address: addr_paid.clone(),
        percent: 100.0,
        sats: Sats(310_000_000),
    };
    let rows = vec![
        coinbase_row(&entry, 700, 1_000),
        pending_row(addr_sub_dust.clone(), Sats(500)), // below dust accumulates
    ];
    let balances = vec![
        BalanceWrite {
            address: addr_paid.clone(),
            pending_sats: Sats(0),
            total_paid_sats: Sats(310_000_000),
        },
        BalanceWrite {
            address: addr_sub_dust.clone(),
            pending_sats: Sats(500),
            total_paid_sats: Sats(0),
        },
    ];

    let result = apply_distribution(
        &pool,
        group_id,
        9_996_003,
        &rows,
        &balances,
        1_700_000_000_000,
    )
    .await
    .unwrap();
    assert_eq!(result.history_inserted, 2);

    // Verify pending row has rowType='pending'.
    let row_types: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT address, "rowType" FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = 9996003 ORDER BY address"#,
    )
    .bind(group_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    let lookup: std::collections::HashMap<String, String> = row_types.into_iter().collect();
    assert_eq!(lookup[addr_paid.as_str()], "coinbase");
    assert_eq!(lookup[addr_sub_dust.as_str()], "pending");

    // Verify sub-dust balance is non-negative (Group-Solo invariant).
    let bal: (i64,) = sqlx::query_as(
        r#"SELECT "pendingSats" FROM pplns_group_balance
           WHERE "groupId" = $1 AND address = $2"#,
    )
    .bind(group_id)
    .bind(addr_sub_dust.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(bal.0, 500);
    assert!(bal.0 >= 0, "Group-Solo pendingSats is unsigned");

    cleanup_group(&pool, group_id).await;
}

#[tokio::test]
async fn apply_distribution_stamps_last_accepted_share_at() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let group_id = Uuid::new_v4();
    let prefix = "test_grp_ledger_lastat_";
    seed_group(&pool, group_id, prefix).await;

    let addr = AddressId::new(format!("{prefix}miner")).unwrap();
    let entry = CoinbaseDistributionEntry {
        address: addr.clone(),
        percent: 100.0,
        sats: Sats(312_500_000),
    };
    let now_ms = 1_700_000_999_000;
    let _ = apply_distribution(
        &pool,
        group_id,
        9_996_004,
        &[coinbase_row(&entry, 1, 1)],
        &[BalanceWrite {
            address: addr.clone(),
            pending_sats: Sats(0),
            total_paid_sats: Sats(312_500_000),
        }],
        now_ms,
    )
    .await
    .unwrap();

    let last_at: (Option<i64>,) = sqlx::query_as(
        r#"SELECT "lastAcceptedShareAt" FROM pplns_group_balance
           WHERE "groupId" = $1 AND address = $2"#,
    )
    .bind(group_id)
    .bind(addr.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        last_at.0,
        Some(now_ms),
        "block-found stamp lastAcceptedShareAt"
    );

    cleanup_group(&pool, group_id).await;
}

#[tokio::test]
async fn apply_distribution_persists_share_counts_in_history() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let group_id = Uuid::new_v4();
    let prefix = "test_grp_ledger_shares_";
    seed_group(&pool, group_id, prefix).await;

    let addr = AddressId::new(format!("{prefix}miner")).unwrap();
    let entry = CoinbaseDistributionEntry {
        address: addr.clone(),
        percent: 75.0,
        sats: Sats(234_375_000),
    };
    let rows = vec![AuditRow {
        address: addr.clone(),
        paid_sats: Sats(234_375_000),
        percent: 75.0,
        shares_in_round: 750,
        total_shares_in_round: 1_000,
        row_type: GroupPayoutRowType::Coinbase,
    }];
    let balances = vec![BalanceWrite {
        address: addr.clone(),
        pending_sats: Sats(0),
        total_paid_sats: Sats(234_375_000),
    }];

    let _ = apply_distribution(
        &pool,
        group_id,
        9_996_005,
        &rows,
        &balances,
        1_700_000_000_000,
    )
    .await
    .unwrap();
    let _ = entry; // suppress unused if test ever drops the entry build

    let counts: (i64, i64) = sqlx::query_as(
        r#"SELECT "sharesInRound", "totalSharesInRound"
           FROM pplns_group_block_history
           WHERE "groupId" = $1 AND "blockHeight" = 9996005"#,
    )
    .bind(group_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(counts.0, 750);
    assert_eq!(counts.1, 1_000);

    cleanup_group(&pool, group_id).await;
}
