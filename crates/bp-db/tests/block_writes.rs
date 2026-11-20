// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! Integration tests for found-block persistence and for
//! `payout_recorded_at_height`.

use bp_common::MiningMode;
use bp_db::{find_found_blocks, found_block_at_height, insert_found_block, FoundBlockInsert};
use sqlx::{postgres::PgPoolOptions, PgPool};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/blitzpool";

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

async fn cleanup(pool: &PgPool, miner_address: &str) {
    sqlx::query(r#"DELETE FROM blocks_entity WHERE "minerAddress" = $1"#)
        .bind(miner_address)
        .execute(pool)
        .await
        .expect("cleanup delete");
}

#[tokio::test]
async fn insert_persists_all_columns() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    const ADDR: &str = "bc1qblockwritetest0001";
    cleanup(&pool, ADDR).await;

    insert_found_block(
        &pool,
        FoundBlockInsert {
            height: 840_001,
            miner_address: ADDR,
            worker: "rig0.worker1",
            session_id: "ab12cd34",
            block_data: "deadbeef01020304",
            mode: Some(MiningMode::GroupSolo),
        },
    )
    .await
    .expect("insert_found_block");

    // Read back via the public find_found_blocks helper and locate the test row.
    let rows = find_found_blocks(&pool).await.expect("find_found_blocks");
    let row = rows
        .iter()
        .find(|r| r.miner_address == ADDR)
        .expect("inserted row not found");

    assert_eq!(row.height, 840_001);
    assert_eq!(row.miner_address, ADDR);
    assert_eq!(row.worker, "rig0.worker1");
    assert_eq!(row.session_id, "ab12cd34");
    let at_height = found_block_at_height(&pool, 840_001)
        .await
        .expect("found_block_at_height")
        .expect("a row at the height");
    assert_eq!(at_height.miner_address, ADDR);
    assert_eq!(
        at_height.mode,
        Some(MiningMode::GroupSolo),
        "the mode reads back"
    );

    cleanup(&pool, ADDR).await;
}

#[tokio::test]
async fn insert_multiple_rows_same_height() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    const ADDR: &str = "bc1qblockwritetest0002";
    cleanup(&pool, ADDR).await;

    // Two blocks at one height (two headers, as a reorg makes) are two rows;
    // the same block found twice (a redelivery) stays one.
    for (i, header) in ["aabbccdd", "eeff0011", "aabbccdd"].into_iter().enumerate() {
        insert_found_block(
            &pool,
            FoundBlockInsert {
                height: 777_000,
                miner_address: ADDR,
                worker: &format!("rig{i}.worker1"),
                session_id: &format!("sess{i:04}"),
                block_data: header,
                mode: Some(MiningMode::Pplns),
            },
        )
        .await
        .expect("insert_found_block");
    }

    let rows = find_found_blocks(&pool).await.expect("find_found_blocks");
    let our_rows: Vec<_> = rows.iter().filter(|r| r.miner_address == ADDR).collect();
    assert_eq!(
        our_rows.len(),
        2,
        "one row per block, none for the redelivery"
    );

    cleanup(&pool, ADDR).await;
}

// ── payout_recorded_at_height — "a row is not an accounting" ──────────

/// Heights well outside any real chain, so these rows can never collide
/// with a genuine block's.
const H_ZERO_ROWS_ONLY: i32 = -99_001;
const H_REAL_PAYOUT: i32 = -99_002;

async fn seed_history(pool: &PgPool, height: i32, address: &str, paid_sats: i64, row_type: &str) {
    sqlx::query(
        r#"INSERT INTO pplns_payout_history
             ("blockHeight", address, "paidSats", percent, "rowType", "createdAt")
           VALUES ($1, $2, $3, 0, $4, 0)"#,
    )
    .bind(height)
    .bind(address)
    .bind(paid_sats)
    .bind(row_type)
    .execute(pool)
    .await
    .expect("seed history row");
}

async fn drop_history(pool: &PgPool, heights: &[i32]) {
    for h in heights {
        let _ = sqlx::query(r#"DELETE FROM pplns_payout_history WHERE "blockHeight" = $1"#)
            .bind(h)
            .execute(pool)
            .await;
    }
}

/// MONEY: a block with only 0-sat rows is NOT booked, so the chain reconcile
/// still reports it.
#[tokio::test]
async fn zero_sat_rows_alone_do_not_count_as_a_recorded_payout() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    drop_history(&pool, &[H_ZERO_ROWS_ONLY, H_REAL_PAYOUT]).await;

    // Rows that move no value, every one of them 0 sats.
    seed_history(&pool, H_ZERO_ROWS_ONLY, "bc1qlate1", 0, "pending").await;
    seed_history(&pool, H_ZERO_ROWS_ONLY, "bc1qlate2", 0, "pending").await;
    // Precondition: rows DO exist, so a plain `EXISTS` would see them.
    let row_count: i64 =
        sqlx::query_scalar(r#"SELECT count(*) FROM pplns_payout_history WHERE "blockHeight" = $1"#)
            .bind(H_ZERO_ROWS_ONLY)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(row_count, 2, "the fixture must leave rows behind");
    assert!(
        !bp_db::payout_recorded_at_height(&pool, H_ZERO_ROWS_ONLY)
            .await
            .expect("query ok"),
        "rows that move no value are not a booking — this block's miners are owed one"
    );

    // And the negative control: one row that DID move value reads as booked,
    // so this is not a blanket "nothing counts".
    seed_history(&pool, H_REAL_PAYOUT, "bc1qpaid", 307_812_500, "coinbase").await;
    assert!(
        bp_db::payout_recorded_at_height(&pool, H_REAL_PAYOUT)
            .await
            .expect("query ok"),
        "a real payout row must still count, or every block false-alarms"
    );

    // A withheld-but-accounted block is the third shape: no coinbase
    // payment, but a non-zero pending DELTA. That IS an accounting.
    drop_history(&pool, &[H_ZERO_ROWS_ONLY]).await;
    seed_history(&pool, H_ZERO_ROWS_ONLY, "bc1qwithheld", 2_999, "pending").await;
    assert!(
        bp_db::payout_recorded_at_height(&pool, H_ZERO_ROWS_ONLY)
            .await
            .expect("query ok"),
        "a withheld miner's non-zero credit is an accounting, not a gap"
    );

    drop_history(&pool, &[H_ZERO_ROWS_ONLY, H_REAL_PAYOUT]).await;
}
