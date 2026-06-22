// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! Integration tests for `insert_found_block` — verifies that found-block
//! records are actually persisted to `blocks_entity` and that the written
//! columns match what was supplied.

use bp_db::{find_found_blocks, insert_found_block};
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
        840_001,
        ADDR,
        "rig0.worker1",
        "ab12cd34",
        "deadbeef01020304",
    )
    .await
    .expect("insert_found_block");

    // Read back via the public find_found_blocks helper and locate our row.
    let rows = find_found_blocks(&pool).await.expect("find_found_blocks");
    let row = rows
        .iter()
        .find(|r| r.miner_address == ADDR)
        .expect("inserted row not found");

    assert_eq!(row.height, 840_001);
    assert_eq!(row.miner_address, ADDR);
    assert_eq!(row.worker, "rig0.worker1");
    assert_eq!(row.session_id, "ab12cd34");

    cleanup(&pool, ADDR).await;
}

#[tokio::test]
async fn insert_multiple_rows_same_height() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    const ADDR: &str = "bc1qblockwritetest0002";
    cleanup(&pool, ADDR).await;

    // No UNIQUE constraint on (height, minerAddress) — plain INSERT should
    // allow two rows at the same height.
    for i in 0u32..2 {
        insert_found_block(
            &pool,
            777_000,
            ADDR,
            &format!("rig{i}.worker1"),
            &format!("sess{i:04}"),
            "aabbccdd",
        )
        .await
        .expect("insert_found_block");
    }

    let rows = find_found_blocks(&pool).await.expect("find_found_blocks");
    let our_rows: Vec<_> = rows.iter().filter(|r| r.miner_address == ADDR).collect();
    assert_eq!(our_rows.len(), 2, "both rows must be present");

    cleanup(&pool, ADDR).await;
}
