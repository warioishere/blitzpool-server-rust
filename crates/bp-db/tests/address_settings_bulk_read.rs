// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! `find_address_settings_for_addresses`: one round trip for many
//! addresses, an address without a row absent from the result.

use std::collections::HashMap;

use bp_db::find_address_settings_for_addresses;
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

async fn cleanup(pool: &PgPool, addrs: &[String]) {
    sqlx::query("DELETE FROM address_settings_entity WHERE address = ANY($1)")
        .bind(addrs.to_vec())
        .execute(pool)
        .await
        .expect("cleanup delete");
}

#[tokio::test]
async fn bulk_read_returns_the_rows_that_exist() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let with_row = ["bc1qbpsettingsbulka1", "bc1qbpsettingsbulkb2"];
    let without_row = "bc1qbpsettingsbulknone";
    let all: Vec<String> = with_row
        .iter()
        .chain([&without_row])
        .map(|a| a.to_string())
        .collect();
    cleanup(&pool, &all).await;
    for (addr, best) in with_row.iter().zip([100.0_f64, 250.5]) {
        sqlx::query(
            r#"INSERT INTO address_settings_entity (address, shares, "bestDifficulty")
               VALUES ($1, 0, $2)"#,
        )
        .bind(addr)
        .bind(best)
        .execute(&pool)
        .await
        .expect("seed");
    }

    let got: HashMap<String, f64> = find_address_settings_for_addresses(&pool, &all)
        .await
        .expect("read")
        .into_iter()
        .map(|row| (row.address.as_str().to_string(), row.best_difficulty))
        .collect();
    cleanup(&pool, &all).await;

    assert_eq!(
        got,
        HashMap::from([
            (with_row[0].to_string(), 100.0),
            (with_row[1].to_string(), 250.5),
        ])
    );
}
