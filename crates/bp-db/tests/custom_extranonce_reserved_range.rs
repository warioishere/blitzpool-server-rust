// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pins the CHECK `pplns_custom_extranonce_prefix_unreserved`: a customer
//! prefix inside the SV2 (`0x00`) or SV1 (`0x01`) allocator partition could be
//! handed to another channel of the same Solo coinbase, wasting its work. The
//! core loads rows unchecked, so the rule must hold in the schema itself.

use sqlx::{postgres::PgPoolOptions, PgPool};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

/// First prefix above SV1's partition — `0x02000000`.
const FIRST_UNRESERVED: i64 = 33_554_432;

const TEST_ADDRESS: &str = "bcrt1qreservedrangetest";

// Printing why an integration test skipped is what stderr is for here.
#[allow(clippy::print_stderr)]
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

async fn insert_prefix(pool: &PgPool, worker: &str, prefix: i64) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO pplns_custom_extranonce (address, worker, prefix) VALUES ($1, $2, $3)")
        .bind(TEST_ADDRESS)
        .bind(worker)
        .bind(prefix)
        .execute(pool)
        .await
        .map(|_| ())
}

async fn cleanup(pool: &PgPool) {
    let _ = sqlx::query("DELETE FROM pplns_custom_extranonce WHERE address = $1")
        .bind(TEST_ADDRESS)
        .execute(pool)
        .await;
}

#[tokio::test]
#[allow(clippy::print_stderr)]
async fn the_database_refuses_an_allocator_owned_prefix_and_accepts_the_rest() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    cleanup(&pool).await;

    // Highest value in SV1's partition: an off-by-one bound fails here.
    let err = insert_prefix(&pool, "sv1-partition-top", FIRST_UNRESERVED - 1)
        .await
        .expect_err("0x01FFFFFF is inside SV1's partition and must be refused");
    assert!(
        err.to_string().contains("prefix_unreserved"),
        "must fail on pplns_custom_extranonce_prefix_unreserved, got: {err}"
    );

    // SV2's partition (0x00000001) — the other allocator, same rule.
    insert_prefix(&pool, "sv2-partition", 1)
        .await
        .expect_err("0x00000001 is inside SV2's partition and must be refused");

    // Negative control: the constraint does not reject everything.
    insert_prefix(&pool, "first-unreserved", FIRST_UNRESERVED)
        .await
        .expect("0x02000000 is the first unowned prefix and must be accepted");
    insert_prefix(&pool, "typical-customer", 0xC0DE_BABE)
        .await
        .expect("a normal customer prefix must be accepted");

    cleanup(&pool).await;
}
