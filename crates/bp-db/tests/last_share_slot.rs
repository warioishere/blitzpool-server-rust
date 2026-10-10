// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pins `find_last_share_slot_for_addresses`: per address the latest slot
//! with shares before the cutoff, nothing for an address without one.

use bp_common::AddressId;
use bp_db::find_last_share_slot_for_addresses;
use sqlx::{postgres::PgPoolOptions, PgPool};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

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

/// A later slot without shares, and one at or past the cutoff, do not count;
/// an address with only share-less rows, or no rows, is absent.
#[tokio::test]
async fn last_share_slot_skips_empty_slots_and_the_cutoff() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin tx");

    // Past every other fixture, so no other row matches these addresses.
    let t: i64 = 9_100_000_000_000_000;
    let slot = 600_000;
    let cutoff = t + 3 * slot;

    // (address, time, shares)
    let seed: &[(&str, i64, f64)] = &[
        ("bp_lss_A", t, 2.0),
        ("bp_lss_A", t + slot, 1.0),     // the answer for A
        ("bp_lss_A", t + 2 * slot, 0.0), // later, but no shares
        ("bp_lss_A", cutoff, 5.0),       // at the cutoff, not yet visible
        ("bp_lss_B", t, 0.0),            // never had shares
    ];
    for (addr, time, shares) in seed {
        sqlx::query(
            r#"INSERT INTO client_statistics_entity
                 (address, "clientName", "sessionId", "time", shares)
               VALUES ($1, 'w', 's', $2, $3)"#,
        )
        .bind(addr)
        .bind(time)
        .bind(shares)
        .execute(&mut *tx)
        .await
        .expect("seed insert");
    }

    let addresses: Vec<AddressId> = ["bp_lss_A", "bp_lss_B", "bp_lss_C"]
        .iter()
        .map(|a| AddressId::new((*a).to_string()).expect("address id"))
        .collect();
    let got = find_last_share_slot_for_addresses(&mut *tx, &addresses, cutoff)
        .await
        .expect("query");
    assert_eq!(got.get("bp_lss_A"), Some(&(t + slot)));
    assert!(
        !got.contains_key("bp_lss_B"),
        "only share-less rows: absent"
    );
    assert!(!got.contains_key("bp_lss_C"), "no rows: absent");
    assert_eq!(got.len(), 1);
}
