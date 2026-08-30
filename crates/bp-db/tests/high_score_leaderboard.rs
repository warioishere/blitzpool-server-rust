// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! The public leaderboard behind `/api/info` → `highScores`.
//!
//! `find_high_scores` had no test at all, which is how it went unnoticed
//! that it read the one column `/bestdiff_reset` zeroes: a miner clearing
//! their own best also deleted their entry from the pool's hall of fame,
//! and the flush's `GREATEST` could never bring it back (it only ever
//! offers the CURRENT window's max). Migration 0014 split the two values;
//! this pins that the list reads the reset-immune one.
//!
//! Needs `bp-test-pg` (15433) — skips when it is unreachable, so watch
//! the passed-count.

use bp_common::AddressId;
use bp_db::{
    bulk_upsert_address_settings, find_high_scores, reset_address_settings_best_difficulty,
    AddressSettingsUpsert,
};
use sqlx::{postgres::PgPoolOptions, PgPool};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

/// Above every real row, so the seeded entry is deterministically inside
/// the query's `LIMIT 10` no matter what else the shared test DB holds.
const ABOVE_EVERYTHING: f64 = 9.9e17;

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

async fn cleanup(pool: &PgPool, address: &str) {
    let _ = sqlx::query(r#"DELETE FROM address_settings_entity WHERE address = $1"#)
        .bind(address)
        .execute(pool)
        .await;
}

/// A miner's own `/bestdiff_reset` must not remove them from the public
/// leaderboard.
///
/// Runs against real rows rather than a rollback transaction, because
/// `find_high_scores` takes a pool — the seeded value is far above any
/// real entry so the assertions do not depend on what else is in the DB.
#[tokio::test]
async fn a_reset_does_not_remove_the_miner_from_the_public_leaderboard() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let address = "test_hs_reset_keeps_entry";
    cleanup(&pool, address).await;

    bulk_upsert_address_settings(
        &pool,
        &[AddressSettingsUpsert {
            address: address.to_string(),
            delta_shares: 0.0,
            best_difficulty: ABOVE_EVERYTHING,
            user_agent: Some("GMiner".to_string()),
        }],
    )
    .await
    .expect("seed record");

    // Precondition: the entry is in the list before the reset. Without
    // this the post-reset assertion could pass on a list that never had
    // it — the failure mode this whole test exists to catch.
    let before = find_high_scores(&pool).await.expect("list before");
    let seeded = before
        .iter()
        .find(|r| r.best_difficulty == ABOVE_EVERYTHING)
        .expect("precondition: the seeded record is on the leaderboard");
    assert_eq!(
        seeded.best_difficulty_user_agent.as_deref(),
        Some("GMiner"),
        "the entry carries the firmware that set it"
    );
    assert!(
        seeded.updated_at.is_some(),
        "the entry carries the timestamp the record was set"
    );

    reset_address_settings_best_difficulty(&pool, &AddressId::new(address).expect("address"))
        .await
        .expect("reset");

    // Negative control: the reset really cleared the miner's own value,
    // so "still on the leaderboard" is not just a reset that did nothing.
    let personal: f64 = sqlx::query_scalar(
        r#"SELECT "bestDifficulty" FROM address_settings_entity WHERE address = $1"#,
    )
    .bind(address)
    .fetch_one(&pool)
    .await
    .expect("read personal best");
    assert_eq!(
        personal, 0.0,
        "precondition: the reset zeroed the personal best"
    );

    let after = find_high_scores(&pool).await.expect("list after");
    let still = after
        .iter()
        .find(|r| r.best_difficulty == ABOVE_EVERYTHING)
        .expect("the public record survives the miner's own reset");
    assert_eq!(
        still.best_difficulty_user_agent.as_deref(),
        Some("GMiner"),
        "and keeps the firmware that set it"
    );

    cleanup(&pool, address).await;
}
