// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration test for `delete_expired_email_verifications`.
//! Inserts a mix of expired and non-expired tokens, runs the purge,
//! and verifies only the expired ones are removed.

use bp_db::delete_expired_email_verifications;
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
            return None;
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            return None;
        }
    }
}

async fn cleanup(pool: &PgPool, tokens: &[&str]) {
    for token in tokens {
        let _ = sqlx::query("DELETE FROM pplns_email_verification WHERE token = $1")
            .bind(*token)
            .execute(pool)
            .await;
    }
}

#[tokio::test]
async fn purge_deletes_expired_keeps_future() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };

    const TOKEN_EXPIRED: &str = "test_ev_expired_001";
    const TOKEN_VALID: &str = "test_ev_valid_001";
    const ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    cleanup(&pool, &[TOKEN_EXPIRED, TOKEN_VALID]).await;

    let now_ms: i64 = 1_700_000_000_000;
    let expired_at = now_ms - 1000; // already past
    let future_at = now_ms + 60_000; // 60s in the future

    // Insert expired token.
    sqlx::query(
        r#"INSERT INTO pplns_email_verification
           (token, address, email, "createdAt", "expiresAt")
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(TOKEN_EXPIRED)
    .bind(ADDRESS)
    .bind("test@example.com")
    .bind(expired_at)
    .bind(expired_at)
    .execute(&pool)
    .await
    .expect("insert expired");

    // Insert still-valid token.
    sqlx::query(
        r#"INSERT INTO pplns_email_verification
           (token, address, email, "createdAt", "expiresAt")
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(TOKEN_VALID)
    .bind(ADDRESS)
    .bind("test@example.com")
    .bind(now_ms)
    .bind(future_at)
    .execute(&pool)
    .await
    .expect("insert valid");

    let deleted = delete_expired_email_verifications(&pool, now_ms)
        .await
        .expect("purge ok");
    assert!(deleted >= 1, "at least the expired token must be removed");

    // Expired token is gone.
    let expired_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM pplns_email_verification WHERE token = $1")
            .bind(TOKEN_EXPIRED)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(expired_count.0, 0, "expired token was not removed");

    // Valid token survives.
    let valid_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM pplns_email_verification WHERE token = $1")
            .bind(TOKEN_VALID)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(valid_count.0, 1, "valid token was incorrectly removed");

    cleanup(&pool, &[TOKEN_EXPIRED, TOKEN_VALID]).await;
}
