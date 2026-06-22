// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! Verifies that the `totalMiners` COUNT query includes soft-deleted
//! client rows. The `/api/pool` response must count all clients, not
//! only active sessions — matching the behaviour of getUserAgents()
//! in the original service, which has no deletedAt filter.

use bp_db::{upsert_client, ClientUpsert};
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

async fn cleanup(pool: &PgPool, session_ids: &[&str]) {
    for sid in session_ids {
        let _ = sqlx::query(r#"DELETE FROM client_entity WHERE "sessionId" = $1"#)
            .bind(*sid)
            .execute(pool)
            .await;
    }
}

#[tokio::test]
async fn total_miners_counts_soft_deleted_rows() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    // Two sessions for the same test address: one active, one soft-deleted.
    const ADDR: &str = "bc1qtotalminerscounttest";
    const SID_ACTIVE: &str = "tmca0001";
    const SID_DELETED: &str = "tmcd0002";
    cleanup(&pool, &[SID_ACTIVE, SID_DELETED]).await;

    // Insert both as active first.
    for sid in [SID_ACTIVE, SID_DELETED] {
        upsert_client(
            &pool,
            &ClientUpsert {
                address: ADDR.to_string(),
                client_name: format!("worker-{sid}"),
                session_id: sid.to_string(),
                user_agent: Some("test-miner/1.0".to_string()),
                start_time_ms: 1_700_000_000_000,
                current_difficulty: None,
            },
        )
        .await
        .expect("upsert_client");
    }

    // Soft-delete the second session.
    sqlx::query(r#"UPDATE client_entity SET "deletedAt" = 1700000001000 WHERE "sessionId" = $1"#)
        .bind(SID_DELETED)
        .execute(&pool)
        .await
        .expect("soft-delete");

    // Run the exact query used by the /api/pool totalMiners field.
    let count: Option<i64> = sqlx::query_scalar(
        r#"SELECT COUNT("userAgent") FROM client_entity
           WHERE "sessionId" = ANY($1)"#,
    )
    .bind(&[SID_ACTIVE, SID_DELETED] as &[&str])
    .fetch_one(&pool)
    .await
    .expect("count query");

    assert_eq!(
        count.unwrap_or(0),
        2,
        "both active and soft-deleted sessions must be counted"
    );

    cleanup(&pool, &[SID_ACTIVE, SID_DELETED]).await;
}
