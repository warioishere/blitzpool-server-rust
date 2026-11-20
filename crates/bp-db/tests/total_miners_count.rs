// SPDX-License-Identifier: AGPL-3.0-or-later

//! Verifies that the `totalMiners` COUNT query includes soft-deleted
//! client rows. The `/api/pool` response must count all clients, not
//! only active sessions, so the query carries no deletedAt filter.

use bp_db::{bulk_upsert_clients, ClientUpsert};
use sqlx::PgPool;

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
    let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
        return;
    };
    // Two sessions for the same test address: one active, one soft-deleted.
    const ADDR: &str = "bc1qtotalminerscounttest";
    const SID_ACTIVE: &str = "tmca0001";
    const SID_DELETED: &str = "tmcd0002";
    cleanup(&pool, &[SID_ACTIVE, SID_DELETED]).await;

    // Insert both as active first.
    for sid in [SID_ACTIVE, SID_DELETED] {
        bulk_upsert_clients(
            &pool,
            &[ClientUpsert {
                address: ADDR.to_string(),
                client_name: format!("worker-{sid}"),
                session_id: sid.to_string(),
                user_agent: Some("test-miner/1.0".to_string()),
                start_time_ms: 1_700_000_000_000,
            }],
        )
        .await
        .expect("bulk_upsert_clients");
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
