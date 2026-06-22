// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration test for `delete_stale_push_subscriptions`.
//! Inserts subscriptions with various `lastNotificationAt` / `createdAt`
//! combinations and verifies only the stale ones are hard-deleted.

use bp_db::delete_stale_push_subscriptions;
use sqlx::{postgres::PgPoolOptions, PgPool};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";
const ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

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

async fn insert_sub(
    pool: &PgPool,
    endpoint: &str,
    created_at: i64,
    last_notification_at: Option<i64>,
) {
    sqlx::query(
        r#"INSERT INTO push_subscription_entity
           (address, endpoint, platform, "subscriptionType",
            "bestDiffNotificationsEnabled", "deviceNotificationsEnabled",
            "blockNotificationsEnabled", "networkDiffNotificationsEnabled",
            "createdAt", "updatedAt", "lastNotificationAt")
           VALUES ($1, $2, 'test', 'FCM', FALSE, FALSE, FALSE, FALSE, $3, $3, $4)
           ON CONFLICT (address, endpoint, "subscriptionType") DO UPDATE
           SET "createdAt" = EXCLUDED."createdAt",
               "updatedAt" = EXCLUDED."updatedAt",
               "lastNotificationAt" = EXCLUDED."lastNotificationAt",
               "deletedAt" = NULL"#,
    )
    .bind(ADDR)
    .bind(endpoint)
    .bind(created_at)
    .bind(last_notification_at)
    .execute(pool)
    .await
    .expect("insert push sub");
}

async fn count_sub(pool: &PgPool, endpoint: &str) -> i64 {
    let row: (i64,) =
        sqlx::query_as(r#"SELECT count(*) FROM push_subscription_entity WHERE endpoint = $1"#)
            .bind(endpoint)
            .fetch_one(pool)
            .await
            .unwrap();
    row.0
}

async fn cleanup(pool: &PgPool, endpoints: &[&str]) {
    for ep in endpoints {
        let _ = sqlx::query("DELETE FROM push_subscription_entity WHERE endpoint = $1")
            .bind(*ep)
            .execute(pool)
            .await;
    }
}

#[tokio::test]
async fn stale_subs_are_deleted_active_subs_survive() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };

    const EP_NEVER_NOTIFIED_OLD: &str = "test_ps_cleanup_never_old";
    const EP_NEVER_NOTIFIED_NEW: &str = "test_ps_cleanup_never_new";
    const EP_LAST_NOTIF_OLD: &str = "test_ps_cleanup_lastnotif_old";
    const EP_LAST_NOTIF_RECENT: &str = "test_ps_cleanup_lastnotif_recent";
    cleanup(
        &pool,
        &[
            EP_NEVER_NOTIFIED_OLD,
            EP_NEVER_NOTIFIED_NEW,
            EP_LAST_NOTIF_OLD,
            EP_LAST_NOTIF_RECENT,
        ],
    )
    .await;

    let now_ms: i64 = 1_700_000_000_000;
    let cutoff_ms = now_ms - 90 * 24 * 60 * 60 * 1000; // 90 days ago

    // Stale: never notified, created > 90 days ago.
    insert_sub(&pool, EP_NEVER_NOTIFIED_OLD, cutoff_ms - 1, None).await;
    // Active: never notified, but created recently.
    insert_sub(&pool, EP_NEVER_NOTIFIED_NEW, now_ms, None).await;
    // Stale: last notified > 90 days ago.
    insert_sub(&pool, EP_LAST_NOTIF_OLD, cutoff_ms - 1, Some(cutoff_ms - 1)).await;
    // Active: last notified recently.
    insert_sub(&pool, EP_LAST_NOTIF_RECENT, cutoff_ms - 1, Some(now_ms)).await;

    let deleted = delete_stale_push_subscriptions(&pool, cutoff_ms)
        .await
        .expect("cleanup ok");
    assert!(deleted >= 2, "at least 2 stale subs deleted, got {deleted}");

    assert_eq!(
        count_sub(&pool, EP_NEVER_NOTIFIED_OLD).await,
        0,
        "stale (never-notified, old) not deleted"
    );
    assert_eq!(
        count_sub(&pool, EP_LAST_NOTIF_OLD).await,
        0,
        "stale (old lastNotification) not deleted"
    );
    assert_eq!(
        count_sub(&pool, EP_NEVER_NOTIFIED_NEW).await,
        1,
        "active (never-notified, new) was deleted"
    );
    assert_eq!(
        count_sub(&pool, EP_LAST_NOTIF_RECENT).await,
        1,
        "active (recent lastNotification) was deleted"
    );

    cleanup(
        &pool,
        &[
            EP_NEVER_NOTIFIED_OLD,
            EP_NEVER_NOTIFIED_NEW,
            EP_LAST_NOTIF_OLD,
            EP_LAST_NOTIF_RECENT,
        ],
    )
    .await;
}
