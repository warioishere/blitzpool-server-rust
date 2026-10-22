// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! The join-request switch a Team admin sets per channel: on for a new
//! subscription, and each write touches that switch alone.

use bp_common::AddressId;
use bp_db::{
    find_ntfy_subscription_by_address, find_push_subscriptions_by_address,
    find_telegram_subscriptions_by_chat, update_ntfy_sub_group_admin_flag,
    update_push_subscription_preferences, update_telegram_sub_group_admin_flag,
    upsert_ntfy_subscription, upsert_push_subscription, upsert_telegram_subscription,
    PushPreferenceUpdate,
};
use sqlx::{postgres::PgPoolOptions, PgPool};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";
const TEST_CHAT_ID: i64 = 990_000_779;
const ADDR: &str = "bc1q_group_admin_flag_test";
const ENDPOINT: &str = "group-admin-flag-test-endpoint";

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

async fn cleanup(pool: &PgPool) {
    sqlx::query(r#"DELETE FROM telegram_subscriptions_entity WHERE "telegramChatId" = $1"#)
        .bind(TEST_CHAT_ID)
        .execute(pool)
        .await
        .expect("cleanup telegram");
    sqlx::query("DELETE FROM ntfy_subscriptions_entity WHERE address = $1")
        .bind(ADDR)
        .execute(pool)
        .await
        .expect("cleanup ntfy");
    sqlx::query("DELETE FROM push_subscription_entity WHERE address = $1")
        .bind(ADDR)
        .execute(pool)
        .await
        .expect("cleanup push");
}

#[tokio::test]
async fn the_group_admin_switch_starts_on_and_flips_alone() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    cleanup(&pool).await;
    let a = AddressId::new(ADDR.to_string()).unwrap();

    // Telegram.
    upsert_telegram_subscription(&pool, TEST_CHAT_ID, &a)
        .await
        .expect("telegram upsert");
    let tg = || async {
        find_telegram_subscriptions_by_chat(&pool, TEST_CHAT_ID)
            .await
            .expect("telegram read")
            .into_iter()
            .next()
            .expect("telegram row")
    };
    let before = tg().await;
    assert!(
        before.group_admin_notifications_enabled,
        "on for a new subscription"
    );
    assert_eq!(
        update_telegram_sub_group_admin_flag(&pool, TEST_CHAT_ID, &a, false)
            .await
            .expect("telegram toggle"),
        1
    );
    let after = tg().await;
    assert!(!after.group_admin_notifications_enabled);
    assert_eq!(
        after.best_diff_notifications_enabled,
        before.best_diff_notifications_enabled
    );
    assert_eq!(
        after.device_notifications_enabled,
        before.device_notifications_enabled
    );

    // ntfy.
    upsert_ntfy_subscription(&pool, &a)
        .await
        .expect("ntfy upsert");
    let ntfy = || async {
        find_ntfy_subscription_by_address(&pool, &a)
            .await
            .expect("ntfy read")
            .expect("ntfy row")
    };
    let before = ntfy().await;
    assert!(
        before.group_admin_notifications_enabled,
        "on for a new subscription"
    );
    update_ntfy_sub_group_admin_flag(&pool, &a, false)
        .await
        .expect("ntfy toggle");
    let after = ntfy().await;
    assert!(!after.group_admin_notifications_enabled);
    assert_eq!(
        after.best_diff_notifications_enabled,
        before.best_diff_notifications_enabled
    );

    // App push: a preference write naming only this switch leaves the rest,
    // and one that leaves it out leaves it.
    upsert_push_subscription(&pool, &a, ENDPOINT, "android", "fcm")
        .await
        .expect("push upsert");
    let push = || async {
        find_push_subscriptions_by_address(&pool, &a)
            .await
            .expect("push read")
            .into_iter()
            .next()
            .expect("push row")
    };
    assert!(
        push().await.group_admin_notifications_enabled,
        "on for a new subscription"
    );
    update_push_subscription_preferences(
        &pool,
        &a,
        ENDPOINT,
        PushPreferenceUpdate {
            group_admin: Some(false),
            ..Default::default()
        },
    )
    .await
    .expect("push off");
    let row = push().await;
    assert!(!row.group_admin_notifications_enabled);
    assert!(row.best_diff_notifications_enabled && row.block_notifications_enabled);
    update_push_subscription_preferences(
        &pool,
        &a,
        ENDPOINT,
        PushPreferenceUpdate {
            best_diff: Some(false),
            ..Default::default()
        },
    )
    .await
    .expect("best diff off");
    let row = push().await;
    assert!(!row.best_diff_notifications_enabled);
    assert!(
        !row.group_admin_notifications_enabled,
        "a write without the switch leaves it as it was"
    );

    cleanup(&pool).await;
}
