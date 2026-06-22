// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for the Telegram-subscription default-management
//! primitives that back the `/show_addresses` inline keyboard:
//! `upsert_telegram_subscription` (new address becomes default),
//! `set_telegram_default_subscription`, and
//! `promote_telegram_default_if_none`.

use bp_common::AddressId;
use bp_db::{
    delete_telegram_subscription_by_chat_address, find_telegram_subscriptions_by_chat,
    promote_telegram_default_if_none, set_telegram_default_subscription, set_telegram_hourly_flags,
    upsert_telegram_subscription,
};
use sqlx::{postgres::PgPoolOptions, PgPool};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";
// Each test uses a distinct chat id so the two tests stay isolated when
// the harness runs them concurrently against the shared local PG.
const TEST_CHAT_ID: i64 = 990_000_777;
const TEST_CHAT_ID_HOURLY: i64 = 990_000_778;

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

async fn hard_cleanup(pool: &PgPool, chat_id: i64) {
    sqlx::query(r#"DELETE FROM telegram_subscriptions_entity WHERE "telegramChatId" = $1"#)
        .bind(chat_id)
        .execute(pool)
        .await
        .expect("cleanup delete");
}

fn addr(s: &str) -> AddressId {
    AddressId::new(s.to_string()).expect("valid test AddressId")
}

async fn is_default_of(pool: &PgPool, chat_id: i64, id: i32) -> bool {
    find_telegram_subscriptions_by_chat(pool, chat_id)
        .await
        .expect("read subs")
        .into_iter()
        .find(|s| s.id == id)
        .map(|s| s.is_default)
        .unwrap_or(false)
}

#[tokio::test]
async fn telegram_default_management_set_and_promote() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let chat_id = TEST_CHAT_ID;
    hard_cleanup(&pool, chat_id).await;

    let a = addr("tg_default_addr_a");
    let b = addr("tg_default_addr_b");
    let c = addr("tg_default_addr_c");

    // First subscribe → A becomes default.
    let id_a = upsert_telegram_subscription(&pool, chat_id, &a)
        .await
        .expect("upsert a");
    assert!(
        is_default_of(&pool, chat_id, id_a).await,
        "first sub is default"
    );

    // Second subscribe → B becomes default, A no longer.
    let id_b = upsert_telegram_subscription(&pool, chat_id, &b)
        .await
        .expect("upsert b");
    assert!(
        is_default_of(&pool, chat_id, id_b).await,
        "new sub becomes default"
    );
    assert!(
        !is_default_of(&pool, chat_id, id_a).await,
        "old default cleared"
    );

    // Explicitly set A back to default.
    let n = set_telegram_default_subscription(&pool, chat_id, id_a)
        .await
        .expect("set default a");
    assert_eq!(n, 2, "touches both active rows");
    assert!(is_default_of(&pool, chat_id, id_a).await);
    assert!(!is_default_of(&pool, chat_id, id_b).await);

    // Add C → becomes default.
    let id_c = upsert_telegram_subscription(&pool, chat_id, &c)
        .await
        .expect("upsert c");
    assert!(is_default_of(&pool, chat_id, id_c).await);

    // Remove a NON-default (A) → default (C) unchanged, promote is a no-op.
    delete_telegram_subscription_by_chat_address(&pool, chat_id, &a)
        .await
        .expect("remove a");
    let promoted = promote_telegram_default_if_none(&pool, chat_id)
        .await
        .expect("promote after non-default removal");
    assert!(!promoted, "a default already exists → no promotion");
    assert!(is_default_of(&pool, chat_id, id_c).await);

    // Remove the DEFAULT (C) → no default remains → promote the lowest-id
    // remaining (B).
    delete_telegram_subscription_by_chat_address(&pool, chat_id, &c)
        .await
        .expect("remove c");
    let promoted = promote_telegram_default_if_none(&pool, chat_id)
        .await
        .expect("promote after default removal");
    assert!(promoted, "default was removed → promote a remaining row");
    assert!(
        is_default_of(&pool, chat_id, id_b).await,
        "B promoted to default"
    );

    hard_cleanup(&pool, chat_id).await;
}

#[tokio::test]
async fn telegram_hourly_flags_toggle_independently() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let chat_id = TEST_CHAT_ID_HOURLY;
    hard_cleanup(&pool, chat_id).await;

    let a = addr("tg_hourly_addr_a");
    upsert_telegram_subscription(&pool, chat_id, &a)
        .await
        .expect("upsert");

    // Stats on, workers off — must set them independently.
    let n = set_telegram_hourly_flags(&pool, chat_id, &a, true, false)
        .await
        .expect("set flags");
    assert_eq!(n, 1);
    let row = find_telegram_subscriptions_by_chat(&pool, chat_id)
        .await
        .expect("read")
        .into_iter()
        .next()
        .expect("row");
    assert!(row.hourly_stats_enabled);
    assert!(!row.hourly_workers_enabled);

    // Flip workers on, stats off.
    set_telegram_hourly_flags(&pool, chat_id, &a, false, true)
        .await
        .expect("set flags 2");
    let row = find_telegram_subscriptions_by_chat(&pool, chat_id)
        .await
        .expect("read")
        .into_iter()
        .next()
        .expect("row");
    assert!(!row.hourly_stats_enabled);
    assert!(row.hourly_workers_enabled);

    hard_cleanup(&pool, chat_id).await;
}
