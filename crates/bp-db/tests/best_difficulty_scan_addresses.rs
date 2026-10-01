// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Which addresses the best-difficulty cron scans:
//! `find_best_difficulty_scan_addresses`, compared with the push-only
//! `find_addresses_with_push_subscription`.

use bp_common::AddressId;
use bp_db::{
    delete_ntfy_subscription_by_address, find_addresses_with_push_subscription,
    find_best_difficulty_scan_addresses, update_telegram_sub_best_diff_flag,
    upsert_ntfy_subscription, upsert_push_subscription, upsert_telegram_subscription,
};
use sqlx::{postgres::PgPoolOptions, PgPool};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";
const TEST_CHAT_ID: i64 = 990_000_779;

const TELEGRAM_ONLY: &str = "bdscan_telegram_only";
const TELEGRAM_FLAG_OFF: &str = "bdscan_telegram_flag_off";
const NTFY_ONLY: &str = "bdscan_ntfy_only";
const NTFY_REMOVED: &str = "bdscan_ntfy_removed";
const PUSH_ONLY: &str = "bdscan_push_only";
const ALL: [&str; 5] = [
    TELEGRAM_ONLY,
    TELEGRAM_FLAG_OFF,
    NTFY_ONLY,
    NTFY_REMOVED,
    PUSH_ONLY,
];

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

async fn hard_cleanup(pool: &PgPool) {
    for table in [
        "telegram_subscriptions_entity",
        "ntfy_subscriptions_entity",
        "push_subscription_entity",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE address = ANY($1)"))
            .bind(ALL.map(str::to_string).to_vec())
            .execute(pool)
            .await
            .expect("cleanup delete");
    }
}

fn addr(s: &str) -> AddressId {
    AddressId::new(s.to_string()).expect("valid test AddressId")
}

/// Telegram- or ntfy-only addresses are scanned (and missed by the push-only
/// query), best-diff switched off is still scanned, a removed subscription
/// is not.
#[tokio::test]
async fn best_diff_scan_covers_every_transport() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    hard_cleanup(&pool).await;

    upsert_telegram_subscription(&pool, TEST_CHAT_ID, &addr(TELEGRAM_ONLY))
        .await
        .expect("telegram sub");
    upsert_telegram_subscription(&pool, TEST_CHAT_ID, &addr(TELEGRAM_FLAG_OFF))
        .await
        .expect("telegram sub (flag off)");
    update_telegram_sub_best_diff_flag(&pool, TEST_CHAT_ID, &addr(TELEGRAM_FLAG_OFF), false)
        .await
        .expect("best-diff off");
    upsert_ntfy_subscription(&pool, &addr(NTFY_ONLY))
        .await
        .expect("ntfy sub");
    upsert_ntfy_subscription(&pool, &addr(NTFY_REMOVED))
        .await
        .expect("ntfy sub to remove");
    delete_ntfy_subscription_by_address(&pool, &addr(NTFY_REMOVED))
        .await
        .expect("ntfy remove");
    upsert_push_subscription(
        &pool,
        &addr(PUSH_ONLY),
        "https://push.example/bdscan",
        "android",
        "unified_push",
    )
    .await
    .expect("push sub");

    let scanned: Vec<String> = find_best_difficulty_scan_addresses(&pool)
        .await
        .expect("scan addresses")
        .into_iter()
        .map(|a| a.as_str().to_string())
        .collect();
    let push_only: Vec<String> = find_addresses_with_push_subscription(&pool)
        .await
        .expect("push addresses")
        .into_iter()
        .map(|a| a.as_str().to_string())
        .collect();
    hard_cleanup(&pool).await;

    let has = |set: &[String], a: &str| set.iter().any(|s| s == a);

    // The push-only query misses Telegram- and ntfy-only addresses.
    assert!(
        !has(&push_only, TELEGRAM_ONLY) && !has(&push_only, NTFY_ONLY),
        "precondition: the push-only query does not see Telegram/ntfy-only addresses"
    );
    assert!(has(&push_only, PUSH_ONLY), "precondition: push row is live");

    assert!(
        has(&scanned, TELEGRAM_ONLY),
        "Telegram-only address scanned"
    );
    assert!(has(&scanned, NTFY_ONLY), "ntfy-only address scanned");
    assert!(has(&scanned, PUSH_ONLY), "push-only address still scanned");
    assert!(
        has(&scanned, TELEGRAM_FLAG_OFF),
        "a switched-off flag is honoured at send time, not by dropping the scan"
    );
    assert!(
        !has(&scanned, NTFY_REMOVED),
        "a removed ntfy subscription is not scanned"
    );
}
