// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Which addresses the device-status gate tracks.

use bp_common::AddressId;
use bp_db::upsert_ntfy_subscription;
use sqlx::{postgres::PgPoolOptions, PgPool};

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/blitzpool";

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

/// The device-status gate tracks an address an ntfy subscription follows with
/// device notices on; with them off it does not (the control).
#[tokio::test]
async fn an_ntfy_device_subscriber_is_tracked_for_device_notices() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let address = AddressId::new("bc1q_ntfy_device_gate_test").unwrap();
    let tracked = |pool: PgPool, address: AddressId| async move {
        bp_db::find_device_notification_addresses(&pool)
            .await
            .unwrap()
            .contains(&address)
    };
    let _ = sqlx::query("DELETE FROM ntfy_subscriptions_entity WHERE address = $1")
        .bind(address.as_str())
        .execute(&pool)
        .await;
    upsert_ntfy_subscription(&pool, &address).await.unwrap();
    bp_db::update_ntfy_sub_device_flag(&pool, &address, false)
        .await
        .unwrap();
    assert!(
        !tracked(pool.clone(), address.clone()).await,
        "control: off is not tracked"
    );
    bp_db::update_ntfy_sub_device_flag(&pool, &address, true)
        .await
        .unwrap();
    assert!(tracked(pool.clone(), address.clone()).await);
    let _ = sqlx::query("DELETE FROM ntfy_subscriptions_entity WHERE address = $1")
        .bind(address.as_str())
        .execute(&pool)
        .await;
}
