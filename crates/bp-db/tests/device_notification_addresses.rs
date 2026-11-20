// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::needless_return)]

//! Which addresses the device-status gate tracks.

use bp_common::AddressId;
use bp_db::upsert_ntfy_subscription;
use sqlx::PgPool;

/// The device-status gate tracks an address an ntfy subscription follows with
/// device notices on; with them off it does not (the control).
#[tokio::test]
async fn an_ntfy_device_subscriber_is_tracked_for_device_notices() {
    let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
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
