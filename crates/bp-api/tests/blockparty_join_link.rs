// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! A Blockparty join link comes back as the shareable URL on the configured
//! pool UI, from creating it and from reading the active one, the same way a
//! Group-Solo open-invite link does.

use std::sync::Arc;

use axum::http::{Request, StatusCode};
use bp_api::{build_router, AppState};
use bp_blockparty_engine::{
    BlockpartyPayoutConfig, BlockpartyPayouts, BlockpartyService, NoopHooks,
};
use bp_common::Sats;
use bp_group_mgmt_engine::AddressCache as PplnsAddressCache;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/blitzpool";
const NAME: &str = "join-link-url-test";
const ADMIN: &str = "bc1qjoinlinkurltestadmin";

async fn connect_or_skip() -> Option<PgPool> {
    let url = std::env::var("BP_PG_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&url),
    )
    .await
    {
        Ok(Ok(p)) => Some(p),
        Ok(Err(e)) => {
            eprintln!("PG connect failed for {url}: {e} — skipping");
            None
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            None
        }
    }
}

async fn cleanup(pool: &PgPool) {
    let _ = sqlx::query("DELETE FROM blockparty_group WHERE name = $1")
        .bind(NAME)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(ADMIN)
        .execute(pool)
        .await;
}

async fn call(app: &axum::Router, method: &str, uri: &str, token: &str) -> serde_json::Value {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-blockparty-admin-token", token);
    let body = if method == "POST" {
        req = req.header("content-type", "application/json");
        axum::body::Body::from(r#"{"ttl":"24h"}"#)
    } else {
        axum::body::Body::empty()
    };
    let res = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "{method} {uri}");
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 16)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn the_join_link_is_the_url_on_the_pool_ui() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    cleanup(&pool).await;
    let svc = Arc::new(
        BlockpartyService::load(
            BlockpartyPayouts::new(
                pool.clone(),
                BlockpartyPayoutConfig {
                    fee_address: bp_common::AddressId::new(
                        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
                    )
                    .unwrap(),
                    fee_percent: 2.0,
                    min_payout_sats: Sats(5_000),
                },
            ),
            Arc::new(NoopHooks::default()),
            PplnsAddressCache::new(),
        )
        .await
        .expect("load blockparty service"),
    );
    let created = svc
        .create_group(NAME, ADMIN, 9_800)
        .await
        .expect("create blockparty");
    let id = created.group.id;

    let mut state = AppState::new(pool.clone(), "0.0.0");
    state.blockparty = Some(svc);
    state.pool_base_url = Some("https://pool.example".to_owned());
    let app = build_router(Arc::new(state));

    let uri = format!("/api/blockparty/{id}/join-link");
    let made = call(&app, "POST", &uri, &created.admin_token).await;
    let token = made["token"].as_str().expect("token").to_owned();
    let active = call(&app, "GET", &uri, &created.admin_token).await;
    cleanup(&pool).await;

    let expected = format!("https://pool.example/blockparty/join/{token}");
    assert_eq!(made["link"], expected.as_str());
    assert_eq!(active["link"], expected.as_str());
}
