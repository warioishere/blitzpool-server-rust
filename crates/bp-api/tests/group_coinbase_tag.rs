// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! A Team's and a Blockparty's coinbase tag: set and cleared only with the
//! admin token, refused outside 25 printable ASCII characters, and the two
//! admin endpoints answer the same input the same way.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use bp_api::{build_router, AppState};
use bp_blockparty_engine::{BlockpartyPayoutConfig, BlockpartyPayouts, BlockpartyService};
use bp_group_mgmt_engine::{AddressCache, GroupService, NoopHooks};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

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

async fn patch(
    app: &axum::Router,
    uri: &str,
    header: (&str, &str),
    body: Value,
) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::patch(uri)
                .header(header.0, header.1)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// One admin endpoint: `set(tag)` sends a tag (or `null`) with a token and
/// returns the status plus the tag the response reports.
async fn exercise<F, Fut>(set: F)
where
    F: Fn(Value, bool) -> Fut,
    Fut: std::future::Future<Output = (StatusCode, Option<String>)>,
{
    let (status, tag) = set(json!("  Dezentralschweiz "), true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tag.as_deref(), Some("Dezentralschweiz"), "trimmed");

    let (status, _) = set(json!("Someone else"), false).await;
    assert!(
        matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
        "a wrong token sets nothing, got {status}"
    );

    for bad in ["Zürich".to_string(), "x".repeat(26), "rig\n1".to_string()] {
        let (status, _) = set(json!(bad), true).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?}");
    }
    let (status, tag) = set(json!("x".repeat(25)), true).await;
    assert_eq!(status, StatusCode::OK, "25 characters is the limit");
    assert_eq!(tag.map(|t| t.len()), Some(25));

    for clear in [json!(""), json!(null)] {
        let (status, tag) = set(clear.clone(), true).await;
        assert_eq!(status, StatusCode::OK, "{clear}");
        assert_eq!(tag, None, "{clear} clears the tag");
    }
}

#[tokio::test]
async fn a_team_admin_sets_and_clears_the_coinbase_tag() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-team-coinbase-tag";
    let _ = sqlx::query("DELETE FROM pplns_group WHERE name = $1")
        .bind(name)
        .execute(&pool)
        .await;
    let svc = Arc::new(
        GroupService::load(pool.clone(), Arc::new(NoopHooks), 14, 10_000)
            .await
            .expect("load group service"),
    );
    let created = svc
        .create_group(name, "bc1qteamcoinbasetag")
        .await
        .expect("create group");
    let id = created.group.id;
    let mut state = AppState::new(pool.clone(), "0.0.0");
    state.group_service = Some(svc);
    let app = build_router(Arc::new(state));

    let uri = format!("/api/pplns/groups/{id}/settings");
    let token = created.admin_token.clone();
    exercise(|tag, right_token| {
        let (app, uri, token) = (app.clone(), uri.clone(), token.clone());
        async move {
            let token = if right_token { token } else { "wrong".into() };
            let (status, body) = patch(
                &app,
                &uri,
                ("x-admin-token", &token),
                json!({ "coinbaseTag": tag }),
            )
            .await;
            (status, body["coinbaseTag"].as_str().map(str::to_string))
        }
    })
    .await;

    let _ = sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn a_blockparty_admin_sets_and_clears_the_coinbase_tag() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-party-coinbase-tag";
    let _ = sqlx::query("DELETE FROM blockparty_group WHERE name = $1")
        .bind(name)
        .execute(&pool)
        .await;
    let svc = Arc::new(
        BlockpartyService::load(
            BlockpartyPayouts::new(
                pool.clone(),
                BlockpartyPayoutConfig {
                    fee_address: None,
                    fee_percent: 0.0,
                    min_payout_sats: bp_common::Sats(5_000),
                },
            ),
            Arc::new(bp_blockparty_engine::NoopHooks::default()),
            AddressCache::new(),
        )
        .await
        .expect("load blockparty service"),
    );
    let created = svc
        .create_group(name, "bc1qpartycoinbasetag", 10_000)
        .await
        .expect("create party");
    let id = created.group.id;
    let mut state = AppState::new(pool.clone(), "0.0.0");
    state.blockparty = Some(svc);
    let app = build_router(Arc::new(state));

    let uri = format!("/api/blockparty/{id}/coinbase-tag");
    let token = created.admin_token.clone();
    exercise(|tag, right_token| {
        let (app, uri, token) = (app.clone(), uri.clone(), token.clone());
        async move {
            let token = if right_token { token } else { "wrong".into() };
            let (status, body) = patch(
                &app,
                &uri,
                ("x-blockparty-admin-token", &token),
                json!({ "tag": tag }),
            )
            .await;
            (status, body["coinbaseTag"].as_str().map(str::to_string))
        }
    })
    .await;

    let _ = sqlx::query("DELETE FROM blockparty_group WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await;
}
