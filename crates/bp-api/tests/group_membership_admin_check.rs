// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! The two lean yes/no reads: Group-Solo `membership/:address` and the
//! `admin-check` of both group modes (Group-Solo and Blockparty share one
//! contract: 204 / 401 / 404).

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use bp_api::{build_router, AppState};
use bp_blockparty_engine::{BlockpartyPayoutConfig, BlockpartyPayouts, BlockpartyService};
use bp_group_mgmt_engine::{AddressCache, GroupService, NoopHooks};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;
use uuid::Uuid;

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

async fn call(
    app: &axum::Router,
    uri: &str,
    header: Option<(&str, &str)>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::get(uri);
    if let Some((k, v)) = header {
        req = req.header(k, v);
    }
    let resp = app
        .clone()
        .oneshot(req.body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn group_solo_membership_and_admin_check() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-membership-admin-check";
    let creator = "bc1qmembershipadmincheck";
    let _ = sqlx::query("DELETE FROM pplns_group WHERE name = $1")
        .bind(name)
        .execute(&pool)
        .await;
    let svc = Arc::new(
        GroupService::load(pool.clone(), Arc::new(NoopHooks), 14, 10_000)
            .await
            .expect("load group service"),
    );
    let created = svc.create_group(name, creator).await.expect("create group");
    let id = created.group.id;

    let mut state = AppState::new(pool.clone(), "0.0.0");
    state.group_service = Some(svc);
    let app = build_router(Arc::new(state));

    let (status, body) = call(
        &app,
        &format!("/api/pplns/groups/membership/{creator}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["groupId"], id.to_string());
    assert_eq!(body["groupName"], name);
    assert_eq!(body["role"], "creator");
    assert_eq!(body.as_object().unwrap().len(), 3, "{body}");

    let (status, body) = call(
        &app,
        "/api/pplns/groups/membership/bc1qnotamemberanywhere",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({ "groupId": null }));

    let check = format!("/api/pplns/groups/{id}/admin-check");
    let token = created.admin_token.as_str();
    assert_eq!(
        call(&app, &check, Some(("x-admin-token", token))).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, &check, Some(("x-admin-token", "wrong"))).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(call(&app, &check, None).await.0, StatusCode::UNAUTHORIZED);
    let unknown = format!("/api/pplns/groups/{}/admin-check", Uuid::new_v4());
    assert_eq!(
        call(&app, &unknown, Some(("x-admin-token", token))).await.0,
        StatusCode::NOT_FOUND
    );

    let _ = sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn blockparty_admin_check() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-bp-admin-check";
    let admin = "bc1qbpadmincheck";
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
        .create_group(name, admin, 10_000)
        .await
        .expect("create party");
    let id = created.group.id;

    let mut state = AppState::new(pool.clone(), "0.0.0");
    state.blockparty = Some(svc);
    let app = build_router(Arc::new(state));

    let check = format!("/api/blockparty/{id}/admin-check");
    let h = "x-blockparty-admin-token";
    let token = created.admin_token.as_str();
    assert_eq!(
        call(&app, &check, Some((h, token))).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, &check, Some((h, "wrong"))).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(call(&app, &check, None).await.0, StatusCode::UNAUTHORIZED);
    let unknown = format!("/api/blockparty/{}/admin-check", Uuid::new_v4());
    assert_eq!(
        call(&app, &unknown, Some((h, token))).await.0,
        StatusCode::NOT_FOUND
    );

    let _ = sqlx::query("DELETE FROM blockparty_group WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(admin)
        .execute(&pool)
        .await;
}
