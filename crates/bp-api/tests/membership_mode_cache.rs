// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! `/api/pplns/mode/:address` is cached, and a Team or Blockparty change
//! that moves an address drops that cache, so the next read shows the new
//! mode rather than the cached one.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use bp_api::{build_router, AppState, ModeCacheNotifier};
use bp_blockparty_engine::{BlockpartyPayoutConfig, BlockpartyPayouts, BlockpartyService};
use bp_group_mgmt_engine::{AddressCache, GroupService, MembershipChangeNotifier, NoopHooks};
use serde_json::Value;
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
            eprintln!("PG connect failed for {url}: {e}, skipping");
            None
        }
        Err(_) => {
            eprintln!("PG connect timed out, skipping");
            None
        }
    }
}

/// Stands in for the stream publisher the api chains after the mode cache.
struct NoopNotifier;

#[async_trait]
impl MembershipChangeNotifier for NoopNotifier {
    async fn membership_changed(&self, _kind: &str) {}
}

async fn send(app: &axum::Router, req: Request<axum::body::Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn mode(app: &axum::Router, address: &str) -> String {
    let req = Request::get(format!("/api/pplns/mode/{address}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, body) = send(app, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["mode"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn dissolving_a_team_drops_its_members_cached_mode() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-team-mode-cache";
    let creator = "bc1qteammodecache";
    let _ = sqlx::query("DELETE FROM pplns_group WHERE name = $1")
        .bind(name)
        .execute(&pool)
        .await;
    bp_test_support::seed_signature_ownership(&pool, creator).await;

    let mut state = AppState::new(pool.clone(), "0.0.0");
    let svc = Arc::new(
        GroupService::load(pool.clone(), Arc::new(NoopHooks), 14, 10_000)
            .await
            .expect("load group service"),
    );
    svc.set_change_notifier(Arc::new(ModeCacheNotifier::new(
        state.cache.clone(),
        Arc::new(NoopNotifier),
    )));
    let created = svc.create_group(name, creator).await.expect("create team");
    let id = created.group.id;
    state.group_service = Some(svc);
    let app = build_router(Arc::new(state));

    assert_eq!(mode(&app, creator).await, "group-solo");
    // A change that bypasses the services leaves the cached mode standing:
    // the cache is what the dissolve below has to clear.
    sqlx::query(r#"DELETE FROM pplns_group_member WHERE "groupId" = $1"#)
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(mode(&app, creator).await, "group-solo", "precondition");

    let req = Request::delete(format!("/api/pplns/groups/{id}"))
        .header("x-admin-token", &created.admin_token)
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(mode(&app, creator).await, "solo");

    let _ = sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn dissolving_a_blockparty_drops_its_admins_cached_mode() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-party-mode-cache";
    let admin = "bc1qpartymodecache";
    let _ = sqlx::query("DELETE FROM blockparty_group WHERE name = $1")
        .bind(name)
        .execute(&pool)
        .await;
    bp_test_support::seed_signature_ownership(&pool, admin).await;

    let mut state = AppState::new(pool.clone(), "0.0.0");
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
    svc.set_change_notifier(Arc::new(ModeCacheNotifier::new(
        state.cache.clone(),
        Arc::new(NoopNotifier),
    )));
    let created = svc
        .create_group(name, admin, 10_000)
        .await
        .expect("create party");
    let id = created.group.id;
    state.blockparty = Some(svc);
    let app = build_router(Arc::new(state));
    let token = ("x-blockparty-admin-token", created.admin_token.as_str());

    // A draft party does not route yet; the lone admin's confirmation makes
    // it ready the moment it goes to confirming.
    assert_eq!(mode(&app, admin).await, "solo");
    let req = Request::post(format!("/api/blockparty/{id}/transition-confirming"))
        .header(token.0, token.1)
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "ready", "precondition");
    assert_eq!(mode(&app, admin).await, "blockparty");

    let req = Request::post(format!("/api/blockparty/{id}/dissolve"))
        .header(token.0, token.1)
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(mode(&app, admin).await, "solo");

    let _ = sqlx::query("DELETE FROM blockparty_group WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await;
}
