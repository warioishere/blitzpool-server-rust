// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Smoke tests for the API router. Verify that:
//! 1. `build_router` constructs without panic on a minimal `AppState`.
//! 2. The "unavailable" paths return 503 with the expected JSON envelope
//!    when their backing handle isn't wired (no PPLNS engine / no TDP).
//! 3. The wired `/api/info/version` + `/api/health` endpoints return 200.
//!
//! All tests run in-process via `tower::ServiceExt::oneshot` — no
//! actual HTTP listener is started.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use bp_api::{build_router, AppState};
use bp_group_mgmt_engine::{NoopEmailHooks, NoopHooks};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

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
            eprintln!("PG connect failed for {url}: {e} — skipping");
            return None;
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            return None;
        }
    }
}

fn minimal_state(pool: PgPool) -> Arc<AppState<NoopHooks, NoopEmailHooks>> {
    Arc::new(AppState::<NoopHooks, NoopEmailHooks>::new(pool, "0.0.0"))
}

#[tokio::test]
async fn version_endpoint_returns_pool_version() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/info/version")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // Wire shape: `{ version: "v<semver>" }` — the `v`-prefix is part
    // of the wire string so the UI can render it verbatim.
    assert_eq!(json["version"], "v0.0.0");
}

#[tokio::test]
async fn pplns_status_returns_503_when_engine_unwired() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/pplns/status")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"]["code"], "upstream-unavailable");
}

#[tokio::test]
async fn block_template_returns_503_when_tdp_unwired() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/info/block-template")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn health_returns_ok_with_database_check() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 2048).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["status"], "healthy");
    assert_eq!(json["checks"]["database"], "connected");
    assert!(json["checks"]["bitcoin"].is_null());
    // No Redis wired into minimal_state → cache check is null (absent),
    // not "disconnected". Mirrors the bitcoin field's None handling.
    assert!(json["checks"]["cache"].is_null());
    // No TDP handle wired → tdp check is null (absent). With no handle
    // the staleness gate can't trip, so status stays "healthy".
    assert!(json["checks"]["tdp"].is_null());
}

#[tokio::test]
async fn groups_returns_503_when_service_unwired() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/pplns/groups")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn client_by_address_invalid_returns_400() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    // Empty / whitespace-only path segment is normalised by axum, but
    // a clearly-invalid (too-long) address fails AddressId validation.
    let resp = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/client/{}", "a".repeat(100)))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"]["code"], "invalid-address");
}

#[tokio::test]
async fn invitation_returns_503_when_service_unwired() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/pplns/invitations/by-address/test_addr")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn info_chart_empty_db_returns_empty_array() {
    // `/api/info/chart` emits sparse data: one ChartPoint per DB row
    // that falls in the window, no pre-filled zero buckets. Empty
    // DB therefore returns `[]`, not the slot-aligned skeleton.
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/info/chart?range=1d")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = json.as_array().expect("array");
    assert!(
        arr.is_empty(),
        "expected empty array, got {} entries",
        arr.len()
    );
}

#[tokio::test]
async fn info_chart_invalid_range_returns_400() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/info/chart?range=forever")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn info_shares_returns_singleton_totals() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/info/shares")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 2048).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // Wire shape uses camelCase: `accepted1d`, `rejected1d`,
    // `accepted14d`, `rejected14d`, `acceptedSinceBlock`.
    assert!(json["accepted1d"].is_number());
    assert!(json["accepted14d"].is_number());
    assert!(json["acceptedSinceBlock"].is_number());
}

#[tokio::test]
async fn post_group_returns_503_when_service_unwired() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/pplns/groups")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    // request body uses camelCase keys.
                    r#"{"name":"x","creatorAddress":"bc1qx"}"#,
                ))
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn delete_group_returns_503_when_service_unwired() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let resp = router
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/pplns/groups/{}", uuid::Uuid::new_v4()))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn invitation_accept_returns_503_when_service_unwired() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    // `/api/pplns/invitations/:token/accept` is rate-limited (20/min);
    // SmartIpKeyExtractor needs an IP source — set the proxy-style
    // header so the layer can key by client IP instead of erroring
    // with 500.
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/pplns/invitations/some-token/accept")
                .header("x-forwarded-for", "127.0.0.1")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn pool_endpoint_returns_basic_shape() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/pool")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // Wire shape: `totalHashRate` + `totalMiners` are numbers,
    // `blocksFound` is the found-block log (array of entries),
    // `fee` is a scalar number.
    assert!(json["totalHashRate"].is_number());
    assert!(json["totalMiners"].is_number());
    assert!(json["blocksFound"].is_array());
    assert!(json["fee"].is_number());
}

#[tokio::test]
async fn push_info_returns_camelcase_doc() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/push/info")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // Shape pinning — `notificationTypes` + `unifiedPush` +
    // `rateLimits` are the expected top-level keys.
    assert_eq!(json["success"], true);
    assert!(json["notificationTypes"].is_array());
    assert!(json["unifiedPush"]["exampleEndpoints"].is_array());
    assert!(json["rateLimits"]["bestDiffNotifications"].is_string());
}

#[tokio::test]
async fn push_register_missing_fields_returns_400() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let body = axum::body::Body::from(r#"{"address":""}"#);
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/push/register")
                .header("content-type", "application/json")
                .body(body)
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"]["code"], "missing-fields-address-endpoint");
}

#[tokio::test]
async fn push_status_for_unknown_address_returns_empty_shape() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    // Valid bech32 mainnet test vector — has no subscriptions in dev DB.
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/push/status/bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["subscriptionCount"], 0);
    assert!(json["subscriptions"].is_array());
}

#[tokio::test]
async fn client_reset_best_difficulty_succeeds() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    // The reset path resets `address_settings.bestDifficulty` AND deletes
    // the address's `best_difficulty_tracker_entity` row. A wrong table
    // name in that DELETE (the table is `_entity`-suffixed) makes the
    // endpoint 500 at runtime — this pins it to 200. Valid bech32
    // mainnet test vector with no real data in the dev DB.
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/client/bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4/reset")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["status"], "reset");
}
