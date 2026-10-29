// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! With the address-token check on, the routes that act for one address
//! answer 401 `{"error": "login required"}` unless the request carries that
//! address's token from the UI sidecar, and reach their own checks with it.
//! With the check off they take any request. The tokens below were issued by
//! the sidecar's algorithm with [`SECRET`].

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use bp_api::middleware::{AddressAuth, AddressTokenSecret};
use bp_api::{build_router, AppState};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

const SECRET: &str = "test-secret-for-bp-api";
const ADDRESS: &str = "bc1qtokenvectoraddress";
const TOKEN: &str = "eyJhIjoiYmMxcXRva2VudmVjdG9yYWRkcmVzcyIsImUiOjQxMDI0NDQ4MDAwMDB9.bG_liAI04HABECVjbYh-FutN61qwWXhMmph4R6AZlts";
const BASE58: &str = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
const BASE58_TOKEN: &str = "eyJhIjoiMWJ2Ym1zZXlzdHdldHF0Zm41YXU0bTRnZmc3eGphbnZuMiIsImUiOjQxMDI0NDQ4MDAwMDB9.ZCOb5F4HvrtHwXDIJ6mLdvSMw-AlXQlrNPKLfr9kmss";
const EXPIRED_TOKEN: &str = "eyJhIjoiYmMxcXRva2VudmVjdG9yYWRkcmVzcyIsImUiOjEwMDB9.7xQ1LDXx9V6e61DJIJ8v3RVwEgG221JRRJbzk2yDHwc";
const ACCOUNT_TOKEN: &str =
    "eyJhY2N0IjoiMDJhYmMiLCJlIjo0MTAyNDQ0ODAwMDAwfQ.9RvDIeR-pfWTnaK1-gQv_gQdL-5Ou7qotLbNk-KDzBM";
const OTHER: &str = "bc1qsomeoneelseaddress";
const SOME_ID: &str = "00000000-0000-0000-0000-000000000001";

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

/// A pool that is never connected: a request refused before its handler
/// touches the database answers without one.
fn unconnected_pool() -> PgPool {
    PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy("postgres://nobody@127.0.0.1:1/none")
        .unwrap()
}

fn app(pool: PgPool, address_auth: AddressAuth) -> axum::Router {
    let mut state = AppState::new(pool, "test");
    state.address_auth = address_auth;
    build_router(Arc::new(state))
}

fn required() -> AddressAuth {
    AddressAuth::Required(AddressTokenSecret::new(SECRET).unwrap())
}

/// Each call from its own client IP, so the per-IP limits stay out of the way.
async fn post(
    app: &axum::Router,
    uri: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut req = Request::post(uri)
        .header("x-forwarded-for", format!("203.0.{}.{}", n / 250, n % 250))
        .header("content-type", "application/json");
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = app
        .clone()
        .oneshot(req.body(axum::body::Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn assert_login_required((status, body): (StatusCode, Value), what: &str) {
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{what}");
    assert_eq!(body, json!({ "error": "login required" }), "{what}");
}

/// The address a route acts for, and the request that names it.
struct AddressRoute {
    name: &'static str,
    uri: String,
    body: fn(&str) -> Value,
}

/// The six routes that read the address from the body or need a service;
/// the three `/api/client` writes take it from the path.
fn body_routes() -> Vec<AddressRoute> {
    vec![
        AddressRoute {
            name: "email register",
            uri: "/api/email/register".into(),
            body: |a| json!({ "address": a, "email": "miner@example.com" }),
        },
        AddressRoute {
            name: "team create",
            uri: "/api/pplns/groups".into(),
            body: |a| json!({ "name": "bp-test-token-team", "creatorAddress": a }),
        },
        AddressRoute {
            name: "team join request",
            uri: format!("/api/pplns/groups/public/{SOME_ID}/join-request"),
            body: |a| json!({ "address": a }),
        },
        AddressRoute {
            name: "open invite accept",
            uri: "/api/pplns/invitations/open/sometoken/accept".into(),
            body: |a| json!({ "address": a }),
        },
        AddressRoute {
            name: "blockparty create",
            uri: "/api/blockparty".into(),
            body: |a| json!({ "name": "bp-test-token-party", "adminAddress": a, "adminPercentBp": 10000 }),
        },
        AddressRoute {
            name: "blockparty join",
            uri: "/api/blockparty/join/sometoken".into(),
            body: |a| json!({ "address": a }),
        },
    ]
}

const CLIENT_WRITES: [&str; 3] = ["reset", "delete-stats", "delete-all"];

#[tokio::test]
async fn every_address_route_refuses_a_request_without_its_token() {
    let app = app(unconnected_pool(), required());
    let forged = format!("{}x", &TOKEN[..TOKEN.len() - 1]);
    let refused: [(&str, Option<&str>); 5] = [
        ("no header", None),
        ("expired", Some(EXPIRED_TOKEN)),
        ("account token", Some(ACCOUNT_TOKEN)),
        ("forged signature", Some(&forged)),
        ("garbage", Some("not-a-token")),
    ];
    for (what, token) in refused {
        for route in body_routes() {
            let res = post(&app, &route.uri, token, (route.body)(ADDRESS)).await;
            assert_login_required(res, &format!("{}: {what}", route.name));
        }
        for write in CLIENT_WRITES {
            let uri = format!("/api/client/{ADDRESS}/{write}");
            let res = post(&app, &uri, token, json!({})).await;
            assert_login_required(res, &format!("{write}: {what}"));
        }
    }
}

#[tokio::test]
async fn a_token_for_another_address_is_refused() {
    let app = app(unconnected_pool(), required());
    for route in body_routes() {
        let res = post(&app, &route.uri, Some(TOKEN), (route.body)(OTHER)).await;
        assert_login_required(res, route.name);
    }
    for write in CLIENT_WRITES {
        let uri = format!("/api/client/{OTHER}/{write}");
        assert_login_required(post(&app, &uri, Some(TOKEN), json!({})).await, write);
    }
}

#[tokio::test]
async fn with_the_check_off_a_request_without_a_token_goes_through() {
    let app = app(unconnected_pool(), AddressAuth::Off);
    for route in body_routes() {
        let (status, body) = post(&app, &route.uri, None, (route.body)(ADDRESS)).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{}: {body}",
            route.name
        );
    }
    // No database behind the pool, so the writes fail inside the handler.
    for write in CLIENT_WRITES {
        let uri = format!("/api/client/{ADDRESS}/{write}");
        let (status, body) = post(&app, &uri, None, json!({})).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{write}: {body}");
    }
}

/// With the matching token each route runs into its own next check: no
/// service is wired and email is off, so each answers that, not 401.
#[tokio::test]
async fn the_matching_token_reaches_the_handlers_own_checks() {
    let app = app(unconnected_pool(), required());
    for route in body_routes() {
        let (status, body) = post(&app, &route.uri, Some(TOKEN), (route.body)(ADDRESS)).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{}: {body}",
            route.name
        );
        assert_ne!(body, json!({ "error": "login required" }), "{}", route.name);
    }
}

#[tokio::test]
async fn the_matching_token_runs_the_client_writes() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let app = app(pool, required());
    for (write, status) in [
        ("reset", "reset"),
        ("delete-stats", "stats-deleted"),
        ("delete-all", "all-deleted"),
    ] {
        let uri = format!("/api/client/{ADDRESS}/{write}");
        let (code, body) = post(&app, &uri, Some(TOKEN), json!({})).await;
        assert_eq!(code, StatusCode::OK, "{write}: {body}");
        assert_eq!(body["status"], status, "{write}");
    }
}

#[tokio::test]
async fn a_base58_route_takes_the_lowercased_token() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let app = app(pool, required());
    let uri = format!("/api/client/{BASE58}/reset");
    let (code, body) = post(&app, &uri, Some(BASE58_TOKEN), json!({})).await;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "reset");
}
