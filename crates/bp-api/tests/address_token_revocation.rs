// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! The sidecar revokes an address key's tokens by a signed push. A token
//! issued before the revocation then opens no route for that address, and
//! one issued after it does.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bp_api::middleware::{AddressAuth, AddressTokenSecret};
use bp_api::{build_router, AppState};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

const SECRET: &str = "test-secret-for-bp-api";
const WEEK_MS: i64 = 7 * 24 * 60 * 60 * 1000;

fn secret() -> AddressTokenSecret {
    AddressTokenSecret::new(SECRET).unwrap()
}

/// A revocation as the sidecar signs it.
fn revocation(key: &str, revoked_before: i64, expires_at: i64) -> String {
    let claims = format!(
        r#"{{"rv":{},"b":{revoked_before},"e":{expires_at}}}"#,
        Value::from(key)
    );
    let payload = URL_SAFE_NO_PAD.encode(claims);
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

#[test]
fn revocation_builds_the_sidecars_string() {
    assert_eq!(
        revocation("bc1qtokenvectoraddress", 4_101_840_000_000, 4_102_444_800_000),
        "eyJydiI6ImJjMXF0b2tlbnZlY3RvcmFkZHJlc3MiLCJiIjo0MTAxODQwMDAwMDAwLCJlIjo0MTAyNDQ0ODAwMDAwfQ.1rcSopEwNuQXGxIOLh6OjL-44ZXHyXDxPLgxCXdU_Ic"
    );
}

/// A token in the format without an issue time, signed the way the sidecar
/// signed it.
fn unstamped(key: &str, expires_at: i64) -> String {
    let claims = format!(r#"{{"a":{},"e":{expires_at}}}"#, Value::from(key));
    let payload = URL_SAFE_NO_PAD.encode(claims);
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn app(pool: PgPool, address_auth: AddressAuth) -> axum::Router {
    let mut state = AppState::new(pool, "test");
    state.address_auth = address_auth;
    build_router(Arc::new(state))
}

async fn post(app: &axum::Router, uri: &str, token: Option<&str>) -> (StatusCode, Value) {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut req = Request::post(uri)
        .header("x-forwarded-for", format!("198.18.0.{}", n % 250))
        .header("content-type", "application/json");
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = app
        .clone()
        .oneshot(req.body(axum::body::Body::from("{}")).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn revoke(app: &axum::Router, token: &str) -> (StatusCode, Value) {
    post(app, "/api/address/token-revocations", Some(token)).await
}

/// Status of a client reset for `address` with `token`.
async fn reset(app: &axum::Router, address: &str, token: &str) -> StatusCode {
    post(app, &format!("/api/client/{address}/reset"), Some(token))
        .await
        .0
}

async fn revoked_before(pool: &PgPool, key: &str) -> Option<i64> {
    sqlx::query_scalar(
        r#"SELECT "revokedBefore" FROM address_token_revocation WHERE "addressKey" = $1"#,
    )
    .bind(key)
    .fetch_optional(pool)
    .await
    .unwrap()
}

async fn forget(pool: &PgPool, key: &str) {
    let _ = sqlx::query(r#"DELETE FROM address_token_revocation WHERE "addressKey" = $1"#)
        .bind(key)
        .execute(pool)
        .await;
}

#[tokio::test]
async fn a_revocation_voids_the_tokens_issued_before_it() {
    let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
        return;
    };
    let address = "bc1qrevokedtokens";
    forget(&pool, address).await;
    let app = app(pool.clone(), AddressAuth::Required(secret()));
    let now = bp_common::now_ms();
    let before = secret().issue(address, now - 10_000, now + 60_000);
    let old_format = unstamped(address, now + 60_000);
    assert_eq!(
        reset(&app, address, &before).await,
        StatusCode::OK,
        "precondition"
    );
    assert_eq!(
        reset(&app, address, &old_format).await,
        StatusCode::OK,
        "precondition"
    );

    let (status, body) = revoke(&app, &revocation(address, now - 5_000, now + 60_000)).await;
    assert_eq!((status, body), (StatusCode::OK, json!({ "ok": true })));

    assert_eq!(
        reset(&app, address, &before).await,
        StatusCode::UNAUTHORIZED
    );
    // Without an issue time a token counts as a week older than its expiry.
    assert_eq!(
        reset(&app, address, &old_format).await,
        StatusCode::UNAUTHORIZED
    );
    let after = secret().issue(address, now, now + 60_000);
    assert_eq!(reset(&app, address, &after).await, StatusCode::OK);
    // Another address keeps its tokens.
    let other = secret().issue("bc1qnotrevoked", now - 10_000, now + 60_000);
    assert_eq!(reset(&app, "bc1qnotrevoked", &other).await, StatusCode::OK);

    forget(&pool, address).await;
}

#[tokio::test]
async fn the_stored_moment_only_moves_forward_and_never_past_now() {
    let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
        return;
    };
    let key = "bc1qrevocationmoment";
    forget(&pool, key).await;
    let app = app(pool.clone(), AddressAuth::Required(secret()));
    let now = bp_common::now_ms();

    assert_eq!(
        revoke(&app, &revocation(key, now - 1_000, now + 60_000))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(revoked_before(&pool, key).await, Some(now - 1_000));
    // An earlier moment, or the same push again, changes nothing.
    assert_eq!(
        revoke(&app, &revocation(key, now - 9_000, now + 60_000))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        revoke(&app, &revocation(key, now - 1_000, now + 60_000))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(revoked_before(&pool, key).await, Some(now - 1_000));
    // A moment in the future counts as now.
    assert_eq!(
        revoke(&app, &revocation(key, now + WEEK_MS, now + 60_000))
            .await
            .0,
        StatusCode::OK
    );
    let stored = revoked_before(&pool, key).await.unwrap();
    assert!(stored >= now && stored <= bp_common::now_ms(), "{stored}");

    forget(&pool, key).await;
}

#[tokio::test]
async fn only_a_signed_unexpired_revocation_is_stored() {
    let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
        return;
    };
    let key = "bc1qrevocationrefused";
    forget(&pool, key).await;
    let app = app(pool.clone(), AddressAuth::Required(secret()));
    let now = bp_common::now_ms();
    let valid = revocation(key, now, now + 60_000);
    let forged = format!("{}x", &valid[..valid.len() - 1]);
    let address_token = secret().issue(key, now, now + 60_000);
    let expired = revocation(key, now, now - 1);
    let empty_key = revocation("", now, now + 60_000);

    for (what, token) in [
        ("missing", None),
        ("forged", Some(forged.as_str())),
        ("expired", Some(expired.as_str())),
        ("empty key", Some(empty_key.as_str())),
        ("address token", Some(address_token.as_str())),
    ] {
        let (status, body) = post(&app, "/api/address/token-revocations", token).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{what}: {body}");
    }
    assert_eq!(revoked_before(&pool, key).await, None);

    let no_secret = self::app(pool.clone(), AddressAuth::Off(None));
    let (status, body) = revoke(&no_secret, &valid).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(revoked_before(&pool, key).await, None);

    // With the check off a configured secret still takes the push.
    let off = self::app(pool.clone(), AddressAuth::Off(Some(secret())));
    assert_eq!(revoke(&off, &valid).await.0, StatusCode::OK);
    assert!(revoked_before(&pool, key).await.is_some());

    forget(&pool, key).await;
}
