// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! A pool proof of an address turns into its address token: a verified email
//! gets a link carrying the address and the token, a verified signature gets the token in the
//! answer. Neither hands one out while the address-token check is off.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::to_bytes;
use axum::http::{header::AUTHORIZATION, HeaderMap, HeaderValue, Request, StatusCode};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network};
use bp_api::middleware::address_auth::authorize;
use bp_api::middleware::{AddressAuth, AddressTokenSecret};
use bp_api::{
    build_router, AddressAccessContext, AppState, BindingChangeContext, EmailVerificationHooks,
    VerificationContext,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

const SECRET: &str = "test-secret-for-bp-api";
const BASE_URL: &str = "https://pool.example";

#[derive(Default)]
struct CapturingHooks {
    access: Mutex<Vec<AddressAccessContext>>,
}

#[async_trait]
impl EmailVerificationHooks for CapturingHooks {
    async fn send_verification(&self, _ctx: VerificationContext) {}
    async fn send_binding_change_attempt(&self, _ctx: BindingChangeContext) {}
    async fn send_address_access(&self, ctx: AddressAccessContext) {
        self.access.lock().unwrap().push(ctx);
    }
}

fn secret() -> AddressTokenSecret {
    AddressTokenSecret::new(SECRET).unwrap()
}

fn app(pool: PgPool, address_auth: AddressAuth, hooks: Arc<CapturingHooks>) -> axum::Router {
    let mut state = AppState::new(pool, "test");
    state.address_auth = address_auth;
    state.email_enabled = true;
    state.pool_base_url = Some(BASE_URL.to_string());
    state.email_verification_hooks = hooks;
    build_router(Arc::new(state))
}

/// Each call from its own client IP, so the per-IP limits stay out of the way.
async fn post(app: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let req = Request::post(uri)
        .header("x-forwarded-for", format!("192.0.2.{}", n % 250))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn token_passes(token: &str, address: &str) -> bool {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    authorize(&secret(), &headers, address, bp_common::now_ms()).is_ok()
}

async fn request_link(app: &axum::Router, address: &str) -> (StatusCode, Value) {
    post(
        app,
        "/api/address/password-link",
        json!({ "address": address }),
    )
    .await
}

/// A mainnet address of `kind` for the key `[seed; 32]`.
fn address(seed: u8, kind: &str) -> String {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
    let pk = CompressedPublicKey(sk.public_key(&secp));
    match kind {
        "p2pkh" => Address::p2pkh(pk, Network::Bitcoin).to_string(),
        _ => Address::p2wpkh(&pk, Network::Bitcoin).to_string(),
    }
}

/// The address and token a sent link carries.
fn link_parts(ctx: &AddressAccessContext) -> (String, String) {
    let rest = ctx
        .access_url
        .strip_prefix(&format!("{BASE_URL}/#/address-access/"))
        .expect("link shape");
    let (address, token) = rest.split_once('/').expect("address/token");
    (address.to_string(), token.to_string())
}

#[tokio::test]
async fn a_verified_email_gets_a_link_with_the_address_and_its_token() {
    let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
        return;
    };
    // Base58 keeps its case in the link; bech32 is written lowercase.
    let base58 = address(0x31, "p2pkh");
    let bech32 = address(0x32, "p2wpkh");
    let pending = address(0x33, "p2wpkh");
    let unbound = address(0x34, "p2wpkh");
    bp_test_support::seed_verified_email(&pool, &base58, "owner@example.com").await;
    bp_test_support::seed_verified_email(&pool, &bech32, "segwit@example.com").await;
    bp_test_support::seed_verified_email(&pool, &pending, "pending@example.com").await;
    sqlx::query(r#"UPDATE pplns_address_email SET "verifiedAt" = NULL WHERE address = $1"#)
        .bind(&pending)
        .execute(&pool)
        .await
        .unwrap();
    bp_test_support::delete_email_binding(&pool, &unbound).await;

    let hooks = Arc::new(CapturingHooks::default());
    let app = app(pool.clone(), AddressAuth::Required(secret()), hooks.clone());

    let same = (StatusCode::OK, json!({ "sent": true }));
    assert_eq!(request_link(&app, &base58).await, same);
    assert_eq!(request_link(&app, &bech32.to_uppercase()).await, same);
    {
        let sent = hooks.access.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].to_email, "owner@example.com");
        assert_eq!(sent[1].to_email, "segwit@example.com");
        for (ctx, want) in sent.iter().zip([&base58, &bech32]) {
            let (linked, token) = link_parts(ctx);
            assert_eq!(&linked, want, "the normalized address");
            assert_eq!(&ctx.address, want);
            assert!(token_passes(&token, want));
            assert!(!token_passes(&token, &unbound));
        }
    }

    // The same answer without a verified email, and no mail.
    assert_eq!(request_link(&app, &pending).await, same);
    assert_eq!(request_link(&app, &unbound).await, same);
    // A second request inside the cooldown sends nothing either.
    assert_eq!(request_link(&app, &base58).await, same);
    assert_eq!(hooks.access.lock().unwrap().len(), 2);
    // Not an address of the pool's network.
    let (status, body) = request_link(&app, "bc1qnotarealaddress").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    for a in [&base58, &bech32, &pending] {
        bp_test_support::delete_email_binding(&pool, a).await;
    }
}

#[tokio::test]
async fn with_the_check_off_no_link_goes_out() {
    let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
        return;
    };
    let verified = address(0x35, "p2wpkh");
    bp_test_support::seed_verified_email(&pool, &verified, "off@example.com").await;
    let hooks = Arc::new(CapturingHooks::default());
    let app = app(pool.clone(), AddressAuth::Off(None), hooks.clone());

    let (status, body) = request_link(&app, &verified).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "address-auth-disabled");
    assert!(hooks.access.lock().unwrap().is_empty());

    bp_test_support::delete_email_binding(&pool, &verified).await;
}

/// A BIP-322 signature by `sk` over `message` for `address`.
fn sign(sk: &SecretKey, address: &str, message: &str) -> String {
    let wif = bitcoin::PrivateKey::new(*sk, Network::Bitcoin).to_wif();
    bip322::sign_simple_encoded(address, message, &[wif], None).unwrap()
}

/// Challenge, sign, verify: the verify answer. `honest = false` signs another
/// message than the challenge.
async fn prove(
    app: &axum::Router,
    address: &str,
    sk: &SecretKey,
    honest: bool,
) -> (StatusCode, Value) {
    let (status, challenge) = post(
        app,
        "/api/address/ownership/challenge",
        json!({ "address": address }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    let mut message = challenge["message"].as_str().unwrap().to_string();
    if !honest {
        message.push_str(" (altered)");
    }
    post(
        app,
        "/api/address/ownership/verify",
        json!({ "address": address, "signature": sign(sk, address, &message) }),
    )
    .await
}

#[tokio::test]
async fn a_verified_signature_answers_with_the_addresss_token() {
    let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
        return;
    };
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x23u8; 32]).unwrap();
    let pk = CompressedPublicKey(sk.public_key(&secp));
    let address = Address::p2wpkh(&pk, Network::Bitcoin).to_string();
    let hooks = Arc::new(CapturingHooks::default());

    let on = app(pool.clone(), AddressAuth::Required(secret()), hooks.clone());
    let (status, body) = prove(&on, &address, &sk, true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["addressToken"].as_str().expect("addressToken");
    assert!(token_passes(token, &address));

    // A signature over another message proves nothing and carries no token.
    let (status, body) = prove(&on, &address, &sk, false).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.get("addressToken").is_none(), "{body}");

    let off = app(pool.clone(), AddressAuth::Off(None), hooks);
    let (status, body) = prove(&off, &address, &sk, true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("addressToken").is_none(), "{body}");

    bp_test_support::delete_signature_ownership(&pool, &address).await;
}
