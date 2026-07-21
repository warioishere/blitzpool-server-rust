// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! Integration test for the custom-extranonce Solo-eligibility guard.
//!
//! The core applies overrides only on the Solo stream, so the API must reject
//! addresses it can determine are non-Solo — group / Group-Solo / Blockparty
//! members — instead of persisting an override the core would silently drop.
//! Runs against a real PG (skips if none reachable), mirroring `smoke.rs`.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use bp_api::{build_router, AppState};
use bp_group_mgmt_engine::{NoopEmailHooks, NoopHooks};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";

// Two distinct valid mainnet bech32 addresses (BIP-173 test vectors).
const GROUPED_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const SOLO_ADDR: &str = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
const TEST_GROUP_NAME: &str = "custom-en-guard-test";

// One address PER TEST: `pplns_extranonce_token` is keyed by address, so
// tests sharing an address would overwrite each other's token and fail
// spuriously under cargo's parallel test execution.
const SWAP_ADDR: &str = "bc1qan5dp8qdayxfs4wtflhzaesjlxp3mq3808yssq";
const ATOMIC_ADDR: &str = "bc1q2vfxp232rx0z9rzn0hay9jptagk8c86d9w4l7k";
const DUP_ADDR: &str = "bc1qha7546x08qwudehuc724np522c2n65m4sseeae";
const HEADER_ADDR: &str = "bc1qyr9dx2zjg7rdla2dwc20za975w2gxtr4q39arj";

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
            None
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            None
        }
    }
}

fn minimal_state(pool: PgPool) -> Arc<AppState<NoopHooks, NoopEmailHooks>> {
    Arc::new(AppState::<NoopHooks, NoopEmailHooks>::new(pool, "0.0.0"))
}

/// Delete any rows a prior (possibly panicking) run left behind, so the test is
/// re-runnable. The group delete cascades to its members (FK ON DELETE CASCADE).
async fn cleanup(pool: &PgPool) {
    let _ = sqlx::query("DELETE FROM pplns_group_member WHERE address = $1")
        .bind(GROUPED_ADDR)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM pplns_group WHERE name = $1")
        .bind(TEST_GROUP_NAME)
        .execute(pool)
        .await;
}

async fn post_json(
    router: axum::Router,
    uri: &str,
    body: String,
) -> (StatusCode, serde_json::Value) {
    post_json_auth(router, uri, body, None).await
}

/// POST with an optional `Authorization: Bearer` token — the extranonce
/// `set` endpoint takes its token in the header, not the body.
async fn post_json_auth(
    router: axum::Router,
    uri: &str,
    body: String,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("x-forwarded-for", "127.0.0.1")
        .header("content-type", "application/json");
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = router
        .oneshot(req.body(axum::body::Body::from(body)).unwrap())
        .await
        .expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn post_challenge(router: axum::Router, address: &str) -> (StatusCode, serde_json::Value) {
    let body = format!(r#"{{"address":"{address}"}}"#);
    post_json(router, "/api/address/extranonce/challenge", body).await
}

#[tokio::test]
async fn challenge_rejects_group_member_and_allows_solo() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    cleanup(&pool).await;

    // Make GROUPED_ADDR a member of a fresh group → non-Solo.
    let group_id = uuid::Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO pplns_group (id, name, "creatorAddress", "adminTokenHash")
           VALUES ($1, $2, $3, 'x')"#,
    )
    .bind(group_id)
    .bind(TEST_GROUP_NAME)
    .bind(GROUPED_ADDR)
    .execute(&pool)
    .await
    .expect("insert group");
    sqlx::query(r#"INSERT INTO pplns_group_member ("groupId", address) VALUES ($1, $2)"#)
        .bind(group_id)
        .bind(GROUPED_ADDR)
        .execute(&pool)
        .await
        .expect("insert member");

    // Grouped (non-Solo) address → 409 not-solo-mode, no challenge issued.
    let (status, json) =
        post_challenge(build_router(minimal_state(pool.clone())), GROUPED_ADDR).await;
    let grouped_ok = status == StatusCode::CONFLICT && json["code"] == "not-solo-mode";

    // Non-grouped address → 200 with a message to sign.
    let (solo_status, solo_json) =
        post_challenge(build_router(minimal_state(pool.clone())), SOLO_ADDR).await;
    let solo_ok = solo_status == StatusCode::OK && solo_json["message"].is_string();

    cleanup(&pool).await;

    assert!(
        grouped_ok,
        "group member must be rejected 409 not-solo-mode; got {status} {json}"
    );
    assert!(
        solo_ok,
        "non-grouped address must get a challenge (200 + message); got {solo_status} {solo_json}"
    );
}

/// `set` is token-gated: a Solo-eligible address that passes the Solo guard but
/// presents no token (or a wrong one) must be rejected 401 — never persisting an
/// override on the strength of the address alone.
#[tokio::test]
async fn set_rejects_without_valid_token() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    // Make sure no stale token/override for SOLO_ADDR lingers from a prior run.
    let _ = sqlx::query("DELETE FROM pplns_extranonce_token WHERE address = $1")
        .bind(SOLO_ADDR)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM pplns_custom_extranonce WHERE address = $1")
        .bind(SOLO_ADDR)
        .execute(&pool)
        .await;

    // No token has ever been issued for this address → 401 no-token.
    let body = format!(
        r#"{{"address":"{SOLO_ADDR}","workers":[{{"worker":"w1","extranonce":"c0debabe"}}]}}"#
    );
    let (status, json) = post_json_auth(
        build_router(minimal_state(pool.clone())),
        "/api/address/extranonce/set",
        body,
        Some("deadbeef"),
    )
    .await;

    // The override must NOT have been written.
    let persisted: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pplns_custom_extranonce WHERE address = $1")
            .bind(SOLO_ADDR)
            .fetch_one(&pool)
            .await
            .unwrap_or(0);

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "set without a token must be 401; got {status} {json}"
    );
    assert_eq!(
        json["code"], "no-token",
        "expected no-token code; got {json}"
    );
    assert_eq!(
        persisted, 0,
        "no override may be persisted on a rejected set"
    );
}

/// Issue a real token for `addr` straight into the DB (bypassing the
/// challenge/signature dance, which is covered elsewhere) so the batch
/// tests can exercise the `set` path itself.
async fn seed_token(pool: &PgPool, addr: &str, token: &str) {
    use sha2::{Digest, Sha256};
    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    let _ = sqlx::query(
        r#"INSERT INTO pplns_extranonce_token (address, "tokenHash", "createdAt")
           VALUES ($1, $2, 0)
           ON CONFLICT (address) DO UPDATE SET "tokenHash" = EXCLUDED."tokenHash""#,
    )
    .bind(addr)
    .bind(hash)
    .execute(pool)
    .await;
}

async fn prefixes_of(pool: &PgPool, addr: &str) -> Vec<(String, i64)> {
    sqlx::query_as::<_, (String, i64)>(
        "SELECT worker, prefix FROM pplns_custom_extranonce WHERE address = $1 ORDER BY worker",
    )
    .bind(addr)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
}

/// THE case that motivated the deferrable constraint: swapping two workers'
/// prefixes inside one batch. With a plain `UNIQUE (address, prefix)` the
/// first row would collide with the second's still-unchanged row and abort
/// the whole request, even though the END state is perfectly valid.
#[tokio::test]
async fn set_batch_can_swap_two_workers_prefixes() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let _ = sqlx::query("DELETE FROM pplns_custom_extranonce WHERE address = $1")
        .bind(SWAP_ADDR)
        .execute(&pool)
        .await;
    seed_token(&pool, SWAP_ADDR, "tok-swap").await;

    // Start: rig1=0x0aaaaaaa, rig2=0x0bbbbbbb
    let initial = format!(
        r#"{{"address":"{SWAP_ADDR}","workers":[{{"worker":"rig1","extranonce":"0aaaaaaa"}},{{"worker":"rig2","extranonce":"0bbbbbbb"}}]}}"#
    );
    let (st, js) = post_json_auth(
        build_router(minimal_state(pool.clone())),
        "/api/address/extranonce/set",
        initial,
        Some("tok-swap"),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "initial batch must apply; got {js}");

    // Now SWAP them in one batch.
    let swap = format!(
        r#"{{"address":"{SWAP_ADDR}","workers":[{{"worker":"rig1","extranonce":"0bbbbbbb"}},{{"worker":"rig2","extranonce":"0aaaaaaa"}}]}}"#
    );
    let (st, js) = post_json_auth(
        build_router(minimal_state(pool.clone())),
        "/api/address/extranonce/set",
        swap,
        Some("tok-swap"),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "swap batch must be accepted; got {js}");

    let rows = prefixes_of(&pool, SWAP_ADDR).await;
    assert_eq!(
        rows,
        vec![
            ("rig1".to_string(), 0x0bbb_bbbb),
            ("rig2".to_string(), 0x0aaa_aaaa)
        ],
        "prefixes must actually be swapped"
    );

    let _ = sqlx::query("DELETE FROM pplns_custom_extranonce WHERE address = $1")
        .bind(SWAP_ADDR)
        .execute(&pool)
        .await;
}

/// All-or-nothing: a batch whose LAST entry is invalid must leave the
/// earlier entries unwritten. A half-applied fleet config is worse than a
/// clean rejection.
#[tokio::test]
async fn set_batch_is_all_or_nothing() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let _ = sqlx::query("DELETE FROM pplns_custom_extranonce WHERE address = $1")
        .bind(ATOMIC_ADDR)
        .execute(&pool)
        .await;
    seed_token(&pool, ATOMIC_ADDR, "tok-atomic").await;

    // Second entry sits in the reserved 0x00/0x01 range → rejected.
    let body = format!(
        r#"{{"address":"{ATOMIC_ADDR}","workers":[{{"worker":"good","extranonce":"0cafe000"}},{{"worker":"bad","extranonce":"01000000"}}]}}"#
    );
    let (st, js) = post_json_auth(
        build_router(minimal_state(pool.clone())),
        "/api/address/extranonce/set",
        body,
        Some("tok-atomic"),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "must reject; got {js}");
    assert_eq!(js["code"], "reserved-extranonce-range");
    assert!(
        prefixes_of(&pool, ATOMIC_ADDR).await.is_empty(),
        "no entry may be written when any entry is invalid"
    );
}

/// Two entries in one request claiming the same prefix can never be
/// satisfied (unlike a swap) — caught up front so the error names the
/// problem instead of surfacing as a database constraint.
#[tokio::test]
async fn set_batch_rejects_duplicate_prefix_within_the_request() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    seed_token(&pool, DUP_ADDR, "tok-dup").await;
    let body = format!(
        r#"{{"address":"{DUP_ADDR}","workers":[{{"worker":"a","extranonce":"0dddddd1"}},{{"worker":"b","extranonce":"0dddddd1"}}]}}"#
    );
    let (st, js) = post_json_auth(
        build_router(minimal_state(pool.clone())),
        "/api/address/extranonce/set",
        body,
        Some("tok-dup"),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(js["code"], "duplicate-extranonce-in-batch");
}

/// The token now travels in `Authorization: Bearer`, not the body. A
/// request without the header must be rejected — and a token placed in the
/// body (the old shape) must NOT be honoured.
#[tokio::test]
async fn set_requires_the_bearer_header() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    seed_token(&pool, HEADER_ADDR, "tok-header").await;
    let body = format!(
        r#"{{"address":"{HEADER_ADDR}","token":"tok-header","workers":[{{"worker":"w","extranonce":"0eeeeee1"}}]}}"#
    );
    // No Authorization header — a body token must not stand in for it.
    let (st, js) = post_json_auth(
        build_router(minimal_state(pool.clone())),
        "/api/address/extranonce/set",
        body,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "got {js}");
    assert_eq!(js["code"], "missing-token");
}
