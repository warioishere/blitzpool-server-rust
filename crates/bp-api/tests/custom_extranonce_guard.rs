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
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                // The layer keys rate-limits by client IP; give it a source so it
                // doesn't 500 on a missing one.
                .header("x-forwarded-for", "127.0.0.1")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
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
        r#"{{"address":"{SOLO_ADDR}","worker":"w1","extranonce":"c0debabe","token":"deadbeef"}}"#
    );
    let (status, json) = post_json(
        build_router(minimal_state(pool.clone())),
        "/api/address/extranonce/set",
        body,
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
