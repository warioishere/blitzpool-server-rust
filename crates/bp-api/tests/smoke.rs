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

/// State with a live-store handle — for endpoints that read the
/// `client:live:*` hashes. Borrowed NO-FLUSH index: these tests write
/// nothing to Redis and tolerate any content, so no flushing sibling is
/// harmed and none can harm them. `None` = Redis unreachable → skip.
async fn state_with_live_store(pool: PgPool) -> Option<Arc<AppState<NoopHooks, NoopEmailHooks>>> {
    let redis = bp_test_support::connect_redis_in_range_no_flush(
        bp_test_support::redis_db::SESSION_PERSISTENCE,
        31,
    )
    .await?;
    let mut state = AppState::<NoopHooks, NoopEmailHooks>::new(pool, "0.0.0");
    state.redis = Some(redis);
    Some(Arc::new(state))
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
    assert_eq!(json["code"], "upstream-unavailable");
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
                .uri("/api/pplns/groups/public")
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
    assert_eq!(json["code"], "invalid-address");
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
                .uri("/api/pplns/invitations/open/some-token")
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

/// `14d` is a valid preset — the /stats page reads a 14-day average
/// and used to pull the 30-day `1m` payload to get it. Before the
/// preset existed this exact request answered 400, so the assertion
/// pins the addition and not just "some range parses".
#[tokio::test]
async fn info_chart_accepts_fourteen_day_range() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let router = build_router(minimal_state(pool));
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/info/chart?range=14d")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
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
    // `/api/pplns/invitations/open/:token/accept` is rate-limited (10/min);
    // SmartIpKeyExtractor needs an IP source — set the proxy-style
    // header so the layer can key by client IP instead of erroring
    // with 500. A valid JSON body clears the extractor so the handler
    // reaches the service-unwired 503.
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/pplns/invitations/open/some-token/accept")
                .header("x-forwarded-for", "127.0.0.1")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"address":"test_addr"}"#))
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
    // `/api/pool` reads the live hashrate from the `client:live:*`
    // Redis hashes; the test asserts only the wire shape.
    let Some(state) = state_with_live_store(pool).await else {
        return;
    };
    let router = build_router(state);
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

/// Without a Redis handle the live hashrate is unknowable, and the
/// endpoint must say so (500), never invent a 0 total.
#[tokio::test]
async fn pool_endpoint_without_live_store_returns_500() {
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
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
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
    assert_eq!(json["code"], "missing-fields-address-endpoint");
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

#[tokio::test]
async fn worker_chart_breaks_rejects_down_by_every_reason() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    // A worker page shows the per-reason breakdown against `rejectedCount`.
    // A reason with a column but no field in `WorkerChartEntry` is a reject
    // the operator sees in the total and cannot find in the breakdown —
    // which is what happened to version rolling between migration 0010 and
    // the field being added. Five distinct counts, so a field wired to the
    // wrong column shows up as a wrong number rather than a coincidence.
    let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let worker = "chart_breakdown_probe";
    // `client_entity."sessionId"` is varchar(8).
    let session = "chartbrk";
    // `TimeSlot` is the slot's END, and the handler keeps rows strictly
    // below `chart_visibility_cutoff_slot`. One slot below it is therefore
    // the newest visible one, and well inside the default 1d window.
    let slot = bp_stats::slot::chart_visibility_cutoff_slot()
        .previous()
        .as_millis();

    let mut tx = pool.begin().await.expect("begin");
    sqlx::query(
        r#"INSERT INTO client_entity (address, "clientName", "sessionId", "startTime")
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(addr)
    .bind(worker)
    .bind(session)
    .bind(slot)
    .execute(&mut *tx)
    .await
    .expect("seed client");
    sqlx::query(
        r#"INSERT INTO client_statistics_entity
             (address, "clientName", "sessionId", "time", shares,
              "acceptedCount", "rejectedCount",
              "rejectedJobNotFoundCount",       "rejectedJobNotFoundDiff1",
              "rejectedDuplicateShareCount",    "rejectedDuplicateShareDiff1",
              "rejectedLowDifficultyShareCount","rejectedLowDifficultyShareDiff1",
              "rejectedVersionRollingCount",    "rejectedVersionRollingDiff1",
              "rejectedStaleCount",             "rejectedStaleDiff1")
           VALUES ($1,$2,$3,$4, 10, 1, 15, 1,0.5, 2,0.25, 3,0.125, 4,0.0625, 5,0.03125)"#,
    )
    .bind(addr)
    .bind(worker)
    .bind(session)
    .bind(slot)
    .execute(&mut *tx)
    .await
    .expect("seed stats");
    tx.commit().await.expect("commit");

    // The worker page composes live fields from Redis now.
    let Some(state) = state_with_live_store(pool.clone()).await else {
        return;
    };
    let router = build_router(state);
    let resp = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/client/{addr}/{worker}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();

    // Clean up before asserting, so a failure doesn't poison the next run.
    let _ = sqlx::query(
        r#"DELETE FROM client_statistics_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#,
    )
    .bind(addr)
    .bind(worker)
    .bind(session)
    .execute(&pool)
    .await;
    let _ = sqlx::query(
        r#"DELETE FROM client_entity
           WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#,
    )
    .bind(addr)
    .bind(worker)
    .bind(session)
    .execute(&pool)
    .await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let entry = json["chartData"]
        .as_array()
        .and_then(|a| a.first())
        .cloned()
        .unwrap_or_else(|| panic!("no chartData in {json}"));

    let n = |k: &str| -> f64 {
        entry
            .get(k)
            .and_then(serde_json::Value::as_f64)
            .unwrap_or_else(|| panic!("missing `{k}` in {entry}"))
    };
    assert_eq!(n("rejectedJobNotFound"), 1.0);
    assert_eq!(n("rejectedDuplicatedShare"), 2.0);
    assert_eq!(n("rejectedLowDifficultyShare"), 3.0);
    assert_eq!(n("rejectedVersionRolling"), 4.0);
    assert_eq!(n("rejectedStale"), 5.0);
    // The point of the whole struct: the breakdown accounts for the total.
    let sum = n("rejectedJobNotFound")
        + n("rejectedDuplicatedShare")
        + n("rejectedLowDifficultyShare")
        + n("rejectedVersionRolling")
        + n("rejectedStale");
    assert_eq!(sum, 15.0, "breakdown must sum to rejectedCount, got {sum}");
    // Diff-1 weights ride along per reason and must not be cross-wired.
    assert_eq!(n("rejectedVersionRollingDiff1"), 0.0625);
    assert_eq!(n("rejectedStaleDiff1"), 0.03125);
    // Hashrate is rounded like every chart endpoint: 10 × 2^32 / 600 s is
    // 71_582_788.27 H/s unrounded.
    assert_eq!(n("data"), 71_582_788.0);
}

/// GET a path on a fresh router; returns status + parsed JSON body.
async fn get_json(pool: PgPool, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = build_router(minimal_state(pool))
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("non-JSON body for {uri} ({e}): {bytes:?}"));
    (status, json)
}

#[tokio::test]
async fn best_difficulty_today_maxes_workers_and_slots_from_since() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    // Own address: no sibling test in this binary touches it.
    let addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    let hour: i64 = 60 * 60 * 1000;
    // `since` on an hour boundary, one hour back, so `since + 1h` is the
    // current hour and every seeded slot lies inside the accepted window.
    let since = (bp_common::now_ms() / hour) * hour - hour;
    // Values exactly representable as f32 (the column is `real`). The
    // highest one sits in the slot BEFORE `since`, so it only shows up in
    // the answer if the boundary is wrong.
    let rows: [(&str, i64, f32); 4] = [
        ("rig_a", since - hour, 9_000.5),
        ("rig_a", since, 1_500.25),
        ("rig_b", since, 800.0),
        ("rig_b", since + hour, 2_048.75),
    ];
    let cleanup = || async {
        let _ = sqlx::query("DELETE FROM client_difficulty_statistics_entity WHERE address = $1")
            .bind(addr)
            .execute(&pool)
            .await;
    };
    cleanup().await;
    for (worker, slot, max) in rows {
        sqlx::query(
            r#"INSERT INTO client_difficulty_statistics_entity
                 (address, "clientName", "slotTime", "maxDifficulty")
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(addr)
        .bind(worker)
        .bind(slot)
        .bind(max)
        .execute(&pool)
        .await
        .expect("seed diff stat");
    }

    let today = get_json(
        pool.clone(),
        &format!("/api/client/{addr}/best-difficulty/today?since={since}"),
    )
    .await;
    // Negative control: one hour earlier the pre-`since` row is in range,
    // so it exists and a missing 9000.5 above is the filter, not the seed.
    let earlier = get_json(
        pool.clone(),
        &format!(
            "/api/client/{addr}/best-difficulty/today?since={}",
            since - hour
        ),
    )
    .await;
    // One ms past the slot start excludes that slot: no flooring to the hour.
    let past_slot = get_json(
        pool.clone(),
        &format!(
            "/api/client/{addr}/best-difficulty/today?since={}",
            since - hour + 1
        ),
    )
    .await;
    cleanup().await;

    assert_eq!(today.0, StatusCode::OK, "{}", today.1);
    assert_eq!(today.1["bestDifficulty"], serde_json::json!(2048.75));
    assert_eq!(earlier.0, StatusCode::OK, "{}", earlier.1);
    assert_eq!(earlier.1["bestDifficulty"], serde_json::json!(9000.5));
    assert_eq!(past_slot.0, StatusCode::OK, "{}", past_slot.1);
    assert_eq!(past_slot.1["bestDifficulty"], serde_json::json!(2048.75));
}

#[tokio::test]
async fn best_difficulty_today_without_rows_is_zero() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    // P2WSH address nothing in the suite writes rows for.
    let addr = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    let since = bp_common::now_ms() - 60 * 60 * 1000;
    let (status, json) = get_json(
        pool,
        &format!("/api/client/{addr}/best-difficulty/today?since={since}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    // Whole number → JSON integer, like every `ser_f64_jsnum` field.
    assert_eq!(json["bestDifficulty"], serde_json::json!(0));
}

#[tokio::test]
async fn best_difficulty_today_rejects_missing_or_out_of_window_since() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    let now = bp_common::now_ms();
    let hour: i64 = 60 * 60 * 1000;
    let base = format!("/api/client/{addr}/best-difficulty/today");
    for uri in [
        base.clone(),
        format!("{base}?since="),
        format!("{base}?since=yesterday"),
        format!("{base}?since=1.5"),
        format!("{base}?since={}", now - 27 * hour),
        format!("{base}?since={}", now + 2 * hour),
    ] {
        let (status, json) = get_json(pool.clone(), &uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {json}");
        assert_eq!(json["code"], "invalid-query", "{uri}: {json}");
    }
    // Bad address is still the address error, checked before `since`.
    let (status, json) = get_json(
        pool,
        &format!(
            "/api/client/{}/best-difficulty/today?since={now}",
            "a".repeat(100)
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
    assert_eq!(json["code"], "invalid-address");
}

/// `POST /api/identity/resolve` records the identity it resolves, so the pool
/// can admit a miner who connects with the payout id (rented hashrate does)
/// without ever having mined with the xpub. Both directions: with the flag off
/// it answers 403 and writes nothing.
#[tokio::test]
async fn identity_resolve_records_the_identity_it_resolves() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    // BIP-32 test vector 3, master public key (published, no funds).
    let xpub = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13";
    let expected = bp_payout_descriptor::RotatingPayout::from_xpub_str(xpub)
        .expect("a BIP-32 vector is a valid xpub");
    let id = expected.payout_id().as_str().to_string();
    sqlx::query(r#"DELETE FROM miner_identity WHERE "payoutId" = $1"#)
        .bind(&id)
        .execute(&pool)
        .await
        .expect("clear any earlier run's row");

    let post = |state: Arc<AppState<NoopHooks, NoopEmailHooks>>| {
        let body = format!(r#"{{"xpub":"{xpub}"}}"#);
        async move {
            let resp = build_router(state)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/identity/resolve")
                        .header("x-forwarded-for", "127.0.0.1")
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(body))
                        .unwrap(),
                )
                .await
                .expect("oneshot");
            let status = resp.status();
            let bytes = to_bytes(resp.into_body(), 1 << 16).await.expect("body");
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            (status, json)
        }
    };

    let (status, _) = post(minimal_state(pool.clone())).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the flag defaults to off");
    assert!(
        bp_db::find_miner_identity(&pool, &id)
            .await
            .unwrap()
            .is_none(),
        "a refused resolve writes nothing"
    );

    let mut state = AppState::<NoopHooks, NoopEmailHooks>::new(pool.clone(), "0.0.0");
    state.allow_rotating_identities = true;
    let (status, json) = post(Arc::new(state)).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["payoutId"], id.as_str());
    let row = bp_db::find_miner_identity(&pool, &id)
        .await
        .unwrap()
        .expect("a resolved identity is recorded");
    assert_eq!(row.kind, bp_db::KIND_ROTATING);
    assert_eq!(
        row.descriptor.as_deref(),
        Some(expected.canonical_descriptor())
    );

    let _ = sqlx::query(r#"DELETE FROM miner_identity WHERE "payoutId" = $1"#)
        .bind(&id)
        .execute(&pool)
        .await;
}
