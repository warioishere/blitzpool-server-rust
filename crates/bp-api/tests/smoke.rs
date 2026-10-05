// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! In-process smoke tests for the API router: it builds on a minimal
//! `AppState`, unwired backends answer 503, and the wire shapes hold.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use bp_api::{build_router, AppState};
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

fn minimal_state(pool: PgPool) -> Arc<AppState> {
    Arc::new(AppState::new(pool, "0.0.0"))
}

/// State with a live-store handle — for endpoints that read the
/// `client:live:*` hashes. Borrowed NO-FLUSH index: these tests write
/// nothing to Redis and tolerate any content, so no flushing sibling is
/// harmed and none can harm them. `None` = Redis unreachable → skip.
async fn state_with_live_store(pool: PgPool) -> Option<Arc<AppState>> {
    let redis = bp_test_support::connect_redis_in_range_no_flush(
        bp_test_support::redis_db::SESSION_PERSISTENCE,
        31,
    )
    .await?;
    let mut state = AppState::new(pool, "0.0.0");
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

/// `14d` is a valid preset (the /stats page reads a 14-day average);
/// the request answers 200, not 400.
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
    // The route is rate-limited, and the limiter needs a client IP or it
    // answers 500, so the request carries `x-forwarded-for`.
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
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
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
    // the address's `best_difficulty_tracker_entity` row; the raw SQL is
    // only checked at runtime, so this pins the endpoint to 200. Valid
    // bech32 mainnet test vector with no real data in the dev DB.
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

async fn purge_probe(pool: &sqlx::PgPool, addr: &str, worker: &str, session: &str) {
    for table in ["client_statistics_entity", "client_entity"] {
        let _ = sqlx::query(&format!(
            r#"DELETE FROM {table}
               WHERE address = $1 AND "clientName" = $2 AND "sessionId" = $3"#
        ))
        .bind(addr)
        .bind(worker)
        .bind(session)
        .execute(pool)
        .await;
    }
}

#[tokio::test]
async fn worker_chart_breaks_rejects_down_by_every_reason() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    // Five distinct counts, so a breakdown field wired to the wrong column
    // shows up as a wrong number rather than a coincidence.
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

    // A run that panicked between seed and cleanup left these rows behind.
    purge_probe(&pool, addr, worker, session).await;
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
              "rejectedJobNotFoundCount",       "rejectedJobNotFoundDiff1",
              "rejectedDuplicateShareCount",    "rejectedDuplicateShareDiff1",
              "rejectedLowDifficultyShareCount","rejectedLowDifficultyShareDiff1",
              "rejectedVersionRollingCount",    "rejectedVersionRollingDiff1",
              "rejectedStaleCount",             "rejectedStaleDiff1")
           VALUES ($1,$2,$3,$4, 10, 1,0.5, 2,0.25, 3,0.125, 4,0.0625, 5,0.03125)"#,
    )
    .bind(addr)
    .bind(worker)
    .bind(session)
    .bind(slot)
    .execute(&mut *tx)
    .await
    .expect("seed stats");
    tx.commit().await.expect("commit");

    // The worker page composes live fields from Redis.
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
    purge_probe(&pool, addr, worker, session).await;

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
    assert_eq!(sum, 15.0, "the breakdown covers all 15 rejects, got {sum}");
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
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
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
    let slot = bp_stats::SLOT_DURATION_MS;
    let hour: i64 = 60 * 60 * 1000;
    // `since` on a slot boundary an hour back, inside the accepted window.
    let since = (bp_common::now_ms() / slot) * slot - hour;
    // Rows are keyed by slot END. Values exactly representable as f32 (the
    // column is `real`). The highest one is the slot that ends at `since`,
    // i.e. lies before it, so it only shows up if the boundary is wrong.
    let rows: [(&str, i64, f32); 4] = [
        ("rig_a", since, 9_000.5),
        ("rig_a", since + slot, 1_500.25),
        ("rig_b", since + slot, 800.0),
        ("rig_b", since + 2 * slot, 2_048.75),
    ];
    let cleanup = || async {
        let _ = sqlx::query("DELETE FROM client_statistics_entity WHERE address = $1")
            .bind(addr)
            .execute(&pool)
            .await;
    };
    cleanup().await;
    for (worker, slot_end, max) in rows {
        sqlx::query(
            r#"INSERT INTO client_statistics_entity
                 (address, "clientName", "sessionId", "time", shares, "maxDifficulty")
               VALUES ($1, $2, 's1', $3, 1, $4)"#,
        )
        .bind(addr)
        .bind(worker)
        .bind(slot_end)
        .bind(max)
        .execute(&pool)
        .await
        .expect("seed client stats");
    }

    let today = get_json(
        pool.clone(),
        &format!("/api/client/{addr}/best-difficulty/today?since={since}"),
    )
    .await;
    // Negative control: one slot earlier the pre-`since` row is in range,
    // so it exists and a missing 9000.5 above is the filter, not the seed.
    let earlier = get_json(
        pool.clone(),
        &format!(
            "/api/client/{addr}/best-difficulty/today?since={}",
            since - slot
        ),
    )
    .await;
    // One ms past a slot's start excludes that slot: nothing before `since`.
    let past_slot = get_json(
        pool.clone(),
        &format!(
            "/api/client/{addr}/best-difficulty/today?since={}",
            since - slot + 1
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

/// Hourly buckets take the max of the 10-minute slots that START in the
/// hour: the slot ending on the hour belongs to the hour before.
#[tokio::test]
async fn diff_scores_folds_slots_into_the_hour_they_start_in() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    // Own address: no sibling test in this binary touches it.
    let addr = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
    let slot = bp_stats::SLOT_DURATION_MS;
    let hour: i64 = 60 * 60 * 1000;
    let h = (bp_common::now_ms() / hour) * hour - 3 * hour;
    let rows: [(i64, f32); 3] = [
        (h + slot, 100.0),      // [h, h+10m): hour h
        (h + hour, 700.0),      // [h+50m, h+60m): still hour h
        (h + hour + slot, 5.0), // [h+60m, h+70m): hour h+1
    ];
    let cleanup = || async {
        let _ = sqlx::query("DELETE FROM client_statistics_entity WHERE address = $1")
            .bind(addr)
            .execute(&pool)
            .await;
    };
    cleanup().await;
    for (slot_end, max) in rows {
        sqlx::query(
            r#"INSERT INTO client_statistics_entity
                 (address, "clientName", "sessionId", "time", shares, "maxDifficulty")
               VALUES ($1, 'rig', 's1', $2, 1, $3)"#,
        )
        .bind(addr)
        .bind(slot_end)
        .bind(max)
        .execute(&pool)
        .await
        .expect("seed client stats");
    }
    let (status, body) = get_json(pool.clone(), &format!("/api/client/{addr}/diff-scores")).await;
    cleanup().await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let at = |t: i64| -> Option<f64> {
        let label = chrono::DateTime::from_timestamp_millis(t)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        body["slotData"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["time"] == label)
            .unwrap_or_else(|| panic!("no bucket {label} in {body}"))["difficulty"]
            .as_f64()
    };
    assert_eq!(at(h), Some(700.0));
    assert_eq!(at(h + hour), Some(5.0));
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

/// `/worker-shares` lists the address's connected workers that have a
/// lifetime row, in name order; a row of a worker without a session stays
/// out, a connected worker without a row too.
#[tokio::test]
async fn worker_shares_lists_connected_workers_with_a_row_in_name_order() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    // Own address: no sibling test in this binary touches it.
    let addr = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
    let cleanup = || async {
        for table in ["client_entity", "worker_shares_entity"] {
            let _ = sqlx::query(&format!("DELETE FROM {table} WHERE address = $1"))
                .bind(addr)
                .execute(&pool)
                .await;
        }
    };
    cleanup().await;
    for (worker, session) in [
        ("rig_b", "wsB00001"),
        ("rig_a", "wsA00001"),
        ("rig_c", "wsC00001"),
    ] {
        sqlx::query(
            r#"INSERT INTO client_entity (address, "clientName", "sessionId", "startTime")
               VALUES ($1, $2, $3, 0)"#,
        )
        .bind(addr)
        .bind(worker)
        .bind(session)
        .execute(&pool)
        .await
        .expect("seed client");
    }
    // rig_c is connected without a row; rig_gone has a row but no session.
    for (worker, shares, rejected) in [
        ("rig_a", 100.0, 1.0),
        ("rig_b", 250.0, 3.0),
        ("rig_gone", 9.0, 0.0),
    ] {
        sqlx::query(
            r#"INSERT INTO worker_shares_entity (address, "clientName", shares, "rejectedShares")
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(addr)
        .bind(worker)
        .bind(shares)
        .bind(rejected)
        .execute(&pool)
        .await
        .expect("seed worker shares");
    }

    let (status, body) = get_json(pool.clone(), &format!("/api/client/{addr}/worker-shares")).await;
    cleanup().await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        serde_json::json!([
            {"workerName": "rig_a", "totalShares": 100, "totalRejected": 1},
            {"workerName": "rig_b", "totalShares": 250, "totalRejected": 3},
        ])
    );
}

/// `/max-difficulty` per address: the highest share of each visible slot
/// over all its sessions, every other slot 0.
#[tokio::test]
async fn client_max_difficulty_takes_the_best_session_per_slot() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    // Own address: no sibling test in this binary touches it.
    let addr = "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h";
    let last = bp_stats::slot::chart_visibility_cutoff_slot()
        .previous()
        .as_millis();
    let earlier = last - bp_stats::SLOT_DURATION_MS;
    let rows: [(&str, i64, f32); 4] = [
        ("mxs00001", earlier, 300.0),
        ("mxs00002", earlier, 4_096.5),
        ("mxs00001", last, 77.25),
        ("mxs00002", last, 12.0),
    ];
    let cleanup = || async {
        let _ = sqlx::query("DELETE FROM client_statistics_entity WHERE address = $1")
            .bind(addr)
            .execute(&pool)
            .await;
    };
    cleanup().await;
    for (session, slot_end, max) in rows {
        sqlx::query(
            r#"INSERT INTO client_statistics_entity
                 (address, "clientName", "sessionId", "time", shares, "maxDifficulty")
               VALUES ($1, 'rig', $2, $3, 1, $4)"#,
        )
        .bind(addr)
        .bind(session)
        .bind(slot_end)
        .bind(max)
        .execute(&pool)
        .await
        .expect("seed client stats");
    }
    let (status, body) =
        get_json(pool.clone(), &format!("/api/client/{addr}/max-difficulty")).await;
    cleanup().await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let slots = body["slotData"].as_array().expect("slotData");
    let at = |t: i64| -> f64 {
        let label = chrono::DateTime::from_timestamp_millis(t)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        slots
            .iter()
            .find(|e| e["time"] == label)
            .unwrap_or_else(|| panic!("no slot {label}"))["counts"]["maxDifficulty"]
            .as_f64()
            .expect("number")
    };
    assert_eq!(at(earlier), 4_096.5);
    assert_eq!(at(last), 77.25);
    let nonzero = slots
        .iter()
        .filter(|e| e["counts"]["maxDifficulty"].as_f64() != Some(0.0))
        .count();
    assert_eq!(nonzero, 2, "every other slot reads 0");
}

/// delete-stats zeroes the address total together with the worker totals,
/// so both count from the same start afterwards; the public record stays.
#[tokio::test]
async fn delete_stats_zeroes_the_address_total_with_the_workers() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    // Own address: no sibling test in this binary touches it.
    let addr = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    let cleanup = || async {
        for table in ["address_settings_entity", "worker_shares_entity"] {
            let _ = sqlx::query(&format!("DELETE FROM {table} WHERE address = $1"))
                .bind(addr)
                .execute(&pool)
                .await;
        }
    };
    cleanup().await;
    sqlx::query(
        r#"INSERT INTO address_settings_entity
             (address, shares, "bestDifficulty", "allTimeBestDifficulty")
           VALUES ($1, 500, 64, 4096)"#,
    )
    .bind(addr)
    .execute(&pool)
    .await
    .expect("seed address");
    sqlx::query(
        r#"INSERT INTO worker_shares_entity (address, "clientName", shares, "rejectedShares")
           VALUES ($1, 'rig', 500, 0)"#,
    )
    .bind(addr)
    .execute(&pool)
    .await
    .expect("seed worker");

    let resp = build_router(minimal_state(pool.clone()))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/client/{addr}/delete-stats"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");
    let status = resp.status();
    let (shares, all_time): (f64, f64) = sqlx::query_as(
        r#"SELECT shares, "allTimeBestDifficulty" FROM address_settings_entity WHERE address = $1"#,
    )
    .bind(addr)
    .fetch_one(&pool)
    .await
    .expect("address row stays");
    let workers: i64 =
        sqlx::query_scalar(r#"SELECT COUNT(*) FROM worker_shares_entity WHERE address = $1"#)
            .bind(addr)
            .fetch_one(&pool)
            .await
            .expect("count workers");
    cleanup().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(workers, 0, "worker totals are gone");
    assert_eq!(shares, 0.0, "the address total starts over with them");
    assert_eq!(all_time, 4096.0, "the public record is never lowered");
}
