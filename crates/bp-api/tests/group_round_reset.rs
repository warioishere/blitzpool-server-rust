// SPDX-License-Identifier: AGPL-3.0-or-later

//! `POST /api/pplns/groups/{id}/round/reset`: the Team admin's manual round
//! reset, over the real router, service and Group-Solo engine.

use std::sync::Arc;

use axum::http::{Request, StatusCode};
use bp_api::{build_router, AppState};
use bp_common::AddressId;
use bp_group_mgmt_engine::{GroupService, NoopHooks};
use bp_group_solo_engine::config::GroupSoloEngineConfig;
use bp_group_solo_engine::engine::GroupSoloEngine;
use serde_json::Value;
use tower::ServiceExt;

const FEE_ADDR: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
const MINER: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

async fn call(app: &axum::Router, request: Request<axum::body::Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn reset(id: uuid::Uuid, token: Option<&str>) -> Request<axum::body::Body> {
    // The rate limiter keys on the client address.
    let mut request = Request::post(format!("/api/pplns/groups/{id}/round/reset"))
        .header("x-forwarded-for", "127.0.0.1");
    if let Some(token) = token {
        request = request.header("x-admin-token", token);
    }
    request.body(axum::body::Body::empty()).unwrap()
}

/// Without the admin token nothing is wiped; with it the round is empty and
/// the Team shows the manual reset; a second one meets the cooldown; a
/// Window Team is refused.
#[tokio::test]
async fn the_admin_resets_the_round_once_per_cooldown() {
    let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
        return;
    };
    let Some(redis) =
        bp_test_support::connect_redis_in_range_or_skip(bp_test_support::redis_db::API, 3).await
    else {
        return;
    };
    const NAME: &str = "bp-test-round-reset";
    // A run that failed half-way leaves its group behind; the FKs cascade.
    let _ = sqlx::query("DELETE FROM pplns_group WHERE name = $1")
        .bind(NAME)
        .execute(&pool)
        .await;
    let group_svc = Arc::new(
        GroupService::load(pool.clone(), Arc::new(NoopHooks), 10_000)
            .await
            .expect("load group service"),
    );
    let creator = "bc1qbptestroundreset";
    bp_test_support::seed_signature_ownership(&pool, creator).await;
    let created = group_svc
        .create_group(NAME, creator)
        .await
        .expect("create group");
    let id = created.group.id;
    let engine = GroupSoloEngine::spawn_core(
        GroupSoloEngineConfig::new(AddressId::new(FEE_ADDR).unwrap()),
        redis.clone(),
        pool.clone(),
    )
    .await
    .expect("engine");
    engine
        .record_share(None, id, MINER, 50.0, 50.0, 1)
        .await
        .expect("share");
    let round_total = || {
        let reader = engine.reader();
        async move { reader.round_stats(id).await.expect("stats").total_shares }
    };

    let mut state = AppState::new(pool.clone(), "0.0.0");
    state.group_service = Some(group_svc);
    state.group_solo = Some(Arc::new(engine.clone()));
    state.redis = Some(redis);
    let app = build_router(Arc::new(state));

    let (status, body) = call(&app, reset(id, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let (status, body) = call(&app, reset(id, Some("not-the-admin-token"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(round_total().await, 50.0, "a refused caller wipes nothing");

    let (status, body) = call(&app, reset(id, Some(&created.admin_token))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let reset_at = body["lastRoundResetAt"].as_str().expect("time").to_string();
    assert_eq!(round_total().await, 0.0);
    let (status, team) = call(
        &app,
        Request::get(format!("/api/pplns/groups/{id}"))
            .header("x-admin-token", &created.admin_token)
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{team}");
    assert_eq!(team["lastManualRoundResetAt"], reset_at, "{team}");

    let (status, body) = call(&app, reset(id, Some(&created.admin_token))).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["code"], "round-reset-cooldown");

    sqlx::query(
        r#"UPDATE pplns_group
           SET "payoutMode" = 'window', "lastManualRoundResetAt" = NULL WHERE id = $1"#,
    )
    .bind(id)
    .execute(&pool)
    .await
    .expect("window mode");
    let (status, body) = call(&app, reset(id, Some(&created.admin_token))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "window-group-has-no-round");

    let _ = sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await;
    bp_test_support::delete_signature_ownership(&pool, creator).await;
}
