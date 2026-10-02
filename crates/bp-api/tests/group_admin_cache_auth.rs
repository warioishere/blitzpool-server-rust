// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! A Group-Solo admin read must check the token before its response cache.
//! The cache key only says "admin", and a check inside the cached
//! computation runs on a miss only, so a warmed entry must still refuse a
//! wrong token (the body holds the open-invite token and join-request roster).

use std::sync::Arc;

use axum::http::{Request, StatusCode};
use bp_api::{build_router, AppState};
use bp_group_mgmt_engine::{
    GroupService, InvitationService, JoinRequestLimits, JoinRequestService,
    JoinRequestServiceConfig, NoopEmailHooks, NoopHooks, OpenInviteTtl,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;
use uuid::Uuid;

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
            eprintln!("PG connect failed for {url}: {e} — skipping");
            None
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            None
        }
    }
}

async fn cleanup(pool: &PgPool, group_id: Uuid) {
    for table in [
        "pplns_group_invitation",
        "pplns_group_join_request",
        "pplns_group_member",
    ] {
        let _ = sqlx::query(&format!(r#"DELETE FROM {table} WHERE "groupId" = $1"#))
            .bind(group_id)
            .execute(pool)
            .await;
    }
    let _ = sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(group_id)
        .execute(pool)
        .await;
}

async fn get(app: &axum::Router, uri: &str, token: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::get(uri)
                .header("x-admin-token", token)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// Warm the admin entry of `path` (under `/api/pplns/groups/:id/`) with the
/// real token, then ask again with a wrong one.
async fn wrong_token_after_warm_admin(name: &str, path: &str) -> Option<(StatusCode, StatusCode)> {
    let pool = connect_or_skip().await?;
    // A run that failed half-way leaves its group behind; the FKs cascade.
    let _ = sqlx::query("DELETE FROM pplns_group WHERE name = $1")
        .bind(name)
        .execute(&pool)
        .await;
    let group_svc = Arc::new(
        GroupService::load(pool.clone(), Arc::new(NoopHooks), 14, 10_000)
            .await
            .expect("load group service"),
    );
    let inv_svc = Arc::new(InvitationService::new(pool.clone(), group_svc.clone()));
    let jr_svc = Arc::new(JoinRequestService::new(
        pool.clone(),
        group_svc.clone(),
        Arc::new(NoopEmailHooks),
        JoinRequestServiceConfig {
            pool_base_url: None,
            limits: JoinRequestLimits::default(),
        },
    ));
    let creator = format!("bc1q{}", name.replace('-', ""));
    let created = group_svc
        .create_group(name, &creator)
        .await
        .expect("create group");
    let id = created.group.id;
    inv_svc
        .create_open_invite(
            id,
            OpenInviteTtl::OneHour,
            Some(&created.admin_token),
            false,
        )
        .await
        .expect("open invite");

    let mut state = AppState::new(pool.clone(), "0.0.0");
    state.group_service = Some(group_svc);
    state.invitation_service = Some(inv_svc);
    state.join_request_service = Some(jr_svc);
    let app = build_router(Arc::new(state));

    let uri = format!("/api/pplns/groups/{id}/{path}");
    let admin = get(&app, &uri, &created.admin_token).await;
    let wrong = get(&app, &uri, "not-the-admin-token").await;
    cleanup(&pool, id).await;
    Some((admin, wrong))
}

#[tokio::test]
async fn a_wrong_token_never_reads_the_cached_open_invite() {
    let Some((admin, wrong)) =
        wrong_token_after_warm_admin("bp-test-cache-auth-invite", "invitations/open/active").await
    else {
        return;
    };
    assert_eq!(
        admin,
        StatusCode::OK,
        "precondition: the admin warmed the entry"
    );
    assert_eq!(wrong, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_wrong_token_never_reads_the_cached_join_requests() {
    let Some((admin, wrong)) =
        wrong_token_after_warm_admin("bp-test-cache-auth-jr", "join-requests").await
    else {
        return;
    };
    assert_eq!(
        admin,
        StatusCode::OK,
        "precondition: the admin warmed the entry"
    );
    assert_eq!(wrong, StatusCode::UNAUTHORIZED);
}
