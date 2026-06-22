// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `bp_group_mgmt_engine::JoinRequestService`.

use std::sync::Arc;

use bp_db::PatchField;
use bp_group_mgmt_engine::{
    expire_join_requests_once, CapturingEmailHooks, GroupService, JoinDecisionOutcome,
    JoinRequestLimits, JoinRequestService, JoinRequestServiceConfig, JoinRequestServiceError,
    NoopHooks, UpdateRoundResetSettings,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
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
            return None;
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            return None;
        }
    }
}

async fn cleanup_group(pool: &PgPool, group_id: Uuid) {
    let _ = sqlx::query("DELETE FROM pplns_group_join_request WHERE \"groupId\" = $1")
        .bind(group_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM pplns_group_member WHERE \"groupId\" = $1")
        .bind(group_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(group_id)
        .execute(pool)
        .await;
}

async fn seed_verified_email(pool: &PgPool, address: &str, email: &str) {
    let now = 1_700_000_000_000_i64;
    sqlx::query(
        r#"INSERT INTO pplns_address_email (address, email, "verifiedAt", "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $4, $4)
           ON CONFLICT (address) DO UPDATE SET email = EXCLUDED.email, "verifiedAt" = EXCLUDED."verifiedAt""#,
    )
    .bind(address)
    .bind(email)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed email");
}

async fn delete_email_for(pool: &PgPool, address: &str) {
    let _ = sqlx::query("DELETE FROM pplns_address_email WHERE address = $1")
        .bind(address)
        .execute(pool)
        .await;
}

fn build_services(
    pool: PgPool,
    limits: JoinRequestLimits,
) -> (
    Arc<GroupService<NoopHooks>>,
    JoinRequestService<NoopHooks, CapturingEmailHooks>,
    CapturingEmailHooks,
) {
    let group = Arc::new(GroupService::new(pool.clone(), Arc::new(NoopHooks), 14));
    let email = CapturingEmailHooks::new();
    let svc = JoinRequestService::new(
        pool,
        group.clone(),
        Arc::new(email.clone()),
        JoinRequestServiceConfig {
            pool_base_url: Some("https://blitzpool.example".into()),
            limits,
        },
    );
    (group, svc, email)
}

async fn create_public_group(
    group_svc: &Arc<GroupService<NoopHooks>>,
    pool: &PgPool,
    suffix: &str,
) -> (Uuid, String) {
    let creator = format!("bc1qcr{suffix}");
    // Name must stay ≤64 chars (`MAX_GROUP_NAME_LEN`); the suffix is
    // 32-hex (Uuid::simple) which is enough on its own.
    let g = group_svc
        .create_group(&format!("g-{suffix}"), &creator)
        .await
        .expect("g");
    // Flip is_public=true via the round-reset PATCH (cheapest path to
    // a public group without writing raw SQL).
    group_svc
        .update_round_reset_config(
            g.group.id,
            UpdateRoundResetSettings {
                is_public: PatchField::Set(true),
                ..Default::default()
            },
            Some(&g.admin_token),
        )
        .await
        .expect("public");
    let _ = pool;
    (g.group.id, g.admin_token)
}

// ─── happy path ──────────────────────────────────────────────────────────

#[tokio::test]
async fn create_join_request_happy_path() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, svc, _email) = build_services(pool.clone(), JoinRequestLimits::default());
    let suffix = Uuid::new_v4().simple().to_string();
    let (group_id, _admin) = create_public_group(&group_svc, &pool, &suffix).await;
    let requester = format!("bc1qreq{suffix}");
    seed_verified_email(&pool, &requester, "req@example.com").await;

    let row = svc
        .create_join_request(group_id, &requester, Some("hi please"))
        .await
        .expect("req");
    assert_eq!(row.address.as_str(), requester.to_lowercase());
    assert_eq!(row.status, "pending");
    assert_eq!(row.email, "req@example.com");
    assert_eq!(row.message.as_deref(), Some("hi please"));

    cleanup_group(&pool, group_id).await;
    delete_email_for(&pool, &requester).await;
}

#[tokio::test]
async fn create_join_request_rejects_private_group_as_not_found() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, svc, _email) = build_services(pool.clone(), JoinRequestLimits::default());
    let suffix = Uuid::new_v4().simple().to_string();
    let creator = format!("bc1qpr{suffix}");
    let g = group_svc
        .create_group(&format!("private-{suffix}"), &creator)
        .await
        .expect("g");
    let requester = format!("bc1qreq{suffix}");
    seed_verified_email(&pool, &requester, "x@x").await;
    let err = svc
        .create_join_request(g.group.id, &requester, None)
        .await
        .expect_err("private");
    assert!(matches!(err, JoinRequestServiceError::NotFound));
    cleanup_group(&pool, g.group.id).await;
    delete_email_for(&pool, &requester).await;
}

#[tokio::test]
async fn create_join_request_rejects_unverified_email() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, svc, _email) = build_services(pool.clone(), JoinRequestLimits::default());
    let suffix = Uuid::new_v4().simple().to_string();
    let (group_id, _admin) = create_public_group(&group_svc, &pool, &suffix).await;
    let requester = format!("bc1qreq{suffix}");
    let err = svc
        .create_join_request(group_id, &requester, None)
        .await
        .expect_err("no email");
    assert!(matches!(err, JoinRequestServiceError::EmailNotVerified));
    cleanup_group(&pool, group_id).await;
}

#[tokio::test]
async fn create_join_request_dup_pending_surfaces_clean_error() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, svc, _email) = build_services(pool.clone(), JoinRequestLimits::default());
    let suffix = Uuid::new_v4().simple().to_string();
    let (group_id, _admin) = create_public_group(&group_svc, &pool, &suffix).await;
    let requester = format!("bc1qreq{suffix}");
    seed_verified_email(&pool, &requester, "r@x").await;
    svc.create_join_request(group_id, &requester, None)
        .await
        .expect("first");
    let err = svc
        .create_join_request(group_id, &requester, None)
        .await
        .expect_err("dup");
    assert!(matches!(err, JoinRequestServiceError::RequestPending));
    cleanup_group(&pool, group_id).await;
    delete_email_for(&pool, &requester).await;
}

// ─── approve / reject ────────────────────────────────────────────────────

#[tokio::test]
async fn approve_request_adds_member_and_sends_email() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, svc, email) = build_services(pool.clone(), JoinRequestLimits::default());
    let suffix = Uuid::new_v4().simple().to_string();
    let (group_id, admin_token) = create_public_group(&group_svc, &pool, &suffix).await;
    let requester = format!("bc1qreq{suffix}");
    seed_verified_email(&pool, &requester, "r@example.com").await;
    let req = svc
        .create_join_request(group_id, &requester, None)
        .await
        .expect("req");

    svc.approve_request(group_id, req.id, Some(&admin_token))
        .await
        .expect("approve");
    let members = group_svc.list_members(group_id).await.expect("members");
    assert!(members
        .iter()
        .any(|m| m.address.as_str() == requester.to_lowercase()));
    let decisions = email.decisions_snapshot();
    assert_eq!(decisions.len(), 1);
    assert!(matches!(
        decisions[0].outcome,
        JoinDecisionOutcome::Approved
    ));
    cleanup_group(&pool, group_id).await;
    delete_email_for(&pool, &requester).await;
}

#[tokio::test]
async fn reject_request_marks_row_and_sends_email() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, svc, email) = build_services(pool.clone(), JoinRequestLimits::default());
    let suffix = Uuid::new_v4().simple().to_string();
    let (group_id, admin_token) = create_public_group(&group_svc, &pool, &suffix).await;
    let requester = format!("bc1qreq{suffix}");
    seed_verified_email(&pool, &requester, "r@example.com").await;
    let req = svc
        .create_join_request(group_id, &requester, None)
        .await
        .expect("req");

    svc.reject_request(group_id, req.id, Some(&admin_token))
        .await
        .expect("reject");
    let decisions = email.decisions_snapshot();
    assert_eq!(decisions.len(), 1);
    assert!(matches!(
        decisions[0].outcome,
        JoinDecisionOutcome::Rejected
    ));
    cleanup_group(&pool, group_id).await;
    delete_email_for(&pool, &requester).await;
}

#[tokio::test]
async fn list_for_group_filters_by_decided() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, svc, _email) = build_services(pool.clone(), JoinRequestLimits::default());
    let suffix = Uuid::new_v4().simple().to_string();
    let (group_id, admin_token) = create_public_group(&group_svc, &pool, &suffix).await;
    let r1 = format!("bc1qreqa{suffix}");
    let r2 = format!("bc1qreqb{suffix}");
    seed_verified_email(&pool, &r1, "a@x").await;
    seed_verified_email(&pool, &r2, "b@x").await;
    let req1 = svc.create_join_request(group_id, &r1, None).await.unwrap();
    let _req2 = svc.create_join_request(group_id, &r2, None).await.unwrap();
    svc.reject_request(group_id, req1.id, Some(&admin_token))
        .await
        .expect("reject");

    let pending = svc
        .list_for_group(group_id, Some(&admin_token), false)
        .await
        .expect("pending");
    assert_eq!(pending.len(), 1);
    let all = svc
        .list_for_group(group_id, Some(&admin_token), true)
        .await
        .expect("all");
    assert_eq!(all.len(), 2);
    cleanup_group(&pool, group_id).await;
    delete_email_for(&pool, &r1).await;
    delete_email_for(&pool, &r2).await;
}

#[tokio::test]
async fn expire_join_requests_once_flips_stale_pending() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, svc, _email) = build_services(pool.clone(), JoinRequestLimits::default());
    let suffix = Uuid::new_v4().simple().to_string();
    let (group_id, _admin) = create_public_group(&group_svc, &pool, &suffix).await;
    let requester = format!("bc1qreq{suffix}");
    seed_verified_email(&pool, &requester, "r@x").await;
    let row = svc
        .create_join_request(group_id, &requester, None)
        .await
        .expect("req");

    // Backdate createdAt to 60 days ago — past the 30d expiry window.
    sqlx::query(r#"UPDATE pplns_group_join_request SET "createdAt" = $1 WHERE id = $2"#)
        .bind(now_ms() - 60 * 24 * 60 * 60 * 1000)
        .bind(row.id)
        .execute(&pool)
        .await
        .expect("backdate");

    let n = expire_join_requests_once(&pool).await.expect("sweep");
    assert!(n >= 1);
    let after = bp_db::find_group_join_request(&pool, row.id)
        .await
        .expect("look")
        .expect("present");
    assert_eq!(after.status, "expired");
    cleanup_group(&pool, group_id).await;
    delete_email_for(&pool, &requester).await;
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
