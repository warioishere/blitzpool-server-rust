// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `bp_group_mgmt_engine::InvitationService`
//! (open-invite links) against docker-PG.

use std::sync::Arc;

use bp_group_mgmt_engine::{
    GroupService, InvitationService, InvitationServiceError, NoopHooks, OpenInviteTtl,
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
    let _ = sqlx::query("DELETE FROM pplns_group_invitation WHERE \"groupId\" = $1")
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

/// Seed a verified signature ownership proof (no email) — the unified gate's
/// second path.
async fn seed_signature_verified(pool: &PgPool, address: &str) {
    let now = 1_700_000_000_000_i64;
    sqlx::query(
        r#"INSERT INTO pplns_address_ownership
             (address, method, "scriptType", "verifiedAt", "createdAt", "updatedAt")
           VALUES ($1, 'bip322', 'p2wpkh', $2, $2, $2)
           ON CONFLICT (address) DO UPDATE SET "verifiedAt" = EXCLUDED."verifiedAt""#,
    )
    .bind(address)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed signature");
}

async fn delete_signature_for(pool: &PgPool, address: &str) {
    let _ = sqlx::query("DELETE FROM pplns_address_ownership WHERE address = $1")
        .bind(address)
        .execute(pool)
        .await;
}

async fn delete_email_for(pool: &PgPool, address: &str) {
    let _ = sqlx::query("DELETE FROM pplns_address_email WHERE address = $1")
        .bind(address)
        .execute(pool)
        .await;
}

fn build_services(pool: PgPool) -> (Arc<GroupService<NoopHooks>>, InvitationService<NoopHooks>) {
    let group = Arc::new(GroupService::new(pool.clone(), Arc::new(NoopHooks), 14));
    let invitation = InvitationService::new(pool, group.clone());
    (group, invitation)
}

// ─── Open invites ─────────────────────────────────────────────────────────

#[tokio::test]
async fn open_invite_create_revoke_and_replace_atomic() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc) = build_services(pool.clone());
    let creator = format!("bc1qcr{}", Uuid::new_v4().simple());
    let g = group_svc
        .create_group(&format!("oi-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");

    let first = inv_svc
        .create_open_invite(
            g.group.id,
            OpenInviteTtl::OneHour,
            Some(&g.admin_token),
            false,
        )
        .await
        .expect("o1");
    let second = inv_svc
        .create_open_invite(
            g.group.id,
            OpenInviteTtl::SevenDays,
            Some(&g.admin_token),
            true,
        )
        .await
        .expect("o2");
    assert_ne!(first.token, second.token);
    let active = inv_svc
        .get_active_open_invite(g.group.id, Some(&g.admin_token))
        .await
        .expect("active")
        .expect("present");
    assert_eq!(active.token, second.token);
    assert!(active.approval_required);

    // First one must now be revoked.
    let row = bp_db::find_group_invitation(&pool, &first.token)
        .await
        .expect("look")
        .expect("present");
    assert_eq!(row.status, "revoked");

    inv_svc
        .revoke_open_invite(g.group.id, Some(&g.admin_token))
        .await
        .expect("rev");
    let gone = inv_svc
        .get_active_open_invite(g.group.id, Some(&g.admin_token))
        .await
        .expect("look");
    assert!(gone.is_none());
    cleanup_group(&pool, g.group.id).await;
}

#[tokio::test]
async fn accept_open_invite_creates_member() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc) = build_services(pool.clone());
    let creator = format!("bc1qcr{}", Uuid::new_v4().simple());
    let joiner = format!("bc1qjoin{}", Uuid::new_v4().simple());
    seed_verified_email(&pool, &joiner, "joiner@example.com").await;
    let g = group_svc
        .create_group(&format!("oja-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    let open = inv_svc
        .create_open_invite(
            g.group.id,
            OpenInviteTtl::SevenDays,
            Some(&g.admin_token),
            false,
        )
        .await
        .expect("o");
    let member = inv_svc
        .accept_open_invite(&open.token, &joiner)
        .await
        .expect("join");
    assert_eq!(member.address.as_str(), joiner.to_lowercase());
    // Open invite stays pending (multi-use).
    let row = bp_db::find_group_invitation(&pool, &open.token)
        .await
        .expect("look")
        .expect("present");
    assert_eq!(row.status, "pending");
    cleanup_group(&pool, g.group.id).await;
    delete_email_for(&pool, &joiner).await;
}

#[tokio::test]
async fn accept_open_invite_creates_member_via_signature() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc) = build_services(pool.clone());
    let creator = format!("bc1qcr{}", Uuid::new_v4().simple());
    let joiner = format!("bc1qjoin{}", Uuid::new_v4().simple());
    // NO verified email — only a signature ownership proof. The unified gate
    // must still admit the joiner.
    seed_signature_verified(&pool, &joiner).await;
    let g = group_svc
        .create_group(&format!("ojs-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    let open = inv_svc
        .create_open_invite(
            g.group.id,
            OpenInviteTtl::SevenDays,
            Some(&g.admin_token),
            false,
        )
        .await
        .expect("o");
    let member = inv_svc
        .accept_open_invite(&open.token, &joiner)
        .await
        .expect("join via signature");
    assert_eq!(member.address.as_str(), joiner.to_lowercase());
    cleanup_group(&pool, g.group.id).await;
    delete_signature_for(&pool, &joiner).await;
}

#[tokio::test]
async fn accept_open_invite_blocks_approval_required() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc) = build_services(pool.clone());
    let creator = format!("bc1qcr{}", Uuid::new_v4().simple());
    let joiner = format!("bc1qjoin{}", Uuid::new_v4().simple());
    seed_verified_email(&pool, &joiner, "j@x").await;
    let g = group_svc
        .create_group(&format!("oja-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    let open = inv_svc
        .create_open_invite(
            g.group.id,
            OpenInviteTtl::OneHour,
            Some(&g.admin_token),
            true,
        )
        .await
        .expect("o");
    let err = inv_svc
        .accept_open_invite(&open.token, &joiner)
        .await
        .expect_err("blocked");
    assert!(matches!(err, InvitationServiceError::ApprovalRequired));
    cleanup_group(&pool, g.group.id).await;
    delete_email_for(&pool, &joiner).await;
}

#[tokio::test]
async fn get_open_invite_public_omits_admin_data() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc) = build_services(pool.clone());
    let creator = format!("bc1qcr{}", Uuid::new_v4().simple());
    let g = group_svc
        .create_group(&format!("pub-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    let open = inv_svc
        .create_open_invite(
            g.group.id,
            OpenInviteTtl::OneHour,
            Some(&g.admin_token),
            false,
        )
        .await
        .expect("o");
    let pub_view = inv_svc
        .get_open_invite_public(&open.token)
        .await
        .expect("look")
        .expect("present");
    assert_eq!(pub_view.group_id, g.group.id);
    assert_eq!(pub_view.token, open.token);
    assert!(!pub_view.approval_required);
    cleanup_group(&pool, g.group.id).await;
}
