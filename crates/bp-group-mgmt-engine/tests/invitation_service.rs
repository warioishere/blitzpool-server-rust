// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `bp_group_mgmt_engine::InvitationService`.
//! Both directed + open paths covered against docker-PG.

use std::sync::Arc;

use bp_common::AddressId;
use bp_group_mgmt_engine::{
    CapturingEmailHooks, GroupService, InvitationService, InvitationServiceConfig,
    InvitationServiceError, NoopHooks, OpenInviteTtl,
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

async fn delete_email_for(pool: &PgPool, address: &str) {
    let _ = sqlx::query("DELETE FROM pplns_address_email WHERE address = $1")
        .bind(address)
        .execute(pool)
        .await;
}

fn build_services(
    pool: PgPool,
) -> (
    Arc<GroupService<NoopHooks>>,
    InvitationService<NoopHooks, CapturingEmailHooks>,
    CapturingEmailHooks,
) {
    let group = Arc::new(GroupService::new(pool.clone(), Arc::new(NoopHooks), 14));
    let email = CapturingEmailHooks::new();
    let invitation = InvitationService::new(
        pool,
        group.clone(),
        Arc::new(email.clone()),
        InvitationServiceConfig {
            pool_base_url: Some("https://blitzpool.example".into()),
        },
    );
    (group, invitation, email)
}

// ─── Directed invites ─────────────────────────────────────────────────────

#[tokio::test]
async fn create_invitation_happy_path_sends_email_and_persists_row() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc, email) = build_services(pool.clone());
    let creator = format!("bc1qcr{}", Uuid::new_v4().simple());
    let invitee = format!("bc1qinv{}", Uuid::new_v4().simple());
    seed_verified_email(&pool, &invitee, "invitee@example.com").await;

    let g = group_svc
        .create_group(&format!("inv-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    let invite = inv_svc
        .create_invitation(g.group.id, &invitee, Some(&g.admin_token))
        .await
        .expect("invite");
    assert_eq!(invite.email, "invitee@example.com");
    assert!(invite.expires_at > 0);

    let sent = email.invitations_snapshot();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].accept_url.contains(&invite.token));
    assert_eq!(sent[0].to_email, "invitee@example.com");

    cleanup_group(&pool, g.group.id).await;
    delete_email_for(&pool, &invitee).await;
}

#[tokio::test]
async fn create_invitation_rejects_unverified_email() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc, _email) = build_services(pool.clone());
    let creator = format!("bc1qcr{}", Uuid::new_v4().simple());
    let invitee = format!("bc1qinv{}", Uuid::new_v4().simple());
    // NO seed_verified_email call.

    let g = group_svc
        .create_group(&format!("inv-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    let err = inv_svc
        .create_invitation(g.group.id, &invitee, Some(&g.admin_token))
        .await
        .expect_err("no email");
    assert!(matches!(err, InvitationServiceError::EmailNotVerified));
    cleanup_group(&pool, g.group.id).await;
}

#[tokio::test]
async fn create_invitation_rejects_pending_duplicate() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc, _email) = build_services(pool.clone());
    let creator = format!("bc1qcr{}", Uuid::new_v4().simple());
    let invitee = format!("bc1qinv{}", Uuid::new_v4().simple());
    seed_verified_email(&pool, &invitee, "invitee@example.com").await;

    let g = group_svc
        .create_group(&format!("inv-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    inv_svc
        .create_invitation(g.group.id, &invitee, Some(&g.admin_token))
        .await
        .expect("first");
    let err = inv_svc
        .create_invitation(g.group.id, &invitee, Some(&g.admin_token))
        .await
        .expect_err("dup");
    assert!(matches!(err, InvitationServiceError::InvitationPending));
    cleanup_group(&pool, g.group.id).await;
    delete_email_for(&pool, &invitee).await;
}

#[tokio::test]
async fn accept_directed_creates_member_and_stamps_invitation() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc, _email) = build_services(pool.clone());
    let creator = format!("bc1qcr{}", Uuid::new_v4().simple());
    let invitee = format!("bc1qinv{}", Uuid::new_v4().simple());
    seed_verified_email(&pool, &invitee, "invitee@example.com").await;

    let g = group_svc
        .create_group(&format!("acc-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    let invite = inv_svc
        .create_invitation(g.group.id, &invitee, Some(&g.admin_token))
        .await
        .expect("inv");

    let member = inv_svc.accept(&invite.token).await.expect("accept");
    assert_eq!(member.address.as_str(), invitee.to_lowercase());
    assert_eq!(member.role, "member");
    let row = bp_db::find_group_invitation(&pool, &invite.token)
        .await
        .expect("inv-r")
        .expect("present");
    assert_eq!(row.status, "accepted");
    assert!(row.responded_at.is_some());

    cleanup_group(&pool, g.group.id).await;
    delete_email_for(&pool, &invitee).await;
}

#[tokio::test]
async fn accept_idempotent_when_already_accepted() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc, _email) = build_services(pool.clone());
    let creator = format!("bc1qcr{}", Uuid::new_v4().simple());
    let invitee = format!("bc1qinv{}", Uuid::new_v4().simple());
    seed_verified_email(&pool, &invitee, "invitee@example.com").await;
    let g = group_svc
        .create_group(&format!("idem-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    let invite = inv_svc
        .create_invitation(g.group.id, &invitee, Some(&g.admin_token))
        .await
        .expect("inv");
    let m1 = inv_svc.accept(&invite.token).await.expect("first");
    let m2 = inv_svc.accept(&invite.token).await.expect("second");
    assert_eq!(m1.id, m2.id);
    cleanup_group(&pool, g.group.id).await;
    delete_email_for(&pool, &invitee).await;
}

#[tokio::test]
async fn decline_flips_status_and_no_auth_required() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc, _email) = build_services(pool.clone());
    let creator = format!("bc1qcr{}", Uuid::new_v4().simple());
    let invitee = format!("bc1qinv{}", Uuid::new_v4().simple());
    seed_verified_email(&pool, &invitee, "i@x").await;
    let g = group_svc
        .create_group(&format!("dec-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    let invite = inv_svc
        .create_invitation(g.group.id, &invitee, Some(&g.admin_token))
        .await
        .expect("inv");
    inv_svc.decline(&invite.token).await.expect("decline");
    let row = bp_db::find_group_invitation(&pool, &invite.token)
        .await
        .expect("look")
        .expect("present");
    assert_eq!(row.status, "declined");
    assert!(row.responded_at.is_some());
    cleanup_group(&pool, g.group.id).await;
    delete_email_for(&pool, &invitee).await;
}

#[tokio::test]
async fn cancel_invitation_by_address_removes_pending_row() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc, _email) = build_services(pool.clone());
    let creator = format!("bc1qcr{}", Uuid::new_v4().simple());
    let invitee = format!("bc1qinv{}", Uuid::new_v4().simple());
    seed_verified_email(&pool, &invitee, "i@x").await;
    let g = group_svc
        .create_group(&format!("cncl-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    inv_svc
        .create_invitation(g.group.id, &invitee, Some(&g.admin_token))
        .await
        .expect("inv");
    inv_svc
        .cancel_invitation_by_address(g.group.id, &invitee, Some(&g.admin_token))
        .await
        .expect("cncl");
    let pending = bp_db::find_pplns_group_invitation_pending_directed(
        &pool,
        g.group.id,
        &AddressId::new(invitee.to_lowercase()).unwrap(),
    )
    .await
    .expect("look");
    assert!(pending.is_none());
    cleanup_group(&pool, g.group.id).await;
    delete_email_for(&pool, &invitee).await;
}

#[tokio::test]
async fn list_pending_for_address_masks_email_and_filters_expired() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc, _email) = build_services(pool.clone());
    let creator = format!("bc1qcr{}", Uuid::new_v4().simple());
    let invitee = format!("bc1qinv{}", Uuid::new_v4().simple());
    seed_verified_email(&pool, &invitee, "longname@example.com").await;
    let g = group_svc
        .create_group(&format!("lpa-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    inv_svc
        .create_invitation(g.group.id, &invitee, Some(&g.admin_token))
        .await
        .expect("inv");
    let list = inv_svc
        .list_pending_for_address(&invitee)
        .await
        .expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].group_id, g.group.id);
    assert_eq!(list[0].masked_email, "l***@example.com");
    cleanup_group(&pool, g.group.id).await;
    delete_email_for(&pool, &invitee).await;
}

// ─── Open invites ─────────────────────────────────────────────────────────

#[tokio::test]
async fn open_invite_create_revoke_and_replace_atomic() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc, _email) = build_services(pool.clone());
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
    let (group_svc, inv_svc, _email) = build_services(pool.clone());
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
async fn accept_open_invite_blocks_approval_required() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let (group_svc, inv_svc, _email) = build_services(pool.clone());
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
    let (group_svc, inv_svc, _email) = build_services(pool.clone());
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
