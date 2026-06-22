// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `BlockpartyInvitationService` against local
//! PG. Email-send fan-out routed through `CapturingEmailHooks` so the
//! tests assert on what would have been emailed without standing up SMTP.

use std::sync::Arc;

use async_trait::async_trait;
use bp_blockparty_engine::{
    BlockpartyHooks, BlockpartyInvitationService, BlockpartyInvitationServiceConfig,
    BlockpartyInvitationServiceError, BlockpartyService, BlockpartyServiceConfig,
};
use bp_common::AddressId;
use bp_group_mgmt_engine::{AddressCache as PplnsAddressCache, CapturingEmailHooks};
use sqlx::{postgres::PgPoolOptions, PgPool};

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

struct AllVerified;

#[async_trait]
impl BlockpartyHooks for AllVerified {
    async fn verified_email_for(&self, address: &AddressId) -> Option<String> {
        Some(format!("{}@test.example", address.as_str()))
    }
}

fn addr(s: &str) -> AddressId {
    AddressId::new(s).expect("test address")
}

fn cfg_svc() -> BlockpartyServiceConfig {
    BlockpartyServiceConfig {
        fee_address: Some(addr("bc1qfeeinv")),
        fee_percent: 2.0,
        min_payout_sats: bp_common::Sats(5_000),
    }
}

fn cfg_inv() -> BlockpartyInvitationServiceConfig {
    BlockpartyInvitationServiceConfig {
        pool_base_url: Some("https://pool.test".to_owned()),
    }
}

async fn build(
    pool: &PgPool,
) -> (
    Arc<BlockpartyService<AllVerified>>,
    BlockpartyInvitationService<AllVerified, CapturingEmailHooks>,
    Arc<CapturingEmailHooks>,
) {
    let svc = Arc::new(BlockpartyService::new(
        pool.clone(),
        Arc::new(AllVerified),
        PplnsAddressCache::new(),
        cfg_svc(),
    ));
    let email = Arc::new(CapturingEmailHooks::new());
    let inv = BlockpartyInvitationService::new(pool.clone(), svc.clone(), email.clone(), cfg_inv());
    (svc, inv, email)
}

async fn cleanup(pool: &PgPool, name: &str, addrs: &[&str]) {
    let _ = sqlx::query(r#"DELETE FROM blockparty_group WHERE name = $1"#)
        .bind(name)
        .execute(pool)
        .await;
    for a in addrs {
        let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
            .bind(*a)
            .execute(pool)
            .await;
    }
}

#[tokio::test]
async fn create_then_accept_promotes_party_to_ready() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-inv-test-create-1";
    let admin = "bc1qinvadmin1";
    let bob = "bc1qinvbob1xx";
    cleanup(&pool, name, &[admin, bob]).await;

    let (svc, inv, email) = build(&pool).await;
    let create = svc
        .create_group(name, admin, "admin@test.example", 5_000)
        .await
        .expect("create");
    svc.add_member(create.group.id, bob, 5_000, Some(&create.admin_token))
        .await
        .expect("add");
    let issued = inv
        .create_invitation(create.group.id, bob, None, Some(&create.admin_token))
        .await
        .expect("create_invitation");
    assert!(!issued.resent, "first issue is not a resend");
    assert!(!issued.token.is_empty());
    assert_eq!(email.invitations.lock().unwrap().len(), 1, "one email sent");

    // Accept the invitation. Should mint member token + flip status to
    // READY (admin was auto-confirmed at create, now bob too).
    let accepted = inv.accept(&issued.token).await.expect("accept");
    assert!(
        accepted.member_token.is_some(),
        "first accept mints persistent token"
    );
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, "ready");
    assert_eq!(
        svc.routable_group_id_for_admin(&addr(admin)).await,
        Some(create.group.id)
    );

    cleanup(&pool, name, &[admin, bob]).await;
}

#[tokio::test]
async fn second_create_reuses_pending_token() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-inv-test-reuse-2";
    let admin = "bc1qinvadmin2";
    let bob = "bc1qinvbob2xx";
    cleanup(&pool, name, &[admin, bob]).await;

    let (svc, inv, _email) = build(&pool).await;
    let create = svc
        .create_group(name, admin, "admin@test.example", 5_000)
        .await
        .expect("create");
    svc.add_member(create.group.id, bob, 5_000, Some(&create.admin_token))
        .await
        .expect("add");
    let first = inv
        .create_invitation(create.group.id, bob, None, Some(&create.admin_token))
        .await
        .expect("first issue");
    let second = inv
        .create_invitation(create.group.id, bob, None, Some(&create.admin_token))
        .await
        .expect("resend");
    assert_eq!(first.token, second.token, "same token reused");
    assert!(second.resent);

    cleanup(&pool, name, &[admin, bob]).await;
}

#[tokio::test]
async fn decline_marks_invitation_declined() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-inv-test-decline-3";
    let admin = "bc1qinvadmin3";
    let bob = "bc1qinvbob3xx";
    cleanup(&pool, name, &[admin, bob]).await;

    let (svc, inv, _email) = build(&pool).await;
    let create = svc
        .create_group(name, admin, "admin@test.example", 5_000)
        .await
        .expect("create");
    svc.add_member(create.group.id, bob, 5_000, Some(&create.admin_token))
        .await
        .expect("add");
    let issued = inv
        .create_invitation(create.group.id, bob, None, Some(&create.admin_token))
        .await
        .expect("create_invitation");
    inv.decline(&issued.token).await.expect("decline");
    // Repeat decline → not-pending.
    let again = inv
        .decline(&issued.token)
        .await
        .expect_err("second decline");
    assert!(matches!(
        again,
        BlockpartyInvitationServiceError::NotPending
    ));

    cleanup(&pool, name, &[admin, bob]).await;
}

#[tokio::test]
async fn resend_after_lost_token_mints_fresh_member_token() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-inv-test-resend-4";
    let admin = "bc1qinvadmin4";
    let bob = "bc1qinvbob4xx";
    cleanup(&pool, name, &[admin, bob]).await;

    let (svc, inv, _email) = build(&pool).await;
    let create = svc
        .create_group(name, admin, "admin@test.example", 5_000)
        .await
        .expect("create");
    svc.add_member(create.group.id, bob, 5_000, Some(&create.admin_token))
        .await
        .expect("add");
    let issued = inv
        .create_invitation(create.group.id, bob, None, Some(&create.admin_token))
        .await
        .expect("issue");
    let first_accept = inv.accept(&issued.token).await.expect("accept");
    let first_token = first_accept.member_token.expect("first mint");

    // Resend invitation → resets member onboarding + (since the prior
    // invitation row is now `accepted` rather than `pending`) mints a
    // fresh invitation token. Next accept mints a NEW member-token
    // distinct from the first.
    let resent = inv
        .resend_invitation(create.group.id, bob, None, Some(&create.admin_token))
        .await
        .expect("resend");
    assert!(
        !resent.resent,
        "fresh token when no pending row exists (previous one already accepted)"
    );
    assert_ne!(resent.token, issued.token);
    let second_accept = inv.accept(&resent.token).await.expect("re-accept");
    let second_token = second_accept.member_token.expect("re-mint after reset");
    assert_ne!(
        first_token, second_token,
        "lost-token recovery mints fresh persistent member token"
    );

    cleanup(&pool, name, &[admin, bob]).await;
}

#[tokio::test]
async fn revoke_flips_pending_to_expired() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-inv-test-revoke-5";
    let admin = "bc1qinvadmin5";
    let bob = "bc1qinvbob5xx";
    cleanup(&pool, name, &[admin, bob]).await;

    let (svc, inv, _email) = build(&pool).await;
    let create = svc
        .create_group(name, admin, "admin@test.example", 5_000)
        .await
        .expect("create");
    svc.add_member(create.group.id, bob, 5_000, Some(&create.admin_token))
        .await
        .expect("add");
    let issued = inv
        .create_invitation(create.group.id, bob, None, Some(&create.admin_token))
        .await
        .expect("issue");
    inv.revoke(create.group.id, &issued.token, Some(&create.admin_token))
        .await
        .expect("revoke");
    let err = inv
        .accept(&issued.token)
        .await
        .expect_err("must not accept");
    assert!(matches!(err, BlockpartyInvitationServiceError::NotPending));

    cleanup(&pool, name, &[admin, bob]).await;
}
