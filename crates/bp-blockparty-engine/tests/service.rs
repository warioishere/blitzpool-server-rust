// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! `BlockpartyService` against the test Postgres: lifecycle transitions and
//! the routing cache staying in lockstep with the DB.

use bp_blockparty::BlockpartyStatus;
use std::sync::Arc;

use async_trait::async_trait;
use bp_blockparty_engine::{
    BlockpartyPayoutConfig, BlockpartyPayouts, BlockpartyService, BlockpartyServiceError,
    CoinbaseReservation,
};
use bp_common::{AddressId, Sats};
use bp_group_mgmt_engine::{AddressCache as PplnsAddressCache, OpenInviteTtl};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/blitzpool";

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

fn addr(s: &str) -> AddressId {
    AddressId::new(s).expect("test address")
}

/// Records every `ensure_capacity_for_members` call.
struct RecordingReservation {
    calls: Arc<std::sync::Mutex<Vec<usize>>>,
}

#[async_trait]
impl CoinbaseReservation for RecordingReservation {
    async fn ensure_capacity_for_members(&self, member_count: usize) {
        self.calls.lock().expect("poisoned").push(member_count);
    }
}

fn config() -> BlockpartyPayoutConfig {
    BlockpartyPayoutConfig {
        fee_address: addr("bc1qfeexxxx"),
        fee_percent: 2.0,
        min_payout_sats: Sats(5_000),
    }
}

async fn svc(pool: &PgPool) -> BlockpartyService {
    BlockpartyService::load(
        BlockpartyPayouts::new(pool.clone(), config()),
        PplnsAddressCache::new(),
    )
    .await
    .expect("load blockparty service")
}

/// Best-effort cleanup; addresses and names are unique per test.
async fn cleanup(pool: &PgPool, name: &str, admin_addr: &str) {
    let _ = sqlx::query(
        r#"DELETE FROM blockparty_join_link
           WHERE "groupId" IN (SELECT id FROM blockparty_group WHERE name = $1)"#,
    )
    .bind(name)
    .execute(pool)
    .await;
    let _ = sqlx::query(r#"DELETE FROM blockparty_group WHERE name = $1"#)
        .bind(name)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM blockparty_member WHERE address = $1"#)
        .bind(admin_addr)
        .execute(pool)
        .await;
}

/// The way into a party in production: `member` joins through the party's
/// link and the admin gives it `percent_bp`. Returns the member's token; the
/// member is not confirmed yet.
async fn join_with_split(
    svc: &BlockpartyService,
    group_id: Uuid,
    admin_token: &str,
    member: &str,
    percent_bp: i32,
) -> String {
    let link = svc
        .create_join_link(group_id, OpenInviteTtl::SevenDays, Some(admin_token))
        .await
        .expect("create_join_link");
    let (member_token, _) = svc
        .join_via_link(&link, member)
        .await
        .expect("join_via_link");
    svc.update_splits(group_id, &[(addr(member), percent_bp)], Some(admin_token))
        .await
        .expect("update_splits");
    member_token
}

async fn confirm(svc: &BlockpartyService, group_id: Uuid, member: &str, member_token: &str) {
    svc.confirm_as_member(group_id, &addr(member), Some(member_token))
        .await
        .expect("confirm_as_member");
}

// ─── Tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn create_group_seeds_draft_and_routing_cache() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-create-1";
    let admin = "bc1qadmincreate1";
    cleanup(&pool, name, admin).await;

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    let svc = svc(&pool).await;
    let res = svc
        .create_group(name, admin, 10_000)
        .await
        .expect("create_group");

    assert_eq!(res.group.status, BlockpartyStatus::Draft);
    assert_eq!(res.admin_member.role, "admin");
    assert!(res.admin_member.confirmed_at.is_some());
    assert!(res.admin_token.starts_with("GRP-"));

    let admin_addr = addr(admin);
    // Cache: routable=None (Draft), unready=Some (a Draft admin gets no work).
    assert!(svc.routable_group_id_for_admin(&admin_addr).await.is_none());
    assert!(svc.unready_group_id_for_admin(&admin_addr).await.is_some());

    cleanup(&pool, name, admin).await;
}

#[tokio::test]
async fn a_joined_member_flips_the_party_to_confirming_and_is_cached() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-add-2";
    let admin = "bc1qadminadd2";
    let bob = "bc1qbobadd2xx";
    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(bob)
        .execute(&pool)
        .await;

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, bob, "test@example.test").await;
    let svc = svc(&pool).await;
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    join_with_split(&svc, create.group.id, &create.admin_token, bob, 5_000).await;

    // DB row: CONFIRMING.
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, BlockpartyStatus::Confirming);

    // Admin cache: unready=Some, routable=None.
    let admin_addr = addr(admin);
    assert!(svc.unready_group_id_for_admin(&admin_addr).await.is_some());
    assert!(svc.routable_group_id_for_admin(&admin_addr).await.is_none());
    // Member cache: bob mapped.
    assert_eq!(svc.member_group_id(&addr(bob)).await, Some(create.group.id));

    cleanup(&pool, name, admin).await;
}

#[tokio::test]
async fn join_via_link_adds_unconfirmed_member_and_mints_token() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-joinlink-1";
    let admin = "bc1qadminjoin1";
    let carol = "bc1qcaroljoin1";
    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(carol)
        .execute(&pool)
        .await;

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, carol, "test@example.test").await;
    let svc = svc(&pool).await;
    let create = svc.create_group(name, admin, 5_000).await.expect("create");

    // Admin mints a join link; Carol self-joins via it (no admin token).
    let link = svc
        .create_join_link(
            create.group.id,
            OpenInviteTtl::SevenDays,
            Some(&create.admin_token),
        )
        .await
        .expect("create_join_link");
    let (member_token, group_id) = svc
        .join_via_link(&link, carol)
        .await
        .expect("join_via_link");
    assert_eq!(group_id, create.group.id);
    assert!(!member_token.is_empty());

    // Unconfirmed, 0 % placeholder, cached; group now confirming.
    let members = svc.list_members(create.group.id).await.unwrap();
    let carol_row = members
        .iter()
        .find(|m| m.address.as_str() == addr(carol).as_str())
        .expect("carol is a member");
    assert!(carol_row.confirmed_at.is_none());
    assert_eq!(carol_row.percent_bp, 0);
    assert_eq!(
        svc.member_group_id(&addr(carol)).await,
        Some(create.group.id)
    );
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, BlockpartyStatus::Confirming);

    // Unknown link → error (not found).
    assert!(svc
        .join_via_link("nonexistent-token", "bc1qzzz")
        .await
        .is_err());

    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(carol)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM blockparty_join_link WHERE token = $1")
        .bind(&link)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn join_via_link_admits_signature_verified_email_less_base58_address() {
    // A signature proof admits an email-less address; the mixed-case Base58
    // address pins that the gate does not lowercase it.
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-sigjoin-1";
    let admin = "bc1qadminsigjoin1";
    let carol = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"; // legacy P2PKH, mixed case
    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(carol)
        .execute(&pool)
        .await;
    bp_test_support::delete_signature_ownership(&pool, carol).await;
    bp_test_support::seed_signature_ownership(&pool, carol).await;
    // The admin must clear the create gate too.
    bp_test_support::delete_signature_ownership(&pool, admin).await;
    bp_test_support::seed_signature_ownership(&pool, admin).await;

    let svc = svc(&pool).await;
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    let link = svc
        .create_join_link(
            create.group.id,
            OpenInviteTtl::SevenDays,
            Some(&create.admin_token),
        )
        .await
        .expect("create_join_link");
    let (member_token, group_id) = svc
        .join_via_link(&link, carol)
        .await
        .expect("signature-verified base58 address should join");
    assert_eq!(group_id, create.group.id);
    assert!(!member_token.is_empty());
    let members = svc.list_members(create.group.id).await.unwrap();
    let carol_row = members
        .iter()
        .find(|m| m.address.as_str() == carol)
        .expect("member row keyed by the verbatim (case-preserved) Base58 address");
    assert_eq!(
        carol_row.email, "",
        "admitted by the signature, not an email"
    );

    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(carol)
        .execute(&pool)
        .await;
    bp_test_support::delete_signature_ownership(&pool, carol).await;
    bp_test_support::delete_signature_ownership(&pool, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_join_link WHERE \"groupId\" = $1")
        .bind(create.group.id)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn join_via_link_rejects_unverified_address() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-unverjoin-1";
    let admin = "bc1qadminunverjoin1";
    let dave = "bc1qdaveunverified1";
    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(dave)
        .execute(&pool)
        .await;
    bp_test_support::delete_signature_ownership(&pool, dave).await;
    // Only dave is unverified, so the join, not the create, is rejected.
    bp_test_support::delete_signature_ownership(&pool, admin).await;
    bp_test_support::seed_signature_ownership(&pool, admin).await;

    let svc = svc(&pool).await;
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    let link = svc
        .create_join_link(
            create.group.id,
            OpenInviteTtl::SevenDays,
            Some(&create.admin_token),
        )
        .await
        .expect("create_join_link");
    let err = svc
        .join_via_link(&link, dave)
        .await
        .expect_err("unverified address must be rejected");
    assert!(
        matches!(err, BlockpartyServiceError::EmailNotVerified),
        "expected EmailNotVerified, got {err:?}"
    );
    // No member row was created.
    assert!(svc.member_group_id(&addr(dave)).await.is_none());

    cleanup(&pool, name, admin).await;
    bp_test_support::delete_signature_ownership(&pool, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_join_link WHERE \"groupId\" = $1")
        .bind(create.group.id)
        .execute(&pool)
        .await;
}

/// A signature-verified, email-less admin can create; its row stores "".
#[tokio::test]
async fn create_group_admits_signature_verified_email_less_admin() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-sigcreate-1";
    let admin = "bc1qadminsigcreate1";
    cleanup(&pool, name, admin).await;
    bp_test_support::delete_signature_ownership(&pool, admin).await;
    bp_test_support::seed_signature_ownership(&pool, admin).await;

    let svc = svc(&pool).await;
    let create = svc
        .create_group(name, admin, 10_000)
        .await
        .expect("signature-verified admin should create");
    assert_eq!(create.group.status, BlockpartyStatus::Draft);
    assert_eq!(create.admin_member.role, "admin");
    assert_eq!(
        create.admin_member.email, "",
        "signature-only admin stores an empty email"
    );

    cleanup(&pool, name, admin).await;
    bp_test_support::delete_signature_ownership(&pool, admin).await;
}

/// An admin with neither email nor signature proof cannot create a party.
#[tokio::test]
async fn create_group_rejects_unverified_admin() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-unvercreate-1";
    let admin = "bc1qadminunvercreate1";
    cleanup(&pool, name, admin).await;
    bp_test_support::delete_signature_ownership(&pool, admin).await;

    let svc = svc(&pool).await;
    let err = svc
        .create_group(name, admin, 10_000)
        .await
        .expect_err("unverified admin must be rejected");
    assert!(
        matches!(err, BlockpartyServiceError::EmailNotVerified),
        "expected EmailNotVerified, got {err:?}"
    );
    let group_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM blockparty_group WHERE name = $1")
            .bind(name)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        group_count, 0,
        "no group row should exist for a rejected create"
    );

    cleanup(&pool, name, admin).await;
}

/// `confirmationRequestedAt` is unset at creation and stamped only by the admin.
#[tokio::test]
async fn request_member_confirmation_stamps_flag_and_is_admin_gated() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-reqconfirm-1";
    let admin = "bc1qadminreqconfirm1";
    cleanup(&pool, name, admin).await;

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    let svc = svc(&pool).await;
    let create = svc.create_group(name, admin, 10_000).await.expect("create");

    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert!(g.confirmation_requested_at.is_none());

    // Wrong admin token is rejected; the flag stays unset.
    assert!(svc
        .request_member_confirmation(create.group.id, Some("GRP-nope"))
        .await
        .is_err());
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert!(g.confirmation_requested_at.is_none());

    // Correct admin token stamps the flag.
    svc.request_member_confirmation(create.group.id, Some(&create.admin_token))
        .await
        .expect("request confirmation");
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert!(g.confirmation_requested_at.is_some());

    cleanup(&pool, name, admin).await;
}

#[tokio::test]
async fn the_last_confirmation_promotes_to_ready_and_unblocks_routing() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-confirm-3";
    let admin = "bc1qadminconf3";
    let bob = "bc1qbobconfirm";
    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(bob)
        .execute(&pool)
        .await;

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, bob, "test@example.test").await;
    let svc = svc(&pool).await;
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    let bob_token = join_with_split(&svc, create.group.id, &create.admin_token, bob, 5_000).await;

    // Pre-confirm: the admin gets no work.
    let admin_addr = addr(admin);
    assert!(svc.unready_group_id_for_admin(&admin_addr).await.is_some());

    // The admin is confirmed at creation, so bob's confirm makes it ready.
    confirm(&svc, create.group.id, bob, &bob_token).await;

    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, BlockpartyStatus::Ready);

    assert!(
        svc.unready_group_id_for_admin(&admin_addr).await.is_none(),
        "READY lets the admin mine"
    );
    assert_eq!(
        svc.routable_group_id_for_admin(&admin_addr).await,
        Some(create.group.id),
        "READY enables routing"
    );

    cleanup(&pool, name, admin).await;
}

#[tokio::test]
async fn on_share_accepted_promotes_ready_to_active_only() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-share-4";
    let admin = "bc1qadminshare4";
    let bob = "bc1qbobshare4x";
    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(bob)
        .execute(&pool)
        .await;

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, bob, "test@example.test").await;
    let svc = svc(&pool).await;
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    let admin_addr = addr(admin);

    // A share in draft must not promote.
    svc.on_share_accepted(&admin_addr)
        .await
        .expect("share-noop");
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, BlockpartyStatus::Draft, "no promotion from draft");

    // Add + confirm bob → READY.
    let bob_token = join_with_split(&svc, create.group.id, &create.admin_token, bob, 5_000).await;
    confirm(&svc, create.group.id, bob, &bob_token).await;

    // First share → READY → ACTIVE.
    svc.on_share_accepted(&admin_addr).await.expect("share");
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, BlockpartyStatus::Active);
    assert!(g.last_share_at.is_some());
    // ACTIVE remains routable.
    assert_eq!(
        svc.routable_group_id_for_admin(&admin_addr).await,
        Some(create.group.id)
    );

    cleanup(&pool, name, admin).await;
}

#[tokio::test]
async fn dissolve_blocked_during_active_cooldown() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-dissolve-5";
    let admin = "bc1qadmindiss5";
    let bob = "bc1qbobdiss5xx";
    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(bob)
        .execute(&pool)
        .await;

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, bob, "test@example.test").await;
    let svc = svc(&pool).await;
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    let bob_token = join_with_split(&svc, create.group.id, &create.admin_token, bob, 5_000).await;
    confirm(&svc, create.group.id, bob, &bob_token).await;
    svc.on_share_accepted(&addr(admin)).await.expect("share");
    // ACTIVE, last_share_at = now. Dissolve must be rejected.
    let err = svc
        .dissolve_group(create.group.id, Some(&create.admin_token))
        .await
        .expect_err("must be rejected");
    assert!(matches!(err, BlockpartyServiceError::DissolveCooldown));

    // Spoof last_share_at to >7d ago — dissolve must succeed.
    let long_ago = bp_blockparty::DISSOLVE_COOLDOWN_MS + 1_000;
    let cutoff = chrono::Utc::now().timestamp_millis() - long_ago;
    sqlx::query(r#"UPDATE blockparty_group SET "lastShareAt" = $2 WHERE id = $1"#)
        .bind(create.group.id)
        .bind(cutoff)
        .execute(&pool)
        .await
        .expect("spoof");
    svc.dissolve_group(create.group.id, Some(&create.admin_token))
        .await
        .expect("dissolve");
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, BlockpartyStatus::Dissolved);
    // Cache: dissolved drops both maps.
    assert!(svc
        .routable_group_id_for_admin(&addr(admin))
        .await
        .is_none());
    assert!(svc.member_group_id(&addr(admin)).await.is_none());

    cleanup(&pool, name, admin).await;
}

#[tokio::test]
async fn dissolve_frees_every_address_for_the_next_party() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-dissolve-free";
    let next = "bp-test-dissolve-free-next";
    let again = "bp-test-dissolve-free-again";
    let admin = "bc1qadminfree1";
    let bob = "bc1qbobfree1xx";
    let other_admin = "bc1qadminfree2";
    for (n, a) in [(name, admin), (next, other_admin), (again, admin)] {
        cleanup(&pool, n, a).await;
    }
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(bob)
        .execute(&pool)
        .await;

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, bob, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, other_admin, "test@example.test").await;
    let svc = svc(&pool).await;
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    join_with_split(&svc, create.group.id, &create.admin_token, bob, 5_000).await;
    // Precondition: bob really is a member before the dissolve.
    assert_eq!(svc.member_group_id(&addr(bob)).await, Some(create.group.id));

    // CONFIRMING dissolves without a cooldown.
    svc.dissolve_group(create.group.id, Some(&create.admin_token))
        .await
        .expect("dissolve");

    assert_eq!(
        svc.get_group(create.group.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        BlockpartyStatus::Dissolved
    );
    assert!(svc.list_members(create.group.id).await.unwrap().is_empty());
    assert!(svc.member_group_id(&addr(bob)).await.is_none());
    assert!(svc.member_group_id(&addr(admin)).await.is_none());

    // Bob can join another party, and the old admin can found a new one.
    let other = svc
        .create_group(next, other_admin, 5_000)
        .await
        .expect("create next");
    join_with_split(&svc, other.group.id, &other.admin_token, bob, 5_000).await;
    let refounded = svc
        .create_group(again, admin, 10_000)
        .await
        .expect("former admin founds a new party");
    assert_eq!(
        svc.member_group_id(&addr(admin)).await,
        Some(refounded.group.id)
    );

    for (n, a) in [(name, admin), (next, other_admin), (again, admin)] {
        cleanup(&pool, n, a).await;
    }
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(bob)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn on_block_found_is_idempotent_on_duplicate_hash() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-blockfound-6";
    let admin = "bc1qadminbf6xx";
    cleanup(&pool, name, admin).await;

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    let svc = svc(&pool).await;
    let create = svc.create_group(name, admin, 10_000).await.expect("create");
    // What the coinbase paid: the admin, and the pool fee to an address that
    // is not a member.
    let paid_to = std::collections::HashMap::from([
        (admin.to_owned(), 306_250_000u64),
        ("bc1qpoolfeeaddrx".to_owned(), 6_250_000u64),
    ]);
    let hash = "0000000000000000abcdef1234567890abcdef1234567890abcdef1234567890";

    let r1 = svc
        .payouts()
        .on_block_found(
            create.group.id,
            900_000,
            hash,
            Sats(312_500_000),
            &paid_to,
            Some(1_700_000_000_000),
        )
        .await
        .expect("first insert")
        .expect("a first booking inserts its row");
    assert_eq!(
        r1.splits.0,
        vec![bp_db::BlockpartySplitSnapshot {
            address: admin.to_owned(),
            percent_bp: 10_000,
            sats: 306_250_000,
            trimmed: false,
        }],
        "the member's sats are what the coinbase paid it"
    );
    assert_eq!(
        r1.pool_fee_sats,
        Sats(6_250_000),
        "the rest is the pool fee"
    );

    let r2 = svc
        .payouts()
        .on_block_found(
            create.group.id,
            900_000,
            hash,
            Sats(312_500_000),
            &paid_to,
            Some(1_700_000_000_000),
        )
        .await
        .expect("replay must not error");
    assert!(r2.is_none(), "replay returns None — ON CONFLICT DO NOTHING");

    // History should still hold exactly one row.
    let history = svc.get_history(create.group.id).await.unwrap();
    assert_eq!(history.len(), 1);

    cleanup(&pool, name, admin).await;
}

#[tokio::test]
async fn name_collision_rejects_second_create() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-nameclash-7";
    let admin_a = "bc1qadminclasha";
    let admin_b = "bc1qadminclashb";
    cleanup(&pool, name, admin_a).await;
    cleanup(&pool, name, admin_b).await;

    bp_test_support::seed_verified_email(&pool, admin_a, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, admin_b, "test@example.test").await;
    let svc = svc(&pool).await;
    svc.create_group(name, admin_a, 10_000)
        .await
        .expect("first");
    let err = svc
        .create_group(name, admin_b, 10_000)
        .await
        .expect_err("second must fail");
    assert!(matches!(err, BlockpartyServiceError::NameTaken));

    cleanup(&pool, name, admin_a).await;
    cleanup(&pool, name, admin_b).await;
}

#[tokio::test]
async fn ready_transition_sizes_coinbase_reservation_to_roster() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-reservation-9";
    let admin = "bc1qadminresv9";
    let bob = "bc1qbobresv9";
    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(bob)
        .execute(&pool)
        .await;

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, bob, "test@example.test").await;
    let calls = Arc::new(std::sync::Mutex::new(Vec::<usize>::new()));
    let svc = BlockpartyService::load(
        BlockpartyPayouts::new(pool.clone(), config()),
        PplnsAddressCache::new(),
    )
    .await
    .expect("load blockparty service")
    .with_coinbase_reservation(Some(Arc::new(RecordingReservation {
        calls: calls.clone(),
    })));

    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    let bob_token = join_with_split(&svc, create.group.id, &create.admin_token, bob, 5_000).await;

    // Still confirming: the hook fires only at ready.
    assert!(
        calls.lock().unwrap().is_empty(),
        "reservation hook must not fire before the party is Ready"
    );

    // Ready with admin + bob: the hook gets exactly 2 members.
    confirm(&svc, create.group.id, bob, &bob_token).await;
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, BlockpartyStatus::Ready);

    let recorded = calls.lock().unwrap().clone();
    assert!(
        !recorded.is_empty(),
        "→ Ready must size the coinbase reservation"
    );
    assert!(
        recorded.iter().all(|&n| n == 2),
        "reservation must be sized to the exact 2-member roster; recorded {recorded:?}"
    );

    cleanup(&pool, name, admin).await;
}

/// Ready already routes shares into the party coinbase, and a block is booked
/// against the roster (who the members are, at what percent), so the roster
/// must be frozen from Ready on. The same edit succeeds while confirming (negative control).
#[tokio::test]
async fn a_ready_party_refuses_every_roster_edit() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-ready-frozen";
    let admin = "bc1qadminfrozen";
    let bob = "bc1qbobfrozen";
    let carol = "bc1qcarolfrozen";
    cleanup(&pool, name, admin).await;
    for a in [bob, carol] {
        let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
            .bind(a)
            .execute(&pool)
            .await;
    }

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, bob, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, carol, "test@example.test").await;
    let svc = svc(&pool).await;
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    let gid = create.group.id;
    let token = Some(create.admin_token.as_str());
    let bob_token = join_with_split(&svc, gid, &create.admin_token, bob, 5_000).await;
    // Minted while the party is editable, used once it is not.
    let link = svc
        .create_join_link(gid, OpenInviteTtl::SevenDays, token)
        .await
        .expect("precondition: confirming is editable");

    confirm(&svc, gid, bob, &bob_token).await;
    let g = svc.get_group(gid).await.unwrap().unwrap();
    assert_eq!(
        g.status,
        BlockpartyStatus::Ready,
        "precondition: the party must be routable"
    );

    let splits = svc.update_splits(gid, &[(addr(bob), 5_000)], token).await;
    assert!(
        matches!(splits, Err(BlockpartyServiceError::NotEditable)),
        "{splits:?}"
    );
    let join = svc.join_via_link(&link, carol).await;
    assert!(
        matches!(join, Err(BlockpartyServiceError::NotEditable)),
        "{join:?}"
    );
    let remove = svc.remove_member(gid, bob, token).await;
    assert!(
        matches!(remove, Err(BlockpartyServiceError::NotEditable)),
        "{remove:?}"
    );
    let g = svc.get_group(gid).await.unwrap().unwrap();
    assert_eq!(g.status, BlockpartyStatus::Ready);
    assert_eq!(svc.list_members(gid).await.unwrap().len(), 2);

    cleanup(&pool, name, admin).await;
}

#[tokio::test]
async fn update_splits_confirms_admin_and_resets_non_admin() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-splits-10";
    let admin = "bc1qadminsplits10";
    let bob = "bc1qbobsplits10";
    // Unconfirmed, so the party stays editable while bob is confirmed.
    let carol = "bc1qcarolsplits10";
    cleanup(&pool, name, admin).await;
    for a in [bob, carol] {
        let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
            .bind(a)
            .execute(&pool)
            .await;
    }

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, bob, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, carol, "test@example.test").await;
    let svc = svc(&pool).await;
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    let gid = create.group.id;
    let token = Some(create.admin_token.as_str());
    let bob_token = join_with_split(&svc, gid, &create.admin_token, bob, 3_000).await;
    let carol_token = join_with_split(&svc, gid, &create.admin_token, carol, 2_000).await;
    confirm(&svc, gid, bob, &bob_token).await;
    let bob_before = bp_db::list_blockparty_members_for_group(&pool, gid)
        .await
        .expect("list members")
        .into_iter()
        .find(|m| m.address.as_str() == bob)
        .unwrap();
    assert!(
        bob_before.confirmed_at.is_some(),
        "precondition: bob must be confirmed before the edit"
    );

    // Edit splits: move percent from bob to the admin.
    svc.update_splits(gid, &[(addr(admin), 6_000), (addr(bob), 2_000)], token)
        .await
        .expect("update_splits");

    let members = bp_db::list_blockparty_members_for_group(&pool, gid)
        .await
        .expect("list members");
    let admin_row = members
        .iter()
        .find(|m| m.address.as_str() == admin)
        .unwrap();
    let bob_row = members.iter().find(|m| m.address.as_str() == bob).unwrap();

    assert!(
        admin_row.confirmed_at.is_some(),
        "admin must be confirmed after splits edit (authoring = consent)"
    );
    assert!(
        bob_row.confirmed_at.is_none(),
        "non-admin must lose confirmedAt after splits edit"
    );
    let g = svc.get_group(gid).await.unwrap().unwrap();
    assert_eq!(g.status, BlockpartyStatus::Confirming);

    // Everyone re-confirms → READY.
    for (m, t) in [(bob, &bob_token), (carol, &carol_token)] {
        confirm(&svc, gid, m, t).await;
    }
    let g = svc.get_group(gid).await.unwrap().unwrap();
    assert_eq!(
        g.status,
        BlockpartyStatus::Ready,
        "group enters READY once all members confirm the new splits"
    );

    cleanup(&pool, name, admin).await;
}

/// On the production path (join link, the member confirms) a party whose
/// splits miss the full cut stays Confirming; once the admin completes the
/// splits and the member confirms them, it turns Ready.
#[tokio::test]
async fn a_party_turns_ready_only_with_complete_splits() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-splitsum-11";
    let admin = "bc1qadminsplitsum11";
    let carol = "bc1qcarolsplitsum11";
    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(carol)
        .execute(&pool)
        .await;

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, carol, "test@example.test").await;
    let svc = svc(&pool).await;
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    let gid = create.group.id;
    let token = Some(create.admin_token.as_str());
    let link = svc
        .create_join_link(gid, OpenInviteTtl::SevenDays, token)
        .await
        .expect("create_join_link");
    let (carol_token, _) = svc.join_via_link(&link, carol).await.expect("join");
    svc.confirm_as_member(gid, &addr(carol), Some(&carol_token))
        .await
        .expect("confirm");
    let g = svc.get_group(gid).await.unwrap().unwrap();
    assert_eq!(
        g.status,
        BlockpartyStatus::Confirming,
        "5000 + 0 bp is not the full cut, even with everyone confirmed"
    );

    svc.update_splits(gid, &[(addr(carol), 5_000)], token)
        .await
        .expect("update_splits");
    svc.confirm_as_member(gid, &addr(carol), Some(&carol_token))
        .await
        .expect("re-confirm");
    let g = svc.get_group(gid).await.unwrap().unwrap();
    assert_eq!(
        g.status,
        BlockpartyStatus::Ready,
        "5000 + 5000 bp, everyone confirmed"
    );

    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(carol)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM blockparty_join_link WHERE token = $1")
        .bind(&link)
        .execute(&pool)
        .await;
}

/// A sole admin at the full cut plus a member who joined by link (0 bp
/// placeholder) sums to 10000 already; the party still stays Confirming,
/// because the member holds no split yet.
#[tokio::test]
async fn a_joined_member_without_a_split_keeps_the_party_confirming() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-splitmin-12";
    let admin = "bc1qadminsplitmin12";
    let dave = "bc1qdavesplitmin12";
    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(dave)
        .execute(&pool)
        .await;

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    bp_test_support::seed_verified_email(&pool, dave, "test@example.test").await;
    let svc = svc(&pool).await;
    let create = svc.create_group(name, admin, 10_000).await.expect("create");
    let gid = create.group.id;
    let link = svc
        .create_join_link(gid, OpenInviteTtl::SevenDays, Some(&create.admin_token))
        .await
        .expect("create_join_link");
    let (dave_token, _) = svc.join_via_link(&link, dave).await.expect("join");
    svc.confirm_as_member(gid, &addr(dave), Some(&dave_token))
        .await
        .expect("confirm");
    let g = svc.get_group(gid).await.unwrap().unwrap();
    assert_eq!(
        g.status,
        BlockpartyStatus::Confirming,
        "10000 + 0 bp sums right, but the member has no split"
    );

    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(dave)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM blockparty_join_link WHERE token = $1")
        .bind(&link)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn update_rental_hint_sets_cleans_and_clears() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-rental-hint-1";
    let admin = "bc1qadminrentalhint1";
    cleanup(&pool, name, admin).await;

    bp_test_support::seed_verified_email(&pool, admin, "test@example.test").await;
    let svc = svc(&pool).await;
    let create = svc
        .create_group(name, admin, 10_000)
        .await
        .expect("create_group");
    let gid = create.group.id;
    let tok = &create.admin_token;

    // Set a plain hint.
    let stored = svc
        .update_rental_hint(gid, Some("MRR"), Some(tok))
        .await
        .expect("set hint");
    assert_eq!(stored.as_deref(), Some("MRR"));

    // Overwrite with a value that needs truncation to 64 chars.
    let long = "x".repeat(80);
    let stored = svc
        .update_rental_hint(gid, Some(&long), Some(tok))
        .await
        .expect("truncate hint");
    assert_eq!(stored.as_deref().map(str::len), Some(64));

    // Whitespace-only hint is stored as None.
    let stored = svc
        .update_rental_hint(gid, Some("  "), Some(tok))
        .await
        .expect("clear hint");
    assert!(
        stored.is_none(),
        "whitespace-only hint must be stored as null"
    );

    // Explicit None also clears.
    let _ = svc
        .update_rental_hint(gid, Some("MRR"), Some(tok))
        .await
        .expect("re-set");
    let stored = svc
        .update_rental_hint(gid, None, Some(tok))
        .await
        .expect("explicit None");
    assert!(stored.is_none());

    // Wrong token is rejected.
    let err = svc
        .update_rental_hint(gid, Some("MRR"), Some("wrong"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            BlockpartyServiceError::InvalidToken | BlockpartyServiceError::MissingToken
        ),
        "wrong token must be rejected"
    );

    cleanup(&pool, name, admin).await;
}
