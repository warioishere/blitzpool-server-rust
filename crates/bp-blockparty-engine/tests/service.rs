// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `bp_blockparty_engine::BlockpartyService`
//! against the local docker-PG (`blitzpool-rust-pg` on :15433).
//!
//! Coverage:
//! - createGroup + DRAFT initial status (+ cache hit)
//! - addMember auto-flips DRAFT → CONFIRMING (+ cache sync)
//! - markMemberConfirmed promotes CONFIRMING → READY and the
//!   load-bearing routing-cache invariant: routable + pending-fee
//!   guards both flip in lockstep with the DB
//! - onShareAccepted promotes READY → ACTIVE (and ONLY from READY)
//! - dissolve cooldown gates ACTIVE within the 7-day silence window
//! - onBlockFound is idempotent on duplicate (groupId, blockHash)
//! - name collision rejects second create

use std::sync::Arc;

use async_trait::async_trait;
use bp_blockparty_engine::{
    BlockpartyHooks, BlockpartyService, BlockpartyServiceConfig, BlockpartyServiceError,
    CoinbaseReservation,
};
use bp_common::{AddressId, Sats};
use bp_group_mgmt_engine::{AddressCache as PplnsAddressCache, OpenInviteTtl};
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

// ── Test hooks: every address binds to the same canned email. ──
struct AllVerified;

#[async_trait]
impl BlockpartyHooks for AllVerified {
    async fn verified_email_for(&self, _address: &AddressId) -> Option<String> {
        Some("test@example.test".to_owned())
    }
}

fn addr(s: &str) -> AddressId {
    AddressId::new(s).expect("test address")
}

/// Records every `ensure_capacity_for_members` call so a test can assert the
/// `→ Ready` transition sizes the coinbase reservation to the exact roster.
struct RecordingReservation {
    calls: Arc<std::sync::Mutex<Vec<usize>>>,
}

#[async_trait]
impl CoinbaseReservation for RecordingReservation {
    async fn ensure_capacity_for_members(&self, member_count: usize) {
        self.calls.lock().expect("poisoned").push(member_count);
    }
}

fn config() -> BlockpartyServiceConfig {
    BlockpartyServiceConfig {
        fee_address: Some(addr("bc1qfeexxxx")),
        fee_percent: 2.0,
        min_payout_sats: Sats(5_000),
    }
}

fn svc(pool: &PgPool) -> BlockpartyService<AllVerified> {
    BlockpartyService::new(
        pool.clone(),
        Arc::new(AllVerified),
        PplnsAddressCache::new(),
        config(),
    )
}

// ── Test hook: NO address has a verified email — forces the gate onto the
//    signature-ownership branch (or the reject branch when neither is present). ──
struct NoEmail;

#[async_trait]
impl BlockpartyHooks for NoEmail {
    async fn verified_email_for(&self, _address: &AddressId) -> Option<String> {
        None
    }
}

fn svc_no_email(pool: &PgPool) -> BlockpartyService<NoEmail> {
    BlockpartyService::new(
        pool.clone(),
        Arc::new(NoEmail),
        PplnsAddressCache::new(),
        config(),
    )
}

/// Seed a verified signature-ownership proof for `address`, stored VERBATIM
/// (case-preserved) exactly as the `/api/address/ownership/verify` path writes it.
async fn seed_signature(pool: &PgPool, address: &str) {
    let now = 1_700_000_000_000_i64;
    let _ = sqlx::query(
        r#"INSERT INTO pplns_address_ownership
             (address, method, "scriptType", "verifiedAt", "createdAt", "updatedAt")
           VALUES ($1, 'bip137', 'p2pkh', $2, $2, $2)
           ON CONFLICT (address) DO UPDATE SET "verifiedAt" = EXCLUDED."verifiedAt""#,
    )
    .bind(address)
    .bind(now)
    .execute(pool)
    .await;
}

async fn delete_signature(pool: &PgPool, address: &str) {
    let _ = sqlx::query(r#"DELETE FROM pplns_address_ownership WHERE address = $1"#)
        .bind(address)
        .execute(pool)
        .await;
}

/// Best-effort row cleanup. We use unique-per-test addresses + names so
/// concurrent runs don't collide, and the FK CASCADE on group dissolve
/// would take care of children — but tests don't always reach dissolve.
async fn cleanup(pool: &PgPool, name: &str, admin_addr: &str) {
    let _ = sqlx::query(r#"DELETE FROM blockparty_group WHERE name = $1"#)
        .bind(name)
        .execute(pool)
        .await;
    let _ = sqlx::query(r#"DELETE FROM blockparty_member WHERE address = $1"#)
        .bind(admin_addr)
        .execute(pool)
        .await;
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

    let svc = svc(&pool);
    let res = svc
        .create_group(name, admin, 10_000)
        .await
        .expect("create_group");

    assert_eq!(res.group.status, "draft");
    assert_eq!(res.admin_member.role, "admin");
    assert!(res.admin_member.confirmed_at.is_some());
    assert!(res.admin_token.starts_with("GRP-"));

    let admin_addr = addr(admin);
    // Cache: routable=None (Draft), pending-fee=Some (Draft is pending).
    assert!(svc.routable_group_id_for_admin(&admin_addr).await.is_none());
    assert!(svc.pending_party_fee_route(&admin_addr).await.is_some());

    cleanup(&pool, name, admin).await;
}

#[tokio::test]
async fn add_member_flips_to_confirming_and_inserts_member_cache() {
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

    let svc = svc(&pool);
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    svc.add_member(create.group.id, bob, 5_000, Some(&create.admin_token))
        .await
        .expect("add_member");

    // DB row: CONFIRMING.
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, "confirming");

    // Admin cache: pending-fee=Some, routable=None.
    let admin_addr = addr(admin);
    assert!(svc.pending_party_fee_route(&admin_addr).await.is_some());
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

    let svc = svc(&pool);
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

    // Member exists, UNCONFIRMED (must still confirm the split the admin sets),
    // 0 % placeholder, cached; group flipped DRAFT → CONFIRMING.
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
    assert_eq!(g.status, "confirming");

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
    // The unified gate's whole point: an address with NO verified email but a
    // valid signature-ownership proof may join. Uses a mixed-case legacy Base58
    // address to also prove the case-normalization fix (the proof is stored
    // verbatim `1BvBM…`; the gate must not lowercase it).
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
    delete_signature(&pool, carol).await;
    seed_signature(&pool, carol).await;
    // The admin must itself clear the create gate (email OR signature); the
    // NoEmail hook gives no email, so seed the admin's signature proof too.
    delete_signature(&pool, admin).await;
    seed_signature(&pool, admin).await;

    let svc = svc_no_email(&pool);
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    let link = svc
        .create_join_link(
            create.group.id,
            OpenInviteTtl::SevenDays,
            Some(&create.admin_token),
        )
        .await
        .expect("create_join_link");
    // NoEmail hook → email.is_none() is true → the gate falls through to the
    // signature-ownership lookup, which must find the verbatim Base58 row.
    let (member_token, group_id) = svc
        .join_via_link(&link, carol)
        .await
        .expect("signature-verified base58 address should join");
    assert_eq!(group_id, create.group.id);
    assert!(!member_token.is_empty());
    let members = svc.list_members(create.group.id).await.unwrap();
    assert!(
        members.iter().any(|m| m.address.as_str() == carol),
        "member row keyed by the verbatim (case-preserved) Base58 address"
    );

    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(carol)
        .execute(&pool)
        .await;
    delete_signature(&pool, carol).await;
    delete_signature(&pool, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_join_link WHERE \"groupId\" = $1")
        .bind(create.group.id)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn join_via_link_rejects_unverified_address() {
    // Neither a verified email nor a signature proof → the gate must reject.
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
    delete_signature(&pool, dave).await;
    // The admin must clear the create gate; only the join target (dave) is
    // left unverified so the join — not the create — is what gets rejected.
    delete_signature(&pool, admin).await;
    seed_signature(&pool, admin).await;

    let svc = svc_no_email(&pool);
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
    delete_signature(&pool, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_join_link WHERE \"groupId\" = $1")
        .bind(create.group.id)
        .execute(&pool)
        .await;
}

/// The create gate itself: a signature-verified but email-less admin can open
/// a party, and the admin member row stores an empty email (badge = signature).
#[tokio::test]
async fn create_group_admits_signature_verified_email_less_admin() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-sigcreate-1";
    let admin = "bc1qadminsigcreate1";
    cleanup(&pool, name, admin).await;
    delete_signature(&pool, admin).await;
    seed_signature(&pool, admin).await;

    let svc = svc_no_email(&pool);
    let create = svc
        .create_group(name, admin, 10_000)
        .await
        .expect("signature-verified admin should create");
    assert_eq!(create.group.status, "draft");
    assert_eq!(create.admin_member.role, "admin");
    assert_eq!(
        create.admin_member.email, "",
        "signature-only admin stores an empty email"
    );

    cleanup(&pool, name, admin).await;
    delete_signature(&pool, admin).await;
}

/// The create gate rejects an admin with neither a verified email nor a
/// signature proof — the party is never inserted.
#[tokio::test]
async fn create_group_rejects_unverified_admin() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-unvercreate-1";
    let admin = "bc1qadminunvercreate1";
    cleanup(&pool, name, admin).await;
    delete_signature(&pool, admin).await;

    let svc = svc_no_email(&pool);
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

/// The admin "members may confirm now" signal: unset at creation, admin-gated,
/// stamps `confirmationRequestedAt` on success.
#[tokio::test]
async fn request_member_confirmation_stamps_flag_and_is_admin_gated() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-reqconfirm-1";
    let admin = "bc1qadminreqconfirm1";
    cleanup(&pool, name, admin).await;

    let svc = svc(&pool);
    let create = svc.create_group(name, admin, 10_000).await.expect("create");

    // Unset at creation — a freshly-joined member must not be nagged yet.
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
async fn mark_member_confirmed_promotes_to_ready_and_unblocks_routing() {
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

    let svc = svc(&pool);
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    svc.add_member(create.group.id, bob, 5_000, Some(&create.admin_token))
        .await
        .expect("add_member");

    // Pre-confirm: pending-fee guard active.
    let admin_addr = addr(admin);
    assert!(svc.pending_party_fee_route(&admin_addr).await.is_some());

    // Confirm bob. Status should flip to READY because all members
    // (admin auto-confirmed at creation, bob now) have confirmedAt.
    let r = svc
        .mark_member_confirmed(create.group.id, &addr(bob))
        .await
        .expect("mark_confirmed");
    assert!(r.member_token.is_some(), "first confirm mints token");

    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, "ready");

    // Cache sync — the load-bearing invariant.
    assert!(
        svc.pending_party_fee_route(&admin_addr).await.is_none(),
        "READY cancels pending-fee guard"
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

    let svc = svc(&pool);
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    let admin_addr = addr(admin);

    // Pre-confirm: share in DRAFT should NOT promote (defensive).
    svc.on_share_accepted(&admin_addr)
        .await
        .expect("share-noop");
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, "draft", "no promotion from draft");

    // Add + confirm bob → READY.
    svc.add_member(create.group.id, bob, 5_000, Some(&create.admin_token))
        .await
        .expect("add");
    svc.mark_member_confirmed(create.group.id, &addr(bob))
        .await
        .expect("confirm");

    // First share → READY → ACTIVE.
    svc.on_share_accepted(&admin_addr).await.expect("share");
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, "active");
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

    let svc = svc(&pool);
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    svc.add_member(create.group.id, bob, 5_000, Some(&create.admin_token))
        .await
        .expect("add");
    svc.mark_member_confirmed(create.group.id, &addr(bob))
        .await
        .expect("confirm");
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
    assert_eq!(g.status, "dissolved");
    // Cache: dissolved drops both maps.
    assert!(svc
        .routable_group_id_for_admin(&addr(admin))
        .await
        .is_none());
    assert!(svc.member_group_id(&addr(admin)).await.is_none());

    cleanup(&pool, name, admin).await;
}

#[tokio::test]
async fn on_block_found_is_idempotent_on_duplicate_hash() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-blockfound-6";
    let admin = "bc1qadminbf6xx";
    cleanup(&pool, name, admin).await;

    let svc = svc(&pool);
    let create = svc.create_group(name, admin, 10_000).await.expect("create");
    let splits = vec![bp_db::BlockpartySplitSnapshot {
        address: admin.to_owned(),
        percent_bp: 10_000,
        sats: 312_500_000,
        trimmed: false,
    }];
    let hash = "0000000000000000abcdef1234567890abcdef1234567890abcdef1234567890";

    let r1 = svc
        .on_block_found(
            create.group.id,
            900_000,
            hash,
            Sats(312_500_000),
            Sats(0),
            &splits,
            Some(1_700_000_000_000),
        )
        .await
        .expect("first insert");
    assert!(r1.is_some());

    let r2 = svc
        .on_block_found(
            create.group.id,
            900_000,
            hash,
            Sats(312_500_000),
            Sats(0),
            &splits,
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

    let svc = svc(&pool);
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

    // Service with a recording reservation hook.
    let calls = Arc::new(std::sync::Mutex::new(Vec::<usize>::new()));
    let svc = BlockpartyService::new(
        pool.clone(),
        Arc::new(AllVerified),
        PplnsAddressCache::new(),
        config(),
    )
    .with_coinbase_reservation(Some(Arc::new(RecordingReservation {
        calls: calls.clone(),
    })));

    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    svc.add_member(create.group.id, bob, 5_000, Some(&create.admin_token))
        .await
        .expect("add_member");

    // Still CONFIRMING (bob unconfirmed) → the reservation hook must NOT have
    // fired yet (only fires at → Ready).
    assert!(
        calls.lock().unwrap().is_empty(),
        "reservation hook must not fire before the party is Ready"
    );

    // Confirm bob → all members confirmed → READY → hook fires with the exact
    // roster (admin auto-confirmed at create + bob = 2 members).
    svc.mark_member_confirmed(create.group.id, &addr(bob))
        .await
        .expect("mark_confirmed");
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(g.status, "ready");

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

#[tokio::test]
async fn update_splits_confirms_admin_and_resets_non_admin() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-splits-10";
    let admin = "bc1qadminsplits10";
    let bob = "bc1qbobsplits10";
    cleanup(&pool, name, admin).await;
    let _ = sqlx::query("DELETE FROM blockparty_member WHERE address = $1")
        .bind(bob)
        .execute(&pool)
        .await;

    let svc = svc(&pool);
    let create = svc.create_group(name, admin, 5_000).await.expect("create");
    svc.add_member(create.group.id, bob, 5_000, Some(&create.admin_token))
        .await
        .expect("add_member");

    // Confirm bob → READY (admin is confirmed at creation).
    svc.mark_member_confirmed(create.group.id, &addr(bob))
        .await
        .expect("mark_confirmed");
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(
        g.status, "ready",
        "precondition: group READY before splits edit"
    );

    // Edit splits: swap percentages.
    svc.update_splits(
        create.group.id,
        &[(addr(admin), 6_000), (addr(bob), 4_000)],
        Some(&create.admin_token),
    )
    .await
    .expect("update_splits");

    // Verify member rows directly.
    let members = bp_db::list_blockparty_members_for_group(&pool, create.group.id)
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

    // Group must be CONFIRMING until bob re-confirms.
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(
        g.status, "confirming",
        "splits edit resets group to CONFIRMING"
    );

    // Re-confirm bob → READY again.
    svc.mark_member_confirmed(create.group.id, &addr(bob))
        .await
        .expect("re-confirm bob");
    let g = svc.get_group(create.group.id).await.unwrap().unwrap();
    assert_eq!(
        g.status, "ready",
        "group re-enters READY once all members re-confirm"
    );

    cleanup(&pool, name, admin).await;
}

#[tokio::test]
async fn update_rental_hint_sets_cleans_and_clears() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    let name = "bp-test-rental-hint-1";
    let admin = "bc1qadminrentalhint1";
    cleanup(&pool, name, admin).await;

    let svc = svc(&pool);
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
