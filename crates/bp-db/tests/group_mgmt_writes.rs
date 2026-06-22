// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for the group-mgmt service-layer write primitives
//! (consumed by `bp-group-mgmt-engine` GroupService /
//! InvitationService / JoinRequestService).
//!
//! Gated on docker-PG at `postgres://postgres:postgres@localhost:15433/public_pool`.
//! Each test runs inside its own TX which rolls back at end so the
//! container's seeded schema stays clean between runs.

use bp_common::AddressId;
use bp_db::{
    count_pplns_group_join_requests_pending_for_address, count_pplns_group_members_for_group,
    delete_pplns_group_invitation_by_token, delete_pplns_group_member,
    delete_pplns_group_members_for_group, expire_pending_pplns_group_invitations,
    expire_pending_pplns_group_join_requests, find_all_pplns_group_members, find_group,
    find_pplns_group_active_open_invite_for_group, find_pplns_group_by_name_not_dissolved,
    find_pplns_group_creator_member, find_pplns_group_invitation_pending_directed,
    find_pplns_group_invitations_pending_for_address_directed,
    find_pplns_group_invitations_pending_for_group_directed,
    find_pplns_group_join_request_most_recent_rejected,
    find_pplns_group_join_request_pending_in_group, find_pplns_group_member_in_group,
    insert_pplns_group, insert_pplns_group_invitation, insert_pplns_group_join_request,
    insert_pplns_group_member, list_active_pplns_groups, list_pplns_group_join_requests_for_group,
    list_pplns_group_join_requests_pending_for_address, revoke_pending_open_invites_for_group,
    update_pplns_group_active, update_pplns_group_creator_and_admin_token,
    update_pplns_group_dissolved, update_pplns_group_invitation_status_by_token,
    update_pplns_group_join_request_decision, update_pplns_group_member_role,
    update_pplns_group_round_reset_config, PatchField, RoundResetConfigPatch,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

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

fn addr(s: &str) -> AddressId {
    AddressId::new(s).expect("test address shape")
}

// ─── Groups ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn insert_group_returns_row_with_defaults() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let mut tx = pool.begin().await.expect("begin tx");
    let id = Uuid::new_v4();
    let row = insert_pplns_group(
        &pool,
        id,
        "test-group-A",
        &addr("test_creator_a"),
        "hash-a",
        false,
        false,
        1_700_000_000_000,
    )
    .await
    .expect("insert");
    // The bp-db helper opens its own connection from the pool, so the
    // resulting row sits outside `tx`. Clean it up manually before the
    // TX rolls back (and unrelated rows that the in-pool ops below
    // create stay isolated in their own TXs).
    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .ok();
    tx.commit().await.expect("commit cleanup");
    // Cleanup-after assertion since the insert lands outside the TX.
    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("cleanup outside tx");

    assert_eq!(row.id, id);
    assert_eq!(row.name, "test-group-A");
    assert!(!row.active);
    assert!(!row.is_public);
    assert_eq!(row.created_at, 1_700_000_000_000);
    assert_eq!(row.updated_at, 1_700_000_000_000);
    assert!(row.dissolved_at.is_none());
    assert!(row.round_reset_preset.is_none());
}

#[tokio::test]
async fn find_group_by_name_filters_dissolved() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let id = Uuid::new_v4();
    let unique_name = format!("dup-name-test-{}", id);
    insert_pplns_group(
        &pool,
        id,
        &unique_name,
        &addr("dup_creator"),
        "h",
        false,
        false,
        1,
    )
    .await
    .expect("insert");
    let found = find_pplns_group_by_name_not_dissolved(&pool, &unique_name)
        .await
        .expect("lookup")
        .expect("present");
    assert_eq!(found.id, id);

    // Dissolve and re-lookup — must be gone.
    update_pplns_group_dissolved(&pool, id, 2)
        .await
        .expect("dis");
    let gone = find_pplns_group_by_name_not_dissolved(&pool, &unique_name)
        .await
        .expect("lookup-2");
    assert!(gone.is_none());

    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
async fn list_active_groups_omits_dissolved() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let alive = Uuid::new_v4();
    let dead = Uuid::new_v4();
    let alive_name = format!("alive-{}", alive);
    let dead_name = format!("dead-{}", dead);
    insert_pplns_group(
        &pool,
        alive,
        &alive_name,
        &addr("alive_c"),
        "h1",
        false,
        false,
        1,
    )
    .await
    .expect("insert-alive");
    insert_pplns_group(
        &pool,
        dead,
        &dead_name,
        &addr("dead_c"),
        "h2",
        false,
        false,
        1,
    )
    .await
    .expect("insert-dead");
    update_pplns_group_dissolved(&pool, dead, 5)
        .await
        .expect("dissolve");

    let listed = list_active_pplns_groups(&pool).await.expect("list");
    assert!(listed.iter().any(|g| g.id == alive));
    assert!(!listed.iter().any(|g| g.id == dead));

    for id in [alive, dead] {
        sqlx::query("DELETE FROM pplns_group WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .ok();
    }
}

#[tokio::test]
async fn active_toggle_and_count_members() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let gid = Uuid::new_v4();
    let name = format!("active-{}", gid);
    insert_pplns_group(
        &pool,
        gid,
        &name,
        &addr("act_creator"),
        "h",
        false,
        false,
        1,
    )
    .await
    .expect("g");
    insert_pplns_group_member(&pool, gid, &addr("m1"), "creator", 2)
        .await
        .expect("m1");
    let count = count_pplns_group_members_for_group(&pool, gid)
        .await
        .expect("count");
    assert_eq!(count, 1);
    insert_pplns_group_member(&pool, gid, &addr("m2"), "member", 3)
        .await
        .expect("m2");
    let count2 = count_pplns_group_members_for_group(&pool, gid)
        .await
        .expect("count2");
    assert_eq!(count2, 2);
    update_pplns_group_active(&pool, gid, true, 10)
        .await
        .expect("active-true");
    let group = find_group(&pool, gid)
        .await
        .expect("find")
        .expect("present");
    assert!(group.active);
    assert_eq!(group.updated_at, 10);

    // Cleanup
    delete_pplns_group_members_for_group(&pool, gid)
        .await
        .expect("del-members");
    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn transfer_creator_swaps_admin_token_and_creator_address() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let gid = Uuid::new_v4();
    let name = format!("xfer-{}", gid);
    insert_pplns_group(
        &pool,
        gid,
        &name,
        &addr("old_creator"),
        "old_hash",
        false,
        false,
        1,
    )
    .await
    .expect("g");
    insert_pplns_group_member(&pool, gid, &addr("old_creator"), "creator", 2)
        .await
        .expect("m1");
    insert_pplns_group_member(&pool, gid, &addr("new_creator"), "member", 3)
        .await
        .expect("m2");

    update_pplns_group_creator_and_admin_token(&pool, gid, &addr("new_creator"), "new_hash", 100)
        .await
        .expect("creator");
    update_pplns_group_member_role(&pool, gid, &addr("old_creator"), "member")
        .await
        .expect("demote");
    update_pplns_group_member_role(&pool, gid, &addr("new_creator"), "creator")
        .await
        .expect("promote");

    let g = find_group(&pool, gid).await.expect("g").expect("present");
    assert_eq!(g.creator_address.as_str(), "new_creator");
    assert_eq!(g.admin_token_hash, "new_hash");
    let creator = find_pplns_group_creator_member(&pool, gid)
        .await
        .expect("c")
        .expect("present");
    assert_eq!(creator.address.as_str(), "new_creator");

    delete_pplns_group_members_for_group(&pool, gid).await.ok();
    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn round_reset_config_patch_applies_per_field() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let gid = Uuid::new_v4();
    let name = format!("rr-{}", gid);
    insert_pplns_group(&pool, gid, &name, &addr("rr_creator"), "h", false, false, 1)
        .await
        .expect("g");

    // First patch — Set everything.
    let p1 = RoundResetConfigPatch {
        preset: PatchField::Set("daily".into()),
        interval_days: PatchField::Untouched,
        timezone: PatchField::Set("Europe/Berlin".into()),
        hour_local: PatchField::Set(0),
        finder_bonus_sats: PatchField::Set(50_000),
        is_public: PatchField::Set(true),
        reset_round_on_block: PatchField::Set(true),
        max_members: PatchField::Set(10),
    };
    let row1 = update_pplns_group_round_reset_config(&pool, gid, &p1, 100)
        .await
        .expect("p1")
        .expect("present");
    assert_eq!(row1.round_reset_preset.as_deref(), Some("daily"));
    assert_eq!(row1.round_reset_timezone.as_deref(), Some("Europe/Berlin"));
    assert_eq!(row1.round_reset_hour_local, Some(0));
    assert_eq!(row1.finder_bonus_sats.map(|s| s.to_i64()), Some(50_000));
    assert!(row1.is_public);
    assert!(row1.reset_round_on_block);
    assert_eq!(row1.max_members, Some(10));

    // Second patch — Clear preset + finder bonus, leave timezone alone.
    let p2 = RoundResetConfigPatch {
        preset: PatchField::Clear,
        interval_days: PatchField::Clear,
        timezone: PatchField::Untouched,
        hour_local: PatchField::Untouched,
        finder_bonus_sats: PatchField::Clear,
        is_public: PatchField::Untouched,
        reset_round_on_block: PatchField::Untouched,
        max_members: PatchField::Untouched,
    };
    let row2 = update_pplns_group_round_reset_config(&pool, gid, &p2, 200)
        .await
        .expect("p2")
        .expect("present");
    assert!(row2.round_reset_preset.is_none());
    assert!(row2.round_reset_interval_days.is_none());
    assert!(row2.finder_bonus_sats.is_none());
    // Timezone untouched.
    assert_eq!(row2.round_reset_timezone.as_deref(), Some("Europe/Berlin"));
    assert!(row2.is_public);
    // reset_round_on_block untouched by p2 → still true from p1.
    assert!(row2.reset_round_on_block);
    // max_members untouched by p2 → still 10 from p1.
    assert_eq!(row2.max_members, Some(10));

    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn dissolve_is_idempotent() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let gid = Uuid::new_v4();
    let name = format!("diss-{}", gid);
    insert_pplns_group(&pool, gid, &name, &addr("d_creator"), "h", true, false, 1)
        .await
        .expect("g");
    let n1 = update_pplns_group_dissolved(&pool, gid, 100)
        .await
        .expect("d1");
    assert_eq!(n1, 1);
    let n2 = update_pplns_group_dissolved(&pool, gid, 200)
        .await
        .expect("d2");
    assert_eq!(n2, 0); // already dissolved, WHERE clause guards
    let g = find_group(&pool, gid).await.expect("g").expect("present");
    assert_eq!(g.dissolved_at, Some(100));
    assert!(!g.active);

    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
}

// ─── Members ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn insert_member_and_delete_roundtrip() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let gid = Uuid::new_v4();
    let name = format!("mem-{}", gid);
    insert_pplns_group(&pool, gid, &name, &addr("m_creator"), "h", false, false, 1)
        .await
        .expect("g");

    let m = insert_pplns_group_member(&pool, gid, &addr("m_x"), "member", 5)
        .await
        .expect("m");
    assert_eq!(m.address.as_str(), "m_x");
    assert_eq!(m.role, "member");
    assert_eq!(m.joined_at, 5);

    let again = find_pplns_group_member_in_group(&pool, gid, &addr("m_x"))
        .await
        .expect("lookup")
        .expect("present");
    assert_eq!(again.id, m.id);

    let deleted = delete_pplns_group_member(&pool, gid, &addr("m_x"))
        .await
        .expect("del");
    assert_eq!(deleted, 1);
    let gone = find_pplns_group_member_in_group(&pool, gid, &addr("m_x"))
        .await
        .expect("lookup");
    assert!(gone.is_none());

    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn find_all_members_returns_all_groups() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let g1 = Uuid::new_v4();
    let g2 = Uuid::new_v4();
    let n1 = format!("all1-{}", g1);
    let n2 = format!("all2-{}", g2);
    insert_pplns_group(&pool, g1, &n1, &addr("a_c1"), "h", false, false, 1)
        .await
        .expect("g1");
    insert_pplns_group(&pool, g2, &n2, &addr("a_c2"), "h", false, false, 1)
        .await
        .expect("g2");
    let m_addr = format!("all_m_unique_{}", g1);
    insert_pplns_group_member(&pool, g1, &addr(&m_addr), "creator", 2)
        .await
        .expect("m1");

    let all = find_all_pplns_group_members(&pool).await.expect("all");
    assert!(all.iter().any(|m| m.address.as_str() == m_addr));

    delete_pplns_group_members_for_group(&pool, g1).await.ok();
    for id in [g1, g2] {
        sqlx::query("DELETE FROM pplns_group WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .ok();
    }
}

// ─── Invitations ───────────────────────────────────────────────────────────

#[tokio::test]
async fn directed_invitation_lifecycle() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let gid = Uuid::new_v4();
    let n = format!("inv-{}", gid);
    insert_pplns_group(&pool, gid, &n, &addr("inv_c"), "h", false, false, 1)
        .await
        .expect("g");

    let token = format!("tok-d-{}", gid);
    let inv = insert_pplns_group_invitation(
        &pool,
        &token,
        gid,
        Some(&addr("invitee")),
        Some("foo@bar.example"),
        "directed",
        false,
        100,
        100 + 7 * 86_400_000,
    )
    .await
    .expect("ins");
    assert_eq!(inv.status, "pending");
    assert_eq!(inv.invite_type, "directed");
    assert!(!inv.approval_required);

    // Pending lookup
    let pending = find_pplns_group_invitation_pending_directed(&pool, gid, &addr("invitee"))
        .await
        .expect("pending")
        .expect("present");
    assert_eq!(pending.token, token);

    // Mark accepted
    let n = update_pplns_group_invitation_status_by_token(&pool, &token, "accepted", Some(200))
        .await
        .expect("upd");
    assert_eq!(n, 1);

    // Now no longer pending
    let gone = find_pplns_group_invitation_pending_directed(&pool, gid, &addr("invitee"))
        .await
        .expect("lookup");
    assert!(gone.is_none());

    // For-group + for-address list should also exclude the accepted row
    let by_group = find_pplns_group_invitations_pending_for_group_directed(&pool, gid)
        .await
        .expect("g");
    assert!(!by_group.iter().any(|r| r.token == token));
    let by_addr =
        find_pplns_group_invitations_pending_for_address_directed(&pool, &addr("invitee"))
            .await
            .expect("a");
    assert!(!by_addr.iter().any(|r| r.token == token));

    sqlx::query("DELETE FROM pplns_group_invitation WHERE token = $1")
        .bind(&token)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn open_invite_revoke_replaces_atomically() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let gid = Uuid::new_v4();
    let n = format!("open-{}", gid);
    insert_pplns_group(&pool, gid, &n, &addr("open_c"), "h", false, false, 1)
        .await
        .expect("g");

    // Two open invites in succession — second should leave only itself active.
    let t1 = format!("open-1-{}", gid);
    insert_pplns_group_invitation(&pool, &t1, gid, None, None, "open", false, 100, 1_000_000)
        .await
        .expect("o1");
    let revoked = revoke_pending_open_invites_for_group(&pool, gid, 150)
        .await
        .expect("rev");
    assert_eq!(revoked, 1);
    let t2 = format!("open-2-{}", gid);
    insert_pplns_group_invitation(&pool, &t2, gid, None, None, "open", true, 200, 2_000_000)
        .await
        .expect("o2");

    let active = find_pplns_group_active_open_invite_for_group(&pool, gid)
        .await
        .expect("active")
        .expect("present");
    assert_eq!(active.token, t2);
    assert!(active.approval_required);

    sqlx::query("DELETE FROM pplns_group_invitation WHERE \"groupId\" = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn expire_invitations_only_flips_past_due() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let gid = Uuid::new_v4();
    let n = format!("exp-i-{}", gid);
    insert_pplns_group(&pool, gid, &n, &addr("ei_c"), "h", false, false, 1)
        .await
        .expect("g");

    let past = format!("past-{}", gid);
    let fresh = format!("fresh-{}", gid);
    insert_pplns_group_invitation(
        &pool,
        &past,
        gid,
        Some(&addr("past_target")),
        Some("p@x"),
        "directed",
        false,
        1,
        100,
    )
    .await
    .expect("p");
    insert_pplns_group_invitation(
        &pool,
        &fresh,
        gid,
        Some(&addr("fresh_target")),
        Some("f@x"),
        "directed",
        false,
        1,
        10_000_000_000_000,
    )
    .await
    .expect("f");

    let flipped = expire_pending_pplns_group_invitations(&pool, 1_000)
        .await
        .expect("exp");
    assert!(flipped >= 1); // at least our `past` row; other test rows may share the sweep
    let past_now = find_pplns_group_invitations_pending_for_group_directed(&pool, gid)
        .await
        .expect("by-g");
    // The `past` row is no longer pending.
    assert!(!past_now.iter().any(|r| r.token == past));
    // The `fresh` row still is.
    assert!(past_now.iter().any(|r| r.token == fresh));

    sqlx::query("DELETE FROM pplns_group_invitation WHERE \"groupId\" = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn delete_invitation_by_token_removes_row() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let gid = Uuid::new_v4();
    let n = format!("delinv-{}", gid);
    insert_pplns_group(&pool, gid, &n, &addr("del_c"), "h", false, false, 1)
        .await
        .expect("g");
    let token = format!("rm-{}", gid);
    insert_pplns_group_invitation(
        &pool,
        &token,
        gid,
        Some(&addr("rm_target")),
        Some("x@x"),
        "directed",
        false,
        1,
        2,
    )
    .await
    .expect("ins");
    let n = delete_pplns_group_invitation_by_token(&pool, &token)
        .await
        .expect("del");
    assert_eq!(n, 1);

    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
}

// ─── Join requests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn join_request_lifecycle() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let gid = Uuid::new_v4();
    let n = format!("jr-{}", gid);
    insert_pplns_group(&pool, gid, &n, &addr("jr_c"), "h", false, true, 1)
        .await
        .expect("g");

    let req_addr = addr(&format!("jr_addr_{}", gid));
    let req = insert_pplns_group_join_request(&pool, gid, &req_addr, "join@x", Some("hi"), 100)
        .await
        .expect("ins");
    assert_eq!(req.status, "pending");
    assert_eq!(req.message.as_deref(), Some("hi"));

    let count = count_pplns_group_join_requests_pending_for_address(&pool, &req_addr)
        .await
        .expect("count");
    assert_eq!(count, 1);

    let by_addr = list_pplns_group_join_requests_pending_for_address(&pool, &req_addr)
        .await
        .expect("by_addr");
    assert_eq!(by_addr.len(), 1);

    let by_group_pending = list_pplns_group_join_requests_for_group(&pool, gid, false)
        .await
        .expect("by_g_p");
    assert_eq!(by_group_pending.len(), 1);

    update_pplns_group_join_request_decision(&pool, req.id, "rejected", 200, "admin_hash")
        .await
        .expect("dec");

    let pending = find_pplns_group_join_request_pending_in_group(&pool, req.id, gid)
        .await
        .expect("look");
    assert!(pending.is_none());

    let by_group_all = list_pplns_group_join_requests_for_group(&pool, gid, true)
        .await
        .expect("by_g_a");
    assert_eq!(by_group_all.len(), 1);
    assert_eq!(by_group_all[0].status, "rejected");

    let recent = find_pplns_group_join_request_most_recent_rejected(&pool, gid, &req_addr)
        .await
        .expect("rec")
        .expect("present");
    assert_eq!(recent.id, req.id);
    assert_eq!(recent.decided_at, Some(200));

    sqlx::query("DELETE FROM pplns_group_join_request WHERE \"groupId\" = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn expire_join_requests_flips_old_pending() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let gid = Uuid::new_v4();
    let n = format!("ejr-{}", gid);
    insert_pplns_group(&pool, gid, &n, &addr("ejr_c"), "h", false, true, 1)
        .await
        .expect("g");
    let old =
        insert_pplns_group_join_request(&pool, gid, &addr(&format!("old_{}", gid)), "o@x", None, 1)
            .await
            .expect("o");
    let fresh = insert_pplns_group_join_request(
        &pool,
        gid,
        &addr(&format!("fresh_{}", gid)),
        "f@x",
        None,
        10_000_000_000_000,
    )
    .await
    .expect("f");

    // `expire_pending_…` is GLOBAL (`WHERE status='pending' AND createdAt < cutoff`,
    // no group filter — it's a cron). On the shared test DB it would also
    // sweep pending rows other tests created concurrently. Keep the cutoff
    // just above this test's own `old` row (createdAt=1) so its blast radius
    // is exactly that row — `join_request_lifecycle` uses createdAt=100 and
    // must stay pending. Don't raise this without making other tests' pending
    // rows use createdAt ≥ the new cutoff.
    expire_pending_pplns_group_join_requests(&pool, 2)
        .await
        .expect("exp");
    let pending = list_pplns_group_join_requests_for_group(&pool, gid, false)
        .await
        .expect("list");
    assert!(!pending.iter().any(|r| r.id == old.id));
    assert!(pending.iter().any(|r| r.id == fresh.id));

    sqlx::query("DELETE FROM pplns_group_join_request WHERE \"groupId\" = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn update_active_ignores_dissolved_group() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let gid = Uuid::new_v4();
    let name = format!("diss-active-{}", gid);
    insert_pplns_group(&pool, gid, &name, &addr("da_creator"), "h", false, false, 1)
        .await
        .expect("g");
    update_pplns_group_dissolved(&pool, gid, 50)
        .await
        .expect("dissolve");

    // Attempting to flip active on a dissolved group must affect 0 rows.
    let n = update_pplns_group_active(&pool, gid, true, 99)
        .await
        .expect("update");
    assert_eq!(n, 0, "dissolved group must not be touched by update_active");

    let g = find_group(&pool, gid).await.expect("f").expect("present");
    assert!(!g.active, "active must still be false");
    assert_eq!(g.dissolved_at, Some(50), "dissolved_at must be unchanged");

    sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(gid)
        .execute(&pool)
        .await
        .ok();
}
