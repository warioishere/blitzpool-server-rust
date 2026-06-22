// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Integration tests for `bp_group_mgmt_engine::GroupService`.
//!
//! Each test seeds + cleans up its own group/member rows against the
//! local docker-PG. The service is wired with a per-test
//! [`TestHooks`] stub so the kick-inactivity flow + dissolve-cleanup +
//! round-reset-applyConfig callbacks can be inspected without standing
//! up the full Redis stack.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bp_common::{AddressId, Sats};
use bp_db::PatchField;
use bp_group_mgmt::group::RoundResetPreset;
use bp_group_mgmt_engine::{
    GroupService, GroupServiceError, GroupServiceHooks, UpdateRoundResetSettings,
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

/// Captures + scripts hook invocations for tests.
#[derive(Default, Debug)]
struct TestHooksState {
    last_active: Option<i64>,
    member_removed: Vec<(Uuid, String, Vec<String>)>,
    group_dissolved: Vec<Uuid>,
    round_reset_applied: Vec<Uuid>,
    min_payout: i64,
}

#[derive(Clone, Default, Debug)]
struct TestHooks(Arc<Mutex<TestHooksState>>);

impl TestHooks {
    fn new(min_payout: i64, last_active: Option<i64>) -> Self {
        Self(Arc::new(Mutex::new(TestHooksState {
            last_active,
            min_payout,
            ..Default::default()
        })))
    }
    fn snapshot(&self) -> TestHooksState {
        let g = self.0.lock().unwrap();
        TestHooksState {
            last_active: g.last_active,
            member_removed: g.member_removed.clone(),
            group_dissolved: g.group_dissolved.clone(),
            round_reset_applied: g.round_reset_applied.clone(),
            min_payout: g.min_payout,
        }
    }
}

#[async_trait]
impl GroupServiceHooks for TestHooks {
    async fn last_active_for_member(&self, _group_id: Uuid, _address: &AddressId) -> Option<i64> {
        self.0.lock().unwrap().last_active
    }
    fn min_payout_sats(&self) -> Sats {
        Sats(self.0.lock().unwrap().min_payout)
    }
    async fn on_member_removed(&self, group_id: Uuid, kicked: &AddressId, remaining: &[AddressId]) {
        self.0.lock().unwrap().member_removed.push((
            group_id,
            kicked.as_str().to_string(),
            remaining.iter().map(|a| a.as_str().to_string()).collect(),
        ));
    }
    async fn on_group_dissolved(&self, group_id: Uuid) {
        self.0.lock().unwrap().group_dissolved.push(group_id);
    }
    async fn apply_round_reset_config(&self, group: &bp_db::PplnsGroupRow) {
        self.0.lock().unwrap().round_reset_applied.push(group.id);
    }
}

async fn cleanup_group(pool: &PgPool, group_id: Uuid) {
    let _ = sqlx::query("DELETE FROM pplns_group_member WHERE \"groupId\" = $1")
        .bind(group_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM pplns_group WHERE id = $1")
        .bind(group_id)
        .execute(pool)
        .await;
}

// ─── createGroup ───────────────────────────────────────────────────────────

#[tokio::test]
async fn create_group_happy_path_returns_token_and_seeds_creator() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let hooks = TestHooks::new(1000, None);
    let svc = GroupService::new(pool.clone(), Arc::new(hooks.clone()), 14);
    let name = format!("test-create-{}", Uuid::new_v4());
    let creator = format!("bc1qcreator{}", Uuid::new_v4().simple());
    let result = svc.create_group(&name, &creator).await.expect("create");
    assert!(result.admin_token.starts_with("GRP-"));
    assert_eq!(result.group.name, name);
    assert!(!result.group.active);
    let members = svc.list_members(result.group.id).await.expect("members");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].role, "creator");
    assert_eq!(members[0].address.as_str(), creator.to_lowercase());

    cleanup_group(&pool, result.group.id).await;
}

#[tokio::test]
async fn create_group_rejects_invalid_name() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let svc = GroupService::new(pool.clone(), Arc::new(TestHooks::new(1000, None)), 14);
    let err = svc
        .create_group("ab", "bc1qx")
        .await
        .expect_err("too short");
    assert!(matches!(err, GroupServiceError::InvalidName));
    let bad_ctrl = "name\nwith\nnewlines";
    let err2 = svc
        .create_group(bad_ctrl, "bc1qx")
        .await
        .expect_err("ctrl chars");
    assert!(matches!(err2, GroupServiceError::InvalidName));
}

#[tokio::test]
async fn create_group_rejects_duplicate_name() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let svc = GroupService::new(pool.clone(), Arc::new(TestHooks::new(1000, None)), 14);
    let name = format!("dup-{}", Uuid::new_v4());
    let first = svc
        .create_group(&name, &format!("bc1qfirst{}", Uuid::new_v4().simple()))
        .await
        .expect("first");
    let err = svc
        .create_group(&name, &format!("bc1qsecond{}", Uuid::new_v4().simple()))
        .await
        .expect_err("dup");
    assert!(matches!(err, GroupServiceError::NameTaken));
    cleanup_group(&pool, first.group.id).await;
}

#[tokio::test]
async fn create_group_rejects_address_already_in_group() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let svc = GroupService::new(pool.clone(), Arc::new(TestHooks::new(1000, None)), 14);
    let shared_addr = format!("bc1qshared{}", Uuid::new_v4().simple());
    let g1 = svc
        .create_group(&format!("a-{}", Uuid::new_v4()), &shared_addr)
        .await
        .expect("g1");
    let err = svc
        .create_group(&format!("b-{}", Uuid::new_v4()), &shared_addr)
        .await
        .expect_err("dup-member");
    assert!(matches!(err, GroupServiceError::AddressInGroup));
    cleanup_group(&pool, g1.group.id).await;
}

// ─── addMember ────────────────────────────────────────────────────────────

#[tokio::test]
async fn add_member_flips_active_when_threshold_met() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let svc = GroupService::new(pool.clone(), Arc::new(TestHooks::new(1000, None)), 14);
    let creator = format!("bc1qcr{}", Uuid::new_v4().simple());
    let new_member = format!("bc1qnew{}", Uuid::new_v4().simple());
    let g = svc
        .create_group(&format!("a-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    assert!(!g.group.active);
    svc.add_member(g.group.id, &new_member, Some(&g.admin_token))
        .await
        .expect("add");
    let group = svc
        .get_group(g.group.id)
        .await
        .expect("get")
        .expect("present");
    assert!(group.active);
    cleanup_group(&pool, g.group.id).await;
}

#[tokio::test]
async fn add_member_rejects_address_in_other_group() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let svc = GroupService::new(pool.clone(), Arc::new(TestHooks::new(1000, None)), 14);
    let g1_creator = format!("bc1qg1cr{}", Uuid::new_v4().simple());
    let g2_creator = format!("bc1qg2cr{}", Uuid::new_v4().simple());
    let shared = format!("bc1qshared{}", Uuid::new_v4().simple());
    let g1 = svc
        .create_group(&format!("g1-{}", Uuid::new_v4()), &g1_creator)
        .await
        .expect("g1");
    let g2 = svc
        .create_group(&format!("g2-{}", Uuid::new_v4()), &g2_creator)
        .await
        .expect("g2");
    svc.add_member(g1.group.id, &shared, Some(&g1.admin_token))
        .await
        .expect("g1+m");
    let err = svc
        .add_member(g2.group.id, &shared, Some(&g2.admin_token))
        .await
        .expect_err("dup-cross");
    assert!(matches!(err, GroupServiceError::AddressInGroup));
    cleanup_group(&pool, g1.group.id).await;
    cleanup_group(&pool, g2.group.id).await;
}

// ─── requireAdminToken ────────────────────────────────────────────────────

#[tokio::test]
async fn require_admin_token_rejects_invalid() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let svc = GroupService::new(pool.clone(), Arc::new(TestHooks::new(1000, None)), 14);
    let g = svc
        .create_group(
            &format!("auth-{}", Uuid::new_v4()),
            &format!("bc1qauth{}", Uuid::new_v4().simple()),
        )
        .await
        .expect("g");

    assert!(matches!(
        svc.require_admin_token(g.group.id, None).await.unwrap_err(),
        GroupServiceError::MissingToken
    ));
    assert!(matches!(
        svc.require_admin_token(g.group.id, Some("bogus"))
            .await
            .unwrap_err(),
        GroupServiceError::InvalidToken
    ));
    let row = svc
        .require_admin_token(g.group.id, Some(&g.admin_token))
        .await
        .expect("valid");
    assert_eq!(row.id, g.group.id);
    cleanup_group(&pool, g.group.id).await;
}

// ─── removeMember ────────────────────────────────────────────────────────

#[tokio::test]
async fn remove_member_creator_rejected() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let svc = GroupService::new(pool.clone(), Arc::new(TestHooks::new(1000, None)), 14);
    let creator = format!("bc1qrmc{}", Uuid::new_v4().simple());
    let g = svc
        .create_group(&format!("rm-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    let err = svc
        .remove_member(g.group.id, &creator, Some(&g.admin_token))
        .await
        .expect_err("creator");
    assert!(matches!(err, GroupServiceError::CreatorCannotBeRemoved));
    cleanup_group(&pool, g.group.id).await;
}

#[tokio::test]
async fn remove_member_inactivity_guard_then_kick_succeeds() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    // First with last_active = now (still active): expect StillActive
    let hooks_active = TestHooks::new(1000, Some(now_ms()));
    let svc_active = GroupService::new(pool.clone(), Arc::new(hooks_active.clone()), 14);
    let creator = format!("bc1qrmkc{}", Uuid::new_v4().simple());
    let target = format!("bc1qrmkt{}", Uuid::new_v4().simple());
    let g = svc_active
        .create_group(&format!("rmk-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    svc_active
        .add_member(g.group.id, &target, Some(&g.admin_token))
        .await
        .expect("add");
    let err = svc_active
        .remove_member(g.group.id, &target, Some(&g.admin_token))
        .await
        .expect_err("still active");
    assert!(matches!(err, GroupServiceError::MemberStillActive { .. }));

    // Now with last_active 30 days ago: kick succeeds.
    let hooks_old = TestHooks::new(1000, Some(now_ms() - 30 * 86_400_000));
    let svc_old = GroupService::new(pool.clone(), Arc::new(hooks_old.clone()), 14);
    svc_old
        .remove_member(g.group.id, &target, Some(&g.admin_token))
        .await
        .expect("kick");
    let members = svc_old.list_members(g.group.id).await.expect("list");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].role, "creator");
    // Hook callback fired
    let snap = hooks_old.snapshot();
    assert_eq!(snap.member_removed.len(), 1);
    assert_eq!(snap.member_removed[0].0, g.group.id);

    cleanup_group(&pool, g.group.id).await;
}

#[tokio::test]
async fn remove_member_flips_active_below_threshold() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    // last_active = 30 days ago so the kick-inactivity guard passes.
    let hooks = TestHooks::new(1000, Some(now_ms() - 30 * 86_400_000));
    let svc = GroupService::new(pool.clone(), Arc::new(hooks), 14);
    let creator = format!("bc1qrmact_c{}", Uuid::new_v4().simple());
    let member = format!("bc1qrmact_m{}", Uuid::new_v4().simple());
    let g = svc
        .create_group(&format!("rmact-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    svc.add_member(g.group.id, &member, Some(&g.admin_token))
        .await
        .expect("add");
    // After add: 2 members → active.
    let before = svc.get_group(g.group.id).await.expect("get").expect("row");
    assert!(before.active);

    svc.remove_member(g.group.id, &member, Some(&g.admin_token))
        .await
        .expect("remove");
    // After remove: 1 member (below threshold) → inactive.
    let after = svc.get_group(g.group.id).await.expect("get").expect("row");
    assert!(!after.active);

    cleanup_group(&pool, g.group.id).await;
}

// ─── transferCreator ─────────────────────────────────────────────────────

#[tokio::test]
async fn transfer_creator_rotates_role_and_token() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let svc = GroupService::new(pool.clone(), Arc::new(TestHooks::new(1000, None)), 14);
    let old_creator = format!("bc1qtcold{}", Uuid::new_v4().simple());
    let new_creator = format!("bc1qtcnew{}", Uuid::new_v4().simple());
    let g = svc
        .create_group(&format!("tc-{}", Uuid::new_v4()), &old_creator)
        .await
        .expect("g");
    svc.add_member(g.group.id, &new_creator, Some(&g.admin_token))
        .await
        .expect("add");

    let rotated = svc
        .transfer_creator(g.group.id, &new_creator, Some(&g.admin_token))
        .await
        .expect("transfer");
    assert_ne!(rotated.admin_token, g.admin_token);
    assert_eq!(
        rotated.group.creator_address.as_str(),
        new_creator.to_lowercase()
    );
    // Old token now rejected
    assert!(matches!(
        svc.require_admin_token(g.group.id, Some(&g.admin_token))
            .await
            .unwrap_err(),
        GroupServiceError::InvalidToken
    ));
    // New token works
    svc.require_admin_token(g.group.id, Some(&rotated.admin_token))
        .await
        .expect("new ok");
    // Role swap
    let members = svc.list_members(g.group.id).await.expect("list");
    let old_role = members
        .iter()
        .find(|m| m.address.as_str() == old_creator.to_lowercase())
        .expect("old in list")
        .role
        .as_str();
    let new_role = members
        .iter()
        .find(|m| m.address.as_str() == new_creator.to_lowercase())
        .expect("new in list")
        .role
        .as_str();
    assert_eq!(old_role, "member");
    assert_eq!(new_role, "creator");
    cleanup_group(&pool, g.group.id).await;
}

#[tokio::test]
async fn transfer_creator_rejects_non_member() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let svc = GroupService::new(pool.clone(), Arc::new(TestHooks::new(1000, None)), 14);
    let g = svc
        .create_group(
            &format!("tcnm-{}", Uuid::new_v4()),
            &format!("bc1qtcnm{}", Uuid::new_v4().simple()),
        )
        .await
        .expect("g");
    let outsider = format!("bc1qoutsider{}", Uuid::new_v4().simple());
    let err = svc
        .transfer_creator(g.group.id, &outsider, Some(&g.admin_token))
        .await
        .expect_err("not member");
    assert!(matches!(err, GroupServiceError::NotMember));
    cleanup_group(&pool, g.group.id).await;
}

// ─── updateRoundResetConfig ──────────────────────────────────────────────

#[tokio::test]
async fn update_round_reset_config_applies_and_fires_hook() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let hooks = TestHooks::new(1000, None);
    let svc = GroupService::new(pool.clone(), Arc::new(hooks.clone()), 14);
    let g = svc
        .create_group(
            &format!("rr-{}", Uuid::new_v4()),
            &format!("bc1qrr{}", Uuid::new_v4().simple()),
        )
        .await
        .expect("g");

    let row = svc
        .update_round_reset_config(
            g.group.id,
            UpdateRoundResetSettings {
                preset: PatchField::Set(RoundResetPreset::Weekly),
                interval_days: PatchField::Untouched,
                timezone: PatchField::Set("Europe/Berlin".into()),
                finder_bonus_sats: PatchField::Set(Sats(50_000)),
                is_public: PatchField::Set(true),
                reset_round_on_block: PatchField::Untouched,
                max_members: PatchField::Untouched,
            },
            Some(&g.admin_token),
        )
        .await
        .expect("update");
    assert_eq!(row.round_reset_preset.as_deref(), Some("weekly"));
    assert_eq!(row.round_reset_timezone.as_deref(), Some("Europe/Berlin"));
    assert_eq!(row.finder_bonus_sats.map(|s| s.to_i64()), Some(50_000));
    assert!(row.is_public);
    let snap = hooks.snapshot();
    assert_eq!(snap.round_reset_applied, vec![g.group.id]);
    cleanup_group(&pool, g.group.id).await;
}

#[tokio::test]
async fn update_round_reset_rejects_invalid_timezone() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let svc = GroupService::new(pool.clone(), Arc::new(TestHooks::new(1000, None)), 14);
    let g = svc
        .create_group(
            &format!("rrbad-{}", Uuid::new_v4()),
            &format!("bc1qrrbad{}", Uuid::new_v4().simple()),
        )
        .await
        .expect("g");
    let err = svc
        .update_round_reset_config(
            g.group.id,
            UpdateRoundResetSettings {
                preset: PatchField::Set(RoundResetPreset::Daily),
                timezone: PatchField::Set("Mars/Sample".into()),
                ..Default::default()
            },
            Some(&g.admin_token),
        )
        .await
        .expect_err("bad tz");
    assert!(matches!(err, GroupServiceError::InvalidTimezone));
    cleanup_group(&pool, g.group.id).await;
}

#[tokio::test]
async fn update_round_reset_rejects_sub_min_payout_bonus() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let svc = GroupService::new(pool.clone(), Arc::new(TestHooks::new(10_000, None)), 14);
    let g = svc
        .create_group(
            &format!("rrlow-{}", Uuid::new_v4()),
            &format!("bc1qrrlow{}", Uuid::new_v4().simple()),
        )
        .await
        .expect("g");
    let err = svc
        .update_round_reset_config(
            g.group.id,
            UpdateRoundResetSettings {
                finder_bonus_sats: PatchField::Set(Sats(100)),
                ..Default::default()
            },
            Some(&g.admin_token),
        )
        .await
        .expect_err("low bonus");
    assert!(matches!(err, GroupServiceError::InvalidBonus));
    cleanup_group(&pool, g.group.id).await;
}

// ─── dissolveGroup ───────────────────────────────────────────────────────

#[tokio::test]
async fn dissolve_group_removes_members_and_marks_row() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let hooks = TestHooks::new(1000, None);
    let svc = GroupService::new(pool.clone(), Arc::new(hooks.clone()), 14);
    let g = svc
        .create_group(
            &format!("diss-{}", Uuid::new_v4()),
            &format!("bc1qdiss{}", Uuid::new_v4().simple()),
        )
        .await
        .expect("g");
    svc.add_member(
        g.group.id,
        &format!("bc1qdissm{}", Uuid::new_v4().simple()),
        Some(&g.admin_token),
    )
    .await
    .expect("add");

    svc.dissolve_group(g.group.id, Some(&g.admin_token))
        .await
        .expect("diss");
    let row = bp_db::find_group(&pool, g.group.id)
        .await
        .expect("find")
        .expect("present");
    assert!(row.dissolved_at.is_some());
    assert!(!row.active);
    let members = svc.list_members(g.group.id).await.expect("list");
    assert!(members.is_empty());
    let snap = hooks.snapshot();
    assert_eq!(snap.group_dissolved, vec![g.group.id]);
    cleanup_group(&pool, g.group.id).await;
}

// ─── address cache rebuild ───────────────────────────────────────────────

#[tokio::test]
async fn address_cache_reflects_membership_changes() {
    let pool = match connect_or_skip().await {
        Some(p) => p,
        None => return,
    };
    let svc = GroupService::new(pool.clone(), Arc::new(TestHooks::new(1000, None)), 14);
    let creator = format!("bc1qcc{}", Uuid::new_v4().simple());
    let cache_addr = AddressId::new(creator.to_lowercase()).unwrap();
    let g = svc
        .create_group(&format!("cc-{}", Uuid::new_v4()), &creator)
        .await
        .expect("g");
    let entry = svc
        .get_group_for_address(&cache_addr)
        .await
        .expect("cached");
    assert_eq!(entry.group_id, g.group.id);
    assert!(!entry.active); // single member

    // Add a member → active flips
    let m = format!("bc1qccm{}", Uuid::new_v4().simple());
    svc.add_member(g.group.id, &m, Some(&g.admin_token))
        .await
        .expect("add");
    let entry2 = svc
        .get_group_for_address(&cache_addr)
        .await
        .expect("cached2");
    assert!(entry2.active);

    // Dissolve → cache empty for this address
    svc.dissolve_group(g.group.id, Some(&g.admin_token))
        .await
        .expect("dis");
    assert!(svc.get_group_for_address(&cache_addr).await.is_none());
    cleanup_group(&pool, g.group.id).await;
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
