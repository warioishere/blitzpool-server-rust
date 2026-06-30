// SPDX-License-Identifier: AGPL-3.0-or-later

//! `GroupService` — group lifecycle, membership, admin-token auth.
//!
//! Pure logic + token generation is delegated to `bp-group-mgmt`;
//! DB writes to `bp-db`; Redis cleanup + cron scheduling to the
//! [`GroupServiceHooks`] trait. The service owns one [`AddressCache`]
//! (rebuilt on every membership change).

use std::sync::Arc;

use bp_common::{AddressId, Sats};
use bp_db::{PatchField, PplnsGroupMemberRow, PplnsGroupRow, RoundResetConfigPatch};
use bp_group_mgmt::{
    constants::{MIN_MEMBERS_ACTIVE, MS_PER_DAY},
    group::{is_active, GroupName, MemberRole, PayoutMode, RoundResetConfig, RoundResetPreset},
    token::{AdminToken, TokenHash},
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::cache::AddressCache;
use crate::error::GroupServiceError;
use crate::hooks::GroupServiceHooks;
use crate::util::{normalize_address, now_ms, PatchFieldExt};

/// Returned by [`GroupService::create_group`]. The plaintext
/// `admin_token` is the only chance the creator gets to see the
/// secret — afterwards only the SHA-256 hash exists on the row.
#[derive(Debug)]
pub struct GroupCreateResult {
    pub group: PplnsGroupRow,
    pub admin_token: String,
}

/// Returned by [`GroupService::transfer_creator`]. Same one-shot
/// secret as `create_group`.
#[derive(Debug)]
pub struct CreatorTransferResult {
    pub group: PplnsGroupRow,
    pub admin_token: String,
}

/// PATCH payload for [`GroupService::update_round_reset_config`].
/// Each field can be `Untouched` / `Clear` / `Set`.
#[derive(Debug, Default, Clone)]
pub struct UpdateRoundResetSettings {
    pub preset: PatchField<RoundResetPreset>,
    pub interval_days: PatchField<u32>,
    pub timezone: PatchField<String>,
    pub finder_bonus_sats: PatchField<Sats>,
    pub is_public: PatchField<bool>,
    pub reset_round_on_block: PatchField<bool>,
    pub max_members: PatchField<i32>,
}

/// Top-level group-management service.
#[derive(Clone)]
pub struct GroupService<H: GroupServiceHooks> {
    pool: PgPool,
    hooks: Arc<H>,
    address_cache: AddressCache,
    kick_inactivity_days: u32,
    /// Cross-mode collision reader. When wired, `create_group` and
    /// `add_member_without_admin` refuse addresses already in a
    /// Blockparty. Deployments without Blockparty leave it unset
    /// and the check short-circuits. `OnceLock` so the reader can be
    /// attached after construction via `&self` (the chicken-and-egg
    /// with the Blockparty service rules out passing it to `new`).
    blockparty_reader: Arc<std::sync::OnceLock<Arc<dyn crate::hooks::BlockpartyMembershipReader>>>,
    /// Optional cross-process cache-invalidation notifier. Attached after
    /// construction (same `OnceLock` rationale as `blockparty_reader`). When
    /// set, every membership mutation publishes a `"group"` invalidation so a
    /// separate Stratum Front rebuilds its routing cache. Unset where no
    /// cross-process notification is needed (e.g. tests).
    change_notifier: Arc<std::sync::OnceLock<Arc<dyn crate::hooks::MembershipChangeNotifier>>>,
}

impl<H: GroupServiceHooks> GroupService<H> {
    /// Wire a fresh service. The caller should call [`Self::rebuild_cache`]
    /// once at startup so the in-memory cache is hot before the stratum
    /// layer starts serving share submits.
    pub fn new(pool: PgPool, hooks: Arc<H>, kick_inactivity_days: u32) -> Self {
        Self {
            pool,
            hooks,
            address_cache: AddressCache::new(),
            kick_inactivity_days,
            blockparty_reader: Arc::new(std::sync::OnceLock::new()),
            change_notifier: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Attach the cross-mode Blockparty-membership reader. Idempotent
    /// — subsequent calls are silently ignored (set-once). Called from
    /// the binary after `blockparty_service::spawn` so the symmetric
    /// PplnsGroup ↔ Blockparty membership-collision check engages.
    pub fn set_blockparty_reader(&self, reader: Arc<dyn crate::hooks::BlockpartyMembershipReader>) {
        let _ = self.blockparty_reader.set(reader);
    }

    /// Attach the cross-process cache-invalidation notifier (idempotent, set-
    /// once, like `set_blockparty_reader`). Wire it on the process that hosts
    /// the API writers so a membership change reaches a separate Front.
    pub fn set_change_notifier(&self, notifier: Arc<dyn crate::hooks::MembershipChangeNotifier>) {
        let _ = self.change_notifier.set(notifier);
    }

    /// Rebuild the local cache after a membership change, then fire the
    /// cross-process invalidation (best-effort). `"group"` matches
    /// `bp_share_stream::cache_kind::GROUP`. The boot warm-up
    /// ([`Self::rebuild_cache`]) deliberately does NOT notify.
    async fn rebuild_and_notify(&self) -> Result<(), GroupServiceError> {
        self.address_cache.rebuild(&self.pool).await?;
        if let Some(n) = self.change_notifier.get() {
            n.membership_changed("group").await;
        }
        Ok(())
    }

    async fn assert_not_in_blockparty(&self, address: &AddressId) -> Result<(), GroupServiceError> {
        if let Some(reader) = self.blockparty_reader.get() {
            if reader.is_member(address).await {
                return Err(GroupServiceError::AddressInBlockparty);
            }
        }
        Ok(())
    }

    /// Expose the underlying cache for sharing with other services
    /// (e.g. invitations / join-requests don't need their own copy).
    pub fn address_cache(&self) -> AddressCache {
        self.address_cache.clone()
    }

    /// Replay all member rows into the in-memory address cache.
    pub async fn rebuild_cache(&self) -> Result<(), GroupServiceError> {
        self.address_cache.rebuild(&self.pool).await
    }

    // ── Token helpers ─────────────────────────────────────────────

    /// Verify `provided_token` against the group's stored hash and
    /// return the row. Errors out for missing-token / dissolved /
    /// invalid-token / not-found.
    pub async fn require_admin_token(
        &self,
        group_id: Uuid,
        provided_token: Option<&str>,
    ) -> Result<PplnsGroupRow, GroupServiceError> {
        let token = provided_token.ok_or(GroupServiceError::MissingToken)?;
        let group = bp_db::find_group(&self.pool, group_id).await?;
        let group = group.ok_or(GroupServiceError::NotFound)?;
        if group.dissolved_at.is_some() {
            return Err(GroupServiceError::NotFound);
        }
        let stored = TokenHash::from_hex(group.admin_token_hash.clone());
        if !stored.verifies(token) {
            return Err(GroupServiceError::InvalidToken);
        }
        Ok(group)
    }

    // ── Lookup ────────────────────────────────────────────────────

    /// Cache-only lookup — `None` if the address isn't in any active
    /// group. Stratum + PPLNS engines call this on every share.
    pub async fn get_group_for_address(
        &self,
        address: &AddressId,
    ) -> Option<crate::cache::GroupCacheEntry> {
        self.address_cache.get(address).await
    }

    /// Single-row fetch by UUID. Returns `None` if not found OR if
    /// dissolved — callers see "no group" either way.
    pub async fn get_group(
        &self,
        group_id: Uuid,
    ) -> Result<Option<PplnsGroupRow>, GroupServiceError> {
        let row = bp_db::find_group(&self.pool, group_id).await?;
        Ok(row.filter(|g| g.dissolved_at.is_none()))
    }

    /// All non-dissolved groups.
    pub async fn list_groups(&self) -> Result<Vec<PplnsGroupRow>, GroupServiceError> {
        Ok(bp_db::list_active_pplns_groups(&self.pool).await?)
    }

    /// All members of a group, ordered `joined_at` ASC (creator first
    /// in practice).
    pub async fn list_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<PplnsGroupMemberRow>, GroupServiceError> {
        Ok(bp_db::find_pplns_group_members_for_group(&self.pool, group_id).await?)
    }

    // ── Lifecycle ─────────────────────────────────────────────────

    /// Create a fresh group. Validates the name shape + the creator
    /// address shape + checks neither name nor address is already in
    /// use. Returns the inserted row plus the **plaintext** admin
    /// token (shown to the creator exactly once).
    pub async fn create_group(
        &self,
        name: &str,
        creator_address: &str,
    ) -> Result<GroupCreateResult, GroupServiceError> {
        // Existing callers default to the classic PROP-per-round mode.
        self.create_group_with_mode(name, creator_address, PayoutMode::Prop)
            .await
    }

    /// Create a fresh group with an explicit [`PayoutMode`]. The mode is chosen
    /// **once at creation and is immutable** — there is no edit path for it (a
    /// live PROP↔Window migration is intentionally unsupported). `Prop` is the
    /// default and what [`Self::create_group`] uses.
    pub async fn create_group_with_mode(
        &self,
        name: &str,
        creator_address: &str,
        mode: PayoutMode,
    ) -> Result<GroupCreateResult, GroupServiceError> {
        let validated_name = GroupName::new(name).map_err(|_| GroupServiceError::InvalidName)?;
        let normalized_address = normalize_address(creator_address)?;

        if bp_db::find_pplns_group_by_name_not_dissolved(&self.pool, validated_name.as_str())
            .await?
            .is_some()
        {
            return Err(GroupServiceError::NameTaken);
        }
        if bp_db::find_group_member_by_address(&self.pool, &normalized_address)
            .await?
            .is_some()
        {
            return Err(GroupServiceError::AddressInGroup);
        }
        self.assert_not_in_blockparty(&normalized_address).await?;

        let admin = AdminToken::generate()?;
        let admin_hash = admin.hash();
        let now = now_ms();
        let id = Uuid::new_v4();

        let mut tx = self.pool.begin().await.map_err(bp_db::DbError::from)?;
        let group = bp_db::insert_pplns_group(
            &mut *tx,
            id,
            validated_name.as_str(),
            &normalized_address,
            admin_hash.as_str(),
            // The creator is added as the sole member just below, so the group
            // starts active whenever a single member already meets the floor
            // (MIN_MEMBERS_ACTIVE == 1) — it can mine immediately.
            /* active = */ is_active(1),
            /* is_public = */ false,
            mode.as_str(),
            now,
        )
        .await?;
        bp_db::insert_pplns_group_member(
            &mut *tx,
            id,
            &normalized_address,
            MemberRole::Creator.as_str(),
            now,
        )
        .await?;
        tx.commit().await.map_err(bp_db::DbError::from)?;

        self.rebuild_and_notify().await?;
        Ok(GroupCreateResult {
            group,
            admin_token: admin.into_inner(),
        })
    }

    /// Admin path to add a new member: verifies the token then
    /// delegates to [`Self::add_member_without_admin`].
    pub async fn add_member(
        &self,
        group_id: Uuid,
        address: &str,
        token: Option<&str>,
    ) -> Result<PplnsGroupMemberRow, GroupServiceError> {
        self.require_admin_token(group_id, token).await?;
        self.add_member_without_admin(group_id, address).await
    }

    /// Add a member bypassing the admin-token check. Used by the
    /// invitation accept + open-invite accept + join-request approve
    /// flows once they've established authorization through a
    /// different mechanism.
    pub async fn add_member_without_admin(
        &self,
        group_id: Uuid,
        address: &str,
    ) -> Result<PplnsGroupMemberRow, GroupServiceError> {
        let normalized = normalize_address(address)?;
        if let Some(existing) = bp_db::find_group_member_by_address(&self.pool, &normalized).await?
        {
            return if existing.group_id == group_id {
                Err(GroupServiceError::AlreadyMember)
            } else {
                Err(GroupServiceError::AddressInGroup)
            };
        }
        self.assert_not_in_blockparty(&normalized).await?;

        // Member cap — the single chokepoint every add path funnels through
        // (directed invite, open invite link, approved join request). NULL =
        // no limit. Enforced server-side so a UI-only block can't be bypassed.
        let max_members = bp_db::find_group(&self.pool, group_id)
            .await?
            .and_then(|g| g.max_members);

        let now = now_ms();
        // DB-side atomic: insert member + recompute active in one TX —
        // mirrors `remove_member`. Without the TX a failure between the
        // insert and the active-recompute leaves the member persisted but
        // `active` stale; a retry then hits AlreadyMember and can't repair
        // the flag (the group would silently route no shares despite
        // having ≥ MIN_MEMBERS_ACTIVE members).
        let mut tx = self.pool.begin().await.map_err(bp_db::DbError::from)?;
        if let Some(max) = max_members {
            // Count inside the TX so a concurrent add can't slip past the cap.
            let current = bp_db::count_pplns_group_members_for_group(&mut *tx, group_id).await?;
            if current >= max as i64 {
                return Err(GroupServiceError::GroupFull); // tx rolls back on drop
            }
        }
        let member = bp_db::insert_pplns_group_member(
            &mut *tx,
            group_id,
            &normalized,
            MemberRole::Member.as_str(),
            now,
        )
        .await?;
        let count = bp_db::count_pplns_group_members_for_group(&mut *tx, group_id).await?;
        let should_be_active = count as u32 >= MIN_MEMBERS_ACTIVE;
        bp_db::update_pplns_group_active(&mut *tx, group_id, should_be_active, now).await?;
        tx.commit().await.map_err(bp_db::DbError::from)?;

        self.rebuild_and_notify().await?;
        Ok(member)
    }

    /// Admin path to remove a non-creator member. Enforces the
    /// kick-inactivity window (`kick_inactivity_days`) and runs Redis
    /// cleanup AFTER the DB transaction commits so a Redis failure
    /// doesn't leave us with an inconsistent DB state.
    pub async fn remove_member(
        &self,
        group_id: Uuid,
        address: &str,
        token: Option<&str>,
    ) -> Result<(), GroupServiceError> {
        self.require_admin_token(group_id, token).await?;
        let normalized = normalize_address(address)?;
        let member = bp_db::find_pplns_group_member_in_group(&self.pool, group_id, &normalized)
            .await?
            .ok_or(GroupServiceError::NotMember)?;
        if member.role == MemberRole::Creator.as_str() {
            return Err(GroupServiceError::CreatorCannotBeRemoved);
        }

        // Kick-inactivity guard.
        let last_active = self
            .hooks
            .last_active_for_member(group_id, &normalized)
            .await;
        let reference = last_active.unwrap_or(member.joined_at);
        let now = now_ms();
        let days_since = (now - reference).max(0) as f64 / MS_PER_DAY as f64;
        if days_since < self.kick_inactivity_days as f64 {
            return Err(GroupServiceError::MemberStillActive {
                required_days: self.kick_inactivity_days,
                actual_days: days_since,
            });
        }

        // Snapshot remaining-member list BEFORE the delete.
        let remaining = bp_db::find_pplns_group_members_for_group(&self.pool, group_id).await?;
        let remaining_addresses: Vec<AddressId> = remaining
            .iter()
            .filter(|m| m.address != normalized)
            .map(|m| m.address.clone())
            .collect();

        // DB-side atomic: delete member + recompute active in one TX.
        // update_pplns_group_active guards against dissolved groups in SQL.
        let mut tx = self.pool.begin().await.map_err(bp_db::DbError::from)?;
        bp_db::delete_pplns_group_member(&mut *tx, group_id, &normalized).await?;
        let count = bp_db::count_pplns_group_members_for_group(&mut *tx, group_id).await?;
        let should_be_active = count as u32 >= MIN_MEMBERS_ACTIVE;
        bp_db::update_pplns_group_active(&mut *tx, group_id, should_be_active, now).await?;
        tx.commit().await.map_err(bp_db::DbError::from)?;

        // Best-effort Redis cleanup (swallows errors + logs).
        self.hooks
            .on_member_removed(group_id, &normalized, &remaining_addresses)
            .await;

        self.rebuild_and_notify().await?;
        Ok(())
    }

    /// Hand the creator role to another member + rotate the admin
    /// token. Returns the rotated row + the new plaintext token (shown
    /// to the new admin exactly once).
    pub async fn transfer_creator(
        &self,
        group_id: Uuid,
        to_address: &str,
        token: Option<&str>,
    ) -> Result<CreatorTransferResult, GroupServiceError> {
        let _group = self.require_admin_token(group_id, token).await?;
        let normalized = normalize_address(to_address)?;
        let new_creator =
            bp_db::find_pplns_group_member_in_group(&self.pool, group_id, &normalized)
                .await?
                .ok_or(GroupServiceError::NotMember)?;
        if new_creator.role == MemberRole::Creator.as_str() {
            return Err(GroupServiceError::AlreadyCreator);
        }
        let old_creator = bp_db::find_pplns_group_creator_member(&self.pool, group_id).await?;

        let new_admin = AdminToken::generate()?;
        let new_hash = new_admin.hash();
        let now = now_ms();

        let mut tx = self.pool.begin().await.map_err(bp_db::DbError::from)?;
        if let Some(old) = old_creator {
            bp_db::update_pplns_group_member_role(
                &mut *tx,
                group_id,
                &old.address,
                MemberRole::Member.as_str(),
            )
            .await?;
        }
        bp_db::update_pplns_group_member_role(
            &mut *tx,
            group_id,
            &normalized,
            MemberRole::Creator.as_str(),
        )
        .await?;
        bp_db::update_pplns_group_creator_and_admin_token(
            &mut *tx,
            group_id,
            &normalized,
            new_hash.as_str(),
            now,
        )
        .await?;
        tx.commit().await.map_err(bp_db::DbError::from)?;

        let saved = bp_db::find_group(&self.pool, group_id)
            .await?
            .ok_or(GroupServiceError::NotFound)?;

        self.rebuild_and_notify().await?;
        Ok(CreatorTransferResult {
            group: saved,
            admin_token: new_admin.into_inner(),
        })
    }

    /// PATCH the round-reset configuration. Only fields tagged
    /// `Set` / `Clear` are touched; the rest stay where they were.
    pub async fn update_round_reset_config(
        &self,
        group_id: Uuid,
        settings: UpdateRoundResetSettings,
        token: Option<&str>,
    ) -> Result<PplnsGroupRow, GroupServiceError> {
        let group = self.require_admin_token(group_id, token).await?;

        // Cross-field consistency check before we touch the DB.
        if let (PatchField::Set(p), PatchField::Set(_)) =
            (&settings.preset, &settings.interval_days)
        {
            if *p != RoundResetPreset::Custom {
                return Err(GroupServiceError::InvalidInterval);
            }
        }

        // maxMembers: null clears the cap, a positive integer >= 2 (the group
        // member floor) sets it. Setting below the current count is allowed —
        // no one is kicked, growth is just frozen.
        if let PatchField::Set(v) = &settings.max_members {
            if *v < 2 || *v > 100_000 {
                return Err(GroupServiceError::InvalidMaxMembers);
            }
        }

        // Build the resolved config we'd see after the PATCH applies —
        // needed for the cross-field validation that follows.
        let resolved = resolve_after_patch(&group, &settings);
        validate_resolved_round_reset(&resolved, self.hooks.min_payout_sats())?;

        let patch = settings_to_db_patch(settings);
        let now = now_ms();
        let updated =
            bp_db::update_pplns_group_round_reset_config(&self.pool, group_id, &patch, now)
                .await?
                .ok_or(GroupServiceError::NotFound)?;

        // Re-arm the cron job. Idempotent.
        self.hooks.apply_round_reset_config(&updated).await;

        Ok(updated)
    }

    /// Mark a group dissolved + cascade-delete all member rows.
    /// Returns once the DB transaction has committed; Redis cleanup
    /// runs after (best-effort).
    pub async fn dissolve_group(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<(), GroupServiceError> {
        self.require_admin_token(group_id, token).await?;
        let now = now_ms();
        let mut tx = self.pool.begin().await.map_err(bp_db::DbError::from)?;
        bp_db::delete_pplns_group_members_for_group(&mut *tx, group_id).await?;
        bp_db::update_pplns_group_dissolved(&mut *tx, group_id, now).await?;
        tx.commit().await.map_err(bp_db::DbError::from)?;

        // Redis cleanup + scheduler tear-down outside the TX.
        self.hooks.on_group_dissolved(group_id).await;
        self.rebuild_and_notify().await?;
        Ok(())
    }
}

// ─── helpers ──────────────────────────────────────────────────────

/// Compute what the group row would look like after applying `settings`
/// — needed to validate the resolved config (e.g. `preset` set + no
/// timezone present + no timezone in patch == IncompleteSchedule).
fn resolve_after_patch(
    current: &PplnsGroupRow,
    settings: &UpdateRoundResetSettings,
) -> RoundResetConfig {
    let preset = match &settings.preset {
        PatchField::Untouched => current
            .round_reset_preset
            .as_deref()
            .and_then(RoundResetPreset::parse),
        PatchField::Clear => None,
        PatchField::Set(p) => Some(*p),
    };
    let interval_days = match &settings.interval_days {
        PatchField::Untouched => current.round_reset_interval_days.map(|d| d as u32),
        PatchField::Clear => None,
        PatchField::Set(d) => Some(*d),
    };
    let timezone = match &settings.timezone {
        PatchField::Untouched => current.round_reset_timezone.clone(),
        PatchField::Clear => None,
        PatchField::Set(tz) => Some(tz.clone()),
    };
    let finder_bonus_sats = match &settings.finder_bonus_sats {
        PatchField::Untouched => current.finder_bonus_sats.unwrap_or(Sats(0)),
        PatchField::Clear => Sats(0),
        PatchField::Set(b) => *b,
    };
    RoundResetConfig {
        preset,
        interval_days,
        timezone,
        finder_bonus_sats,
    }
}

/// Validate the post-patch config. Combines the pure-math validators
/// from `bp-group-mgmt::group::validate_round_reset` with an IANA TZ
/// check the pure crate deliberately leaves to the service layer.
fn validate_resolved_round_reset(
    resolved: &RoundResetConfig,
    min_payout: Sats,
) -> Result<(), GroupServiceError> {
    bp_group_mgmt::group::validate_round_reset(resolved, min_payout).map_err(|e| {
        use bp_group_mgmt::group::RoundResetError;
        match e {
            RoundResetError::IntervalWithoutCustomPreset
            | RoundResetError::IntervalOutOfRange(_) => GroupServiceError::InvalidInterval,
            RoundResetError::MissingTimezone | RoundResetError::IntervalRequiredForCustom => {
                GroupServiceError::IncompleteSchedule
            }
            RoundResetError::FinderBonusOutOfRange(_)
            | RoundResetError::FinderBonusSubMinPayout { .. } => GroupServiceError::InvalidBonus,
        }
    })?;
    // IANA TZ check happens here (service layer owns the TZ DB).
    if let Some(tz) = &resolved.timezone {
        if tz.parse::<chrono_tz::Tz>().is_err() {
            return Err(GroupServiceError::InvalidTimezone);
        }
    }
    Ok(())
}

/// Lift the engine-facing PATCH-DTO into the bp-db form.
fn settings_to_db_patch(s: UpdateRoundResetSettings) -> RoundResetConfigPatch {
    RoundResetConfigPatch {
        preset: s.preset.map_set(|p| p.as_str().to_string()),
        interval_days: s.interval_days.map_set(|d| d as i32),
        timezone: s.timezone,
        // hour_local is hard-coded to 0 on every PATCH —
        // calendar resets fire at midnight local time, always.
        hour_local: PatchField::Set(0),
        finder_bonus_sats: s.finder_bonus_sats.map_set(|sats| sats.to_i64()),
        is_public: s.is_public,
        reset_round_on_block: s.reset_round_on_block,
        max_members: s.max_members,
    }
}
