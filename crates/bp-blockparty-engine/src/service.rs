// SPDX-License-Identifier: AGPL-3.0-or-later

//! `BlockpartyService` — group lifecycle FSM, token-gated mutations,
//! routing cache, and the share/block hooks.
//!
//! ## Load-bearing invariant
//!
//! Every method that changes a party's `status` column **must** also
//! call [`BlockpartyCache::set_admin_status`] for the new value. If the
//! cache drifts from the DB the routing guards either pin shares to the
//! pool-fee fallback for a confirmed party, or skip the Blockparty
//! coinbase for one whose members have all confirmed. Grep this file
//! for `set_admin_status` to audit: every status-mutation site must
//! have a matching cache write.

use std::sync::Arc;

use bp_blockparty::{
    build_blockparty_distribution, BlockpartyDistributionInput, BlockpartyDistributionResult,
    BlockpartyMemberInput, BlockpartyStatus, DISSOLVE_COOLDOWN_MS, MAX_PERCENT_BP, MIN_PERCENT_BP,
    NAME_MAX_LEN, NAME_MIN_LEN, TOTAL_PERCENT_BP,
};
use bp_common::AddressId;
use bp_db::{
    BlockpartyBlockHistoryRow, BlockpartyGroupRow, BlockpartyMemberRow, BlockpartySplitSnapshot,
};
use bp_group_mgmt::token::{AdminToken, InvitationToken, TokenHash};
use bp_group_mgmt_engine::AddressCache as PplnsAddressCache;
use sqlx::PgPool;
use uuid::Uuid;

use crate::cache::BlockpartyCache;
use crate::error::BlockpartyServiceError;
use crate::hooks::BlockpartyHooks;
use crate::util::{normalize_address, now_ms};

// ─── Config + result types ─────────────────────────────────────────

/// Construction-time config knobs. The pool fee address + percent are
/// resolved from environment in the bin/blitzpool boot layer (env keys
/// `GROUP_FEE_ADDRESS`/`GROUP_FEE_PERCENT` with `PPLNS_FEE_*` fallback)
/// and handed in here as values.
#[derive(Clone, Debug)]
pub struct BlockpartyServiceConfig {
    pub fee_address: Option<AddressId>,
    pub fee_percent: f64,
    /// Operational dust floor for per-member coinbase outputs. Clamped
    /// to ≥ `bp_blockparty::DUST_LIMIT_SATS` at distribution time.
    pub min_payout_sats: bp_common::Sats,
}

impl Default for BlockpartyServiceConfig {
    fn default() -> Self {
        Self {
            fee_address: None,
            fee_percent: 2.0,
            min_payout_sats: bp_common::Sats(5_000),
        }
    }
}

/// Hook that re-sizes the Blockparty coinbase reservation to fit a party's
/// confirmed roster. Called at the `Confirming → Ready` transition — the point
/// the roster is final-for-now and the party becomes routable (Ready miners
/// build the party coinbase, and the first share flips it to Active). Any later
/// roster edit bounces the party back through `Confirming`, so each `→ Ready`
/// carries the current member count.
///
/// Decoupled from the TDP layer on purpose: the bin implements it over the
/// Blockparty `TdpHandle`; the engine just signals "this many members are about
/// to mine". Implementations are high-water-mark (only raise) above a floor.
///
/// **Validity note:** a raise reaches bitcoin-core templates within ~one TDP
/// cycle, so this is *headroom above a floor that already covers the typical
/// party*, not the sole guarantee — keep `[blockparty].coinbase_weight_budget`
/// ≥ your realistic max party so the common case never needs a (lagging) raise.
#[async_trait::async_trait]
pub trait CoinbaseReservation: Send + Sync {
    /// Ensure the Blockparty coinbase reservation can hold `member_count`
    /// member outputs plus the pool-fee output. Idempotent / high-water.
    async fn ensure_capacity_for_members(&self, member_count: usize);
}

#[derive(Debug)]
pub struct BlockpartyCreateResult {
    pub group: BlockpartyGroupRow,
    pub admin_member: BlockpartyMemberRow,
    /// Plaintext admin token — surfaces to the human exactly once.
    pub admin_token: String,
    /// Echoed back for the create-response so the UI doesn't need to
    /// re-fetch config to display "you'll be charged X% on each block".
    pub pool_fee_percent: f64,
}

#[derive(Debug)]
pub struct MarkMemberConfirmedResult {
    /// `Some` when this confirmation minted a fresh persistent token
    /// (first accept or post-reset). `None` when the member already had
    /// a token (idempotent re-confirm via the persistent token).
    pub member_token: Option<String>,
}

/// Result of [`BlockpartyService::pending_party_fee_route`]. Wraps the
/// concrete pool-fee output the Solo-fallback path must emit when the
/// admin's address belongs to an unconfirmed party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPartyFeeRoute {
    pub fee_address: AddressId,
    /// Always 100. Encoded as a field so the type doesn't lie.
    pub percent: u8,
}

// ─── Service struct ────────────────────────────────────────────────

pub struct BlockpartyService<H: BlockpartyHooks> {
    pool: PgPool,
    hooks: Arc<H>,
    cache: BlockpartyCache,
    /// PplnsGroup cache — read-only here, used for the bidirectional
    /// mode-collision check on `create_group` / `add_member`.
    pplns_cache: PplnsAddressCache,
    config: BlockpartyServiceConfig,
    /// Optional coinbase-reservation hook — sizes the Blockparty TDP stream's
    /// reservation to a party's roster at `→ Ready`. `None` in tests and when
    /// the Blockparty TDP stream isn't wired (`--skip-tdp`).
    reservation: Option<Arc<dyn CoinbaseReservation>>,
    /// Optional cross-process cache-invalidation notifier (set-once). When set,
    /// every public mutation publishes a `"blockparty"` invalidation so a
    /// separate Stratum Front rebuilds its routing cache. Unset where no
    /// cross-process notification is needed (e.g. tests).
    change_notifier:
        Arc<std::sync::OnceLock<Arc<dyn bp_group_mgmt_engine::MembershipChangeNotifier>>>,
}

impl<H: BlockpartyHooks> BlockpartyService<H> {
    pub fn new(
        pool: PgPool,
        hooks: Arc<H>,
        pplns_cache: PplnsAddressCache,
        config: BlockpartyServiceConfig,
    ) -> Self {
        Self {
            pool,
            hooks,
            cache: BlockpartyCache::new(),
            pplns_cache,
            config,
            reservation: None,
            change_notifier: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Attach the cross-process cache-invalidation notifier (idempotent, set-
    /// once). Wire on the process hosting the API writers so a party status
    /// change reaches a separate Front's routing cache.
    pub fn set_change_notifier(
        &self,
        notifier: Arc<dyn bp_group_mgmt_engine::MembershipChangeNotifier>,
    ) {
        let _ = self.change_notifier.set(notifier);
    }

    /// Fire the cross-process invalidation (best-effort). `"blockparty"` matches
    /// `bp_share_stream::cache_kind::BLOCKPARTY`. No-op until a notifier is set.
    async fn notify_changed(&self) {
        if let Some(n) = self.change_notifier.get() {
            n.membership_changed("blockparty").await;
        }
    }

    /// Attach the coinbase-reservation hook (the bin's Blockparty TDP-stream
    /// sizer). `None` leaves the reservation fixed at its configured floor.
    /// Builder-style so it can be chained before the service is `Arc`-wrapped.
    pub fn with_coinbase_reservation(
        mut self,
        reservation: Option<Arc<dyn CoinbaseReservation>>,
    ) -> Self {
        self.reservation = reservation;
        self
    }

    /// Expose the cache for downstream consumers (stratum layer, bp-api
    /// hot-path readers). Clones are cheap — `Arc` under the hood.
    pub fn cache(&self) -> BlockpartyCache {
        self.cache.clone()
    }

    /// Borrow the hooks bundle — used by the invitation service to
    /// pull verified email bindings without duplicating the hook trait.
    pub fn hooks(&self) -> &H {
        &self.hooks
    }

    /// Read access to the wrapped PgPool — used by the invitation
    /// service for the few raw queries it does outside `bp_db::*`.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Full rebuild from PG. Call once at boot before the stratum layer
    /// starts handing shares; subsequent state-transition methods keep
    /// the cache in sync via [`BlockpartyCache::set_admin_status`] etc.
    pub async fn rebuild_cache(&self) -> Result<(), BlockpartyServiceError> {
        self.cache.rebuild(&self.pool).await
    }

    pub fn pool_fee_percent(&self) -> f64 {
        self.config.fee_percent
    }

    pub fn fee_address(&self) -> Option<&AddressId> {
        self.config.fee_address.as_ref()
    }

    // ─── Read paths (cache-backed, stratum hot path) ───────────────

    /// `None` unless the admin's party is `ready` or `active`.
    pub async fn routable_group_id_for_admin(&self, address: &AddressId) -> Option<Uuid> {
        self.cache.routable_group_id_for_admin(address).await
    }

    /// Returns a concrete fee output when the admin's address belongs
    /// to a DRAFT/CONFIRMING party AND the pool has a configured fee
    /// address. `None` otherwise — the caller then falls through to
    /// the standard Solo coinbase.
    pub async fn pending_party_fee_route(
        &self,
        address: &AddressId,
    ) -> Option<PendingPartyFeeRoute> {
        let _gid = self.cache.pending_fee_route_admin(address).await?;
        let fee_address = self.config.fee_address.clone()?;
        Some(PendingPartyFeeRoute {
            fee_address,
            percent: 100,
        })
    }

    /// Member-side lookup. Returns the party's group id if `address`
    /// is a member of any non-dissolved party.
    pub async fn member_group_id(&self, address: &AddressId) -> Option<Uuid> {
        self.cache.member_group_id(address).await
    }

    pub async fn get_group(
        &self,
        group_id: Uuid,
    ) -> Result<Option<BlockpartyGroupRow>, BlockpartyServiceError> {
        Ok(bp_db::find_blockparty_group(&self.pool, group_id).await?)
    }

    pub async fn list_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<BlockpartyMemberRow>, BlockpartyServiceError> {
        Ok(bp_db::list_blockparty_members_for_group(&self.pool, group_id).await?)
    }

    pub async fn list_groups(&self) -> Result<Vec<BlockpartyGroupRow>, BlockpartyServiceError> {
        Ok(bp_db::list_blockparty_groups(&self.pool).await?)
    }

    /// Non-dissolved subset — drives `/api/blockparty/public`.
    pub async fn list_groups_public(
        &self,
    ) -> Result<Vec<BlockpartyGroupRow>, BlockpartyServiceError> {
        Ok(bp_db::list_blockparty_groups_non_dissolved(&self.pool).await?)
    }

    pub async fn get_history(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<BlockpartyBlockHistoryRow>, BlockpartyServiceError> {
        Ok(bp_db::list_blockparty_block_history(&self.pool, group_id).await?)
    }

    /// Build the coinbase payout distribution for a found block: pure-
    /// function math over the current member roster + config. Returns
    /// `Ok(None)` when the group does not exist (no panic for the
    /// stratum-hot path).
    pub async fn build_payouts(
        &self,
        group_id: Uuid,
        block_reward_sats: bp_common::Sats,
    ) -> Result<Option<BlockpartyDistributionResult>, BlockpartyServiceError> {
        if bp_db::find_blockparty_group(&self.pool, group_id)
            .await?
            .is_none()
        {
            return Ok(None);
        }
        let members = bp_db::list_blockparty_members_for_group(&self.pool, group_id).await?;
        let inputs: Vec<BlockpartyMemberInput<'_>> = members
            .iter()
            .map(|m| BlockpartyMemberInput {
                address: &m.address,
                percent_bp: m.percent_bp,
            })
            .collect();
        let result = build_blockparty_distribution(BlockpartyDistributionInput {
            members: &inputs,
            block_reward_sats,
            pool_fee_address: self.config.fee_address.as_ref(),
            pool_fee_percent: self.config.fee_percent,
            min_payout_sats: self.config.min_payout_sats,
        });
        Ok(Some(result))
    }

    // ─── Token gating ──────────────────────────────────────────────

    /// Resolve `(group, validated)` for an admin-token request. Returns
    /// `InvalidToken` on any mismatch, `MissingToken` if the caller
    /// supplied `None`, `NotFound` if dissolved/missing.
    pub async fn require_admin_token(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<BlockpartyGroupRow, BlockpartyServiceError> {
        let provided = token.ok_or(BlockpartyServiceError::MissingToken)?;
        let group = bp_db::find_blockparty_group(&self.pool, group_id)
            .await?
            .ok_or(BlockpartyServiceError::NotFound)?;
        // Dissolved groups behave as not-found for admin actions — UI
        // doesn't need to disambiguate "wrong group" vs "dissolved".
        if group.status == BlockpartyStatus::Dissolved.as_str() {
            return Err(BlockpartyServiceError::NotFound);
        }
        let stored = TokenHash::from_hex(group.admin_token_hash.clone());
        if !stored.verifies(provided) {
            return Err(BlockpartyServiceError::InvalidToken);
        }
        Ok(group)
    }

    /// Validate a member-token for `(group, address)`. Returns the
    /// member row on success.
    pub async fn require_member_token(
        &self,
        group_id: Uuid,
        address: &AddressId,
        token: Option<&str>,
    ) -> Result<BlockpartyMemberRow, BlockpartyServiceError> {
        let provided = token.ok_or(BlockpartyServiceError::MissingMemberToken)?;
        let member = bp_db::find_blockparty_member_in_group(&self.pool, group_id, address)
            .await?
            .ok_or(BlockpartyServiceError::NotMember)?;
        let stored_hex = member
            .member_token_hash
            .as_deref()
            .ok_or(BlockpartyServiceError::MemberNotConfirmed)?;
        let stored = TokenHash::from_hex(stored_hex.to_owned());
        if !stored.verifies(provided) {
            return Err(BlockpartyServiceError::InvalidMemberToken);
        }
        Ok(member)
    }

    // ─── Lifecycle ─────────────────────────────────────────────────

    /// Create a fresh party. Validates name/address, checks mode-
    /// collision against PplnsGroup, inserts group + admin member row,
    /// populates cache. Admin token returned plaintext exactly once.
    pub async fn create_group(
        &self,
        name: &str,
        admin_address: &str,
        admin_email: &str,
        admin_percent_bp: i32,
    ) -> Result<BlockpartyCreateResult, BlockpartyServiceError> {
        validate_name(name)?;
        validate_percent_bp(admin_percent_bp)?;
        validate_email(admin_email)?;
        let admin_addr = normalize_address(admin_address)?;

        // Bidirectional mode-collision — reuse the PplnsGroup cache.
        if self.pplns_cache.get(&admin_addr).await.is_some() {
            return Err(BlockpartyServiceError::AddressInPplnsGroup);
        }
        // Uniqueness — name + admin address are both globally unique.
        if bp_db::find_blockparty_group_by_name(&self.pool, name)
            .await?
            .is_some()
        {
            return Err(BlockpartyServiceError::NameTaken);
        }
        if bp_db::find_blockparty_group_by_admin_address(&self.pool, &admin_addr)
            .await?
            .is_some()
        {
            return Err(BlockpartyServiceError::AdminAddressTaken);
        }
        // Pool-wide member-address uniqueness (admin row will use this slot).
        if bp_db::find_blockparty_member_by_address(&self.pool, &admin_addr)
            .await?
            .is_some()
        {
            return Err(BlockpartyServiceError::AddressInBlockparty);
        }

        let admin_token = AdminToken::generate()?;
        let admin_hash = admin_token.hash();
        let now = now_ms();
        let id = Uuid::new_v4();

        let group = bp_db::insert_blockparty_group(
            &self.pool,
            id,
            name,
            &admin_addr,
            admin_hash.as_str(),
            BlockpartyStatus::Draft.as_str(),
            now,
        )
        .await?;

        // Admin is auto-confirmed at creation (they hold the token, the
        // authoring is the confirmation). No member-token minted yet —
        // mark_member_confirmed handles that on first non-admin confirm.
        let admin_member = bp_db::insert_blockparty_member(
            &self.pool,
            id,
            &admin_addr,
            admin_email,
            admin_percent_bp,
            "admin",
            Some(now),
            now,
        )
        .await?;

        self.cache
            .set_admin_status(&admin_addr, id, BlockpartyStatus::Draft)
            .await;

        Ok(BlockpartyCreateResult {
            group,
            admin_member,
            admin_token: admin_token.into_inner(),
            pool_fee_percent: self.config.fee_percent,
        })
    }

    /// Add a member. Admin-token gated. Pulls verified email via the
    /// hook (admin input ignored — single source of truth is the
    /// binding). Auto-flips DRAFT → CONFIRMING on first add.
    pub async fn add_member(
        &self,
        group_id: Uuid,
        member_address: &str,
        percent_bp: i32,
        token: Option<&str>,
    ) -> Result<BlockpartyMemberRow, BlockpartyServiceError> {
        let group = self.require_admin_token(group_id, token).await?;
        assert_editable(&group)?;
        validate_percent_bp(percent_bp)?;

        let address = normalize_address(member_address)?;
        if address == group.admin_address {
            return Err(BlockpartyServiceError::AdminCannotRejoin);
        }
        if bp_db::find_blockparty_member_by_address(&self.pool, &address)
            .await?
            .is_some()
        {
            return Err(BlockpartyServiceError::AddressInBlockparty);
        }
        if self.pplns_cache.get(&address).await.is_some() {
            return Err(BlockpartyServiceError::AddressInPplnsGroup);
        }

        // Unified onboarding gate: verified by a confirmed email OR a signature
        // ownership proof. The email (if any) is snapshotted onto the member row;
        // a signature-only member has none.
        let email = self.hooks.verified_email_for(&address).await;
        if email.is_none() && !bp_db::is_address_ownership_verified(&self.pool, &address).await? {
            return Err(BlockpartyServiceError::EmailNotVerified);
        }
        let email = email.map(|e| e.to_ascii_lowercase()).unwrap_or_default();

        let now = now_ms();
        let inserted = match bp_db::insert_blockparty_member(
            &self.pool, group_id, &address, &email, percent_bp, "member",
            None, // confirmed_at = null; member must accept invitation
            now,
        )
        .await
        {
            Ok(row) => row,
            Err(bp_db::DbError::Sqlx(sqlx::Error::Database(db_err)))
                if db_err.code().as_deref() == Some("23505") =>
            {
                // Concurrent admin-click race past the find-by-address
                // check above. UNIQUE(address) catches it; surface as
                // typed error so the UI shows the address-collision
                // toast instead of a generic 500.
                return Err(BlockpartyServiceError::AddressInBlockparty);
            }
            Err(e) => return Err(e.into()),
        };

        // DRAFT → CONFIRMING on first member (incl. cache sync).
        if group.status == BlockpartyStatus::Draft.as_str() {
            bp_db::update_blockparty_group_status(
                &self.pool,
                group_id,
                BlockpartyStatus::Confirming.as_str(),
                now,
            )
            .await?;
            self.cache
                .set_admin_status(&group.admin_address, group_id, BlockpartyStatus::Confirming)
                .await;
        }
        // Member entry into cache for mode-collision + UI.
        self.cache.insert_member(&address, group_id).await;
        // Recompute keeps the cache in sync after every membership
        // change. Idempotent and cheap.
        self.recompute_status(group_id).await?;

        Ok(inserted)
    }

    /// Create (or replace) the group's single self-service join link. Admin-gated.
    /// Returns the plaintext link token to share.
    pub async fn create_join_link(
        &self,
        group_id: Uuid,
        ttl_days: Option<i64>,
        token: Option<&str>,
    ) -> Result<String, BlockpartyServiceError> {
        let group = self.require_admin_token(group_id, token).await?;
        assert_editable(&group)?;
        let now = now_ms();
        let ttl_days = ttl_days.unwrap_or(7).clamp(1, 90);
        let expires_at = now + ttl_days * 24 * 60 * 60 * 1000;
        let link = InvitationToken::generate()?;
        bp_db::upsert_blockparty_join_link(&self.pool, group_id, link.as_str(), expires_at, now)
            .await?;
        Ok(link.as_str().to_owned())
    }

    /// Revoke the group's join link. Admin-gated.
    pub async fn revoke_join_link(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        let _ = self.require_admin_token(group_id, token).await?;
        bp_db::delete_blockparty_join_link(&self.pool, group_id).await?;
        Ok(())
    }

    /// Self-service join via a shared link. No admin token — the joining address
    /// proves itself (verified email OR signature ownership). Adds the member
    /// unconfirmed with a 0 % placeholder split (the admin assigns it) and mints
    /// the member token used to later confirm that split. Returns
    /// `(member_token, group_id)`.
    pub async fn join_via_link(
        &self,
        link_token: &str,
        member_address: &str,
    ) -> Result<(String, Uuid), BlockpartyServiceError> {
        let link = bp_db::find_blockparty_join_link_by_token(&self.pool, link_token)
            .await?
            .ok_or(BlockpartyServiceError::NotFound)?;
        let now = now_ms();
        // An expired/invalid link surfaces as not-found (no info leak).
        if link.expires_at < now {
            return Err(BlockpartyServiceError::NotFound);
        }
        let group = bp_db::find_blockparty_group(&self.pool, link.group_id)
            .await?
            .ok_or(BlockpartyServiceError::NotFound)?;
        assert_editable(&group)?;

        let address = normalize_address(member_address)?;
        if address == group.admin_address {
            return Err(BlockpartyServiceError::AdminCannotRejoin);
        }
        if bp_db::find_blockparty_member_by_address(&self.pool, &address)
            .await?
            .is_some()
        {
            return Err(BlockpartyServiceError::AddressInBlockparty);
        }
        if self.pplns_cache.get(&address).await.is_some() {
            return Err(BlockpartyServiceError::AddressInPplnsGroup);
        }

        // Unified onboarding gate: verified email OR signature ownership proof.
        let email = self.hooks.verified_email_for(&address).await;
        if email.is_none() && !bp_db::is_address_ownership_verified(&self.pool, &address).await? {
            return Err(BlockpartyServiceError::EmailNotVerified);
        }
        let email = email.map(|e| e.to_ascii_lowercase()).unwrap_or_default();

        // Insert unconfirmed with a 0 % placeholder (the admin sets the real split).
        match bp_db::insert_blockparty_member(
            &self.pool,
            group.id,
            &address,
            &email,
            0,
            "member",
            None,
            now,
        )
        .await
        {
            Ok(_) => {}
            Err(bp_db::DbError::Sqlx(sqlx::Error::Database(db_err)))
                if db_err.code().as_deref() == Some("23505") =>
            {
                return Err(BlockpartyServiceError::AddressInBlockparty);
            }
            Err(e) => return Err(e.into()),
        }

        // Mint the member token now (no confirm) so the member can confirm the
        // split the admin will assign.
        let t = InvitationToken::generate()?;
        let hash = t.hash();
        bp_db::update_blockparty_member_confirmed(
            &self.pool,
            group.id,
            &address,
            None,
            Some(hash.as_str()),
            now,
        )
        .await?;

        // DRAFT → CONFIRMING + cache + status recompute (mirrors add_member).
        if group.status == BlockpartyStatus::Draft.as_str() {
            bp_db::update_blockparty_group_status(
                &self.pool,
                group.id,
                BlockpartyStatus::Confirming.as_str(),
                now,
            )
            .await?;
            self.cache
                .set_admin_status(&group.admin_address, group.id, BlockpartyStatus::Confirming)
                .await;
        }
        self.cache.insert_member(&address, group.id).await;
        self.recompute_status(group.id).await?;

        Ok((t.as_str().to_owned(), group.id))
    }

    /// Public read: the group behind a valid, non-expired join link (for the
    /// join landing page). `None` if the link is unknown, expired, or dissolved.
    /// Returns `(group, link_expires_at)`.
    pub async fn join_link_group(
        &self,
        link_token: &str,
    ) -> Result<Option<(BlockpartyGroupRow, i64)>, BlockpartyServiceError> {
        let link = match bp_db::find_blockparty_join_link_by_token(&self.pool, link_token).await? {
            Some(l) => l,
            None => return Ok(None),
        };
        if link.expires_at < now_ms() {
            return Ok(None);
        }
        let group = bp_db::find_blockparty_group(&self.pool, link.group_id).await?;
        Ok(group
            .filter(|g| g.dissolved_at.is_none())
            .map(|g| (g, link.expires_at)))
    }

    /// Remove a member. Admin-token gated. Refuses admin removal.
    pub async fn remove_member(
        &self,
        group_id: Uuid,
        member_address: &str,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        let group = self.require_admin_token(group_id, token).await?;
        assert_editable(&group)?;
        let address = normalize_address(member_address)?;
        if address == group.admin_address {
            return Err(BlockpartyServiceError::AdminCannotBeRemoved);
        }
        let affected = bp_db::delete_blockparty_member(&self.pool, group_id, &address).await?;
        if affected == 0 {
            return Err(BlockpartyServiceError::NotMember);
        }
        self.cache.remove_member(&address).await;
        self.recompute_status(group_id).await?;
        Ok(())
    }

    /// Update per-member splits. Validates each supplied member's percent
    /// is in range. Non-admin members lose their `confirmedAt` (they must
    /// re-confirm the new deal). The admin is presumed to confirm by
    /// virtue of authoring the edit.
    pub async fn update_splits(
        &self,
        group_id: Uuid,
        updates: &[(AddressId, i32)],
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        let group = self.require_admin_token(group_id, token).await?;
        assert_editable(&group)?;

        // Validate each percentBp. No total-sum check: splits arrive as
        // the changed subset only, so the full roster isn't summable here.
        for (_, p) in updates {
            validate_percent_bp(*p)?;
        }

        let now = now_ms();
        let mut tx = self.pool.begin().await.map_err(bp_db::DbError::from)?;
        for (addr, pct) in updates {
            let affected = sqlx::query!(
                r#"UPDATE blockparty_member
                   SET "percentBp" = $3, "updatedAt" = $4
                   WHERE "groupId" = $1 AND address = $2"#,
                group_id,
                addr.as_str(),
                *pct,
                now,
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| BlockpartyServiceError::Db(bp_db::DbError::Sqlx(e)))?
            .rows_affected();
            if affected == 0 {
                return Err(BlockpartyServiceError::NotMember);
            }
        }
        // Reset non-admin confirmations inside the same TX so a partial
        // failure doesn't leave splits updated but confirmations stale.
        sqlx::query!(
            r#"UPDATE blockparty_member
               SET "confirmedAt" = NULL, "updatedAt" = $2
               WHERE "groupId" = $1 AND role <> 'admin'"#,
            group_id,
            now,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| BlockpartyServiceError::Db(bp_db::DbError::Sqlx(e)))?;
        // Admin's edit authorship counts as their re-confirmation of the
        // new splits. Explicitly stamping the timestamp also self-heals
        // rows where confirmedAt was previously null.
        sqlx::query!(
            r#"UPDATE blockparty_member
               SET "confirmedAt" = $2, "updatedAt" = $2
               WHERE "groupId" = $1 AND role = 'admin'"#,
            group_id,
            now,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| BlockpartyServiceError::Db(bp_db::DbError::Sqlx(e)))?;
        tx.commit().await.map_err(bp_db::DbError::from)?;

        // Reset means status drops back to CONFIRMING — handled by
        // recompute_status (which also updates the cache).
        self.recompute_status(group_id).await?;
        Ok(())
    }

    /// Mark a member's row confirmed. Mints a persistent member token
    /// on first call; idempotent on re-call. Plaintext returned once.
    pub async fn mark_member_confirmed(
        &self,
        group_id: Uuid,
        address: &AddressId,
    ) -> Result<MarkMemberConfirmedResult, BlockpartyServiceError> {
        let member = bp_db::find_blockparty_member_in_group(&self.pool, group_id, address)
            .await?
            .ok_or(BlockpartyServiceError::NotMember)?;

        let now = now_ms();
        let (member_token, hash_for_db) = if member.member_token_hash.is_none() {
            let t = InvitationToken::generate()?;
            let h = t.hash();
            (Some(t.into_inner()), Some(h))
        } else {
            (None, None)
        };

        // Set confirmedAt if null; otherwise leave existing timestamp.
        let confirmed_at = Some(member.confirmed_at.unwrap_or(now));
        let hash_str = hash_for_db
            .as_ref()
            .map(|h| h.as_str())
            .or(member.member_token_hash.as_deref());

        // Atomic: persist the confirm AND recompute the group status in one
        // TX. A crash between the two (the old non-atomic version) could
        // leave a fully-confirmed party permanently stuck in CONFIRMING —
        // never routable despite every member having confirmed.
        let mut tx = self.pool.begin().await.map_err(bp_db::DbError::from)?;
        bp_db::update_blockparty_member_confirmed(
            &mut *tx,
            group_id,
            address,
            confirmed_at,
            hash_str,
            now,
        )
        .await?;
        let outcome = recompute_status_in_tx(&mut tx, group_id, now).await?;
        tx.commit().await.map_err(bp_db::DbError::from)?;
        if let Some(o) = outcome {
            self.apply_status_side_effects(group_id, &o).await;
        }
        Ok(MarkMemberConfirmedResult { member_token })
    }

    /// Member-token-gated re-confirmation. Used by members to flip
    /// `confirmedAt` back to non-null after an admin splits-edit reset
    /// their confirmation. Does NOT mint a new token — the persistent
    /// token from the original accept is the auth here.
    pub async fn confirm_as_member(
        &self,
        group_id: Uuid,
        address: &AddressId,
        member_token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        let member = self
            .require_member_token(group_id, address, member_token)
            .await?;
        if member.confirmed_at.is_some() {
            return Ok(()); // idempotent
        }
        let now = now_ms();
        // Atomic confirm + status recompute — see mark_member_confirmed.
        let mut tx = self.pool.begin().await.map_err(bp_db::DbError::from)?;
        bp_db::update_blockparty_member_confirmed(
            &mut *tx,
            group_id,
            address,
            Some(now),
            member.member_token_hash.as_deref(),
            now,
        )
        .await?;
        let outcome = recompute_status_in_tx(&mut tx, group_id, now).await?;
        tx.commit().await.map_err(bp_db::DbError::from)?;
        if let Some(o) = outcome {
            self.apply_status_side_effects(group_id, &o).await;
        }
        Ok(())
    }

    /// Explicit DRAFT → CONFIRMING transition. Validates the splits
    /// sum first. CONFIRMING/READY are no-ops; ACTIVE/DISSOLVED reject.
    pub async fn transition_to_confirming(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<BlockpartyStatus, BlockpartyServiceError> {
        let group = self.require_admin_token(group_id, token).await?;
        let status = group
            .status
            .parse::<BlockpartyStatus>()
            .map_err(|_| BlockpartyServiceError::InvalidState)?;
        match status {
            BlockpartyStatus::Confirming | BlockpartyStatus::Ready => return Ok(status),
            BlockpartyStatus::Active | BlockpartyStatus::Dissolved => {
                return Err(BlockpartyServiceError::InvalidState)
            }
            BlockpartyStatus::Draft => {}
        }
        let members = bp_db::list_blockparty_members_for_group(&self.pool, group_id).await?;
        if members.is_empty() {
            return Err(BlockpartyServiceError::NoMembers);
        }
        let sum: i32 = members.iter().map(|m| m.percent_bp).sum();
        if sum != TOTAL_PERCENT_BP {
            return Err(BlockpartyServiceError::InvalidSplitsSum);
        }
        let now = now_ms();
        bp_db::update_blockparty_group_status(
            &self.pool,
            group_id,
            BlockpartyStatus::Confirming.as_str(),
            now,
        )
        .await?;
        self.cache
            .set_admin_status(&group.admin_address, group_id, BlockpartyStatus::Confirming)
            .await;
        self.recompute_status(group_id).await?;
        Ok(BlockpartyStatus::Confirming)
    }

    /// Promotes CONFIRMING → READY when all members are confirmed;
    /// demotes READY → CONFIRMING otherwise. **Always** updates the
    /// admin-address cache so the routing guards don't see a stale
    /// status — see the load-bearing invariant note at file top.
    ///
    /// The DB read+write is wrapped in its own transaction
    /// ([`recompute_status_in_tx`]) so the status the row ends up with is
    /// always consistent with the member roster read in the same TX.
    /// Callers that need the member-write AND this recompute to be atomic
    /// (the two confirm paths) call `recompute_status_in_tx` directly
    /// inside their own TX instead.
    async fn recompute_status(&self, group_id: Uuid) -> Result<(), BlockpartyServiceError> {
        let mut tx = self.pool.begin().await.map_err(bp_db::DbError::from)?;
        let outcome = recompute_status_in_tx(&mut tx, group_id, now_ms()).await?;
        tx.commit().await.map_err(bp_db::DbError::from)?;
        if let Some(o) = outcome {
            self.apply_status_side_effects(group_id, &o).await;
        }
        Ok(())
    }

    /// Non-DB side-effects of a status recompute, run AFTER the TX commits:
    /// size the coinbase reservation (when the party is now READY) and
    /// refresh the routing-guard cache. Both are idempotent.
    ///
    /// The reservation is sized after the status flip (not before, as the
    /// previous non-atomic version did). The ~1 ms window where status is
    /// READY but the reservation hasn't grown yet is harmless: the
    /// Blockparty distribution trimmer rolls any members beyond the budget
    /// into the pool-fee output, so a block built in that window is still
    /// VALID (only fairness, not validity, depends on the reservation —
    /// see `bp_blockparty::build_blockparty_distribution`).
    async fn apply_status_side_effects(&self, group_id: Uuid, outcome: &RecomputeOutcome) {
        if outcome.target == BlockpartyStatus::Ready {
            if let Some(reservation) = self.reservation.as_ref() {
                reservation
                    .ensure_capacity_for_members(outcome.members_len)
                    .await;
            }
        }
        self.cache
            .set_admin_status(&outcome.admin_address, group_id, outcome.target)
            .await;
        // Admin routing changed (status flip) — invalidate a separate Front's
        // cache. Covers confirm_as_member + transition_to_confirming.
        self.notify_changed().await;
    }

    /// Dissolve a party. Gated by `DISSOLVE_COOLDOWN_MS` of zero-share
    /// silence when the party is ACTIVE. DRAFT/CONFIRMING/READY may
    /// dissolve immediately (no rented hashpower in flight).
    pub async fn dissolve_group(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        let group = self.require_admin_token(group_id, token).await?;
        let status = group
            .status
            .parse::<BlockpartyStatus>()
            .map_err(|_| BlockpartyServiceError::InvalidState)?;
        if matches!(status, BlockpartyStatus::Dissolved) {
            return Ok(()); // idempotent
        }
        // Cooldown only applies once shares have landed.
        if matches!(status, BlockpartyStatus::Active) {
            if let Some(last) = group.last_share_at {
                let now = now_ms();
                if now - last < DISSOLVE_COOLDOWN_MS {
                    return Err(BlockpartyServiceError::DissolveCooldown);
                }
            }
        }

        let now = now_ms();
        bp_db::update_blockparty_group_dissolved(&self.pool, group_id, now, now).await?;
        self.cache
            .set_admin_status(&group.admin_address, group_id, BlockpartyStatus::Dissolved)
            .await;
        // Admin stops routing — invalidate a separate Front's cache (dissolve
        // bypasses apply_status_side_effects).
        self.notify_changed().await;
        Ok(())
    }

    /// Update `rentalProviderHint`. Admin-token gated. Trims the hint,
    /// truncates to 64 chars, stores `None` when the result is empty.
    /// Returns the stored value so the controller can echo it back.
    pub async fn update_rental_hint(
        &self,
        group_id: Uuid,
        hint: Option<&str>,
        token: Option<&str>,
    ) -> Result<Option<String>, BlockpartyServiceError> {
        let _group = self.require_admin_token(group_id, token).await?;
        let cleaned: Option<String> = hint.and_then(|h| {
            let t = h.trim();
            if t.is_empty() {
                None
            } else {
                let truncated = &t[..t.len().min(64)];
                Some(truncated.to_owned())
            }
        });
        bp_db::update_blockparty_group_rental_hint(
            &self.pool,
            group_id,
            cleaned.as_deref(),
            now_ms(),
        )
        .await?;
        Ok(cleaned)
    }

    // ─── Share / block hooks ───────────────────────────────────────

    /// Refreshes `lastShareAt` on every share for the admin's address
    /// and promotes READY → ACTIVE on the first share. Promotion is
    /// restricted to READY — defensive against races where the status
    /// changed between route-decision and share-accept.
    pub async fn on_share_accepted(
        &self,
        admin_address: &AddressId,
    ) -> Result<(), BlockpartyServiceError> {
        let Some(entry) = self.cache.get_admin(admin_address).await else {
            return Ok(());
        };
        let Some(group) = bp_db::find_blockparty_group(&self.pool, entry.group_id).await? else {
            return Ok(());
        };
        if group.status == BlockpartyStatus::Dissolved.as_str() {
            return Ok(());
        }
        let current = group
            .status
            .parse::<BlockpartyStatus>()
            .map_err(|_| BlockpartyServiceError::InvalidState)?;
        let promote = matches!(current, BlockpartyStatus::Ready);
        let next = if promote {
            BlockpartyStatus::Active
        } else {
            current
        };
        let now = now_ms();
        bp_db::update_blockparty_group_last_share_and_status(
            &self.pool,
            entry.group_id,
            now,
            next.as_str(),
            now,
        )
        .await?;
        if promote {
            self.cache
                .set_admin_status(admin_address, entry.group_id, BlockpartyStatus::Active)
                .await;
        }
        Ok(())
    }

    /// Record a found block. Idempotent via the DB UNIQUE(groupId,
    /// blockHash) constraint and `ON CONFLICT DO NOTHING` in
    /// `insert_blockparty_block_history`. Returns the inserted row on
    /// first call, `None` on replay.
    #[allow(clippy::too_many_arguments)]
    pub async fn on_block_found(
        &self,
        group_id: Uuid,
        block_height: i32,
        block_hash: &str,
        coinbase_value_sats: bp_common::Sats,
        pool_fee_sats: bp_common::Sats,
        splits: &[BlockpartySplitSnapshot],
        found_at: Option<i64>,
    ) -> Result<Option<BlockpartyBlockHistoryRow>, BlockpartyServiceError> {
        let now = now_ms();
        let row = bp_db::insert_blockparty_block_history(
            &self.pool,
            group_id,
            block_height,
            block_hash,
            found_at.unwrap_or(now),
            coinbase_value_sats,
            pool_fee_sats,
            splits,
            now,
        )
        .await?;
        Ok(row)
    }
}

// ─── Status recompute (TX-internal) ────────────────────────────────

/// Result of a status recompute — the target status plus the data the
/// caller needs for the post-commit side-effects (reservation sizing +
/// cache refresh). `None` from [`recompute_status_in_tx`] means the
/// group is gone or in a terminal status (no recompute applies).
struct RecomputeOutcome {
    target: BlockpartyStatus,
    members_len: usize,
    admin_address: AddressId,
}

/// The DB half of a status recompute, runnable inside a caller-supplied
/// transaction. Reads the group + member roster and writes the new
/// status — all on the same connection, so the persisted status is
/// always consistent with the roster it was derived from.
///
/// The two confirm paths (`mark_member_confirmed` / `confirm_as_member`)
/// call this INSIDE the same TX as their member-confirm write, which
/// closes the stuck-state where a crash between the confirm and the
/// recompute left a fully-confirmed party permanently CONFIRMING (never
/// routable). `recompute_status` wraps it in a standalone TX for callers
/// that don't need that coupling.
///
/// Promotes CONFIRMING → READY when all members are confirmed; demotes
/// READY → CONFIRMING otherwise. Terminal statuses (DRAFT / ACTIVE /
/// DISSOLVED) are left untouched.
async fn recompute_status_in_tx(
    conn: &mut sqlx::PgConnection,
    group_id: Uuid,
    now_ms: i64,
) -> Result<Option<RecomputeOutcome>, BlockpartyServiceError> {
    let Some(group) = bp_db::find_blockparty_group(&mut *conn, group_id).await? else {
        return Ok(None);
    };
    let current = group
        .status
        .parse::<BlockpartyStatus>()
        .map_err(|_| BlockpartyServiceError::InvalidState)?;
    // Only the two transient statuses participate.
    if !matches!(
        current,
        BlockpartyStatus::Confirming | BlockpartyStatus::Ready
    ) {
        return Ok(None);
    }

    let members = bp_db::list_blockparty_members_for_group(&mut *conn, group_id).await?;
    let all_confirmed = !members.is_empty() && members.iter().all(|m| m.confirmed_at.is_some());
    let target = if all_confirmed {
        BlockpartyStatus::Ready
    } else {
        BlockpartyStatus::Confirming
    };

    if current != target {
        bp_db::update_blockparty_group_status(&mut *conn, group_id, target.as_str(), now_ms)
            .await?;
    }

    Ok(Some(RecomputeOutcome {
        target,
        members_len: members.len(),
        admin_address: group.admin_address,
    }))
}

// ─── Validators ────────────────────────────────────────────────────

fn validate_name(name: &str) -> Result<(), BlockpartyServiceError> {
    let trimmed = name.trim();
    if trimmed.len() < NAME_MIN_LEN || trimmed.len() > NAME_MAX_LEN {
        return Err(BlockpartyServiceError::InvalidName);
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(BlockpartyServiceError::InvalidName);
    }
    Ok(())
}

fn validate_email(email: &str) -> Result<(), BlockpartyServiceError> {
    let trimmed = email.trim();
    if trimmed.is_empty() || trimmed.len() > bp_blockparty::EMAIL_MAX_LEN {
        return Err(BlockpartyServiceError::InvalidEmail);
    }
    // Shape: no whitespace, one @, domain contains a dot with non-empty
    // parts before and after the last dot (local@domain.tld).
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return Err(BlockpartyServiceError::InvalidEmail);
    }
    let at = trimmed
        .find('@')
        .ok_or(BlockpartyServiceError::InvalidEmail)?;
    if at == 0 {
        return Err(BlockpartyServiceError::InvalidEmail);
    }
    let domain = &trimmed[at + 1..];
    if domain.is_empty() || domain.contains('@') {
        return Err(BlockpartyServiceError::InvalidEmail);
    }
    // Domain must have a dot with non-empty TLD after it.
    let last_dot = domain
        .rfind('.')
        .ok_or(BlockpartyServiceError::InvalidEmail)?;
    if last_dot == 0 || last_dot == domain.len() - 1 {
        return Err(BlockpartyServiceError::InvalidEmail);
    }
    Ok(())
}

fn validate_percent_bp(bp: i32) -> Result<(), BlockpartyServiceError> {
    if !(MIN_PERCENT_BP..=MAX_PERCENT_BP).contains(&bp) {
        return Err(BlockpartyServiceError::InvalidPercent);
    }
    Ok(())
}

fn assert_editable(group: &BlockpartyGroupRow) -> Result<(), BlockpartyServiceError> {
    let status = group
        .status
        .parse::<BlockpartyStatus>()
        .map_err(|_| BlockpartyServiceError::InvalidState)?;
    if !status.is_editable() {
        return Err(BlockpartyServiceError::NotEditable);
    }
    Ok(())
}

#[cfg(test)]
mod email_validation_tests {
    use super::*;

    #[test]
    fn valid_emails_pass() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("a.b+tag@sub.domain.org").is_ok());
        assert!(validate_email("x@y.z").is_ok());
    }

    #[test]
    fn dotless_domain_fails() {
        assert!(validate_email("user@nodot").is_err());
        assert!(validate_email("user@localhost").is_err());
    }

    #[test]
    fn no_local_part_fails() {
        assert!(validate_email("@example.com").is_err());
    }

    #[test]
    fn no_at_sign_fails() {
        assert!(validate_email("userexample.com").is_err());
    }

    #[test]
    fn whitespace_fails() {
        assert!(validate_email("user @example.com").is_err());
        assert!(validate_email("user@exam ple.com").is_err());
    }

    #[test]
    fn empty_tld_fails() {
        assert!(validate_email("user@domain.").is_err());
    }

    #[test]
    fn multiple_at_signs_fail() {
        assert!(validate_email("user@@example.com").is_err());
    }
}
