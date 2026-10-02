// SPDX-License-Identifier: AGPL-3.0-or-later

//! `BlockpartyService`: group lifecycle, token-gated mutations, routing cache.
//! Invariant: every change to a party's `status` must also call
//! [`BlockpartyCache::set_admin_status`], or routing drifts from the DB and
//! pays a confirmed party's block to the pool fee (or skips its coinbase).

use std::sync::Arc;

use bp_blockparty::{
    BlockpartyStatus, DISSOLVE_COOLDOWN_MS, MAX_PERCENT_BP, MIN_PERCENT_BP, NAME_MAX_LEN,
    NAME_MIN_LEN, TOTAL_PERCENT_BP,
};
use bp_common::AddressId;
use bp_db::{BlockpartyBlockHistoryRow, BlockpartyGroupRow, BlockpartyMemberRow};
use bp_group_mgmt::token::{AdminToken, InvitationToken, TokenHash};
use bp_group_mgmt_engine::{AddressCache as PplnsAddressCache, OpenInviteTtl};
use uuid::Uuid;

use crate::cache::BlockpartyCache;
use crate::error::BlockpartyServiceError;
use crate::hooks::BlockpartyHooks;
use crate::payouts::BlockpartyPayouts;
use crate::util::normalize_address;
use bp_common::now_ms;

// ─── Config + result types ─────────────────────────────────────────

/// Re-sizes the Blockparty coinbase reservation at `Confirming → Ready`,
/// when the roster becomes routable. High-water only. A raise reaches
/// templates one TDP cycle late, so `[blockparty].coinbase_weight_budget`
/// must already cover a realistic party; this is only headroom.
#[async_trait::async_trait]
pub trait CoinbaseReservation: Send + Sync {
    /// Room for `member_count` member outputs plus the pool-fee output.
    async fn ensure_capacity_for_members(&self, member_count: usize);
}

#[derive(Debug)]
pub struct BlockpartyCreateResult {
    pub group: BlockpartyGroupRow,
    pub admin_member: BlockpartyMemberRow,
    /// Plaintext admin token — surfaces to the human exactly once.
    pub admin_token: String,
    pub pool_fee_percent: f64,
}

#[derive(Debug)]
pub struct MarkMemberConfirmedResult {
    /// `Some` only when this confirmation minted a fresh token; a re-confirm
    /// with the existing token returns `None`.
    pub member_token: Option<String>,
}

/// The address that receives the WHOLE block reward when the admin of an
/// unconfirmed party mines on the Solo fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPartyFeeRoute {
    pub fee_address: AddressId,
}

// ─── Service struct ────────────────────────────────────────────────

/// Exists only with a warm routing cache: [`Self::load`] is the sole
/// constructor, so a process that never reads the cache holds
/// [`BlockpartyPayouts`] instead and cannot reach a cold one.
pub struct BlockpartyService {
    payouts: BlockpartyPayouts,
    hooks: Arc<dyn BlockpartyHooks>,
    cache: BlockpartyCache,
    /// Read-only; for the mode-collision check against PPLNS groups.
    pplns_cache: PplnsAddressCache,
    /// `None` in tests and when the Blockparty TDP stream is not wired.
    reservation: Option<Arc<dyn CoinbaseReservation>>,
    /// Publishes a `"blockparty"` invalidation on every mutation so a
    /// separate Stratum Front rebuilds its routing cache.
    change_notifier:
        Arc<std::sync::OnceLock<Arc<dyn bp_group_mgmt_engine::MembershipChangeNotifier>>>,
}

impl BlockpartyService {
    /// Builds the service and fills its routing cache from PG.
    pub async fn load(
        payouts: BlockpartyPayouts,
        hooks: Arc<dyn BlockpartyHooks>,
        pplns_cache: PplnsAddressCache,
    ) -> Result<Self, BlockpartyServiceError> {
        let service = Self {
            payouts,
            hooks,
            cache: BlockpartyCache::new(),
            pplns_cache,
            reservation: None,
            change_notifier: Arc::new(std::sync::OnceLock::new()),
        };
        service.rebuild_cache().await?;
        Ok(service)
    }

    /// Set-once. Wire on the process hosting the API writers.
    pub fn set_change_notifier(
        &self,
        notifier: Arc<dyn bp_group_mgmt_engine::MembershipChangeNotifier>,
    ) {
        let _ = self.change_notifier.set(notifier);
    }

    /// Best-effort. `"blockparty"` must match
    /// `bp_share_stream::cache_kind::BLOCKPARTY`.
    async fn notify_changed(&self) {
        if let Some(n) = self.change_notifier.get() {
            n.membership_changed("blockparty").await;
        }
    }

    /// `None` leaves the reservation at its configured floor.
    pub fn with_coinbase_reservation(
        mut self,
        reservation: Option<Arc<dyn CoinbaseReservation>>,
    ) -> Self {
        self.reservation = reservation;
        self
    }

    pub fn cache(&self) -> BlockpartyCache {
        self.cache.clone()
    }

    /// The DB-only payout half, shared with processes that hold no cache.
    pub fn payouts(&self) -> &BlockpartyPayouts {
        &self.payouts
    }

    /// Full rebuild from PG; the state-transition methods keep the cache in
    /// sync between rebuilds.
    pub async fn rebuild_cache(&self) -> Result<(), BlockpartyServiceError> {
        self.cache.rebuild(&self.payouts.pool).await
    }

    // ─── Read paths (cache-backed, stratum hot path) ───────────────

    /// `None` unless the admin's party is `ready` or `active`.
    pub async fn routable_group_id_for_admin(&self, address: &AddressId) -> Option<Uuid> {
        self.cache.routable_group_id_for_admin(address).await
    }

    /// `Some` when the admin's party is draft/confirming and a fee address
    /// is configured; `None` means the plain Solo coinbase.
    pub async fn pending_party_fee_route(
        &self,
        address: &AddressId,
    ) -> Option<PendingPartyFeeRoute> {
        let _gid = self.cache.pending_fee_route_admin(address).await?;
        let fee_address = self.payouts.config.fee_address.clone()?;
        Some(PendingPartyFeeRoute { fee_address })
    }

    /// Group id of the non-dissolved party `address` is a member of.
    pub async fn member_group_id(&self, address: &AddressId) -> Option<Uuid> {
        self.cache.member_group_id(address).await
    }

    pub async fn get_group(
        &self,
        group_id: Uuid,
    ) -> Result<Option<BlockpartyGroupRow>, BlockpartyServiceError> {
        Ok(bp_db::find_blockparty_group(&self.payouts.pool, group_id).await?)
    }

    pub async fn list_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<BlockpartyMemberRow>, BlockpartyServiceError> {
        Ok(bp_db::list_blockparty_members_for_group(&self.payouts.pool, group_id).await?)
    }

    pub async fn get_history(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<BlockpartyBlockHistoryRow>, BlockpartyServiceError> {
        Ok(bp_db::list_blockparty_block_history(&self.payouts.pool, group_id).await?)
    }

    // ─── Token gating ──────────────────────────────────────────────

    /// The group, if `token` is its admin token. A dissolved group is
    /// `NotFound`.
    pub async fn require_admin_token(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<BlockpartyGroupRow, BlockpartyServiceError> {
        let provided = token.ok_or(BlockpartyServiceError::MissingToken)?;
        let group = bp_db::find_blockparty_group(&self.payouts.pool, group_id)
            .await?
            .ok_or(BlockpartyServiceError::NotFound)?;
        if group.status == BlockpartyStatus::Dissolved.as_str() {
            return Err(BlockpartyServiceError::NotFound);
        }
        let stored = TokenHash::from_hex(group.admin_token_hash.clone());
        if !stored.verifies(provided) {
            return Err(BlockpartyServiceError::InvalidToken);
        }
        Ok(group)
    }

    pub async fn require_member_token(
        &self,
        group_id: Uuid,
        address: &AddressId,
        token: Option<&str>,
    ) -> Result<BlockpartyMemberRow, BlockpartyServiceError> {
        let provided = token.ok_or(BlockpartyServiceError::MissingMemberToken)?;
        let member = bp_db::find_blockparty_member_in_group(&self.payouts.pool, group_id, address)
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

    /// The admin token is returned in plaintext exactly once.
    pub async fn create_group(
        &self,
        name: &str,
        admin_address: &str,
        admin_percent_bp: i32,
    ) -> Result<BlockpartyCreateResult, BlockpartyServiceError> {
        validate_name(name)?;
        validate_percent_bp(admin_percent_bp)?;
        let admin_addr = normalize_address(admin_address)?;

        // The admin address needs a confirmed email or a signature ownership
        // proof. The email comes from the binding, never from the client; a
        // signature-only admin stores "".
        let admin_email = self.hooks.verified_email_for(&admin_addr).await;
        if admin_email.is_none()
            && !bp_db::is_address_ownership_verified(&self.payouts.pool, &admin_addr).await?
        {
            return Err(BlockpartyServiceError::EmailNotVerified);
        }
        let admin_email = admin_email
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_default();

        if self.pplns_cache.get(&admin_addr).await.is_some() {
            return Err(BlockpartyServiceError::AddressInPplnsGroup);
        }
        if bp_db::find_blockparty_group_by_name(&self.payouts.pool, name)
            .await?
            .is_some()
        {
            return Err(BlockpartyServiceError::NameTaken);
        }
        if bp_db::find_blockparty_group_by_admin_address(&self.payouts.pool, &admin_addr)
            .await?
            .is_some()
        {
            return Err(BlockpartyServiceError::AdminAddressTaken);
        }
        if bp_db::find_blockparty_member_by_address(&self.payouts.pool, &admin_addr)
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
            &self.payouts.pool,
            id,
            name,
            &admin_addr,
            admin_hash.as_str(),
            BlockpartyStatus::Draft.as_str(),
            now,
        )
        .await?;

        // Creating the party is the admin's confirmation.
        let admin_member = bp_db::insert_blockparty_member(
            &self.payouts.pool,
            id,
            &admin_addr,
            &admin_email,
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
            pool_fee_percent: self.payouts.config.fee_percent,
        })
    }

    /// Admin-gated. The member's email comes from its verified binding;
    /// the first add moves the party from draft to confirming.
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
        if bp_db::find_blockparty_member_by_address(&self.payouts.pool, &address)
            .await?
            .is_some()
        {
            return Err(BlockpartyServiceError::AddressInBlockparty);
        }
        if self.pplns_cache.get(&address).await.is_some() {
            return Err(BlockpartyServiceError::AddressInPplnsGroup);
        }

        // Confirmed email or signature ownership proof required.
        let email = self.hooks.verified_email_for(&address).await;
        if email.is_none()
            && !bp_db::is_address_ownership_verified(&self.payouts.pool, &address).await?
        {
            return Err(BlockpartyServiceError::EmailNotVerified);
        }
        let email = email.map(|e| e.to_ascii_lowercase()).unwrap_or_default();

        let now = now_ms();
        let inserted = match bp_db::insert_blockparty_member(
            &self.payouts.pool,
            group_id,
            &address,
            &email,
            percent_bp,
            "member",
            None, // confirmed_at = null; member must accept invitation
            now,
        )
        .await
        {
            Ok(row) => row,
            Err(bp_db::DbError::Sqlx(sqlx::Error::Database(db_err)))
                if db_err.code().as_deref() == Some("23505") =>
            {
                // A concurrent add slipped past the lookup above;
                // UNIQUE(address) caught it.
                return Err(BlockpartyServiceError::AddressInBlockparty);
            }
            Err(e) => return Err(e.into()),
        };

        if group.status == BlockpartyStatus::Draft.as_str() {
            bp_db::update_blockparty_group_status(
                &self.payouts.pool,
                group_id,
                BlockpartyStatus::Confirming.as_str(),
                now,
            )
            .await?;
            self.cache
                .set_admin_status(&group.admin_address, group_id, BlockpartyStatus::Confirming)
                .await;
        }
        self.cache.insert_member(&address, group_id).await;
        self.recompute_status(group_id).await?;

        Ok(inserted)
    }

    /// Create or replace the group's single join link; returns its token.
    pub async fn create_join_link(
        &self,
        group_id: Uuid,
        ttl: OpenInviteTtl,
        token: Option<&str>,
    ) -> Result<String, BlockpartyServiceError> {
        let group = self.require_admin_token(group_id, token).await?;
        assert_editable(&group)?;
        let now = now_ms();
        let expires_at = now + ttl.as_ms();
        let link = InvitationToken::generate()?;
        bp_db::upsert_blockparty_join_link(
            &self.payouts.pool,
            group_id,
            link.as_str(),
            expires_at,
            now,
        )
        .await?;
        Ok(link.as_str().to_owned())
    }

    /// Stamps `confirmationRequestedAt`. Members see the confirm prompt only
    /// after this, so nobody confirms before the real splits are assigned.
    pub async fn request_member_confirmation(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        let group = self.require_admin_token(group_id, token).await?;
        assert_editable(&group)?;
        bp_db::set_blockparty_confirmation_requested(&self.payouts.pool, group_id, now_ms())
            .await?;
        Ok(())
    }

    pub async fn revoke_join_link(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        let _ = self.require_admin_token(group_id, token).await?;
        bp_db::delete_blockparty_join_link(&self.payouts.pool, group_id).await?;
        Ok(())
    }

    /// The non-expired join link as `(token, expires_at)`, so the admin can
    /// re-display it without minting a new one.
    pub async fn active_join_link(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<Option<(String, i64)>, BlockpartyServiceError> {
        let _ = self.require_admin_token(group_id, token).await?;
        let link = bp_db::find_blockparty_join_link_for_group(&self.payouts.pool, group_id).await?;
        Ok(link
            .filter(|l| l.expires_at >= now_ms())
            .map(|l| (l.token, l.expires_at)))
    }

    /// Self-service join; the address proves itself by email or signature.
    /// Joins unconfirmed at a 0 % placeholder split and returns
    /// `(member_token, group_id)` for confirming the split later.
    pub async fn join_via_link(
        &self,
        link_token: &str,
        member_address: &str,
    ) -> Result<(String, Uuid), BlockpartyServiceError> {
        let link = bp_db::find_blockparty_join_link_by_token(&self.payouts.pool, link_token)
            .await?
            .ok_or(BlockpartyServiceError::NotFound)?;
        let now = now_ms();
        // Expired looks like unknown, so link validity does not leak.
        if link.expires_at < now {
            return Err(BlockpartyServiceError::NotFound);
        }
        let group = bp_db::find_blockparty_group(&self.payouts.pool, link.group_id)
            .await?
            .ok_or(BlockpartyServiceError::NotFound)?;
        assert_editable(&group)?;

        let address = normalize_address(member_address)?;
        if address == group.admin_address {
            return Err(BlockpartyServiceError::AdminCannotRejoin);
        }
        if bp_db::find_blockparty_member_by_address(&self.payouts.pool, &address)
            .await?
            .is_some()
        {
            return Err(BlockpartyServiceError::AddressInBlockparty);
        }
        if self.pplns_cache.get(&address).await.is_some() {
            return Err(BlockpartyServiceError::AddressInPplnsGroup);
        }

        let email = self.hooks.verified_email_for(&address).await;
        if email.is_none()
            && !bp_db::is_address_ownership_verified(&self.payouts.pool, &address).await?
        {
            return Err(BlockpartyServiceError::EmailNotVerified);
        }
        let email = email.map(|e| e.to_ascii_lowercase()).unwrap_or_default();

        match bp_db::insert_blockparty_member(
            &self.payouts.pool,
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

        let t = InvitationToken::generate()?;
        let hash = t.hash();
        bp_db::update_blockparty_member_confirmed(
            &self.payouts.pool,
            group.id,
            &address,
            None,
            Some(hash.as_str()),
            now,
        )
        .await?;

        if group.status == BlockpartyStatus::Draft.as_str() {
            bp_db::update_blockparty_group_status(
                &self.payouts.pool,
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

    /// `(group, link_expires_at)` for a valid link; `None` if the link is
    /// unknown or expired or the group dissolved.
    pub async fn join_link_group(
        &self,
        link_token: &str,
    ) -> Result<Option<(BlockpartyGroupRow, i64)>, BlockpartyServiceError> {
        let link = match bp_db::find_blockparty_join_link_by_token(&self.payouts.pool, link_token)
            .await?
        {
            Some(l) => l,
            None => return Ok(None),
        };
        if link.expires_at < now_ms() {
            return Ok(None);
        }
        let group = bp_db::find_blockparty_group(&self.payouts.pool, link.group_id).await?;
        Ok(group
            .filter(|g| g.dissolved_at.is_none())
            .map(|g| (g, link.expires_at)))
    }

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
        let affected =
            bp_db::delete_blockparty_member(&self.payouts.pool, group_id, &address).await?;
        if affected == 0 {
            return Err(BlockpartyServiceError::NotMember);
        }
        self.cache.remove_member(&address).await;
        self.recompute_status(group_id).await?;
        Ok(())
    }

    /// Non-admin members lose their confirmation and must re-confirm the new
    /// splits; authoring the edit confirms the admin.
    pub async fn update_splits(
        &self,
        group_id: Uuid,
        updates: &[(AddressId, i32)],
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        let group = self.require_admin_token(group_id, token).await?;
        assert_editable(&group)?;

        // No total-sum check: only the changed subset arrives here.
        for (_, p) in updates {
            validate_percent_bp(*p)?;
        }

        let now = now_ms();
        let mut tx = self
            .payouts
            .pool
            .begin()
            .await
            .map_err(bp_db::DbError::from)?;
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
        // Same TX, so splits never change without resetting confirmations.
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
        // Stamped unconditionally so an admin row with a null confirmedAt
        // is covered too.
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

        // Drops the status back to confirming.
        self.recompute_status(group_id).await?;
        Ok(())
    }

    /// Idempotent. Mints the member token on the first call and returns its
    /// plaintext only then.
    pub async fn mark_member_confirmed(
        &self,
        group_id: Uuid,
        address: &AddressId,
    ) -> Result<MarkMemberConfirmedResult, BlockpartyServiceError> {
        let member = bp_db::find_blockparty_member_in_group(&self.payouts.pool, group_id, address)
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

        let confirmed_at = Some(member.confirmed_at.unwrap_or(now));
        let hash_str = hash_for_db
            .as_ref()
            .map(|h| h.as_str())
            .or(member.member_token_hash.as_deref());

        // One TX with the status recompute: a crash between them would leave
        // a fully-confirmed party stuck in confirming, never routable.
        let mut tx = self
            .payouts
            .pool
            .begin()
            .await
            .map_err(bp_db::DbError::from)?;
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

    /// Re-confirmation after a splits edit reset it, authenticated by the
    /// existing member token; mints no new token.
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
        let mut tx = self
            .payouts
            .pool
            .begin()
            .await
            .map_err(bp_db::DbError::from)?;
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

    /// Draft to confirming, only once the splits sum to 100 %.
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
        let members =
            bp_db::list_blockparty_members_for_group(&self.payouts.pool, group_id).await?;
        if members.is_empty() {
            return Err(BlockpartyServiceError::NoMembers);
        }
        let sum: i32 = members.iter().map(|m| m.percent_bp).sum();
        if sum != TOTAL_PERCENT_BP {
            return Err(BlockpartyServiceError::InvalidSplitsSum);
        }
        let now = now_ms();
        bp_db::update_blockparty_group_status(
            &self.payouts.pool,
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

    /// [`recompute_status_in_tx`] in a standalone TX, then the cache update
    /// the module invariant requires.
    async fn recompute_status(&self, group_id: Uuid) -> Result<(), BlockpartyServiceError> {
        let mut tx = self
            .payouts
            .pool
            .begin()
            .await
            .map_err(bp_db::DbError::from)?;
        let outcome = recompute_status_in_tx(&mut tx, group_id, now_ms()).await?;
        tx.commit().await.map_err(bp_db::DbError::from)?;
        if let Some(o) = outcome {
            self.apply_status_side_effects(group_id, &o).await;
        }
        Ok(())
    }

    /// Post-commit side effects of a recompute. Blockparty does not
    /// weight-trim, so a party beyond the configured floor relies on this
    /// reservation raise, which reaches templates a TDP cycle late.
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
        self.notify_changed().await;
    }

    /// An active party must first be share-silent for
    /// `DISSOLVE_COOLDOWN_MS`, so no rented hashpower is in flight.
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
        if matches!(status, BlockpartyStatus::Active) {
            if let Some(last) = group.last_share_at {
                let now = now_ms();
                if now - last < DISSOLVE_COOLDOWN_MS {
                    return Err(BlockpartyServiceError::DissolveCooldown);
                }
            }
        }

        // Members go with the status flip in one TX: UNIQUE(address) would
        // otherwise lock them out of every later party, and the
        // custom-extranonce Solo check reads the same rows.
        let now = now_ms();
        let mut tx = self
            .payouts
            .pool
            .begin()
            .await
            .map_err(bp_db::DbError::from)?;
        bp_db::delete_blockparty_members_for_group(&mut *tx, group_id).await?;
        bp_db::delete_blockparty_join_link(&mut *tx, group_id).await?;
        bp_db::update_blockparty_group_dissolved(&mut *tx, group_id, now, now).await?;
        tx.commit().await.map_err(bp_db::DbError::from)?;
        self.cache
            .set_admin_status(&group.admin_address, group_id, BlockpartyStatus::Dissolved)
            .await;
        // Dissolve bypasses apply_status_side_effects.
        self.notify_changed().await;
        Ok(())
    }

    /// Returns the stored (trimmed, truncated) hint.
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
            &self.payouts.pool,
            group_id,
            cleaned.as_deref(),
            now_ms(),
        )
        .await?;
        Ok(cleaned)
    }

    // ─── Share / block hooks ───────────────────────────────────────

    /// Refreshes `lastShareAt` and promotes ready to active. Only from
    /// ready, because the status may have changed since routing.
    pub async fn on_share_accepted(
        &self,
        admin_address: &AddressId,
    ) -> Result<(), BlockpartyServiceError> {
        let Some(entry) = self.cache.get_admin(admin_address).await else {
            return Ok(());
        };
        let Some(group) = bp_db::find_blockparty_group(&self.payouts.pool, entry.group_id).await?
        else {
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
            &self.payouts.pool,
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
}

// ─── Status recompute (TX-internal) ────────────────────────────────

/// What the post-commit side effects need from a recompute.
struct RecomputeOutcome {
    target: BlockpartyStatus,
    members_len: usize,
    admin_address: AddressId,
}

/// Confirming becomes ready when all members are confirmed, ready falls back
/// otherwise; other statuses are untouched (`None`). Runs in the caller's TX
/// so the status always matches the roster it was read from, and the confirm
/// paths stay atomic with their member write.
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
