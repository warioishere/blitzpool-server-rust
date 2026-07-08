// SPDX-License-Identifier: AGPL-3.0-or-later

//! Trait-object surface for the bp-api crate.
//!
//! `BlockpartyService<H>` is generic over its hook trait, which makes it
//! awkward to store in the generic `bp_api::AppState<H, M>` without forcing
//! every existing handler to gain a third generic param. We hide the generic
//! behind an object-safe `#[async_trait]` trait — the api crate stores
//! `Option<Arc<dyn BlockpartyApi>>` and the dynamic dispatch cost is
//! invisible next to the JSON / SQL roundtrips per request.

use std::sync::Arc;

use async_trait::async_trait;
use bp_common::{AddressId, Sats};
use bp_group_mgmt_engine::OpenInviteTtl;
use bp_db::{
    BlockpartyBlockHistoryRow, BlockpartyGroupRow, BlockpartyMemberRow, BlockpartySplitSnapshot,
};
use uuid::Uuid;

use crate::error::BlockpartyServiceError;
use crate::hooks::BlockpartyHooks;
use crate::service::{BlockpartyCreateResult, BlockpartyService, PendingPartyFeeRoute};
use bp_blockparty::{BlockpartyDistributionResult, BlockpartyStatus};

#[async_trait]
#[allow(clippy::too_many_arguments)]
pub trait BlockpartyApi: Send + Sync {
    // ── Read paths (cache-backed) ──
    async fn routable_group_id_for_admin(&self, address: &AddressId) -> Option<Uuid>;
    async fn pending_party_fee_route(&self, address: &AddressId) -> Option<PendingPartyFeeRoute>;
    async fn member_group_id(&self, address: &AddressId) -> Option<Uuid>;

    /// Rebuild the in-memory routing cache from the DB. Used by the Front's
    /// cross-process cache-sync consumer to pick up status changes made on
    /// another process (e.g. the api).
    async fn rebuild_cache(&self) -> Result<(), BlockpartyServiceError>;

    /// Attach the cross-process cache-invalidation notifier (writer process).
    fn set_change_notifier(
        &self,
        notifier: Arc<dyn bp_group_mgmt_engine::MembershipChangeNotifier>,
    );

    // ── Read paths (DB) ──
    async fn get_group(
        &self,
        group_id: Uuid,
    ) -> Result<Option<BlockpartyGroupRow>, BlockpartyServiceError>;
    async fn list_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<BlockpartyMemberRow>, BlockpartyServiceError>;
    async fn get_history(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<BlockpartyBlockHistoryRow>, BlockpartyServiceError>;

    // ── Config readback ──
    fn pool_fee_percent(&self) -> f64;
    fn fee_address(&self) -> Option<AddressId>;

    // ── Lifecycle mutations ──
    async fn create_group(
        &self,
        name: &str,
        admin_address: &str,
        admin_percent_bp: i32,
    ) -> Result<BlockpartyCreateResult, BlockpartyServiceError>;
    async fn create_join_link(
        &self,
        group_id: Uuid,
        ttl: OpenInviteTtl,
        token: Option<&str>,
    ) -> Result<String, BlockpartyServiceError>;
    async fn request_member_confirmation(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError>;
    async fn revoke_join_link(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError>;
    async fn active_join_link(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<Option<(String, i64)>, BlockpartyServiceError>;
    async fn join_via_link(
        &self,
        link_token: &str,
        member_address: &str,
    ) -> Result<(String, Uuid), BlockpartyServiceError>;
    async fn join_link_group(
        &self,
        link_token: &str,
    ) -> Result<Option<(BlockpartyGroupRow, i64)>, BlockpartyServiceError>;
    async fn remove_member(
        &self,
        group_id: Uuid,
        member_address: &str,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError>;
    async fn update_splits(
        &self,
        group_id: Uuid,
        updates: Vec<(AddressId, i32)>,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError>;
    async fn dissolve_group(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError>;
    async fn update_rental_hint(
        &self,
        group_id: Uuid,
        hint: Option<&str>,
        token: Option<&str>,
    ) -> Result<Option<String>, BlockpartyServiceError>;
    async fn transition_to_confirming(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<BlockpartyStatus, BlockpartyServiceError>;
    async fn confirm_as_member(
        &self,
        group_id: Uuid,
        address: &AddressId,
        member_token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError>;
    /// Member-token gate for `GET /:id/member-view/:address`. Returns
    /// `Ok(())` when the token verifies; surfaces the typed errors
    /// otherwise.
    async fn verify_member_token(
        &self,
        group_id: Uuid,
        address: &AddressId,
        member_token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError>;

    // ── Share / block hooks (called from stratum, not from bp-api,
    //    but exposed here so the same trait covers all integration
    //    points) ──
    /// Build the coinbase payout distribution for the next block.
    /// `Ok(None)` for an unknown group_id; the resolver falls back to
    /// solo payouts in that case.
    async fn build_payouts(
        &self,
        group_id: Uuid,
        block_reward_sats: Sats,
    ) -> Result<Option<BlockpartyDistributionResult>, BlockpartyServiceError>;

    async fn on_share_accepted(
        &self,
        admin_address: &AddressId,
    ) -> Result<(), BlockpartyServiceError>;
    async fn on_block_found(
        &self,
        group_id: Uuid,
        block_height: i32,
        block_hash: &str,
        coinbase_value_sats: Sats,
        pool_fee_sats: Sats,
        splits: Vec<BlockpartySplitSnapshot>,
        found_at: Option<i64>,
    ) -> Result<Option<BlockpartyBlockHistoryRow>, BlockpartyServiceError>;
}

#[async_trait]
impl<H: BlockpartyHooks + 'static> BlockpartyApi for BlockpartyService<H> {
    async fn routable_group_id_for_admin(&self, address: &AddressId) -> Option<Uuid> {
        BlockpartyService::routable_group_id_for_admin(self, address).await
    }
    async fn pending_party_fee_route(&self, address: &AddressId) -> Option<PendingPartyFeeRoute> {
        BlockpartyService::pending_party_fee_route(self, address).await
    }
    async fn member_group_id(&self, address: &AddressId) -> Option<Uuid> {
        BlockpartyService::member_group_id(self, address).await
    }
    async fn rebuild_cache(&self) -> Result<(), BlockpartyServiceError> {
        BlockpartyService::rebuild_cache(self).await
    }
    fn set_change_notifier(
        &self,
        notifier: Arc<dyn bp_group_mgmt_engine::MembershipChangeNotifier>,
    ) {
        BlockpartyService::set_change_notifier(self, notifier);
    }

    async fn get_group(
        &self,
        group_id: Uuid,
    ) -> Result<Option<BlockpartyGroupRow>, BlockpartyServiceError> {
        BlockpartyService::get_group(self, group_id).await
    }
    async fn list_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<BlockpartyMemberRow>, BlockpartyServiceError> {
        BlockpartyService::list_members(self, group_id).await
    }
    async fn get_history(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<BlockpartyBlockHistoryRow>, BlockpartyServiceError> {
        BlockpartyService::get_history(self, group_id).await
    }

    fn pool_fee_percent(&self) -> f64 {
        BlockpartyService::pool_fee_percent(self)
    }
    fn fee_address(&self) -> Option<AddressId> {
        BlockpartyService::fee_address(self).cloned()
    }

    async fn create_group(
        &self,
        name: &str,
        admin_address: &str,
        admin_percent_bp: i32,
    ) -> Result<BlockpartyCreateResult, BlockpartyServiceError> {
        BlockpartyService::create_group(self, name, admin_address, admin_percent_bp).await
    }
    async fn create_join_link(
        &self,
        group_id: Uuid,
        ttl: OpenInviteTtl,
        token: Option<&str>,
    ) -> Result<String, BlockpartyServiceError> {
        BlockpartyService::create_join_link(self, group_id, ttl, token).await
    }
    async fn request_member_confirmation(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        BlockpartyService::request_member_confirmation(self, group_id, token).await
    }
    async fn revoke_join_link(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        BlockpartyService::revoke_join_link(self, group_id, token).await
    }
    async fn active_join_link(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<Option<(String, i64)>, BlockpartyServiceError> {
        BlockpartyService::active_join_link(self, group_id, token).await
    }
    async fn join_via_link(
        &self,
        link_token: &str,
        member_address: &str,
    ) -> Result<(String, Uuid), BlockpartyServiceError> {
        BlockpartyService::join_via_link(self, link_token, member_address).await
    }
    async fn join_link_group(
        &self,
        link_token: &str,
    ) -> Result<Option<(BlockpartyGroupRow, i64)>, BlockpartyServiceError> {
        BlockpartyService::join_link_group(self, link_token).await
    }
    async fn remove_member(
        &self,
        group_id: Uuid,
        member_address: &str,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        BlockpartyService::remove_member(self, group_id, member_address, token).await
    }
    async fn update_splits(
        &self,
        group_id: Uuid,
        updates: Vec<(AddressId, i32)>,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        BlockpartyService::update_splits(self, group_id, &updates, token).await
    }
    async fn dissolve_group(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        BlockpartyService::dissolve_group(self, group_id, token).await
    }

    async fn update_rental_hint(
        &self,
        group_id: Uuid,
        hint: Option<&str>,
        token: Option<&str>,
    ) -> Result<Option<String>, BlockpartyServiceError> {
        BlockpartyService::update_rental_hint(self, group_id, hint, token).await
    }

    async fn transition_to_confirming(
        &self,
        group_id: Uuid,
        token: Option<&str>,
    ) -> Result<BlockpartyStatus, BlockpartyServiceError> {
        BlockpartyService::transition_to_confirming(self, group_id, token).await
    }

    async fn confirm_as_member(
        &self,
        group_id: Uuid,
        address: &AddressId,
        member_token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        BlockpartyService::confirm_as_member(self, group_id, address, member_token).await
    }

    async fn verify_member_token(
        &self,
        group_id: Uuid,
        address: &AddressId,
        member_token: Option<&str>,
    ) -> Result<(), BlockpartyServiceError> {
        BlockpartyService::require_member_token(self, group_id, address, member_token)
            .await
            .map(|_| ())
    }

    async fn build_payouts(
        &self,
        group_id: Uuid,
        block_reward_sats: Sats,
    ) -> Result<Option<BlockpartyDistributionResult>, BlockpartyServiceError> {
        BlockpartyService::build_payouts(self, group_id, block_reward_sats).await
    }

    async fn on_share_accepted(
        &self,
        admin_address: &AddressId,
    ) -> Result<(), BlockpartyServiceError> {
        BlockpartyService::on_share_accepted(self, admin_address).await
    }
    async fn on_block_found(
        &self,
        group_id: Uuid,
        block_height: i32,
        block_hash: &str,
        coinbase_value_sats: Sats,
        pool_fee_sats: Sats,
        splits: Vec<BlockpartySplitSnapshot>,
        found_at: Option<i64>,
    ) -> Result<Option<BlockpartyBlockHistoryRow>, BlockpartyServiceError> {
        BlockpartyService::on_block_found(
            self,
            group_id,
            block_height,
            block_hash,
            coinbase_value_sats,
            pool_fee_sats,
            &splits,
            found_at,
        )
        .await
    }
}
