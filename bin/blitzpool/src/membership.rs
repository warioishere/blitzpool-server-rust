// SPDX-License-Identifier: AGPL-3.0-or-later

//! The group and Blockparty services with their warm routing caches. Built
//! only on the roles that read them (front routing, API endpoints); the other
//! roles hold no instance, so no caller there can read a cache nobody filled.

use std::sync::Arc;

use async_trait::async_trait;
use bp_blockparty_engine::BlockpartyService;
use bp_common::AddressId;
use bp_group_mgmt_engine::GroupService;
use bp_mining_mode::MiningModeResult;
use bp_share_hook::{AdmissionRefusal, MinerAdmission};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::blockparty_service::SharedBlockparty;
use crate::coinbase_tags::CoinbaseTagCache;
use crate::group_service::SharedGroupService;

pub(crate) struct Membership {
    pub(crate) group: SharedGroupService,
    /// `None` unless Blockparty is configured.
    pub(crate) blockparty: Option<SharedBlockparty>,
    /// Kept current by `cache_sync` on the front.
    pub(crate) coinbase_tags: Arc<CoinbaseTagCache>,
    /// Addresses whose mode changed. `cache_sync` sends, every Stratum
    /// connection listens and closes on its own address.
    pub(crate) session_kicks: broadcast::Sender<String>,
}

/// Kicks queued per connection before it falls behind. A connection that
/// falls behind misses kicks; the next cache-sync backstop sends them again.
pub(crate) const SESSION_KICKS_CAPACITY: usize = 1024;

impl Membership {
    pub(crate) fn blockparty_service(&self) -> Option<Arc<BlockpartyService>> {
        self.blockparty.as_ref().map(|bp| bp.service.clone())
    }

    /// The one admission decision SV1, SV2 and JDP ask before a session.
    pub(crate) fn admission(&self) -> Arc<dyn MinerAdmission> {
        Arc::new(BlockpartyAdmission(self.blockparty_service()))
    }
}

/// Refuses the admin of a Blockparty that is not Ready; without Blockparty
/// configured, nobody.
pub(crate) struct BlockpartyAdmission(pub(crate) Option<Arc<BlockpartyService>>);

#[async_trait]
impl MinerAdmission for BlockpartyAdmission {
    async fn refusal(&self, address: &str) -> Option<AdmissionRefusal> {
        let blockparty = self.0.as_ref()?;
        let address = AddressId::new(address.to_string()).ok()?;
        blockparty
            .unready_group_id_for_admin(&address)
            .await
            .map(|_| AdmissionRefusal::BlockpartyNotReady)
    }
}

// ─── GroupLookup trait (group_id resolution) ──────────────────────

/// Address → active-group-id lookup, a trait so unit tests need no
/// `PgPool`.
#[async_trait]
pub(crate) trait GroupLookup: Send + Sync {
    /// Cache-only lookup. Returns `Some(group_id)` only when the
    /// address is in an **active** group; inactive groups + missing
    /// addresses both yield `None`.
    async fn group_for_address(&self, address: &AddressId) -> Option<Uuid>;
}

#[async_trait]
impl GroupLookup for GroupService {
    async fn group_for_address(&self, address: &AddressId) -> Option<Uuid> {
        self.get_group_for_address(address)
            .await
            .filter(|e| e.active)
            .map(|e| e.group_id)
    }
}

// ─── BlockpartyAdminLookup trait (admin → routable-party-id) ───────

/// Narrow admin lookup over `BlockpartyService`, like [`GroupLookup`]: "is this
/// address the admin of a **routable** (Ready/Active) Blockparty?". Only
/// the admin hashes in Blockparty; members are payout recipients, so the
/// mode resolves admin-keyed.
#[async_trait]
pub(crate) trait BlockpartyAdminLookup: Send + Sync {
    /// `Some(group_id)` only when `address` is the admin of a Ready/Active
    /// party (see `BlockpartyStatus::is_routable`); `None` otherwise.
    async fn routable_group_id_for_admin(&self, address: &AddressId) -> Option<Uuid>;
}

#[async_trait]
impl BlockpartyAdminLookup for BlockpartyService {
    async fn routable_group_id_for_admin(&self, address: &AddressId) -> Option<Uuid> {
        BlockpartyService::routable_group_id_for_admin(self, address).await
    }
}

/// The mode an address's memberships give it, port aside: an active team
/// (Group-Solo) wins, then being the admin of a routable (Ready/Active)
/// Blockparty, where only the admin hashes and the coinbase splits to the
/// members. `None` leaves the port's mode. Session registration and the
/// cache-sync kick check both read a membership through this.
pub(crate) async fn membership_mode(
    group: &dyn GroupLookup,
    blockparty: Option<&dyn BlockpartyAdminLookup>,
    address: &AddressId,
) -> Option<MiningModeResult> {
    if let Some(group_id) = group.group_for_address(address).await {
        return Some(MiningModeResult::GroupSolo(group_id));
    }
    match blockparty {
        Some(bp) => bp
            .routable_group_id_for_admin(address)
            .await
            .map(MiningModeResult::Blockparty),
        None => None,
    }
}
