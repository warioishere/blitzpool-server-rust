// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared Blockparty service owner, like [`crate::group_service`]: the API and
//! the Stratum layer need the same handle so membership state and routing
//! cache stay coherent. Opt-in: without `[blockparty]` every surface falls back
//! to its Solo-equivalent default.

use std::sync::Arc;

use async_trait::async_trait;
use bp_blockparty_engine::{
    BlockpartyHooks, BlockpartyPayouts, BlockpartyService, CoinbaseReservation,
};
use bp_common::{AddressId, MiningMode, StreamKind};
use bp_config::AppConfig;
use bp_db::{find_address_email, Db};
use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareSink};
use thiserror::Error;
use tracing::{info, warn};

use crate::boot::FoundationHandles;
use crate::group_service::SharedGroupService;

/// Production [`BlockpartyHooks`] impl. Looks up verified email
/// bindings against the same `pplns_address_email` table the
/// Group-Solo invitation flow uses — the binding is the cross-mode
/// trust anchor.
pub(crate) struct ProductionBlockpartyHooks {
    db: Db,
}

#[async_trait]
impl BlockpartyHooks for ProductionBlockpartyHooks {
    async fn verified_email_for(&self, address: &AddressId) -> Option<String> {
        match find_address_email(self.db.pool(), address).await {
            Ok(Some(row)) if row.verified_at.is_some() => Some(row.email),
            Ok(_) => None,
            Err(err) => {
                warn!(%err, address = %address.as_str(), "blockparty: email-binding lookup failed");
                None
            }
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum BlockpartySpawnError {
    #[error("blockparty cache rebuild failed: {0}")]
    Rebuild(#[from] bp_blockparty_engine::BlockpartyServiceError),
}

pub(crate) struct SharedBlockparty {
    pub(crate) service: Arc<BlockpartyService>,
    /// Membership reader — handed to `GroupService::set_blockparty_reader`
    /// so the PPLNS-group side rejects addresses already in a Blockparty.
    pub(crate) membership_reader: Arc<dyn bp_group_mgmt_engine::BlockpartyMembershipReader>,
}

/// The cache-carrying Blockparty service over `payouts`, for the roles in
/// [`crate::membership::Membership`].
pub(crate) async fn spawn(
    cfg: &AppConfig,
    foundation: &FoundationHandles,
    payouts: &BlockpartyPayouts,
    group_service: &SharedGroupService,
) -> Result<SharedBlockparty, BlockpartySpawnError> {
    let hooks = Arc::new(ProductionBlockpartyHooks {
        db: foundation.db.clone(),
    });

    // PplnsGroup membership cache is the cross-mode collision check
    // source of truth — share the same handle the GroupService owns.
    let pplns_cache = group_service.service.address_cache();

    // Size the reservation to a party's roster when it reaches Ready. The
    // configured budget is the floor the stream booted with; without the
    // Blockparty TDP stream (`--skip-tdp`) it stays fixed there.
    let reservation: Option<Arc<dyn CoinbaseReservation>> = foundation
        .alt_tdp
        .get(&StreamKind::Blockparty)
        .zip(cfg.blockparty.as_ref())
        .map(|(tdp, bp_cfg)| {
            Arc::new(crate::blockparty_reservation::TdpCoinbaseReservation::new(
                tdp.clone(),
                bp_cfg.coinbase_weight_budget,
            )) as Arc<dyn CoinbaseReservation>
        });

    info!("blockparty: loading routing cache");
    let concrete = Arc::new(
        BlockpartyService::load(payouts.clone(), hooks, pplns_cache)
            .await?
            .with_coinbase_reservation(reservation),
    );
    info!("blockparty: routing cache warm");
    // Stash the routing cache as a membership reader for the
    // GroupService bidirectional collision check.
    let membership_reader: Arc<dyn bp_group_mgmt_engine::BlockpartyMembershipReader> =
        Arc::new(concrete.cache());

    Ok(SharedBlockparty {
        service: concrete,
        membership_reader,
    })
}

/// Calls `on_share_accepted` for every Blockparty share: the first promotes
/// READY → ACTIVE, later ones refresh `lastShareAt` (the dissolve-cooldown
/// gate). Reads the producer-stamped `share.mode`, so it needs no mode gate.
/// Front only: it reads the admin from the routing cache.
pub(crate) struct BlockpartyAcceptedShareSink {
    service: Arc<BlockpartyService>,
}

impl BlockpartyAcceptedShareSink {
    pub(crate) fn new(service: Arc<BlockpartyService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl SharedAcceptedShareSink for BlockpartyAcceptedShareSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        if share.mode != MiningMode::Blockparty {
            return;
        }
        let Ok(addr) = AddressId::new(share.address.to_string()) else {
            return;
        };
        if let Err(err) = self.service.on_share_accepted(&addr).await {
            warn!(
                %err,
                address = share.address,
                "BlockpartyAcceptedShareSink: on_share_accepted failed"
            );
        }
    }
}
