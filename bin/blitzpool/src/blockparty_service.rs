// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared Blockparty service owner.
//!
//! Mirrors [`crate::group_service`] but for the Blockparty mode. Both
//! the bp-api HTTP layer (`api_server.rs`) and the SV1 / SV2 stratum
//! layer (via `PayoutResolver` in `payout_resolver.rs`) need the same
//! handle so membership state + the routing cache stay coherent.
//!
//! The feature is **opt-in**: when `cfg.blockparty` is `None` this
//! module returns `Ok(None)` and every Blockparty surface falls back
//! to its safe Solo-equivalent default.

use std::sync::Arc;

use async_trait::async_trait;
use bp_blockparty_engine::{
    BlockpartyApi, BlockpartyHooks, BlockpartyService, BlockpartyServiceConfig, CoinbaseReservation,
};
use bp_common::{AddressId, MiningMode, Sats, StreamKind};
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
    #[error("invalid blockparty fee_address: {0}")]
    InvalidFeeAddress(String),
}

#[allow(dead_code)]
pub(crate) struct SharedBlockparty {
    pub(crate) service: Arc<dyn BlockpartyApi>,
    /// Membership reader — handed to `GroupService::set_blockparty_reader`
    /// so the PPLNS-group side rejects addresses already in a Blockparty.
    pub(crate) membership_reader: Arc<dyn bp_group_mgmt_engine::BlockpartyMembershipReader>,
}

/// Construct the production Blockparty handles when the feature is
/// configured. `None` cleanly disables every Blockparty code path.
pub(crate) async fn spawn(
    cfg: &AppConfig,
    foundation: &FoundationHandles,
    group_service: &SharedGroupService,
) -> Result<Option<SharedBlockparty>, BlockpartySpawnError> {
    let Some(bp_cfg) = cfg.blockparty.as_ref() else {
        info!("blockparty: feature disabled (no `[blockparty]` config block)");
        return Ok(None);
    };

    // Fee config flows from the shared `[group_fees]` lane (with
    // fallback to `[pplns]`) — both Group-Solo and Blockparty read
    // the same resolver so a single config knob applies everywhere.
    let (fee_address, fee_percent) =
        resolve_group_fees(cfg).map_err(|(raw, _)| BlockpartySpawnError::InvalidFeeAddress(raw))?;
    let svc_config = BlockpartyServiceConfig {
        fee_address,
        fee_percent,
        min_payout_sats: Sats(bp_cfg.min_payout_sats),
    };

    let hooks = Arc::new(ProductionBlockpartyHooks {
        db: foundation.db.clone(),
    });

    // PplnsGroup membership cache is the cross-mode collision check
    // source of truth — share the same handle the GroupService owns.
    let pplns_cache = group_service.service.address_cache();

    // Size the Blockparty coinbase reservation to a party's roster when it
    // reaches Ready (the engine calls the hook from `recompute_status`). Wired
    // only when the Blockparty TDP stream exists; the configured budget is the
    // floor the stream was already booted with. `None` (e.g. `--skip-tdp`)
    // leaves the reservation fixed at that floor.
    let reservation: Option<Arc<dyn CoinbaseReservation>> =
        foundation.alt_tdp.get(&StreamKind::Blockparty).map(|tdp| {
            Arc::new(crate::blockparty_reservation::TdpCoinbaseReservation::new(
                tdp.clone(),
                bp_cfg.coinbase_weight_budget,
            )) as Arc<dyn CoinbaseReservation>
        });

    let concrete = Arc::new(
        BlockpartyService::new(foundation.db.pool().clone(), hooks, pplns_cache, svc_config)
            .with_coinbase_reservation(reservation),
    );
    info!("blockparty: rebuilding routing cache");
    concrete.rebuild_cache().await?;
    info!("blockparty: routing cache warm");
    // Stash the routing cache as a membership reader for the
    // GroupService bidirectional collision check.
    let membership_reader: Arc<dyn bp_group_mgmt_engine::BlockpartyMembershipReader> =
        Arc::new(concrete.cache());

    Ok(Some(SharedBlockparty {
        service: concrete,
        membership_reader,
    }))
}

/// Resolve the shared group-fee config (Group-Solo + Blockparty).
/// `cfg.group_fees.address` / `.percent` win when set; otherwise we
/// fall back to `cfg.pplns.fee_address` / `.fee_percent` so PPLNS-only
/// deployments keep working without a config change. Returns
/// `(parsed_address, percent)` — `Err((raw, parse_error))` when the
/// resolved address string fails `AddressId::new`.
pub(crate) fn resolve_group_fees(
    cfg: &AppConfig,
) -> Result<(Option<AddressId>, f64), (String, bp_common::InvalidAddressError)> {
    let raw_address = cfg
        .group_fees
        .address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            cfg.pplns
                .as_ref()
                .map(|p| p.fee_address.trim().to_owned())
                .filter(|s| !s.is_empty())
        });
    let address = match raw_address {
        Some(raw) => match AddressId::new(raw.clone()) {
            Ok(a) => Some(a),
            Err(e) => return Err((raw, e)),
        },
        None => None,
    };
    let percent = cfg
        .group_fees
        .percent
        .or_else(|| cfg.pplns.as_ref().map(|p| p.fee_percent))
        .unwrap_or(0.0);
    Ok((address, percent))
}

/// `SharedAcceptedShareSink` that calls `on_share_accepted` for every
/// share whose connecting address resolves to Blockparty mode. Drives
/// the READY → ACTIVE auto-promotion on the first share landing on
/// the admin's address; subsequent shares refresh `lastShareAt` (the
/// dissolve-cooldown gate).
///
/// Reads the producer-stamped `share.mode` (the Core composite resolved it
/// from the mode gate at fan-out), so it holds no gate and runs unchanged on
/// the Satellite off the accepted stream.
pub(crate) struct BlockpartyAcceptedShareSink {
    service: Arc<dyn BlockpartyApi>,
}

impl BlockpartyAcceptedShareSink {
    pub(crate) fn new(service: Arc<dyn BlockpartyApi>) -> Self {
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
