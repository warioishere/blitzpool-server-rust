// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared `GroupService` owner: the API and the Stratum authorize path use one
//! instance so they see a single
//! [`AddressCache`](bp_group_mgmt_engine::AddressCache).

use std::sync::Arc;

use bp_group_mgmt_engine::{GroupService, GroupServiceError};
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_pplns::max_coinbase_outputs;
use thiserror::Error;
use tracing::info;

use crate::boot::FoundationHandles;
use crate::hooks::{ProductionGroupServiceHooks, ProductionHooks};

pub(crate) const KICK_INACTIVITY_DAYS: u32 = 14;

#[derive(Debug, Error)]
pub(crate) enum GroupServiceSpawnError {
    #[error("group-service initial cache rebuild failed: {0}")]
    Rebuild(#[from] GroupServiceError),
}

#[derive(Clone)]
pub(crate) struct SharedGroupService {
    pub(crate) service: Arc<GroupService<ProductionGroupServiceHooks>>,
}

/// A failed cache rebuild is fatal: Stratum and API need it at first share.
/// The member ceiling uses the same [`max_coinbase_outputs`] the
/// coinbase-capacity endpoint reports, so the UI and the join refusal agree.
pub(crate) async fn spawn(
    foundation: &FoundationHandles,
    production_hooks: &ProductionHooks,
    group_solo: &GroupSoloEngine,
) -> Result<SharedGroupService, GroupServiceSpawnError> {
    let cfg = group_solo.config();
    let coinbase_max_members = max_coinbase_outputs(cfg.coinbase_weight_budget);
    info!(
        coinbase_weight_budget = cfg.coinbase_weight_budget,
        coinbase_max_members,
        "group-service: group member ceiling derived from the group-solo coinbase budget"
    );
    let service = Arc::new(GroupService::new(
        foundation.db.pool().clone(),
        production_hooks.group_service.clone(),
        KICK_INACTIVITY_DAYS,
        coinbase_max_members,
    ));
    info!("group-service: rebuilding address cache");
    service.rebuild_cache().await?;
    info!("group-service: address cache warm");
    Ok(SharedGroupService { service })
}
