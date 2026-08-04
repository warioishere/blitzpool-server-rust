// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared `GroupService` owner — Phase 7.4b.
//!
//! Both the bp-api HTTP layer (`api_server.rs`) and the SV1 Stratum
//! layer (`stratum_v1.rs`) need access to the same
//! [`GroupService<ProductionGroupServiceHooks>`]: the API performs
//! group lifecycle operations, while Stratum reads the
//! [`AddressCache`](bp_group_mgmt_engine::AddressCache) on each
//! authorize to resolve `address → group_id` for mode-gate
//! population. Sharing one instance means one source of truth for
//! membership state and a single cache that both layers see.
//!
//! The cache is warmed at boot via `GroupService::rebuild_cache()`
//! so the first share doesn't pay a PG round-trip for an empty
//! cache.

use std::sync::Arc;

use bp_group_mgmt_engine::{GroupService, GroupServiceError};
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_pplns::max_coinbase_outputs;
use thiserror::Error;
use tracing::info;

use crate::boot::FoundationHandles;
use crate::hooks::{ProductionGroupServiceHooks, ProductionHooks};

/// Default kick-inactivity cutoff (days) handed to `GroupService::new`.
/// Can become configurable later.
pub(crate) const KICK_INACTIVITY_DAYS: u32 = 14;

#[derive(Debug, Error)]
pub(crate) enum GroupServiceSpawnError {
    #[error("group-service initial cache rebuild failed: {0}")]
    Rebuild(#[from] GroupServiceError),
}

/// Shared handle aggregate — clone the inner `Arc` to hand the same
/// service to multiple consumers.
#[derive(Clone)]
pub(crate) struct SharedGroupService {
    pub(crate) service: Arc<GroupService<ProductionGroupServiceHooks>>,
}

/// Construct the production `GroupService`, warm the address cache,
/// and return the shared aggregate. Failure to rebuild the cache is
/// fatal — Stratum + API both depend on a hot cache at first share.
///
/// The member ceiling comes from the Group-Solo engine's coinbase weight
/// budget, computed with the same [`max_coinbase_outputs`] that
/// `GET /api/pplns/groups/coinbase-capacity` reports, so what the UI shows and
/// what a join is refused against are one number.
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
