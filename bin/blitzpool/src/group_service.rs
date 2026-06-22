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
#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct SharedGroupService {
    pub(crate) service: Arc<GroupService<ProductionGroupServiceHooks>>,
}

/// Construct the production `GroupService`, warm the address cache,
/// and return the shared aggregate. Failure to rebuild the cache is
/// fatal — Stratum + API both depend on a hot cache at first share.
pub(crate) async fn spawn(
    foundation: &FoundationHandles,
    production_hooks: &ProductionHooks,
) -> Result<SharedGroupService, GroupServiceSpawnError> {
    let service = Arc::new(GroupService::new(
        foundation.db.pool().clone(),
        production_hooks.group_service.clone(),
        KICK_INACTIVITY_DAYS,
    ));
    info!("group-service: rebuilding address cache");
    service.rebuild_cache().await?;
    info!("group-service: address cache warm");
    Ok(SharedGroupService { service })
}
