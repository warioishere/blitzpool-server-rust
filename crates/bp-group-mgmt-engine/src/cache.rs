// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-memory `address → { group_id, active }` index so the stratum
//! layer can answer "what group does this miner belong to and is that
//! group active?" without a DB round-trip per share.
//!
//! Refreshed after every membership change (create, add, remove,
//! transfer, dissolve, round-reset). The map is small — capped at
//! the active member count — so a full rebuild on each change is the
//! simplest correct strategy.

use std::collections::HashMap;
use std::sync::Arc;

use bp_common::AddressId;
use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::GroupServiceError;

/// Cache row for one address. Empty groups (`active = false`) still
/// surface because the stratum layer refuses Group-Solo connections
/// for *inactive* groups too — knowing the group ID matters, not just
/// the active flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupCacheEntry {
    pub group_id: Uuid,
    pub active: bool,
}

/// Concurrent address → group entry cache. `Arc`-clonable so multiple
/// services + stratum sessions share the same map without copying.
#[derive(Debug, Clone, Default)]
pub struct AddressCache {
    inner: Arc<RwLock<HashMap<AddressId, GroupCacheEntry>>>,
}

impl AddressCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot lookup. `O(1)` under the read lock — never blocks
    /// writers for more than a clone of `GroupCacheEntry` (Copy).
    pub async fn get(&self, address: &AddressId) -> Option<GroupCacheEntry> {
        let guard = self.inner.read().await;
        guard.get(address).copied()
    }

    /// Full rebuild from PG: reads every member row pool-wide, joins
    /// against non-dissolved groups in-memory, and replaces the map
    /// atomically. Single SELECT-per-rebuild is deliberate because
    /// membership changes are rare.
    pub async fn rebuild(&self, pool: &PgPool) -> Result<(), GroupServiceError> {
        // Lenient reads (raw address strings, no `AddressId` decode): one
        // malformed legacy address must NOT fail the whole boot-time rebuild
        // and crash the pool. We parse + skip invalid ones below instead.
        let members = bp_db::find_all_pplns_group_member_addresses(pool).await?;
        let active_by_id: HashMap<Uuid, bool> = bp_db::list_active_pplns_group_flags(pool)
            .await?
            .into_iter()
            .collect();

        let mut next = HashMap::with_capacity(members.len());
        let mut skipped = 0usize;
        for (group_id, address) in members {
            // Members of dissolved groups are silently dropped.
            let Some(&active) = active_by_id.get(&group_id) else {
                continue;
            };
            match AddressId::new(address) {
                Ok(addr) => {
                    next.insert(addr, GroupCacheEntry { group_id, active });
                }
                Err(err) => {
                    skipped += 1;
                    tracing::warn!(
                        %group_id, %err,
                        "group-cache: skipping member with invalid address (legacy/corrupt \
                         data); it won't route to its group until the row is fixed"
                    );
                }
            }
        }
        if skipped > 0 {
            tracing::warn!(
                skipped,
                "group-cache: rebuilt, some members skipped (invalid address)"
            );
        }
        let mut guard = self.inner.write().await;
        *guard = next;
        Ok(())
    }

    /// Snapshot map size — used by tests and operator dashboards
    /// (a stratum-share path doesn't need this, but a `/metrics` gauge
    /// might).
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    /// `true` iff the cache currently holds zero entries.
    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }
}
