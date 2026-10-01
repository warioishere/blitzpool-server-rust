// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-memory `address → { group_id, active }` index, so the stratum layer
//! needs no DB round-trip per share. The map is small, so it is fully
//! rebuilt after every membership change.

use std::collections::HashMap;
use std::sync::Arc;

use bp_common::AddressId;
use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::GroupServiceError;

/// Inactive groups are cached too: the stratum layer refuses Group-Solo
/// connections for them, so the group ID matters, not just the flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupCacheEntry {
    pub group_id: Uuid,
    pub active: bool,
}

/// Cheap to clone; all clones share one map.
#[derive(Debug, Clone, Default)]
pub struct AddressCache {
    inner: Arc<RwLock<HashMap<AddressId, GroupCacheEntry>>>,
}

impl AddressCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get(&self, address: &AddressId) -> Option<GroupCacheEntry> {
        let guard = self.inner.read().await;
        guard.get(address).copied()
    }

    /// Full rebuild from PG, replacing the map atomically; members of
    /// dissolved groups are dropped.
    pub async fn rebuild(&self, pool: &PgPool) -> Result<(), GroupServiceError> {
        // Raw address strings: one malformed address must not fail the
        // boot-time rebuild and crash the pool, so it is skipped below.
        let members = bp_db::find_all_pplns_group_member_addresses(pool).await?;
        let active_by_id: HashMap<Uuid, bool> = bp_db::list_active_pplns_group_flags(pool)
            .await?
            .into_iter()
            .collect();

        let mut next = HashMap::with_capacity(members.len());
        let mut skipped = 0usize;
        for (group_id, address) in members {
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

    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }
}
