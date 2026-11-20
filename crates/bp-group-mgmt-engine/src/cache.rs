// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-memory `address → group_id` index of the groups that are not
//! dissolved, so the stratum layer needs no DB round-trip per share. The map
//! is small, so it is fully rebuilt after every membership change.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bp_common::AddressId;
use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::GroupServiceError;

/// Cheap to clone; all clones share one map.
#[derive(Debug, Clone, Default)]
pub struct AddressCache {
    inner: Arc<RwLock<HashMap<AddressId, Uuid>>>,
}

impl AddressCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get(&self, address: &AddressId) -> Option<Uuid> {
        let guard = self.inner.read().await;
        guard.get(address).copied()
    }

    /// Full rebuild from PG, replacing the map atomically; members of
    /// dissolved groups are dropped.
    pub async fn rebuild(&self, pool: &PgPool) -> Result<(), GroupServiceError> {
        // Raw address strings: one malformed address must not fail the
        // boot-time rebuild and crash the pool, so it is skipped below.
        let members = bp_db::find_all_pplns_group_member_addresses(pool).await?;
        let live: HashSet<Uuid> = bp_db::list_live_pplns_group_ids(pool)
            .await?
            .into_iter()
            .collect();

        let mut next = HashMap::with_capacity(members.len());
        let mut skipped = 0usize;
        for (group_id, address) in members {
            if !live.contains(&group_id) {
                continue;
            }
            match AddressId::new(address) {
                Ok(addr) => {
                    next.insert(addr, group_id);
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
