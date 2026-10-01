// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-memory routing cache, read on every share. Every status transition
//! must call `set_admin_status`; a stale status routes a confirmed party's
//! block to the pool fee, or skips its coinbase.

use std::collections::HashMap;
use std::sync::Arc;

use bp_blockparty::BlockpartyStatus;
use bp_common::AddressId;
use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::BlockpartyServiceError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminCacheEntry {
    pub group_id: Uuid,
    pub status: BlockpartyStatus,
}

/// One lock over both maps so a rebuild swaps them together.
#[derive(Debug, Default)]
struct Inner {
    /// Non-dissolved parties only.
    admin: HashMap<AddressId, AdminCacheEntry>,
    /// Includes the admin's own member row.
    member: HashMap<AddressId, Uuid>,
}

#[derive(Debug, Clone, Default)]
pub struct BlockpartyCache {
    inner: Arc<RwLock<Inner>>,
}

impl BlockpartyCache {
    pub fn new() -> Self {
        Self::default()
    }

    // ─── Read paths (stratum hot path) ─────────────────────────────

    pub async fn get_admin(&self, address: &AddressId) -> Option<AdminCacheEntry> {
        self.inner.read().await.admin.get(address).copied()
    }

    /// `Some` only for a ready or active party.
    pub async fn routable_group_id_for_admin(&self, address: &AddressId) -> Option<Uuid> {
        let entry = self.inner.read().await.admin.get(address).copied()?;
        entry.status.is_routable().then_some(entry.group_id)
    }

    /// `Some` for a draft or confirming party: the Solo fallback then pays
    /// the whole reward to the pool fee, so the admin cannot pocket it
    /// before the members confirm the splits.
    pub async fn pending_fee_route_admin(&self, address: &AddressId) -> Option<Uuid> {
        let entry = self.inner.read().await.admin.get(address).copied()?;
        entry
            .status
            .is_pending_fee_route()
            .then_some(entry.group_id)
    }

    /// Any role, admin included.
    pub async fn member_group_id(&self, address: &AddressId) -> Option<Uuid> {
        self.inner.read().await.member.get(address).copied()
    }

    // ─── Write paths (service-layer only) ──────────────────────────

    /// Must be called from every status transition. `Dissolved` also drops
    /// the group's member entries, matching the dissolve's row deletion.
    pub async fn set_admin_status(
        &self,
        admin_address: &AddressId,
        group_id: Uuid,
        status: BlockpartyStatus,
    ) {
        let mut guard = self.inner.write().await;
        if matches!(status, BlockpartyStatus::Dissolved) {
            guard.admin.remove(admin_address);
            guard.member.retain(|_, g| *g != group_id);
        } else {
            guard
                .admin
                .insert(admin_address.clone(), AdminCacheEntry { group_id, status });
            guard.member.insert(admin_address.clone(), group_id);
        }
    }

    pub async fn insert_member(&self, address: &AddressId, group_id: Uuid) {
        self.inner
            .write()
            .await
            .member
            .insert(address.clone(), group_id);
    }

    pub async fn remove_member(&self, address: &AddressId) {
        self.inner.write().await.member.remove(address);
    }

    /// Full rebuild from PG, swapped in under one write lock so readers
    /// never see a partial map.
    pub async fn rebuild(&self, pool: &PgPool) -> Result<(), BlockpartyServiceError> {
        let groups = bp_db::list_blockparty_groups_non_dissolved(pool).await?;
        let members = bp_db::list_all_blockparty_members(pool).await?;

        let mut status_by_id: HashMap<Uuid, BlockpartyStatus> =
            HashMap::with_capacity(groups.len());
        let mut admin_by_id: HashMap<Uuid, AddressId> = HashMap::with_capacity(groups.len());
        for g in &groups {
            if let Ok(s) = g.status.parse::<BlockpartyStatus>() {
                status_by_id.insert(g.id, s);
                admin_by_id.insert(g.id, g.admin_address.clone());
            }
        }

        let mut next_admin: HashMap<AddressId, AdminCacheEntry> =
            HashMap::with_capacity(groups.len());
        for g in &groups {
            if let Some(&status) = status_by_id.get(&g.id) {
                next_admin.insert(
                    g.admin_address.clone(),
                    AdminCacheEntry {
                        group_id: g.id,
                        status,
                    },
                );
            }
        }

        let mut next_member: HashMap<AddressId, Uuid> = HashMap::with_capacity(members.len());
        for m in members {
            if status_by_id.contains_key(&m.group_id) {
                next_member.insert(m.address, m.group_id);
            }
        }

        let mut guard = self.inner.write().await;
        guard.admin = next_admin;
        guard.member = next_member;
        Ok(())
    }
}

/// Lets `GroupService` refuse a PPLNS join for an address already in a
/// Blockparty, admin or member.
#[async_trait::async_trait]
impl bp_group_mgmt_engine::BlockpartyMembershipReader for BlockpartyCache {
    async fn is_member(&self, address: &AddressId) -> bool {
        let guard = self.inner.read().await;
        guard.member.contains_key(address) || guard.admin.contains_key(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::AddressId;

    fn addr(s: &str) -> AddressId {
        AddressId::new(s).expect("test address")
    }

    #[tokio::test]
    async fn routable_only_when_status_routable() {
        let cache = BlockpartyCache::new();
        let admin = addr("bc1qadmin1");
        let gid = Uuid::new_v4();

        // DRAFT → not routable but is pending-fee.
        cache
            .set_admin_status(&admin, gid, BlockpartyStatus::Draft)
            .await;
        assert!(cache.routable_group_id_for_admin(&admin).await.is_none());
        assert_eq!(cache.pending_fee_route_admin(&admin).await, Some(gid));

        // CONFIRMING → same.
        cache
            .set_admin_status(&admin, gid, BlockpartyStatus::Confirming)
            .await;
        assert!(cache.routable_group_id_for_admin(&admin).await.is_none());
        assert_eq!(cache.pending_fee_route_admin(&admin).await, Some(gid));

        // READY → routable, NOT pending-fee.
        cache
            .set_admin_status(&admin, gid, BlockpartyStatus::Ready)
            .await;
        assert_eq!(cache.routable_group_id_for_admin(&admin).await, Some(gid));
        assert!(cache.pending_fee_route_admin(&admin).await.is_none());

        // ACTIVE → routable, NOT pending-fee.
        cache
            .set_admin_status(&admin, gid, BlockpartyStatus::Active)
            .await;
        assert_eq!(cache.routable_group_id_for_admin(&admin).await, Some(gid));
        assert!(cache.pending_fee_route_admin(&admin).await.is_none());

        // DISSOLVED → cleared from both maps.
        cache
            .set_admin_status(&admin, gid, BlockpartyStatus::Dissolved)
            .await;
        assert!(cache.routable_group_id_for_admin(&admin).await.is_none());
        assert!(cache.pending_fee_route_admin(&admin).await.is_none());
        assert!(cache.member_group_id(&admin).await.is_none());
    }

    #[tokio::test]
    async fn admin_status_keeps_admin_as_member_until_dissolved() {
        let cache = BlockpartyCache::new();
        let admin = addr("bc1qadmin2");
        let gid = Uuid::new_v4();

        cache
            .set_admin_status(&admin, gid, BlockpartyStatus::Draft)
            .await;
        assert_eq!(cache.member_group_id(&admin).await, Some(gid));

        cache
            .set_admin_status(&admin, gid, BlockpartyStatus::Confirming)
            .await;
        assert_eq!(cache.member_group_id(&admin).await, Some(gid));

        cache
            .set_admin_status(&admin, gid, BlockpartyStatus::Dissolved)
            .await;
        assert!(cache.member_group_id(&admin).await.is_none());
    }

    #[tokio::test]
    async fn dissolve_drops_every_member_of_that_group_only() {
        let cache = BlockpartyCache::new();
        let admin = addr("bc1qadmin4");
        let bob = addr("bc1qbobyyy");
        let gid = Uuid::new_v4();
        let other_admin = addr("bc1qadmin5");
        let carol = addr("bc1qcarol");
        let other = Uuid::new_v4();
        cache
            .set_admin_status(&admin, gid, BlockpartyStatus::Ready)
            .await;
        cache.insert_member(&bob, gid).await;
        cache
            .set_admin_status(&other_admin, other, BlockpartyStatus::Ready)
            .await;
        cache.insert_member(&carol, other).await;

        cache
            .set_admin_status(&admin, gid, BlockpartyStatus::Dissolved)
            .await;

        assert!(cache.member_group_id(&bob).await.is_none());
        assert!(cache.member_group_id(&admin).await.is_none());
        assert_eq!(cache.member_group_id(&carol).await, Some(other));
        assert_eq!(cache.member_group_id(&other_admin).await, Some(other));
    }

    #[tokio::test]
    async fn insert_remove_member_independent_of_admin() {
        let cache = BlockpartyCache::new();
        let admin = addr("bc1qadmin3");
        let bob = addr("bc1qbobxxx");
        let gid = Uuid::new_v4();
        cache
            .set_admin_status(&admin, gid, BlockpartyStatus::Confirming)
            .await;
        cache.insert_member(&bob, gid).await;

        assert_eq!(cache.member_group_id(&bob).await, Some(gid));
        // Bob is not an admin — guards must both be None.
        assert!(cache.routable_group_id_for_admin(&bob).await.is_none());
        assert!(cache.pending_fee_route_admin(&bob).await.is_none());

        cache.remove_member(&bob).await;
        assert!(cache.member_group_id(&bob).await.is_none());
        // Admin entry untouched.
        assert!(cache.member_group_id(&admin).await.is_some());
    }
}
