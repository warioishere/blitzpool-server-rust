// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! In-memory routing cache. The stratum layer hits this on every share
//! to decide whether the connected miner's address should route to a
//! Blockparty coinbase (admin), be considered a member of one (for
//! mode-collision / UI badging), or fall through to whatever mode the
//! address resolves to elsewhere.
//!
//! **Load-bearing invariant**: `set_admin_status` MUST be called from
//! every state-transition site (`recompute_status`, `on_share_accepted`,
//! `dissolve_group`). If the cache holds a stale status the routing
//! guards either keep an unconfirmed admin's reward in the pool-fee
//! fallback or skip a confirmed party's coinbase entirely.

use std::collections::HashMap;
use std::sync::Arc;

use bp_blockparty::BlockpartyStatus;
use bp_common::AddressId;
use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::BlockpartyServiceError;

/// Cached admin-side entry. `status` drives the two routing predicates
/// (READY/ACTIVE → coinbase, DRAFT/CONFIRMING → pending-fee fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminCacheEntry {
    pub group_id: Uuid,
    pub status: BlockpartyStatus,
}

/// Two-map routing index. Both maps live behind one `RwLock` so a
/// `rebuild()` atomically swaps both — the stratum layer never sees
/// a half-rebuilt state where admin lookup hits but member lookup misses.
#[derive(Debug, Default)]
struct Inner {
    /// Admin address → routable entry. Populated for every non-dissolved
    /// party.
    admin: HashMap<AddressId, AdminCacheEntry>,
    /// Member address → group id. Populated for every member row of every
    /// non-dissolved party (incl. the admin's own member row — admin is
    /// also a member with role='admin').
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

    /// `O(1)` admin lookup. Returns `None` for non-admin addresses or
    /// addresses of dissolved parties.
    pub async fn get_admin(&self, address: &AddressId) -> Option<AdminCacheEntry> {
        self.inner.read().await.admin.get(address).copied()
    }

    /// Returns a groupId only if status is `ready` or `active`.
    /// CONFIRMING/DRAFT/DISSOLVED → `None`, so shares fall through to
    /// whatever the next routing layer decides.
    pub async fn routable_group_id_for_admin(&self, address: &AddressId) -> Option<Uuid> {
        let entry = self.inner.read().await.admin.get(address).copied()?;
        entry.status.is_routable().then_some(entry.group_id)
    }

    /// When the admin address belongs to a DRAFT/CONFIRMING party,
    /// signals to the Solo-fallback path that the entire block reward
    /// should route to the pool-fee address instead of to the admin.
    /// Without this guard the admin would otherwise pocket the full
    /// reward via Solo before members confirm the splits.
    pub async fn pending_fee_route_admin(&self, address: &AddressId) -> Option<Uuid> {
        let entry = self.inner.read().await.admin.get(address).copied()?;
        entry
            .status
            .is_pending_fee_route()
            .then_some(entry.group_id)
    }

    /// `O(1)` member lookup. Returns the party's group id if `address`
    /// is a member (any role). Used for mode-collision checks against
    /// PplnsGroup and for UI mode-badging.
    pub async fn member_group_id(&self, address: &AddressId) -> Option<Uuid> {
        self.inner.read().await.member.get(address).copied()
    }

    // ─── Write paths (service-layer only) ──────────────────────────

    /// Replace the admin entry for a single address. **MUST** be called
    /// from every state transition (`recompute_status`,
    /// `on_share_accepted`, `dissolve_group`) so the routing guards
    /// don't read stale status.
    ///
    /// `status == Dissolved` removes both the admin entry and the
    /// admin's own member entry (admin is also a member row).
    pub async fn set_admin_status(
        &self,
        admin_address: &AddressId,
        group_id: Uuid,
        status: BlockpartyStatus,
    ) {
        let mut guard = self.inner.write().await;
        if matches!(status, BlockpartyStatus::Dissolved) {
            guard.admin.remove(admin_address);
            // Member row for the admin disappears too — dissolve cascades
            // on the DB side, here we keep the cache in lockstep.
            guard.member.remove(admin_address);
        } else {
            guard
                .admin
                .insert(admin_address.clone(), AdminCacheEntry { group_id, status });
            // First-time createGroup populates the admin's own member
            // entry too (admin role).
            guard.member.insert(admin_address.clone(), group_id);
        }
    }

    /// Insert a member entry (non-admin role).
    pub async fn insert_member(&self, address: &AddressId, group_id: Uuid) {
        self.inner
            .write()
            .await
            .member
            .insert(address.clone(), group_id);
    }

    /// Remove a member entry (single removeMember call).
    pub async fn remove_member(&self, address: &AddressId) {
        self.inner.write().await.member.remove(address);
    }

    /// Full rebuild from PG. Single read-lock-then-swap so the hot path
    /// never sees a partial map. Used at boot and after operations that
    /// touch many rows (bulk imports, dissolve cleanup).
    pub async fn rebuild(&self, pool: &PgPool) -> Result<(), BlockpartyServiceError> {
        let groups = bp_db::list_blockparty_groups_non_dissolved(pool).await?;
        let members = bp_db::list_all_blockparty_members(pool).await?;

        // status_by_id + admin_by_id: avoid a second SELECT for each
        // member by indexing groups once.
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
            // Members of dissolved groups are silently dropped.
        }

        let mut guard = self.inner.write().await;
        guard.admin = next_admin;
        guard.member = next_member;
        Ok(())
    }

    /// Snapshot count — diagnostics / `/metrics` gauge.
    pub async fn admin_len(&self) -> usize {
        self.inner.read().await.admin.len()
    }

    pub async fn member_len(&self) -> usize {
        self.inner.read().await.member.len()
    }
}

/// Cross-mode collision: when `bp_group_mgmt_engine::GroupService`
/// adds an address to a PPLNS group it consults this trait to refuse
/// addresses already in a Blockparty (admin OR member row counts).
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
