// SPDX-License-Identifier: AGPL-3.0-or-later

//! Resolution algorithm with the small in-process cache.
//!
//! # Algorithm
//!
//! Given an address:
//!
//! 1. **Live marker wins.** Read the port-marker:
//!    - `Pplns` ⇒ return PPLNS (regardless of group / window state).
//!    - `GroupSolo` ⇒ if the address is in an *active* group, return
//!      group-solo with that group_id. **Defensive fall-through** if the
//!      group was dissolved between the mark and the read — the rest of
//!      the algorithm picks Solo/PPLNS correctly without surfacing a
//!      dangling group_id.
//!    - `Solo` ⇒ if the address is in an *active* group, return group-solo
//!      (an active membership beats a stale, self-refreshing Solo marker so a
//!      joined member switches over on its next authorize); otherwise Solo.
//!    - `None` ⇒ continue.
//! 2. **Active group wins over residual PPLNS window shares.** Group
//!    membership is an intentional admin action; PPLNS window shares may
//!    linger for hours after a port-switch. So in the fallback, the active
//!    group check beats the window check.
//! 3. **PPLNS window membership ⇒ PPLNS.**
//! 4. **Otherwise ⇒ Solo.**
//!
//! # In-process cache
//!
//! 30 s TTL. Short enough that a port-switch
//! propagates within one UI dashboard poll cycle (typical 60 s) yet long
//! enough that bursty dashboard polling doesn't spam Redis + DB on every
//! page load. Per-address keyed; `invalidate(addr)` drops a single entry
//! (used after group-membership changes).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bp_common::{AddressId, MiningMode};

use crate::reader::{
    BlockpartyMembershipReader, GroupMembershipReader, LiveMarkerReader, NoopBlockpartyReader,
    PplnsWindowReader,
};
use crate::result::MiningModeResult;

/// 30 s cache TTL.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(30);

pub struct ModeResolver<L, G, P, B = NoopBlockpartyReader> {
    marker: L,
    groups: G,
    pplns: P,
    blockparty: B,
    cache: Mutex<HashMap<AddressId, CachedEntry>>,
    cache_ttl: Duration,
}

struct CachedEntry {
    result: MiningModeResult,
    expires_at: Instant,
}

impl<L, G, P> ModeResolver<L, G, P, NoopBlockpartyReader>
where
    L: LiveMarkerReader,
    G: GroupMembershipReader,
    P: PplnsWindowReader,
{
    pub fn new(marker: L, groups: G, pplns: P) -> Self {
        Self {
            marker,
            groups,
            pplns,
            blockparty: NoopBlockpartyReader,
            cache: Mutex::new(HashMap::new()),
            cache_ttl: DEFAULT_CACHE_TTL,
        }
    }
}

impl<L, G, P, B> ModeResolver<L, G, P, B>
where
    L: LiveMarkerReader,
    G: GroupMembershipReader,
    P: PplnsWindowReader,
    B: BlockpartyMembershipReader,
{
    /// Swap in a real Blockparty reader. Without this, the resolver
    /// uses [`NoopBlockpartyReader`] and never returns
    /// `MiningMode::Blockparty`.
    pub fn with_blockparty<B2: BlockpartyMembershipReader>(
        self,
        blockparty: B2,
    ) -> ModeResolver<L, G, P, B2> {
        ModeResolver {
            marker: self.marker,
            groups: self.groups,
            pplns: self.pplns,
            blockparty,
            cache: self.cache,
            cache_ttl: self.cache_ttl,
        }
    }

    /// Override the cache TTL. Mostly useful for tests; production should
    /// stick to the default.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Resolve `address` to a mining mode. Hits the cache when possible,
    /// otherwise composes the three reader traits per the algorithm above.
    pub async fn get_mode(&self, address: &AddressId) -> MiningModeResult {
        // Cache check (short critical section, no .await held).
        {
            let cache = self.cache.lock().expect("mining-mode cache mutex poisoned");
            if let Some(entry) = cache.get(address) {
                if entry.expires_at > Instant::now() {
                    return entry.result.clone();
                }
            }
        }

        let result = self.compute(address).await;

        let expires_at = Instant::now() + self.cache_ttl;
        let mut cache = self.cache.lock().expect("mining-mode cache mutex poisoned");
        cache.insert(
            address.clone(),
            CachedEntry {
                result: result.clone(),
                expires_at,
            },
        );
        result
    }

    /// Drop the cached entry for `address` (e.g. after a group-membership
    /// change). The next `get_mode` call re-computes from the readers.
    pub fn invalidate(&self, address: &AddressId) {
        let mut cache = self.cache.lock().expect("mining-mode cache mutex poisoned");
        cache.remove(address);
    }

    async fn compute(&self, address: &AddressId) -> MiningModeResult {
        // 1) Live marker is primary.
        match self.marker.get(address).await {
            Some(MiningMode::Pplns) => return MiningModeResult::pplns(),
            Some(MiningMode::GroupSolo) => {
                if let Some(group_id) = self.groups.active_group_for(address).await {
                    return MiningModeResult::group_solo(group_id);
                }
                // Group dissolved between mark and read — fall through.
            }
            Some(MiningMode::Blockparty) => {
                // Resolve the routable group_id from the Blockparty
                // membership reader. If the group was dissolved between
                // mark and read, fall through to the slower fallback
                // chain below.
                if let Some(group_id) = self.blockparty.admin_group_for(address).await {
                    return MiningModeResult::blockparty(group_id);
                }
            }
            Some(MiningMode::Solo) => {
                // An active group membership beats a stale Solo marker. A miner
                // that solo-mined before joining a group keeps a self-refreshing
                // Solo marker (5-min TTL, re-written on every accepted share),
                // which would otherwise pin it to solo forever — approving its
                // join would never take effect. Re-checking the group here lets a
                // joined member resolve to group-solo on its next authorize
                // (e.g. after a deploy/reconnect) with no manual intervention.
                if let Some(group_id) = self.groups.active_group_for(address).await {
                    return MiningModeResult::group_solo(group_id);
                }
                return MiningModeResult::solo();
            }
            None => {}
        }

        // 2) Active group beats residual PPLNS window shares.
        if let Some(group_id) = self.groups.active_group_for(address).await {
            return MiningModeResult::group_solo(group_id);
        }

        // 3) Blockparty admin without a live-marker — covers post-
        // restart / cold-cache reads where the marker hasn't been
        // re-stamped yet.
        if let Some(group_id) = self.blockparty.admin_group_for(address).await {
            return MiningModeResult::blockparty(group_id);
        }

        // 4) PPLNS window membership.
        if self.pplns.contains(address).await {
            return MiningModeResult::pplns();
        }

        // 5) Default.
        MiningModeResult::solo()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::{GroupMembershipReader, LiveMarkerReader, PplnsWindowReader};
    use async_trait::async_trait;
    use std::collections::HashMap as Map;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn addr(s: &str) -> AddressId {
        AddressId::new(s.to_string()).expect("test address well-formed")
    }

    struct FakeMarker {
        map: Map<String, MiningMode>,
        calls: AtomicUsize,
    }
    impl FakeMarker {
        fn new(map: Map<String, MiningMode>) -> Self {
            Self {
                map,
                calls: AtomicUsize::new(0),
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }
    #[async_trait]
    impl LiveMarkerReader for FakeMarker {
        async fn get(&self, address: &AddressId) -> Option<MiningMode> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.map.get(address.as_str()).copied()
        }
    }

    struct FakeGroups(Map<String, Option<String>>);
    #[async_trait]
    impl GroupMembershipReader for FakeGroups {
        async fn active_group_for(&self, address: &AddressId) -> Option<String> {
            self.0.get(address.as_str()).cloned().flatten()
        }
    }

    struct FakePplns(Map<String, bool>);
    #[async_trait]
    impl PplnsWindowReader for FakePplns {
        async fn contains(&self, address: &AddressId) -> bool {
            self.0.get(address.as_str()).copied().unwrap_or(false)
        }
    }

    fn resolver(
        marker: FakeMarker,
        groups: FakeGroups,
        pplns: FakePplns,
    ) -> ModeResolver<FakeMarker, FakeGroups, FakePplns> {
        ModeResolver::new(marker, groups, pplns)
    }

    fn arc_resolver(
        marker: Arc<FakeMarker>,
        groups: FakeGroups,
        pplns: FakePplns,
    ) -> ModeResolver<Arc<FakeMarker>, FakeGroups, FakePplns> {
        ModeResolver::new(marker, groups, pplns)
    }

    // ── Live marker priority ─────────────────────────────────────────

    #[tokio::test]
    async fn live_marker_pplns_wins_over_group_and_window() {
        let r = resolver(
            FakeMarker::new(Map::from([("bc1qalice".into(), MiningMode::Pplns)])),
            FakeGroups(Map::from([("bc1qalice".into(), Some("grp-1".into()))])),
            FakePplns(Map::from([("bc1qalice".into(), true)])),
        );
        assert_eq!(
            r.get_mode(&addr("bc1qalice")).await,
            MiningModeResult::pplns()
        );
    }

    #[tokio::test]
    async fn live_marker_group_solo_returns_group_id_when_active() {
        let r = resolver(
            FakeMarker::new(Map::from([("bc1qalice".into(), MiningMode::GroupSolo)])),
            FakeGroups(Map::from([("bc1qalice".into(), Some("grp-7".into()))])),
            FakePplns(Map::new()),
        );
        assert_eq!(
            r.get_mode(&addr("bc1qalice")).await,
            MiningModeResult::group_solo("grp-7")
        );
    }

    #[tokio::test]
    async fn live_marker_group_solo_falls_through_when_group_dissolved() {
        // Marker says group-solo but group_for_address says None
        // (group dissolved or never active). Window shares exist → PPLNS.
        let r = resolver(
            FakeMarker::new(Map::from([("bc1qalice".into(), MiningMode::GroupSolo)])),
            FakeGroups(Map::from([("bc1qalice".into(), None)])),
            FakePplns(Map::from([("bc1qalice".into(), true)])),
        );
        assert_eq!(
            r.get_mode(&addr("bc1qalice")).await,
            MiningModeResult::pplns()
        );
    }

    #[tokio::test]
    async fn live_marker_solo_overrides_residual_pplns_window() {
        let r = resolver(
            FakeMarker::new(Map::from([("bc1qalice".into(), MiningMode::Solo)])),
            FakeGroups(Map::new()),
            FakePplns(Map::from([("bc1qalice".into(), true)])),
        );
        assert_eq!(
            r.get_mode(&addr("bc1qalice")).await,
            MiningModeResult::solo()
        );
    }

    #[tokio::test]
    async fn live_marker_solo_yields_group_solo_when_in_active_group() {
        // A miner that solo-mined before joining a group keeps a self-refreshing
        // Solo marker; an active group membership must still win, so an approved
        // join takes effect on the next authorize without manual intervention.
        let r = resolver(
            FakeMarker::new(Map::from([("bc1qalice".into(), MiningMode::Solo)])),
            FakeGroups(Map::from([("bc1qalice".into(), Some("grp-9".into()))])),
            FakePplns(Map::new()),
        );
        assert_eq!(
            r.get_mode(&addr("bc1qalice")).await,
            MiningModeResult::group_solo("grp-9")
        );
    }

    // ── Fallback ordering ────────────────────────────────────────────

    #[tokio::test]
    async fn fallback_group_membership_beats_window_shares() {
        // No live marker, active group + window shares → group wins.
        let r = resolver(
            FakeMarker::new(Map::new()),
            FakeGroups(Map::from([("bc1qalice".into(), Some("grp-1".into()))])),
            FakePplns(Map::from([("bc1qalice".into(), true)])),
        );
        assert_eq!(
            r.get_mode(&addr("bc1qalice")).await,
            MiningModeResult::group_solo("grp-1")
        );
    }

    #[tokio::test]
    async fn fallback_window_shares_yield_pplns_without_group() {
        let r = resolver(
            FakeMarker::new(Map::new()),
            FakeGroups(Map::new()),
            FakePplns(Map::from([("bc1qbob".into(), true)])),
        );
        assert_eq!(
            r.get_mode(&addr("bc1qbob")).await,
            MiningModeResult::pplns()
        );
    }

    #[tokio::test]
    async fn fallback_default_is_solo() {
        let r = resolver(
            FakeMarker::new(Map::new()),
            FakeGroups(Map::new()),
            FakePplns(Map::new()),
        );
        assert_eq!(r.get_mode(&addr("bc1qnew")).await, MiningModeResult::solo());
    }

    #[tokio::test]
    async fn inactive_group_falls_through_to_window() {
        // Group exists but isn't active (e.g. min-members threshold not met).
        // GroupMembershipReader returns None for inactive groups by contract.
        let r = resolver(
            FakeMarker::new(Map::new()),
            FakeGroups(Map::from([("bc1qalice".into(), None)])),
            FakePplns(Map::from([("bc1qalice".into(), true)])),
        );
        assert_eq!(
            r.get_mode(&addr("bc1qalice")).await,
            MiningModeResult::pplns()
        );
    }

    // ── Cache behaviour ──────────────────────────────────────────────

    #[tokio::test]
    async fn cache_hits_avoid_recomputation_within_ttl() {
        let marker = Arc::new(FakeMarker::new(Map::from([(
            "bc1qalice".into(),
            MiningMode::Pplns,
        )])));
        let r = arc_resolver(
            marker.clone(),
            FakeGroups(Map::new()),
            FakePplns(Map::new()),
        );
        r.get_mode(&addr("bc1qalice")).await;
        r.get_mode(&addr("bc1qalice")).await;
        r.get_mode(&addr("bc1qalice")).await;
        assert_eq!(marker.calls(), 1, "marker should be hit exactly once");
    }

    #[tokio::test]
    async fn cache_is_per_address() {
        let marker = Arc::new(FakeMarker::new(Map::from([
            ("bc1qalice".into(), MiningMode::Pplns),
            ("bc1qbob".into(), MiningMode::Solo),
        ])));
        let r = arc_resolver(
            marker.clone(),
            FakeGroups(Map::new()),
            FakePplns(Map::new()),
        );
        r.get_mode(&addr("bc1qalice")).await;
        r.get_mode(&addr("bc1qbob")).await;
        assert_eq!(marker.calls(), 2);
    }

    #[tokio::test]
    async fn invalidate_drops_cached_entry() {
        let marker = Arc::new(FakeMarker::new(Map::from([(
            "bc1qalice".into(),
            MiningMode::Solo,
        )])));
        let r = arc_resolver(
            marker.clone(),
            FakeGroups(Map::new()),
            FakePplns(Map::new()),
        );
        r.get_mode(&addr("bc1qalice")).await;
        r.invalidate(&addr("bc1qalice"));
        r.get_mode(&addr("bc1qalice")).await;
        assert_eq!(marker.calls(), 2);
    }

    #[tokio::test]
    async fn ttl_expiry_triggers_recomputation() {
        let marker = Arc::new(FakeMarker::new(Map::from([(
            "bc1qalice".into(),
            MiningMode::Solo,
        )])));
        // Tiny TTL so the test stays fast.
        let r = ModeResolver::new(
            marker.clone(),
            FakeGroups(Map::new()),
            FakePplns(Map::new()),
        )
        .with_cache_ttl(Duration::from_millis(10));
        r.get_mode(&addr("bc1qalice")).await;
        tokio::time::sleep(Duration::from_millis(25)).await;
        r.get_mode(&addr("bc1qalice")).await;
        assert_eq!(marker.calls(), 2);
    }
}
