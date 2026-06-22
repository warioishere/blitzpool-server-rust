// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-address best-difficulty cache. Backed by in-memory storage with a
//! Redis-swappable trait surface (scope 2026-05-16: kept simple until
//! Phase-7 wiring decides on Redis).
//!
//! The trait surface stays small + `Send + Sync + 'static`-bound so a
//! Redis-backed impl can drop in later without touching call sites.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

/// Cached snapshot of the fields we care about on
/// `address_settings_entity`.
#[derive(Clone, Debug, PartialEq)]
pub struct CachedAddressSettings {
    pub best_difficulty: f64,
    pub best_difficulty_user_agent: Option<String>,
}

impl CachedAddressSettings {
    /// Predicate used by [`crate::hooks::BestDifficultySink`] to decide
    /// whether the accepted share's `submission_difficulty` warrants a
    /// write-through. Strictly greater — equal values are no-ops.
    pub fn should_update(&self, candidate_difficulty: f64) -> bool {
        candidate_difficulty.is_finite()
            && candidate_difficulty > 0.0
            && candidate_difficulty > self.best_difficulty
    }
}

/// Cache surface. Cheap to clone via `Arc` at the call site.
#[async_trait]
pub trait AddressSettingsCache: Send + Sync + 'static {
    /// Read the cached settings. Cold path returns `None` so the caller
    /// can decide whether to warm from PG (we currently lazy-warm via
    /// [`Self::set`] on the first share).
    async fn get(&self, address: &str) -> Option<CachedAddressSettings>;

    /// Insert or overwrite the cache entry. Called post-PG-persist when
    /// a new best-difficulty share arrives.
    async fn set(&self, address: &str, settings: CachedAddressSettings);

    /// Drop the cache entry for `address` — used by admin/settings APIs
    /// that mutate `address_settings_entity` out-of-band so the cache
    /// can't serve stale data.
    async fn invalidate(&self, address: &str);

    /// Drop every entry. Used by tests + by admin "reset" endpoints.
    async fn invalidate_all(&self);

    /// Current entry count (for the `/api/admin/cache-health` surface
    /// + the eviction guard against `address_cache_capacity`).
    async fn len(&self) -> usize;

    /// Convenience predicate; default impl in terms of [`Self::len`].
    async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

/// In-memory hash-map-backed impl. Cheap (single `Mutex<HashMap>`),
/// suitable for our single-node deployment. A Redis-backed impl can
/// drop in later by satisfying the same trait.
///
/// Eviction policy: hard cap at `capacity`. When the cap is reached,
/// further inserts are silently dropped — the share path still works
/// (the next read just sees `None` and lazy-warms again). Simpler than
/// LRU; revisit if profiling shows a hot cap-clash pattern.
pub struct InMemoryAddressSettingsCache {
    inner: Mutex<HashMap<String, CachedAddressSettings>>,
    capacity: usize,
}

impl InMemoryAddressSettingsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::with_capacity(capacity.min(1024))),
            capacity,
        }
    }
}

#[async_trait]
impl AddressSettingsCache for InMemoryAddressSettingsCache {
    async fn get(&self, address: &str) -> Option<CachedAddressSettings> {
        self.inner
            .lock()
            .expect("address cache poisoned")
            .get(address)
            .cloned()
    }

    async fn set(&self, address: &str, settings: CachedAddressSettings) {
        let mut guard = self.inner.lock().expect("address cache poisoned");
        // Hard cap: drop overflow inserts silently (caller will re-warm
        // on next read). UPDATE for an existing key always succeeds.
        if guard.contains_key(address) || guard.len() < self.capacity {
            guard.insert(address.to_string(), settings);
        }
    }

    async fn invalidate(&self, address: &str) {
        self.inner
            .lock()
            .expect("address cache poisoned")
            .remove(address);
    }

    async fn invalidate_all(&self) {
        self.inner.lock().expect("address cache poisoned").clear();
    }

    async fn len(&self) -> usize {
        self.inner.lock().expect("address cache poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cs(d: f64, ua: &str) -> CachedAddressSettings {
        CachedAddressSettings {
            best_difficulty: d,
            best_difficulty_user_agent: Some(ua.to_string()),
        }
    }

    #[tokio::test]
    async fn set_then_get_returns_inserted() {
        let cache = InMemoryAddressSettingsCache::new(100);
        cache.set("bc1qalice", cs(100.0, "bitaxe")).await;
        let v = cache.get("bc1qalice").await;
        assert_eq!(v, Some(cs(100.0, "bitaxe")));
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let cache = InMemoryAddressSettingsCache::new(100);
        assert!(cache.get("bc1qmissing").await.is_none());
    }

    #[tokio::test]
    async fn set_overwrites_existing_entry() {
        let cache = InMemoryAddressSettingsCache::new(100);
        cache.set("bc1qalice", cs(50.0, "v1")).await;
        cache.set("bc1qalice", cs(200.0, "v2")).await;
        assert_eq!(cache.get("bc1qalice").await, Some(cs(200.0, "v2")));
    }

    #[tokio::test]
    async fn invalidate_removes_only_target_entry() {
        let cache = InMemoryAddressSettingsCache::new(100);
        cache.set("bc1qalice", cs(100.0, "x")).await;
        cache.set("bc1qbob", cs(200.0, "y")).await;
        cache.invalidate("bc1qalice").await;
        assert!(cache.get("bc1qalice").await.is_none());
        assert_eq!(cache.get("bc1qbob").await, Some(cs(200.0, "y")));
    }

    #[tokio::test]
    async fn invalidate_all_clears_everything() {
        let cache = InMemoryAddressSettingsCache::new(100);
        cache.set("bc1qalice", cs(100.0, "x")).await;
        cache.set("bc1qbob", cs(200.0, "y")).await;
        cache.invalidate_all().await;
        assert_eq!(cache.len().await, 0);
    }

    #[tokio::test]
    async fn capacity_cap_drops_overflow_inserts() {
        let cache = InMemoryAddressSettingsCache::new(2);
        cache.set("a", cs(1.0, "x")).await;
        cache.set("b", cs(2.0, "x")).await;
        cache.set("c", cs(3.0, "x")).await;
        assert_eq!(cache.len().await, 2, "overflow insert dropped silently");
        assert!(cache.get("c").await.is_none());
    }

    #[tokio::test]
    async fn capacity_cap_still_allows_updating_existing_keys() {
        let cache = InMemoryAddressSettingsCache::new(2);
        cache.set("a", cs(1.0, "x")).await;
        cache.set("b", cs(2.0, "x")).await;
        // At cap, but "a" already exists → update is allowed.
        cache.set("a", cs(99.0, "y")).await;
        assert_eq!(cache.get("a").await, Some(cs(99.0, "y")));
    }

    #[test]
    fn should_update_strictly_greater() {
        let s = CachedAddressSettings {
            best_difficulty: 100.0,
            best_difficulty_user_agent: None,
        };
        assert!(s.should_update(101.0));
        assert!(!s.should_update(100.0), "equal must NOT trigger update");
        assert!(!s.should_update(50.0));
    }

    #[test]
    fn should_update_rejects_non_finite_and_non_positive() {
        let s = CachedAddressSettings {
            best_difficulty: 0.0,
            best_difficulty_user_agent: None,
        };
        assert!(!s.should_update(f64::NAN));
        assert!(!s.should_update(f64::INFINITY));
        assert!(!s.should_update(0.0));
        assert!(!s.should_update(-1.0));
    }
}
