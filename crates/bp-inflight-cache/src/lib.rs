// SPDX-License-Identifier: AGPL-3.0-or-later

//! `InflightResultCache<K, V, E>` — per-key dedup of concurrent
//! `compute()` callers + TTL-based result caching.
//!
//! In-flight-promise coalescing pattern. The use case: one NewTemplate fans out
//! to N OpenMiningChannel responses, each of which calls
//! `getPayoutDistribution(block_reward_sats)`. Without coalescing
//! every concurrent caller would trigger a fresh Redis-window-read +
//! PG-balance-read + math-build, hammering both backends for a
//! result that's identical across all callers.
//!
//! Behavior:
//!
//! - First caller for `key`: stamps an in-flight slot, runs the
//!   `compute` future, and broadcasts the result to any waiters.
//! - Concurrent caller for the same `key`: subscribes to the
//!   in-flight slot and awaits the broadcast.
//! - Caller within `ttl` of a previous successful compute: gets the
//!   cached `Arc<V>` directly, no compute call.
//! - Caller after a failed compute: the failed slot is removed
//!   immediately (no negative caching); the next caller retries.
//!
//! `Result<Arc<V>, Arc<E>>` is the shared shape — `Arc<E>` works
//! around the common case where `E` doesn't impl `Clone`
//! (e.g. `sqlx::Error`).

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::broadcast;

type SharedResult<V, E> = Result<Arc<V>, Arc<E>>;

enum Slot<V, E> {
    InFlight(broadcast::Sender<SharedResult<V, E>>),
    Cached { value: Arc<V>, expires_at: Instant },
}

/// Generic per-key in-flight dedup + TTL cache. Cheap to clone (the
/// inner state is `Arc<Mutex<…>>`).
pub struct InflightResultCache<K, V, E> {
    state: Arc<Mutex<HashMap<K, Slot<V, E>>>>,
    ttl: Duration,
}

// Manual `Clone` impl so `Clone` doesn't require `K: Clone, V: Clone,
// E: Clone` — only the `Arc` + `Duration` are cloned, neither of
// which constrains the type parameters.
impl<K, V, E> Clone for InflightResultCache<K, V, E> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            ttl: self.ttl,
        }
    }
}

impl<K, V, E> InflightResultCache<K, V, E>
where
    K: Hash + Eq + Clone + Send + 'static,
    V: Send + Sync + 'static,
    E: Send + Sync + Default + 'static,
{
    pub fn new(ttl: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            ttl,
        }
    }

    /// Look up `key`; if a fresh cached result exists return it; else
    /// either run `compute` (we're the leader) or subscribe to the
    /// in-flight broadcast (we're a follower).
    ///
    /// On compute success the result is cached for `ttl`. On failure
    /// the slot is dropped immediately — no negative caching, the next
    /// caller retries.
    pub async fn get_or_compute<F, Fut>(&self, key: K, compute: F) -> SharedResult<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        // Critical section: probe the cache, install in-flight slot
        // if we're the leader, otherwise grab a follower receiver.
        let receiver = {
            let mut state = self.state.lock().expect("inflight mutex poisoned");
            match state.get(&key) {
                Some(Slot::Cached { value, expires_at }) if *expires_at > Instant::now() => {
                    return Ok(value.clone());
                }
                Some(Slot::InFlight(tx)) => Some(tx.subscribe()),
                _ => {
                    // No entry OR expired entry — we're the leader.
                    let (tx, _) = broadcast::channel::<SharedResult<V, E>>(1);
                    state.insert(key.clone(), Slot::InFlight(tx));
                    None
                }
            }
        };

        if let Some(mut rx) = receiver {
            // Wait for the leader to publish. `recv()` returns
            // `RecvError::Closed` if the leader's sender was dropped
            // without sending (shouldn't happen unless the leader
            // panicked — surface as Lagged-equivalent via fresh compute
            // on retry).
            return match rx.recv().await {
                Ok(result) => result,
                Err(_) => {
                    // Leader dropped the sender — only happens if the
                    // leader's task panicked. Surface a default-constructed
                    // E so the caller's error path runs. Consumers whose
                    // error type can't reasonably default should retry by
                    // calling `get_or_compute` again themselves.
                    Err(Arc::new(E::default()))
                }
            };
        }

        // We're the leader.
        let outcome = compute().await;
        let shared: SharedResult<V, E> = match outcome {
            Ok(v) => Ok(Arc::new(v)),
            Err(e) => Err(Arc::new(e)),
        };

        // Update state + broadcast.
        let prev = {
            let mut state = self.state.lock().expect("inflight mutex poisoned");
            state.remove(&key)
        };
        if let Some(Slot::InFlight(tx)) = prev {
            // Best-effort broadcast — if there are no followers it
            // returns `Err(SendError)` which we ignore.
            let _ = tx.send(shared.clone());
        }
        if shared.is_ok() {
            let value = match &shared {
                Ok(v) => v.clone(),
                Err(_) => unreachable!(),
            };
            let mut state = self.state.lock().expect("inflight mutex poisoned");
            state.insert(
                key,
                Slot::Cached {
                    value,
                    expires_at: Instant::now() + self.ttl,
                },
            );
        }
        shared
    }

    /// Invalidate any cached or in-flight entry for `key`. The next
    /// caller will run `compute` fresh. Used by the engine after
    /// state-mutating events that would change the distribution (e.g.
    /// a new share landed, network difficulty changed).
    pub fn invalidate(&self, key: &K) {
        let mut state = self.state.lock().expect("inflight mutex poisoned");
        state.remove(key);
    }

    /// Drop all cached + in-flight entries. Useful at engine shutdown.
    pub fn clear(&self) {
        let mut state = self.state.lock().expect("inflight mutex poisoned");
        state.clear();
    }

    /// Snapshot of the current entry count (cached + in-flight).
    pub fn len(&self) -> usize {
        self.state.lock().expect("inflight mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default, Debug, Clone, PartialEq, thiserror::Error)]
    enum FakeError {
        #[default]
        #[error("unset")]
        Unset,
        #[error("computation failed")]
        Failed,
    }

    #[tokio::test]
    async fn single_call_runs_compute_once() {
        let cache: InflightResultCache<u64, u64, FakeError> =
            InflightResultCache::new(Duration::from_secs(60));
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let result = cache
            .get_or_compute(42, || async move {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Ok(100u64)
            })
            .await
            .expect("ok");
        assert_eq!(*result, 100);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn second_call_within_ttl_uses_cached_value() {
        let cache: InflightResultCache<u64, u64, FakeError> =
            InflightResultCache::new(Duration::from_secs(60));
        let calls = Arc::new(AtomicUsize::new(0));

        for _ in 0..3 {
            let calls_clone = calls.clone();
            let _ = cache
                .get_or_compute(7, || async move {
                    calls_clone.fetch_add(1, Ordering::SeqCst);
                    Ok(33u64)
                })
                .await
                .expect("ok");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "compute should run only once within TTL"
        );
    }

    #[tokio::test]
    async fn concurrent_callers_dedup_to_one_compute() {
        let cache: Arc<InflightResultCache<u64, u64, FakeError>> =
            Arc::new(InflightResultCache::new(Duration::from_secs(60)));
        let calls = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..10 {
            let cache = cache.clone();
            let calls = calls.clone();
            handles.push(tokio::spawn(async move {
                cache
                    .get_or_compute(99, || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        // Yield + sleep so others have time to subscribe.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok(777u64)
                    })
                    .await
            }));
        }

        for h in handles {
            let result = h.await.unwrap().expect("ok");
            assert_eq!(*result, 777);
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "exactly one compute despite 10 concurrent callers"
        );
    }

    #[tokio::test]
    async fn failed_compute_does_not_cache() {
        let cache: InflightResultCache<u64, u64, FakeError> =
            InflightResultCache::new(Duration::from_secs(60));
        let calls = Arc::new(AtomicUsize::new(0));

        let calls_clone = calls.clone();
        let r1 = cache
            .get_or_compute(1, || async move {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Err::<u64, _>(FakeError::Failed)
            })
            .await;
        assert!(r1.is_err());

        let calls_clone = calls.clone();
        let r2 = cache
            .get_or_compute(1, || async move {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Ok(42u64)
            })
            .await
            .expect("retry ok");
        assert_eq!(*r2, 42);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "retry runs compute again because failure isn't cached"
        );
    }

    #[tokio::test]
    async fn invalidate_drops_cache() {
        let cache: InflightResultCache<u64, u64, FakeError> =
            InflightResultCache::new(Duration::from_secs(60));
        let calls = Arc::new(AtomicUsize::new(0));

        for _ in 0..2 {
            let calls_clone = calls.clone();
            let _ = cache
                .get_or_compute(5, || async move {
                    calls_clone.fetch_add(1, Ordering::SeqCst);
                    Ok(10u64)
                })
                .await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        cache.invalidate(&5);
        let calls_clone = calls.clone();
        let _ = cache
            .get_or_compute(5, || async move {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Ok(10u64)
            })
            .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "after invalidate, next get_or_compute runs"
        );
    }

    #[tokio::test]
    async fn ttl_expiry_triggers_recompute() {
        let cache: InflightResultCache<u64, u64, FakeError> =
            InflightResultCache::new(Duration::from_millis(50));
        let calls = Arc::new(AtomicUsize::new(0));

        let calls_clone = calls.clone();
        let _ = cache
            .get_or_compute(3, || async move {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Ok(1u64)
            })
            .await;
        tokio::time::sleep(Duration::from_millis(70)).await;

        let calls_clone = calls.clone();
        let _ = cache
            .get_or_compute(3, || async move {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Ok(2u64)
            })
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn distinct_keys_run_independently() {
        let cache: InflightResultCache<u64, u64, FakeError> =
            InflightResultCache::new(Duration::from_secs(60));
        let calls = Arc::new(AtomicUsize::new(0));

        for key in 1..=5 {
            let calls_clone = calls.clone();
            let r = cache
                .get_or_compute(key, || async move {
                    calls_clone.fetch_add(1, Ordering::SeqCst);
                    Ok(key * 10)
                })
                .await
                .expect("ok");
            assert_eq!(*r, key * 10);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        assert_eq!(cache.len(), 5);

        cache.clear();
        assert!(cache.is_empty());
    }
}
