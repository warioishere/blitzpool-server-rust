// SPDX-License-Identifier: AGPL-3.0-or-later

//! `InflightResultCache<K, V, E>`: per-key dedup of concurrent `compute()`
//! callers plus TTL caching of successes (failures are not cached). One
//! NewTemplate fans out to N channels asking for the same distribution, so N
//! builds become one. `Arc<E>` lets errors without `Clone` be shared.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::broadcast;

type SharedResult<V, E> = Result<Arc<V>, Arc<E>>;

enum Slot<V, E> {
    /// A compute is running; `leader` tells whose, so a leader only ever
    /// removes its own slot.
    InFlight {
        leader: u64,
        tx: broadcast::Sender<SharedResult<V, E>>,
    },
    Cached {
        value: Arc<V>,
        expires_at: Instant,
    },
}

/// Slot map plus a generation counter that every invalidation bumps, so a
/// leader can tell an invalidation landed mid-compute and must not cache its
/// already superseded result.
struct Inner<K, V, E> {
    slots: HashMap<K, Slot<V, E>>,
    generation: u64,
    next_leader: u64,
}

impl<K: Hash + Eq, V, E> Inner<K, V, E> {
    /// Remove `key`'s slot only while it is `leader`'s in-flight slot.
    fn remove_own(&mut self, key: &K, leader: u64) {
        if matches!(self.slots.get(key), Some(Slot::InFlight { leader: l, .. }) if *l == leader) {
            self.slots.remove(key);
        }
    }
}

/// Held by a running leader. Dropped before the leader finishes (its future
/// cancelled or panicking), it removes the leader's slot: the followers'
/// channel closes and the next caller leads, instead of waiting for good.
struct LeaderGuard<K: Hash + Eq, V, E> {
    state: Arc<Mutex<Inner<K, V, E>>>,
    key: K,
    leader: u64,
    finished: bool,
}

impl<K: Hash + Eq, V, E> Drop for LeaderGuard<K, V, E> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Ok(mut state) = self.state.lock() {
            state.remove_own(&self.key, self.leader);
        }
    }
}

enum Role<V, E> {
    Follower(broadcast::Receiver<SharedResult<V, E>>),
    Leader {
        id: u64,
        tx: broadcast::Sender<SharedResult<V, E>>,
    },
}

/// Per-key in-flight dedup + TTL cache. Clones share state.
pub struct InflightResultCache<K, V, E> {
    state: Arc<Mutex<Inner<K, V, E>>>,
    ttl: Duration,
}

// Manual impl: a derive would require `K, V, E: Clone`.
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
            state: Arc::new(Mutex::new(Inner {
                slots: HashMap::new(),
                generation: 0,
                next_leader: 0,
            })),
            ttl,
        }
    }

    /// Return a fresh cached result, or run `compute` as leader, or wait for
    /// the leader's broadcast. Success is cached for `ttl`; a failure drops
    /// the slot so the next caller retries.
    pub async fn get_or_compute<F, Fut>(&self, key: K, compute: F) -> SharedResult<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        let (role, generation_at_start) = {
            let mut state = self.state.lock().expect("inflight mutex poisoned");
            let generation_at_start = state.generation;
            let role = match state.slots.get(&key) {
                Some(Slot::Cached { value, expires_at }) if *expires_at > Instant::now() => {
                    return Ok(value.clone());
                }
                Some(Slot::InFlight { tx, .. }) => Role::Follower(tx.subscribe()),
                _ => {
                    // No entry OR expired entry: this caller leads.
                    let (tx, _) = broadcast::channel::<SharedResult<V, E>>(1);
                    let id = state.next_leader;
                    state.next_leader = state.next_leader.wrapping_add(1);
                    state.slots.insert(
                        key.clone(),
                        Slot::InFlight {
                            leader: id,
                            tx: tx.clone(),
                        },
                    );
                    Role::Leader { id, tx }
                }
            };
            (role, generation_at_start)
        };

        let (id, tx) = match role {
            Role::Follower(mut rx) => {
                return match rx.recv().await {
                    Ok(result) => result,
                    // The leader was cancelled or panicked before publishing.
                    // A default-constructed E sends the caller down its error
                    // path; the next call leads.
                    Err(_) => Err(Arc::new(E::default())),
                };
            }
            Role::Leader { id, tx } => (id, tx),
        };
        let mut guard = LeaderGuard {
            state: self.state.clone(),
            key: key.clone(),
            leader: id,
            finished: false,
        };

        let outcome = compute().await;
        let shared: SharedResult<V, E> = match outcome {
            Ok(v) => Ok(Arc::new(v)),
            Err(e) => Err(Arc::new(e)),
        };

        // One lock, so an invalidation cannot slip between remove and insert.
        {
            let mut state = self.state.lock().expect("inflight mutex poisoned");
            state.remove_own(&key, id);
            // Cache only if no invalidation landed during the compute;
            // otherwise the value is already superseded.
            if let Ok(value) = &shared {
                if state.generation == generation_at_start {
                    state.slots.insert(
                        key,
                        Slot::Cached {
                            value: value.clone(),
                            expires_at: Instant::now() + self.ttl,
                        },
                    );
                }
            }
            guard.finished = true;
        }
        // Errs with no followers. Followers get the result even when it was
        // not cached: it is the value they queued for.
        let _ = tx.send(shared.clone());
        shared
    }

    /// Drop all entries and bump the generation, so a compute already in
    /// flight does not install its superseded result.
    pub fn clear(&self) {
        let mut state = self.state.lock().expect("inflight mutex poisoned");
        state.slots.clear();
        state.generation = state.generation.wrapping_add(1);
    }

    /// Snapshot of the current entry count (cached + in-flight).
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .expect("inflight mutex poisoned")
            .slots
            .len()
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

    /// A mid-compute clear: the leader's result reaches its caller and the
    /// followers that queued before the clear, but is not cached.
    #[tokio::test]
    async fn clear_during_inflight_is_not_resurrected() {
        let cache: Arc<InflightResultCache<u64, u64, FakeError>> =
            Arc::new(InflightResultCache::new(Duration::from_secs(60)));
        let calls = Arc::new(AtomicUsize::new(0));

        let leader = {
            let cache = cache.clone();
            let calls = calls.clone();
            tokio::spawn(async move {
                cache
                    .get_or_compute(1, || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(80)).await;
                        Ok(11u64)
                    })
                    .await
            })
        };

        // A follower queued behind the leader before the clear.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let early_follower = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.get_or_compute(1, || async { Ok(99u64) }).await })
        };

        // Land the clear while the leader is still computing.
        tokio::time::sleep(Duration::from_millis(10)).await;
        cache.clear();

        // The leader still returns its value to its own caller, and to the
        // follower that queued for it.
        assert_eq!(*leader.await.unwrap().expect("leader ok"), 11);
        assert_eq!(
            *early_follower
                .await
                .unwrap()
                .expect("follower gets the leader's value"),
            11
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // But it must not have been cached: the next caller recomputes.
        let calls_clone = calls.clone();
        let r = cache
            .get_or_compute(1, || async move {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Ok(22u64)
            })
            .await
            .expect("ok");
        assert_eq!(
            *r, 22,
            "next caller must see fresh state, not the superseded value"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "clear during in-flight compute must force a recompute"
        );
    }

    /// A leader whose future is dropped mid-compute (a client gone, a
    /// timeout) frees its slot: its follower errors at once and the next
    /// caller leads instead of waiting for good.
    #[tokio::test]
    async fn a_cancelled_leader_blocks_no_later_caller() {
        let cache: Arc<InflightResultCache<u64, u64, FakeError>> =
            Arc::new(InflightResultCache::new(Duration::from_secs(60)));
        let leader = {
            let cache = cache.clone();
            tokio::spawn(async move {
                cache
                    .get_or_compute(1, || async {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        Ok(1u64)
                    })
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        let follower = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.get_or_compute(1, || async { Ok(9u64) }).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        leader.abort();

        let followed = tokio::time::timeout(Duration::from_secs(1), follower)
            .await
            .expect("the follower must not wait for a dead leader")
            .unwrap();
        assert_eq!(
            followed.expect_err("no result was published").as_ref(),
            &FakeError::Unset
        );
        let next = tokio::time::timeout(
            Duration::from_secs(1),
            cache.get_or_compute(1, || async { Ok(2u64) }),
        )
        .await
        .expect("the next caller must lead, not wait on the dead slot");
        assert_eq!(*next.expect("ok"), 2);
    }

    /// A leader that finishes after a clear leaves the slot of the leader
    /// that started after the clear alone: that one's followers get its own
    /// result, not the superseded one.
    #[tokio::test]
    async fn a_superseded_leader_leaves_the_next_leaders_slot_alone() {
        let cache: Arc<InflightResultCache<u64, u64, FakeError>> =
            Arc::new(InflightResultCache::new(Duration::from_secs(60)));
        let old = {
            let cache = cache.clone();
            tokio::spawn(async move {
                cache
                    .get_or_compute(1, || async {
                        tokio::time::sleep(Duration::from_millis(40)).await;
                        Ok(111u64)
                    })
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        cache.clear();
        let new = {
            let cache = cache.clone();
            tokio::spawn(async move {
                cache
                    .get_or_compute(1, || async {
                        tokio::time::sleep(Duration::from_millis(80)).await;
                        Ok(222u64)
                    })
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        let follower = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.get_or_compute(1, || async { Ok(999u64) }).await })
        };

        assert_eq!(*old.await.unwrap().expect("ok"), 111);
        assert_eq!(*new.await.unwrap().expect("ok"), 222);
        assert_eq!(
            *follower.await.unwrap().expect("ok"),
            222,
            "the follower queued behind the new leader gets the new value"
        );
    }

    #[tokio::test]
    async fn clear_drops_cache() {
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

        cache.clear();
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
            "after clear, next get_or_compute runs"
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
