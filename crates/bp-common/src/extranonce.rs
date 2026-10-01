// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-wide unique 4-byte extranonce prefixes: top byte = worker, counter from 1 (some firmware
//! reads all-zero as "no prefix"). One shared instance per protocol, since PPLNS miners hash one
//! coinbase and the prefix is their only work partitioner. Workers 2..=255 stay unowned for
//! hand-administered prefixes; 8 slot bytes remain because Braiins needs `extranonce2_size >= 7`.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// Errors returned by the allocator.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExtranonceError {
    /// All prefixes inside the worker's partition are in use.
    #[error("extranonce prefix space exhausted")]
    Exhausted,
}

/// Worker partition per stratum protocol (SV2 `0x00…`, SV1 `0x01…`), kept
/// together so the cross-protocol uniqueness invariant lives in one place.
pub const SV2_WORKER_ID: u32 = 0;
/// See [`SV2_WORKER_ID`]. SV1's partition (`0x01…`), disjoint from SV2's.
pub const SV1_WORKER_ID: u32 = 1;

/// Bits of a prefix below the worker byte: the per-worker counter.
const WORKER_SHIFT: u32 = 24;

/// Highest per-worker counter value: a partition holds 2^24 - 1 prefixes
/// (the counter skips 0).
const PARTITION_MAX: u32 = (1 << WORKER_SHIFT) - 1;

/// Pool-side extranonce-prefix allocator. **Not thread-safe**; reached only
/// through [`SharedExtranonceAllocator`], which holds it behind a `Mutex`.
#[derive(Debug)]
pub(crate) struct ExtranonceAllocator {
    worker_offset: u32,
    /// Highest per-worker counter value; [`PARTITION_MAX`] outside tests,
    /// which shrink it to reach an exhausted partition.
    max_prefix: u32,
    next_prefix: u32,
    allocated: HashMap<u64, u32>, // globally-unique channel key → prefix
    used: HashSet<u32>,
}

impl ExtranonceAllocator {
    /// # Panics
    /// When `worker_id` does not fit the top byte (> 255).
    pub(crate) fn new_default_on_worker(worker_id: u32) -> Self {
        assert!(
            worker_id <= 0xFF,
            "extranonce worker id {worker_id} does not fit the prefix's top byte"
        );
        Self {
            worker_offset: worker_id << WORKER_SHIFT,
            max_prefix: PARTITION_MAX,
            next_prefix: 1,
            allocated: HashMap::new(),
            used: HashSet::new(),
        }
    }

    pub(crate) fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Big-endian prefix for `channel_key`; a repeated key gets the same one
    /// back. `Err(Exhausted)` only when the whole partition is in use.
    pub(crate) fn allocate(&mut self, channel_key: u64) -> Result<[u8; 4], ExtranonceError> {
        if let Some(&existing) = self.allocated.get(&channel_key) {
            return Ok(existing.to_be_bytes());
        }

        let mut local = self.next_prefix;
        let mut attempts = 0u64;
        let attempts_limit = u64::from(self.max_prefix);
        loop {
            let global = self.worker_offset + local;
            if !self.used.contains(&global) {
                self.allocated.insert(channel_key, global);
                self.used.insert(global);
                self.next_prefix = if local >= self.max_prefix {
                    1
                } else {
                    local + 1
                };
                return Ok(global.to_be_bytes());
            }
            if attempts > attempts_limit {
                return Err(ExtranonceError::Exhausted);
            }
            local = if local >= self.max_prefix {
                1
            } else {
                local + 1
            };
            attempts += 1;
        }
    }

    /// Drop the channel's allocation. Idempotent for unknown keys.
    pub(crate) fn release(&mut self, channel_key: u64) {
        if let Some(prefix) = self.allocated.remove(&channel_key) {
            self.used.remove(&prefix);
        }
    }
}

/// One protocol's allocator, shared by all of its ports, plus the counter
/// its keys come from: a counter is unique by construction, a random session
/// id only with high probability.
#[derive(Clone, Debug)]
pub struct SharedExtranonceAllocator {
    allocator: Arc<Mutex<ExtranonceAllocator>>,
    next_key: Arc<AtomicU64>,
}

impl SharedExtranonceAllocator {
    /// A 4-byte prefix on `worker_id`. Build
    /// once per protocol and clone into every port.
    pub fn new_default_on_worker(worker_id: u32) -> Self {
        Self {
            allocator: Arc::new(Mutex::new(ExtranonceAllocator::new_default_on_worker(
                worker_id,
            ))),
            next_key: Arc::new(AtomicU64::new(1)),
        }
    }

    /// A key no earlier call returned.
    pub fn next_key(&self) -> u64 {
        self.next_key.fetch_add(1, Ordering::Relaxed)
    }

    /// Big-endian prefix for `key`; a repeated key gets the same one back.
    /// `Err(Exhausted)` only when the whole partition is in use.
    pub fn allocate(&self, key: u64) -> Result<[u8; 4], ExtranonceError> {
        self.lock().allocate(key)
    }

    /// A no-op for a key holding no prefix.
    pub fn release(&self, key: u64) {
        self.lock().release(key);
    }

    pub fn allocated_count(&self) -> usize {
        self.lock().allocated_count()
    }

    /// Recovers a poisoned lock: no operation leaves the allocator half-updated,
    /// and giving up would strand every prefix or refuse every new channel.
    fn lock(&self) -> MutexGuard<'_, ExtranonceAllocator> {
        self.allocator
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ── core allocation invariants ──────────────────────────────────

    /// Different channel keys get distinct prefixes.
    #[test]
    fn allocates_unique_prefixes_for_different_channels() {
        let mut mgr = ExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID);
        let p1 = mgr.allocate(1).unwrap();
        let p2 = mgr.allocate(2).unwrap();
        let p3 = mgr.allocate(3).unwrap();
        assert_ne!(p1, p2);
        assert_ne!(p2, p3);
        assert_ne!(p1, p3);
    }

    /// Re-allocating the same channel key returns the same prefix.
    #[test]
    fn returns_same_prefix_for_same_channel_on_realloc() {
        let mut mgr = ExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID);
        let p1a = mgr.allocate(1).unwrap();
        let p1b = mgr.allocate(1).unwrap();
        assert_eq!(p1a, p1b);
    }

    /// Releasing a prefix returns it to the pool for reuse.
    #[test]
    fn releases_prefix_and_allows_reuse() {
        let mut mgr = ExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID);
        let _p1 = mgr.allocate(1).unwrap();
        assert_eq!(mgr.allocated_count(), 1);
        mgr.release(1);
        assert_eq!(mgr.allocated_count(), 0);
        mgr.allocate(10).unwrap();
        assert_eq!(mgr.allocated_count(), 1);
    }

    /// Releasing an unknown channel key is a no-op.
    #[test]
    fn release_is_idempotent_for_unknown_channels() {
        let mut mgr = ExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID);
        mgr.release(999); // must not panic
        assert_eq!(mgr.allocated_count(), 0);
    }

    /// A thousand allocations yield no duplicate prefixes.
    #[test]
    fn handles_many_allocations_without_collision() {
        let mut mgr = ExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID);
        let mut seen: HashSet<[u8; 4]> = HashSet::new();
        for i in 1..=1000 {
            let p = mgr.allocate(i).unwrap();
            assert!(seen.insert(p), "collision at channel {i}");
        }
        assert_eq!(mgr.allocated_count(), 1000);
    }

    /// A released prefix slot is handed out again on the next allocation.
    #[test]
    fn reuses_released_prefix_slot() {
        let mut mgr = ExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID);
        let _p1 = mgr.allocate(1).unwrap();
        let _p2 = mgr.allocate(2).unwrap();
        mgr.release(1);
        mgr.allocate(3).unwrap();
        assert_eq!(mgr.allocated_count(), 2);
    }

    /// allocated_count tracks live allocations across allocate/release.
    #[test]
    fn tracks_allocated_count_correctly() {
        let mut mgr = ExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID);
        assert_eq!(mgr.allocated_count(), 0);
        mgr.allocate(1).unwrap();
        assert_eq!(mgr.allocated_count(), 1);
        mgr.allocate(2).unwrap();
        assert_eq!(mgr.allocated_count(), 2);
        mgr.release(1);
        assert_eq!(mgr.allocated_count(), 1);
        mgr.release(2);
        assert_eq!(mgr.allocated_count(), 0);
    }

    // ── Encoding and exhaustion ─────────────────────────────────────

    /// The first prefix is 1, big-endian.
    #[test]
    fn first_allocation_is_one_big_endian() {
        let mut mgr = ExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID);
        let p = mgr.allocate(7).unwrap();
        assert_eq!(p, [0x00, 0x00, 0x00, 0x01]);
    }

    /// An exhausted partition returns `Exhausted` instead of looping; a release makes room.
    #[test]
    fn exhausted_partition_reports_exhausted() {
        let mut mgr = ExtranonceAllocator::new_default_on_worker(SV1_WORKER_ID);
        mgr.max_prefix = 2;
        assert_eq!(mgr.allocate(1), Ok([0x01, 0x00, 0x00, 0x01]));
        assert_eq!(mgr.allocate(2), Ok([0x01, 0x00, 0x00, 0x02]));
        assert_eq!(mgr.allocate(3), Err(ExtranonceError::Exhausted));
        mgr.release(1);
        assert_eq!(mgr.allocate(3), Ok([0x01, 0x00, 0x00, 0x01]));
    }

    // ── Worker-partition invariants (SV1 / SV2 disjointness) ─────────

    /// SV2 (worker 0) and SV1 (worker 1) prefix spaces never overlap.
    #[test]
    fn worker_partitions_never_overlap() {
        let mut sv2 = ExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID); // worker 0
        let mut sv1 = ExtranonceAllocator::new_default_on_worker(1); // worker 1
        let mut worker0: HashSet<[u8; 4]> = HashSet::new();
        let mut worker1: HashSet<[u8; 4]> = HashSet::new();
        for i in 1..=1000 {
            let p0 = sv2.allocate(i).unwrap();
            let p1 = sv1.allocate(i).unwrap();
            assert_eq!(p0[0], 0x00, "worker 0 prefix must start 0x00");
            assert_eq!(p1[0], 0x01, "worker 1 prefix must start 0x01");
            worker0.insert(p0);
            worker1.insert(p1);
        }
        assert!(
            worker0.is_disjoint(&worker1),
            "SV1 and SV2 prefix spaces must never overlap"
        );
    }

    /// First allocation on worker 1 is `0x01000001` big-endian.
    #[test]
    fn worker_one_first_allocation_big_endian() {
        let mut mgr = ExtranonceAllocator::new_default_on_worker(1);
        let p = mgr.allocate(1).unwrap();
        assert_eq!(p, [0x01, 0x00, 0x00, 0x01]);
    }

    /// Worker 255 is the last partition; 256 is refused, not truncated into another.
    #[test]
    fn worker_255_is_the_last_partition() {
        let mut mgr = ExtranonceAllocator::new_default_on_worker(255);
        assert_eq!(mgr.allocate(1), Ok([0xFF, 0x00, 0x00, 0x01]));
        assert!(
            std::panic::catch_unwind(|| ExtranonceAllocator::new_default_on_worker(256)).is_err()
        );
    }

    /// The two reserved worker ids get different top bytes.
    #[test]
    fn reserved_worker_ids_are_disjoint() {
        let mut sv2 = ExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID);
        let mut sv1 = ExtranonceAllocator::new_default_on_worker(SV1_WORKER_ID);
        assert_eq!(sv2.allocate(1).unwrap()[0], 0x00);
        assert_eq!(sv1.allocate(1).unwrap()[0], 0x01);
    }
}
