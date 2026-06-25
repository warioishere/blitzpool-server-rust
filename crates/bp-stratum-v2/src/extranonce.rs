// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-side extranonce-prefix allocation for **Extended** mining
//! channels. Two channels MUST NOT share the same prefix or their
//! coinbases collide on the same `(extranonce_prefix + extranonce)`
//! pair and produce identical hashes.
//!
//! Allocation strategy: prefixes live in a
//! per-worker partition of `(prefix_size - 1) * 8` bits (one worker by
//! default, ID 0); the allocator hands out the next free big-endian
//! integer starting from 1 (we skip 0 because some firmwares treat
//! `extranonce_prefix == all-zero` as "no prefix"). On release the
//! prefix returns to the pool; reuse is allowed.
//!
//! `total_extranonce_size` defaults to 12 bytes (4 prefix + 8
//! miner-controlled) to match `bp_mining_job`'s coinbase slot size.
//! The bump from 8 → 12 came from the Braiins Hashpower marketplace,
//! which requires `extranonce2_size >= 7` on the miner side.

use std::collections::{HashMap, HashSet};

/// Errors returned by the allocator.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExtranonceError {
    /// All prefixes inside the worker's partition are in use.
    #[error("extranonce prefix space exhausted")]
    Exhausted,
}

/// Pool-side extranonce-prefix allocator. **Not thread-safe** —
/// wrap in `Mutex` if the calling layer is multi-threaded.
#[derive(Debug)]
pub struct ExtranonceAllocator {
    prefix_size: usize,
    total_extranonce_size: usize,
    worker_offset: u32,
    max_prefix: u32,
    next_prefix: u32,
    allocated: HashMap<u64, u32>, // globally-unique channel key → prefix
    used: HashSet<u32>,
}

impl ExtranonceAllocator {
    /// Construct with the default configuration: 4-byte prefix
    /// inside a 12-byte total extranonce slot.
    pub fn new_default() -> Self {
        Self::new(4, 12).expect("default sizes are valid")
    }

    /// Construct with explicit sizes.
    ///
    /// `prefix_size` must be ≥ 1 and ≤ 4 (we use `u32` internally for
    /// the partition counter; values > 4 would silently overflow).
    /// `total_extranonce_size` must be ≥ `prefix_size`.
    pub fn new(prefix_size: usize, total_extranonce_size: usize) -> Result<Self, &'static str> {
        if prefix_size == 0 || prefix_size > 4 {
            return Err("prefix_size must be in 1..=4");
        }
        if total_extranonce_size < prefix_size {
            return Err("total_extranonce_size must be ≥ prefix_size");
        }
        let worker_id: u32 = 0;
        let bits_per_worker = (prefix_size - 1) as u32 * 8;
        // partition_size = 2^bits_per_worker; max_prefix = partition_size - 1.
        // For prefix_size==4 → bits_per_worker = 24, partition_size = 2^24,
        // max_prefix = 0x00FFFFFF. worker_offset = worker_id * 2^24.
        let partition_size = 1u32.checked_shl(bits_per_worker).unwrap_or(1);
        let worker_offset = worker_id.saturating_mul(partition_size);
        let max_prefix = partition_size.saturating_sub(1);
        Ok(Self {
            prefix_size,
            total_extranonce_size,
            worker_offset,
            max_prefix,
            next_prefix: 1,
            allocated: HashMap::new(),
            used: HashSet::new(),
        })
    }

    /// Miner-controlled extranonce length in bytes
    /// (`total_extranonce_size - prefix_size`).
    pub fn miner_extranonce_size(&self) -> usize {
        self.total_extranonce_size - self.prefix_size
    }

    /// Pool-assigned prefix length in bytes.
    pub fn prefix_size(&self) -> usize {
        self.prefix_size
    }

    /// Count of currently-allocated channels.
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Allocate (or re-return) the prefix for `channel_key` — a
    /// GLOBALLY-unique key (the allocator is shared pool-wide, so the
    /// per-connection wire `channel_id` is not unique on its own; the
    /// caller combines it with the session id). Big-endian
    /// `prefix_size`-byte buffer. Returns `Err(Exhausted)` only when
    /// every prefix in the worker partition is in use.
    pub fn allocate(&mut self, channel_key: u64) -> Result<Vec<u8>, ExtranonceError> {
        if let Some(&existing) = self.allocated.get(&channel_key) {
            return Ok(prefix_to_be_bytes(existing, self.prefix_size));
        }

        let mut local = self.next_prefix;
        let mut attempts = 0u64;
        let attempts_limit = u64::from(self.max_prefix);
        loop {
            let global = self.worker_offset.wrapping_add(local);
            if !self.used.contains(&global) {
                self.allocated.insert(channel_key, global);
                self.used.insert(global);
                self.next_prefix = if local >= self.max_prefix {
                    1
                } else {
                    local + 1
                };
                return Ok(prefix_to_be_bytes(global, self.prefix_size));
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
    pub fn release(&mut self, channel_key: u64) {
        if let Some(prefix) = self.allocated.remove(&channel_key) {
            self.used.remove(&prefix);
        }
    }

    /// Look up the prefix for a channel key without allocating. Returns
    /// `None` if unknown.
    pub fn get_prefix(&self, channel_key: u64) -> Option<Vec<u8>> {
        self.allocated
            .get(&channel_key)
            .map(|&p| prefix_to_be_bytes(p, self.prefix_size))
    }
}

fn prefix_to_be_bytes(prefix: u32, size: usize) -> Vec<u8> {
    let mut out = vec![0u8; size];
    let mut v = prefix;
    for i in (0..size).rev() {
        out[i] = (v & 0xff) as u8;
        v >>= 8;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ── spec-vector ports ───────────────────────────────────────────

    /// `allocates unique prefixes for different channels`
    #[test]
    fn allocates_unique_prefixes_for_different_channels() {
        let mut mgr = ExtranonceAllocator::new_default();
        let p1 = mgr.allocate(1).unwrap();
        let p2 = mgr.allocate(2).unwrap();
        let p3 = mgr.allocate(3).unwrap();
        assert_ne!(p1, p2);
        assert_ne!(p2, p3);
        assert_ne!(p1, p3);
    }

    /// `returns same prefix for same channel on re-allocation`
    #[test]
    fn returns_same_prefix_for_same_channel_on_realloc() {
        let mut mgr = ExtranonceAllocator::new_default();
        let p1a = mgr.allocate(1).unwrap();
        let p1b = mgr.allocate(1).unwrap();
        assert_eq!(p1a, p1b);
    }

    /// `prefix is 4 bytes by default`
    #[test]
    fn prefix_is_four_bytes_by_default() {
        let mut mgr = ExtranonceAllocator::new_default();
        let p = mgr.allocate(1).unwrap();
        assert_eq!(p.len(), 4);
    }

    /// `minerExtranonceSize is total minus prefix`
    #[test]
    fn miner_extranonce_size_is_total_minus_prefix() {
        assert_eq!(
            ExtranonceAllocator::new(4, 8)
                .unwrap()
                .miner_extranonce_size(),
            4
        );
        assert_eq!(
            ExtranonceAllocator::new(2, 6)
                .unwrap()
                .miner_extranonce_size(),
            4
        );
    }

    /// `releases prefix and allows reuse`
    #[test]
    fn releases_prefix_and_allows_reuse() {
        let mut mgr = ExtranonceAllocator::new_default();
        let _p1 = mgr.allocate(1).unwrap();
        assert_eq!(mgr.allocated_count(), 1);
        mgr.release(1);
        assert_eq!(mgr.allocated_count(), 0);
        assert_eq!(mgr.get_prefix(1), None);
        let p2 = mgr.allocate(10).unwrap();
        assert_eq!(p2.len(), 4);
        assert_eq!(mgr.allocated_count(), 1);
    }

    /// `release is idempotent for unknown channels`
    #[test]
    fn release_is_idempotent_for_unknown_channels() {
        let mut mgr = ExtranonceAllocator::new_default();
        mgr.release(999); // must not panic
        assert_eq!(mgr.allocated_count(), 0);
    }

    /// `getPrefix returns undefined for unallocated channel`
    #[test]
    fn get_prefix_none_for_unallocated() {
        let mgr = ExtranonceAllocator::new_default();
        assert_eq!(mgr.get_prefix(42), None);
    }

    /// `getPrefix returns the allocated prefix`
    #[test]
    fn get_prefix_returns_allocated() {
        let mut mgr = ExtranonceAllocator::new_default();
        let p = mgr.allocate(1).unwrap();
        assert_eq!(mgr.get_prefix(1).as_deref(), Some(p.as_slice()));
    }

    /// `handles many allocations without collision`
    #[test]
    fn handles_many_allocations_without_collision() {
        let mut mgr = ExtranonceAllocator::new_default();
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for i in 1..=1000 {
            let p = mgr.allocate(i).unwrap();
            assert!(seen.insert(p), "collision at channel {i}");
        }
        assert_eq!(mgr.allocated_count(), 1000);
    }

    /// `works with 2-byte prefix size`
    #[test]
    fn works_with_two_byte_prefix() {
        let mut mgr = ExtranonceAllocator::new(2, 4).unwrap();
        let p = mgr.allocate(1).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(mgr.miner_extranonce_size(), 2);
    }

    /// `reuses released prefix slot`
    #[test]
    fn reuses_released_prefix_slot() {
        let mut mgr = ExtranonceAllocator::new_default();
        let _p1 = mgr.allocate(1).unwrap();
        let _p2 = mgr.allocate(2).unwrap();
        mgr.release(1);
        let p3 = mgr.allocate(3).unwrap();
        assert_eq!(p3.len(), 4);
        assert_eq!(mgr.allocated_count(), 2);
    }

    /// `tracks allocatedCount correctly`
    #[test]
    fn tracks_allocated_count_correctly() {
        let mut mgr = ExtranonceAllocator::new_default();
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

    // ── Extra Rust-side invariants ──────────────────────────────────

    /// Big-endian encoding: prefix=1 with prefix_size=4 must be 0x00,0x00,0x00,0x01.
    /// Skips 0 so the first allocation lands at 1.
    #[test]
    fn first_allocation_is_one_big_endian() {
        let mut mgr = ExtranonceAllocator::new_default();
        let p = mgr.allocate(7).unwrap();
        assert_eq!(p, vec![0x00, 0x00, 0x00, 0x01]);
    }

    /// 2-byte prefix BE encoding.
    #[test]
    fn two_byte_prefix_big_endian() {
        let mut mgr = ExtranonceAllocator::new(2, 6).unwrap();
        let _ = mgr.allocate(1).unwrap();
        let p2 = mgr.allocate(2).unwrap();
        assert_eq!(p2, vec![0x00, 0x02]);
    }

    /// Tiny partition (`prefix_size = 1` → `max_prefix = 0`): exactly
    /// one prefix is allocatable (the value 1; the zero is reserved).
    /// The second allocation must terminate with `Exhausted` instead of
    /// looping forever — this pins the loop's exit condition. With
    /// `max_prefix = 0` the first `allocate` succeeds (used is empty),
    /// the second enters the loop, hits `attempts > 0`, then returns
    /// `Exhausted`.
    #[test]
    fn tiny_partition_reports_exhausted_after_one() {
        let mut mgr = ExtranonceAllocator::new(1, 9).unwrap();
        assert_eq!(mgr.allocate(1), Ok(vec![0x01]));
        assert_eq!(mgr.allocate(2), Err(ExtranonceError::Exhausted));
    }

    /// Constructor argument validation.
    #[test]
    fn rejects_invalid_construction() {
        assert!(ExtranonceAllocator::new(0, 12).is_err());
        assert!(ExtranonceAllocator::new(5, 12).is_err());
        assert!(ExtranonceAllocator::new(4, 3).is_err());
    }
}
