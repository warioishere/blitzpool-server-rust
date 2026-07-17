// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-side extranonce-prefix allocation, shared by the SV1 and SV2
//! stratum servers.
//!
//! ## What prefix uniqueness actually buys
//!
//! Two connections search the same space only if they hash the **same
//! coinbase** — the header commits to it through the merkle root, so a
//! shared `(extranonce_prefix + extranonce)` pair produces identical
//! hashes only when everything *else* in the coinbase is identical too.
//! "Same coinbase" is exactly `bp_mining_job`'s job-cache key
//! (`network, pool_identifier, extranonce_slot_size, payouts, template…`
//! — see `cache::job_key_tuple`):
//!
//! - **Same cache key** ⟺ same coinbase ⟺ the prefix is the sole
//!   work-partitioner. A shared prefix here means overlapping search plus
//!   duplicate-share rejects on the colliding session.
//! - **Different cache key** ⟺ a shared prefix is harmless: the coinbases,
//!   and therefore the headers, differ no matter what the prefix is.
//!
//! The payout set is part of that key, and this pool is non-custodial, so
//! the distinction is not academic: Solo / Group-Solo / Blockparty sessions
//! each hash their own payout outputs and can never collide with a
//! different address, whatever prefix they hold. PPLNS is the mode where
//! the prefix carries the entire burden — `build_distribution(reward_sats)`
//! is address-independent, so every PPLNS miner on a stream hashes one
//! identical coinbase.
//!
//! The allocator nonetheless guarantees prefixes unique **pool-wide**, not
//! merely per coinbase class. That is deliberate: the global guarantee
//! subsumes the per-class one, costs nothing (a worker partition holds
//! 2^24 prefixes — orders of magnitude past any realistic connection
//! count), and spares every caller from having to reason about which mode
//! a session ended up resolving to. Treat pool-wide uniqueness as a
//! simplifying invariant, not as a claim that a shared prefix is always
//! harmful.
//!
//! ## Allocation strategy
//!
//! Prefixes live in a per-worker partition. The
//! prefix is `prefix_size` bytes; the top 8 bits select the worker
//! (0..=255) and the remaining `(prefix_size - 1) * 8` bits are the
//! per-worker prefix counter. The allocator hands out the next free
//! big-endian integer starting from 1 (we skip 0 because some firmwares
//! treat `extranonce_prefix == all-zero` as "no prefix"). On release the
//! prefix returns to the pool; reuse is allowed.
//!
//! The worker partition is what lets the SV1 and SV2 servers share this
//! allocator without ever handing out overlapping prefixes: each server
//! constructs its own instance on a distinct worker id, so an SV1 prefix
//! (`0x01…`) and an SV2 prefix (`0x00…`) can never collide even though
//! the two protocols run separate instances. The partition is a namespace
//! split, not a rationing device — it buys the two instances freedom from
//! having to coordinate (no shared instance, no shared lock, no
//! cross-crate wiring), and uniqueness falls out by construction.
//!
//! Only workers 0 and 1 are assigned; **workers 2..=255 are unowned**, so
//! nothing is ever emitted from `0x02…`..`0xFF…`. That is headroom, not
//! waste: a partition serves 2^24 concurrent prefixes, so two of them
//! already cover both protocols with room to spare, and any future
//! independent allocator (another protocol, another region) can claim a
//! worker id and stay collision-free without talking to the others. The
//! same property makes the unowned range the natural home for a
//! hand-administered prefix: no counter will ever reach it.
//!
//! `total_extranonce_size` defaults to 12 bytes (4 prefix + 8
//! miner-controlled) to match `bp_mining_job`'s coinbase slot size and
//! SV1's fixed 4-byte extranonce1 + 8-byte extranonce2. The bump from
//! 8 → 12 came from the Braiins Hashpower marketplace, which requires
//! `extranonce2_size >= 7` on the miner side.

use std::collections::{HashMap, HashSet};

/// Errors returned by the allocator.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExtranonceError {
    /// All prefixes inside the worker's partition are in use.
    #[error("extranonce prefix space exhausted")]
    Exhausted,
}

/// Worker-partition ids reserved per stratum protocol. The top byte of a
/// 4-byte prefix carries the worker id, so allocators built on distinct
/// workers hand out disjoint prefixes — this is what lets the SV1 and SV2
/// servers share the extranonce space (one allocator instance per worker)
/// without ever colliding. Keep both reservations here so the
/// cross-protocol uniqueness invariant lives in one place rather than as
/// magic numbers spread across the protocol crates.
///
/// SV2 builds its allocator via [`ExtranonceAllocator::new_default`]
/// (worker 0 → `0x00…` prefixes); SV1 uses
/// [`ExtranonceAllocator::new_default_on_worker`] with [`SV1_WORKER_ID`]
/// (worker 1 → `0x01…`).
pub const SV2_WORKER_ID: u32 = 0;
/// See [`SV2_WORKER_ID`]. SV1's partition (`0x01…`), disjoint from SV2's.
pub const SV1_WORKER_ID: u32 = 1;

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
    /// Construct with the default configuration on **worker 0**: 4-byte
    /// prefix inside a 12-byte total extranonce slot.
    pub fn new_default() -> Self {
        Self::new(4, 12).expect("default sizes are valid")
    }

    /// Construct with the default sizes (4-byte prefix / 12-byte total)
    /// on the given worker partition. Use this to give a second server
    /// (e.g. the SV1 translator) a prefix space disjoint from worker 0
    /// (e.g. the SV2 server): the two never collide because the top byte
    /// of the prefix carries the worker id.
    pub fn new_default_on_worker(worker_id: u32) -> Self {
        Self::new_on_worker(4, 12, worker_id).expect("default sizes are valid")
    }

    /// Construct with explicit sizes on worker 0.
    ///
    /// `prefix_size` must be ≥ 1 and ≤ 4 (we use `u32` internally for
    /// the partition counter; values > 4 would silently overflow).
    /// `total_extranonce_size` must be ≥ `prefix_size`.
    pub fn new(prefix_size: usize, total_extranonce_size: usize) -> Result<Self, &'static str> {
        Self::new_on_worker(prefix_size, total_extranonce_size, 0)
    }

    /// Construct with explicit sizes on a chosen worker partition.
    ///
    /// The worker id occupies the top 8 bits of the prefix, so it must
    /// be in `0..=255`; a value whose partition would not fit inside
    /// `prefix_size` bytes is rejected.
    pub fn new_on_worker(
        prefix_size: usize,
        total_extranonce_size: usize,
        worker_id: u32,
    ) -> Result<Self, &'static str> {
        if prefix_size == 0 || prefix_size > 4 {
            return Err("prefix_size must be in 1..=4");
        }
        if total_extranonce_size < prefix_size {
            return Err("total_extranonce_size must be ≥ prefix_size");
        }
        let bits_per_worker = (prefix_size - 1) as u32 * 8;
        // partition_size = 2^bits_per_worker; max_prefix = partition_size - 1.
        // For prefix_size==4 → bits_per_worker = 24, partition_size = 2^24,
        // max_prefix = 0x00FFFFFF. worker_offset = worker_id * 2^24.
        let partition_size = 1u32.checked_shl(bits_per_worker).unwrap_or(1);
        let max_prefix = partition_size.saturating_sub(1);
        // worker_id lives in the top 8 bits (prefix_size*8 - bits_per_worker
        // == 8), so it must fit in a byte AND its partition must land inside
        // the prefix_size-byte value space (otherwise `prefix_to_be_bytes`
        // would truncate the high bits and two workers could collide).
        // `allocate` skips 0, so it emits at least `worker_offset + 1`; the
        // highest emitted prefix is therefore `worker_offset + max(max_prefix,
        // 1)`. Validating against that (not `+ max_prefix`) also rejects the
        // degenerate single-slot partition (`max_prefix == 0`, i.e.
        // prefix_size == 1) whose lone emitted value would otherwise overflow
        // into the next worker or wrap to the reserved all-zero prefix.
        let worker_offset = worker_id
            .checked_mul(partition_size)
            .ok_or("worker_id too large for prefix_size")?;
        let highest = worker_offset
            .checked_add(max_prefix.max(1))
            .ok_or("worker partition overflows prefix space")?;
        let prefix_capacity_bits = prefix_size as u32 * 8;
        if prefix_capacity_bits < 32 && highest >= (1u32 << prefix_capacity_bits) {
            return Err("worker_id too large for prefix_size");
        }
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

    // ── core allocation invariants ──────────────────────────────────

    /// Different channel keys get distinct prefixes.
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

    /// Re-allocating the same channel key returns the same prefix.
    #[test]
    fn returns_same_prefix_for_same_channel_on_realloc() {
        let mut mgr = ExtranonceAllocator::new_default();
        let p1a = mgr.allocate(1).unwrap();
        let p1b = mgr.allocate(1).unwrap();
        assert_eq!(p1a, p1b);
    }

    /// The default prefix is 4 bytes.
    #[test]
    fn prefix_is_four_bytes_by_default() {
        let mut mgr = ExtranonceAllocator::new_default();
        let p = mgr.allocate(1).unwrap();
        assert_eq!(p.len(), 4);
    }

    /// miner_extranonce_size == total - prefix.
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

    /// Releasing a prefix returns it to the pool for reuse.
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

    /// Releasing an unknown channel key is a no-op.
    #[test]
    fn release_is_idempotent_for_unknown_channels() {
        let mut mgr = ExtranonceAllocator::new_default();
        mgr.release(999); // must not panic
        assert_eq!(mgr.allocated_count(), 0);
    }

    /// get_prefix returns None for an unallocated channel key.
    #[test]
    fn get_prefix_none_for_unallocated() {
        let mgr = ExtranonceAllocator::new_default();
        assert_eq!(mgr.get_prefix(42), None);
    }

    /// get_prefix returns the currently-allocated prefix.
    #[test]
    fn get_prefix_returns_allocated() {
        let mut mgr = ExtranonceAllocator::new_default();
        let p = mgr.allocate(1).unwrap();
        assert_eq!(mgr.get_prefix(1).as_deref(), Some(p.as_slice()));
    }

    /// A thousand allocations yield no duplicate prefixes.
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

    /// A 2-byte prefix size produces 2-byte prefixes.
    #[test]
    fn works_with_two_byte_prefix() {
        let mut mgr = ExtranonceAllocator::new(2, 4).unwrap();
        let p = mgr.allocate(1).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(mgr.miner_extranonce_size(), 2);
    }

    /// A released prefix slot is handed out again on the next allocation.
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

    /// allocated_count tracks live allocations across allocate/release.
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

    // ── Worker-partition invariants (SV1 / SV2 disjointness) ─────────

    /// Worker 0 (SV2) and worker 1 (SV1) draw from disjoint prefix
    /// spaces: worker 0's top byte is 0x00, worker 1's is 0x01, so no
    /// prefix can ever appear in both — even across many allocations.
    #[test]
    fn worker_partitions_never_overlap() {
        let mut sv2 = ExtranonceAllocator::new_default(); // worker 0
        let mut sv1 = ExtranonceAllocator::new_default_on_worker(1); // worker 1
        let mut worker0: HashSet<Vec<u8>> = HashSet::new();
        let mut worker1: HashSet<Vec<u8>> = HashSet::new();
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

    /// First allocation on worker 1 is `0x01000001` big-endian
    /// (worker_offset 0x01000000 + first local prefix 1).
    #[test]
    fn worker_one_first_allocation_big_endian() {
        let mut mgr = ExtranonceAllocator::new_default_on_worker(1);
        let p = mgr.allocate(1).unwrap();
        assert_eq!(p, vec![0x01, 0x00, 0x00, 0x01]);
    }

    /// Worker 255 is the last valid partition for a 4-byte prefix
    /// (0xFF000000 + 0x00FFFFFF == 0xFFFFFFFF, fits exactly); 256 does
    /// not fit and is rejected.
    #[test]
    fn worker_id_bounds_for_four_byte_prefix() {
        assert!(ExtranonceAllocator::new_on_worker(4, 12, 255).is_ok());
        assert!(ExtranonceAllocator::new_on_worker(4, 12, 256).is_err());
    }

    /// The single-slot partition (`prefix_size == 1` → `max_prefix == 0`)
    /// emits `worker_offset + 1`, so worker 255 would emit value 256 —
    /// which overflows the one prefix byte and wraps to the reserved
    /// all-zero prefix. The bounds check must reject it. Worker 0 stays
    /// valid and emits `0x01` (never the reserved `0x00`).
    #[test]
    fn single_slot_partition_rejects_overflowing_worker() {
        assert!(ExtranonceAllocator::new_on_worker(1, 9, 255).is_err());
        let mut w0 = ExtranonceAllocator::new_on_worker(1, 9, 0).unwrap();
        assert_eq!(w0.allocate(1), Ok(vec![0x01]));
    }

    /// Both reserved worker ids construct, and worker 1's prefixes never
    /// collide with worker 0's (different top byte).
    #[test]
    fn reserved_worker_ids_are_disjoint() {
        let mut sv2 = ExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID);
        let mut sv1 = ExtranonceAllocator::new_default_on_worker(SV1_WORKER_ID);
        assert_eq!(sv2.allocate(1).unwrap()[0], 0x00);
        assert_eq!(sv1.allocate(1).unwrap()[0], 0x01);
    }
}
