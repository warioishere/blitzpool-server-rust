// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-wide memoization of built [`MiningJob`]s.
//!
//! On every template broadcast each connection (SV1) / channel (SV2)
//! builds a `MiningJob` for its resolved payout set. For PPLNS the
//! payout set is identical across every connection, so N connections
//! re-run the exact same build — including one
//! [`crate::address_to_script`] parse PER payout output — N times per
//! template. This cache collapses those into one build shared as
//! `Arc<MiningJob>`.
//!
//! Two memoization levels:
//!
//! 1. **Job level** — the fully-serialized `MiningJob`, keyed by EVERY
//!    input of [`crate::build_mining_job_from_tdp`] (network, payouts,
//!    all TDP coinbase fields, pool identifier, extranonce-slot size).
//!    Key equality ⇒ input equality ⇒ byte-identical build, so the
//!    cache can never hand out wrong coinbase bytes; payout sets that
//!    differ per finder (Solo / Group-Solo / Blockparty) get distinct
//!    keys by construction — no per-mode special-casing.
//! 2. **Payout-outputs level** — the parsed `(sats, script)` outputs,
//!    keyed by (network, payouts, reward). A job-level miss with an
//!    already-seen payout set (different slot size on SV2 Extended, or
//!    a template refresh that left the reward unchanged) reuses the
//!    parsed scripts and only re-serializes.
//!
//! ## Concurrency
//!
//! Both levels are instances of one generic [`CoalescingSlotMap`]. Its
//! mutex guards ONLY map operations (lookup / insert / prune) — never a
//! build. Each key owns a slot with its own mutex: the first caller for
//! a key becomes the leader and builds while holding just that slot's
//! lock, so callers for OTHER keys build in parallel exactly as they
//! did pre-cache (Solo / Group-Solo payout sets are distinct per
//! connection — those must not serialize behind one pool-wide lock),
//! while same-key callers (PPLNS broadcast storm) wait on their slot
//! and then share the leader's result instead of thundering-herd-
//! rebuilding it. A failed build leaves the slot empty — no negative
//! caching, the next caller retries.
//!
//! Across the two levels the lock order is job-slot → outputs-map →
//! outputs-slot: a job-slot leader takes the outputs map lock (released
//! before it takes the outputs-slot lock) to parse. The two map mutexes
//! are never held at once, and nothing takes a job-slot while holding an
//! outputs-slot, so no cycle can form.
//!
//! ## Key definition
//!
//! The key is defined ONCE as a tuple type ([`JobKeyTuple`] /
//! [`OutputsKeyTuple`]): hashing and equality both go through the same
//! tuple, and the owned key's `as_tuple()` destructures the struct
//! exhaustively — adding a field to the struct without wiring it into
//! the tuple is a compile error, not a silent key-collision bug.
//!
//! Entries are touched on use and lazily pruned after [`ENTRY_TTL`] of
//! disuse — on lookups AND via [`MiningJobCache::prune_expired`],
//! which the stratum translator tasks drive on every template update
//! so memory is reclaimed even when no miner is connected. A job-hit
//! also touches its backing outputs entry, so the shared parsed
//! outputs never age out from under a live job.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bitcoin::Network;

use crate::coinbase::{
    assemble_tdp_job, build_payout_outputs, checked_tdp_scriptsig, MiningJob, MiningJobError,
    PayoutEntry, TdpCoinbaseTemplate,
};

/// Drop an entry after this long without a hit. Comfortably above the
/// template-refresh cadence so entries for the CURRENT template never
/// expire mid-use (every use refreshes the clock).
const ENTRY_TTL: Duration = Duration::from_secs(120);

/// Minimum spacing between prune sweeps (piggybacked on lookups and
/// the translator heartbeat).
const PRUNE_INTERVAL: Duration = Duration::from_secs(10);

type PayoutOutputs = Vec<(u64, Vec<u8>)>;

// ── Key definition (single source of truth) ─────────────────────────

/// THE job-level cache key, as one tuple type. Both hashing and
/// equality operate on this tuple, for the borrowed lookup side and
/// the owned stored side alike — the two can never diverge.
type JobKeyTuple<'a> = (
    Network,
    &'a str, // pool_identifier
    usize,   // extranonce_slot_size
    &'a [PayoutEntry],
    &'a [u8], // coinbase_prefix
    u32,      // coinbase_tx_version
    u32,      // coinbase_tx_input_sequence
    u64,      // coinbase_tx_value_remaining
    &'a [u8], // coinbase_tx_outputs
    u32,      // coinbase_tx_outputs_count
    u32,      // coinbase_tx_locktime
);

fn job_key_tuple<'a>(
    network: Network,
    payouts: &'a [PayoutEntry],
    template: &TdpCoinbaseTemplate<'a>,
    pool_identifier: &'a str,
    extranonce_slot_size: usize,
) -> JobKeyTuple<'a> {
    (
        network,
        pool_identifier,
        extranonce_slot_size,
        payouts,
        template.coinbase_prefix,
        template.coinbase_tx_version,
        template.coinbase_tx_input_sequence,
        template.coinbase_tx_value_remaining,
        template.coinbase_tx_outputs,
        template.coinbase_tx_outputs_count,
        template.coinbase_tx_locktime,
    )
}

/// THE outputs-level cache key: (network, reward, payouts).
type OutputsKeyTuple<'a> = (Network, u64, &'a [PayoutEntry]);

fn hash_tuple<T: Hash>(tuple: &T) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    tuple.hash(&mut h);
    h.finish()
}

/// Owned copy of every job-build input — the stored side of the cache
/// key. Compared against lookups via [`JobKeyTuple`] only.
struct JobKey {
    network: Network,
    pool_identifier: String,
    extranonce_slot_size: usize,
    /// Shared with the matching [`OutputsKey`] (and across job entries
    /// of the same payout set) — one allocation per distinct payout
    /// set, not one per entry.
    payouts: Arc<Vec<PayoutEntry>>,
    coinbase_prefix: Vec<u8>,
    coinbase_tx_version: u32,
    coinbase_tx_input_sequence: u32,
    coinbase_tx_value_remaining: u64,
    coinbase_tx_outputs: Vec<u8>,
    coinbase_tx_outputs_count: u32,
    coinbase_tx_locktime: u32,
}

impl JobKey {
    /// Exhaustive destructure — adding a JobKey field without adding it
    /// to the tuple fails to compile, keeping key equality complete.
    fn as_tuple(&self) -> JobKeyTuple<'_> {
        let JobKey {
            network,
            pool_identifier,
            extranonce_slot_size,
            payouts,
            coinbase_prefix,
            coinbase_tx_version,
            coinbase_tx_input_sequence,
            coinbase_tx_value_remaining,
            coinbase_tx_outputs,
            coinbase_tx_outputs_count,
            coinbase_tx_locktime,
        } = self;
        (
            *network,
            pool_identifier.as_str(),
            *extranonce_slot_size,
            payouts.as_slice(),
            coinbase_prefix.as_slice(),
            *coinbase_tx_version,
            *coinbase_tx_input_sequence,
            *coinbase_tx_value_remaining,
            coinbase_tx_outputs.as_slice(),
            *coinbase_tx_outputs_count,
            *coinbase_tx_locktime,
        )
    }
}

struct OutputsKey {
    network: Network,
    reward_sats: u64,
    payouts: Arc<Vec<PayoutEntry>>,
}

impl OutputsKey {
    fn as_tuple(&self) -> OutputsKeyTuple<'_> {
        let OutputsKey {
            network,
            reward_sats,
            payouts,
        } = self;
        (*network, *reward_sats, payouts.as_slice())
    }
}

// ── Generic coalescing slot map ─────────────────────────────────────

/// Per-key build slot. The slot mutex is the ONLY lock held during a
/// build: the leader locks it, builds, publishes; same-key followers
/// block here (not on the map's global lock) and read the result.
struct ValueSlot<V> {
    value: Mutex<Option<Arc<V>>>,
}

// Manual, not `#[derive(Default)]`: the slot must default to an EMPTY
// value regardless of whether `V: Default` (MiningJob has no Default).
impl<V> Default for ValueSlot<V> {
    fn default() -> Self {
        Self {
            value: Mutex::new(None),
        }
    }
}

struct SlotEntry<K, V> {
    key: K,
    slot: Arc<ValueSlot<V>>,
    last_used: Instant,
}

/// Did [`CoalescingSlotMap::get_or_build`] serve an already-built value,
/// or run the builder? The caller maps this onto its own hit/built
/// counters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SlotOutcome {
    Hit,
    Built,
}

/// A hash-bucketed map with per-key build coalescing + TTL pruning — the
/// one place the leader/follower slot invariant lives, shared by both
/// cache levels.
///
/// The map mutex guards ONLY map operations (bucket lookup / install /
/// prune); the actual build runs under the per-key slot lock so distinct
/// keys build in parallel while same-key callers coalesce. The owned key
/// `K` is compared against a borrowed lookup via a caller-supplied
/// predicate and hashed by the caller — the map stays agnostic to the
/// key/lookup shapes.
struct CoalescingSlotMap<K, V> {
    inner: Mutex<SlotMapInner<K, V>>,
}

struct SlotMapInner<K, V> {
    buckets: HashMap<u64, Vec<SlotEntry<K, V>>>,
    last_prune: Instant,
}

impl<K, V> CoalescingSlotMap<K, V> {
    fn new() -> Self {
        Self {
            inner: Mutex::new(SlotMapInner {
                buckets: HashMap::new(),
                last_prune: Instant::now(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SlotMapInner<K, V>> {
        // Recover a poisoned lock: the map is only mutated by single-step
        // ops, so no cross-op invariant can be left half-applied by a
        // panic elsewhere.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Return the value for `hash`/`matches` — from the slot if already
    /// built (coalescing onto the leader), else build it as the leader
    /// via `build`, installing a fresh slot keyed by `make_key` on a map
    /// miss. `now` also drives the rate-limited prune sweep. A failed
    /// build leaves the slot empty (no negative caching).
    fn get_or_build<E>(
        &self,
        hash: u64,
        now: Instant,
        matches: impl Fn(&K) -> bool,
        make_key: impl FnOnce() -> K,
        build: impl FnOnce() -> Result<Arc<V>, E>,
    ) -> Result<(Arc<V>, SlotOutcome), E> {
        // Map phase (map lock only — no build): find or install the slot.
        let slot = {
            let mut inner = self.lock();
            inner.maybe_prune(now);
            let existing = inner
                .buckets
                .get_mut(&hash)
                .and_then(|bucket| bucket.iter_mut().find(|e| matches(&e.key)))
                .map(|entry| {
                    entry.last_used = now;
                    entry.slot.clone()
                });
            match existing {
                Some(slot) => slot,
                None => {
                    let slot = Arc::new(ValueSlot::default());
                    inner.buckets.entry(hash).or_default().push(SlotEntry {
                        key: make_key(),
                        slot: slot.clone(),
                        last_used: now,
                    });
                    slot
                }
            }
        };

        // Build phase (per-key slot lock only): leader builds, same-key
        // followers block here while other keys proceed in parallel.
        let mut guard = slot
            .value
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(value) = guard.as_ref() {
            return Ok((value.clone(), SlotOutcome::Hit));
        }
        let value = build()?;
        *guard = Some(value.clone());
        Ok((value, SlotOutcome::Built))
    }

    /// Refresh the `last_used` of the entry for `hash`/`matches` and
    /// return `project(&key)` if present — keeps an entry warm (and reads
    /// a shared field off its key) without building.
    fn touch<R>(
        &self,
        hash: u64,
        now: Instant,
        matches: impl Fn(&K) -> bool,
        project: impl FnOnce(&K) -> R,
    ) -> Option<R> {
        let mut inner = self.lock();
        let entry = inner
            .buckets
            .get_mut(&hash)?
            .iter_mut()
            .find(|e| matches(&e.key))?;
        entry.last_used = now;
        Some(project(&entry.key))
    }

    fn prune_expired(&self, now: Instant) {
        self.lock().maybe_prune(now);
    }

    /// Test hook: force a sweep at `now`, bypassing the rate limit.
    #[cfg(test)]
    fn force_prune(&self, now: Instant) {
        self.lock().prune(now);
    }

    /// Test hook: number of entries currently stored.
    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.lock().buckets.values().map(Vec::len).sum()
    }

    /// Test hook: `project(&key)` for every stored entry.
    #[cfg(test)]
    fn map_keys<R>(&self, project: impl Fn(&K) -> R) -> Vec<R> {
        self.lock()
            .buckets
            .values()
            .flatten()
            .map(|e| project(&e.key))
            .collect()
    }

    /// Test hook: `last_used` of the sole entry (panics unless exactly
    /// one exists — the single-payout-set test shape).
    #[cfg(test)]
    fn sole_last_used(&self) -> Instant {
        let inner = self.lock();
        let mut it = inner.buckets.values().flatten();
        let first = it.next().expect("one entry");
        assert!(it.next().is_none(), "expected exactly one entry");
        first.last_used
    }
}

impl<K, V> SlotMapInner<K, V> {
    fn maybe_prune(&mut self, now: Instant) {
        if now.duration_since(self.last_prune) < PRUNE_INTERVAL {
            return;
        }
        self.prune(now);
    }

    fn prune(&mut self, now: Instant) {
        self.last_prune = now;
        self.buckets.retain(|_, bucket| {
            bucket.retain(|e| now.duration_since(e.last_used) < ENTRY_TTL);
            !bucket.is_empty()
        });
    }
}

/// Cumulative counters — how often the cache actually built vs served
/// from memory. Exposed for tests + metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MiningJobCacheStats {
    /// `get_or_build` calls answered from an already-built slot.
    pub job_hits: u64,
    /// Full job assemblies (serialize + split) that had to run.
    pub jobs_built: u64,
    /// Payout-output parses (`address_to_script` per output) that had
    /// to run — the expensive step the cache exists to collapse.
    pub outputs_built: u64,
}

/// Pool-wide `MiningJob` memoization — see the module docs. Cheap to
/// share via `Arc`; all methods take `&self`. Both levels are
/// [`CoalescingSlotMap`]s; this type only wires them together (payouts
/// Arc sharing, error precedence) and tallies stats.
pub struct MiningJobCache {
    jobs: CoalescingSlotMap<JobKey, MiningJob>,
    outputs: CoalescingSlotMap<OutputsKey, PayoutOutputs>,
    job_hits: AtomicU64,
    jobs_built: AtomicU64,
    outputs_built: AtomicU64,
}

impl std::fmt::Debug for MiningJobCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MiningJobCache")
            .field("job_buckets", &self.jobs.lock().buckets.len())
            .field("output_buckets", &self.outputs.lock().buckets.len())
            .field("stats", &self.stats())
            .finish()
    }
}

impl Default for MiningJobCache {
    fn default() -> Self {
        Self::new()
    }
}

impl MiningJobCache {
    pub fn new() -> Self {
        Self {
            jobs: CoalescingSlotMap::new(),
            outputs: CoalescingSlotMap::new(),
            job_hits: AtomicU64::new(0),
            jobs_built: AtomicU64::new(0),
            outputs_built: AtomicU64::new(0),
        }
    }

    /// Return the memoized `MiningJob` for these exact build inputs, or
    /// build (and cache) it. Behaviorally identical to
    /// [`crate::build_mining_job_from_tdp`] — same result bytes, same
    /// errors in the same precedence; failed builds are never cached.
    pub fn get_or_build(
        &self,
        network: Network,
        payouts: &[PayoutEntry],
        template: &TdpCoinbaseTemplate<'_>,
        pool_identifier: &str,
        extranonce_slot_size: usize,
    ) -> Result<Arc<MiningJob>, MiningJobError> {
        if payouts.is_empty() {
            return Err(MiningJobError::NoPayouts);
        }

        let lookup = job_key_tuple(
            network,
            payouts,
            template,
            pool_identifier,
            extranonce_slot_size,
        );
        let job_hash = hash_tuple(&lookup);
        let reward = template.coinbase_tx_value_remaining;
        let now = Instant::now();

        // Resolve the canonical payouts Arc from the outputs level FIRST.
        // This also refreshes that entry's `last_used`, so the shared
        // parsed outputs stay warm alongside this job even on a pure
        // job-hit (which never reaches the build closure below). Absent
        // → allocate the payout vec once; the job key and the outputs
        // entry then share this one allocation.
        let payouts_arc = self
            .touch_outputs(network, reward, payouts, now)
            .unwrap_or_else(|| Arc::new(payouts.to_vec()));
        let key_payouts = payouts_arc.clone();

        let (job, outcome) = self.jobs.get_or_build(
            job_hash,
            now,
            |k| k.as_tuple() == lookup,
            move || JobKey {
                network,
                pool_identifier: pool_identifier.to_string(),
                extranonce_slot_size,
                payouts: key_payouts,
                coinbase_prefix: template.coinbase_prefix.to_vec(),
                coinbase_tx_version: template.coinbase_tx_version,
                coinbase_tx_input_sequence: template.coinbase_tx_input_sequence,
                coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
                coinbase_tx_outputs: template.coinbase_tx_outputs.to_vec(),
                coinbase_tx_outputs_count: template.coinbase_tx_outputs_count,
                coinbase_tx_locktime: template.coinbase_tx_locktime,
            },
            // Leader build. Error precedence mirrors
            // build_mining_job_from_tdp: ScriptSigTooLong before
            // InvalidAddress.
            move || -> Result<Arc<MiningJob>, MiningJobError> {
                let script_sig = checked_tdp_scriptsig(
                    template.coinbase_prefix,
                    pool_identifier,
                    extranonce_slot_size,
                )?;
                let payout_outputs =
                    self.get_or_parse_outputs(network, payouts, reward, payouts_arc, now)?;
                Ok(Arc::new(assemble_tdp_job(
                    script_sig,
                    &payout_outputs,
                    template,
                    extranonce_slot_size,
                )))
            },
        )?;

        match outcome {
            SlotOutcome::Hit => {
                self.job_hits.fetch_add(1, Ordering::Relaxed);
            }
            SlotOutcome::Built => {
                self.jobs_built.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(job)
    }

    /// Outputs-level lookup over the shared coalescing map. Called only
    /// by a job-slot leader — the job-slot lock is held across the
    /// outputs map lock + outputs-slot lock (lock order job-slot →
    /// outputs-map → outputs-slot, no cycle; see the module docs).
    fn get_or_parse_outputs(
        &self,
        network: Network,
        payouts: &[PayoutEntry],
        reward_sats: u64,
        payouts_arc: Arc<Vec<PayoutEntry>>,
        now: Instant,
    ) -> Result<Arc<PayoutOutputs>, MiningJobError> {
        let lookup: OutputsKeyTuple<'_> = (network, reward_sats, payouts);
        let hash = hash_tuple(&lookup);
        let (outputs, outcome) = self.outputs.get_or_build(
            hash,
            now,
            |k| k.as_tuple() == lookup,
            // Share the job entry's payouts allocation — one copy per
            // distinct payout set across both levels.
            move || OutputsKey {
                network,
                reward_sats,
                payouts: payouts_arc,
            },
            || -> Result<Arc<PayoutOutputs>, MiningJobError> {
                Ok(Arc::new(build_payout_outputs(
                    network,
                    payouts,
                    reward_sats,
                )?))
            },
        )?;
        if matches!(outcome, SlotOutcome::Built) {
            self.outputs_built.fetch_add(1, Ordering::Relaxed);
        }
        Ok(outputs)
    }

    /// Refresh the `last_used` of the outputs entry for
    /// (network, reward, payouts) and return its shared payouts Arc, if
    /// one exists. Called on every `get_or_build` — including a pure
    /// job-hit — so the backing outputs entry can never age out from
    /// under a live job (which would waste the address-parse
    /// memoization it exists for), and so a new job entry reuses the one
    /// payouts allocation instead of cloning the vec again.
    fn touch_outputs(
        &self,
        network: Network,
        reward_sats: u64,
        payouts: &[PayoutEntry],
        now: Instant,
    ) -> Option<Arc<Vec<PayoutEntry>>> {
        let lookup: OutputsKeyTuple<'_> = (network, reward_sats, payouts);
        let hash = hash_tuple(&lookup);
        self.outputs
            .touch(hash, now, |k| k.as_tuple() == lookup, |k| k.payouts.clone())
    }

    /// Drop entries unused for [`ENTRY_TTL`], rate-limited to one sweep
    /// per [`PRUNE_INTERVAL`] per level. Piggybacked on every lookup AND
    /// driven by the stratum translator tasks on each template update,
    /// so memory is reclaimed even when no miner is connected (no
    /// lookups).
    pub fn prune_expired(&self) {
        let now = Instant::now();
        self.jobs.prune_expired(now);
        self.outputs.prune_expired(now);
    }

    pub fn stats(&self) -> MiningJobCacheStats {
        MiningJobCacheStats {
            job_hits: self.job_hits.load(Ordering::Relaxed),
            jobs_built: self.jobs_built.load(Ordering::Relaxed),
            outputs_built: self.outputs_built.load(Ordering::Relaxed),
        }
    }

    /// Test hook: force a sweep at `now` on both levels, bypassing the
    /// PRUNE_INTERVAL rate limit.
    #[cfg(test)]
    fn prune_at(&self, now: Instant) {
        self.jobs.force_prune(now);
        self.outputs.force_prune(now);
    }

    /// Test hook: (job entries, output entries) currently stored.
    #[cfg(test)]
    fn entry_counts(&self) -> (usize, usize) {
        (self.jobs.entry_count(), self.outputs.entry_count())
    }

    /// Test hook: `last_used` of the sole outputs entry (panics unless
    /// exactly one exists — the single-payout-set test shape).
    #[cfg(test)]
    fn sole_outputs_last_used(&self) -> Instant {
        self.outputs.sole_last_used()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coinbase::build_mining_job_from_tdp;

    const MINER_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const MINER_B: &str = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
    const REWARD: u64 = 5_000_000_000;

    fn tdp_fixture() -> (Vec<u8>, Vec<u8>) {
        // BIP-34 prefix for height 800_000 + one OP_RETURN-shaped output.
        let prefix = vec![0x03, 0x00, 0x35, 0x0c];
        let mut outputs = Vec::new();
        outputs.extend_from_slice(&0u64.to_le_bytes());
        outputs.push(0x26);
        outputs.push(0x6a);
        outputs.push(0x24);
        outputs.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]);
        outputs.extend(std::iter::repeat_n(0xCC, 32));
        (prefix, outputs)
    }

    fn template<'a>(prefix: &'a [u8], outputs: &'a [u8]) -> TdpCoinbaseTemplate<'a> {
        TdpCoinbaseTemplate {
            coinbase_prefix: prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFF_FFFE,
            coinbase_tx_value_remaining: REWARD,
            coinbase_tx_outputs: outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        }
    }

    fn payouts_two_way() -> Vec<PayoutEntry> {
        vec![
            PayoutEntry {
                address: MINER_A.to_string(),
                sats: 3_000_000_000,
            },
            PayoutEntry {
                address: MINER_B.to_string(),
                sats: 2_000_000_000,
            },
        ]
    }

    #[test]
    fn cached_job_is_byte_identical_to_direct_build() {
        let (prefix, outputs) = tdp_fixture();
        let tmpl = template(&prefix, &outputs);
        let payouts = payouts_two_way();
        let cache = MiningJobCache::new();

        let cached = cache
            .get_or_build(Network::Bitcoin, &payouts, &tmpl, "BP", 12)
            .unwrap();
        let direct =
            build_mining_job_from_tdp(Network::Bitcoin, &payouts, &tmpl, "BP", 12).unwrap();

        assert_eq!(cached.coinbase_prefix(), direct.coinbase_prefix());
        assert_eq!(cached.coinbase_suffix(), direct.coinbase_suffix());
    }

    #[test]
    fn identical_inputs_share_one_arc() {
        let (prefix, outputs) = tdp_fixture();
        let tmpl = template(&prefix, &outputs);
        let payouts = payouts_two_way();
        let cache = MiningJobCache::new();

        let first = cache
            .get_or_build(Network::Bitcoin, &payouts, &tmpl, "BP", 12)
            .unwrap();
        let second = cache
            .get_or_build(Network::Bitcoin, &payouts, &tmpl, "BP", 12)
            .unwrap();

        assert!(
            Arc::ptr_eq(&first, &second),
            "second call must be a cache hit"
        );
        let stats = cache.stats();
        assert_eq!(stats.jobs_built, 1);
        assert_eq!(stats.job_hits, 1);
        assert_eq!(stats.outputs_built, 1);
    }

    #[test]
    fn concurrent_same_key_callers_build_exactly_once() {
        // 8 threads race on one key: exactly one leader builds, the
        // rest coalesce onto its slot and share the same Arc.
        let (prefix, outputs) = tdp_fixture();
        let payouts = payouts_two_way();
        let cache = Arc::new(MiningJobCache::new());

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let cache = cache.clone();
                let prefix = prefix.clone();
                let outputs = outputs.clone();
                let payouts = payouts.clone();
                std::thread::spawn(move || {
                    let tmpl = template(&prefix, &outputs);
                    cache
                        .get_or_build(Network::Bitcoin, &payouts, &tmpl, "BP", 12)
                        .unwrap()
                })
            })
            .collect();

        let jobs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for job in &jobs[1..] {
            assert!(Arc::ptr_eq(&jobs[0], job));
        }
        let stats = cache.stats();
        assert_eq!(stats.jobs_built, 1, "exactly one leader build");
        assert_eq!(stats.outputs_built, 1);
        assert_eq!(stats.job_hits, 7);
    }

    #[test]
    fn concurrent_distinct_keys_build_independently() {
        // 8 threads with 8 distinct payout sets (the Solo/Group-Solo
        // broadcast-storm shape): all build, none blocks on another
        // key's slot, and every job pays its own miner.
        let (prefix, outputs) = tdp_fixture();
        let cache = Arc::new(MiningJobCache::new());

        let handles: Vec<_> = (0..8u64)
            .map(|i| {
                let cache = cache.clone();
                let prefix = prefix.clone();
                let outputs = outputs.clone();
                std::thread::spawn(move || {
                    let tmpl = template(&prefix, &outputs);
                    // Same addresses, distinct sats split per "finder".
                    let payouts = vec![
                        PayoutEntry {
                            address: MINER_A.to_string(),
                            sats: 3_000_000_000 + i,
                        },
                        PayoutEntry {
                            address: MINER_B.to_string(),
                            sats: 2_000_000_000 - i,
                        },
                    ];
                    cache
                        .get_or_build(Network::Bitcoin, &payouts, &tmpl, "BP", 12)
                        .unwrap()
                })
            })
            .collect();

        let jobs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for (i, a) in jobs.iter().enumerate() {
            for b in &jobs[i + 1..] {
                assert!(!Arc::ptr_eq(a, b));
                assert_ne!(a.coinbase_suffix(), b.coinbase_suffix());
            }
        }
        assert_eq!(cache.stats().jobs_built, 8);
    }

    #[test]
    fn different_payout_sets_get_distinct_jobs() {
        // The per-finder case (Solo / Group-Solo / Blockparty): two
        // payout sets differing in ONE address must never share bytes.
        let (prefix, outputs) = tdp_fixture();
        let tmpl = template(&prefix, &outputs);
        let cache = MiningJobCache::new();

        let payouts_a = vec![PayoutEntry {
            address: MINER_A.to_string(),
            sats: REWARD,
        }];
        let payouts_b = vec![PayoutEntry {
            address: MINER_B.to_string(),
            sats: REWARD,
        }];

        let job_a = cache
            .get_or_build(Network::Bitcoin, &payouts_a, &tmpl, "BP", 12)
            .unwrap();
        let job_b = cache
            .get_or_build(Network::Bitcoin, &payouts_b, &tmpl, "BP", 12)
            .unwrap();

        assert!(!Arc::ptr_eq(&job_a, &job_b));
        assert_ne!(job_a.coinbase_suffix(), job_b.coinbase_suffix());
        assert_eq!(cache.stats().jobs_built, 2);
    }

    #[test]
    fn different_payout_amounts_get_distinct_jobs() {
        // Same addresses, different sats split (e.g. a Group-Solo
        // finder bonus moving between members) must be distinct keys.
        let (prefix, outputs) = tdp_fixture();
        let tmpl = template(&prefix, &outputs);
        let cache = MiningJobCache::new();

        let payouts_a = payouts_two_way();
        let mut payouts_b = payouts_two_way();
        payouts_b[0].sats += 1;
        payouts_b[1].sats -= 1;

        let job_a = cache
            .get_or_build(Network::Bitcoin, &payouts_a, &tmpl, "BP", 12)
            .unwrap();
        let job_b = cache
            .get_or_build(Network::Bitcoin, &payouts_b, &tmpl, "BP", 12)
            .unwrap();

        assert!(!Arc::ptr_eq(&job_a, &job_b));
        assert_ne!(job_a.coinbase_suffix(), job_b.coinbase_suffix());
    }

    #[test]
    fn different_slot_sizes_reuse_parsed_outputs() {
        // SV2 Extended: same payout set, channel-negotiated slot sizes.
        // Each slot size is its own job, but the address parse runs once.
        let (prefix, outputs) = tdp_fixture();
        let tmpl = template(&prefix, &outputs);
        let payouts = payouts_two_way();
        let cache = MiningJobCache::new();

        let job_12 = cache
            .get_or_build(Network::Bitcoin, &payouts, &tmpl, "BP", 12)
            .unwrap();
        let job_16 = cache
            .get_or_build(Network::Bitcoin, &payouts, &tmpl, "BP", 16)
            .unwrap();

        assert!(!Arc::ptr_eq(&job_12, &job_16));
        let stats = cache.stats();
        assert_eq!(stats.jobs_built, 2);
        assert_eq!(
            stats.outputs_built, 1,
            "outputs parsed once across slot sizes"
        );

        // Both must match their direct-build equivalents.
        for (job, slot) in [(&job_12, 12), (&job_16, 16)] {
            let direct =
                build_mining_job_from_tdp(Network::Bitcoin, &payouts, &tmpl, "BP", slot).unwrap();
            assert_eq!(job.coinbase_prefix(), direct.coinbase_prefix());
            assert_eq!(job.coinbase_suffix(), direct.coinbase_suffix());
        }
    }

    #[test]
    fn template_change_is_a_distinct_job_but_reuses_outputs() {
        let (prefix, outputs) = tdp_fixture();
        let tmpl_a = template(&prefix, &outputs);
        // Same reward, different BIP-34 prefix (next height) — as in a
        // template refresh where fees happened to cancel out.
        let prefix_b = vec![0x03, 0x01, 0x35, 0x0c];
        let tmpl_b = template(&prefix_b, &outputs);
        let payouts = payouts_two_way();
        let cache = MiningJobCache::new();

        let job_a = cache
            .get_or_build(Network::Bitcoin, &payouts, &tmpl_a, "BP", 12)
            .unwrap();
        let job_b = cache
            .get_or_build(Network::Bitcoin, &payouts, &tmpl_b, "BP", 12)
            .unwrap();

        assert!(!Arc::ptr_eq(&job_a, &job_b));
        assert_ne!(job_a.coinbase_prefix(), job_b.coinbase_prefix());
        let stats = cache.stats();
        assert_eq!(stats.jobs_built, 2);
        assert_eq!(
            stats.outputs_built, 1,
            "same payout set + reward → one parse"
        );
    }

    #[test]
    fn error_precedence_matches_direct_build() {
        // Oversized TDP prefix (identifier-less scriptsig already > 100
        // bytes) AND an invalid payout address: both the direct build
        // and the cache must report ScriptSigTooLong — the scriptsig
        // check runs before any address parse.
        let long_prefix = vec![0x01; 95]; // 95 + 12-byte slot > 100
        let (_, outputs) = tdp_fixture();
        let tmpl = template(&long_prefix, &outputs);
        let bad = vec![PayoutEntry {
            address: "not-an-address".to_string(),
            sats: REWARD,
        }];

        assert!(matches!(
            build_mining_job_from_tdp(Network::Bitcoin, &bad, &tmpl, "BP", 12),
            Err(MiningJobError::ScriptSigTooLong(_))
        ));
        let cache = MiningJobCache::new();
        assert!(matches!(
            cache.get_or_build(Network::Bitcoin, &bad, &tmpl, "BP", 12),
            Err(MiningJobError::ScriptSigTooLong(_))
        ));
    }

    #[test]
    fn empty_payouts_error_and_are_not_cached() {
        let (prefix, outputs) = tdp_fixture();
        let tmpl = template(&prefix, &outputs);
        let cache = MiningJobCache::new();
        assert!(matches!(
            cache.get_or_build(Network::Bitcoin, &[], &tmpl, "BP", 12),
            Err(MiningJobError::NoPayouts)
        ));
        assert_eq!(cache.stats(), MiningJobCacheStats::default());
        assert_eq!(cache.entry_counts(), (0, 0));
    }

    #[test]
    fn invalid_address_error_is_not_cached_and_retries() {
        let (prefix, outputs) = tdp_fixture();
        let tmpl = template(&prefix, &outputs);
        let cache = MiningJobCache::new();
        let bad = vec![PayoutEntry {
            address: "not-an-address".to_string(),
            sats: REWARD,
        }];
        for _ in 0..2 {
            assert!(matches!(
                cache.get_or_build(Network::Bitcoin, &bad, &tmpl, "BP", 12),
                Err(MiningJobError::InvalidAddress(_))
            ));
        }
        let stats = cache.stats();
        assert_eq!(stats.jobs_built, 0);
        assert_eq!(stats.job_hits, 0, "a failed slot must not count as a hit");
    }

    #[test]
    fn network_is_part_of_the_key() {
        // Same bech32 string can't be valid on two networks, but the
        // key must still separate networks so a (theoretical) shared
        // encoding can never leak a script across networks.
        let (prefix, outputs) = tdp_fixture();
        let tmpl = template(&prefix, &outputs);
        let cache = MiningJobCache::new();
        let payouts = vec![PayoutEntry {
            address: MINER_A.to_string(),
            sats: REWARD,
        }];
        let job = cache
            .get_or_build(Network::Bitcoin, &payouts, &tmpl, "BP", 12)
            .unwrap();
        // Regtest lookup with the same payouts must NOT return the
        // mainnet job — it fails the parse instead of hitting.
        let regtest = cache.get_or_build(Network::Regtest, &payouts, &tmpl, "BP", 12);
        assert!(regtest.is_err());
        drop(job);
    }

    #[test]
    fn prune_evicts_entries_after_ttl() {
        let (prefix, outputs) = tdp_fixture();
        let tmpl = template(&prefix, &outputs);
        let payouts = payouts_two_way();
        let cache = MiningJobCache::new();

        cache
            .get_or_build(Network::Bitcoin, &payouts, &tmpl, "BP", 12)
            .unwrap();
        assert_eq!(cache.entry_counts(), (1, 1));

        // Within TTL: entries survive a sweep.
        cache.prune_at(Instant::now() + ENTRY_TTL / 2);
        assert_eq!(cache.entry_counts(), (1, 1));

        // Past TTL: both levels are emptied.
        cache.prune_at(Instant::now() + ENTRY_TTL + Duration::from_secs(1));
        assert_eq!(cache.entry_counts(), (0, 0));

        // And a rebuilt entry works fine afterwards.
        let again = cache
            .get_or_build(Network::Bitcoin, &payouts, &tmpl, "BP", 12)
            .unwrap();
        assert!(!again.coinbase_prefix().is_empty());
        assert_eq!(cache.stats().jobs_built, 2);
    }

    #[test]
    fn job_hit_refreshes_backing_outputs_entry() {
        // Regression: a pure job-hit never reaches get_or_parse_outputs,
        // so it must still refresh the backing outputs entry's last_used
        // — otherwise a long run of hits on a stable template would let
        // the shared outputs entry age out from under the live job and
        // force a needless address reparse for the next distinct job key.
        let (prefix, outputs) = tdp_fixture();
        let tmpl = template(&prefix, &outputs);
        let payouts = payouts_two_way();
        let cache = MiningJobCache::new();

        cache
            .get_or_build(Network::Bitcoin, &payouts, &tmpl, "BP", 12)
            .unwrap();
        let built_at = cache.sole_outputs_last_used();

        // Guarantee the monotonic clock advances so the refresh is
        // observable (Instant has ns resolution on the CI platform).
        std::thread::sleep(Duration::from_millis(2));

        // Pure job-hit: identical key.
        cache
            .get_or_build(Network::Bitcoin, &payouts, &tmpl, "BP", 12)
            .unwrap();
        assert_eq!(cache.stats().job_hits, 1, "second call must be a job-hit");

        assert!(
            cache.sole_outputs_last_used() > built_at,
            "a job-hit must refresh the backing outputs entry's last_used"
        );
    }

    #[test]
    fn job_key_shares_payouts_arc_with_outputs_key() {
        // The payout vec is stored once per distinct payout set: the
        // second template's JobKey reuses the outputs entry's Arc
        // instead of cloning the vec again.
        let (prefix, outputs) = tdp_fixture();
        let tmpl_a = template(&prefix, &outputs);
        let prefix_b = vec![0x03, 0x01, 0x35, 0x0c];
        let tmpl_b = template(&prefix_b, &outputs);
        let payouts = payouts_two_way();
        let cache = MiningJobCache::new();

        cache
            .get_or_build(Network::Bitcoin, &payouts, &tmpl_a, "BP", 12)
            .unwrap();
        cache
            .get_or_build(Network::Bitcoin, &payouts, &tmpl_b, "BP", 12)
            .unwrap();

        let job_arcs = cache.jobs.map_keys(|k| k.payouts.clone());
        let outputs_arcs = cache.outputs.map_keys(|k| k.payouts.clone());
        assert_eq!(job_arcs.len(), 2, "one job entry per template");
        assert_eq!(
            outputs_arcs.len(),
            1,
            "one outputs entry for the payout set"
        );
        for arc in &job_arcs {
            assert!(
                Arc::ptr_eq(arc, &outputs_arcs[0]),
                "job keys must share the outputs entry's payouts allocation"
            );
        }
    }
}
