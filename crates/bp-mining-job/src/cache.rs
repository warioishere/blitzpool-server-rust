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
//! The global mutex guards ONLY the map operations (lookup / insert /
//! prune) — never a build. Each key owns a slot with its own mutex:
//! the first caller for a key becomes the leader and builds while
//! holding just that slot's lock, so callers for OTHER keys build in
//! parallel exactly as they did pre-cache (Solo / Group-Solo payout
//! sets are distinct per connection — those must not serialize behind
//! one pool-wide lock), while same-key callers (PPLNS broadcast storm)
//! wait on their slot and then share the leader's result instead of
//! thundering-herd-rebuilding it. A failed build leaves the slot empty
//! — no negative caching, the next caller retries.
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
//! so memory is reclaimed even when no miner is connected.

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

// ── Slots + entries ─────────────────────────────────────────────────

/// Per-key build slot. The slot mutex is the ONLY lock held during a
/// build: the leader locks it, builds, publishes; same-key followers
/// block here (not on the global map lock) and read the result.
#[derive(Default)]
struct JobSlot {
    job: Mutex<Option<Arc<MiningJob>>>,
}

#[derive(Default)]
struct OutputsSlot {
    outputs: Mutex<Option<Arc<PayoutOutputs>>>,
}

struct JobEntry {
    key: JobKey,
    slot: Arc<JobSlot>,
    last_used: Instant,
}

struct OutputsEntry {
    key: OutputsKey,
    slot: Arc<OutputsSlot>,
    last_used: Instant,
}

struct CacheInner {
    jobs: HashMap<u64, Vec<JobEntry>>,
    outputs: HashMap<u64, Vec<OutputsEntry>>,
    last_prune: Instant,
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
/// share via `Arc`; all methods take `&self`.
pub struct MiningJobCache {
    inner: Mutex<CacheInner>,
    job_hits: AtomicU64,
    jobs_built: AtomicU64,
    outputs_built: AtomicU64,
}

impl std::fmt::Debug for MiningJobCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.lock_inner();
        f.debug_struct("MiningJobCache")
            .field("job_buckets", &inner.jobs.len())
            .field("output_buckets", &inner.outputs.len())
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
            inner: Mutex::new(CacheInner {
                jobs: HashMap::new(),
                outputs: HashMap::new(),
                last_prune: Instant::now(),
            }),
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
        let now = Instant::now();

        // Map phase (global lock, map ops only — no build): find the
        // key's slot or install a fresh one. The entry's payouts Arc
        // rides along so the outputs level can share the allocation.
        let (slot, payouts_arc) = {
            let mut inner = self.lock_inner();
            inner.maybe_prune(now);
            match inner
                .jobs
                .get_mut(&job_hash)
                .and_then(|bucket| bucket.iter_mut().find(|e| e.key.as_tuple() == lookup))
            {
                Some(entry) => {
                    entry.last_used = now;
                    (entry.slot.clone(), entry.key.payouts.clone())
                }
                None => {
                    // One payouts allocation per distinct payout set:
                    // reuse the outputs-level Arc when this set is
                    // already known (e.g. a new template, same window).
                    let payouts_arc = inner
                        .find_outputs_payouts_arc(network, payouts, template)
                        .unwrap_or_else(|| Arc::new(payouts.to_vec()));
                    let slot = Arc::new(JobSlot::default());
                    let key = JobKey {
                        network,
                        pool_identifier: pool_identifier.to_string(),
                        extranonce_slot_size,
                        payouts: payouts_arc,
                        coinbase_prefix: template.coinbase_prefix.to_vec(),
                        coinbase_tx_version: template.coinbase_tx_version,
                        coinbase_tx_input_sequence: template.coinbase_tx_input_sequence,
                        coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
                        coinbase_tx_outputs: template.coinbase_tx_outputs.to_vec(),
                        coinbase_tx_outputs_count: template.coinbase_tx_outputs_count,
                        coinbase_tx_locktime: template.coinbase_tx_locktime,
                    };
                    let payouts_arc = key.payouts.clone();
                    inner.jobs.entry(job_hash).or_default().push(JobEntry {
                        key,
                        slot: slot.clone(),
                        last_used: now,
                    });
                    (slot, payouts_arc)
                }
            }
        };

        // Build phase (per-key slot lock only): first locker with an
        // empty slot is the leader; same-key followers block on THIS
        // slot while other keys proceed in parallel.
        let mut job_guard = slot
            .job
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(job) = job_guard.as_ref() {
            self.job_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(job.clone());
        }

        // Leader. Error precedence mirrors build_mining_job_from_tdp:
        // ScriptSigTooLong before InvalidAddress.
        let script_sig = checked_tdp_scriptsig(
            template.coinbase_prefix,
            pool_identifier,
            extranonce_slot_size,
        )?;
        let payout_outputs = self.get_or_parse_outputs(
            network,
            payouts,
            template.coinbase_tx_value_remaining,
            payouts_arc,
            now,
        )?;
        let job = Arc::new(assemble_tdp_job(
            script_sig,
            &payout_outputs,
            template,
            extranonce_slot_size,
        ));
        self.jobs_built.fetch_add(1, Ordering::Relaxed);
        *job_guard = Some(job.clone());
        Ok(job)
        // On error the slot stays empty: waiting followers see None,
        // become the new leader, and retry — no negative caching.
    }

    /// Outputs-level lookup with the same slot pattern. Called only by
    /// a job-slot leader; the job-slot lock is held while this takes
    /// the global lock and then an outputs-slot lock. Lock order is
    /// strictly job-slot → global → outputs-slot and the global lock
    /// is never held while waiting on a slot, so no cycle can form.
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

        let slot = {
            let mut inner = self.lock_inner();
            match inner
                .outputs
                .get_mut(&hash)
                .and_then(|bucket| bucket.iter_mut().find(|e| e.key.as_tuple() == lookup))
            {
                Some(entry) => {
                    entry.last_used = now;
                    entry.slot.clone()
                }
                None => {
                    let slot = Arc::new(OutputsSlot::default());
                    inner.outputs.entry(hash).or_default().push(OutputsEntry {
                        key: OutputsKey {
                            network,
                            reward_sats,
                            // Share the job entry's allocation — one
                            // payouts copy per distinct payout set.
                            payouts: payouts_arc,
                        },
                        slot: slot.clone(),
                        last_used: now,
                    });
                    slot
                }
            }
        };

        let mut guard = slot
            .outputs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(outputs) = guard.as_ref() {
            return Ok(outputs.clone());
        }
        let outputs = Arc::new(build_payout_outputs(network, payouts, reward_sats)?);
        self.outputs_built.fetch_add(1, Ordering::Relaxed);
        *guard = Some(outputs.clone());
        Ok(outputs)
    }

    /// Drop entries unused for [`ENTRY_TTL`], rate-limited to one sweep
    /// per [`PRUNE_INTERVAL`]. Piggybacked on every lookup AND driven by
    /// the stratum translator tasks on each template update, so memory
    /// is reclaimed even when no miner is connected (no lookups).
    pub fn prune_expired(&self) {
        let now = Instant::now();
        self.lock_inner().maybe_prune(now);
    }

    pub fn stats(&self) -> MiningJobCacheStats {
        MiningJobCacheStats {
            job_hits: self.job_hits.load(Ordering::Relaxed),
            jobs_built: self.jobs_built.load(Ordering::Relaxed),
            outputs_built: self.outputs_built.load(Ordering::Relaxed),
        }
    }

    fn lock_inner(&self) -> MutexGuard<'_, CacheInner> {
        // Recover a poisoned lock: the maps are only mutated by
        // single-step HashMap ops, so no cross-op invariant can be left
        // half-applied by a panic elsewhere.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Test hook: force a sweep as if the wall clock were `now`,
    /// bypassing the PRUNE_INTERVAL rate limit.
    #[cfg(test)]
    fn prune_at(&self, now: Instant) {
        self.lock_inner().prune(now);
    }

    /// Test hook: (job entries, output entries) currently stored.
    #[cfg(test)]
    fn entry_counts(&self) -> (usize, usize) {
        let inner = self.lock_inner();
        (
            inner.jobs.values().map(Vec::len).sum(),
            inner.outputs.values().map(Vec::len).sum(),
        )
    }
}

impl CacheInner {
    /// Reuse the payouts Arc of an existing outputs entry for this
    /// (network, payouts, reward) so a new job entry doesn't clone the
    /// payout vec again.
    fn find_outputs_payouts_arc(
        &mut self,
        network: Network,
        payouts: &[PayoutEntry],
        template: &TdpCoinbaseTemplate<'_>,
    ) -> Option<Arc<Vec<PayoutEntry>>> {
        let lookup: OutputsKeyTuple<'_> = (network, template.coinbase_tx_value_remaining, payouts);
        let hash = hash_tuple(&lookup);
        self.outputs
            .get(&hash)?
            .iter()
            .find(|e| e.key.as_tuple() == lookup)
            .map(|e| e.key.payouts.clone())
    }

    fn maybe_prune(&mut self, now: Instant) {
        if now.duration_since(self.last_prune) < PRUNE_INTERVAL {
            return;
        }
        self.prune(now);
    }

    fn prune(&mut self, now: Instant) {
        self.last_prune = now;
        self.jobs.retain(|_, bucket| {
            bucket.retain(|e| now.duration_since(e.last_used) < ENTRY_TTL);
            !bucket.is_empty()
        });
        self.outputs.retain(|_, bucket| {
            bucket.retain(|e| now.duration_since(e.last_used) < ENTRY_TTL);
            !bucket.is_empty()
        });
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

        let inner = cache.lock_inner();
        let job_arcs: Vec<&Arc<Vec<PayoutEntry>>> = inner
            .jobs
            .values()
            .flatten()
            .map(|e| &e.key.payouts)
            .collect();
        let outputs_arc = inner
            .outputs
            .values()
            .flatten()
            .map(|e| &e.key.payouts)
            .next()
            .expect("one outputs entry");
        assert_eq!(job_arcs.len(), 2);
        for arc in job_arcs {
            assert!(
                Arc::ptr_eq(arc, outputs_arc),
                "job keys must share the outputs entry's payouts allocation"
            );
        }
    }
}
