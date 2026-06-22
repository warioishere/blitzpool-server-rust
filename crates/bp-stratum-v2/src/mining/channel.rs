// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-channel state for SV2 Standard + Extended mining channels.
//!
//! Single `ChannelState` struct (not an enum); the [`ChannelKind`] discriminant
//! tells callers which subset of fields is meaningful for a given
//! channel:
//!
//! - **Standard**: `extranonce_size = 0` (the entire 12-byte coinbase
//!   slot is `[extranonce_prefix(4) | zero(8)]` — the miner can't
//!   roll). [`StandardJobMaps`] (`job_id_to_difficulty` +
//!   `job_id_to_merkle_root`) is the source of truth for share
//!   validation; `extended_jobs` stays empty.
//!
//! - **Extended**: `extranonce_size > 0` (miner-controlled bytes after
//!   the pool-assigned prefix; total ≤ 12). [`ExtendedJob`] storage in
//!   `extended_jobs` carries everything needed to reconstruct the
//!   coinbase + walk the merkle path on share submit;
//!   `standard_jobs` stays empty (Extended share validation reads
//!   `extended_jobs[jobId].sessionDifficulty` from the job record
//!   itself).
//!
//! `declared_max_target` is the channel's SV2-spec ceiling on
//! difficulty: the pool MUST NOT assign a target lower (= harder) than
//! this. Vardiff retargeting clamps against it before sending
//! `SetTarget`.
//!
//! [`SubmissionCache`] is the per-channel dedup set. A tuple-keyed
//! `HashSet` tracks submitted shares for duplicate detection. Cleared on
//! `SetNewPrevHash` (block change), the same point that retires the
//! extended-jobs map.
//!
//! `is_jdc` flags channels owned by Job-Declaration-Client miners
//! (BraiinsOS, custom firmware that uses ext-0x0003 + JDP). The flag
//! gates pool job broadcast — JDC clients build their own jobs via
//! `SetCustomMiningJob` and shouldn't receive pool-built
//! `NewExtendedMiningJob` frames. The detection itself (cross-check
//! against the JDP server's IP table) lives in the connection
//! state-machine; this struct just carries the flag.

use std::collections::{HashMap, HashSet};

use bp_share::{difficulty_to_target, Difficulty, Target};

use super::jobs::{ExtendedJob, StandardJobMaps};
use super::submit::ExtranonceBytes;

/// Discriminator between the two SV2 channel topologies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelKind {
    Standard,
    Extended,
}

/// Per-channel mutable state. Owned `&mut` by the connection task that
/// drives the channel (one task per SV2 connection; multiple channels
/// per connection live in a `HashMap<ChannelId, ChannelState>`).
#[derive(Clone, Debug)]
pub struct ChannelState {
    pub channel_id: u32,
    pub kind: ChannelKind,

    /// Pool-assigned extranonce prefix. 4 bytes typical for Standard
    /// (the entire prefix); 4–8 bytes for Extended (variable, allocated
    /// by [`crate::extranonce::ExtranonceAllocator`]).
    pub extranonce_prefix: Vec<u8>,
    /// Miner-controlled bytes after the prefix. `0` for Standard;
    /// `(12 - prefix.len)`-clamped for Extended (BitAxe/NerdQAxe quirk
    /// — some firmware ignores larger sizes and corrupts the coinbase
    /// varint).
    pub extranonce_size: u8,

    pub session_difficulty: Difficulty,

    /// SV2 spec: the client's declared maximum target. Pool MUST NOT
    /// assign easier targets (`difficulty > declared_max_difficulty`
    /// equivalently `target < declared_max_target`). Vardiff clamps
    /// against this before sending `SetTarget`. Stored as raw 32-byte
    /// little-endian U256 so we don't lose precision converting
    /// to/from `Difficulty` during the clamp check.
    pub declared_max_target: [u8; 32],

    /// Standard-channel job bookkeeping
    /// (`job_id_to_difficulty` + `job_id_to_merkle_root`). Empty for
    /// Extended channels.
    pub standard_jobs: StandardJobMaps,

    /// Extended-channel job storage with retire-not-clear lifecycle
    /// (sv2-ui#143). Empty for Standard channels.
    pub extended_jobs: HashMap<u32, ExtendedJob>,

    /// Block context stored at `SetNewPrevHash` time so future
    /// `NewExtendedMiningJob` frames don't need to re-derive it.
    /// `None` until the first `SetNewPrevHash` arrives. Standard
    /// channels don't need this — `NewMiningJob` carries an absolute
    /// merkle root.
    pub latest_extended_prev_hash: Option<[u8; 32]>,
    pub latest_extended_n_bits: Option<u32>,
    pub latest_extended_min_ntime: Option<u32>,

    pub accepted_share_count: u64,
    /// Sum of accepted-share difficulties. f64 because PPLNS-on-low-
    /// diff ports can have sub-1 entries; an integer accumulator
    /// would lose them.
    pub accepted_share_difficulty_sum: f64,

    /// Channel-local job-id counter. Each `NewMiningJob` /
    /// `NewExtendedMiningJob` send bumps it. SV2 `job_id` is a `u32`
    /// per the mining-protocol spec; the pool uses per-channel monotonic
    /// allocation.
    pub next_job_id: u32,

    /// Per-channel submission dedup set. Cleared on block change.
    pub submission_cache: SubmissionCache,

    /// JD-Client flag (set when the connection's IP also has an
    /// active JDP-server connection). Gates pool job broadcast.
    pub is_jdc: bool,

    /// One-shot diagnostic flag — pool logs the actual extranonce length
    /// of the first share per channel so operators can spot firmware
    /// that ignores the advertised `extranonce_size`. The flag stays
    /// `false` until the first share is processed.
    pub first_share_logged: bool,

    /// `submission_difficulty` of the most-recent accepted share — the
    /// JDC vardiff algorithm reads this to cap retargets at the work
    /// the JDC has actually proven.
    /// `None` until the first share is accepted on this channel.
    pub last_submission_difficulty: Option<Difficulty>,

    /// Memo for `difficulty_to_target` on the per-share accept check.
    /// Per-job difficulty changes only on a vardiff ratchet, so within a
    /// channel nearly every share validates at the same difficulty — a
    /// single `(difficulty bits → target)` slot serves them all and a
    /// miss just recomputes. Keyed on the exact f64 bit pattern, so the
    /// cached target is bit-identical to recomputing: purely a
    /// per-share BigUint-divide saving, no behaviour change.
    target_memo: Option<(u64, Target)>,
}

impl ChannelState {
    /// Construct a fresh **Standard** channel.
    pub fn new_standard(
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
        session_difficulty: Difficulty,
        declared_max_target: [u8; 32],
    ) -> Self {
        Self {
            channel_id,
            kind: ChannelKind::Standard,
            extranonce_prefix,
            extranonce_size: 0,
            session_difficulty,
            declared_max_target,
            standard_jobs: StandardJobMaps::new(),
            extended_jobs: HashMap::new(),
            latest_extended_prev_hash: None,
            latest_extended_n_bits: None,
            latest_extended_min_ntime: None,
            accepted_share_count: 0,
            accepted_share_difficulty_sum: 0.0,
            next_job_id: 1,
            submission_cache: SubmissionCache::Standard(HashSet::new()),
            is_jdc: false,
            first_share_logged: false,
            last_submission_difficulty: None,
            target_memo: None,
        }
    }

    /// Construct a fresh **Extended** channel.
    pub fn new_extended(
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
        extranonce_size: u8,
        session_difficulty: Difficulty,
        declared_max_target: [u8; 32],
    ) -> Self {
        Self {
            channel_id,
            kind: ChannelKind::Extended,
            extranonce_prefix,
            extranonce_size,
            session_difficulty,
            declared_max_target,
            standard_jobs: StandardJobMaps::new(),
            extended_jobs: HashMap::new(),
            latest_extended_prev_hash: None,
            latest_extended_n_bits: None,
            latest_extended_min_ntime: None,
            accepted_share_count: 0,
            accepted_share_difficulty_sum: 0.0,
            next_job_id: 1,
            submission_cache: SubmissionCache::Extended(HashSet::new()),
            is_jdc: false,
            first_share_logged: false,
            last_submission_difficulty: None,
            target_memo: None,
        }
    }

    /// Record an accepted share. Bumps the per-channel counters; the
    /// dedup-cache write happens via [`SubmissionCache::insert_*`] at
    /// the call site (the validator already produced the dedup key).
    pub fn record_accepted_share(&mut self, share_difficulty: Difficulty) {
        self.accepted_share_count = self.accepted_share_count.saturating_add(1);
        self.accepted_share_difficulty_sum += share_difficulty.as_f64();
    }

    /// Target for `job_difficulty`, memoized per channel. Returns the
    /// cached target when the difficulty matches the last computed one
    /// (the common case — per-job difficulty only moves on a vardiff
    /// ratchet), otherwise computes it via `difficulty_to_target` and
    /// caches the result. Keyed on the exact f64 bit pattern, so the
    /// returned target is identical to an uncached
    /// `difficulty_to_target(job_difficulty)`.
    pub fn target_for(&mut self, job_difficulty: Difficulty) -> Target {
        let key = job_difficulty.as_f64().to_bits();
        if let Some((cached_key, cached_target)) = self.target_memo {
            if cached_key == key {
                return cached_target;
            }
        }
        let target = difficulty_to_target(job_difficulty);
        self.target_memo = Some((key, target));
        target
    }

    /// Reset the submission-dedup cache. Called on `SetNewPrevHash`
    /// (block change). The retire-not-clear pattern only applies to the
    /// **job storage** (so in-flight shares can still resolve a
    /// jobId to `stale-share` instead of `invalid-job-id`); the
    /// dedup cache is rebuilt naturally as new shares arrive.
    pub fn clear_submission_cache(&mut self) {
        match &mut self.submission_cache {
            SubmissionCache::Standard(s) => s.clear(),
            SubmissionCache::Extended(s) => s.clear(),
        }
    }

    /// Total bytes the miner sees as the "coinbase extranonce slot"
    /// (`prefix + miner-rollable`). Always 12 by design; the constant is
    /// implicit in the [`crate::extranonce::ExtranonceAllocator`] default.
    pub fn full_extranonce_size(&self) -> usize {
        self.extranonce_prefix.len() + self.extranonce_size as usize
    }
}

// ── SubmissionCache ──────────────────────────────────────────────────

/// Per-channel duplicate-share guard. Standard and Extended share-submit
/// frames carry different field sets, so the dedup key is a different
/// tuple shape per kind. Wrapping in an enum keeps the
/// non-applicable variant zero-cost (the empty `HashSet<...>` for the
/// other kind never gets touched).
#[derive(Clone, Debug)]
pub enum SubmissionCache {
    Standard(HashSet<StandardDedupKey>),
    Extended(HashSet<ExtendedDedupKey>),
}

/// Dedup key for `SubmitSharesStandard`. Field order matches the wire frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StandardDedupKey {
    pub job_id: u32,
    pub nonce: u32,
    pub ntime: u32,
    pub version: u32,
}

/// Dedup key for `SubmitSharesExtended`. Adds the miner-supplied
/// extranonce bytes to the dedup key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExtendedDedupKey {
    pub job_id: u32,
    pub nonce: u32,
    pub ntime: u32,
    pub version: u32,
    pub extranonce: ExtranonceBytes,
}

impl SubmissionCache {
    /// Try to record a Standard-channel submission. Returns `true` if
    /// it was newly inserted (= not a duplicate), `false` if the key
    /// was already present. Panics in debug builds if called on an
    /// Extended-cache variant — the caller should be asserting the
    /// channel kind anyway.
    pub fn insert_standard(&mut self, key: StandardDedupKey) -> bool {
        match self {
            SubmissionCache::Standard(set) => set.insert(key),
            SubmissionCache::Extended(_) => {
                debug_assert!(false, "insert_standard on Extended cache");
                false
            }
        }
    }

    /// Try to record an Extended-channel submission. Returns `true` if
    /// it was newly inserted, `false` if duplicate. See
    /// [`Self::insert_standard`] for the kind-mismatch behaviour.
    pub fn insert_extended(&mut self, key: ExtendedDedupKey) -> bool {
        match self {
            SubmissionCache::Extended(set) => set.insert(key),
            SubmissionCache::Standard(_) => {
                debug_assert!(false, "insert_extended on Standard cache");
                false
            }
        }
    }

    pub fn len(&self) -> usize {
        match self {
            SubmissionCache::Standard(s) => s.len(),
            SubmissionCache::Extended(s) => s.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn max_target() -> [u8; 32] {
        [0xFF; 32]
    }

    // ── Construction ───────────────────────────────────────────────

    /// The per-channel target memo returns bit-identical results to an
    /// uncached `difficulty_to_target` and recomputes on a difficulty
    /// change — so it's a pure performance shim, no behaviour change.
    #[test]
    fn target_memo_matches_uncached_and_recomputes_on_change() {
        let mut ch = ChannelState::new_standard(1, vec![0; 4], Difficulty(1024.0), max_target());
        for d in [1.0, 1024.0, 65535.0, 0.5, 1e9, 1234.5678] {
            let direct = difficulty_to_target(Difficulty(d));
            assert_eq!(
                ch.target_for(Difficulty(d)),
                direct,
                "diff {d}: memo != uncached"
            );
            // Immediate repeat is served from the slot — still equal.
            assert_eq!(
                ch.target_for(Difficulty(d)),
                direct,
                "diff {d}: repeat mismatch"
            );
        }
        // Switching difficulty recomputes (no stale slot); switching back
        // still yields the correct target.
        let a = ch.target_for(Difficulty(1024.0));
        let b = ch.target_for(Difficulty(2048.0));
        assert_ne!(a, b, "distinct difficulties must map to distinct targets");
        assert_eq!(
            ch.target_for(Difficulty(1024.0)),
            difficulty_to_target(Difficulty(1024.0)),
            "re-selecting a prior difficulty must recompute correctly"
        );
    }

    /// Fresh Standard channel: zero extranonce_size, empty maps.
    #[test]
    fn standard_channel_starts_clean() {
        let ch = ChannelState::new_standard(1, vec![0; 4], Difficulty(1024.0), max_target());
        assert_eq!(ch.kind, ChannelKind::Standard);
        assert_eq!(ch.extranonce_size, 0);
        assert!(ch.standard_jobs.is_empty());
        assert!(ch.extended_jobs.is_empty());
        assert!(ch.submission_cache.is_empty());
        assert!(matches!(ch.submission_cache, SubmissionCache::Standard(_)));
        assert_eq!(ch.full_extranonce_size(), 4);
        assert!(!ch.is_jdc);
        assert!(!ch.first_share_logged);
    }

    /// Fresh Extended channel: extranonce_size > 0, Extended-cache.
    #[test]
    fn extended_channel_starts_clean() {
        let ch = ChannelState::new_extended(2, vec![0; 4], 8, Difficulty(1024.0), max_target());
        assert_eq!(ch.kind, ChannelKind::Extended);
        assert_eq!(ch.extranonce_size, 8);
        assert!(matches!(ch.submission_cache, SubmissionCache::Extended(_)));
        assert_eq!(ch.full_extranonce_size(), 12);
    }

    // ── declared_max_target round-trip ─────────────────────────────

    /// `declared_max_target` round-trips through construction.
    #[test]
    fn declared_max_target_is_stored_verbatim() {
        let mut tgt = [0u8; 32];
        tgt[0] = 0x01;
        tgt[31] = 0xFF;
        let ch = ChannelState::new_standard(1, vec![0; 4], Difficulty(1.0), tgt);
        assert_eq!(ch.declared_max_target, tgt);
    }

    // ── record_accepted_share ──────────────────────────────────────

    /// Counters increment together; difficulty sum accumulates as f64.
    #[test]
    fn record_accepted_share_bumps_counters() {
        let mut ch = ChannelState::new_standard(1, vec![0; 4], Difficulty(1.0), max_target());
        ch.record_accepted_share(Difficulty(1024.0));
        ch.record_accepted_share(Difficulty(2048.5));
        assert_eq!(ch.accepted_share_count, 2);
        assert!((ch.accepted_share_difficulty_sum - 3072.5).abs() < 1e-9);
    }

    // ── SubmissionCache ────────────────────────────────────────────

    /// Standard dedup: same key blocked, different key OK.
    #[test]
    fn standard_dedup_blocks_duplicate_keys() {
        let mut cache = SubmissionCache::Standard(HashSet::new());
        let key = StandardDedupKey {
            job_id: 1,
            nonce: 0xdeadbeef,
            ntime: 100,
            version: 0x2000_0000,
        };
        assert!(cache.insert_standard(key), "first insert is new");
        assert!(!cache.insert_standard(key), "second is duplicate");
        let other = StandardDedupKey {
            nonce: 0x1234,
            ..key
        };
        assert!(cache.insert_standard(other), "different nonce is new");
        assert_eq!(cache.len(), 2);
    }

    /// Extended dedup: extranonce bytes are part of the key.
    #[test]
    fn extended_dedup_includes_extranonce_in_key() {
        let mut cache = SubmissionCache::Extended(HashSet::new());
        let base = ExtendedDedupKey {
            job_id: 1,
            nonce: 1,
            ntime: 1,
            version: 1,
            extranonce: ExtranonceBytes::from_slice(&[0x01, 0x02]),
        };
        assert!(cache.insert_extended(base.clone()));
        assert!(!cache.insert_extended(base.clone()));
        let other_extranonce = ExtendedDedupKey {
            extranonce: ExtranonceBytes::from_slice(&[0x01, 0x03]),
            ..base
        };
        assert!(cache.insert_extended(other_extranonce));
        assert_eq!(cache.len(), 2);
    }

    /// `clear_submission_cache` empties the dedup set (block-change
    /// trigger).
    #[test]
    fn clear_submission_cache_empties_dedup() {
        let mut ch = ChannelState::new_standard(1, vec![0; 4], Difficulty(1.0), max_target());
        ch.submission_cache.insert_standard(StandardDedupKey {
            job_id: 1,
            nonce: 1,
            ntime: 1,
            version: 1,
        });
        assert_eq!(ch.submission_cache.len(), 1);
        ch.clear_submission_cache();
        assert!(ch.submission_cache.is_empty());
    }

    /// Dedup-cache kind matches the channel kind — clearing on a
    /// Standard channel doesn't accidentally turn it into an Extended
    /// cache.
    #[test]
    fn cache_kind_is_preserved_after_clear() {
        let mut ch = ChannelState::new_standard(1, vec![0; 4], Difficulty(1.0), max_target());
        ch.clear_submission_cache();
        assert!(matches!(ch.submission_cache, SubmissionCache::Standard(_)));

        let mut ch = ChannelState::new_extended(2, vec![0; 4], 8, Difficulty(1.0), max_target());
        ch.clear_submission_cache();
        assert!(matches!(ch.submission_cache, SubmissionCache::Extended(_)));
    }

    // ── is_jdc + first_share_logged toggles ────────────────────────

    /// The diagnostic flags are mutable (callers flip them on detect /
    /// first-share-log).
    #[test]
    fn diagnostic_flags_can_be_toggled() {
        let mut ch = ChannelState::new_extended(1, vec![0; 4], 8, Difficulty(1.0), max_target());
        ch.is_jdc = true;
        ch.first_share_logged = true;
        assert!(ch.is_jdc);
        assert!(ch.first_share_logged);
    }

    // ── full_extranonce_size invariant ─────────────────────────────

    /// `full_extranonce_size = prefix.len + extranonce_size`. Should
    /// stay ≤ 12 by SV2 spec (caller responsibility, not enforced
    /// here — Standard always 4+0, Extended typically 4+8).
    #[test]
    fn full_extranonce_size_is_sum_of_prefix_and_rollable() {
        let ch = ChannelState::new_standard(1, vec![0; 4], Difficulty(1.0), max_target());
        assert_eq!(ch.full_extranonce_size(), 4);
        let ch = ChannelState::new_extended(2, vec![0; 6], 6, Difficulty(1.0), max_target());
        assert_eq!(ch.full_extranonce_size(), 12);
    }
}
