// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-channel state for SV2 Standard + Extended mining channels.
//!
//! One `ChannelState` struct; the [`ChannelKind`] discriminant tells callers
//! which fields are meaningful:
//!
//! - **Standard**: `extranonce_size = 0` (the miner cannot roll).
//!   [`StandardJobMaps`] drives share validation; `extended_jobs` stays empty.
//! - **Extended**: `extranonce_size > 0` after the pool-assigned prefix.
//!   [`ExtendedJob`] entries in `extended_jobs` carry everything needed to
//!   rebuild the coinbase and walk the merkle path on submit, including the
//!   job's difficulty.
//!
//! `declared_max_target` is the channel's SV2 ceiling: vardiff clamps against
//! it before sending `SetTarget`.
//!
//! [`SubmissionCache`] is the per-channel dedup set, cleared on
//! `SetNewPrevHash`.

use std::collections::{HashMap, HashSet};

use bp_jobs_lifecycle::LifecycleConfig;
use bp_share::{Difficulty, Target, TargetMemo};

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
    /// by [`crate::extranonce::ConnectionExtranonce`]).
    pub extranonce_prefix: Vec<u8>,
    /// Miner-controlled bytes after the prefix. `0` for Standard;
    /// clamped to `12 - prefix.len` for Extended, because some BitAxe /
    /// NerdQAxe firmware ignores larger sizes and corrupts the coinbase varint.
    pub extranonce_size: u8,

    pub session_difficulty: Difficulty,

    /// SV2: the client's declared maximum target; vardiff clamps against it
    /// before sending `SetTarget`. Kept as raw 32-byte little-endian U256 so
    /// the clamp check loses no precision.
    pub declared_max_target: [u8; 32],

    /// The `nominal_hash_rate` this channel last declared, if any.
    ///
    /// The silence-easing path uses it to tell a NEW declaration (news about
    /// the channel now, e.g. a proxy whose workers just attached) from the
    /// same value re-sent on a timer, where observed silence still rules.
    pub last_declared_hash_rate: Option<f32>,

    /// Standard-channel job bookkeeping
    /// (`job_id_to_difficulty` + `job_id_to_merkle_root`). Empty for
    /// Extended channels.
    pub standard_jobs: StandardJobMaps,

    /// Extended-channel job storage with retire-not-clear lifecycle.
    /// Empty for Standard channels.
    pub extended_jobs: HashMap<u32, ExtendedJob>,

    /// Block context stored at `SetNewPrevHash` time for later
    /// `NewExtendedMiningJob` frames. `None` until the first
    /// `SetNewPrevHash`. Standard channels do not need it: `NewMiningJob`
    /// carries an absolute merkle root.
    pub latest_extended_prev_hash: Option<[u8; 32]>,
    pub latest_extended_n_bits: Option<u32>,
    pub latest_extended_min_ntime: Option<u32>,

    pub accepted_share_count: u64,
    /// Sum of accepted-share difficulties. f64 because low-diff ports can
    /// have sub-1 entries.
    pub accepted_share_difficulty_sum: f64,

    /// Channel-local, monotonic job-id counter, bumped on each
    /// `NewMiningJob` / `NewExtendedMiningJob`.
    pub next_job_id: u32,

    /// Per-channel submission dedup set. Cleared on block change.
    pub submission_cache: SubmissionCache,

    /// Content signature of the last job sent on this channel — version,
    /// prev_hash, n_bits and the merkle root (Standard) or coinbase
    /// prefix/suffix + merkle path (Extended). A same-block *refresh*
    /// whose signature matches is byte-identical work and is NOT re-issued
    /// under a fresh `job_id`: strict firmware (BraiinsOS) resets its
    /// hashing pipeline on every `NewMiningJob`, so re-announcing identical
    /// work freezes its effective hashrate / best-difficulty. A real block
    /// change (`SetNewPrevHash`) is always sent. `None` until the first job.
    pub last_sent_job_signature: Option<u64>,

    /// One-shot diagnostic flag: the first share per channel logs its actual
    /// extranonce length, to spot firmware that ignores the advertised
    /// `extranonce_size`.
    pub first_share_logged: bool,

    /// Target memo for the per-share accept check. Per-job difficulty
    /// changes only on a vardiff ratchet.
    target_memo: TargetMemo,
}

impl ChannelState {
    /// Construct a fresh **Standard** channel.
    pub fn new_standard(
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
        session_difficulty: Difficulty,
        declared_max_target: [u8; 32],
        job_lifecycle: LifecycleConfig,
    ) -> Self {
        Self {
            channel_id,
            kind: ChannelKind::Standard,
            extranonce_prefix,
            extranonce_size: 0,
            session_difficulty,
            declared_max_target,
            last_declared_hash_rate: None,
            standard_jobs: StandardJobMaps::new(job_lifecycle),
            extended_jobs: HashMap::new(),
            latest_extended_prev_hash: None,
            latest_extended_n_bits: None,
            latest_extended_min_ntime: None,
            accepted_share_count: 0,
            accepted_share_difficulty_sum: 0.0,
            next_job_id: 1,
            submission_cache: SubmissionCache::Standard(HashSet::new()),
            last_sent_job_signature: None,
            first_share_logged: false,
            target_memo: TargetMemo::default(),
        }
    }

    /// Construct a fresh **Extended** channel.
    pub fn new_extended(
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
        extranonce_size: u8,
        session_difficulty: Difficulty,
        declared_max_target: [u8; 32],
        job_lifecycle: LifecycleConfig,
    ) -> Self {
        Self {
            channel_id,
            kind: ChannelKind::Extended,
            extranonce_prefix,
            extranonce_size,
            session_difficulty,
            declared_max_target,
            last_declared_hash_rate: None,
            standard_jobs: StandardJobMaps::new(job_lifecycle),
            extended_jobs: HashMap::new(),
            latest_extended_prev_hash: None,
            latest_extended_n_bits: None,
            latest_extended_min_ntime: None,
            accepted_share_count: 0,
            accepted_share_difficulty_sum: 0.0,
            next_job_id: 1,
            submission_cache: SubmissionCache::Extended(HashSet::new()),
            last_sent_job_signature: None,
            first_share_logged: false,
            target_memo: TargetMemo::default(),
        }
    }

    /// Record an accepted share in the per-channel counters. The dedup-cache
    /// write happens at the call site via `SubmissionCache::insert_*`.
    pub fn record_accepted_share(&mut self, share_difficulty: Difficulty) {
        self.accepted_share_count = self.accepted_share_count.saturating_add(1);
        self.accepted_share_difficulty_sum += share_difficulty.as_f64();
    }

    /// Target for `job_difficulty`, memoized per channel (see
    /// [`TargetMemo`]).
    pub fn target_for(&mut self, job_difficulty: Difficulty) -> Target {
        self.target_memo.target_for(job_difficulty)
    }

    /// Reset the submission-dedup cache on `SetNewPrevHash`. Only the job
    /// storage is retired rather than cleared (so in-flight shares resolve
    /// to `stale-share`, not `invalid-job-id`).
    pub fn clear_submission_cache(&mut self) {
        match &mut self.submission_cache {
            SubmissionCache::Standard(s) => s.clear(),
            SubmissionCache::Extended(s) => s.clear(),
        }
    }

    /// Total bytes the miner sees as the "coinbase extranonce slot"
    /// (`prefix + miner-rollable`). Always 12 by design; the constant is
    /// set by [`bp_mining_job::EXTRANONCE_SLOT_LEN`].
    pub fn full_extranonce_size(&self) -> usize {
        self.extranonce_prefix.len() + self.extranonce_size as usize
    }
}

// ── SubmissionCache ──────────────────────────────────────────────────

/// Per-channel duplicate-share guard. Standard and Extended submit frames
/// carry different fields, so each kind has its own key type.
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

/// Upper bound on the per-channel submission dedup set. The set is only
/// cleared on a block change, and a channel may keep one `job_id` for the
/// whole block, so without a cap a fast miner grows it without end (and a
/// firmware nonce-range replay gets flagged as duplicates). When it fills,
/// the whole generation is dropped.
const MAX_SUBMISSION_CACHE: usize = 10_000;

impl SubmissionCache {
    /// Record a Standard-channel submission. `true` if new, `false` if a
    /// duplicate. Debug-asserts on an Extended cache.
    pub fn insert_standard(&mut self, key: StandardDedupKey) -> bool {
        match self {
            SubmissionCache::Standard(set) => {
                if set.len() >= MAX_SUBMISSION_CACHE {
                    set.clear();
                }
                set.insert(key)
            }
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
            SubmissionCache::Extended(set) => {
                if set.len() >= MAX_SUBMISSION_CACHE {
                    set.clear();
                }
                set.insert(key)
            }
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

    /// Fresh Standard channel: zero extranonce_size, empty maps.
    #[test]
    fn standard_channel_starts_clean() {
        let ch = ChannelState::new_standard(
            1,
            vec![0; 4],
            Difficulty(1024.0),
            max_target(),
            LifecycleConfig::DEFAULT,
        );
        assert_eq!(ch.kind, ChannelKind::Standard);
        assert_eq!(ch.extranonce_size, 0);
        assert!(ch.standard_jobs.is_empty());
        assert!(ch.extended_jobs.is_empty());
        assert!(ch.submission_cache.is_empty());
        assert!(matches!(ch.submission_cache, SubmissionCache::Standard(_)));
        assert_eq!(ch.full_extranonce_size(), 4);
        assert!(!ch.first_share_logged);
    }

    /// Fresh Extended channel: extranonce_size > 0, Extended-cache.
    #[test]
    fn extended_channel_starts_clean() {
        let ch = ChannelState::new_extended(
            2,
            vec![0; 4],
            8,
            Difficulty(1024.0),
            max_target(),
            LifecycleConfig::DEFAULT,
        );
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
        let ch = ChannelState::new_standard(
            1,
            vec![0; 4],
            Difficulty(1.0),
            tgt,
            LifecycleConfig::DEFAULT,
        );
        assert_eq!(ch.declared_max_target, tgt);
    }

    // ── record_accepted_share ──────────────────────────────────────

    /// Counters increment together; difficulty sum accumulates as f64.
    #[test]
    fn record_accepted_share_bumps_counters() {
        let mut ch = ChannelState::new_standard(
            1,
            vec![0; 4],
            Difficulty(1.0),
            max_target(),
            LifecycleConfig::DEFAULT,
        );
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
        let mut ch = ChannelState::new_standard(
            1,
            vec![0; 4],
            Difficulty(1.0),
            max_target(),
            LifecycleConfig::DEFAULT,
        );
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

    /// Clearing keeps the dedup-cache kind matching the channel kind.
    #[test]
    fn cache_kind_is_preserved_after_clear() {
        let mut ch = ChannelState::new_standard(
            1,
            vec![0; 4],
            Difficulty(1.0),
            max_target(),
            LifecycleConfig::DEFAULT,
        );
        ch.clear_submission_cache();
        assert!(matches!(ch.submission_cache, SubmissionCache::Standard(_)));

        let mut ch = ChannelState::new_extended(
            2,
            vec![0; 4],
            8,
            Difficulty(1.0),
            max_target(),
            LifecycleConfig::DEFAULT,
        );
        ch.clear_submission_cache();
        assert!(matches!(ch.submission_cache, SubmissionCache::Extended(_)));
    }

    // ── first_share_logged toggle ──────────────────────────────────

    /// The diagnostic flag is mutable (callers flip it on first-share-log).
    #[test]
    fn diagnostic_flags_can_be_toggled() {
        let mut ch = ChannelState::new_extended(
            1,
            vec![0; 4],
            8,
            Difficulty(1.0),
            max_target(),
            LifecycleConfig::DEFAULT,
        );
        ch.first_share_logged = true;
        assert!(ch.first_share_logged);
    }

    // ── full_extranonce_size invariant ─────────────────────────────

    /// `full_extranonce_size = prefix.len + extranonce_size`. The SV2 cap is
    /// **32** (`extranonce_prefix` is `B0_32`, enforced at channel open);
    /// 12 is only this pool's layout.
    #[test]
    fn full_extranonce_size_is_sum_of_prefix_and_rollable() {
        let ch = ChannelState::new_standard(
            1,
            vec![0; 4],
            Difficulty(1.0),
            max_target(),
            LifecycleConfig::DEFAULT,
        );
        assert_eq!(ch.full_extranonce_size(), 4);
        let ch = ChannelState::new_extended(
            2,
            vec![0; 6],
            6,
            Difficulty(1.0),
            max_target(),
            LifecycleConfig::DEFAULT,
        );
        assert_eq!(ch.full_extranonce_size(), 12);
    }
}
