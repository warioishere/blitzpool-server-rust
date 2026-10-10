// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-channel state for SV2 Standard + Extended mining channels. The
//! [`ChannelKind`] says which fields are meaningful: Standard channels use
//! [`StandardJobMaps`] and cannot roll extranonce; Extended channels keep
//! [`ExtendedJob`]s with everything needed to rebuild the coinbase on submit.

use std::collections::HashMap;

use bp_jobs_lifecycle::{LifecycleConfig, SeenShares};
use bp_share::{Difficulty, Target, TargetMemo};

use super::jobs::{ExtendedJob, StandardJobMaps};

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

    /// The `nominal_hash_rate` this channel last declared. `UpdateChannel` uses
    /// it to tell a NEW declaration (e.g. a proxy whose workers just attached)
    /// from the same value re-sent on a timer, where observed silence rules.
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

    /// Channel-local, monotonic job-id counter, bumped on each
    /// `NewMiningJob` / `NewExtendedMiningJob`.
    pub next_job_id: u32,

    /// Header hashes of accepted shares; see [`SeenShares`] for how long a
    /// tip's hashes outlive the tip.
    pub seen_shares: SeenShares,

    /// Content signature of the last job sent. A same-block refresh with the
    /// same signature is not re-issued: BraiinsOS resets its hashing pipeline
    /// on every `NewMiningJob`, so identical re-announced work stalls it. A
    /// block change (`SetNewPrevHash`) is always sent.
    pub last_sent_job_signature: Option<u64>,

    /// Target memo for the per-share accept check. Per-job difficulty
    /// changes only on a vardiff ratchet.
    target_memo: TargetMemo,
}

impl ChannelState {
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
            next_job_id: 1,
            seen_shares: SeenShares::new(),
            last_sent_job_signature: None,
            target_memo: TargetMemo::default(),
        }
    }

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
            next_job_id: 1,
            seen_shares: SeenShares::new(),
            last_sent_job_signature: None,
            target_memo: TargetMemo::default(),
        }
    }

    /// Target for `job_difficulty`, memoized per channel (see
    /// [`TargetMemo`]).
    pub fn target_for(&mut self, job_difficulty: Difficulty) -> Target {
        self.target_memo.target_for(job_difficulty)
    }

    /// Total bytes the miner sees as the "coinbase extranonce slot"
    /// (`prefix + miner-rollable`). Always 12 by design; the constant is
    /// set by [`bp_mining_job::EXTRANONCE_SLOT_LEN`].
    pub fn full_extranonce_size(&self) -> usize {
        self.extranonce_prefix.len() + self.extranonce_size as usize
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
        assert!(ch.seen_shares.is_empty());
        assert_eq!(ch.full_extranonce_size(), 4);
    }

    /// Fresh Extended channel: extranonce_size > 0.
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
        assert!(ch.seen_shares.is_empty());
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
