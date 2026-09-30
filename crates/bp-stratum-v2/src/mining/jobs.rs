// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-channel **Extended**-job storage + the **Standard**-side
//! `(job_id_to_difficulty, job_id_to_merkle_root)` maps for SV2 mining
//! channels.
//!
//! The retire-not-clear lifecycle math (`retired_at` stamping,
//! `JobClassification`, two-tier aging with a minimum-retained floor) is
//! shared with SV1 via the [`bp_jobs_lifecycle`] crate; only the
//! SV2-specific storage shape lives here.
//!
//! ## Two pieces
//!
//! - [`ExtendedJob`] + [`retire_extended_jobs`] +
//!   [`cleanup_retired_extended_jobs`] cover the **Extended** channel
//!   side. Each sent `NewExtendedMiningJob` is stored per-channel so the
//!   coinbase and merkle path can be reconstructed on share submission.
//!   On block change (`SetNewPrevHash`) entries are **retired** instead
//!   of cleared, and aging drops retired entries past
//!   [`bp_jobs_lifecycle::LifecycleConfig::retention_ms`].
//!
//! - [`StandardJobMaps`] covers the **Standard** channel side: per job id
//!   it records the difficulty at send time (SV2 Mining/SubmitShares.Error:
//!   a share is validated against the target its job was issued at) and
//!   the exact merkle root the miner received in `NewMiningJob`, stored on
//!   send rather than recomputed on validate.
//!
//! ## Lifecycle constants
//!
//! Each channel carries one [`LifecycleConfig`], stored in its
//! [`StandardJobMaps`] and read back via [`StandardJobMaps::lifecycle`]
//! for the Extended-side helpers. The binary builds it from
//! [`LifecycleConfig::DEFAULT`] (5 s grace, 3-entry floor) with
//! `retention_ms` taken from `[stratum] job_retention_ms`; the grace
//! window is not configurable.

use std::collections::HashMap;

use bp_jobs_lifecycle::{age_entries, classify, LifecycleConfig};
use bp_share::Difficulty;

pub use bp_jobs_lifecycle::JobClassification;

// ── ExtendedJob ──────────────────────────────────────────────────────

/// Stored payload of a single `NewExtendedMiningJob` (or a
/// `SetCustomMiningJob`-derived job) so share submission can
/// reconstruct the coinbase, walk the merkle path, and assemble the
/// 80-byte header.
///
/// `retired_at` timestamps when the job was superseded. `created_at` feeds
/// the [`bp_jobs_lifecycle::age_entries`] fallback that drops a non-retired
/// entry past `2 ×` retention (clock jump or missed retire signal).
#[derive(Clone, Debug, PartialEq)]
pub struct ExtendedJob {
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_suffix: Vec<u8>,
    /// Identity of the payout list this job's coinbase pays, copied off the
    /// `MiningJob`, so a block found on this job books exactly that
    /// distribution rather than a later build's snapshot. Zeroed for jobs
    /// the pool did not build the coinbase for (`SetCustomMiningJob`).
    pub payouts_fingerprint: [u8; 32],
    pub merkle_path: Vec<[u8; 32]>,
    pub version: u32,
    pub prev_hash: [u8; 32],
    /// Pinned at send-time (SV2 Mining/SubmitShares.Error). The block-found
    /// gate reads the network target from THIS, not the current template's —
    /// a block change between job-send and share-submit must not
    /// retroactively reclassify an in-flight share's block-candidacy.
    pub n_bits: u32,
    pub min_ntime: u32,
    /// The channel's extranonce prefix **as of send-time**. It is not part
    /// of `coinbase_prefix` because the miner appends it itself, so the
    /// validator splices it back in to reproduce the miner's coinbase.
    ///
    /// Pinned per job because SV2 Mining/SetExtranoncePrefix takes effect
    /// only from the **next** job: a miner still on the current job keeps
    /// the old prefix, and validating against the channel's new one would
    /// reject those shares.
    pub extranonce_prefix: Vec<u8>,
    /// Difficulty at send-time. SV2 Mining/SubmitShares.Error validates a
    /// share against the target its job was issued at, not the current
    /// session difficulty, so a vardiff change in between does not
    /// misjudge in-flight shares. Same field as
    /// [`StandardJobEntry::difficulty`] on the Standard side.
    pub difficulty: Difficulty,
    /// Block-reward portion the coinbase claims (the template's
    /// `coinbase_tx_value_remaining` at send-time), carried onto
    /// [`crate::mining::submit::ShareAccept`] for the block-found ledger.
    pub coinbase_tx_value_remaining: u64,
    /// TDP template id for pool-built jobs, so a found block can be sent
    /// as `SubmitSolution`. `None` for `SetCustomMiningJob` jobs, whose
    /// template the JDC built.
    pub template_id: Option<u64>,
    /// `true` when a block found on this custom job will be recorded by the
    /// JDP `PushSolution` path, so the mining side must NOT record it too
    /// (the `blocks_entity` insert has no `ON CONFLICT`).
    ///
    /// Two conditions, and both are about the DECLARATION — never about the
    /// job in hand. `PushSolution` claims a solution by matching it against a
    /// **declared job** and drops anything arriving on a connection that is
    /// not in Full-Template mode; and what it then writes is decided by that
    /// declaration's own `distribution_id`
    /// ([`crate::jdp::dynamic_outputs::CandidateBacking`]: `Bookable` and
    /// `UnbookableDistribution` both record, `BaseProtocol` records nothing).
    ///
    /// | job came from | JDP claims it | who records |
    /// |---|---|---|
    /// | declared, declaration referenced a distribution | yes | JDP |
    /// | declared, base protocol | no — `BaseProtocol`, nothing to record | mining side |
    /// | Coinbase-only + ext 0x0003 | **no** — SV2 JDP/Coinbase-only Mode, that mode never declares | mining side |
    /// | Coinbase-only, base protocol | no — never declares | mining side |
    ///
    /// ⚠️ This is not "is the job distribution-backed?": row three would then
    /// be recorded nowhere, with no ext 0x0003/Implementation Notes settle.
    /// Nor is it "did the ext 0x0003/Output Verification gate resolve a
    /// distribution?" (`distribution_ref` in
    /// `crate::mining::client::handle_set_custom_mining_job`):
    /// `resolve_distribution_reference` declines to inherit a declaration's
    /// reference on a Solo stream while the JDP side stamps one on every
    /// accepted 0x0003 declaration, so row one would be recorded twice.
    ///
    /// Always `false` for pool-built jobs, which carry a `template_id` and
    /// take the ordinary submit path instead.
    pub jdp_claims_the_block: bool,
    /// Wall-clock ms when stored.
    pub created_at: u64,
    /// Wall-clock ms when superseded by a newer block. `None` while
    /// active. Once set, the entry is aging-eligible after
    /// [`bp_jobs_lifecycle::LifecycleConfig::retention_ms`].
    pub retired_at: Option<u64>,
}

/// Classify a previously-stored extended job for share validation.
/// Thin wrapper around [`bp_jobs_lifecycle::classify`] with the
/// channel's lifecycle config.
pub fn classify_extended_job(
    ej: &ExtendedJob,
    now_ms: u64,
    config: &LifecycleConfig,
) -> JobClassification {
    classify(ej.retired_at, now_ms, config)
}

/// Stamp `retired_at = Some(now_ms)` on every entry that doesn't
/// already have one — the **block-change path** run on `SetNewPrevHash`.
/// Idempotent: a second call at a later timestamp keeps the original
/// `retired_at` so the grace window does not slide.
pub fn retire_extended_jobs<K>(map: &mut HashMap<K, ExtendedJob>, now_ms: u64) {
    for ej in map.values_mut() {
        if ej.retired_at.is_none() {
            ej.retired_at = Some(now_ms);
        }
    }
}

/// Per-channel extended-jobs aging — thin wrapper around
/// [`bp_jobs_lifecycle::age_entries`] threading the SV2-specific field
/// accessors (`created_at`, `retired_at`) with the channel's lifecycle
/// config.
pub fn cleanup_retired_extended_jobs<K>(
    map: &mut HashMap<K, ExtendedJob>,
    now_ms: u64,
    config: &LifecycleConfig,
) where
    K: Eq + std::hash::Hash + Clone,
{
    age_entries(map, now_ms, config, |ej| ej.created_at, |ej| ej.retired_at);
}

// ── StandardTemplateSnapshot ─────────────────────────────────────────

/// Per-job template context, stored on [`StandardJobEntry`] at send-time so
/// share validation uses the template the miner hashed against, not the
/// latest one (SV2 Mining/SubmitShares.Error). Re-exported as
/// [`crate::mining::client::StandardTemplateSnapshot`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StandardTemplateSnapshot {
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub n_bits: u32,
    /// Block-reward portion the coinbase claims (the template's
    /// `coinbase_tx_value_remaining` at send-time), carried onto
    /// [`crate::mining::submit::ShareAccept`] for the block-found ledger.
    pub coinbase_tx_value_remaining: u64,
}

// ── StandardJobMaps ──────────────────────────────────────────────────

/// One sent Standard `NewMiningJob`, with everything the share validator
/// and the retire-not-clear lifecycle need.
///
/// `difficulty` and `merkle_root` are stored at send time
/// (SV2 Mining/SubmitShares.Error: job-specific target; the merkle root is
/// the one the miner received, not a recomputation).
///
/// `template_snapshot` is the template the miner hashes against; retired
/// entries keep it, so in-flight shares validate against the template they
/// were issued under.
///
/// `created_at_ms` / `retired_at_ms` drive the same retire-not-clear
/// algorithm the Extended side uses, via [`bp_jobs_lifecycle`].
///
/// `coinbase_stratum` lets the validator build the witness-form coinbase
/// for `submit_solution` without holding the `MiningJob`. Standard channels
/// have no miner-rolled extranonce (the whole slot is pool-controlled), so
/// the full coinbase is known at send time. Empty for a
/// `SetCustomMiningJob`-declared job.
#[derive(Clone, Debug, PartialEq)]
pub struct StandardJobEntry {
    pub difficulty: Difficulty,
    pub merkle_root: [u8; 32],
    pub template_snapshot: StandardTemplateSnapshot,
    /// Full non-witness coinbase bytes (= `mining_job.coinbase_prefix() +
    /// channel.extranonce_prefix + [0u8; 8] + mining_job.coinbase_suffix()`
    /// for Standard pool-built jobs). Convertible to the
    /// witness-form by [`bp_mining_job::assemble_witness_coinbase`]
    /// at submit time. Empty for `SetCustomMiningJob`-derived jobs.
    pub coinbase_stratum: Vec<u8>,
    /// Identity of the payout list this job's coinbase pays, copied off the
    /// `MiningJob`, so a block found on this job books exactly that
    /// distribution rather than a later build's snapshot. Zeroed for jobs
    /// the pool did not build the coinbase for (`SetCustomMiningJob`).
    pub payouts_fingerprint: [u8; 32],
    /// TDP template id the job was built against. `None` for
    /// `SetCustomMiningJob`-derived jobs (no pool template).
    pub template_id: Option<u64>,
    pub created_at_ms: u64,
    pub retired_at_ms: Option<u64>,
}

/// Per-channel job-bookkeeping for **Standard** mining channels.
///
/// Entry table keyed by the channel-local SV2 `job_id`.
///
/// **Retire-not-clear (SV2 Mining/SubmitShares.Error)**: on block change the
/// IO layer calls [`Self::retire`], which stamps entries instead of deleting
/// them. In-flight shares for retired jobs then classify as
/// `StaleCreditable` (within grace, still credited) or `StaleRejected`
/// (wire code `stale-share`, not `invalid-job-id`). [`Self::cleanup_expired`]
/// ages old entries out; a missing entry resolves to `invalid-job-id` via
/// [`Self::classify`] returning `None`.
///
/// Extended channels reconstruct the merkle root from [`ExtendedJob`] and
/// store no entry here.
#[derive(Clone, Debug)]
pub struct StandardJobMaps {
    entries: HashMap<u32, StandardJobEntry>,
    config: LifecycleConfig,
}

impl StandardJobMaps {
    /// Empty maps aging under `config` — the channel's lifecycle config.
    pub fn new(config: LifecycleConfig) -> Self {
        Self {
            entries: HashMap::new(),
            config,
        }
    }

    /// The channel's lifecycle config. The Extended-side helpers
    /// ([`classify_extended_job`], [`cleanup_retired_extended_jobs`]) read
    /// it from here so a channel has exactly one.
    pub fn lifecycle(&self) -> &LifecycleConfig {
        &self.config
    }

    /// Record a `NewMiningJob` send. `template_snapshot` freezes the
    /// template context so validation rebuilds the exact header the miner
    /// hashed (SV2 Mining/SubmitShares.Error).
    ///
    /// Re-sending a `job_id` overwrites the entry and clears `retired_at_ms`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_send(
        &mut self,
        job_id: u32,
        difficulty: Difficulty,
        merkle_root: [u8; 32],
        template_snapshot: StandardTemplateSnapshot,
        coinbase_stratum: Vec<u8>,
        payouts_fingerprint: [u8; 32],
        template_id: Option<u64>,
        now_ms: u64,
    ) {
        self.entries.insert(
            job_id,
            StandardJobEntry {
                difficulty,
                merkle_root,
                template_snapshot,
                coinbase_stratum,
                payouts_fingerprint,
                template_id,
                created_at_ms: now_ms,
                retired_at_ms: None,
            },
        );
    }

    /// Test-only shorthand without coinbase, fingerprint or template id,
    /// for fixtures that don't exercise block submission.
    #[cfg(test)]
    pub(crate) fn record_send_for_test(
        &mut self,
        job_id: u32,
        difficulty: Difficulty,
        merkle_root: [u8; 32],
        template_snapshot: StandardTemplateSnapshot,
        now_ms: u64,
    ) {
        self.record_send(
            job_id,
            difficulty,
            merkle_root,
            template_snapshot,
            Vec::new(),
            [0u8; 32],
            None,
            now_ms,
        );
    }

    /// Stamp `retired_at_ms = Some(now_ms)` on every entry that doesn't
    /// already have one — the block-change path (SV2 `SetNewPrevHash`
    /// fan-out). Idempotent: a second call at a later timestamp keeps
    /// the original `retired_at_ms` so the grace window does not slide.
    pub fn retire(&mut self, now_ms: u64) {
        for e in self.entries.values_mut() {
            if e.retired_at_ms.is_none() {
                e.retired_at_ms = Some(now_ms);
            }
        }
    }

    /// Two-tier aging GC via [`bp_jobs_lifecycle::age_entries`]. Honours
    /// [`LifecycleConfig::min_retained`] floor. Idempotent.
    pub fn cleanup_expired(&mut self, now_ms: u64) {
        age_entries(
            &mut self.entries,
            now_ms,
            &self.config,
            |e| e.created_at_ms,
            |e| e.retired_at_ms,
        );
    }

    /// Classify a submitted-share's `job_id` against the current
    /// retire-state. Returns:
    ///
    /// - `None` — entry doesn't exist (never sent or aged out); caller
    ///   emits `invalid-job-id`.
    /// - `Some(Active)` / `Some(StaleCreditable)` — validate normally
    ///   (both credit the share).
    /// - `Some(StaleRejected)` — caller emits `stale-share`.
    pub fn classify(&self, job_id: u32, now_ms: u64) -> Option<JobClassification> {
        self.entries
            .get(&job_id)
            .map(|e| classify(e.retired_at_ms, now_ms, &self.config))
    }

    /// Lookup the difficulty + merkle root for a submitted share's
    /// `job_id`. Returns `None` if the job is genuinely unknown.
    /// **Returns `Some(...)` for retired entries** too — pair with
    /// [`Self::classify`] to decide accept-vs-reject.
    pub fn lookup(&self, job_id: u32) -> Option<(Difficulty, [u8; 32])> {
        self.entries
            .get(&job_id)
            .map(|e| (e.difficulty, e.merkle_root))
    }

    /// Full entry, including the per-job [`StandardTemplateSnapshot`].
    pub fn entry_of(&self, job_id: u32) -> Option<&StandardJobEntry> {
        self.entries.get(&job_id)
    }

    /// Per-job difficulty lookup.
    pub fn difficulty_of(&self, job_id: u32) -> Option<Difficulty> {
        self.entries.get(&job_id).map(|e| e.difficulty)
    }

    /// Drop the entry for a job id. Rarely needed — prefer
    /// [`Self::retire`] + [`Self::cleanup_expired`].
    pub fn forget(&mut self, job_id: u32) {
        self.entries.remove(&job_id);
    }

    /// Number of jobs currently tracked (retired + active).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default test snapshot — every record_send-using test threads it.
    fn snap() -> StandardTemplateSnapshot {
        StandardTemplateSnapshot {
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            n_bits: 0x1d00_ffff,
            coinbase_tx_value_remaining: 5_000_000_000,
        }
    }

    fn ej(now_ms: u64) -> ExtendedJob {
        ExtendedJob {
            payouts_fingerprint: [0u8; 32],
            coinbase_prefix: vec![0; 8],
            coinbase_suffix: vec![0; 8],
            merkle_path: vec![[0u8; 32]],
            extranonce_prefix: Vec::new(),
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            n_bits: 0x1d00_ffff,
            min_ntime: 0,
            difficulty: Difficulty(1.0),
            coinbase_tx_value_remaining: 5_000_000_000,
            template_id: None,
            jdp_claims_the_block: false,
            created_at: now_ms,
            retired_at: None,
        }
    }

    /// `classify_extended_job` defers to the shared lifecycle; these pin
    /// the wiring, the math is tested in `bp-jobs-lifecycle`.
    #[test]
    fn classify_active_for_fresh_job() {
        assert_eq!(
            classify_extended_job(&ej(1_000), 1_500, &LifecycleConfig::DEFAULT),
            JobClassification::Active
        );
    }

    #[test]
    fn classify_stale_creditable_at_grace_boundary() {
        let mut job = ej(1_000);
        job.retired_at = Some(10_000);
        assert_eq!(
            classify_extended_job(
                &job,
                10_000 + LifecycleConfig::DEFAULT.grace_ms,
                &LifecycleConfig::DEFAULT
            ),
            JobClassification::StaleCreditable
        );
    }

    #[test]
    fn classify_stale_rejected_one_ms_past_grace() {
        let mut job = ej(1_000);
        job.retired_at = Some(10_000);
        assert_eq!(
            classify_extended_job(
                &job,
                10_000 + LifecycleConfig::DEFAULT.grace_ms + 1,
                &LifecycleConfig::DEFAULT
            ),
            JobClassification::StaleRejected
        );
    }

    // ── retire_extended_jobs ────────────────────────────────────────

    #[test]
    fn retire_stamps_retired_at_on_active_entries() {
        let mut map: HashMap<u32, ExtendedJob> = HashMap::new();
        map.insert(1, ej(1_000));
        map.insert(2, ej(2_000));
        retire_extended_jobs(&mut map, 10_000);
        assert_eq!(map[&1].retired_at, Some(10_000));
        assert_eq!(map[&2].retired_at, Some(10_000));
    }

    #[test]
    fn retire_is_idempotent_keeps_original_timestamp() {
        let mut map: HashMap<u32, ExtendedJob> = HashMap::new();
        map.insert(1, ej(1_000));
        retire_extended_jobs(&mut map, 10_000);
        retire_extended_jobs(&mut map, 20_000);
        assert_eq!(map[&1].retired_at, Some(10_000));
    }

    // ── cleanup_retired_extended_jobs ───────────────────────────────

    /// Smoke-test the wiring against the shared aging algorithm.
    #[test]
    fn cleanup_uses_shared_aging_with_default_config() {
        let mut map: HashMap<u32, ExtendedJob> = HashMap::new();
        for i in 0..5u32 {
            let mut j = ej(1_000 + u64::from(i) * 1_000);
            j.retired_at = Some(6_000);
            map.insert(i, j);
        }
        cleanup_retired_extended_jobs(
            &mut map,
            6_000 + LifecycleConfig::DEFAULT.retention_ms * 5,
            &LifecycleConfig::DEFAULT,
        );
        assert_eq!(map.len(), LifecycleConfig::DEFAULT.min_retained);
    }

    /// End-to-end lifecycle: active → retired → still-creditable →
    /// stale-rejected → aged out.
    #[test]
    fn end_to_end_lifecycle() {
        let t0 = 1_000_000_000u64;
        let mut map: HashMap<u32, ExtendedJob> = HashMap::new();
        map.insert(1, ej(t0 - 10_000));
        assert_eq!(
            classify_extended_job(&map[&1], t0, &LifecycleConfig::DEFAULT),
            JobClassification::Active
        );
        retire_extended_jobs(&mut map, t0);
        assert_eq!(
            classify_extended_job(&map[&1], t0 + 1_000, &LifecycleConfig::DEFAULT),
            JobClassification::StaleCreditable
        );
        assert_eq!(
            classify_extended_job(&map[&1], t0 + 30_000, &LifecycleConfig::DEFAULT),
            JobClassification::StaleRejected
        );
        for i in 0..3u32 {
            map.insert(100 + i, ej(t0 + 100 + u64::from(i)));
        }
        cleanup_retired_extended_jobs(
            &mut map,
            t0 + LifecycleConfig::DEFAULT.retention_ms + 1,
            &LifecycleConfig::DEFAULT,
        );
        assert!(!map.contains_key(&1));
    }

    // ── StandardJobMaps ─────────────────────────────────────────────

    #[test]
    fn standard_job_maps_record_and_lookup_in_lockstep() {
        let mut maps = StandardJobMaps::new(LifecycleConfig::DEFAULT);
        let mr = [0x42u8; 32];
        maps.record_send_for_test(7, Difficulty(1024.0), mr, snap(), 1_000);
        let (d, r) = maps.lookup(7).expect("must find");
        assert_eq!(d, Difficulty(1024.0));
        assert_eq!(r, mr);
    }

    #[test]
    fn standard_job_maps_lookup_returns_none_for_unknown() {
        let maps = StandardJobMaps::new(LifecycleConfig::DEFAULT);
        assert_eq!(maps.lookup(42), None);
    }

    #[test]
    fn standard_job_maps_pin_per_job_difficulty() {
        let mut maps = StandardJobMaps::new(LifecycleConfig::DEFAULT);
        maps.record_send_for_test(1, Difficulty(100.0), [0u8; 32], snap(), 1_000);
        maps.record_send_for_test(2, Difficulty(200.0), [0u8; 32], snap(), 2_000);
        assert_eq!(maps.difficulty_of(1), Some(Difficulty(100.0)));
        assert_eq!(maps.difficulty_of(2), Some(Difficulty(200.0)));
        assert_eq!(maps.difficulty_of(99), None);
    }

    /// SV2 Mining/SubmitShares.Error: a retired entry keeps its send-time
    /// snapshot, so in-flight shares for the old job hash against the OLD
    /// prev_hash, n_bits and version.
    #[test]
    fn standard_per_job_snapshot_pins_template_context_at_send_time() {
        let mut maps = StandardJobMaps::new(LifecycleConfig::DEFAULT);
        let snap_old = StandardTemplateSnapshot {
            version: 0x2000_0000,
            prev_hash: [0xAA; 32],
            n_bits: 0x1d00_ffff,
            coinbase_tx_value_remaining: 5_000_000_000,
        };
        let snap_new = StandardTemplateSnapshot {
            version: 0x2000_0001,
            prev_hash: [0xBB; 32],
            n_bits: 0x1d01_ffff,
            coinbase_tx_value_remaining: 4_900_000_000,
        };
        maps.record_send_for_test(1, Difficulty(1.0), [0x11; 32], snap_old, 1_000);
        maps.record_send_for_test(2, Difficulty(2.0), [0x22; 32], snap_new, 2_000);
        let e1 = maps.entry_of(1).expect("entry 1");
        let e2 = maps.entry_of(2).expect("entry 2");
        assert_eq!(e1.template_snapshot.prev_hash, [0xAA; 32]);
        assert_eq!(e2.template_snapshot.prev_hash, [0xBB; 32]);
        // Retire job 1 (block change at t=3_000). Its snapshot must
        // survive — in-flight shares need the OLD prev_hash.
        maps.retire(3_000);
        let e1_after = maps.entry_of(1).expect("retired entry still present");
        assert_eq!(
            e1_after.template_snapshot.prev_hash, [0xAA; 32],
            "retired entry must keep its send-time snapshot"
        );
        assert_eq!(
            e1_after.template_snapshot.n_bits, 0x1d00_ffff,
            "the block-found gate reads the send-time n_bits, not the new tip's"
        );
        assert_eq!(e1_after.retired_at_ms, Some(3_000));
    }

    #[test]
    fn standard_job_maps_forget_drops_entry() {
        let mut maps = StandardJobMaps::new(LifecycleConfig::DEFAULT);
        maps.record_send_for_test(1, Difficulty(100.0), [0u8; 32], snap(), 0);
        maps.forget(1);
        assert!(maps.is_empty());
        assert_eq!(maps.lookup(1), None);
    }

    #[test]
    fn standard_record_send_stamps_created_at_and_clears_retired_at() {
        let mut maps = StandardJobMaps::new(LifecycleConfig::DEFAULT);
        maps.record_send_for_test(1, Difficulty(1.0), [0u8; 32], snap(), 1_000);
        maps.retire(2_000);
        // Re-send the same id to pin the overwrite semantics.
        maps.record_send_for_test(1, Difficulty(2.0), [0x11; 32], snap(), 3_000);
        assert_eq!(
            maps.classify(1, 3_000),
            Some(JobClassification::Active),
            "re-sent entry must classify as Active (retired_at cleared)"
        );
    }

    // ── retire-not-clear classification ─────────────────────────────

    #[test]
    fn standard_classify_unknown_job_returns_none() {
        let maps = StandardJobMaps::new(LifecycleConfig::DEFAULT);
        assert_eq!(maps.classify(42, 1_000), None);
    }

    #[test]
    fn standard_classify_active_for_fresh_job() {
        let mut maps = StandardJobMaps::new(LifecycleConfig::DEFAULT);
        maps.record_send_for_test(1, Difficulty(1.0), [0u8; 32], snap(), 1_000);
        assert_eq!(maps.classify(1, 1_500), Some(JobClassification::Active));
    }

    #[test]
    fn standard_classify_stale_creditable_at_grace_boundary() {
        let mut maps = StandardJobMaps::new(LifecycleConfig::DEFAULT);
        maps.record_send_for_test(1, Difficulty(1.0), [0u8; 32], snap(), 1_000);
        maps.retire(10_000);
        assert_eq!(
            maps.classify(1, 10_000 + LifecycleConfig::DEFAULT.grace_ms),
            Some(JobClassification::StaleCreditable)
        );
    }

    #[test]
    fn standard_classify_stale_rejected_one_ms_past_grace() {
        let mut maps = StandardJobMaps::new(LifecycleConfig::DEFAULT);
        maps.record_send_for_test(1, Difficulty(1.0), [0u8; 32], snap(), 1_000);
        maps.retire(10_000);
        assert_eq!(
            maps.classify(1, 10_000 + LifecycleConfig::DEFAULT.grace_ms + 1),
            Some(JobClassification::StaleRejected)
        );
    }

    #[test]
    fn standard_retire_is_idempotent_keeps_original_timestamp() {
        let mut maps = StandardJobMaps::new(LifecycleConfig::DEFAULT);
        maps.record_send_for_test(1, Difficulty(1.0), [0u8; 32], snap(), 1_000);
        maps.retire(10_000);
        maps.retire(20_000);
        // Grace window still applies relative to the original retire.
        assert_eq!(
            maps.classify(1, 10_000 + LifecycleConfig::DEFAULT.grace_ms),
            Some(JobClassification::StaleCreditable)
        );
        assert_eq!(
            maps.classify(1, 10_000 + LifecycleConfig::DEFAULT.grace_ms + 1),
            Some(JobClassification::StaleRejected)
        );
    }

    #[test]
    fn standard_cleanup_expired_respects_min_retained_floor() {
        let mut maps = StandardJobMaps::new(LifecycleConfig::DEFAULT);
        for i in 0..5u32 {
            maps.record_send_for_test(
                i,
                Difficulty(1.0),
                [0u8; 32],
                snap(),
                1_000 + u64::from(i) * 1_000,
            );
        }
        maps.retire(6_000);
        maps.cleanup_expired(6_000 + LifecycleConfig::DEFAULT.retention_ms * 5);
        assert_eq!(maps.len(), LifecycleConfig::DEFAULT.min_retained);
    }

    /// End-to-end lifecycle on the Standard side: active → retired →
    /// still-creditable → stale-rejected → aged out (becomes `None`).
    #[test]
    fn standard_end_to_end_lifecycle() {
        let t0 = 1_000_000_000u64;
        let mut maps = StandardJobMaps::new(LifecycleConfig::DEFAULT);
        maps.record_send_for_test(1, Difficulty(1.0), [0u8; 32], snap(), t0 - 10_000);
        assert_eq!(maps.classify(1, t0), Some(JobClassification::Active));
        maps.retire(t0);
        assert_eq!(
            maps.classify(1, t0 + 1_000),
            Some(JobClassification::StaleCreditable)
        );
        assert_eq!(
            maps.classify(1, t0 + 30_000),
            Some(JobClassification::StaleRejected)
        );
        // Add 3 more fresh entries so the floor doesn't protect job 1.
        for i in 0..3u32 {
            maps.record_send_for_test(
                100 + i,
                Difficulty(1.0),
                [0u8; 32],
                snap(),
                t0 + 100 + u64::from(i),
            );
        }
        maps.cleanup_expired(t0 + LifecycleConfig::DEFAULT.retention_ms + 1);
        assert_eq!(
            maps.classify(1, t0 + LifecycleConfig::DEFAULT.retention_ms + 1),
            None,
            "fully retired + past retention → entry GC'd, classify returns None"
        );
    }

    /// A tighter custom retention window ages entries out earlier.
    #[test]
    fn standard_with_config_honours_custom_retention() {
        let mut maps = StandardJobMaps::new(LifecycleConfig {
            grace_ms: 100,
            retention_ms: 500,
            min_retained: 1,
        });
        maps.record_send_for_test(1, Difficulty(1.0), [0u8; 32], snap(), 0);
        maps.record_send_for_test(2, Difficulty(1.0), [0u8; 32], snap(), 1);
        maps.retire(0);
        maps.cleanup_expired(600);
        // Floor=1 keeps the newer entry; older one GC'd.
        assert!(maps.classify(2, 600).is_some());
        assert!(maps.classify(1, 600).is_none());
    }
}
