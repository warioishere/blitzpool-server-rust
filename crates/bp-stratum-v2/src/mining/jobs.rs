// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-channel storage of sent SV2 jobs: [`ExtendedJob`] for Extended
//! channels, [`StandardJobMaps`] for Standard ones. Jobs are retired on
//! block change instead of cleared, so in-flight shares still validate; the
//! lifecycle math is shared with SV1 in [`bp_jobs_lifecycle`].

use std::collections::HashMap;

use bp_jobs_lifecycle::{age_entries, classify, LifecycleConfig};
use bp_share::Difficulty;

pub use bp_jobs_lifecycle::JobClassification;

// ── ExtendedJob ──────────────────────────────────────────────────────

/// One sent `NewExtendedMiningJob` (or `SetCustomMiningJob`-derived job),
/// kept so a share's coinbase, merkle root and header can be rebuilt.
#[derive(Clone, Debug, PartialEq)]
pub struct ExtendedJob {
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_suffix: Vec<u8>,
    /// Payout list this job's coinbase pays, so a block found on it books
    /// exactly that distribution rather than a later build's snapshot.
    /// Zeroed for `SetCustomMiningJob` jobs.
    pub payouts_fingerprint: [u8; 32],
    pub merkle_path: Vec<[u8; 32]>,
    pub version: u32,
    pub prev_hash: [u8; 32],
    /// Pinned at send-time (SV2 Mining/SubmitShares.Error): a block change
    /// between send and submit must not reclassify a share's block-candidacy.
    pub n_bits: u32,
    pub min_ntime: u32,
    /// The channel's prefix as of send-time, which the miner appends itself.
    /// Pinned per job because SV2 Mining/SetExtranoncePrefix takes effect only
    /// from the next job; the channel's new prefix would reject in-flight shares.
    pub extranonce_prefix: Vec<u8>,
    /// Difficulty at send-time: SV2 Mining/SubmitShares.Error validates a
    /// share against the target its job was issued at, not the current one.
    pub difficulty: Difficulty,
    pub coinbase_tx_value_remaining: u64,
    /// `None` for `SetCustomMiningJob` jobs, whose template the JDC built.
    pub template_id: Option<u64>,
    /// The JDP `PushSolution` path records this block, so the mining side must
    /// not (`blocks_entity` has no `ON CONFLICT`). Decided by the declaration,
    /// not by this job's distribution: true only if it referenced one.
    /// Coinbase-only jobs never declare, even with ext 0x0003; pool-built: false.
    pub jdp_claims_the_block: bool,
    pub created_at: u64,
    pub retired_at: Option<u64>,
}

pub fn classify_extended_job(
    ej: &ExtendedJob,
    now_ms: u64,
    config: &LifecycleConfig,
) -> JobClassification {
    classify(ej.retired_at, now_ms, config)
}

/// Block-change path. Keeps an existing `retired_at` so the grace window
/// does not slide on a second call.
pub fn retire_extended_jobs<K>(map: &mut HashMap<K, ExtendedJob>, now_ms: u64) {
    for ej in map.values_mut() {
        if ej.retired_at.is_none() {
            ej.retired_at = Some(now_ms);
        }
    }
}

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

/// Template context pinned per job at send-time, so a share validates against
/// the template the miner hashed, not the latest one (SV2
/// Mining/SubmitShares.Error).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StandardTemplateSnapshot {
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub n_bits: u32,
    pub coinbase_tx_value_remaining: u64,
}

// ── StandardJobMaps ──────────────────────────────────────────────────

/// One sent Standard `NewMiningJob`. Difficulty, merkle root and template
/// are pinned at send-time; the merkle root is the one the miner received,
/// not a recomputation.
#[derive(Clone, Debug, PartialEq)]
pub struct StandardJobEntry {
    pub difficulty: Difficulty,
    pub merkle_root: [u8; 32],
    pub template_snapshot: StandardTemplateSnapshot,
    /// Full non-witness coinbase, known at send-time because a Standard
    /// channel has no miner-rolled extranonce; lets the validator build the
    /// block's coinbase without the `MiningJob`. Empty for `SetCustomMiningJob`.
    pub coinbase_stratum: Vec<u8>,
    /// See `ExtendedJob::payouts_fingerprint`.
    pub payouts_fingerprint: [u8; 32],
    /// `None` for `SetCustomMiningJob`-derived jobs (no pool template).
    pub template_id: Option<u64>,
    pub created_at_ms: u64,
    pub retired_at_ms: Option<u64>,
}

/// Standard-channel jobs keyed by `job_id`. On block change [`Self::retire`]
/// stamps entries instead of deleting them, so an in-flight share is credited
/// within grace and rejected as `stale-share` (not `invalid-job-id`) after.
/// Also holds the channel's one [`LifecycleConfig`] for the Extended helpers.
#[derive(Clone, Debug)]
pub struct StandardJobMaps {
    entries: HashMap<u32, StandardJobEntry>,
    config: LifecycleConfig,
}

impl StandardJobMaps {
    pub fn new(config: LifecycleConfig) -> Self {
        Self {
            entries: HashMap::new(),
            config,
        }
    }

    pub fn lifecycle(&self) -> &LifecycleConfig {
        &self.config
    }

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

    /// Keeps an existing `retired_at_ms` so the grace window does not slide.
    pub fn retire(&mut self, now_ms: u64) {
        for e in self.entries.values_mut() {
            if e.retired_at_ms.is_none() {
                e.retired_at_ms = Some(now_ms);
            }
        }
    }

    pub fn cleanup_expired(&mut self, now_ms: u64) {
        age_entries(
            &mut self.entries,
            now_ms,
            &self.config,
            |e| e.created_at_ms,
            |e| e.retired_at_ms,
        );
    }

    /// `None` means never sent or aged out, i.e. `invalid-job-id`.
    pub fn classify(&self, job_id: u32, now_ms: u64) -> Option<JobClassification> {
        self.entries
            .get(&job_id)
            .map(|e| classify(e.retired_at_ms, now_ms, &self.config))
    }

    /// Also returns retired entries; pair with [`Self::classify`].
    pub fn lookup(&self, job_id: u32) -> Option<(Difficulty, [u8; 32])> {
        self.entries
            .get(&job_id)
            .map(|e| (e.difficulty, e.merkle_root))
    }

    pub fn entry_of(&self, job_id: u32) -> Option<&StandardJobEntry> {
        self.entries.get(&job_id)
    }

    pub fn difficulty_of(&self, job_id: u32) -> Option<Difficulty> {
        self.entries.get(&job_id).map(|e| e.difficulty)
    }

    pub fn forget(&mut self, job_id: u32) {
        self.entries.remove(&job_id);
    }

    /// Retired and active entries alike.
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

    /// A retired entry keeps its send-time template snapshot.
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
