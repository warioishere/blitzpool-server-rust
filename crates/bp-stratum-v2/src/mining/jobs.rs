// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-channel **Extended**-job storage + the **Standard**-side
//! `(job_id_to_difficulty, job_id_to_merkle_root)` maps for SV2 mining
//! channels.
//!
//! The retire-not-clear lifecycle math (sv2-ui#143 — `retired_at`
//! stamping, `JobClassification`, two-tier aging with `MIN_RETAINED`
//! floor) is shared with `bp-stratum-v1::jobs` via the
//! [`bp_jobs_lifecycle`] crate; only the SV2-specific storage shape
//! lives here.
//!
//! ## Two pieces
//!
//! - [`ExtendedJob`] + [`retire_extended_jobs`] +
//!   [`cleanup_retired_extended_jobs`] cover the **Extended** channel
//!   side. Each `NewExtendedMiningJob` we send out gets stored
//!   per-channel so we can reconstruct the coinbase + merkle path on
//!   share submission. On block change (`SetNewPrevHash`) we **retire**
//!   the existing entries instead of clearing them, then aging GCs
//!   retired entries past
//!   [`bp_jobs_lifecycle::LifecycleConfig::retention_ms`].
//!
//! - [`StandardJobMaps`] covers the **Standard** channel side: per-jobId
//!   we record the session difficulty at send time
//!   (`job_id_to_difficulty`, SV2 spec §5.3.14 — share validated
//!   against the target the job was issued at, not the current session
//!   target) AND the exact 32-byte merkle root the miner received in
//!   `NewMiningJob` (`job_id_to_merkle_root` — store-on-send, NOT
//!   recompute-on-validate; the previous design mutated the MiningJob's
//!   coinbase script buffer in place via
//!   `applyExtranonceAndGetCoinbaseHash` and broke for BraiinsOS
//!   Standard channels under message-ordering edge cases).
//!
//! ## Lifecycle constants
//!
//! [`bp_jobs_lifecycle::LifecycleConfig::DEFAULT`] holds the standard
//! defaults (5 s grace, 10 min retention, 3-entry floor). Production
//! wiring reads `SV2_STALE_GRACE_MS` and
//! `SV2_EXTENDED_JOB_RETENTION_MS` env-vars and overrides; both helpers
//! below pin against `LifecycleConfig::DEFAULT`.

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
/// `retired_at` timestamps when the job was superseded (sv2-ui#143).
/// `created_at` is used by the [`bp_jobs_lifecycle::age_entries`]
/// defense-in-depth fallback when a non-retired entry somehow piles up
/// past `2 ×` retention (clock jump or missed retire signal).
#[derive(Clone, Debug, PartialEq)]
pub struct ExtendedJob {
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_suffix: Vec<u8>,
    pub merkle_path: Vec<[u8; 32]>,
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub n_bits: u32,
    pub min_ntime: u32,
    /// The channel's extranonce prefix **as of send-time**. Extended jobs
    /// do NOT bake the prefix into `coinbase_prefix` — the miner appends it
    /// itself at share-build time — so the validator has to splice it back
    /// in to reproduce the miner's coinbase byte-for-byte.
    ///
    /// It is pinned per-job rather than read live off the channel because
    /// SV2 §5.3.10 lets `SetExtranoncePrefix` take effect only from the
    /// **next** job onward: a miner still working the current job keeps
    /// using the old prefix. Validating those in-flight shares against the
    /// channel's new prefix would diverge the reconstructed coinbase and
    /// reject every one of them as diff-too-low. Same send-time-pinning
    /// rationale as [`Self::difficulty`] and [`Self::network_difficulty`]
    /// (§5.3.14), applied to the one input those two don't cover.
    pub extranonce_prefix: Vec<u8>,
    /// Per-job session difficulty stored at send-time. SV2 spec §5.3.14
    /// requires share validation against the target the job was issued
    /// at, NOT the current `session_difficulty` — without this a vardiff
    /// ratchet between job-send and share-submit would falsely accept /
    /// reject in-flight shares. The Standard side stores the same field
    /// on [`StandardJobEntry::difficulty`]; mirroring it here lets the
    /// Extended submit-handler read directly from the job record
    /// instead of cross-referencing the Standard-side map.
    pub difficulty: Difficulty,
    /// Per-job **network** difficulty pinned at send-time (SV2 §5.3.14).
    /// The block-found gate compares the share's solved difficulty against
    /// THIS, not the current template's — a block-change between job-send
    /// and share-submit must not retroactively reclassify an in-flight
    /// share's block-candidacy. Mirrors the Standard side, which pins it on
    /// [`StandardTemplateSnapshot::network_difficulty`].
    pub network_difficulty: Difficulty,
    /// Block-reward portion the coinbase claims (= the template's
    /// `coinbase_tx_value_remaining` at send-time). Threaded onto
    /// [`crate::mining::submit::ShareAccept`] so the block-found fan-out can
    /// write the per-mode engine ledger with the correct reward.
    pub coinbase_tx_value_remaining: u64,
    /// `None` for jobs declared via `SetCustomMiningJob` (the JDC built
    /// the template; pool has no template-side context). For pool-built
    /// jobs the caller stores the template id (or another opaque
    /// reference) so the block-found path can produce a `SubmitSolution`.
    pub template_id: Option<u64>,
    /// Wall-clock ms when stored.
    pub created_at: u64,
    /// Wall-clock ms when superseded by a newer block. `None` while
    /// active. Once set, the entry is aging-eligible after
    /// [`bp_jobs_lifecycle::LifecycleConfig::retention_ms`].
    pub retired_at: Option<u64>,
}

/// Classify a previously-stored extended job for share validation.
/// Thin wrapper around [`bp_jobs_lifecycle::classify`] that pins the
/// SV2 default config — the SV2 callsite always wants
/// [`LifecycleConfig::DEFAULT`] (env-overrides come from the consumer
/// crate when wiring lands).
pub fn classify_extended_job(ej: &ExtendedJob, now_ms: u64) -> JobClassification {
    classify(ej.retired_at, now_ms, &LifecycleConfig::DEFAULT)
}

/// Stamp `retired_at = Some(now_ms)` on every entry that doesn't
/// already have one — the **block-change path** run on `SetNewPrevHash`.
/// Idempotent: a second call at a later timestamp keeps the original
/// `retired_at` so the grace-window math doesn't slide backwards.
///
/// Lives here (not in [`bp_jobs_lifecycle`]) because the field-name
/// choice is consumer-specific and a generic two-closure wrapper is
/// more boilerplate than the 3-line loop saves.
pub fn retire_extended_jobs<K>(map: &mut HashMap<K, ExtendedJob>, now_ms: u64) {
    for ej in map.values_mut() {
        if ej.retired_at.is_none() {
            ej.retired_at = Some(now_ms);
        }
    }
}

/// Per-channel extended-jobs aging — thin wrapper around
/// [`bp_jobs_lifecycle::age_entries`] threading the SV2-specific field
/// accessors (`created_at`, `retired_at`) and pinning
/// [`LifecycleConfig::DEFAULT`].
pub fn cleanup_retired_extended_jobs<K>(map: &mut HashMap<K, ExtendedJob>, now_ms: u64)
where
    K: Eq + std::hash::Hash + Clone,
{
    age_entries(
        map,
        now_ms,
        &LifecycleConfig::DEFAULT,
        |ej| ej.created_at,
        |ej| ej.retired_at,
    );
}

// ── StandardTemplateSnapshot ─────────────────────────────────────────

/// Per-job template context — stored on [`StandardJobEntry`] at
/// send-time so share validation uses the *same* template the miner
/// hashed against, not the most-recent one (SV2 §5.3.14 strict).
///
/// Lives in `mining/jobs.rs` (not `mining/client.rs`) because the
/// storage owns the lifecycle. The handler re-exports it via
/// [`crate::mining::client::StandardTemplateSnapshot`] for callers.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StandardTemplateSnapshot {
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub n_bits: u32,
    pub network_difficulty: Difficulty,
    /// Block-reward portion the coinbase claims (= the template's
    /// `coinbase_tx_value_remaining` at send-time). Threaded onto
    /// [`crate::mining::submit::ShareAccept`] so the block-found fan-out can
    /// write the per-mode engine ledger with the correct reward.
    pub coinbase_tx_value_remaining: u64,
}

// ── StandardJobMaps ──────────────────────────────────────────────────

/// One Standard `NewMiningJob` we've sent, with everything the share
/// validator + retire-not-clear lifecycle need.
///
/// `difficulty` + `merkle_root` are stored at send time (SV2 §5.3.14
/// — job-specific target; store-on-send merkle root avoids the
/// `applyExtranonceAndGetCoinbaseHash` mutation bug that caused ~19%
/// reject on BraiinsOS).
///
/// `template_snapshot` is the **template the miner is hashing
/// against**. On block change retired entries keep their snapshot —
/// in-flight shares for the retired job validate against the snapshot
/// they were issued under, not the current template. This is the
/// strict SV2 §5.3.14 per-job-template-pinning fix.
///
/// `created_at_ms` / `retired_at_ms` drive the same retire-not-clear
/// algorithm the Extended side uses, via [`bp_jobs_lifecycle`].
///
/// `coinbase_stratum` is stored at send-time so the
/// submit-validator can convert it to the witness-form coinbase for
/// `submit_solution` without holding the `MiningJob`. Standard
/// channels have **no miner-rolling extranonce** (the entire 12-byte
/// slot is pool-controlled: 4-byte `channel.extranonce_prefix` +
/// 8 zero bytes), so the full non-witness coinbase is deterministic
/// at job-send time and can be pre-assembled here. Empty when the
/// job was declared via `SetCustomMiningJob` (the JDC built the
/// coinbase; pool has no template-side bytes).
///
/// **No `Copy`** — the `Vec<u8>` field forces heap storage; the
/// `Clone` derive is still cheap (single allocator move per clone)
/// and consumers historically only `cloned()` for ownership.
#[derive(Clone, Debug, PartialEq)]
pub struct StandardJobEntry {
    pub difficulty: Difficulty,
    pub merkle_root: [u8; 32],
    pub template_snapshot: StandardTemplateSnapshot,
    /// Full non-witness coinbase bytes (= `mining_job.coinbase_prefix() +
    /// channel.extranonce_prefix + [0u8; 8] + mining_job.coinbase_suffix()`
    /// for Standard pool-built jobs). Convertible to the
    /// witness-form by [`bp_stratum_v2::mining::submit::assemble_witness_coinbase`]
    /// at submit time. Empty for `SetCustomMiningJob`-derived jobs.
    pub coinbase_stratum: Vec<u8>,
    /// TDP template id the job was built against. `None` for
    /// `SetCustomMiningJob`-derived jobs (no pool template).
    pub template_id: Option<u64>,
    pub created_at_ms: u64,
    pub retired_at_ms: Option<u64>,
}

/// Per-channel job-bookkeeping for **Standard** mining channels.
///
/// Single entry table keyed by SV2 `job_id` (channel-local `u32`).
/// Each entry carries the send-time difficulty + 32-byte merkle root
/// the miner received in `NewMiningJob`, plus lifecycle timestamps for
/// the retire-not-clear algorithm shared with the Extended side via
/// [`bp_jobs_lifecycle`].
///
/// **Retire-not-clear (SV2 §5.3.14)**: on block change the IO layer
/// calls [`Self::retire`] (stamps `retired_at_ms` on every entry,
/// idempotent) — it does **not** delete entries. In-flight shares for
/// the retired jobs then classify as `StaleCreditable` (within grace —
/// still credited) or `StaleRejected` (past grace — emits wire-code
/// `stale-share`, NOT the spec-incorrect `invalid-job-id`). Older
/// retired entries get GC'd by [`Self::cleanup_expired`] using the
/// shared two-tier aging algorithm.
///
/// Genuinely missing entries (past retention GC, or never sent) still
/// resolve to `invalid-job-id` via [`Self::classify`] returning `None`.
///
/// Extended channels reconstruct the merkle root on submit from
/// [`ExtendedJob`] + miner-supplied extranonce — they don't store a
/// merkle root here. Extended *difficulty* lookup for the per-job
/// target rule reads [`Self::difficulty_of`] (until per-job difficulty
/// migrates onto `ExtendedJob` itself).
#[derive(Clone, Debug)]
pub struct StandardJobMaps {
    entries: HashMap<u32, StandardJobEntry>,
    config: LifecycleConfig,
}

impl Default for StandardJobMaps {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            config: LifecycleConfig::DEFAULT,
        }
    }
}

impl StandardJobMaps {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build with a custom [`LifecycleConfig`]. Useful for tests that
    /// want tight grace/retention windows; production uses
    /// [`Self::new`] which pins [`LifecycleConfig::DEFAULT`].
    pub fn with_config(config: LifecycleConfig) -> Self {
        Self {
            entries: HashMap::new(),
            config,
        }
    }

    /// Record a fresh `NewMiningJob` send. `now_ms` stamps
    /// `created_at_ms` for the aging algorithm. `template_snapshot`
    /// freezes the template context (version / prev_hash / n_bits /
    /// network_difficulty) at send-time so submit-validation can
    /// reconstruct the exact 80-byte header the miner hashed against
    /// — SV2 §5.3.14 strict-conform.
    ///
    /// Re-sending the same `job_id` (shouldn't happen —
    /// channel-local ids are `next_job_id`-allocated) overwrites the
    /// prior entry, including resetting `retired_at_ms` to `None`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_send(
        &mut self,
        job_id: u32,
        difficulty: Difficulty,
        merkle_root: [u8; 32],
        template_snapshot: StandardTemplateSnapshot,
        coinbase_stratum: Vec<u8>,
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
                template_id,
                created_at_ms: now_ms,
                retired_at_ms: None,
            },
        );
    }

    /// Test-only convenience that mirrors the pre-7.4d.3 5-argument
    /// shape (no coinbase / template_id). Lets fixtures that don't
    /// exercise block-submit stay terse.
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
            None,
            now_ms,
        );
    }

    /// Stamp `retired_at_ms = Some(now_ms)` on every entry that doesn't
    /// already have one — the block-change path (SV2 `SetNewPrevHash`
    /// fan-out). Idempotent: a second call at a later timestamp keeps
    /// the original `retired_at_ms` so the grace-window math doesn't
    /// slide backwards.
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

    /// Full-entry accessor — exposes the per-job
    /// [`StandardTemplateSnapshot`] alongside the difficulty + merkle
    /// root. Preferred over [`Self::lookup`] when the caller needs the
    /// snapshot (= every submit-validation call in production).
    pub fn entry_of(&self, job_id: u32) -> Option<&StandardJobEntry> {
        self.entries.get(&job_id)
    }

    /// Stand-alone per-job difficulty lookup. Used by the Extended
    /// submit handler to look up per-job difficulty for target
    /// validation.
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
            network_difficulty: Difficulty(1.0),
            coinbase_tx_value_remaining: 5_000_000_000,
        }
    }

    fn ej(now_ms: u64) -> ExtendedJob {
        ExtendedJob {
            coinbase_prefix: vec![0; 8],
            coinbase_suffix: vec![0; 8],
            merkle_path: vec![[0u8; 32]],
            extranonce_prefix: Vec::new(),
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            n_bits: 0x1d00_ffff,
            min_ntime: 0,
            difficulty: Difficulty(1.0),
            network_difficulty: Difficulty(1.0),
            coinbase_tx_value_remaining: 5_000_000_000,
            template_id: None,
            created_at: now_ms,
            retired_at: None,
        }
    }

    /// `classify_extended_job` defers to the shared lifecycle config
    /// — verify the wiring rather than re-test the math (that's done
    /// in `bp-jobs-lifecycle::tests`).
    #[test]
    fn classify_active_for_fresh_job() {
        assert_eq!(
            classify_extended_job(&ej(1_000), 1_500),
            JobClassification::Active
        );
    }

    #[test]
    fn classify_stale_creditable_at_grace_boundary() {
        let mut job = ej(1_000);
        job.retired_at = Some(10_000);
        assert_eq!(
            classify_extended_job(&job, 10_000 + LifecycleConfig::DEFAULT.grace_ms),
            JobClassification::StaleCreditable
        );
    }

    #[test]
    fn classify_stale_rejected_one_ms_past_grace() {
        let mut job = ej(1_000);
        job.retired_at = Some(10_000);
        assert_eq!(
            classify_extended_job(&job, 10_000 + LifecycleConfig::DEFAULT.grace_ms + 1),
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
        cleanup_retired_extended_jobs(&mut map, 6_000 + LifecycleConfig::DEFAULT.retention_ms * 5);
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
            classify_extended_job(&map[&1], t0),
            JobClassification::Active
        );
        retire_extended_jobs(&mut map, t0);
        assert_eq!(
            classify_extended_job(&map[&1], t0 + 1_000),
            JobClassification::StaleCreditable
        );
        assert_eq!(
            classify_extended_job(&map[&1], t0 + 30_000),
            JobClassification::StaleRejected
        );
        for i in 0..3u32 {
            map.insert(100 + i, ej(t0 + 100 + u64::from(i)));
        }
        cleanup_retired_extended_jobs(&mut map, t0 + LifecycleConfig::DEFAULT.retention_ms + 1);
        assert!(!map.contains_key(&1));
    }

    // ── StandardJobMaps ─────────────────────────────────────────────

    #[test]
    fn standard_job_maps_record_and_lookup_in_lockstep() {
        let mut maps = StandardJobMaps::new();
        let mr = [0x42u8; 32];
        maps.record_send_for_test(7, Difficulty(1024.0), mr, snap(), 1_000);
        let (d, r) = maps.lookup(7).expect("must find");
        assert_eq!(d, Difficulty(1024.0));
        assert_eq!(r, mr);
    }

    #[test]
    fn standard_job_maps_lookup_returns_none_for_unknown() {
        let maps = StandardJobMaps::new();
        assert_eq!(maps.lookup(42), None);
    }

    #[test]
    fn standard_job_maps_pin_per_job_difficulty() {
        let mut maps = StandardJobMaps::new();
        maps.record_send_for_test(1, Difficulty(100.0), [0u8; 32], snap(), 1_000);
        maps.record_send_for_test(2, Difficulty(200.0), [0u8; 32], snap(), 2_000);
        assert_eq!(maps.difficulty_of(1), Some(Difficulty(100.0)));
        assert_eq!(maps.difficulty_of(2), Some(Difficulty(200.0)));
        assert_eq!(maps.difficulty_of(99), None);
    }

    /// SV2 §5.3.14: per-job template-snapshot pinning. Two
    /// record_send calls with different snapshots produce entries
    /// whose snapshots survive retire (in-flight shares for the old
    /// job hash against the OLD prev_hash + n_bits + version, not
    /// the current template's).
    #[test]
    fn standard_per_job_snapshot_pins_template_context_at_send_time() {
        let mut maps = StandardJobMaps::new();
        let snap_old = StandardTemplateSnapshot {
            version: 0x2000_0000,
            prev_hash: [0xAA; 32],
            n_bits: 0x1d00_ffff,
            network_difficulty: Difficulty(100.0),
            coinbase_tx_value_remaining: 5_000_000_000,
        };
        let snap_new = StandardTemplateSnapshot {
            version: 0x2000_0001,
            prev_hash: [0xBB; 32],
            n_bits: 0x1d01_ffff,
            network_difficulty: Difficulty(200.0),
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
        assert_eq!(e1_after.retired_at_ms, Some(3_000));
    }

    #[test]
    fn standard_job_maps_forget_drops_entry() {
        let mut maps = StandardJobMaps::new();
        maps.record_send_for_test(1, Difficulty(100.0), [0u8; 32], snap(), 0);
        maps.forget(1);
        assert!(maps.is_empty());
        assert_eq!(maps.lookup(1), None);
    }

    #[test]
    fn standard_record_send_stamps_created_at_and_clears_retired_at() {
        let mut maps = StandardJobMaps::new();
        maps.record_send_for_test(1, Difficulty(1.0), [0u8; 32], snap(), 1_000);
        maps.retire(2_000);
        // Re-send same id (shouldn't happen with next_job_id but pin
        // the overwrite semantics anyway).
        maps.record_send_for_test(1, Difficulty(2.0), [0x11; 32], snap(), 3_000);
        assert_eq!(
            maps.classify(1, 3_000),
            Some(JobClassification::Active),
            "re-sent entry must classify as Active (retired_at cleared)"
        );
    }

    // ── retire-not-clear classification (the Item-B fix) ─────────────

    #[test]
    fn standard_classify_unknown_job_returns_none() {
        let maps = StandardJobMaps::new();
        assert_eq!(maps.classify(42, 1_000), None);
    }

    #[test]
    fn standard_classify_active_for_fresh_job() {
        let mut maps = StandardJobMaps::new();
        maps.record_send_for_test(1, Difficulty(1.0), [0u8; 32], snap(), 1_000);
        assert_eq!(maps.classify(1, 1_500), Some(JobClassification::Active));
    }

    #[test]
    fn standard_classify_stale_creditable_at_grace_boundary() {
        let mut maps = StandardJobMaps::new();
        maps.record_send_for_test(1, Difficulty(1.0), [0u8; 32], snap(), 1_000);
        maps.retire(10_000);
        assert_eq!(
            maps.classify(1, 10_000 + LifecycleConfig::DEFAULT.grace_ms),
            Some(JobClassification::StaleCreditable)
        );
    }

    #[test]
    fn standard_classify_stale_rejected_one_ms_past_grace() {
        let mut maps = StandardJobMaps::new();
        maps.record_send_for_test(1, Difficulty(1.0), [0u8; 32], snap(), 1_000);
        maps.retire(10_000);
        assert_eq!(
            maps.classify(1, 10_000 + LifecycleConfig::DEFAULT.grace_ms + 1),
            Some(JobClassification::StaleRejected)
        );
    }

    #[test]
    fn standard_retire_is_idempotent_keeps_original_timestamp() {
        let mut maps = StandardJobMaps::new();
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
        let mut maps = StandardJobMaps::new();
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
        let mut maps = StandardJobMaps::new();
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

    /// Custom-config knob exercised: tighter retention window aging
    /// kicks in earlier.
    #[test]
    fn standard_with_config_honours_custom_retention() {
        let mut maps = StandardJobMaps::with_config(LifecycleConfig {
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
