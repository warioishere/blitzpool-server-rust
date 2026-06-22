// SPDX-License-Identifier: AGPL-3.0-or-later

//! ckpool-style job / template lifecycle registry.
//!
//! Job and template lifecycle registry:
//!
//! 1. **Two maps** keyed by lowercase-hex strings: `jobs` (per-miner
//!    `MiningJob` + the template-id it belongs to) and `templates`
//!    (the assembled [`ActiveSV1Template`] each batch of jobs was built
//!    against).
//!
//! 2. **Retire-then-age** lifecycle: a block boundary stamps `retired_at`
//!    on every current entry without deleting them (so late shares for
//!    the previous tip can still resolve to a real job, not be reported
//!    as `JobNotFound`). Aging removes entries whose retirement is past
//!    [`bp_jobs_lifecycle::LifecycleConfig::retention_ms`], subject to
//!    the [`bp_jobs_lifecycle::LifecycleConfig::min_retained`] floor.
//!
//! 3. **Three-way share classification** ([`JobClassification`]
//!    re-exported from [`bp_jobs_lifecycle`]):
//!    - `Active` — the job has not been retired.
//!    - `StaleCreditable` — retired ≤
//!      [`bp_jobs_lifecycle::LifecycleConfig::grace_ms`] ago. The work
//!      was valid at the moment it was issued; we credit it as if
//!      current (network-jitter absorption).
//!    - `StaleRejected` — retired beyond the grace window. Reject with
//!      a distinct internal counter (wire code 21, same as JobNotFound,
//!      because SV1 has no separate "stale" code).
//!
//! The lifecycle math itself (`classify`, `age_entries`) lives in
//! [`bp_jobs_lifecycle`] so it stays in lock-step with the per-channel
//! Extended-job lifecycle in `bp-stratum-v2::mining::jobs`. This module
//! keeps the SV1-specific storage shape (hex-string ids,
//! template-indirection, single `Mutex<Inner>` for the global registry)
//! and delegates the math.
//!
//! All state lives behind a single `std::sync::Mutex` — concurrent
//! callers serialize on registry mutations but the per-call work
//! (insert / classify / cleanup) is microseconds. The hot share path
//! takes the lock once per submission. No `Arc<Mutex<…>>`-of-many.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bp_jobs_lifecycle::{age_entries, classify, LifecycleConfig};
use bp_mining_job::MiningJob;

use crate::config::ServerConfig;
use crate::notify::ActiveSV1Template;

pub use bp_jobs_lifecycle::JobClassification;

/// Build a [`LifecycleConfig`] from the SV1 [`ServerConfig`] field
/// names. Free helper so the `JobRegistry` constructors stay simple.
pub fn lifecycle_from_server_config(cfg: &ServerConfig) -> LifecycleConfig {
    LifecycleConfig {
        grace_ms: cfg.stale_grace_ms,
        retention_ms: cfg.job_retention_ms,
        min_retained: cfg.min_retained_jobs,
    }
}

/// Snapshot returned by [`JobRegistry::classify`] when a job is found.
/// Holds `Arc` handles to the shared [`MiningJob`] and
/// [`ActiveSV1Template`] so the caller can release the registry lock
/// and continue work — including building a block-submission coinbase
/// — without holding it. Cloning a lookup out of the lock is a pair of
/// refcount bumps, not a deep copy of the coinbase/merkle buffers.
#[derive(Clone, Debug)]
pub struct JobLookup {
    pub classification: JobClassification,
    pub mining_job: Arc<MiningJob>,
    pub template: Arc<ActiveSV1Template>,
    pub template_id_hex: String,
}

// ── Internal entries ─────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct JobEntry {
    mining_job: Arc<MiningJob>,
    template_id_hex: String,
    creation_ms: u64,
    retired_at_ms: Option<u64>,
}

#[derive(Clone, Debug)]
struct TemplateEntry {
    template: Arc<ActiveSV1Template>,
    creation_ms: u64,
    retired_at_ms: Option<u64>,
}

struct Inner {
    jobs: HashMap<String, JobEntry>,
    templates: HashMap<String, TemplateEntry>,
    /// Monotonic counter for `jobs` keys. Hex form is what miners see in
    /// the `mining.notify[0]` field and echo back in `mining.submit[1]`.
    next_job_id: u64,
    /// Monotonic counter for `templates` keys. Stored on each `JobEntry`
    /// so submit lookup can chase job → template in one hop.
    next_template_id: u64,
}

// ── JobRegistry ──────────────────────────────────────────────────────

pub struct JobRegistry {
    inner: Mutex<Inner>,
    config: LifecycleConfig,
}

impl JobRegistry {
    pub fn new(config: LifecycleConfig) -> Self {
        Self {
            inner: Mutex::new(Inner {
                jobs: HashMap::new(),
                templates: HashMap::new(),
                next_job_id: 1,
                next_template_id: 1,
            }),
            config,
        }
    }

    pub fn from_server_config(cfg: &ServerConfig) -> Self {
        Self::new(lifecycle_from_server_config(cfg))
    }

    pub fn config(&self) -> LifecycleConfig {
        self.config
    }

    /// Peek the next job-id WITHOUT bumping the counter. Used by the
    /// vardiff race-clamp snapshot in `StratumV1Client::checkDifficulty`,
    /// where we record the boundary id and the next `add_job` call
    /// commits it.
    pub fn peek_next_job_id(&self) -> u64 {
        self.inner
            .lock()
            .expect("job-registry mutex poisoned")
            .next_job_id
    }

    /// Insert a template under a freshly-allocated hex id. Returns the
    /// id the caller should reference in subsequent `add_job` calls.
    /// Convenience wrapper that takes ownership and wraps in `Arc` —
    /// used by tests. The hot broadcast path uses
    /// [`Self::add_template_shared`] to register the already-shared Arc
    /// without a deep copy.
    pub fn add_template(&self, template: ActiveSV1Template, now_ms: u64) -> String {
        self.add_template_shared(Arc::new(template), now_ms)
    }

    /// Insert an already-`Arc`-shared template under a freshly-allocated
    /// hex id. Each connection registers per broadcast, so taking the
    /// shared `Arc` here turns those N registrations into refcount bumps
    /// instead of N deep copies of the merkle path / coinbase buffers.
    pub fn add_template_shared(&self, template: Arc<ActiveSV1Template>, now_ms: u64) -> String {
        let mut inner = self.inner.lock().expect("job-registry mutex poisoned");
        let id = inner.next_template_id;
        inner.next_template_id += 1;
        let id_hex = format!("{:x}", id);
        inner.templates.insert(
            id_hex.clone(),
            TemplateEntry {
                template,
                creation_ms: now_ms,
                retired_at_ms: None,
            },
        );
        id_hex
    }

    /// Insert a mining job linked to a template, under a freshly-allocated
    /// hex id. Returns the id the SV1 wire layer should put in
    /// `mining.notify[0]`.
    pub fn add_job(&self, mining_job: MiningJob, template_id_hex: String, now_ms: u64) -> String {
        let mut inner = self.inner.lock().expect("job-registry mutex poisoned");
        let id = inner.next_job_id;
        inner.next_job_id += 1;
        let id_hex = format!("{:x}", id);
        inner.jobs.insert(
            id_hex.clone(),
            JobEntry {
                mining_job: Arc::new(mining_job),
                template_id_hex,
                creation_ms: now_ms,
                retired_at_ms: None,
            },
        );
        id_hex
    }

    /// Classify a share-submit's referenced job against the lifecycle
    /// state. Returns:
    ///
    /// - `None` — neither the job nor its template is currently
    ///   recoverable. Caller emits `JobNotFound`. Orphan job entries
    ///   (the job is there but its template was GC'd) self-prune here.
    /// - `Some(lookup)` — job + template are present and the
    ///   classification reports the wire-result the caller should send.
    pub fn classify(&self, job_id_hex: &str, now_ms: u64) -> Option<JobLookup> {
        let mut inner = self.inner.lock().expect("job-registry mutex poisoned");
        let job_entry = inner.jobs.get(job_id_hex)?.clone();

        let template_entry = match inner.templates.get(&job_entry.template_id_hex) {
            Some(t) => t.clone(),
            None => {
                // Orphan job — its template aged out. Self-prune so we
                // don't keep classifying the same dead reference.
                inner.jobs.remove(job_id_hex);
                return None;
            }
        };
        drop(inner);

        let classification = classify(job_entry.retired_at_ms, now_ms, &self.config);

        Some(JobLookup {
            classification,
            mining_job: job_entry.mining_job,
            template: template_entry.template,
            template_id_hex: job_entry.template_id_hex,
        })
    }

    /// Run the ckpool-style lifecycle.
    ///
    /// - `clear_jobs = true` stamps `retired_at = now_ms` on every entry
    ///   that doesn't already have one (idempotent — already-retired
    ///   entries keep their original timestamp). This is what
    ///   [`crate::notify::TemplateChange::NewBlock`] triggers in the
    ///   server.
    /// - `clear_jobs = false` is a periodic age-only tick.
    ///
    /// Both paths then run `age_entries`, which deletes retired entries
    /// past the retention window and (defense-in-depth) non-retired
    /// entries past 2× retention, while always preserving the newest
    /// [`JobRegistryConfig::min_retained`] entries.
    pub fn cleanup(&self, clear_jobs: bool, now_ms: u64) {
        let mut inner = self.inner.lock().expect("job-registry mutex poisoned");
        let cfg = self.config;

        if clear_jobs {
            for j in inner.jobs.values_mut() {
                if j.retired_at_ms.is_none() {
                    j.retired_at_ms = Some(now_ms);
                }
            }
            for t in inner.templates.values_mut() {
                if t.retired_at_ms.is_none() {
                    t.retired_at_ms = Some(now_ms);
                }
            }
        }

        age_entries(
            &mut inner.jobs,
            now_ms,
            &cfg,
            |j| j.creation_ms,
            |j| j.retired_at_ms,
        );
        age_entries(
            &mut inner.templates,
            now_ms,
            &cfg,
            |t| t.creation_ms,
            |t| t.retired_at_ms,
        );
    }

    pub fn job_count(&self) -> usize {
        self.inner
            .lock()
            .expect("job-registry mutex poisoned")
            .jobs
            .len()
    }

    pub fn template_count(&self) -> usize {
        self.inner
            .lock()
            .expect("job-registry mutex poisoned")
            .templates
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bp_mining_job::{
        build_mining_job_from_tdp, PayoutEntry, TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
    };

    // ── Test fixtures ─────────────────────────────────────────────────

    fn cfg() -> LifecycleConfig {
        LifecycleConfig {
            grace_ms: 5_000,
            retention_ms: 600_000,
            min_retained: 3,
        }
    }

    fn dummy_active_template() -> ActiveSV1Template {
        ActiveSV1Template {
            template_id: 1,
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            n_bits: 0x1d00_ffff,
            header_timestamp: 0x65a1_b2c3,
            network_target: [0xFF; 32],
            network_difficulty: 1.0,
            coinbase_prefix: vec![0x03, 0x40, 0x0d, 0x03],
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xffff_ffff,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: {
                let mut v = vec![0u8; 8];
                v.push(0x26);
                v.extend_from_slice(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
                v.extend(std::iter::repeat_n(0xCC, 32));
                v
            },
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
            merkle_path: vec![[0x11; 32]],
            merkle_branch_hex: vec![
                "1111111111111111111111111111111111111111111111111111111111111111".into(),
            ],
        }
    }

    fn dummy_mining_job() -> MiningJob {
        let active = dummy_active_template();
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &active.coinbase_prefix,
            coinbase_tx_version: active.coinbase_tx_version,
            coinbase_tx_input_sequence: active.coinbase_tx_input_sequence,
            coinbase_tx_value_remaining: active.coinbase_tx_value_remaining,
            coinbase_tx_outputs: &active.coinbase_tx_outputs,
            coinbase_tx_outputs_count: active.coinbase_tx_outputs_count,
            coinbase_tx_locktime: active.coinbase_tx_locktime,
        };
        let payouts = vec![PayoutEntry {
            address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            percent: 100.0,
        }];
        build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap()
    }

    // ── ID allocation: 1, 2, 3, ... hex ────────────────────────────────

    #[test]
    fn template_and_job_ids_are_monotonic_lowercase_hex_starting_at_one() {
        let reg = JobRegistry::new(cfg());
        let t1 = reg.add_template(dummy_active_template(), 1_000);
        let t2 = reg.add_template(dummy_active_template(), 1_000);
        assert_eq!(t1, "1");
        assert_eq!(t2, "2");

        let j1 = reg.add_job(dummy_mining_job(), t1.clone(), 1_000);
        let j2 = reg.add_job(dummy_mining_job(), t2.clone(), 1_000);
        assert_eq!(j1, "1");
        assert_eq!(j2, "2");
    }

    #[test]
    fn peek_next_job_id_does_not_advance_the_counter() {
        let reg = JobRegistry::new(cfg());
        assert_eq!(reg.peek_next_job_id(), 1);
        assert_eq!(reg.peek_next_job_id(), 1);
        reg.add_template(dummy_active_template(), 1_000);
        reg.add_job(dummy_mining_job(), "1".to_string(), 1_000);
        assert_eq!(reg.peek_next_job_id(), 2);
    }

    // ── classify: 3 outcomes + None ────────────────────────────────────

    #[test]
    fn classify_returns_active_for_fresh_job() {
        let reg = JobRegistry::new(cfg());
        let tid = reg.add_template(dummy_active_template(), 1_000);
        let jid = reg.add_job(dummy_mining_job(), tid.clone(), 1_000);

        let lookup = reg.classify(&jid, 1_500).expect("must be found");
        assert_eq!(lookup.classification, JobClassification::Active);
        assert_eq!(lookup.template_id_hex, tid);
    }

    #[test]
    fn classify_returns_none_for_unknown_job_id() {
        let reg = JobRegistry::new(cfg());
        assert!(reg.classify("deadbeef", 1_000).is_none());
    }

    #[test]
    fn classify_returns_stale_creditable_within_grace_window() {
        let reg = JobRegistry::new(cfg());
        let tid = reg.add_template(dummy_active_template(), 1_000);
        let jid = reg.add_job(dummy_mining_job(), tid, 1_000);
        reg.cleanup(true, 10_000); // retire at t=10_000

        // 0 ms past retirement
        assert_eq!(
            reg.classify(&jid, 10_000).unwrap().classification,
            JobClassification::StaleCreditable
        );
        // Just before grace expires
        assert_eq!(
            reg.classify(&jid, 10_000 + cfg().grace_ms - 1)
                .unwrap()
                .classification,
            JobClassification::StaleCreditable
        );
        // Exact grace boundary — still creditable (≤)
        assert_eq!(
            reg.classify(&jid, 10_000 + cfg().grace_ms)
                .unwrap()
                .classification,
            JobClassification::StaleCreditable
        );
    }

    #[test]
    fn classify_returns_stale_rejected_past_grace_window() {
        let reg = JobRegistry::new(cfg());
        let tid = reg.add_template(dummy_active_template(), 1_000);
        let jid = reg.add_job(dummy_mining_job(), tid, 1_000);
        reg.cleanup(true, 10_000);

        // 1 ms past grace
        assert_eq!(
            reg.classify(&jid, 10_000 + cfg().grace_ms + 1)
                .unwrap()
                .classification,
            JobClassification::StaleRejected
        );
    }

    #[test]
    fn classify_self_prunes_orphan_jobs_when_template_is_gone() {
        let reg = JobRegistry::new(cfg());
        let tid = reg.add_template(dummy_active_template(), 1_000);
        let jid = reg.add_job(dummy_mining_job(), tid.clone(), 1_000);

        // Force-delete the template by faking the lifecycle: retire +
        // age out at far-future time.
        reg.cleanup(true, 10_000);
        // Add 3 fresh templates so the original isn't kept by the
        // MIN_RETAINED floor.
        for _ in 0..3 {
            reg.add_template(dummy_active_template(), 20_000);
        }
        reg.cleanup(false, 20_000 + cfg().retention_ms + 1);
        // Original template should be GC'd; the job still references it.
        assert!(
            reg.template_count() < 4 + 1,
            "expected original template GC'd"
        );

        // classify on the orphan job → None and self-prune.
        let before = reg.job_count();
        assert!(reg.classify(&jid, 21_000_000).is_none());
        // The orphan job entry was removed.
        assert_eq!(reg.job_count(), before - 1);
    }

    // ── cleanup(true): retire-not-delete + idempotent ──────────────────

    #[test]
    fn cleanup_true_stamps_retired_at_on_every_entry() {
        let reg = JobRegistry::new(cfg());
        let t1 = reg.add_template(dummy_active_template(), 1_000);
        let t2 = reg.add_template(dummy_active_template(), 2_000);
        reg.add_job(dummy_mining_job(), t1.clone(), 1_000);
        reg.add_job(dummy_mining_job(), t2.clone(), 2_000);

        reg.cleanup(true, 10_000);

        // Nothing deleted (4 entries < some threshold; also under
        // MIN_RETAINED floor protection).
        assert_eq!(reg.template_count(), 2);
        assert_eq!(reg.job_count(), 2);

        // All entries classified as stale-creditable (still within grace).
        let lookup = reg.classify("1", 10_000).unwrap();
        assert_eq!(lookup.classification, JobClassification::StaleCreditable);
    }

    #[test]
    fn cleanup_true_is_idempotent_keeps_original_retired_at() {
        let reg = JobRegistry::new(cfg());
        let tid = reg.add_template(dummy_active_template(), 1_000);
        let jid = reg.add_job(dummy_mining_job(), tid, 1_000);

        reg.cleanup(true, 10_000);
        // Second retire at later timestamp — original entries must keep
        // their original retired_at (only stamp if not already set).
        reg.cleanup(true, 20_000);

        // Verify by classifying at a time that's between 10_000 + grace
        // and 20_000 + grace: if retired_at had bumped to 20_000, this
        // would still be creditable. With original retired_at=10_000,
        // it's rejected at 17_000.
        let cls = reg.classify(&jid, 17_000).unwrap().classification;
        assert_eq!(cls, JobClassification::StaleRejected);
    }

    // ── aging: MIN_RETAINED + retention-window + 2x-defense ────────────

    #[test]
    fn aging_respects_min_retained_floor() {
        let reg = JobRegistry::new(cfg());
        // 5 entries all retired right at creation, all far past retention.
        for i in 0..5 {
            let creation = 1_000 + i * 1_000;
            reg.add_template(dummy_active_template(), creation);
        }
        reg.cleanup(true, 6_000); // retire all
                                  // Sanity: 5 entries, all retired at 6_000.
        assert_eq!(reg.template_count(), 5);
        // Cleanup well past retention.
        reg.cleanup(false, 6_000 + cfg().retention_ms * 5);
        // Floor: 3 newest survive.
        assert_eq!(reg.template_count(), 3);
    }

    #[test]
    fn aging_does_not_drop_retired_entries_still_within_retention() {
        let reg = JobRegistry::new(cfg());
        // 4 entries — 2 retired far in the past, 2 fresh.
        // Note: cleanup(true, …) stamps retired_at at the call-time,
        // so we directly construct the registry state.
        for i in 0..2 {
            reg.add_template(dummy_active_template(), 1_000 + i * 1_000);
        }
        // Retire the older two.
        reg.cleanup(true, 3_000);
        for i in 0..2 {
            reg.add_template(dummy_active_template(), 10_000 + i * 1_000);
        }

        // Cleanup at t = 3_000 + retention - 1 → older retired entries are
        // STILL within retention window. None should be deleted (MIN_RETAINED
        // would also save them; verify the retention-window condition is
        // hit correctly).
        reg.cleanup(false, 3_000 + cfg().retention_ms - 1);
        assert_eq!(reg.template_count(), 4);
    }

    #[test]
    fn aging_keeps_non_retired_entries_alive() {
        let reg = JobRegistry::new(cfg());
        for i in 0..5 {
            // Fresh non-retired entries, all ≤ retention old.
            reg.add_template(dummy_active_template(), 1_000 + i * 1_000);
        }
        reg.cleanup(false, 1_000 + cfg().retention_ms);
        assert_eq!(reg.template_count(), 5);
    }

    #[test]
    fn aging_falls_back_to_absolute_age_past_two_x_retention() {
        let reg = JobRegistry::new(cfg());
        // 5 non-retired entries WAY past 2× retention. With MIN_RETAINED=3
        // the oldest 2 get evicted via the defense-in-depth fallback.
        for i in 0..5 {
            reg.add_template(dummy_active_template(), 1_000 + i * 1_000);
        }
        let now = 1_000 + cfg().retention_ms * 3;
        reg.cleanup(false, now);
        assert_eq!(reg.template_count(), 3);
    }

    // ── End-to-end lifecycle ──────────────────────────────────────────

    #[test]
    fn end_to_end_lifecycle_active_then_retired_then_aged() {
        let reg = JobRegistry::new(cfg());
        let t0 = 1_000_000_000;
        let tid = reg.add_template(dummy_active_template(), t0 - 10_000);
        let jid = reg.add_job(dummy_mining_job(), tid.clone(), t0 - 10_000);

        // Phase 1: active.
        assert_eq!(
            reg.classify(&jid, t0).unwrap().classification,
            JobClassification::Active
        );

        // Phase 2: block change at t0 → retired, not deleted.
        reg.cleanup(true, t0);
        assert_eq!(reg.job_count(), 1);

        // Phase 3: share within grace → still creditable.
        assert_eq!(
            reg.classify(&jid, t0 + 1_000).unwrap().classification,
            JobClassification::StaleCreditable
        );

        // Phase 4: share well past grace → rejected stale (NOT JobNotFound).
        assert_eq!(
            reg.classify(&jid, t0 + 30_000).unwrap().classification,
            JobClassification::StaleRejected
        );
        // Entry still in the map for accurate classification.
        assert_eq!(reg.job_count(), 1);

        // Phase 5: add 3 newer entries so the MIN_RETAINED floor doesn't
        // protect our original.
        for i in 0..3 {
            let later = reg.add_template(dummy_active_template(), t0 + 100 + i);
            reg.add_job(dummy_mining_job(), later, t0 + 100 + i);
        }
        // Aging at t0 + retention + 1 → original job GC'd.
        reg.cleanup(false, t0 + cfg().retention_ms + 1);
        assert!(
            reg.classify(&jid, t0 + cfg().retention_ms + 100).is_none(),
            "original job must be GC'd past retention"
        );
    }
}
