// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV1 job/template registry: a tip change retires entries instead of deleting them, so
//! a late share within the grace window is still credited and a later one is stale, not
//! `JobNotFound`. The lifecycle math lives in [`bp_jobs_lifecycle`] so SV1 and SV2 stay
//! in lock-step; SV1 has no stale code, so a rejected stale share goes out as code 21.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bp_jobs_lifecycle::{age_entries, classify, LifecycleConfig};
use bp_mining_job::MiningJob;

use crate::config::ServerConfig;
use crate::notify::ActiveSV1Template;

pub(crate) use bp_jobs_lifecycle::JobClassification;

/// Result of [`JobRegistry::classify`]. Holds `Arc` handles so the caller can
/// drop the registry lock before building a block coinbase.
#[derive(Clone, Debug)]
pub struct JobLookup {
    pub classification: JobClassification,
    pub mining_job: Arc<MiningJob>,
    pub template: Arc<ActiveSV1Template>,
    /// Numeric id; the hex form exists only on the wire, which keeps allocation
    /// and string hashing out of the registry's critical section.
    pub template_id: u64,
}

// ── Internal entries ─────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct JobEntry {
    mining_job: Arc<MiningJob>,
    /// See [`JobLookup::template_id`].
    template_id: u64,
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
    jobs: HashMap<u64, JobEntry>,
    templates: HashMap<u64, TemplateEntry>,
    /// The hex form miners see is rendered outside the lock.
    next_job_id: u64,
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
        Self::new(cfg.lifecycle)
    }

    pub fn config(&self) -> LifecycleConfig {
        self.config
    }

    /// Next job id without bumping the counter; the vardiff race-clamp uses it
    /// as its ratchet boundary.
    pub fn peek_next_job_id(&self) -> u64 {
        self.inner
            .lock()
            .expect("job-registry mutex poisoned")
            .next_job_id
    }

    /// Test convenience over [`Self::add_template_shared`].
    pub fn add_template(&self, template: ActiveSV1Template, now_ms: u64) -> u64 {
        self.add_template_shared(Arc::new(template), now_ms)
    }

    /// Takes a shared `Arc` because every connection registers on every
    /// broadcast; N registrations stay refcount bumps, not N deep copies.
    pub fn add_template_shared(&self, template: Arc<ActiveSV1Template>, now_ms: u64) -> u64 {
        let mut inner = self.inner.lock().expect("job-registry mutex poisoned");
        let id = inner.next_template_id;
        inner.next_template_id += 1;
        // Integer key: this section is contended by every connection on every broadcast.
        inner.templates.insert(
            id,
            TemplateEntry {
                template,
                creation_ms: now_ms,
                retired_at_ms: None,
            },
        );
        id
    }

    /// Test convenience over [`Self::add_job_shared`].
    pub fn add_job(&self, mining_job: MiningJob, template_id: u64, now_ms: u64) -> String {
        self.add_job_shared(Arc::new(mining_job), template_id, now_ms)
    }

    /// Returns the hex id for `mining.notify[0]`. Takes a shared `Arc` because
    /// same-payout connections register the same cached job on every broadcast.
    pub fn add_job_shared(
        &self,
        mining_job: Arc<MiningJob>,
        template_id: u64,
        now_ms: u64,
    ) -> String {
        let id = {
            let mut inner = self.inner.lock().expect("job-registry mutex poisoned");
            let id = inner.next_job_id;
            inner.next_job_id += 1;
            inner.jobs.insert(
                id,
                JobEntry {
                    mining_job,
                    template_id,
                    creation_ms: now_ms,
                    retired_at_ms: None,
                },
            );
            id
        };
        format!("{id:x}")
    }

    /// `None` means `JobNotFound` (unknown, malformed, or its template is gone;
    /// such an orphan job self-prunes here).
    pub fn classify(&self, job_id_hex: &str, now_ms: u64) -> Option<JobLookup> {
        // `from_str_radix` accepts a leading `+`, so without the digit check
        // `"+1"` would alias job `1`.
        if job_id_hex.is_empty() || !job_id_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let job_id = u64::from_str_radix(job_id_hex, 16).ok()?;

        let mut inner = self.inner.lock().expect("job-registry mutex poisoned");
        let job_entry = inner.jobs.get(&job_id)?.clone();

        let template_entry = match inner.templates.get(&job_entry.template_id) {
            Some(t) => t.clone(),
            None => {
                inner.jobs.remove(&job_id);
                return None;
            }
        };
        drop(inner);

        let classification = classify(job_entry.retired_at_ms, now_ms, &self.config);

        Some(JobLookup {
            classification,
            mining_job: job_entry.mining_job,
            template: template_entry.template,
            template_id: job_entry.template_id,
        })
    }

    /// `clear_jobs` retires every entry unconditionally, then ages. Not for block
    /// changes: the registry is shared by all streams of a port and a blanket
    /// retire would hit other streams' fresh jobs; use [`Self::cleanup_for_tip`].
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

    /// Retires entries built on a prev-hash other than `tip_prev_hash` (and orphan
    /// jobs), then ages. Keyed on prev-hash because all streams of a port share the
    /// registry and see a block change at different instants: the pass must be
    /// order-independent and never retire jobs already registered for the new tip.
    pub fn cleanup_for_tip(&self, tip_prev_hash: &[u8; 32], now_ms: u64) {
        let mut guard = self.inner.lock().expect("job-registry mutex poisoned");
        let cfg = self.config;
        let inner = &mut *guard;

        for t in inner.templates.values_mut() {
            if t.retired_at_ms.is_none() && t.template.prev_hash != *tip_prev_hash {
                t.retired_at_ms = Some(now_ms);
            }
        }
        // A job whose template is already gone is retired too, so a late share
        // gets a stale classification instead of racing the self-prune.
        let templates = &inner.templates;
        for j in inner.jobs.values_mut() {
            if j.retired_at_ms.is_some() {
                continue;
            }
            let stale = match templates.get(&j.template_id) {
                Some(t) => t.template.prev_hash != *tip_prev_hash,
                None => true,
            };
            if stale {
                j.retired_at_ms = Some(now_ms);
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
        ActiveSV1Template::from_template(bp_template_distribution::ActiveTemplate {
            template_id: 1,
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            n_bits: 0x1d00_ffff,
            header_timestamp: 0x65a1_b2c3,
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
        })
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
            sats: 5_000_000_000,
        }];
        build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap()
    }

    // ── ID allocation: 1, 2, 3, ... hex ────────────────────────────────

    #[test]
    fn template_and_job_ids_are_monotonic_lowercase_hex_starting_at_one() {
        let reg = JobRegistry::new(cfg());
        let t1 = reg.add_template(dummy_active_template(), 1_000);
        let t2 = reg.add_template(dummy_active_template(), 1_000);
        assert_eq!(t1, 1);
        assert_eq!(t2, 2);

        let j1 = reg.add_job(dummy_mining_job(), t1, 1_000);
        let j2 = reg.add_job(dummy_mining_job(), t2, 1_000);
        assert_eq!(j1, "1");
        assert_eq!(j2, "2");
    }

    #[test]
    fn peek_next_job_id_does_not_advance_the_counter() {
        let reg = JobRegistry::new(cfg());
        assert_eq!(reg.peek_next_job_id(), 1);
        assert_eq!(reg.peek_next_job_id(), 1);
        reg.add_template(dummy_active_template(), 1_000);
        reg.add_job(dummy_mining_job(), 1, 1_000);
        assert_eq!(reg.peek_next_job_id(), 2);
    }

    // ── classify: 3 outcomes + None ────────────────────────────────────

    /// Pins that `classify` reports the template id `add_template` handed out.
    #[test]
    fn classify_reports_the_registering_template_id() {
        let reg = JobRegistry::new(cfg());
        let tid = reg.add_template(dummy_active_template(), 1_000);
        let jid = reg.add_job(dummy_mining_job(), tid, 1_000);

        let lookup = reg.classify(&jid, 1_500).expect("must be found");
        assert_eq!(lookup.template_id, tid);
    }

    /// Pins that `classify` accepts the hex id `add_job` returned.
    #[test]
    fn job_id_hex_round_trips_through_classify() {
        let reg = JobRegistry::new(cfg());
        let tid = reg.add_template(dummy_active_template(), 1_000);
        // Push the counter past 9 so the hex form is genuinely hex (`a`),
        // not a digit that would also parse as decimal.
        for _ in 0..10 {
            reg.add_job(dummy_mining_job(), tid, 1_000);
        }
        let jid = reg.add_job(dummy_mining_job(), tid, 1_000);
        assert_eq!(jid, "b", "wire id must be lowercase hex");
        assert!(
            reg.classify(&jid, 1_500).is_some(),
            "classify must accept the hex id it just issued"
        );
    }

    /// Pins that a malformed or non-canonical job id resolves to `None`.
    #[test]
    fn classify_rejects_malformed_job_id() {
        let reg = JobRegistry::new(cfg());
        let tid = reg.add_template(dummy_active_template(), 1_000);
        let _ = reg.add_job(dummy_mining_job(), tid, 1_000);

        assert!(reg.classify("not-hex", 1_500).is_none());
        assert!(reg.classify("", 1_500).is_none());
        assert!(reg.classify("zzzz", 1_500).is_none());
        // `from_str_radix` alone would resolve `"+1"` to job 1.
        assert!(
            reg.classify("1", 1_500).is_some(),
            "sanity: job 1 exists, so the +1 assertion below is meaningful"
        );
        assert!(
            reg.classify("+1", 1_500).is_none(),
            "a non-canonical id must not alias a real job"
        );
    }

    #[test]
    fn classify_returns_active_for_fresh_job() {
        let reg = JobRegistry::new(cfg());
        let tid = reg.add_template(dummy_active_template(), 1_000);
        let jid = reg.add_job(dummy_mining_job(), tid, 1_000);

        let lookup = reg.classify(&jid, 1_500).expect("must be found");
        assert_eq!(lookup.classification, JobClassification::Active);
        assert_eq!(lookup.template_id, tid);
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
        let jid = reg.add_job(dummy_mining_job(), tid, 1_000);

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
        reg.add_job(dummy_mining_job(), t1, 1_000);
        reg.add_job(dummy_mining_job(), t2, 2_000);

        reg.cleanup(true, 10_000);

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

        // Rejected at 17_000 only if retired_at stayed at 10_000.
        let cls = reg.classify(&jid, 17_000).unwrap().classification;
        assert_eq!(cls, JobClassification::StaleRejected);
    }

    // ── cleanup_for_tip: prev-hash-conditioned retire ──────────────────

    fn template_with_prev(prev: u8) -> ActiveSV1Template {
        let mut active = dummy_active_template();
        active.template.prev_hash = [prev; 32];
        active.recompute_notify_header_hex();
        active
    }

    /// Pins that only old-tip entries are retired.
    #[test]
    fn cleanup_for_tip_retires_only_entries_from_other_tips() {
        let reg = JobRegistry::new(cfg());
        let t_old = reg.add_template(template_with_prev(0xAB), 1_000);
        let j_old = reg.add_job(dummy_mining_job(), t_old, 1_000);
        let t_new = reg.add_template(template_with_prev(0xCD), 2_000);
        let j_new = reg.add_job(dummy_mining_job(), t_new, 2_000);

        reg.cleanup_for_tip(&[0xCD; 32], 10_000);

        assert_eq!(
            reg.classify(&j_old, 10_000).unwrap().classification,
            JobClassification::StaleCreditable,
            "old-tip job must be retired"
        );
        assert_eq!(
            reg.classify(&j_new, 10_000).unwrap().classification,
            JobClassification::Active,
            "new-tip job must stay active"
        );
    }

    /// Pins that a later same-tip pass from another stream changes nothing.
    #[test]
    fn cleanup_for_tip_is_idempotent_and_order_independent() {
        let reg = JobRegistry::new(cfg());
        let t_old = reg.add_template(template_with_prev(0xAB), 1_000);
        let j_old = reg.add_job(dummy_mining_job(), t_old, 1_000);

        // Stream A observes the new block at t=10_000 …
        reg.cleanup_for_tip(&[0xCD; 32], 10_000);
        // … a connection registers a fresh new-tip job right after …
        let t_new = reg.add_template(template_with_prev(0xCD), 10_100);
        let j_new = reg.add_job(dummy_mining_job(), t_new, 10_100);
        // … and stream B's translator fires later with the same tip.
        reg.cleanup_for_tip(&[0xCD; 32], 12_000);

        // The fresh job survives the late second pass.
        assert_eq!(
            reg.classify(&j_new, 12_500).unwrap().classification,
            JobClassification::Active,
            "a later same-tip pass must never retire fresh new-tip jobs"
        );
        // Rejected at 17_000 only if retired_at stayed at 10_000.
        assert_eq!(
            reg.classify(&j_old, 17_000).unwrap().classification,
            JobClassification::StaleRejected
        );
    }

    /// Pins that a same-tip refresh retires nothing.
    #[test]
    fn cleanup_for_tip_same_tip_is_age_only() {
        let reg = JobRegistry::new(cfg());
        let tid = reg.add_template(template_with_prev(0xAB), 1_000);
        let jid = reg.add_job(dummy_mining_job(), tid, 1_000);

        reg.cleanup_for_tip(&[0xAB; 32], 50_000);

        assert_eq!(
            reg.classify(&jid, 50_000).unwrap().classification,
            JobClassification::Active
        );
    }

    /// Pins that a job whose template is gone is retired by the pass.
    #[test]
    fn cleanup_for_tip_retires_orphan_jobs() {
        let reg = JobRegistry::new(cfg());
        // A template id that was never registered.
        let jid = reg.add_job(dummy_mining_job(), 9_999, 1_000);

        reg.cleanup_for_tip(&[0xAB; 32], 10_000);

        assert_eq!(reg.job_count(), 1);
        assert!(reg.classify(&jid, 10_000).is_none());
        assert_eq!(reg.job_count(), 0);
    }

    /// Pins that tip-retired entries age out on a later pass past retention.
    #[test]
    fn cleanup_for_tip_ages_out_retired_entries_past_retention() {
        let reg = JobRegistry::new(cfg());
        let t_old = reg.add_template(template_with_prev(0xAB), 1_000);
        let j_old = reg.add_job(dummy_mining_job(), t_old, 1_000);

        // Block change at t=10_000 retires the old-tip entries.
        reg.cleanup_for_tip(&[0xCD; 32], 10_000);
        // Enough newer entries that the MIN_RETAINED floor doesn't save
        // the originals.
        for i in 0..3 {
            let t = reg.add_template(template_with_prev(0xCD), 20_000 + i);
            reg.add_job(dummy_mining_job(), t, 20_000 + i);
        }

        // A later same-tip pass past retention GCs the retired entries.
        reg.cleanup_for_tip(&[0xCD; 32], 10_000 + cfg().retention_ms + 1);

        assert!(
            reg.classify(&j_old, 10_000 + cfg().retention_ms + 100)
                .is_none(),
            "old-tip job must be GC'd past retention"
        );
        assert_eq!(reg.job_count(), 3);
        assert_eq!(reg.template_count(), 3);
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
        // 4 entries — 2 retired far in the past, 2 fresh. cleanup(true, …)
        // stamps retired_at at call time, so the fresh two are added after.
        for i in 0..2 {
            reg.add_template(dummy_active_template(), 1_000 + i * 1_000);
        }
        // Retire the older two.
        reg.cleanup(true, 3_000);
        for i in 0..2 {
            reg.add_template(dummy_active_template(), 10_000 + i * 1_000);
        }

        // The older retired entries are still within retention.
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
        let jid = reg.add_job(dummy_mining_job(), tid, t0 - 10_000);

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
        // protect the original.
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
