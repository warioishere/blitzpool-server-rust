// SPDX-License-Identifier: AGPL-3.0-or-later

//! Share-validation hot path.
//!
//! Given a parsed `mining.submit` request + the session's vardiff/ratchet
//! state + the shared [`JobRegistry`], compute one of:
//!
//! - [`ShareValidation::Accepted`] — header met the effective target.
//!   Carries the assembled header, the share's submission difficulty,
//!   the clamp-aware effective difficulty (for accounting), and the
//!   [`MiningJob`] + [`ActiveSV1Template`] snapshot the caller needs
//!   for downstream side-effects (block-found bookkeeping if
//!   `is_block_candidate`).
//! - [`ShareValidation::Rejected`] — exactly one of the four wire-
//!   visible reject classes (`DuplicateShare`, `JobNotFound`, `Stale`,
//!   `LowDifficulty`).
//!
//! This module is pure logic: no I/O, no broadcasting, no DB. The
//! per-share share-stats fan-out (PPLNS / group-solo recordShare, share-
//! totals cache, address-settings best-diff update) is the caller's job
//! and lives in `client.rs` (Task #8) on top of the trait boundaries
//! in `hooks.rs` (Task #9).

use std::collections::HashSet;
use std::sync::Arc;

use bp_mining_job::{build_block_header, merkle_root_from_coinbase};
use bp_share::{calculate_difficulty, difficulty_to_target, Difficulty, Target};

use crate::frame::{
    SubmitRequest, ERR_DUPLICATE_SHARE, ERR_JOB_NOT_FOUND, ERR_LOW_DIFFICULTY_SHARE,
    REJECT_DUPLICATE, REJECT_JOB_NOT_FOUND, REJECT_LOW_DIFF, REJECT_STALE,
};
use crate::jobs::{JobClassification, JobRegistry};
use crate::notify::ActiveSV1Template;
use bp_mining_job::MiningJob;
use bp_vardiff::effective_job_difficulty;

// ── Reject classification ────────────────────────────────────────────

/// One of the four wire-visible reject reasons.
///
/// `Stale` shares the wire code with `JobNotFound` (SV1 has no separate
/// stale code) but reports a different `wire_message` (`"stale"`) and is
/// tracked under a distinct internal counter so operators can tell the
/// two failure modes apart in the rejection breakdown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    DuplicateShare,
    JobNotFound,
    Stale,
    LowDifficulty,
}

impl RejectReason {
    /// JSON-RPC `error[0]` numeric code on the wire.
    pub fn wire_code(self) -> i64 {
        match self {
            RejectReason::DuplicateShare => ERR_DUPLICATE_SHARE,
            RejectReason::JobNotFound | RejectReason::Stale => ERR_JOB_NOT_FOUND,
            RejectReason::LowDifficulty => ERR_LOW_DIFFICULTY_SHARE,
        }
    }

    /// JSON-RPC `error[1]` human-readable message — standard wire format.
    /// Some monitoring tooling parses these; do not paraphrase.
    pub fn wire_message(self) -> &'static str {
        match self {
            RejectReason::DuplicateShare => REJECT_DUPLICATE,
            RejectReason::JobNotFound => REJECT_JOB_NOT_FOUND,
            RejectReason::Stale => REJECT_STALE,
            RejectReason::LowDifficulty => REJECT_LOW_DIFF,
        }
    }
}

// ── Validation result ────────────────────────────────────────────────

/// Accepted-share details. Carried back to the caller so it can build the
/// `mining.submit` success reply, fan out share-stats, and (if
/// `is_block_candidate`) trigger the TDP `SubmitSolution` path.
#[derive(Clone, Debug)]
pub struct ShareAccept {
    /// `Active` or `StaleCreditable`. Both credit the share; the caller
    /// may want to bookkeep them separately for diagnostics.
    pub classification: JobClassification,
    /// Difficulty the share is **credited at**: post-ckpool-clamp value.
    /// Used by both PPLNS / group-solo accounting and the
    /// `addAcceptedShare` accumulators. May be lower than the session's
    /// current diff when the share was issued before a vardiff ratchet.
    pub effective_difficulty: f64,
    /// Difficulty the **share actually solved for**, derived from the
    /// hash via `bp_share::calculate_difficulty`. Drives the block-found
    /// gate (`>= network_difficulty`) and the best-diff tracker
    /// (`addressSettings.bestDifficulty`).
    pub submission_difficulty: f64,
    /// 80-byte block header that produced the hash. Forwarded to the
    /// external-share-submitter when enabled.
    pub header: [u8; 80],
    /// sha256d of the header — the share's identity.
    pub hash: [u8; 32],
    /// True when the submission difficulty meets or exceeds the network
    /// difficulty derived from `n_bits`. bitcoind is the authoritative
    /// validator — this only triggers the SubmitSolution path.
    pub is_block_candidate: bool,
    /// Shared handle to the job. Needed for `witness_coinbase_with_extranonce`
    /// in the block-found path. `Arc` so the per-share accept carries a
    /// refcount bump, not a deep copy of the coinbase buffers.
    pub mining_job: Arc<MiningJob>,
    /// Shared handle to the template. Needed for the TDP
    /// `submit_solution(template_id, version, timestamp, nonce, …)` call
    /// in the block-found path.
    pub template: Arc<ActiveSV1Template>,
    /// Per-session 4-byte extranonce1 (allocated by the server at
    /// `mining.subscribe`). Combined with `extranonce2` it lets the
    /// `BlockSubmissionSink` rebuild the witness coinbase via
    /// `MiningJob::witness_coinbase_with_extranonce(&enonce1, &enonce2)`
    /// when `is_block_candidate` triggers a TDP `submit_solution`.
    pub enonce1: [u8; 4],
    /// 8-byte extranonce2 as parsed from the `mining.submit` request.
    pub extranonce2: [u8; 8],
}

/// Rejected-share details. Bundles the reason with its on-the-wire form
/// so the caller writes the error frame without re-deriving them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareReject {
    pub reason: RejectReason,
    pub wire_code: i64,
    pub wire_message: &'static str,
}

impl From<RejectReason> for ShareReject {
    fn from(reason: RejectReason) -> Self {
        Self {
            reason,
            wire_code: reason.wire_code(),
            wire_message: reason.wire_message(),
        }
    }
}

/// Outcome of [`validate_submit`].
#[derive(Clone, Debug)]
pub enum ShareValidation {
    Accepted(Box<ShareAccept>),
    Rejected(ShareReject),
}

// ── Per-session state passed into the validator ──────────────────────

/// Per-session inputs that don't live in the [`JobRegistry`]. Owned by
/// the client task; passed by reference into [`validate_submit`] so the
/// validator stays pure.
#[derive(Clone, Copy, Debug)]
pub struct SessionContext<'a> {
    /// 4-byte extranonce1 — pinned at subscribe time, never changes for
    /// the life of the session (ckpool-style fixed enonce1).
    pub extranonce1: &'a [u8; 4],
    /// Current session difficulty as advertised in the latest
    /// `mining.set_difficulty`.
    pub session_difficulty: f64,
    /// Difficulty before the most recent vardiff ratchet. Equal to
    /// `session_difficulty` when no ratchet has happened.
    pub old_session_difficulty: f64,
    /// Boundary id — jobs allocated before this id were issued at
    /// `old_session_difficulty`. `None` means no ratchet has happened
    /// since the session started.
    pub diff_change_job_id: Option<u64>,
    /// Per-share diagnostic logging toggle (server-level
    /// `stratum_share_logs`). Gates the `🎯 Share difficulty` +
    /// `✅ Share accepted` traces below; rejections always log at WARN
    /// regardless.
    pub share_logs: bool,
}

// ── Duplicate-share cache (per session) ──────────────────────────────

/// Per-session dedup cache for accepted-share inputs.
/// `miningSubmissionHashes: Set<string>` exactly: same set of fields
/// (`versionMask`, `nonce`, `extraNonce2`, `ntime`, `jobId`),
/// per-session, cleared on every `clean_jobs=true` notify.
///
/// Uses a sha256d-base64 hash as the set key; semantically a tuple-
/// keyed `HashSet` is identical (any new combo means "not yet seen"),
/// ~10× cheaper, and we don't expose the dedup key on the wire so the
/// choice has no observable side-effects.
#[derive(Default)]
pub struct SessionShareCache {
    seen: HashSet<DedupKey>,
    /// Memo for `difficulty_to_target` on the per-share accept check.
    /// The effective difficulty takes at most two values per session
    /// (current vs ckpool-clamped), changing only on a vardiff ratchet,
    /// so a single `(effective_diff bits → target)` slot serves nearly
    /// every share and a miss just recomputes. Keyed on the exact f64
    /// bit pattern, so the cached target is bit-identical to recomputing
    /// — purely an allocation/BigUint-divide saving, no behaviour change.
    target_memo: Option<(u64, Target)>,
}

/// Parsed-integer dedup key — zero heap allocations per share (mirrors
/// the SV2 fixed-size key). Two submits with the same numeric values are
/// the same share regardless of hex formatting, which is the correct
/// identity; real miners echo our canonical fixed-width hex so this is
/// not observably different from the old 5-`String` key.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
struct DedupKey {
    job_id: u64,
    nonce: u32,
    ntime: u32,
    version_mask: u32,
    extranonce2: [u8; 8],
}

impl DedupKey {
    /// `None` when any field is malformed — such a share is rejected at
    /// the parse step anyway, so it never needs a dedup slot.
    fn from_submit(submit: &SubmitRequest) -> Option<Self> {
        let (version_mask, nonce, ntime, extranonce2) = parse_submit_fields(submit)?;
        let job_id = u64::from_str_radix(submit.job_id, 16).ok()?;
        Some(Self {
            job_id,
            nonce,
            ntime,
            version_mask,
            extranonce2,
        })
    }
}

impl SessionShareCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test whether this submit is a duplicate; if not, record it and
    /// return `false`. Returns `true` if the same `(jobId, nonce, ntime,
    /// versionMask, extranonce2)` tuple has been seen before in this
    /// session. A malformed submit (unparseable fields) can't form a key
    /// and returns `false` — it is rejected at the parse step regardless.
    pub fn record(&mut self, submit: &SubmitRequest) -> bool {
        match DedupKey::from_submit(submit) {
            Some(key) => !self.seen.insert(key),
            None => false,
        }
    }

    /// Drop all accumulated keys. Called when a `clean_jobs=true` notify
    /// goes out — old shares can no longer collide with anything we'd
    /// accept now anyway, and the set otherwise grows unbounded across a
    /// long-lived session.
    pub fn clear(&mut self) {
        self.seen.clear();
    }

    /// Target for `effective_diff`, memoized. Returns the cached target
    /// when the difficulty matches the last computed one (the common
    /// case — diff only moves on a vardiff ratchet), otherwise computes
    /// it via `difficulty_to_target` and caches the result. The key is
    /// the exact f64 bit pattern, so the returned target is identical to
    /// an uncached `difficulty_to_target(Difficulty(effective_diff))`.
    pub(crate) fn target_for(&mut self, effective_diff: f64) -> Target {
        let key = effective_diff.to_bits();
        if let Some((cached_key, cached_target)) = self.target_memo {
            if cached_key == key {
                return cached_target;
            }
        }
        let target = difficulty_to_target(Difficulty(effective_diff));
        self.target_memo = Some((key, target));
        target
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// ── validate_submit ──────────────────────────────────────────────────

/// Validate a `mining.submit` request against the registry + session
/// state. See module docstring for the contract.
///
/// Order of checks:
///   1. Duplicate-share cache (cheapest; bails before any hash work).
///   2. Registry lookup → `None` ⇒ `JobNotFound`.
///   3. `StaleRejected` classification ⇒ `Stale`.
///   4. Hex-parse submit fields → malformed ⇒ `LowDifficulty` (the
///      hash will never match anyway; a garbled header produces the
///      same end-state).
///   5. Assemble header → hash → submission difficulty.
///   6. Apply [`effective_job_difficulty`] clamp; compare hash against
///      `target_for(effective_diff)`.
///   7. `meets_target` ⇒ `Accepted`; else `LowDifficulty`.
pub fn validate_submit(
    submit: &SubmitRequest,
    session: &SessionContext<'_>,
    dedup: &mut SessionShareCache,
    registry: &JobRegistry,
    now_ms: u64,
) -> ShareValidation {
    // 1. Duplicate.
    if dedup.record(submit) {
        tracing::warn!(
            worker = %submit.worker,
            job_id = %submit.job_id,
            "❌ Share rejected: duplicate-share"
        );
        return ShareValidation::Rejected(RejectReason::DuplicateShare.into());
    }

    // 2 + 3. Registry classify.
    let Some(lookup) = registry.classify(submit.job_id, now_ms) else {
        tracing::warn!(
            worker = %submit.worker,
            job_id = %submit.job_id,
            "❌ Share rejected: job-not-found (jobId=0x{})",
            submit.job_id
        );
        return ShareValidation::Rejected(RejectReason::JobNotFound.into());
    };
    if lookup.classification == JobClassification::StaleRejected {
        tracing::warn!(
            worker = %submit.worker,
            job_id = %submit.job_id,
            "❌ Share rejected: stale-share (jobId=0x{}, classification=StaleRejected)",
            submit.job_id
        );
        return ShareValidation::Rejected(RejectReason::Stale.into());
    }

    // 4. Parse the wire-hex fields. We've already validated string-ness
    // at the frame layer; here we check semantic well-formedness.
    let Some((version_mask, nonce, ntime, extranonce2)) = parse_submit_fields(submit) else {
        tracing::warn!(
            worker = %submit.worker,
            job_id = %submit.job_id,
            "❌ Share rejected: malformed-fields (nonce/ntime/version-mask/extranonce2 parse failed)"
        );
        return ShareValidation::Rejected(RejectReason::LowDifficulty.into());
    };

    // 5. Assemble header.
    let coinbase_hash = lookup
        .mining_job
        .coinbase_txid_with_extranonce(session.extranonce1, &extranonce2);
    let merkle_root = merkle_root_from_coinbase(&coinbase_hash, &lookup.template.merkle_path);
    let header = build_block_header(
        lookup.template.version as i32,
        version_mask,
        &lookup.template.prev_hash,
        &merkle_root,
        ntime,
        lookup.template.n_bits,
        nonce,
    );
    let scored = calculate_difficulty(&header);
    let submission_difficulty = scored.submission_difficulty.as_f64();
    let hash = scored.submission_hash;

    // 6. Effective-diff clamp + target check.
    let job_id_int = u64::from_str_radix(submit.job_id, 16).ok();
    let effective_diff = effective_job_difficulty(
        job_id_int,
        session.session_difficulty,
        session.old_session_difficulty,
        session.diff_change_job_id,
    );
    let effective_target = dedup.target_for(effective_diff);

    // Per-share diff trace, gated by the `stratum_share_logs` config
    // flag (still DEBUG, so it also needs `RUST_LOG=...,bp_stratum_v1=debug`).
    // Format `🎯 Share difficulty: X (target: Y)` mirrors the SV2 trace.
    if session.share_logs {
        tracing::debug!(
            worker = %submit.worker,
            job_id = %submit.job_id,
            "🎯 Share difficulty: {:.2} (target: {:.2})",
            submission_difficulty,
            effective_diff
        );
    }

    if !effective_target.is_met_by_le(&hash) {
        // Share dedup:
        //   `❌ Share rejected: difficulty-too-low (submitted=X < effective=Y)`
        // Plus hash_prefix_be for cross-checking against the miner's
        // own debug trace when validator vs miner disagree on the hash.
        let hash_prefix: String = hash[..8].iter().map(|b| format!("{b:02x}")).collect();
        tracing::warn!(
            worker = %submit.worker,
            job_id = %submit.job_id,
            nonce = format_args!("0x{:08x}", nonce),
            extranonce2 = %{
                let mut s = String::with_capacity(extranonce2.len() * 2);
                for b in extranonce2.iter() { s.push_str(&format!("{b:02x}")); }
                s
            },
            hash_prefix_be = %hash_prefix,
            "❌ Share rejected: difficulty-too-low (submitted={:.2} < effective={:.2})",
            submission_difficulty,
            effective_diff
        );
        return ShareValidation::Rejected(RejectReason::LowDifficulty.into());
    }

    // 7. Accepted. Block-find gate uses the (unclamped) submission diff
    // against the network diff — a stale-creditable hit during a reorg
    // can still find a valid alternative tip.
    let is_block_candidate = submission_difficulty >= lookup.template.network_difficulty;
    // Block found marker at
    // INFO when the share also clears network diff. Always-on, no
    // debug flag — block events are too important to gate.
    if is_block_candidate {
        tracing::info!(
            worker = %submit.worker,
            job_id = %submit.job_id,
            height = lookup.template.template_id,
            "🎉🎉🎉 !!! BLOCK FOUND !!! (SV1) — submission_diff={:.2}, network_diff={:.2}",
            submission_difficulty,
            lookup.template.network_difficulty
        );
    } else if session.share_logs {
        // Per-share accept trace, gated by `stratum_share_logs`.
        tracing::debug!(
            worker = %submit.worker,
            job_id = %submit.job_id,
            "✅ Share accepted: submitted={:.2} ≥ effective={:.2}",
            submission_difficulty,
            effective_diff
        );
    }
    ShareValidation::Accepted(Box::new(ShareAccept {
        classification: lookup.classification,
        effective_difficulty: effective_diff,
        submission_difficulty,
        header,
        hash,
        is_block_candidate,
        mining_job: lookup.mining_job,
        template: lookup.template,
        enonce1: *session.extranonce1,
        extranonce2,
    }))
}

/// Parse the four numeric / byte fields from a [`SubmitRequest`]. Returns
/// `None` on any malformed value: invalid hex, wrong byte length for
/// extranonce2, hex value out of u32 range for the numerics.
fn parse_submit_fields(submit: &SubmitRequest) -> Option<(u32, u32, u32, [u8; 8])> {
    let version_mask = u32::from_str_radix(submit.version_mask_hex, 16).ok()?;
    let nonce = u32::from_str_radix(submit.nonce_hex, 16).ok()?;
    let ntime = u32::from_str_radix(submit.ntime_hex, 16).ok()?;
    // extranonce2 is fixed at 8 bytes (16 hex chars) per SV1 spec; use
    // faster-hex's SIMD-accelerated fixed-size decode into a stack buffer
    // to avoid the per-share Vec allocation that `hex::decode` does.
    let hex_bytes = submit.extranonce2_hex.as_bytes();
    if hex_bytes.len() != 16 {
        return None;
    }
    let mut extranonce2 = [0u8; 8];
    faster_hex::hex_decode(hex_bytes, &mut extranonce2).ok()?;
    Some((version_mask, nonce, ntime, extranonce2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::frame::RpcId;
    use crate::notify::ActiveSV1Template;
    use bitcoin::Network;
    use bp_mining_job::{
        build_mining_job_from_tdp, PayoutEntry, TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
    };

    // ── Fixtures ──────────────────────────────────────────────────────

    fn server_config() -> ServerConfig {
        ServerConfig::defaults_for(Network::Bitcoin)
    }

    fn template_with_network_diff(network_difficulty: f64) -> ActiveSV1Template {
        ActiveSV1Template {
            template_id: 1,
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            n_bits: 0x1d00_ffff,
            header_timestamp: 0x65a1_b2c3,
            network_target: [0xFF; 32],
            network_difficulty,
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
            merkle_branch_hex: vec![],
        }
    }

    fn mining_job_from(active: &ActiveSV1Template) -> MiningJob {
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

    fn populated_registry(network_difficulty: f64) -> (JobRegistry, String) {
        let reg = JobRegistry::from_server_config(&server_config());
        let active = template_with_network_diff(network_difficulty);
        let tid = reg.add_template(active.clone(), 1_000);
        let job = mining_job_from(&active);
        let jid = reg.add_job(job, tid, 1_000);
        (reg, jid)
    }

    fn submit<'a>(job_id_hex: &'a str, nonce_hex: &'a str) -> SubmitRequest<'a> {
        SubmitRequest {
            id: RpcId::from(1),
            worker: "addr.w".into(),
            job_id: job_id_hex,
            extranonce2_hex: "1122334455667788",
            ntime_hex: "65a1b2c3",
            nonce_hex,
            version_mask_hex: "1fffe000",
        }
    }

    fn easy_session() -> SessionContext<'static> {
        // session diff 0 → effective target = Target::MAX → any hash passes.
        SessionContext {
            extranonce1: &[0x12, 0x34, 0x56, 0x78],
            session_difficulty: 0.0,
            old_session_difficulty: 0.0,
            diff_change_job_id: None,
            share_logs: false,
        }
    }

    fn impossible_session() -> SessionContext<'static> {
        // session diff 1e30 → target near zero → no hash passes.
        SessionContext {
            extranonce1: &[0x12, 0x34, 0x56, 0x78],
            session_difficulty: 1.0e30,
            old_session_difficulty: 1.0e30,
            diff_change_job_id: None,
            share_logs: false,
        }
    }

    // ── RejectReason wire-code / wire-message tables ──────────────────

    #[test]
    fn reject_wire_codes_match_ts_enum_values() {
        assert_eq!(RejectReason::DuplicateShare.wire_code(), 22);
        // Stale shares the wire code with JobNotFound.
        assert_eq!(RejectReason::JobNotFound.wire_code(), 21);
        assert_eq!(RejectReason::Stale.wire_code(), 21);
        assert_eq!(RejectReason::LowDifficulty.wire_code(), 23);
    }

    #[test]
    fn reject_wire_messages_match_ts_literals() {
        assert_eq!(
            RejectReason::DuplicateShare.wire_message(),
            "Duplicate share"
        );
        assert_eq!(RejectReason::JobNotFound.wire_message(), "Job not found");
        // Stale is a separate message from JobNotFound.
        assert_eq!(RejectReason::Stale.wire_message(), "stale");
        assert_eq!(
            RejectReason::LowDifficulty.wire_message(),
            "Difficulty too low"
        );
    }

    // ── SessionShareCache ─────────────────────────────────────────────

    #[test]
    fn dedup_detects_identical_submissions() {
        let mut cache = SessionShareCache::new();
        let s = submit("1", "deadbeef");
        assert!(!cache.record(&s)); // first time: not a duplicate
        assert!(cache.record(&s)); // second time: duplicate
    }

    #[test]
    fn target_memo_matches_uncached_and_recomputes_on_change() {
        let mut cache = SessionShareCache::new();
        // Across a spread of difficulties (integer, fractional, extreme)
        // the memoized target must be bit-identical to the uncached path.
        for d in [1.0, 1024.0, 65535.0, 0.5, 1e9, 1234.5678] {
            let direct = difficulty_to_target(Difficulty(d));
            assert_eq!(cache.target_for(d), direct, "diff {d}: memo != uncached");
            // Immediate repeat is served from the slot — still equal.
            assert_eq!(cache.target_for(d), direct, "diff {d}: repeat mismatch");
        }
        // Switching difficulty must recompute (no stale slot), and
        // switching back must still yield the correct target.
        let a = cache.target_for(1024.0);
        let b = cache.target_for(2048.0);
        assert_ne!(a, b, "distinct difficulties must map to distinct targets");
        assert_eq!(
            cache.target_for(1024.0),
            difficulty_to_target(Difficulty(1024.0)),
            "re-selecting a prior difficulty must recompute correctly"
        );
    }

    #[test]
    fn dedup_treats_any_field_change_as_a_new_share() {
        let mut cache = SessionShareCache::new();
        cache.record(&submit("1", "deadbeef"));
        // Each of the 5 fields, when changed, must produce a fresh entry.
        let s2 = SubmitRequest {
            job_id: "2",
            ..submit("1", "deadbeef")
        };
        let s3 = SubmitRequest {
            nonce_hex: "feedface",
            ..submit("1", "deadbeef")
        };
        let s4 = SubmitRequest {
            ntime_hex: "00000001",
            ..submit("1", "deadbeef")
        };
        let s5 = SubmitRequest {
            extranonce2_hex: "ffffffffffffffff",
            ..submit("1", "deadbeef")
        };
        let s6 = SubmitRequest {
            version_mask_hex: "0",
            ..submit("1", "deadbeef")
        };
        for s in [s2, s3, s4, s5, s6] {
            assert!(!cache.record(&s), "expected fresh: {:?}", s);
        }
    }

    #[test]
    fn dedup_clear_resets_the_set() {
        let mut cache = SessionShareCache::new();
        cache.record(&submit("1", "deadbeef"));
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert!(cache.is_empty());
        assert!(!cache.record(&submit("1", "deadbeef")));
    }

    #[test]
    fn dedup_malformed_submit_is_not_recorded() {
        // A submit with an unparseable field can't form an integer key —
        // record() returns false (not a duplicate) and stores nothing;
        // the share is rejected at the parse step regardless.
        let mut cache = SessionShareCache::new();
        let bad = SubmitRequest {
            extranonce2_hex: "xyz", // not valid hex / wrong length
            ..submit("1", "deadbeef")
        };
        assert!(!cache.record(&bad));
        assert!(cache.is_empty());
        // A second identical malformed submit is still "not a duplicate".
        assert!(!cache.record(&bad));
        assert!(cache.is_empty());
    }

    // ── Rejection paths ───────────────────────────────────────────────

    #[test]
    fn rejects_duplicate_share_before_any_other_check() {
        let (reg, jid) = populated_registry(1.0);
        let session = easy_session();
        let mut cache = SessionShareCache::new();
        let s = submit(&jid, "deadbeef");

        // First submit accepted (any hash on session diff 0).
        let v1 = validate_submit(&s, &session, &mut cache, &reg, 1_500);
        assert!(matches!(v1, ShareValidation::Accepted(_)));

        // Second submit with identical fields → duplicate.
        let v2 = validate_submit(&s, &session, &mut cache, &reg, 1_500);
        match v2 {
            ShareValidation::Rejected(r) => assert_eq!(r.reason, RejectReason::DuplicateShare),
            _ => panic!("expected DuplicateShare reject"),
        }
    }

    #[test]
    fn rejects_with_job_not_found_for_unknown_id() {
        let (reg, _jid) = populated_registry(1.0);
        let session = easy_session();
        let mut cache = SessionShareCache::new();
        let v = validate_submit(&submit("deadbeef", "1"), &session, &mut cache, &reg, 1_500);
        match v {
            ShareValidation::Rejected(r) => {
                assert_eq!(r.reason, RejectReason::JobNotFound);
                assert_eq!(r.wire_code, 21);
                assert_eq!(r.wire_message, "Job not found");
            }
            _ => panic!("expected JobNotFound"),
        }
    }

    #[test]
    fn rejects_stale_shares_beyond_grace_window() {
        let (reg, jid) = populated_registry(1.0);
        let session = easy_session();
        let mut cache = SessionShareCache::new();
        // Retire at t=10_000, share arrives well beyond grace (5s default).
        reg.cleanup(true, 10_000);
        let v = validate_submit(&submit(&jid, "1"), &session, &mut cache, &reg, 20_000);
        match v {
            ShareValidation::Rejected(r) => {
                assert_eq!(r.reason, RejectReason::Stale);
                assert_eq!(r.wire_code, 21); // same wire code as JobNotFound
                assert_eq!(r.wire_message, "stale");
            }
            _ => panic!("expected Stale"),
        }
    }

    #[test]
    fn stale_creditable_shares_are_accepted() {
        let (reg, jid) = populated_registry(1.0);
        let session = easy_session();
        let mut cache = SessionShareCache::new();
        // Retire at t=10_000, share within grace window (10_000 + 1s).
        reg.cleanup(true, 10_000);
        let v = validate_submit(&submit(&jid, "1"), &session, &mut cache, &reg, 11_000);
        match v {
            ShareValidation::Accepted(a) => {
                assert_eq!(a.classification, JobClassification::StaleCreditable);
            }
            _ => panic!("expected Accepted/StaleCreditable"),
        }
    }

    #[test]
    fn malformed_extranonce2_hex_rejects_as_low_difficulty() {
        let (reg, jid) = populated_registry(1.0);
        let session = easy_session();
        let mut cache = SessionShareCache::new();
        let mut s = submit(&jid, "1");
        s.extranonce2_hex = "ZZZZ"; // invalid hex
        let v = validate_submit(&s, &session, &mut cache, &reg, 1_500);
        match v {
            ShareValidation::Rejected(r) => assert_eq!(r.reason, RejectReason::LowDifficulty),
            _ => panic!("expected LowDifficulty for malformed hex"),
        }
    }

    #[test]
    fn wrong_extranonce2_byte_length_rejects_as_low_difficulty() {
        let (reg, jid) = populated_registry(1.0);
        let session = easy_session();
        let mut cache = SessionShareCache::new();
        let mut s = submit(&jid, "1");
        s.extranonce2_hex = "112233"; // 3 bytes — must be 8
        let v = validate_submit(&s, &session, &mut cache, &reg, 1_500);
        match v {
            ShareValidation::Rejected(r) => assert_eq!(r.reason, RejectReason::LowDifficulty),
            _ => panic!("expected LowDifficulty for wrong byte length"),
        }
    }

    #[test]
    fn rejects_low_difficulty_when_hash_does_not_meet_target() {
        let (reg, jid) = populated_registry(1.0);
        let session = impossible_session();
        let mut cache = SessionShareCache::new();
        let v = validate_submit(&submit(&jid, "deadbeef"), &session, &mut cache, &reg, 1_500);
        match v {
            ShareValidation::Rejected(r) => {
                assert_eq!(r.reason, RejectReason::LowDifficulty);
                assert_eq!(r.wire_message, "Difficulty too low");
            }
            _ => panic!("expected LowDifficulty"),
        }
    }

    // ── Acceptance paths ──────────────────────────────────────────────

    #[test]
    fn accepts_share_that_meets_easy_target() {
        let (reg, jid) = populated_registry(1.0);
        let session = easy_session();
        let mut cache = SessionShareCache::new();
        let v = validate_submit(&submit(&jid, "deadbeef"), &session, &mut cache, &reg, 1_500);
        match v {
            ShareValidation::Accepted(a) => {
                // session_difficulty=0 → effective_diff=0; the clamp
                // didn't activate because diff_change_job_id is None.
                assert_eq!(a.effective_difficulty, 0.0);
                assert_eq!(a.classification, JobClassification::Active);
                // Hash + submission_difficulty are deterministic given
                // the fixed extranonce/nonce/timestamp; just sanity-check
                // they're populated.
                assert!(a.submission_difficulty >= 0.0);
                assert_eq!(a.hash.len(), 32);
                assert_eq!(a.header.len(), 80);
            }
            _ => panic!("expected Accepted"),
        }
    }

    #[test]
    fn block_candidate_flagged_when_submission_diff_meets_network_diff() {
        // network_difficulty=0 → any non-negative submission_diff is a candidate.
        let (reg, jid) = populated_registry(0.0);
        let session = easy_session();
        let mut cache = SessionShareCache::new();
        let v = validate_submit(&submit(&jid, "deadbeef"), &session, &mut cache, &reg, 1_500);
        match v {
            ShareValidation::Accepted(a) => assert!(a.is_block_candidate),
            _ => panic!("expected Accepted with is_block_candidate=true"),
        }
    }

    #[test]
    fn block_candidate_not_flagged_for_submission_below_network_diff() {
        let (reg, jid) = populated_registry(1.0e30);
        let session = easy_session();
        let mut cache = SessionShareCache::new();
        let v = validate_submit(&submit(&jid, "deadbeef"), &session, &mut cache, &reg, 1_500);
        match v {
            ShareValidation::Accepted(a) => assert!(!a.is_block_candidate),
            _ => panic!("expected Accepted with is_block_candidate=false"),
        }
    }

    // ── Effective-difficulty clamp at validation time ─────────────────

    #[test]
    fn pre_ratchet_share_validates_against_clamped_diff() {
        // Setup: add ONE job (id=1) before the ratchet, then signal a
        // ratchet to id=2 with new_diff=high (impossible to hit) +
        // old_diff=0 (easy). For job_id=1 (< 2) the validator must
        // clamp to MIN(high, 0) = 0 → accepts. Without the clamp this
        // would be a LowDifficulty reject.
        let (reg, jid) = populated_registry(1.0);
        let session = SessionContext {
            extranonce1: &[0x12, 0x34, 0x56, 0x78],
            session_difficulty: 1.0e30,
            old_session_difficulty: 0.0,
            diff_change_job_id: Some(2),
            share_logs: false,
        };
        let mut cache = SessionShareCache::new();
        let v = validate_submit(&submit(&jid, "deadbeef"), &session, &mut cache, &reg, 1_500);
        match v {
            ShareValidation::Accepted(a) => {
                // Clamp activated: effective=MIN(1e30, 0)=0.
                assert_eq!(a.effective_difficulty, 0.0);
            }
            _ => panic!("expected Accepted via clamp; the pre-ratchet share was real work"),
        }
    }

    #[test]
    fn post_ratchet_share_validates_against_current_diff() {
        // Same registry, but session says boundary=jobId 1 → job_id 1
        // is "at or after" the boundary (current diff applies). With
        // session=1e30 the share fails the target check → LowDifficulty.
        let (reg, jid) = populated_registry(1.0);
        let session = SessionContext {
            extranonce1: &[0x12, 0x34, 0x56, 0x78],
            session_difficulty: 1.0e30,
            old_session_difficulty: 0.0,
            diff_change_job_id: Some(1),
            share_logs: false,
        };
        let mut cache = SessionShareCache::new();
        let v = validate_submit(&submit(&jid, "deadbeef"), &session, &mut cache, &reg, 1_500);
        match v {
            ShareValidation::Rejected(r) => assert_eq!(r.reason, RejectReason::LowDifficulty),
            _ => panic!("expected LowDifficulty (no clamp, hit impossible target)"),
        }
    }
}
