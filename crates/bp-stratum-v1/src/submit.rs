// SPDX-License-Identifier: AGPL-3.0-or-later

//! Share validation for `mining.submit`: pure logic against the session state and
//! the shared [`JobRegistry`], no I/O. Share accounting is the caller's job.

use std::sync::Arc;

use bitcoin::hex::DisplayHex;
use bp_jobs_lifecycle::{SeenShareRefusal, SeenShares, MAX_SEEN_SHARES_PER_TIP};
use bp_mining_job::{build_block_header, meets_network_target, merkle_root_from_coinbase};
use bp_share::{calculate_difficulty, Difficulty, TargetMemo};

use crate::frame::{
    SubmitRequest, ERR_DUPLICATE_SHARE, ERR_JOB_NOT_FOUND, ERR_LOW_DIFFICULTY_SHARE,
    ERR_OTHER_UNKNOWN, REJECT_DUPLICATE, REJECT_JOB_NOT_FOUND, REJECT_LOW_DIFF, REJECT_STALE,
    REJECT_VERSION_ROLLING,
};
use crate::jobs::{JobClassification, JobRegistry};
use crate::notify::ActiveSV1Template;
use bp_mining_job::MiningJob;
use bp_vardiff::effective_job_difficulty;

// ── Reject classification ────────────────────────────────────────────

/// Wire-visible reject reasons. `Stale` shares the wire code with `JobNotFound`
/// (SV1 has no stale code) but keeps its own message and counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RejectReason {
    DuplicateShare,
    JobNotFound,
    Stale,
    LowDifficulty,
    /// Version bits changed outside the negotiated mask, which BIP-310 says the
    /// server rejects. No dedicated SV1 code, so it goes out as [`ERR_OTHER_UNKNOWN`].
    VersionRollingNotAllowed,
}

impl RejectReason {
    /// JSON-RPC `error[0]` numeric code on the wire.
    pub(crate) fn wire_code(self) -> i64 {
        match self {
            RejectReason::DuplicateShare => ERR_DUPLICATE_SHARE,
            RejectReason::JobNotFound | RejectReason::Stale => ERR_JOB_NOT_FOUND,
            RejectReason::LowDifficulty => ERR_LOW_DIFFICULTY_SHARE,
            RejectReason::VersionRollingNotAllowed => ERR_OTHER_UNKNOWN,
        }
    }

    /// JSON-RPC `error[1]`. Monitoring tooling parses these; do not paraphrase.
    pub(crate) fn wire_message(self) -> &'static str {
        match self {
            RejectReason::DuplicateShare => REJECT_DUPLICATE,
            RejectReason::JobNotFound => REJECT_JOB_NOT_FOUND,
            RejectReason::Stale => REJECT_STALE,
            RejectReason::LowDifficulty => REJECT_LOW_DIFF,
            RejectReason::VersionRollingNotAllowed => REJECT_VERSION_ROLLING,
        }
    }
}

// ── Validation result ────────────────────────────────────────────────

/// Accepted share, with what the block-found path needs to rebuild the coinbase
/// and submit the solution.
#[derive(Clone, Debug)]
pub struct ShareAccept {
    /// `Active` or `StaleCreditable`; both are credited.
    pub classification: JobClassification,
    /// Difficulty the share is credited at: the ratchet-clamped value, which can be
    /// below the current session diff for work issued before a vardiff ratchet.
    pub effective_difficulty: f64,
    /// Difficulty the hash actually reached; drives best-diff.
    pub submission_difficulty: f64,
    pub header: [u8; 80],
    pub hash: [u8; 32],
    /// Hash meets the template's network target. bitcoind stays the authoritative
    /// validator; this only triggers the submit path.
    pub is_block_candidate: bool,
    pub mining_job: Arc<MiningJob>,
    pub template: Arc<ActiveSV1Template>,
    pub enonce1: [u8; 4],
    pub extranonce2: [u8; 8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ShareReject {
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
pub(crate) enum ShareValidation {
    Accepted(Box<ShareAccept>),
    Rejected(ShareReject),
}

// ── Per-session state passed into the validator ──────────────────────

/// Per-session inputs to [`validate_submit`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionContext<'a> {
    pub extranonce1: &'a [u8; 4],
    pub session_difficulty: f64,
    /// Difficulty before the last vardiff ratchet.
    pub old_session_difficulty: f64,
    /// Jobs allocated before this id were issued at `old_session_difficulty`.
    pub diff_change_job_id: Option<u64>,
    /// Gates the per-share debug traces; rejections always log.
    pub share_logs: bool,
    /// BIP-310 `last_mask`: the pool's advertised mask until `mining.configure`
    /// narrows it (see `SessionState::version_rolling_mask` for why not zero).
    pub version_rolling_mask: u32,
}

// ── Duplicate-share cache (per session) ──────────────────────────────

/// Per-session share state: the duplicate guard and the target memo.
#[derive(Default)]
pub(crate) struct SessionShareCache {
    /// Header hashes of accepted shares; [`SeenShares::on_tip`] is driven by
    /// every new template, so a tip's hashes outlive its creditable jobs.
    pub(crate) seen: SeenShares,
    /// Effective difficulty takes at most two values per session (current vs
    /// ratchet-clamped), so memoizing the target pays off.
    target_memo: TargetMemo,
}

impl SessionShareCache {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

// ── validate_submit ──────────────────────────────────────────────────

/// Checks run cheapest first: job lookup, stale, field parse, version mask, the
/// duplicate guard on the header hash, then that hash against the
/// [`effective_job_difficulty`] target. Only an accepted share is recorded.
/// Malformed fields reject as `LowDifficulty`, the same end state as a garbled header.
pub(crate) fn validate_submit(
    submit: &SubmitRequest,
    session: &SessionContext<'_>,
    dedup: &mut SessionShareCache,
    registry: &JobRegistry,
    now_ms: u64,
) -> ShareValidation {
    // Registry classify.
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

    let Some((version_bits, nonce, ntime, extranonce2)) = parse_submit_fields(submit) else {
        tracing::warn!(
            worker = %submit.worker,
            job_id = %submit.job_id,
            "❌ Share rejected: malformed-fields (nonce/ntime/version-mask/extranonce2 parse failed)"
        );
        return ShareValidation::Rejected(RejectReason::LowDifficulty.into());
    };

    // BIP-310: `version_bits & ~last_mask` must be zero, else the server rejects.
    // A non-rolling miner sends zero, which passes under every mask.
    let last_mask = session.version_rolling_mask;
    if version_bits & !last_mask != 0 {
        tracing::warn!(
            worker = %submit.worker,
            job_id = %submit.job_id,
            version_bits = format_args!("0x{version_bits:08x}"),
            last_mask = format_args!("0x{last_mask:08x}"),
            "❌ Share rejected: version-rolling-not-allowed (bits outside the negotiated mask)"
        );
        return ShareValidation::Rejected(RejectReason::VersionRollingNotAllowed.into());
    }

    // XOR, not BIP-310's `(job_version & ~mask) | (bits & mask)`: that clears a
    // template bit signalling inside the mask when a miner rolls nothing, so the
    // pool would hash a header it never published and reject every share.
    let n_version = lookup.template.version ^ version_bits;
    let coinbase_hash = lookup
        .mining_job
        .coinbase_txid_with_extranonce(session.extranonce1, &extranonce2);
    let merkle_root = merkle_root_from_coinbase(&coinbase_hash, &lookup.template.merkle_path);
    let header = build_block_header(
        n_version as i32,
        &lookup.template.prev_hash,
        &merkle_root,
        ntime,
        lookup.template.n_bits,
        nonce,
    );
    let scored = calculate_difficulty(&header);
    let submission_difficulty = scored.submission_difficulty.as_f64();
    let hash = scored.submission_hash;

    if let Err(refusal) = dedup.seen.check(&lookup.template.prev_hash, &hash) {
        match refusal {
            SeenShareRefusal::Duplicate => {
                tracing::warn!(
                    worker = %submit.worker,
                    job_id = %submit.job_id,
                    "❌ Share rejected: duplicate-share"
                );
            }
            // Not the miner's fault, but no other code fits and the share
            // must not be credited.
            SeenShareRefusal::Full => {
                tracing::warn!(
                    worker = %submit.worker,
                    job_id = %submit.job_id,
                    "❌ Share rejected: this tip's duplicate guard is full ({} accepted shares), \
                     so no further share on it can be checked; refused as duplicate-share",
                    MAX_SEEN_SHARES_PER_TIP
                );
            }
        }
        return ShareValidation::Rejected(RejectReason::DuplicateShare.into());
    }

    let job_id_int = u64::from_str_radix(submit.job_id, 16).ok();
    let effective_diff = effective_job_difficulty(
        job_id_int,
        session.session_difficulty,
        session.old_session_difficulty,
        session.diff_change_job_id,
    );
    let effective_target = dedup.target_memo.target_for(Difficulty(effective_diff));

    // DEBUG level, so it also needs `RUST_LOG=...,bp_stratum_v1=debug`.
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
        // `hash_prefix_be` is for cross-checking against the miner's own trace.
        tracing::warn!(
            worker = %submit.worker,
            job_id = %submit.job_id,
            nonce = format_args!("0x{:08x}", nonce),
            extranonce2 = %extranonce2.as_hex(),
            hash_prefix_be = %hash[..8].as_hex(),
            "❌ Share rejected: difficulty-too-low (submitted={:.2} < effective={:.2})",
            submission_difficulty,
            effective_diff
        );
        return ShareValidation::Rejected(RejectReason::LowDifficulty.into());
    }

    dedup.seen.record(lookup.template.prev_hash, hash);

    // Against the network target, independent of the clamped share diff: a
    // stale-creditable hit during a reorg can still find a valid alternative tip.
    let is_block_candidate = meets_network_target(&hash, lookup.template.n_bits);
    if is_block_candidate {
        tracing::info!(
            worker = %submit.worker,
            job_id = %submit.job_id,
            template_id = lookup.template.template_id,
            n_bits = format_args!("{:#010x}", lookup.template.n_bits),
            "🎉🎉🎉 !!! BLOCK FOUND !!! (SV1) — submission_diff={:.2}",
            submission_difficulty
        );
    } else if session.share_logs {
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

fn parse_submit_fields(submit: &SubmitRequest) -> Option<(u32, u32, u32, [u8; 8])> {
    let version_mask = u32::from_str_radix(submit.version_mask_hex, 16).ok()?;
    let nonce = u32::from_str_radix(submit.nonce_hex, 16).ok()?;
    let ntime = u32::from_str_radix(submit.ntime_hex, 16).ok()?;
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
    /// Pins that the reject log's `as_hex()` matches per-byte `{b:02x}` formatting.
    #[test]
    fn reject_log_hex_matches_the_per_byte_format() {
        use bitcoin::hex::DisplayHex;
        let hash: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37));
        let old: String = hash[..8].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hash[..8].as_hex().to_string(), old);
        let en2 = [0x00u8, 0x0a, 0xff, 0xde, 0xad, 0xbe, 0xef, 0x01];
        assert_eq!(en2.as_hex().to_string(), "000affdeadbeef01");
    }

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

    /// Difficulty 1 — out of reach for the synthetic shares below.
    const DIFF_ONE_N_BITS: u32 = 0x1d00_ffff;
    /// Target `0xffff·2^240`: met by every hash except the top 2^-16.
    const TRIVIAL_N_BITS: u32 = 0x2100_ffff;
    /// Target 1: met by no real hash.
    const IMPOSSIBLE_N_BITS: u32 = 0x0300_0001;

    fn template_with_n_bits(n_bits: u32) -> ActiveSV1Template {
        ActiveSV1Template::from_template(bp_template_distribution::ActiveTemplate {
            template_id: 1,
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            n_bits,
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

    fn populated_registry(n_bits: u32) -> (JobRegistry, String) {
        let reg = JobRegistry::from_server_config(&server_config());
        let active = template_with_n_bits(n_bits);
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
            version_rolling_mask: crate::config::VERSION_ROLLING_MASK,
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
            version_rolling_mask: crate::config::VERSION_ROLLING_MASK,
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

    // ── Rejection paths ───────────────────────────────────────────────

    // ── BIP-310 version rolling ───────────────────────────────────────

    /// Build a submit that rolls exactly `version_bits`.
    fn submit_rolling<'a>(job_id_hex: &'a str, version_bits_hex: &'a str) -> SubmitRequest<'a> {
        SubmitRequest {
            id: RpcId::from(1),
            worker: "addr.w".into(),
            job_id: job_id_hex,
            extranonce2_hex: "1122334455667788",
            ntime_hex: "65a1b2c3",
            nonce_hex: "deadbeef",
            version_mask_hex: version_bits_hex,
        }
    }

    /// Pins BIP-310's reject of bits outside the mask, with the inside case as control.
    #[test]
    fn bits_outside_the_negotiated_mask_are_rejected() {
        let (reg, jid) = populated_registry(DIFF_ONE_N_BITS);
        let session = easy_session(); // negotiated 0x1fffe000
        let mut cache = SessionShareCache::new();

        // Inside the mask -> accepted, at session diff 0 any hash passes.
        let inside = validate_submit(
            &submit_rolling(&jid, "1fffe000"),
            &session,
            &mut cache,
            &reg,
            1_500,
        );
        assert!(
            matches!(inside, ShareValidation::Accepted(_)),
            "rolling within the negotiated mask must still be accepted"
        );

        // One bit outside -> rejected. 0x00000001 is a signalling bit the
        // pool never grants.
        let outside = validate_submit(
            &submit_rolling(&jid, "00000001"),
            &session,
            &mut cache,
            &reg,
            1_500,
        );
        match outside {
            ShareValidation::Rejected(r) => {
                assert_eq!(r.reason, RejectReason::VersionRollingNotAllowed)
            }
            _ => panic!("a bit outside the negotiated mask must be rejected"),
        }
    }

    /// Pins that a miner is held to the narrowed mask it was answered with.
    #[test]
    fn a_negotiated_subset_is_what_the_miner_is_held_to() {
        let (reg, jid) = populated_registry(DIFF_ONE_N_BITS);
        let session = SessionContext {
            // What `handle_configure` stores after the miner asked for a
            // subset of the pool's mask.
            version_rolling_mask: 0x00c0_0000,
            ..easy_session()
        };
        let mut cache = SessionShareCache::new();

        let inside = validate_submit(
            &submit_rolling(&jid, "00c00000"),
            &session,
            &mut cache,
            &reg,
            1_500,
        );
        assert!(matches!(inside, ShareValidation::Accepted(_)));

        // Inside the pool's mask but outside the session's.
        let outside = validate_submit(
            &submit_rolling(&jid, "00002000"),
            &session,
            &mut cache,
            &reg,
            1_500,
        );
        assert!(matches!(
            outside,
            ShareValidation::Rejected(ShareReject {
                reason: RejectReason::VersionRollingNotAllowed,
                ..
            })
        ));
    }

    /// Pins that a non-rolling miner hashes the template's version even when it
    /// signals inside the mask (BIP-310's masked OR would fail this).
    #[test]
    fn a_non_rolling_miner_keeps_the_templates_in_mask_bits() {
        // Template signalling on bit 28, as core's regtest does once
        // `testdummy` is STARTED. Bit 28 is inside the advertised mask.
        const DIRTY_TEMPLATE: u32 = 0x3000_0000;
        assert_ne!(
            DIRTY_TEMPLATE & crate::config::VERSION_ROLLING_MASK,
            0,
            "precondition: the template sets a bit the miner is allowed to roll"
        );

        let reg = JobRegistry::from_server_config(&server_config());
        let mut active = template_with_n_bits(DIFF_ONE_N_BITS);
        active.template.version = DIRTY_TEMPLATE;
        active.recompute_notify_header_hex();
        let tid = reg.add_template(active.clone(), 1_000);
        let jid = reg.add_job(mining_job_from(&active), tid, 1_000);

        let session = easy_session();
        let mut cache = SessionShareCache::new();
        let accept = match validate_submit(
            &submit_rolling(&jid, "00000000"),
            &session,
            &mut cache,
            &reg,
            1_500,
        ) {
            ShareValidation::Accepted(a) => a,
            other => panic!("a non-rolling share must be accepted, got {other:?}"),
        };

        let built = u32::from_le_bytes(accept.header[0..4].try_into().unwrap());
        assert_eq!(
            built,
            DIRTY_TEMPLATE,
            "the pool must hash the version it published; BIP-310's masked OR \
             would give 0x{:08x} here",
            DIRTY_TEMPLATE & !crate::config::VERSION_ROLLING_MASK
        );

        // Negative control: rolling still moves the version.
        let rolled = match validate_submit(
            &submit_rolling(&jid, "00002000"),
            &session,
            &mut cache,
            &reg,
            1_500,
        ) {
            ShareValidation::Accepted(a) => a,
            other => panic!("rolling inside the mask must be accepted, got {other:?}"),
        };
        assert_eq!(
            u32::from_le_bytes(rolled.header[0..4].try_into().unwrap()),
            DIRTY_TEMPLATE ^ 0x0000_2000
        );
    }

    #[test]
    fn rejects_duplicate_share() {
        let (reg, jid) = populated_registry(DIFF_ONE_N_BITS);
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
        let (reg, _jid) = populated_registry(DIFF_ONE_N_BITS);
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
        let (reg, jid) = populated_registry(DIFF_ONE_N_BITS);
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

    /// Replay across a block change: the old job stays creditable for
    /// `grace_ms`, so its accepted shares must stay duplicates. The control
    /// shows the same share is creditable to a session that never saw it.
    #[test]
    fn replay_after_block_change_is_a_duplicate() {
        let (reg, jid) = populated_registry(DIFF_ONE_N_BITS);
        let session = easy_session();
        let mut cache = SessionShareCache::new();
        let s = submit(&jid, "deadbeef");
        let first = validate_submit(&s, &session, &mut cache, &reg, 1_500);
        assert!(matches!(first, ShareValidation::Accepted(_)));

        let mut new_tip = reg.classify(&jid, 1_500).unwrap().template.prev_hash;
        new_tip[0] ^= 0xFF;
        reg.cleanup_for_tip(&new_tip, 10_000);
        cache.seen.on_tip(&new_tip, 10_000, &reg.config());
        let replay = validate_submit(&s, &session, &mut cache, &reg, 11_000);
        match replay {
            ShareValidation::Rejected(r) => assert_eq!(r.reason, RejectReason::DuplicateShare),
            ShareValidation::Accepted(_) => panic!("replayed share credited twice"),
        }

        let control = validate_submit(&s, &session, &mut SessionShareCache::new(), &reg, 11_000);
        match control {
            ShareValidation::Accepted(a) => {
                assert_eq!(a.classification, JobClassification::StaleCreditable)
            }
            ShareValidation::Rejected(r) => panic!("control must be creditable, got {r:?}"),
        }
    }

    #[test]
    fn stale_creditable_shares_are_accepted() {
        let (reg, jid) = populated_registry(DIFF_ONE_N_BITS);
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
        let (reg, jid) = populated_registry(DIFF_ONE_N_BITS);
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
        let (reg, jid) = populated_registry(DIFF_ONE_N_BITS);
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
        let (reg, jid) = populated_registry(DIFF_ONE_N_BITS);
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
        let (reg, jid) = populated_registry(DIFF_ONE_N_BITS);
        let session = easy_session();
        let mut cache = SessionShareCache::new();
        let v = validate_submit(&submit(&jid, "deadbeef"), &session, &mut cache, &reg, 1_500);
        match v {
            ShareValidation::Accepted(a) => {
                assert_eq!(a.effective_difficulty, 0.0);
                assert_eq!(a.classification, JobClassification::Active);
                assert!(a.submission_difficulty >= 0.0);
                assert_eq!(a.hash.len(), 32);
                assert_eq!(a.header.len(), 80);
            }
            _ => panic!("expected Accepted"),
        }
    }

    #[test]
    fn block_candidate_flagged_when_the_hash_meets_the_network_target() {
        let (reg, jid) = populated_registry(TRIVIAL_N_BITS);
        let session = easy_session();
        let mut cache = SessionShareCache::new();
        let v = validate_submit(&submit(&jid, "deadbeef"), &session, &mut cache, &reg, 1_500);
        match v {
            ShareValidation::Accepted(a) => assert!(a.is_block_candidate),
            _ => panic!("expected Accepted with is_block_candidate=true"),
        }
    }

    #[test]
    fn block_candidate_not_flagged_when_the_hash_misses_the_network_target() {
        let (reg, jid) = populated_registry(IMPOSSIBLE_N_BITS);
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
        // Job 1 predates the ratchet at id 2, so it is clamped to the old diff 0;
        // without the clamp this would be a LowDifficulty reject.
        let (reg, jid) = populated_registry(DIFF_ONE_N_BITS);
        let session = SessionContext {
            extranonce1: &[0x12, 0x34, 0x56, 0x78],
            session_difficulty: 1.0e30,
            old_session_difficulty: 0.0,
            version_rolling_mask: crate::config::VERSION_ROLLING_MASK,
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
        // Job 1 is at the ratchet boundary, so the impossible current diff applies.
        let (reg, jid) = populated_registry(DIFF_ONE_N_BITS);
        let session = SessionContext {
            extranonce1: &[0x12, 0x34, 0x56, 0x78],
            session_difficulty: 1.0e30,
            old_session_difficulty: 0.0,
            version_rolling_mask: crate::config::VERSION_ROLLING_MASK,
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
