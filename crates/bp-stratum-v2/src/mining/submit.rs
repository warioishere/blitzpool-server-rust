// SPDX-License-Identifier: AGPL-3.0-or-later

//! Share validation for Standard and Extended SV2 mining channels.
//! Pure logic, no I/O: per-share side effects (payout accounting,
//! accumulators, block-found bookkeeping) are the caller's job, behind the
//! [`crate::hooks`] trait boundaries.

use bp_jobs_lifecycle::JobClassification;
use bp_mining_job::{
    assemble_witness_coinbase, build_block_header, meets_network_target, merkle_root_from_coinbase,
};
use bp_share::{calculate_difficulty, sha256d_from_parts, Difficulty, Target};
use smallvec::SmallVec;

/// Per-share `extranonce` buffer: 16 inline bytes cover the negotiated
/// sizes without a heap allocation per share.
pub type ExtranonceBytes = SmallVec<[u8; 16]>;

use super::channel::{ChannelKind, ChannelState};
use super::jobs::{classify_extended_job, ExtendedJob};
use bp_jobs_lifecycle::{LifecycleConfig, SeenShareRefusal, SeenShares};

// ── Wire codes (SV2 mining-protocol error strings) ───────────────────

pub const ERR_INVALID_CHANNEL_ID: &str = "invalid-channel-id";

/// Job id unknown (past retention GC, or never sent), as opposed to
/// `stale-share`, where the job was known and since superseded.
pub const ERR_INVALID_JOB_ID: &str = "invalid-job-id";

/// Job retired past [`bp_jobs_lifecycle::LifecycleConfig::grace_ms`].
pub const ERR_STALE_SHARE: &str = "stale-share";

/// A header hash already accepted, or a share refused because its tip's
/// [`SeenShares`] set is full ([`SeenShareRefusal::Full`]). None of these
/// codes is spec-assigned: SV2 Overview/Error Codes lets the list differ
/// between implementations and a receiver MUST log-no-op on unknown codes.
pub const ERR_DUPLICATE_SHARE: &str = "duplicate-share";

pub const ERR_DIFFICULTY_TOO_LOW: &str = "difficulty-too-low";

/// Hard reject: with a different extranonce size the reconstructed coinbase
/// is not what the miner hashed, so the credited work would be unverified.
pub const ERR_BAD_EXTRANONCE_SIZE: &str = "bad-extranonce-size";

// ── Reject reasons ───────────────────────────────────────────────────

/// Internal classification of a rejected share, mapped to its wire code by
/// [`Self::wire_code`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    InvalidJobId,
    /// Distinct from [`Self::DuplicateShare`] so the stats fan-out can
    /// bucket them separately.
    StaleShare,
    DuplicateShare,
    DifficultyTooLow,
    /// Extended-channel only; see [`ERR_BAD_EXTRANONCE_SIZE`].
    BadExtranonceSize,
}

impl RejectReason {
    pub fn wire_code(self) -> &'static str {
        match self {
            RejectReason::InvalidJobId => ERR_INVALID_JOB_ID,
            RejectReason::StaleShare => ERR_STALE_SHARE,
            RejectReason::DuplicateShare => ERR_DUPLICATE_SHARE,
            RejectReason::DifficultyTooLow => ERR_DIFFICULTY_TOO_LOW,
            RejectReason::BadExtranonceSize => ERR_BAD_EXTRANONCE_SIZE,
        }
    }
}

// ── Validation result ────────────────────────────────────────────────

/// Successful validation: what the caller needs for the success frame, the
/// share-stats fan-out and, for a block candidate, `SubmitSolution`.
#[derive(Clone, Debug)]
pub struct ShareAccept {
    /// `Active` or `StaleCreditable`. Both credit the share.
    pub classification: JobClassification,
    /// Difficulty the share is credited at: the job's difficulty pinned at
    /// send-time (SV2 Mining/SubmitShares.Error), which may be below the
    /// session's current difficulty after a vardiff increase.
    pub effective_difficulty: Difficulty,
    /// Difficulty the hash actually reached; drives the block-found gate and
    /// the personal-best tracker.
    pub submission_difficulty: Difficulty,
    pub header: [u8; 80],
    /// `sha256d(header)` in LE byte order.
    pub hash: [u8; 32],
    /// Hash meets the job's network target. bitcoind stays the authoritative
    /// validator; this only triggers `TdpHandle::submit_solution`.
    pub is_block_candidate: bool,
    /// `None` for `SetCustomMiningJob`-declared jobs (no pool-side template).
    pub template_id: Option<u64>,
    /// See [`crate::mining::jobs::ExtendedJob::jdp_claims_the_block`];
    /// always `false` on the Standard path, which has no custom jobs.
    pub jdp_claims_the_block: bool,
    /// Payout list the job's coinbase pays, so the ledger books what this
    /// block actually paid rather than whatever the snapshot key holds by
    /// then. Zeroed when the pool did not build the coinbase.
    pub payouts_fingerprint: [u8; 32],
    /// BIP-141 coinbase for `submit_solution`, built only for block
    /// candidates. Empty for a `SetCustomMiningJob` job, which carries no
    /// pool-side coinbase.
    pub witness_coinbase: Vec<u8>,
    /// Worker named by a valid ext 0x0002 Worker-ID TLV; `None` means the
    /// channel's `user_identity`. Without ext 0x0002 the TLVs are ignored
    /// (ext 0x0002/Behavior Based on Negotiation).
    pub effective_worker_name: Option<String>,
    /// The job's pinned block-reward portion for the ledger. `0` for
    /// `SetCustomMiningJob` jobs, whose accounting the JDC owns.
    pub coinbase_tx_value_remaining: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareReject {
    pub reason: RejectReason,
    pub wire_code: &'static str,
}

impl From<RejectReason> for ShareReject {
    fn from(reason: RejectReason) -> Self {
        Self {
            reason,
            wire_code: reason.wire_code(),
        }
    }
}

/// Outcome of [`validate_submit_standard`] / [`validate_submit_extended`].
#[derive(Clone, Debug)]
pub enum ShareValidation {
    Accepted(Box<ShareAccept>),
    Rejected(ShareReject),
}

// ── Submit-frame inputs ──────────────────────────────────────────────

/// The `SubmitSharesStandard` fields the validator reads, decoupled from
/// `stratum_core::mining_sv2`'s lifetimes.
#[derive(Clone, Copy, Debug)]
pub struct SubmitSharesStandardInput {
    pub channel_id: u32,
    pub sequence_number: u32,
    pub job_id: u32,
    pub nonce: u32,
    pub version: u32,
    pub ntime: u32,
}

#[derive(Clone, Debug)]
pub struct SubmitSharesExtendedInput {
    pub channel_id: u32,
    pub sequence_number: u32,
    pub job_id: u32,
    pub nonce: u32,
    pub version: u32,
    pub ntime: u32,
    pub extranonce: ExtranonceBytes,
    /// TLVs after the base payload, resolved into
    /// [`ShareAccept::effective_worker_name`] via
    /// [`crate::extensions::resolve_share_worker_name_from_tlv`].
    pub tlvs: Vec<stratum_core::parsers_sv2::Tlv>,
}

// ── Standard-channel job context ─────────────────────────────────────

/// Per-job context for the Standard validator, resolved by the caller so
/// the validator stays pure.
#[derive(Clone, Copy, Debug)]
pub struct StandardJobContext<'a> {
    pub template_version: i32,
    pub prev_hash: [u8; 32],
    /// Encodes the network target the block-found gate checks.
    pub n_bits: u32,
    pub classification: JobClassification,
    /// `None` for `SetCustomMiningJob`-derived jobs.
    pub template_id: Option<u64>,
    /// Non-witness coinbase matching the merkle root the miner hashed, from
    /// [`crate::mining::jobs::StandardJobEntry::coinbase_stratum`]. Empty for
    /// a `SetCustomMiningJob`-declared job.
    pub coinbase_stratum: &'a [u8],
    /// See `ShareAccept::payouts_fingerprint`.
    pub payouts_fingerprint: [u8; 32],
    pub coinbase_tx_value_remaining: u64,
}

// ── Standard validation ──────────────────────────────────────────────

/// The caller resolves the channel and the job from
/// [`crate::mining::jobs::StandardJobMaps`]. Duplicates are judged by the
/// header hash (see [`SeenShares`]), and only an accepted share is recorded.
pub fn validate_submit_standard(
    channel: &mut ChannelState,
    submission: &SubmitSharesStandardInput,
    job_difficulty: Difficulty,
    stored_merkle_root: &[u8; 32],
    job_ctx: &StandardJobContext<'_>,
) -> ShareValidation {
    if channel.kind != ChannelKind::Standard {
        // A call-site error, not a wire-protocol one; rejecting keeps the
        // connection running.
        return ShareValidation::Rejected(RejectReason::InvalidJobId.into());
    }

    if job_ctx.classification == JobClassification::StaleRejected {
        return ShareValidation::Rejected(RejectReason::StaleShare.into());
    }

    // SV2 submits the "Full nVersion field", so it goes into the header as-is.
    let header = build_block_header(
        submission.version as i32,
        &job_ctx.prev_hash,
        stored_merkle_root,
        submission.ntime,
        job_ctx.n_bits,
        submission.nonce,
    );

    let pow = calculate_difficulty(&header);
    if let Err(refusal) = channel
        .seen_shares
        .check(&job_ctx.prev_hash, &pow.submission_hash)
    {
        return refuse_seen_share(refusal, submission.channel_id, submission.job_id);
    }
    let job_target = channel.target_for(job_difficulty);
    if !job_target.is_met_by_le(&pow.submission_hash) {
        return ShareValidation::Rejected(RejectReason::DifficultyTooLow.into());
    }

    channel
        .seen_shares
        .record(job_ctx.prev_hash, pow.submission_hash);

    let is_block_candidate = meets_network_target(&pow.submission_hash, job_ctx.n_bits);
    // An empty `coinbase_stratum` (a `SetCustomMiningJob` job) yields no
    // coinbase rather than malformed bytes for bitcoind.
    let witness_coinbase = if is_block_candidate && !job_ctx.coinbase_stratum.is_empty() {
        assemble_witness_coinbase(job_ctx.coinbase_stratum)
    } else {
        Vec::new()
    };
    ShareValidation::Accepted(Box::new(ShareAccept {
        classification: job_ctx.classification,
        effective_difficulty: job_difficulty,
        submission_difficulty: pow.submission_difficulty,
        header,
        hash: pow.submission_hash,
        is_block_candidate,
        template_id: job_ctx.template_id,
        jdp_claims_the_block: false,
        payouts_fingerprint: job_ctx.payouts_fingerprint,
        witness_coinbase,
        effective_worker_name: None,
        coinbase_tx_value_remaining: job_ctx.coinbase_tx_value_remaining,
    }))
}

// ── Extended validation ──────────────────────────────────────────────

/// Read-only projection of the channel for the extended validator. A view
/// instead of `&mut ChannelState` lets the caller lend only the
/// [`SeenShares`] mutably while borrowing the `ExtendedJob` from the same
/// channel, so the job is not cloned per share.
#[derive(Clone, Copy, Debug)]
pub struct ExtendedChannelView {
    pub kind: ChannelKind,
    pub extranonce_size: u8,
    /// Precomputed via [`ChannelState::target_for`], so the validator needs
    /// no `&mut` access to the channel's memo.
    pub job_target: Target,
    pub job_lifecycle: LifecycleConfig,
}

/// Validates against the resolved [`ExtendedJob`] by rebuilding the coinbase
/// and walking the merkle path. Both the share target and the network target
/// come from the job as pinned at send-time (SV2 Mining/SubmitShares.Error),
/// so a block change between send and submit cannot reclassify the share.
#[allow(clippy::too_many_arguments)]
pub fn validate_submit_extended(
    seen_shares: &mut SeenShares,
    view: &ExtendedChannelView,
    submission: &SubmitSharesExtendedInput,
    ext_job: &ExtendedJob,
    job_difficulty: Difficulty,
    now_ms: u64,
    ext_0x0002_negotiated: bool,
    debug_share_logs: bool,
) -> ShareValidation {
    if view.kind != ChannelKind::Extended {
        tracing::warn!(
            channel_id = submission.channel_id,
            "❌ Extended share rejected: invalid-channel-id {}",
            submission.channel_id
        );
        return ShareValidation::Rejected(RejectReason::InvalidJobId.into());
    }

    let classification = classify_extended_job(ext_job, now_ms, &view.job_lifecycle);
    if classification == JobClassification::StaleRejected {
        let retired_ago_ms = ext_job
            .retired_at
            .map(|r| now_ms.saturating_sub(r))
            .unwrap_or(0);
        tracing::warn!(
            channel_id = submission.channel_id,
            job_id = submission.job_id,
            retired_ago_ms,
            "❌ Extended share rejected: stale-share (jobId={}, retired {}ms ago)",
            submission.job_id,
            retired_ago_ms
        );
        return ShareValidation::Rejected(RejectReason::StaleShare.into());
    }

    if submission.extranonce.len() != view.extranonce_size as usize {
        tracing::warn!(
            channel_id = submission.channel_id,
            got = submission.extranonce.len(),
            expected = view.extranonce_size,
            "⚠️  Extranonce size mismatch: got={}, expected={} — share rejected (bad-extranonce-size)",
            submission.extranonce.len(),
            view.extranonce_size
        );
        return ShareValidation::Rejected(RejectReason::BadExtranonceSize.into());
    }

    // The extranonce prefix is read off the JOB, never off the channel:
    // SV2 Mining/SetExtranoncePrefix is effective only from the next job on,
    // so a share for an older job was built with that job's prefix.
    let coinbase_parts: [&[u8]; 4] = [
        &ext_job.coinbase_prefix[..],
        &ext_job.extranonce_prefix[..],
        &submission.extranonce[..],
        &ext_job.coinbase_suffix[..],
    ];

    // Streamed into the hasher so the hot path never allocates the full
    // coinbase; it is concatenated only in the cold branches below.
    let coinbase_txid = sha256d_from_parts(&coinbase_parts);

    let merkle_root = merkle_root_from_coinbase(&coinbase_txid, &ext_job.merkle_path);

    // SV2 submits the full nVersion, so it goes in verbatim.
    let header = build_block_header(
        submission.version as i32,
        &ext_job.prev_hash,
        &merkle_root,
        submission.ntime,
        ext_job.n_bits,
        submission.nonce,
    );

    let pow = calculate_difficulty(&header);
    if let Err(refusal) = seen_shares.check(&ext_job.prev_hash, &pow.submission_hash) {
        return refuse_seen_share(refusal, submission.channel_id, submission.job_id);
    }
    let job_target = view.job_target;

    // Needs both `stratum_share_logs` and `RUST_LOG=...,bp_stratum_v2=debug`.
    if debug_share_logs {
        tracing::debug!(
            channel_id = submission.channel_id,
            job_id = submission.job_id,
            "🎯 Extended share difficulty: {:.2} (target: {:.2})",
            pow.submission_difficulty.as_f64(),
            job_difficulty.as_f64()
        );
    }

    if !job_target.is_met_by_le(&pow.submission_hash) {
        // Full byte dump (coinbase, merkle root, header) so the hashed bytes
        // can be compared with what the miner built from the
        // NewExtendedMiningJob frame without instrumenting the miner.
        let to_hex = |b: &[u8]| -> String {
            let mut s = String::with_capacity(b.len() * 2);
            for x in b {
                s.push_str(&format!("{x:02x}"));
            }
            s
        };
        let hash_prefix = to_hex(&pow.submission_hash[..8]);
        let coinbase_hex = to_hex(&coinbase_parts.concat());
        let merkle_root_hex = to_hex(&merkle_root);
        let header_hex = to_hex(&header);
        let prefix_hex = to_hex(&ext_job.coinbase_prefix);
        let suffix_hex = to_hex(&ext_job.coinbase_suffix);
        let ext_hex = to_hex(submission.extranonce.as_slice());
        tracing::warn!(
            channel_id = submission.channel_id,
            job_id = submission.job_id,
            nonce = format_args!("0x{:08x}", submission.nonce),
            ntime = submission.ntime,
            version = format_args!("0x{:08x}", submission.version),
            ext_job_version = format_args!("0x{:08x}", ext_job.version),
            extranonce = %ext_hex,
            hash_prefix_be = %hash_prefix,
            ext_job_prefix_len = ext_job.coinbase_prefix.len(),
            ext_job_suffix_len = ext_job.coinbase_suffix.len(),
            ext_job_merkle_path_len = ext_job.merkle_path.len(),
            ext_job_prefix_hex = %prefix_hex,
            ext_job_suffix_hex = %suffix_hex,
            coinbase_hex = %coinbase_hex,
            merkle_root_hex = %merkle_root_hex,
            header_hex = %header_hex,
            "❌ Extended share rejected: difficulty-too-low ({:.6} < {:.2})",
            pow.submission_difficulty.as_f64(),
            job_difficulty.as_f64()
        );
        return ShareValidation::Rejected(RejectReason::DifficultyTooLow.into());
    }

    seen_shares.record(ext_job.prev_hash, pow.submission_hash);

    // The job's own n_bits: the hashed header commits to it, not to the
    // latest template.
    let is_block_candidate = meets_network_target(&pow.submission_hash, ext_job.n_bits);
    let witness_coinbase = if is_block_candidate {
        assemble_witness_coinbase(&coinbase_parts.concat())
    } else {
        Vec::new()
    };
    let effective_worker_name = crate::extensions::resolve_share_worker_name_from_tlv(
        &submission.tlvs,
        ext_0x0002_negotiated,
    );

    ShareValidation::Accepted(Box::new(ShareAccept {
        classification,
        effective_difficulty: job_difficulty,
        submission_difficulty: pow.submission_difficulty,
        header,
        hash: pow.submission_hash,
        is_block_candidate,
        template_id: ext_job.template_id,
        jdp_claims_the_block: ext_job.jdp_claims_the_block,
        payouts_fingerprint: ext_job.payouts_fingerprint,
        witness_coinbase,
        effective_worker_name,
        coinbase_tx_value_remaining: ext_job.coinbase_tx_value_remaining,
    }))
}

/// A share [`SeenShares`] refused goes out as `duplicate-share` either way:
/// a full set is not the miner's fault, but no other code fits and the share
/// must not be credited.
fn refuse_seen_share(refusal: SeenShareRefusal, channel_id: u32, job_id: u32) -> ShareValidation {
    match refusal {
        SeenShareRefusal::Duplicate => {
            tracing::warn!(channel_id, job_id, "❌ Share rejected: duplicate-share");
        }
        SeenShareRefusal::Full => {
            tracing::warn!(
                channel_id,
                job_id,
                "❌ Share rejected: this tip's duplicate guard is full ({} accepted shares), \
                 so no further share on it can be checked; refused as duplicate-share",
                bp_jobs_lifecycle::MAX_SEEN_SHARES_PER_TIP
            );
        }
    }
    ShareValidation::Rejected(RejectReason::DuplicateShare.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mining::channel::ChannelState;

    fn max_target() -> [u8; 32] {
        [0xFF; 32]
    }

    fn easy_diff() -> Difficulty {
        // Difficulty 1 / 2^32: any SHA256d output meets it, so no CPU search
        // is needed.
        Difficulty(1.0 / 4_294_967_296.0)
    }

    fn std_channel() -> ChannelState {
        ChannelState::new_standard(
            1,
            vec![0u8; 4],
            Difficulty(1024.0),
            max_target(),
            LifecycleConfig::DEFAULT,
        )
    }

    fn ext_channel() -> ChannelState {
        ChannelState::new_extended(
            2,
            vec![0u8; 4],
            8,
            Difficulty(1024.0),
            max_target(),
            LifecycleConfig::DEFAULT,
        )
    }

    fn ext_job(prev: [u8; 32], n_bits: u32) -> ExtendedJob {
        ExtendedJob {
            payouts_fingerprint: [0u8; 32],
            coinbase_prefix: vec![0xAA; 8],
            coinbase_suffix: vec![0xBB; 8],
            merkle_path: vec![[0u8; 32]],
            version: 0x2000_0000,
            prev_hash: prev,
            n_bits,
            min_ntime: 0,
            // Must match `ext_channel()`'s prefix: the validator rebuilds the
            // coinbase from the job's prefix.
            extranonce_prefix: vec![0u8; 4],
            difficulty: Difficulty(1.0 / 4_294_967_296.0),
            coinbase_tx_value_remaining: 5_000_000_000,
            template_id: None,
            jdp_claims_the_block: false,
            created_at: 0,
            retired_at: None,
        }
    }

    fn std_ctx(class: JobClassification) -> StandardJobContext<'static> {
        StandardJobContext {
            payouts_fingerprint: [0u8; 32],
            template_version: 0x2000_0000,
            prev_hash: [0xCC; 32],
            n_bits: 0x1d00_ffff,
            classification: class,
            template_id: None,
            coinbase_stratum: &[],
            coinbase_tx_value_remaining: 5_000_000_000,
        }
    }

    fn std_submission() -> SubmitSharesStandardInput {
        SubmitSharesStandardInput {
            channel_id: 1,
            sequence_number: 1,
            job_id: 7,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
        }
    }

    fn ext_submission() -> SubmitSharesExtendedInput {
        SubmitSharesExtendedInput {
            channel_id: 2,
            sequence_number: 1,
            job_id: 7,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
            extranonce: SmallVec::from_slice(&[0x11; 8]),
            tlvs: Vec::new(),
        }
    }

    /// Test shim: projects the channel into the `ExtendedChannelView` and
    /// `&mut seen_shares` the validator takes.
    fn validate_ext(
        ch: &mut ChannelState,
        sub: &SubmitSharesExtendedInput,
        job: &ExtendedJob,
        job_difficulty: Difficulty,
        now_ms: u64,
        ext_0x0002_negotiated: bool,
        debug_share_logs: bool,
    ) -> ShareValidation {
        let job_target = ch.target_for(job_difficulty);
        let view = ExtendedChannelView {
            kind: ch.kind,
            extranonce_size: ch.extranonce_size,
            job_target,
            job_lifecycle: *ch.standard_jobs.lifecycle(),
        };
        validate_submit_extended(
            &mut ch.seen_shares,
            &view,
            sub,
            job,
            job_difficulty,
            now_ms,
            ext_0x0002_negotiated,
            debug_share_logs,
        )
    }

    // ── RejectReason wire-code mapping ─────────────────────────────

    #[test]
    fn reject_reason_wire_codes_match_sv2_spec_literals() {
        assert_eq!(RejectReason::InvalidJobId.wire_code(), "invalid-job-id");
        assert_eq!(RejectReason::StaleShare.wire_code(), "stale-share");
        assert_eq!(RejectReason::DuplicateShare.wire_code(), "duplicate-share");
        assert_eq!(
            RejectReason::DifficultyTooLow.wire_code(),
            "difficulty-too-low"
        );
        assert_eq!(
            RejectReason::BadExtranonceSize.wire_code(),
            "bad-extranonce-size"
        );
    }

    /// `From<RejectReason> for ShareReject` populates the wire code.
    #[test]
    fn share_reject_from_reason_populates_wire_code() {
        let r: ShareReject = RejectReason::StaleShare.into();
        assert_eq!(r.wire_code, "stale-share");
    }

    // ── Standard happy path ────────────────────────────────────────

    #[test]
    fn standard_accepts_easy_share_with_max_target() {
        let mut ch = std_channel();
        let stored_merkle = [0xDD; 32];
        let out = validate_submit_standard(
            &mut ch,
            &std_submission(),
            easy_diff(),
            &stored_merkle,
            &std_ctx(JobClassification::Active),
        );
        match out {
            ShareValidation::Accepted(accept) => {
                assert_eq!(accept.classification, JobClassification::Active);
                assert_eq!(accept.effective_difficulty, easy_diff());
                assert!(!accept.is_block_candidate, "1e15 net-diff is unreachable");
            }
            _ => panic!("expected Accept"),
        }
        assert_eq!(ch.seen_shares.len(), 1);
    }

    /// A resubmission is a `duplicate-share` without a second cache insert.
    #[test]
    fn standard_rejects_duplicate_submit() {
        let mut ch = std_channel();
        let merkle = [0xDD; 32];
        let sub = std_submission();
        let _ = validate_submit_standard(
            &mut ch,
            &sub,
            easy_diff(),
            &merkle,
            &std_ctx(JobClassification::Active),
        );
        let out = validate_submit_standard(
            &mut ch,
            &sub,
            easy_diff(),
            &merkle,
            &std_ctx(JobClassification::Active),
        );
        match out {
            ShareValidation::Rejected(r) => {
                assert_eq!(r.reason, RejectReason::DuplicateShare);
                assert_eq!(r.wire_code, "duplicate-share");
            }
            _ => panic!("expected duplicate to be Rejected(DuplicateShare)"),
        }
        assert_eq!(ch.seen_shares.len(), 1, "no double-insert");
    }

    /// A share with a different header is not a duplicate.
    #[test]
    fn standard_different_header_is_not_a_duplicate() {
        let mut ch = std_channel();
        let merkle = [0xDD; 32];
        let mut sub = std_submission();
        let _ = validate_submit_standard(
            &mut ch,
            &sub,
            easy_diff(),
            &merkle,
            &std_ctx(JobClassification::Active),
        );
        sub.nonce ^= 1;
        let out = validate_submit_standard(
            &mut ch,
            &sub,
            easy_diff(),
            &merkle,
            &std_ctx(JobClassification::Active),
        );
        assert!(matches!(out, ShareValidation::Accepted(_)));
        assert_eq!(ch.seen_shares.len(), 2);
    }

    /// Replay across a block change: the old job stays creditable for
    /// `grace_ms`, so its accepted shares must stay duplicates. The control
    /// shows the same share is creditable to a channel that never saw it.
    #[test]
    fn standard_replay_after_block_change_is_a_duplicate() {
        let merkle = [0xDD; 32];
        let sub = std_submission();
        let mut ch = std_channel();
        let first = validate_submit_standard(
            &mut ch,
            &sub,
            easy_diff(),
            &merkle,
            &std_ctx(JobClassification::Active),
        );
        assert!(matches!(first, ShareValidation::Accepted(_)));

        ch.seen_shares
            .on_tip(&[0xEE; 32], 2_000, &LifecycleConfig::DEFAULT);
        let replay = validate_submit_standard(
            &mut ch,
            &sub,
            easy_diff(),
            &merkle,
            &std_ctx(JobClassification::StaleCreditable),
        );
        match replay {
            ShareValidation::Rejected(r) => assert_eq!(r.reason, RejectReason::DuplicateShare),
            ShareValidation::Accepted(_) => panic!("replayed share credited twice"),
        }

        let control = validate_submit_standard(
            &mut std_channel(),
            &sub,
            easy_diff(),
            &merkle,
            &std_ctx(JobClassification::StaleCreditable),
        );
        assert!(matches!(control, ShareValidation::Accepted(_)));
    }

    /// `StaleRejected` classification → wire `stale-share`.
    #[test]
    fn standard_stale_rejected_classification_emits_stale_share() {
        let mut ch = std_channel();
        let merkle = [0xDD; 32];
        let out = validate_submit_standard(
            &mut ch,
            &std_submission(),
            easy_diff(),
            &merkle,
            &std_ctx(JobClassification::StaleRejected),
        );
        match out {
            ShareValidation::Rejected(r) => {
                assert_eq!(r.reason, RejectReason::StaleShare);
                assert_eq!(r.wire_code, "stale-share");
            }
            _ => panic!("expected StaleShare"),
        }
    }

    /// `StaleCreditable` still validates and is credited.
    #[test]
    fn standard_stale_creditable_still_validates() {
        let mut ch = std_channel();
        let merkle = [0xDD; 32];
        let out = validate_submit_standard(
            &mut ch,
            &std_submission(),
            easy_diff(),
            &merkle,
            &std_ctx(JobClassification::StaleCreditable),
        );
        match out {
            ShareValidation::Accepted(accept) => {
                assert_eq!(accept.classification, JobClassification::StaleCreditable);
            }
            _ => panic!("StaleCreditable must accept"),
        }
    }

    /// A hash missing the job target is rejected without a dedup write.
    #[test]
    fn standard_rejects_below_job_target() {
        let mut ch = std_channel();
        let merkle = [0xDD; 32];
        let out = validate_submit_standard(
            &mut ch,
            &std_submission(),
            Difficulty(1e20), // impossible job target
            &merkle,
            &std_ctx(JobClassification::Active),
        );
        match out {
            ShareValidation::Rejected(r) => assert_eq!(r.reason, RejectReason::DifficultyTooLow),
            _ => panic!("expected DifficultyTooLow"),
        }
        // No dedup write on reject.
        assert_eq!(ch.seen_shares.len(), 0);
    }

    /// The header takes the submitted full nVersion verbatim, including a
    /// template bit the miner cleared, which an OR-based rebuild would restore.
    #[test]
    fn standard_header_version_is_the_submitted_version_verbatim() {
        let ctx = std_ctx(JobClassification::Active);
        let merkle = [0xDD; 32];

        // Sets a bit the template (0x2000_0000) does not have.
        let mut ch = std_channel();
        let mut sub = std_submission();
        sub.version = 0x2000_0001;
        let accept = match validate_submit_standard(&mut ch, &sub, easy_diff(), &merkle, &ctx) {
            ShareValidation::Accepted(a) => a,
            _ => panic!("expected Accept"),
        };
        assert_eq!(
            u32::from_le_bytes(accept.header[0..4].try_into().unwrap()),
            0x2000_0001
        );

        // Clears bit 29, which the template (0x2000_0000) has.
        let mut ch = std_channel();
        let mut sub = std_submission();
        sub.version = 0x0000_0000;
        let accept = match validate_submit_standard(&mut ch, &sub, easy_diff(), &merkle, &ctx) {
            ShareValidation::Accepted(a) => a,
            _ => panic!("expected Accept"),
        };
        assert_eq!(
            u32::from_le_bytes(accept.header[0..4].try_into().unwrap()),
            0x0000_0000,
            "a cleared template bit must survive into the header — an OR-based \
             reconstruction would put it back"
        );
    }

    /// Target `0xffff·2^240`: met by every hash except the top 2^-16.
    const TRIVIAL_N_BITS: u32 = 0x2100_ffff;

    /// A hash meeting the job's network target marks a block candidate.
    #[test]
    fn standard_marks_block_candidate_when_the_hash_meets_the_network_target() {
        let mut ch = std_channel();
        let merkle = [0xDD; 32];
        let mut ctx = std_ctx(JobClassification::Active);
        ctx.n_bits = TRIVIAL_N_BITS;
        let out = validate_submit_standard(&mut ch, &std_submission(), easy_diff(), &merkle, &ctx);
        match out {
            ShareValidation::Accepted(a) => assert!(a.is_block_candidate),
            _ => panic!("expected Accept"),
        }
    }

    // ── Extended happy path ────────────────────────────────────────

    #[test]
    fn extended_accepts_easy_share() {
        let mut ch = ext_channel();
        let job = ext_job([0xCC; 32], 0x1d00_ffff);
        let out = validate_ext(
            &mut ch,
            &ext_submission(),
            &job,
            easy_diff(),
            0,
            false,
            false,
        );
        match out {
            ShareValidation::Accepted(a) => {
                assert_eq!(a.classification, JobClassification::Active);
                assert!(!a.is_block_candidate);
                assert_eq!(
                    a.coinbase_tx_value_remaining,
                    job.coinbase_tx_value_remaining
                );
            }
            _ => panic!("expected Accept"),
        }
        assert_eq!(ch.seen_shares.len(), 1);
    }

    /// The block-candidate gate reads the `n_bits` pinned on the job, not the
    /// channel's latest template.
    #[test]
    fn extended_block_candidate_uses_per_job_pinned_n_bits() {
        let mut ch = ext_channel();
        let job = ext_job([0xCC; 32], TRIVIAL_N_BITS);
        let out = validate_ext(
            &mut ch,
            &ext_submission(),
            &job,
            easy_diff(),
            0,
            false,
            false,
        );
        match out {
            ShareValidation::Accepted(a) => {
                assert!(
                    a.is_block_candidate,
                    "a trivial per-job target must yield a block candidate"
                );
                // Witness coinbase is assembled only for candidates.
                assert!(!a.witness_coinbase.is_empty());
            }
            _ => panic!("expected Accept"),
        }
    }

    /// The extranonce is part of the header, so changing it is new work.
    #[test]
    fn extended_dedup_includes_extranonce() {
        let mut ch = ext_channel();
        let job = ext_job([0xCC; 32], 0x1d00_ffff);
        let mut sub = ext_submission();
        let _ = validate_ext(&mut ch, &sub, &job, easy_diff(), 0, false, false);
        // Same header → duplicate.
        let dup = validate_ext(&mut ch, &sub, &job, easy_diff(), 0, false, false);
        assert!(matches!(
            dup,
            ShareValidation::Rejected(ShareReject {
                reason: RejectReason::DuplicateShare,
                ..
            })
        ));
        // Different extranonce → fresh.
        sub.extranonce = SmallVec::from_slice(&[0x22; 8]);
        let fresh = validate_ext(&mut ch, &sub, &job, easy_diff(), 0, false, false);
        assert!(matches!(fresh, ShareValidation::Accepted(_)));
    }

    /// A job retired past grace rejects as stale-share despite a valid hash.
    #[test]
    fn extended_rejects_retired_past_grace() {
        let mut ch = ext_channel();
        let mut job = ext_job([0xCC; 32], 0x1d00_ffff);
        job.retired_at = Some(0);
        let out = validate_ext(
            &mut ch,
            &ext_submission(),
            &job,
            easy_diff(), // Way past 5 s grace.
            1_000_000,
            false,
            false,
        );
        match out {
            ShareValidation::Rejected(r) => {
                assert_eq!(r.reason, RejectReason::StaleShare);
                assert_eq!(r.wire_code, "stale-share");
            }
            _ => panic!("expected StaleShare"),
        }
    }

    /// An extranonce-size mismatch is rejected without a dedup write.
    #[test]
    fn extended_extranonce_size_mismatch_hard_rejects() {
        let mut ch = ext_channel();
        let job = ext_job([0xCC; 32], 0x1d00_ffff);
        let mut sub = ext_submission();
        sub.extranonce = SmallVec::from_slice(&[0x11; 7]); // expected 8, got 7
        let out = validate_ext(&mut ch, &sub, &job, easy_diff(), 0, false, false);
        match out {
            ShareValidation::Rejected(r) => {
                assert_eq!(r.reason, RejectReason::BadExtranonceSize);
                assert_eq!(r.wire_code, "bad-extranonce-size");
            }
            _ => panic!("expected BadExtranonceSize reject"),
        }
        assert_eq!(ch.seen_shares.len(), 0, "no dedup write on reject");
    }

    /// A wrong channel kind is rejected rather than panicking.
    #[test]
    fn standard_validator_rejects_extended_channel() {
        let mut ch = ext_channel();
        let merkle = [0xDD; 32];
        let out = validate_submit_standard(
            &mut ch,
            &std_submission(),
            easy_diff(),
            &merkle,
            &std_ctx(JobClassification::Active),
        );
        assert!(matches!(
            out,
            ShareValidation::Rejected(ShareReject {
                reason: RejectReason::InvalidJobId,
                ..
            })
        ));
    }

    #[test]
    fn extended_validator_rejects_standard_channel() {
        let mut ch = std_channel();
        let job = ext_job([0xCC; 32], 0x1d00_ffff);
        let out = validate_ext(
            &mut ch,
            &ext_submission(),
            &job,
            easy_diff(),
            0,
            false,
            false,
        );
        assert!(matches!(
            out,
            ShareValidation::Rejected(ShareReject {
                reason: RejectReason::InvalidJobId,
                ..
            })
        ));
    }

    // ── ext 0x0002 Worker-ID TLV resolution in validate_submit_extended ──

    fn worker_id_tlvs(user_identity: &str) -> Vec<stratum_core::parsers_sv2::Tlv> {
        vec![stratum_core::parsers_sv2::Tlv::new(
            crate::extensions::SV2_EXTENSION_TYPE_WORKER_ID,
            crate::extensions::SV2_FIELD_TYPE_USER_IDENTITY,
            user_identity.as_bytes().to_vec(),
        )]
    }

    /// ext 0x0002 negotiated + valid TLV: the TLV names the worker.
    #[test]
    fn ext_0x0002_tlv_present_when_negotiated_sets_effective_worker_name() {
        let mut ch = ext_channel();
        let job = ext_job([0xCC; 32], 0x1d00_ffff);
        let mut sub = ext_submission();
        sub.tlvs = worker_id_tlvs("Worker_001");

        let out = validate_ext(
            &mut ch,
            &sub,
            &job,
            easy_diff(),
            0,
            true, // ext 0x0002 negotiated
            false,
        );
        match out {
            ShareValidation::Accepted(a) => {
                assert_eq!(
                    a.effective_worker_name.as_deref(),
                    Some("Worker_001"),
                    "negotiated + valid TLV must surface the TLV worker name"
                );
            }
            _ => panic!("expected Accept"),
        }
    }

    /// ext 0x0002 not negotiated: the TLV is ignored (ext 0x0002/Behavior
    /// Based on Negotiation).
    #[test]
    fn ext_0x0002_tlv_present_when_not_negotiated_is_ignored() {
        let mut ch = ext_channel();
        let job = ext_job([0xCC; 32], 0x1d00_ffff);
        let mut sub = ext_submission();
        sub.tlvs = worker_id_tlvs("Worker_001");

        let out = validate_ext(
            &mut ch,
            &sub,
            &job,
            easy_diff(),
            0,
            false, // ext 0x0002 NOT negotiated
            false,
        );
        match out {
            ShareValidation::Accepted(a) => {
                assert!(
                    a.effective_worker_name.is_none(),
                    "non-negotiated TLV must be silently dropped (ext 0x0002/Behavior Based on Negotiation)"
                );
            }
            _ => panic!("expected Accept"),
        }
    }

    /// ext 0x0002 negotiated without a TLV: falls back to the channel default.
    #[test]
    fn ext_0x0002_negotiated_no_tlv_falls_back_to_channel_default() {
        let mut ch = ext_channel();
        let job = ext_job([0xCC; 32], 0x1d00_ffff);
        let sub = ext_submission(); // tlvs is empty.

        let out = validate_ext(
            &mut ch,
            &sub,
            &job,
            easy_diff(),
            0,
            true, // ext 0x0002 negotiated
            false,
        );
        match out {
            ShareValidation::Accepted(a) => {
                assert!(
                    a.effective_worker_name.is_none(),
                    "negotiated + missing TLV must fall back to channel-default"
                );
            }
            _ => panic!("expected Accept"),
        }
    }

    // ── Extended replay ────────────────────────────────────────────

    /// Replay across a block change on an Extended channel; see
    /// `standard_replay_after_block_change_is_a_duplicate`.
    #[test]
    fn extended_replay_after_block_change_is_a_duplicate() {
        let sub = ext_submission();
        let mut job = ext_job([0xCC; 32], 0x1d00_ffff);
        let mut ch = ext_channel();
        let first = validate_ext(&mut ch, &sub, &job, easy_diff(), 1_000, false, false);
        assert!(matches!(first, ShareValidation::Accepted(_)));

        job.retired_at = Some(2_000);
        ch.seen_shares
            .on_tip(&[0xEE; 32], 2_000, &LifecycleConfig::DEFAULT);
        let replay = validate_ext(&mut ch, &sub, &job, easy_diff(), 3_000, false, false);
        match replay {
            ShareValidation::Rejected(r) => assert_eq!(r.reason, RejectReason::DuplicateShare),
            ShareValidation::Accepted(_) => panic!("replayed share credited twice"),
        }

        let control = validate_ext(
            &mut ext_channel(),
            &sub,
            &job,
            easy_diff(),
            3_000,
            false,
            false,
        );
        match control {
            ShareValidation::Accepted(a) => {
                assert_eq!(a.classification, JobClassification::StaleCreditable)
            }
            ShareValidation::Rejected(r) => panic!("control must be creditable, got {r:?}"),
        }
    }

    /// Two job ids with the same content are the same work: the header hash,
    /// not the job id, decides what is a duplicate.
    #[test]
    fn extended_same_work_under_a_second_job_id_is_a_duplicate() {
        let job = ext_job([0xCC; 32], 0x1d00_ffff);
        let mut ch = ext_channel();
        let mut sub = ext_submission();
        let first = validate_ext(&mut ch, &sub, &job, easy_diff(), 1_000, false, false);
        assert!(matches!(first, ShareValidation::Accepted(_)));

        sub.job_id = 8;
        let again = validate_ext(&mut ch, &sub, &job, easy_diff(), 1_000, false, false);
        match again {
            ShareValidation::Rejected(r) => assert_eq!(r.reason, RejectReason::DuplicateShare),
            ShareValidation::Accepted(_) => panic!("same work credited under a second job id"),
        }
    }
}
