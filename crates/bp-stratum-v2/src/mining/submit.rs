// SPDX-License-Identifier: AGPL-3.0-or-later

//! Share validation for **Standard** and **Extended** SV2 mining channels.
//! Pure logic, no I/O: the per-share side effects (PPLNS / group-solo
//! accounting, accumulators, block-found bookkeeping) are the caller's job,
//! behind the [`crate::hooks`] trait boundaries.
//!
//! Both paths run duplicate-check, classification, header assembly, hash
//! and target check. Standard uses the merkle root stored when the
//! `NewMiningJob` was sent; Extended rebuilds the coinbase from the job's
//! prefix, extranonce prefix, the submitted extranonce and suffix, and walks
//! the job's merkle path.
//!
//! The result is [`ShareValidation::Accepted`] (header, submission and
//! credited difficulty, [`bp_jobs_lifecycle::JobClassification`], and whether
//! the hash meets the job's network target via
//! [`bp_mining_job::meets_network_target`]) or [`ShareValidation::Rejected`]
//! with the wire code the caller writes into `SubmitSharesError.error_code`
//! verbatim.

use bp_jobs_lifecycle::JobClassification;
use bp_mining_job::{
    assemble_witness_coinbase, build_block_header, meets_network_target, merkle_root_from_coinbase,
};
use bp_share::{calculate_difficulty, sha256d_from_parts, Difficulty, Target};
use smallvec::SmallVec;

/// Inline storage for the per-share `extranonce` buffer. 16 inline bytes
/// cover the sizes miners negotiate without a heap allocation per share;
/// larger sizes spill to the heap.
pub type ExtranonceBytes = SmallVec<[u8; 16]>;

use super::channel::{
    ChannelKind, ChannelState, ExtendedDedupKey, StandardDedupKey, SubmissionCache,
};
use super::jobs::{classify_extended_job, ExtendedJob};
use bp_jobs_lifecycle::LifecycleConfig;

// ── Wire codes (SV2 mining-protocol error strings) ───────────────────

/// Channel id in the submission doesn't match any open channel on
/// this connection.
pub const ERR_INVALID_CHANNEL_ID: &str = "invalid-channel-id";

/// Job id is genuinely unknown — past retention GC, or never sent.
/// SV2 Mining/SubmitShares.Error distinguishes this from `stale-share` (job
/// *was* known, since superseded).
pub const ERR_INVALID_JOB_ID: &str = "invalid-job-id";

/// Job id resolves to a retired entry past
/// [`bp_jobs_lifecycle::LifecycleConfig::grace_ms`]. Separate from
/// `ERR_DUPLICATE_SHARE` because they are different faults, not because the
/// spec separates them (see the note below).
pub const ERR_STALE_SHARE: &str = "stale-share";

/// Duplicate `(job_id, nonce, ntime, version[, extranonce])` tuple
/// re-submitted on this channel.
///
/// **None of these strings is spec-assigned.** SV2 Mining/SubmitShares.Error
/// types `error_code` as a bare `STR0_255` and SV2 Overview/Error Codes says
/// the list "can differ between implementations" and that a receiver MUST
/// log-no-op on unknown codes. The vocabulary is convention shared with
/// common clients and can be extended; a downstream that treats an unknown
/// code as fatal is outside the spec.
pub const ERR_DUPLICATE_SHARE: &str = "duplicate-share";

/// Header hash didn't meet the job-specific target.
pub const ERR_DIFFICULTY_TOO_LOW: &str = "difficulty-too-low";

/// Miner-supplied `extranonce.len()` doesn't match the channel's
/// negotiated `rollable_extranonce_size`. A hard reject: with a different
/// size the reconstructed coinbase is not what the miner hashed, so the
/// validated hash would not be the miner's and the credited work would be
/// unverified.
pub const ERR_BAD_EXTRANONCE_SIZE: &str = "bad-extranonce-size";

// ── Reject reasons ───────────────────────────────────────────────────

/// Internal classification of a rejected share. Maps to an SV2 wire
/// code via [`Self::wire_code`]; the caller emits the literal in
/// `SubmitSharesError.error_code`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    InvalidChannelId,
    InvalidJobId,
    /// Job entry exists but was retired past
    /// [`bp_jobs_lifecycle::LifecycleConfig::grace_ms`]. Wire
    /// `stale-share`. Distinct from [`Self::DuplicateShare`] so the
    /// stats fan-out can bucket them separately.
    StaleShare,
    /// `(job_id, nonce, ntime, version[, extranonce])` re-submitted
    /// on this channel. Wire `duplicate-share`.
    DuplicateShare,
    DifficultyTooLow,
    /// Extended-channel only. Miner sent an extranonce whose length
    /// doesn't match `channel.extranonce_size`. See
    /// [`ERR_BAD_EXTRANONCE_SIZE`] doc for the hard-reject rationale.
    BadExtranonceSize,
}

impl RejectReason {
    pub fn wire_code(self) -> &'static str {
        match self {
            RejectReason::InvalidChannelId => ERR_INVALID_CHANNEL_ID,
            RejectReason::InvalidJobId => ERR_INVALID_JOB_ID,
            RejectReason::StaleShare => ERR_STALE_SHARE,
            RejectReason::DuplicateShare => ERR_DUPLICATE_SHARE,
            RejectReason::DifficultyTooLow => ERR_DIFFICULTY_TOO_LOW,
            RejectReason::BadExtranonceSize => ERR_BAD_EXTRANONCE_SIZE,
        }
    }
}

// ── Validation result ────────────────────────────────────────────────

/// Successful validation. Carries everything the caller needs to:
/// build the `SubmitSharesSuccess` frame, fan share-stats to PPLNS /
/// group-solo / accumulators, and (if `is_block_candidate`) trigger
/// the TDP `SubmitSolution` path.
#[derive(Clone, Debug)]
pub struct ShareAccept {
    /// `Active` or `StaleCreditable`. Both credit the share.
    pub classification: JobClassification,
    /// Difficulty the share is **credited at** — the job-specific difficulty
    /// stored at send-time (SV2 Mining/SubmitShares.Error). Feeds the payout
    /// accounting and the accepted-share accumulators; may be below the
    /// session's current difficulty after a vardiff increase.
    pub effective_difficulty: Difficulty,
    /// Difficulty the share **actually solved for**, derived from the
    /// header hash. Drives the block-found gate and the personal-best
    /// tracker.
    pub submission_difficulty: Difficulty,
    /// 80-byte block header that produced the hash. The block-submit path
    /// assembles a found block from it.
    pub header: [u8; 80],
    /// `sha256d(header)` in LE byte order.
    pub hash: [u8; 32],
    /// True when the hash meets the network target from the job's `n_bits`.
    /// bitcoind stays the authoritative validator; this only triggers the
    /// `TdpHandle::submit_solution` path.
    pub is_block_candidate: bool,
    /// TDP template id the job was built against. `None` for
    /// `SetCustomMiningJob`-declared jobs, which have no pool-side template.
    pub template_id: Option<u64>,
    /// Copied off [`crate::mining::jobs::ExtendedJob::jdp_claims_the_block`]:
    /// `true` when a block found on this job will be claimed by the JDP
    /// `PushSolution` path. The block sink needs it to decide whether a
    /// custom-job block is its own to record. Always `false` on the
    /// Standard path, which has no custom jobs.
    pub jdp_claims_the_block: bool,
    /// Identity of the payout list the job's coinbase pays. The block sink
    /// hands it on so the ledger books the distribution this block actually
    /// paid, not whatever the shared snapshot key holds by then. Zeroed when
    /// the pool did not build the coinbase.
    pub payouts_fingerprint: [u8; 32],
    /// Witness-form (BIP-141) coinbase transaction, ready for
    /// `TdpHandle::submit_solution`'s `coinbase_tx`. Built only for block
    /// candidates, by both validators. Empty for a `SetCustomMiningJob`-declared
    /// job, which carries no pool-side coinbase; the block sink then logs a
    /// WARN instead of submitting.
    pub witness_coinbase: Vec<u8>,
    /// Per-share worker name. `Some` when ext 0x0002 was negotiated and the
    /// share carries a valid Worker-ID TLV (ext 0x0002/Behavior Based on
    /// Negotiation); `None` means the caller uses the channel's
    /// `user_identity`. Always `None` on Standard channels, and on connections
    /// without ext 0x0002, whose TLVs "the server MUST ignore".
    pub effective_worker_name: Option<String>,
    /// Block-reward portion the coinbase claims: the job's pinned
    /// `coinbase_tx_value_remaining`, passed to the per-mode ledger on a
    /// found block. `0` for `SetCustomMiningJob`-declared jobs, whose
    /// accounting the JDC owns.
    pub coinbase_tx_value_remaining: u64,
}

/// Rejected share. Bundles the internal reason with its wire form so
/// the caller writes the `SubmitSharesError` frame without re-deriving.
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

// ── Submit-frame inputs (minimal shape — wire types belong elsewhere) ─

/// Inputs from a deserialized `SubmitSharesStandard` frame, narrowed to
/// what the validator reads, so it stays decoupled from
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

/// Inputs from a deserialized `SubmitSharesExtended` frame. Adds the
/// miner-supplied `extranonce` bytes.
#[derive(Clone, Debug)]
pub struct SubmitSharesExtendedInput {
    pub channel_id: u32,
    pub sequence_number: u32,
    pub job_id: u32,
    pub nonce: u32,
    pub version: u32,
    pub ntime: u32,
    pub extranonce: ExtranonceBytes,
    /// TLVs decoded after the `SubmitSharesExtended` base payload, e.g. the
    /// ext 0x0002 Worker-ID TLV. Resolved into
    /// [`ShareAccept::effective_worker_name`] via
    /// [`crate::extensions::resolve_share_worker_name_from_tlv`]; order does
    /// not matter (ext 0x0002/Behavior Based on Negotiation).
    pub tlvs: Vec<stratum_core::parsers_sv2::Tlv>,
}

// ── Standard-channel job context ─────────────────────────────────────

/// Per-job context the **Standard**-channel validator needs, resolved by
/// the caller so the validator stays pure.
#[derive(Clone, Copy, Debug)]
pub struct StandardJobContext<'a> {
    /// `block.version` from the template the job was built against.
    pub template_version: i32,
    /// 32-byte previous-block hash from the template.
    pub prev_hash: [u8; 32],
    /// `n_bits` (`block.bits`) from the template — encodes the network
    /// target the block-found gate checks.
    pub n_bits: u32,
    /// Job classification from the central registry.
    pub classification: JobClassification,
    /// TDP template id the job was built against, carried to
    /// [`ShareAccept::template_id`] for `TdpHandle::submit_solution`.
    /// `None` for `SetCustomMiningJob`-derived jobs.
    pub template_id: Option<u64>,
    /// Non-witness coinbase bytes matching the merkle root the miner hashed,
    /// from [`crate::mining::jobs::StandardJobEntry::coinbase_stratum`].
    /// Empty for a `SetCustomMiningJob`-declared job.
    pub coinbase_stratum: &'a [u8],
    /// Identity of the payout list this job's coinbase pays, copied off the
    /// `MiningJob`, so a block found on this job books exactly that
    /// distribution rather than a later build's snapshot. Zeroed for jobs
    /// the pool did not build the coinbase for.
    pub payouts_fingerprint: [u8; 32],
    /// Block-reward portion the coinbase claims (per-job pinned
    /// `coinbase_tx_value_remaining`).
    pub coinbase_tx_value_remaining: u64,
}

// ── Standard validation ──────────────────────────────────────────────

/// Validate a `SubmitSharesStandard` frame against pre-resolved channel
/// state and job context.
///
/// The caller resolves the channel ([`RejectReason::InvalidChannelId`] when
/// missing) and the job's classification, difficulty and merkle root from
/// [`crate::mining::jobs::StandardJobMaps`] ([`RejectReason::InvalidJobId`]
/// when missing).
///
/// The [`StandardDedupKey`] goes into the submission cache only on accept,
/// so a rejected share never makes a later valid resubmission look like a
/// duplicate.
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

    let dedup_key = StandardDedupKey {
        job_id: submission.job_id,
        nonce: submission.nonce,
        ntime: submission.ntime,
        version: submission.version,
    };

    // Pre-check duplicate WITHOUT inserting — only insert on accept.
    if matches!(&channel.submission_cache, SubmissionCache::Standard(s) if s.contains(&dedup_key)) {
        return ShareValidation::Rejected(RejectReason::DuplicateShare.into());
    }

    if job_ctx.classification == JobClassification::StaleRejected {
        return ShareValidation::Rejected(RejectReason::StaleShare.into());
    }

    // `submission.version` is the FULL nVersion (SV2 spec:
    // `SubmitSharesStandard.version` is the "Full nVersion field"), so it
    // goes into the header as-is.
    let header = build_block_header(
        submission.version as i32,
        &job_ctx.prev_hash,
        stored_merkle_root,
        submission.ntime,
        job_ctx.n_bits,
        submission.nonce,
    );

    let pow = calculate_difficulty(&header);
    let job_target = channel.target_for(job_difficulty);
    if !job_target.is_met_by_le(&pow.submission_hash) {
        return ShareValidation::Rejected(RejectReason::DifficultyTooLow.into());
    }

    // Recorded only after every reject, so a resubmission of a bad share is
    // not reported as a duplicate.
    channel.submission_cache.insert_standard(dedup_key);

    let is_block_candidate = meets_network_target(&pow.submission_hash, job_ctx.n_bits);
    // Built only for block candidates. An empty `coinbase_stratum` (a
    // `SetCustomMiningJob` job) yields no coinbase rather than malformed
    // bytes for bitcoind.
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
        // Standard-channel shares carry no Worker-ID TLV.
        effective_worker_name: None,
        coinbase_tx_value_remaining: job_ctx.coinbase_tx_value_remaining,
    }))
}

// ── Extended validation ──────────────────────────────────────────────

/// Read-only projection of the channel fields the extended validator
/// needs, plus the per-job target the caller already computed via
/// [`ChannelState::target_for`].
///
/// A view instead of `&mut ChannelState` lets the caller lend only the
/// dedup cache mutably while holding a shared borrow of the `ExtendedJob`
/// in the same channel, so no per-share clone of the job is needed.
#[derive(Clone, Copy, Debug)]
pub struct ExtendedChannelView {
    pub kind: ChannelKind,
    pub extranonce_size: u8,
    /// `channel.target_for(job_difficulty)` — precomputed by the caller
    /// so the validator needs no `&mut` access to the channel's memo.
    pub job_target: Target,
    /// The channel's lifecycle config (`channel.standard_jobs.lifecycle()`),
    /// which the stale-share classification runs against.
    pub job_lifecycle: LifecycleConfig,
}

/// Validate a `SubmitSharesExtended` frame against the resolved
/// [`ExtendedJob`], rebuilding the coinbase and walking the merkle path.
///
/// An extranonce-size mismatch is a hard reject (`bad-extranonce-size`),
/// see [`ERR_BAD_EXTRANONCE_SIZE`].
///
/// `job_difficulty` is the per-job difficulty the share validates against
/// (SV2 Mining/SubmitShares.Error). The network target for the block-found
/// gate comes from `ext_job.n_bits`, pinned at send-time, so a block change
/// between job-send and submit cannot reclassify the share.
#[allow(clippy::too_many_arguments)]
pub fn validate_submit_extended(
    submission_cache: &mut SubmissionCache,
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

    let dedup_key = ExtendedDedupKey {
        job_id: submission.job_id,
        nonce: submission.nonce,
        ntime: submission.ntime,
        version: submission.version,
        extranonce: submission.extranonce.clone(),
    };
    if matches!(&*submission_cache, SubmissionCache::Extended(s) if s.contains(&dedup_key)) {
        tracing::warn!(
            channel_id = submission.channel_id,
            job_id = submission.job_id,
            "❌ Extended share rejected: duplicate-share"
        );
        return ShareValidation::Rejected(RejectReason::DuplicateShare.into());
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

    // Hard reject: with a different size the reconstructed coinbase is not
    // what the miner hashed, so the work would be credited unverified.
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

    // 1. Reconstruct the coinbase byte-for-byte as the miner does:
    //
    //   coinbase = ext_job.coinbase_prefix
    //            + ext_job.extranonce_prefix
    //            + submission.extranonce
    //            + ext_job.coinbase_suffix
    //
    // `coinbase_prefix` excludes the extranonce prefix, because miners
    // append that themselves.
    //
    // The extranonce prefix is read off the JOB, never off the channel:
    // SV2 Mining/SetExtranoncePrefix is effective only from the next job on,
    // so a share for an older job was built with that job's prefix.
    let coinbase_parts: [&[u8]; 4] = [
        &ext_job.coinbase_prefix[..],
        &ext_job.extranonce_prefix[..],
        &submission.extranonce[..],
        &ext_job.coinbase_suffix[..],
    ];

    // 2. Coinbase txid, streamed into the hasher so the hot path never
    //    allocates the full coinbase. It is only concatenated in the cold
    //    branches below: reject diagnostics and the block-candidate coinbase.
    let coinbase_txid = sha256d_from_parts(&coinbase_parts);

    // 3. Walk the merkle path to derive the root.
    let merkle_root = merkle_root_from_coinbase(&coinbase_txid, &ext_job.merkle_path);

    // 4. Assemble the 80-byte header with `submission.version` verbatim, as
    //    on the Standard path: SV2 submits the full nVersion.
    let header = build_block_header(
        submission.version as i32,
        &ext_job.prev_hash,
        &merkle_root,
        submission.ntime,
        ext_job.n_bits,
        submission.nonce,
    );

    let pow = calculate_difficulty(&header);
    let job_target = view.job_target;

    // Gated by the `stratum_share_logs` config flag and emitted at DEBUG, so
    // it also needs `RUST_LOG=...,bp_stratum_v2=debug` to surface.
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

    submission_cache.insert_extended(dedup_key);

    // The job's own n_bits — the header the miner hashed commits to it, so
    // the gate uses the template the miner hashed against, not the latest
    // one.
    let is_block_candidate = meets_network_target(&pow.submission_hash, ext_job.n_bits);
    // Built only for block candidates, keeping the allocation off the hot path.
    let witness_coinbase = if is_block_candidate {
        assemble_witness_coinbase(&coinbase_parts.concat())
    } else {
        Vec::new()
    };
    // ext 0x0002/Behavior Based on Negotiation: `Some(_)` attributes the
    // share to the TLV's worker instead of the channel's.
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
    /// `&mut submission_cache` the validator takes.
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
            &mut ch.submission_cache,
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
        assert_eq!(
            RejectReason::InvalidChannelId.wire_code(),
            "invalid-channel-id"
        );
        assert_eq!(RejectReason::InvalidJobId.wire_code(), "invalid-job-id");
        assert_eq!(RejectReason::StaleShare.wire_code(), "stale-share");
        assert_eq!(RejectReason::DuplicateShare.wire_code(), "duplicate-share");
        assert_eq!(
            RejectReason::DifficultyTooLow.wire_code(),
            "difficulty-too-low"
        );
        // Extension wire-code (not in the canonical SV2 spec list).
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
        // With easy_diff() the target is MAX, so any hash meets it.
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
        // Dedup cache should have been written.
        assert_eq!(ch.submission_cache.len(), 1);
    }

    /// A resubmission of the same key is rejected as `duplicate-share`
    /// without a second cache insert.
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
        assert_eq!(ch.submission_cache.len(), 1, "no double-insert");
    }

    /// Different `(job, nonce, ntime, version)` tuple is NOT a duplicate.
    #[test]
    fn standard_different_dedup_key_is_not_a_duplicate() {
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
        assert_eq!(ch.submission_cache.len(), 2);
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

    /// A hash that misses the job target is rejected as `difficulty-too-low`
    /// and leaves the dedup cache untouched.
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
        assert_eq!(ch.submission_cache.len(), 0);
    }

    /// The header version is `submission.version`, verbatim.
    ///
    /// SV2 submits the full nVersion (spec: `SubmitSharesStandard.version`
    /// is the "Full nVersion field"), so no reconstruction happens — unlike
    /// SV1, which submits a masked subset and rebuilds per BIP-310.
    ///
    /// Both directions are covered; the second pins that a miner can
    /// **clear** a bit the template set, which an OR-based reconstruction
    /// cannot express.
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

        // Clears a bit the template DOES have. `std_ctx` builds its job at
        // template version 0x2000_0000, so dropping bit 29 lands on
        // 0x0000_0000 — which an OR would leave at 0x2000_0000.
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

    /// `is_block_candidate` flips to true when the hash meets the job's
    /// network target.
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
                // The per-job block reward is carried onto the accept for the
                // block-found ledger write.
                assert_eq!(
                    a.coinbase_tx_value_remaining,
                    job.coinbase_tx_value_remaining
                );
            }
            _ => panic!("expected Accept"),
        }
        assert_eq!(ch.submission_cache.len(), 1);
    }

    /// The block-candidate gate reads the `n_bits` pinned on the job at
    /// send-time (SV2 Mining/SubmitShares.Error): the same easy share is a
    /// candidate here and not in `extended_accepts_easy_share`, so a block
    /// change between send and submit cannot reclassify an in-flight share.
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

    /// Extended dedup includes the extranonce — same `(job, nonce, ntime,
    /// version)` with a different extranonce IS a fresh share.
    #[test]
    fn extended_dedup_includes_extranonce() {
        let mut ch = ext_channel();
        let job = ext_job([0xCC; 32], 0x1d00_ffff);
        let mut sub = ext_submission();
        let _ = validate_ext(&mut ch, &sub, &job, easy_diff(), 0, false, false);
        // Same key → duplicate.
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

    /// Retired-past-grace extended job rejects as stale-share even
    /// when the hash would otherwise meet target.
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

    /// An extranonce-size mismatch is a hard reject with wire code
    /// `bad-extranonce-size` and no dedup write.
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
        assert_eq!(ch.submission_cache.len(), 0, "no dedup write on reject");
    }

    /// A wrong channel kind is rejected rather than panicking, keeping the
    /// connection alive.
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

    /// ext 0x0002 negotiated + valid TLV → `ShareAccept.effective_worker_name`
    /// carries the TLV value (ext 0x0002/Behavior Based on Negotiation).
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

    /// ext 0x0002 NOT negotiated + TLV present → resolver ignores the TLV
    /// (ext 0x0002/Behavior Based on Negotiation "server MUST ignore
    /// unexpected TLV fields") → effective_worker_name is None (caller falls
    /// back to channel-default).
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

    /// ext 0x0002 negotiated + no TLV in submission → channel default
    /// fallback (`effective_worker_name = None`).
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
}
