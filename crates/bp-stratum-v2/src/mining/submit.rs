// SPDX-License-Identifier: AGPL-3.0-or-later

//! Share-validation hot path for both **Standard** and **Extended** SV2
//! mining channels. Pure logic — no I/O, no broadcasting, no DB. The
//! per-share side-effect fan-out (PPLNS / group-solo `record_share`,
//! `addAcceptedShare` accumulators, block-found bookkeeping, external-
//! shares submit) is the caller's job and runs on top of the
//! [`crate::hooks`] trait boundaries.
//!
//! Share-validation handler for both Standard and Extended channels.
//! The two share the same skeleton — channel-lookup → duplicate-check →
//! job-lookup → classification → header-assembly → hash → target-check —
//! but differ in:
//!
//! - **Standard**: looks up the **stored merkle root** the miner
//!   received in `NewMiningJob` (store-on-send pattern — avoids
//!   recomputing the merkle root on every share, which is more reliable).
//!   Extranonce is implicitly zero-filled in the coinbase slot.
//! - **Extended**: reconstructs the coinbase from
//!   `extJob.coinbase_prefix + channel.extranonce_prefix +
//!   submission.extranonce + extJob.coinbase_suffix`, walks the
//!   `extJob.merkle_path` to derive the root, then assembles the
//!   header. Worker-name override via ext 0x0002 TLV is the caller's
//!   responsibility (call [`crate::extensions::resolve_share_worker_name_from_tlv`]
//!   before passing the worker name down to the share-stats fan-out).
//!
//! Returns [`ShareValidation::Accepted`] with the assembled header,
//! the share's submission difficulty (post-hash), the job-specific
//! effective difficulty (for accounting), the classification
//! (`Active` vs `StaleCreditable` — both credit, see
//! [`bp_jobs_lifecycle::JobClassification`]), and the `is_block_candidate`
//! flag indicating that `submission_difficulty >= network_difficulty`.
//! Or [`ShareValidation::Rejected`] carrying one of four SV2 wire
//! codes: `invalid-channel-id`, `invalid-job-id`, `stale-share`,
//! `difficulty-too-low`.
//!
//! Wire codes are kept as `&'static str` constants — they're consumed
//! by the SV2 `SubmitSharesError.error_code` field (`Str0_32`). The
//! caller serializes the chosen literal directly without paraphrasing.

use bp_jobs_lifecycle::JobClassification;
use bp_mining_job::{build_block_header, merkle_root_from_coinbase};
use bp_share::{calculate_difficulty, sha256d, Difficulty, Target};
use smallvec::SmallVec;

/// Inline storage for the per-share `extranonce` buffer. Extended-channel
/// extranonce sizes are negotiated per-connection and capped well below
/// 32 bytes in practice (typical ASIC firmwares pick 4–16). At 16 bytes
/// inline we cover the realistic upper bound without a heap allocation
/// per share; larger sizes silently fall back to a Vec.
pub type ExtranonceBytes = SmallVec<[u8; 16]>;

use super::channel::{
    ChannelKind, ChannelState, ExtendedDedupKey, StandardDedupKey, SubmissionCache,
};
use super::jobs::{classify_extended_job, ExtendedJob};

// ── Wire codes (SV2 mining-protocol error strings) ───────────────────

/// Channel id in the submission doesn't match any open channel on
/// this connection.
pub const ERR_INVALID_CHANNEL_ID: &str = "invalid-channel-id";

/// Job id is genuinely unknown — past retention GC, or never sent.
/// SV2 spec §5.3.14 distinguishes this from `stale-share` (job *was*
/// known, since superseded).
pub const ERR_INVALID_JOB_ID: &str = "invalid-job-id";

/// Job id resolves to a retired entry past
/// [`bp_jobs_lifecycle::LifecycleConfig::grace_ms`]. Separate from
/// `ERR_DUPLICATE_SHARE` per SV2 spec — both have their own wire
/// code.
pub const ERR_STALE_SHARE: &str = "stale-share";

/// Duplicate `(job_id, nonce, ntime, version[, extranonce])` tuple
/// re-submitted on this channel. SV2 spec assigns this its own wire
/// code, distinct from `ERR_STALE_SHARE`.
pub const ERR_DUPLICATE_SHARE: &str = "duplicate-share";

/// Header hash didn't meet the job-specific target. Includes the case
/// where `meets_target` returns false even though the miner's own
/// pre-filter said it should — that's typically a vardiff race or a
/// malformed extranonce.
pub const ERR_DIFFICULTY_TOO_LOW: &str = "difficulty-too-low";

/// Miner-supplied `extranonce.len()` doesn't match the channel's
/// negotiated `rollable_extranonce_size`. Not in the SV2-spec
/// canonical error-code list.
/// **Hard-reject implementation**: if extranonce size differs, the
/// reconstructed coinbase ≠ what the miner hashed → the header-hash
/// we validate against ISN'T the miner's hash → we'd be crediting
/// un-verified hashpower. Hard-reject closes the cheating-vector.
/// See memory `feedback-sv2-bad-extranonce-size-hard-reject` for the
/// rationale.
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
    /// `Active` or `StaleCreditable`. Both credit the share; the caller
    /// may want to bookkeep them separately for diagnostics.
    pub classification: JobClassification,
    /// Difficulty the share is **credited at** — the job-specific
    /// difficulty stored at send-time (SV2 §5.3.14). Used by both
    /// PPLNS / group-solo accounting and the `add_accepted_share`
    /// accumulators. May be lower than the session's current diff when
    /// the share was issued before a vardiff ratchet.
    pub effective_difficulty: Difficulty,
    /// Difficulty the share **actually solved for**, derived from the
    /// header hash. Drives the block-found gate and the personal-best
    /// tracker.
    pub submission_difficulty: Difficulty,
    /// 80-byte block header that produced the hash. Forwarded to the
    /// external-share-submitter (when enabled).
    pub header: [u8; 80],
    /// `sha256d(header)` in LE byte order — the share's identity, the
    /// PoW result.
    pub hash: [u8; 32],
    /// True when the submission difficulty meets or exceeds the network
    /// difficulty derived from the job's `n_bits`. bitcoind is the
    /// authoritative validator — this only triggers the
    /// `TdpHandle::submit_solution` path.
    pub is_block_candidate: bool,
    /// TDP template id the job was built against. `Some` for jobs the
    /// pool issued from a pool-side template (Extended channels with
    /// pool-built jobs), `None` for `SetCustomMiningJob`-declared
    /// jobs (no pool-side template reference) and for Standard
    /// channels until [`StandardJobContext`] threads the template id
    /// through (Standard block-submit path).
    pub template_id: Option<u64>,
    /// Fully-assembled **witness-form** coinbase transaction bytes
    /// (BIP-141 layout: marker `0x00` + flag `0x01` inserted after
    /// version, 32-zero coinbase witness reserved value inserted
    /// before locktime). Ready to be passed to
    /// `TdpHandle::submit_solution`'s `coinbase_tx` argument.
    ///
    /// Populated by [`validate_submit_extended`] (rebuilds the stratum coinbase
    /// from per-channel + per-job state) AND by [`validate_submit_standard`]
    /// (from the per-job `StandardJobEntry::coinbase_stratum` stored at
    /// NewMiningJob send-time). **Empty** only when the job carries no pool-side
    /// coinbase — a `SetCustomMiningJob`-declared job — in which case block-found
    /// surfaces a WARN in the bin block-sink instead of submitting.
    pub witness_coinbase: Vec<u8>,
    /// Effective per-share worker name. `Some(value)` when ext
    /// 0x0002 (Worker-Specific Hashrate Tracking) was negotiated
    /// AND the miner appended a valid Worker-ID TLV to this share
    /// (spec §1.3). `None` means the caller should fall back to the
    /// channel-default `user_identity` from `OpenExtendedMiningChannel`.
    ///
    /// Always `None` for Standard-channel shares (channel-default
    /// only). Always `None` for Extended-channel shares whose
    /// connection did not negotiate ext 0x0002 (spec §1.3 — "the
    /// server MUST ignore unexpected TLV fields").
    pub effective_worker_name: Option<String>,
    /// Block-reward portion the coinbase claims — the per-job pinned
    /// `coinbase_tx_value_remaining` (subsidy + fees the pool's coinbase
    /// keeps). The block-found fan-out passes this to the per-mode engine
    /// ledger (`on_block_found`). `0` for `SetCustomMiningJob`-declared jobs
    /// (no pool template; the JDC owns the block-submit + accounting).
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
/// what the validator actually reads. Wrapped in our own struct so the
/// validator stays decoupled from `stratum_core::mining_sv2`'s lifetimes.
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
    /// Trailing TLV bytes from the frame's tail (after the
    /// `SubmitSharesExtended` base payload). Carries ext 0x0002
    /// `[ext_type 0x0002 BE][field_type 0x01][len BE16][user_identity]`
    /// when the miner has negotiated 0x0002 (Worker-Specific Hashrate
    /// Tracking). Empty when no TLVs are present.
    ///
    /// Resolved into [`ShareAccept::effective_worker_name`] by
    /// [`validate_submit_extended`] via
    /// [`crate::extensions::resolve_share_worker_name_from_tlv`] —
    /// spec §1.3: scan-for-known-TLV semantics, TLV-order-irrelevant.
    pub tail_tlvs: Vec<u8>,
}

// ── Standard-channel job context ─────────────────────────────────────

/// Per-job context the **Standard**-channel validator needs from the
/// caller. The validator stays pure by accepting the resolved values
/// directly as arguments.
#[derive(Clone, Copy, Debug)]
pub struct StandardJobContext<'a> {
    /// `block.version` from the template the job was built against
    /// (BIP-310 version-rolling applies via XOR-mask in
    /// [`validate_submit_standard`]).
    pub template_version: i32,
    /// 32-byte previous-block hash from the template.
    pub prev_hash: [u8; 32],
    /// `n_bits` (`block.bits`) from the template — encodes the network
    /// target.
    pub n_bits: u32,
    /// Network difficulty derived from `n_bits`. Cached on the template
    /// so we don't recompute per-share.
    pub network_difficulty: Difficulty,
    /// Job classification from the central registry (`JobNotFound` /
    /// `Active` / `StaleCreditable` / `StaleRejected`). `None` for
    /// genuinely missing jobs.
    pub classification: JobClassification,
    /// TDP template id the job was built against. Threaded through
    /// to [`ShareAccept::template_id`] so the block-sink can pass it
    /// to `TdpHandle::submit_solution` on a block-candidate. `None`
    /// for `SetCustomMiningJob`-derived jobs.
    pub template_id: Option<u64>,
    /// Full pre-assembled non-witness coinbase bytes (matches the
    /// merkle root the miner hashed against). Source: stored on
    /// [`crate::mining::jobs::StandardJobEntry::coinbase_stratum`]
    /// at `NewMiningJob` send time. Empty when the job was declared
    /// via `SetCustomMiningJob` (no pool template) — block-submit
    /// then falls through to a WARN at the bin block-sink.
    pub coinbase_stratum: &'a [u8],
    /// Block-reward portion the coinbase claims (per-job pinned
    /// `coinbase_tx_value_remaining`). Threaded onto [`ShareAccept`].
    pub coinbase_tx_value_remaining: u64,
}

// ── Standard validation ──────────────────────────────────────────────

/// Validate a `SubmitSharesStandard` frame. Pure function: takes the
/// pre-resolved per-channel state + the per-job context, returns a
/// [`ShareValidation`] without touching any external resource.
///
/// **Caller's prep work** (before this function):
/// 1. Look up `channel = channels.get(submission.channel_id)` —
///    `None` → emit [`RejectReason::InvalidChannelId`] directly (we
///    can't do it here because we need `&ChannelState`).
/// 2. Look up `job_id` in the central `JobRegistry` (or the per-channel
///    Standard maps) → if not found, emit
///    [`RejectReason::InvalidJobId`]. If found, fold the classification
///    + the template metadata into a [`StandardJobContext`].
/// 3. Look up `(job_difficulty, merkle_root)` from
///    [`crate::mining::jobs::StandardJobMaps`] — if missing, emit
///    [`RejectReason::InvalidJobId`] directly.
///
/// **What this function does**:
/// 1. Reject up-front if `channel.kind != Standard`
///    (defensive — caller shouldn't call this for an Extended channel).
/// 2. Duplicate-check the dedup tuple against the channel's submission
///    cache. Hit → [`RejectReason::StaleShare`].
/// 3. Reject if `classification == StaleRejected`.
/// 4. Build the 80-byte header from `(version XOR version_mask,
///    prev_hash, stored_merkle_root, ntime, n_bits, nonce)`.
/// 5. Compute `sha256d(header)` and the implied submission difficulty.
/// 6. Compare against `difficulty_to_target(job_difficulty)`. Miss →
///    [`RejectReason::DifficultyTooLow`].
/// 7. Otherwise build [`ShareAccept`] with `is_block_candidate =
///    submission_difficulty >= job_ctx.network_difficulty`.
///
/// The dedup-cache **write** is the caller's responsibility — it
/// happens INSIDE this function only when the share validates (so a
/// duplicate share that arrives mid-validation can't poison the cache).
/// On accept the function inserts the [`StandardDedupKey`] before
/// returning.
pub fn validate_submit_standard(
    channel: &mut ChannelState,
    submission: &SubmitSharesStandardInput,
    job_difficulty: Difficulty,
    stored_merkle_root: &[u8; 32],
    job_ctx: &StandardJobContext<'_>,
) -> ShareValidation {
    if channel.kind != ChannelKind::Standard {
        // Defensive — bug at the call site, not a wire-protocol error.
        // We still return InvalidJobId so the connection keeps running.
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

    let version_mask = submission.version ^ (job_ctx.template_version as u32);
    let header = build_block_header(
        job_ctx.template_version,
        version_mask,
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

    // Accept — record dedup AFTER all rejects so a duplicate of a
    // bad share doesn't get logged as duplicate.
    channel.submission_cache.insert_standard(dedup_key);

    let is_block_candidate = pow.submission_difficulty >= job_ctx.network_difficulty;
    // Witness-form coinbase for the block-found path.
    // Built only for block-candidates; per-share allocation cost is
    // negligible on the rare candidate path.
    //
    // Empty `coinbase_stratum` means the job was declared via
    // `SetCustomMiningJob` (no pool template available) — block-submit
    // then falls through to a WARN at the bin block-sink instead of
    // sending malformed bytes to bitcoin-core.
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
        witness_coinbase,
        // Standard-channel shares never carry a per-share Worker-ID
        // TLV — channel-default attribution only.
        effective_worker_name: None,
        coinbase_tx_value_remaining: job_ctx.coinbase_tx_value_remaining,
    }))
}

// ── Extended validation ──────────────────────────────────────────────

/// Read-only projection of the channel fields the extended validator
/// needs, plus the per-job target the caller already computed via
/// [`ChannelState::target_for`].
///
/// Passing these as a borrowed view (rather than `&mut ChannelState`)
/// lets the caller hand the validator a `&mut` borrow of *only* the
/// dedup cache while still holding a `&` borrow of the `ExtendedJob`
/// that lives in the same channel — disjoint-field borrows that the
/// whole-`&mut ChannelState` signature could not express, forcing a
/// per-share clone of the job. Mirrors the SV1 `validate_submit`
/// projection (`SessionContext` + `&mut share_cache`).
#[derive(Clone, Copy, Debug)]
pub struct ExtendedChannelView<'a> {
    pub kind: ChannelKind,
    pub extranonce_prefix: &'a [u8],
    pub extranonce_size: u8,
    /// `channel.target_for(job_difficulty)` — precomputed by the caller
    /// so the validator needs no `&mut` access to the channel's memo.
    pub job_target: Target,
}

/// Validate a `SubmitSharesExtended` frame. Pure function with the
/// same shape as [`validate_submit_standard`], but the caller passes
/// the resolved [`ExtendedJob`] reference (storage lives on the
/// channel) and the validator handles coinbase reconstruction +
/// merkle-path walking itself.
///
/// **Caller's prep work**: channel lookup only (`None` → emit
/// [`RejectReason::InvalidChannelId`] directly). Everything else —
/// extended-job lookup, classification, network-difficulty lookup —
/// happens inside.
///
/// **Extranonce-size mismatch is a HARD reject** with wire-code
/// `bad-extranonce-size`. Hard-reject implementation:
/// when extranonce sizes differ, the reconstructed coinbase ≠ what
/// the miner hashed, so the header-hash we'd validate against isn't
/// the miner's hash. Accepting would credit un-verified hashpower —
/// see memory `feedback-sv2-bad-extranonce-size-hard-reject`.
///
/// `job_difficulty` is the per-job target the share validates against
/// (SV2 §5.3.14). Caller resolves it from
/// `channel.standard_jobs.job_id_to_difficulty` if present, else falls
/// back to `channel.session_difficulty`. The **network** difficulty for
/// the block-found gate is read from `ext_job.network_difficulty` (pinned
/// at send-time, SV2 §5.3.14 strict) — NOT the current template, so a
/// block-change between job-send and submit can't reclassify the share.
#[allow(clippy::too_many_arguments)]
pub fn validate_submit_extended(
    submission_cache: &mut SubmissionCache,
    view: &ExtendedChannelView<'_>,
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

    let classification = classify_extended_job(ext_job, now_ms);
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

    // Extranonce-size check — HARD reject on mismatch.
    // Hard-reject is required — soft-accepting would be unsafe since
    // the reconstructed coinbase would diverge from what the miner
    // hashed, and we'd credit un-verified work.
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

    // 1. Reconstruct the coinbase exactly how the miner does it:
    //
    //   coinbase = ext_job.coinbase_prefix
    //            + channel.extranonce_prefix
    //            + submission.extranonce
    //            + ext_job.coinbase_suffix
    //
    // `ext_job.coinbase_prefix` here is the bytes BEFORE the
    // extranonce slot — `apply_template_to_channel` no longer bakes
    // `channel.extranonce_prefix` into it (doing so would double-count
    // the prefix on the miner side, since miners append it themselves
    // at share-build time). Validator must mirror miner's reconstruction
    // byte-for-byte or the resulting hash diverges → 100% diff-too-low
    // rejections.
    let mut coinbase = Vec::with_capacity(
        ext_job.coinbase_prefix.len()
            + view.extranonce_prefix.len()
            + submission.extranonce.len()
            + ext_job.coinbase_suffix.len(),
    );
    coinbase.extend_from_slice(&ext_job.coinbase_prefix);
    coinbase.extend_from_slice(view.extranonce_prefix);
    coinbase.extend_from_slice(&submission.extranonce);
    coinbase.extend_from_slice(&ext_job.coinbase_suffix);

    // 2. Coinbase txid = sha256d(coinbase).
    let coinbase_txid = sha256d(&coinbase);

    // 3. Walk the merkle path to derive the root.
    let merkle_root = merkle_root_from_coinbase(&coinbase_txid, &ext_job.merkle_path);

    // 4. Assemble the 80-byte header. Version-mask is XOR'd against
    //    the job's template version (BIP-310). `validate_submit_standard`
    //    folds the same algebra (version XOR mask == submission.version
    //    when mask = submission.version ^ template.version).
    let version_mask = submission.version ^ ext_job.version;
    let header = build_block_header(
        ext_job.version as i32,
        version_mask,
        &ext_job.prev_hash,
        &merkle_root,
        submission.ntime,
        ext_job.n_bits,
        submission.nonce,
    );

    let pow = calculate_difficulty(&header);
    let job_target = view.job_target;

    // Per-share difficulty trace for debugging. Gated by the
    // `stratum_share_logs` config flag (threaded in as
    // `debug_share_logs`); still emitted at DEBUG, so it also needs
    // `RUST_LOG=...,bp_stratum_v2=debug` to surface.
    // Format: `🎯 Extended share difficulty: X (target: Y)` with .2f.
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
        // Reject with full diagnostic dump (coinbase + merkle_root +
        // header) so we can byte-cross-check against what the miner
        // built from the wire NewExtendedMiningJob frame. If the bytes
        // the validator hashed don't match the miner's, this log is the
        // only way to spot it without instrumenting the miner.
        let to_hex = |b: &[u8]| -> String {
            let mut s = String::with_capacity(b.len() * 2);
            for x in b {
                s.push_str(&format!("{x:02x}"));
            }
            s
        };
        let hash_prefix = to_hex(&pow.submission_hash[..8]);
        let coinbase_hex = to_hex(&coinbase);
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

    // Per-job pinned network difficulty (SV2 §5.3.14 strict) — the gate
    // uses the template the miner hashed against, not the latest one.
    let is_block_candidate = pow.submission_difficulty >= ext_job.network_difficulty;
    // Witness-form coinbase for the block-found path. Built only for
    // block-candidates to keep the per-share allocation off the hot
    // path (every non-candidate share goes through the validator,
    // ~95+% of them).
    let witness_coinbase = if is_block_candidate {
        assemble_witness_coinbase(&coinbase)
    } else {
        Vec::new()
    };
    // ext 0x0002 Worker-ID TLV resolution (spec §1.3). The validator
    // operates at the channel layer and doesn't know the
    // session-level `address` or `channel_worker` — those are
    // session-state. We pass empty channel defaults so the resolver
    // either returns a non-empty TLV-derived worker name (TLV present
    // + valid + spec-compliant) or the empty channel default. The
    // empty string is collapsed to `None` so consumers can rely on
    // `Some(_) ⇒ TLV was present and the caller should override
    // attribution`.
    //
    // The IO layer applies the cross-account-attribution security
    // check (TLV-address must match the channel's session address)
    // before applying `effective_worker_name` to share-stats, because
    // it has the session context.
    let resolved = crate::extensions::resolve_share_worker_name_from_tlv(
        &crate::extensions::ResolveWorkerNameInput {
            tail: &submission.tail_tlvs,
            channel_address: None,
            channel_worker: "",
            ext_0x0002_negotiated,
        },
    );
    let effective_worker_name = if resolved.is_empty() {
        None
    } else {
        Some(resolved)
    };

    ShareValidation::Accepted(Box::new(ShareAccept {
        classification,
        effective_difficulty: job_difficulty,
        submission_difficulty: pow.submission_difficulty,
        header,
        hash: pow.submission_hash,
        is_block_candidate,
        template_id: ext_job.template_id,
        witness_coinbase,
        effective_worker_name,
        coinbase_tx_value_remaining: ext_job.coinbase_tx_value_remaining,
    }))
}

/// Convert the non-witness (stratum) coinbase bytes into the
/// witness-form serialisation Bitcoin Core's `submitblock` expects:
/// inserts BIP-141 marker `0x00` + flag `0x01` right after `version`,
/// then a single witness item of 32 zero bytes (the coinbase input's
/// mandatory reserved value) right before `locktime`.
///
/// Mirrors the algebra in
/// [`bp_mining_job::MiningJob::witness_coinbase_with_extranonce`] but
/// operates on already-assembled stratum-coinbase bytes — the SV2
/// extended-validator path reconstructs them from
/// `ext_job.coinbase_prefix + channel.extranonce_prefix +
/// submission.extranonce + ext_job.coinbase_suffix` and has no
/// `MiningJob` handle. Output is byte-identical to the SV1 path.
///
/// `pub` so the bin's JDP-block-submission
/// sink (`bin/blitzpool/src/jdp_hooks.rs`) can reuse it: a JDP-declared
/// job's coinbase arrives in stratum (non-witness) form via
/// `DeclareMiningJob`, but block submission to bitcoin-core needs the
/// witness form. Single source of truth for the BIP-141 layout.
pub fn assemble_witness_coinbase(stratum_coinbase: &[u8]) -> Vec<u8> {
    debug_assert!(
        stratum_coinbase.len() >= 8,
        "stratum coinbase smaller than version+locktime"
    );
    let locktime_at = stratum_coinbase.len() - 4;
    let mut buf = Vec::with_capacity(stratum_coinbase.len() + 2 + 1 + 1 + 32);
    // version
    buf.extend_from_slice(&stratum_coinbase[..4]);
    // BIP-141 marker + flag
    buf.push(0x00);
    buf.push(0x01);
    // everything between version and locktime (input + outputs)
    buf.extend_from_slice(&stratum_coinbase[4..locktime_at]);
    // witness stack: 1 item of 32 zero bytes
    buf.push(0x01);
    buf.push(0x20);
    buf.extend_from_slice(&[0u8; 32]);
    // locktime
    buf.extend_from_slice(&stratum_coinbase[locktime_at..]);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mining::channel::ChannelState;

    fn max_target() -> [u8; 32] {
        [0xFF; 32]
    }

    fn easy_diff() -> Difficulty {
        // Difficulty 1 / 2^32 — the minimum we can reasonably test against
        // a SHA256d output without a CPU-search. Any random hash beats it.
        Difficulty(1.0 / 4_294_967_296.0)
    }

    fn std_channel() -> ChannelState {
        ChannelState::new_standard(1, vec![0u8; 4], Difficulty(1024.0), max_target())
    }

    fn ext_channel() -> ChannelState {
        ChannelState::new_extended(2, vec![0u8; 4], 8, Difficulty(1024.0), max_target())
    }

    fn ext_job(prev: [u8; 32], n_bits: u32) -> ExtendedJob {
        ExtendedJob {
            coinbase_prefix: vec![0xAA; 8],
            coinbase_suffix: vec![0xBB; 8],
            merkle_path: vec![[0u8; 32]],
            version: 0x2000_0000,
            prev_hash: prev,
            n_bits,
            min_ntime: 0,
            difficulty: Difficulty(1.0 / 4_294_967_296.0),
            // Unreasonably hard pinned network difficulty → not a block
            // candidate. Tests that exercise the candidate gate set this
            // field explicitly on the returned job.
            network_difficulty: Difficulty(1e15),
            coinbase_tx_value_remaining: 5_000_000_000,
            template_id: None,
            created_at: 0,
            retired_at: None,
        }
    }

    fn std_ctx(class: JobClassification) -> StandardJobContext<'static> {
        StandardJobContext {
            template_version: 0x2000_0000,
            prev_hash: [0xCC; 32],
            n_bits: 0x1d00_ffff,
            network_difficulty: Difficulty(1e15), // unreasonably hard → not a block
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
            tail_tlvs: Vec::new(),
        }
    }

    /// Test shim: projects the channel into the `ExtendedChannelView` +
    /// `&mut submission_cache` the validator now takes, so the existing
    /// `&mut channel`-style call sites keep their shape. (The production
    /// handler does this projection inline to drop the per-share job clone.)
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
            extranonce_prefix: &ch.extranonce_prefix,
            extranonce_size: ch.extranonce_size,
            job_target,
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

    /// Spec note: `From<RejectReason> for ShareReject` populates the
    /// wire code automatically.
    #[test]
    fn share_reject_from_reason_populates_wire_code() {
        let r: ShareReject = RejectReason::StaleShare.into();
        assert_eq!(r.wire_code, "stale-share");
    }

    // ── Standard happy path ────────────────────────────────────────

    #[test]
    fn standard_accepts_easy_share_with_max_target() {
        // With easy_diff() → target = MAX, ANY hash meets the target.
        // We expect Accept.
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

    /// Duplicate submit on the same key is rejected as `stale-share`.
    /// First call accepts + writes cache; second call sees the cache
    /// hit and rejects WITHOUT modifying anything else.
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

    /// Difficulty mismatch — hash doesn't meet job target.
    /// We construct an impossibly hard target (DIFF_ONE × huge factor)
    /// so the random submission hash won't meet it.
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

    /// Header byte-shape: version XOR-mask is applied (BIP-310). The
    /// submitted-version field is the FINAL header version when
    /// `submission.version != template.version`. We test by passing
    /// a submission version with a non-zero rolled bit and verifying
    /// the header[0..4] matches the submission version (LE).
    #[test]
    fn standard_header_applies_version_rolling_mask() {
        let mut ch = std_channel();
        let merkle = [0xDD; 32];
        let mut sub = std_submission();
        sub.version = 0x2000_0001; // version-rolled by 1 bit
        let ctx = std_ctx(JobClassification::Active);
        let out = validate_submit_standard(&mut ch, &sub, easy_diff(), &merkle, &ctx);
        let accept = match out {
            ShareValidation::Accepted(a) => a,
            _ => panic!("expected Accept"),
        };
        // header[0..4] LE == 0x2000_0001 because the mask propagates the
        // bit difference: template=0x2000_0000, submitted=0x2000_0001,
        // mask = 0x0000_0001, applied: 0x2000_0000 XOR 0x0000_0001 = 0x2000_0001.
        let v = u32::from_le_bytes(accept.header[0..4].try_into().unwrap());
        assert_eq!(v, 0x2000_0001);
    }

    /// `is_block_candidate` flips to true when submission ≥ network.
    #[test]
    fn standard_marks_block_candidate_when_submission_meets_network() {
        let mut ch = std_channel();
        let merkle = [0xDD; 32];
        let mut ctx = std_ctx(JobClassification::Active);
        ctx.network_difficulty = Difficulty(0.0); // trivially meetable
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
                // 5a: the per-job block reward is threaded onto the accept so
                // the block-found fan-out can write the engine ledger.
                assert_eq!(
                    a.coinbase_tx_value_remaining,
                    job.coinbase_tx_value_remaining
                );
            }
            _ => panic!("expected Accept"),
        }
        assert_eq!(ch.submission_cache.len(), 1);
    }

    /// 5b (SV2 §5.3.14 strict): the block-candidate gate reads the network
    /// difficulty **pinned on the job at send-time**, not any current/latest
    /// template. A job pinned with a trivial network difficulty yields a
    /// block-candidate for the same easy share that the default (1e15) job
    /// classifies as non-candidate — proving the gate is per-job, so a
    /// block-change between send and submit can't reclassify an in-flight share.
    #[test]
    fn extended_block_candidate_uses_per_job_pinned_network_difficulty() {
        let mut ch = ext_channel();
        let mut job = ext_job([0xCC; 32], 0x1d00_ffff);
        // Trivial pinned network difficulty → any valid share is a candidate.
        job.network_difficulty = Difficulty(1.0e-18);
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
                    "trivial per-job network difficulty must yield a block candidate"
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

    /// Extranonce-size mismatch is a HARD reject with wire-code
    /// `bad-extranonce-size`. The hard-reject closes the cheating-vector.
    /// See memory `feedback-sv2-bad-extranonce-size-hard-reject`.
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

    /// Wrong channel kind defensively rejects (caller bug; shouldn't
    /// reach the wire as a real error, just keeps the connection alive).
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

    // ── assemble_witness_coinbase — byte-identical to SV1's path ──────

    /// Pin the BIP-141 witness layout: marker `0x00` + flag `0x01`
    /// right after the 4-byte `version`, then a 1-byte witness-stack
    /// length (`0x01`) + 1-byte item length (`0x20`) + 32 zero bytes
    /// inserted right before the trailing 4-byte `locktime`.
    #[test]
    fn assemble_witness_coinbase_pins_bip141_layout() {
        // Minimal coinbase: 4B version + 4B body + 4B locktime = 12B.
        let mut stratum = Vec::with_capacity(12);
        stratum.extend_from_slice(&1u32.to_le_bytes()); // version=1
        stratum.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // body
        stratum.extend_from_slice(&[0xEE, 0xEE, 0xEE, 0xEE]); // locktime
        let w = assemble_witness_coinbase(&stratum);
        // 12 stratum bytes + 2 marker/flag + 1 stack-count + 1 item-len
        // + 32 witness bytes = 48.
        assert_eq!(w.len(), 12 + 2 + 1 + 1 + 32);
        // Version intact.
        assert_eq!(&w[..4], &1u32.to_le_bytes());
        // Marker + flag.
        assert_eq!(w[4], 0x00);
        assert_eq!(w[5], 0x01);
        // Body intact.
        assert_eq!(&w[6..10], &[0xAA, 0xBB, 0xCC, 0xDD]);
        // Witness stack: count=1, len=0x20, 32 zero bytes.
        assert_eq!(w[10], 0x01);
        assert_eq!(w[11], 0x20);
        assert!(w[12..44].iter().all(|b| *b == 0));
        // Locktime intact.
        assert_eq!(&w[44..], &[0xEE, 0xEE, 0xEE, 0xEE]);
    }

    #[test]
    fn assemble_witness_coinbase_matches_mining_job_for_segwit_round_trip() {
        // Build a real MiningJob (SV1's coinbase shape) + a synthetic
        // 12-byte extranonce, then compare the witness-form output of
        // both the MiningJob helper and our SV2-side assembler over
        // the same stratum-coinbase bytes.
        use bitcoin::Network;
        use bp_mining_job::{build_mining_job, CoinbaseTemplate, PayoutEntry, EXTRANONCE_SLOT_LEN};

        let payouts = [PayoutEntry {
            address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string(),
            percent: 100.0,
        }];
        let template = CoinbaseTemplate {
            block_height: 42,
            coinbase_value_sats: 5_000_000_000,
            witness_commitment: [0x77; 32],
        };
        let job = build_mining_job(
            Network::Regtest,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
        )
        .expect("ok");
        let enonce1 = [0xAA; 4];
        let enonce2 = [0xBB; 8];

        // SV1's path: build witness coinbase from the MiningJob helpers.
        let sv1_witness = job.witness_coinbase_with_extranonce(&enonce1, &enonce2);

        // SV2's path: reconstruct the stratum coinbase the same way
        // `validate_submit_extended` does (prefix + extranonce slot
        // + suffix), then run the witness assembler.
        let mut stratum = Vec::new();
        stratum.extend_from_slice(job.coinbase_prefix());
        stratum.extend_from_slice(&enonce1);
        stratum.extend_from_slice(&enonce2);
        stratum.extend_from_slice(job.coinbase_suffix());
        let sv2_witness = assemble_witness_coinbase(&stratum);

        assert_eq!(
            sv1_witness, sv2_witness,
            "SV1's MiningJob::witness_coinbase_with_extranonce and SV2's \
             assemble_witness_coinbase MUST produce byte-identical output \
             over the same stratum-coinbase input"
        );
    }

    // ── ext 0x0002 Worker-ID TLV resolution in validate_submit_extended ──

    fn worker_id_tlv_bytes(user_identity: &str) -> Vec<u8> {
        // Hand-built wire-form TLV: [ext_type 0x0002 BE][field_type 0x01]
        // [length BE16][value bytes]. Mirrors ext 0x0002 §1.1.
        let value = user_identity.as_bytes();
        let mut tlv = Vec::with_capacity(5 + value.len());
        tlv.extend_from_slice(&0x0002u16.to_be_bytes());
        tlv.push(0x01);
        tlv.extend_from_slice(&(value.len() as u16).to_be_bytes());
        tlv.extend_from_slice(value);
        tlv
    }

    /// ext 0x0002 negotiated + valid TLV → `ShareAccept.effective_worker_name`
    /// carries the TLV value (spec §1.3).
    #[test]
    fn ext_0x0002_tlv_present_when_negotiated_sets_effective_worker_name() {
        let mut ch = ext_channel();
        let job = ext_job([0xCC; 32], 0x1d00_ffff);
        let mut sub = ext_submission();
        sub.tail_tlvs = worker_id_tlv_bytes("Worker_001");

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

    /// ext 0x0002 NOT negotiated + TLV present → resolver ignores the
    /// TLV (spec §1.3 "server MUST ignore unexpected TLV fields") →
    /// effective_worker_name is None (caller falls back to channel-default).
    #[test]
    fn ext_0x0002_tlv_present_when_not_negotiated_is_ignored() {
        let mut ch = ext_channel();
        let job = ext_job([0xCC; 32], 0x1d00_ffff);
        let mut sub = ext_submission();
        sub.tail_tlvs = worker_id_tlv_bytes("Worker_001");

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
                    "non-negotiated TLV must be silently dropped (spec §1.3)"
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
        let sub = ext_submission(); // tail_tlvs is empty.

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
