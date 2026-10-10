// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure handler layer for the SV2 mining-protocol per-connection state machine:
//! no I/O, no DB writes. Each handler mutates the session state and returns a
//! [`HandlerOutcome`] of [`OutboundFrame`]s and [`SessionEvent`]s for `server.rs`.
//! Standard jobs are retired, not cleared, on a block change so late shares get `stale-share`.

use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::Network;
use bp_common::{normalize_btc_address, AddressId, StreamKind};
use bp_jobs_lifecycle::LifecycleConfig;
use bp_mining_job::{
    address_to_script, merkle_root_from_coinbase, MiningJob, MiningJobCache, MiningJobError,
    PayoutEntry, TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
};
use bp_share::{
    clamp_difficulty_to_max_target, difficulty_to_target, hash_rate_to_difficulty, sha256d,
    Difficulty, Target,
};
use bp_stats::MAX_REASONABLE_DIFFICULTY;
use bp_vardiff::{Clock, VarDiffEngine};

use crate::codec_common::SetupConnectionInput;
use crate::extensions::{
    RequestExtensions, SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS, SV2_EXTENSION_TYPE_WORKER_ID,
};
use crate::protocol_version::{negotiate_version, MIN_PROTOCOL_VERSION};

use super::channel::{ChannelKind, ChannelState};
use super::groups::GroupChannelRegistry;
use super::jobs::{cleanup_retired_extended_jobs, retire_extended_jobs, ExtendedJob};
#[cfg(test)]
use super::submit::ExtranonceBytes;
use super::submit::{
    validate_submit_extended, validate_submit_standard, ExtendedChannelView, RejectReason,
    ShareAccept, ShareReject, ShareValidation, StandardJobContext, SubmitSharesExtendedInput,
    SubmitSharesStandardInput,
};
use super::translator::TemplateBroadcast;
use bp_template_distribution::TemplateChange;

// ── SetupConnection flags ──────────────────────────────────────────
// (BIP-310 / SV2 Mining/SetupConnection Flags for Mining Protocol)

/// Protocol code for the mining sub-protocol (the `protocol` field of
/// SV2 Overview/SetupConnection).
pub const PROTOCOL_MINING: u8 = 0;
/// Protocol code for the template-distribution sub-protocol (same field).
/// A setup with it marks the session `is_tdp_client`; no mining jobs are
/// sent to it.
pub const PROTOCOL_TEMPLATE_DISTRIBUTION: u8 = 2;

/// Miner REQUIRES standard mining jobs (no extranonce rolling).
pub const FLAG_REQUIRES_STANDARD_JOBS: u32 = 1 << 0;
/// Miner REQUIRES work selection (BIP-310 §3 — JDC integration).
pub const FLAG_REQUIRES_WORK_SELECTION: u32 = 1 << 1;
/// Miner REQUIRES BIP-323 version-rolling support. Nothing reads this bit:
/// rolling is granted unconditionally ([`VERSION_ROLLING_ALLOWED`]).
pub const FLAG_REQUIRES_VERSION_ROLLING: u32 = 1 << 2;

/// `version_rolling_allowed` on every extended job, whatever the client asked:
/// the client flag only obliges rolling when required
/// (SV2 Mining/SetupConnection Flags for Mining Protocol), while `false` would bind
/// the miner. Matches [`FLAG_SUCCESS_REQUIRES_FIXED_VERSION`] staying clear.
pub const VERSION_ROLLING_ALLOWED: bool = true;

// `SetupConnection.Success.flags` is a separate server→client bitset whose bit
// meanings are unrelated to the client request flags above; only indices 0/1 coincide.
/// Server will NOT accept version-field changes. Per spec MUST NOT be set if
/// the client requested [`FLAG_REQUIRES_VERSION_ROLLING`].
pub const FLAG_SUCCESS_REQUIRES_FIXED_VERSION: u32 = 1 << 0;
/// Server will NOT accept opening of standard channels (extended channels only).
pub const FLAG_SUCCESS_REQUIRES_EXTENDED_CHANNELS: u32 = 1 << 1;

/// Maximum miner-rollable extranonce bytes on an Extended channel: room for an
/// aggregating proxy to subdivide, while prefix + rollable stays within the SV2
/// 32-byte cap. A larger `min_extranonce_size` is rejected with
/// [`ERR_MIN_EXTRANONCE_SIZE_TOO_LARGE`] rather than silently under-granted.
pub const MAX_EXTENDED_ROLLABLE: usize = 16;

// ── Wire error codes (SV2 spec setup/open-channel error strings) ────

/// `unknown-user` — the address parsed out of `user_identity` failed
/// `bp_common::normalize_btc_address` validation.
pub const ERR_UNKNOWN_USER: &str = "unknown-user";

/// `max-target-out-of-range` — miner's declared `max_target` is below
/// the pool's enforced floor (would require a harder target than the
/// pool is willing to assign).
pub const ERR_MAX_TARGET_OUT_OF_RANGE: &str = "max-target-out-of-range";

/// `address-locked` — multi-channel connection sent an
/// `OpenMiningChannel` request whose `user_identity` resolves to a
/// different address than the connection's first channel.
pub const ERR_ADDRESS_LOCKED: &str = "address-locked";

/// `min-extranonce-size-too-large` — requested `min_extranonce_size` exceeds
/// [`MAX_EXTENDED_ROLLABLE`]. Pool rule, not a spec MUST: a silently smaller
/// region would make an aggregating proxy tear down the upstream.
pub const ERR_MIN_EXTRANONCE_SIZE_TOO_LARGE: &str = "min-extranonce-size-too-large";

/// `invalid-channel-id` — `UpdateChannel` / `CloseChannel` referenced
/// an unknown channel on this connection.
pub const ERR_INVALID_CHANNEL_ID: &str = "invalid-channel-id";

/// `invalid-job-id` — used in `SetCustomMiningJob.Error` when the
/// channel kind isn't Extended (custom jobs are Extended-only per
/// SV2 spec — Standard channels don't have an extranonce slot).
pub const ERR_INVALID_JOB_ID: &str = "invalid-job-id";

/// `invalid-job-param-value-token-mismatch` — the `mining_job_token` was
/// declared under a different miner address than the channel's locked one
/// (see [`handle_set_custom_mining_job`]'s `bridge_job`).
pub const ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH: &str = "invalid-job-param-value-token-mismatch";

/// `invalid-mining-job-token` — the token resolves to no declared job and the
/// job references no ext-0x0003 distribution. Fail-closed: without either there
/// is nothing a non-custodial pool could validate the coinbase against.
pub const ERR_INVALID_MINING_JOB_TOKEN: &str = "invalid-mining-job-token";

/// `stale-chain-tip` — `prev_hash` differs from the tip the declaration was
/// accepted under. The exact string matters: JDCs treat it as retryable and
/// every other declaration error as fatal.
pub const ERR_STALE_CHAIN_TIP: &str = "stale-chain-tip";

/// `custom-jobs-require-solo` — a base-protocol custom job on a non-Solo stream:
/// its shares would enter shared accounting with nothing checking that the
/// self-built coinbase pays it. With an ext 0x0003 distribution reference the
/// ext 0x0003/Output Verification check enforces the split, so non-Solo is fine.
pub const ERR_CUSTOM_JOB_REQUIRES_SOLO: &str = "custom-jobs-require-solo";

/// `invalid-nbits` — a custom job on the pool's own tip whose `n_bits` is not
/// what the pool served. The block-candidate threshold derives from it, so a
/// trivial `n_bits` would record every share as a found block. Across a tip
/// change a mismatch is the ordinary stale race and gets [`ERR_STALE_CHAIN_TIP`].
pub const ERR_INVALID_NBITS: &str = "invalid-nbits";

/// `invalid-job-param-value-coinbase_tx_outputs` — the coinbase does not pay
/// what the pool is owed (ext 0x0003/Payout Computation, or the
/// SV2 JDP/AllocateMiningJobToken.Success pool payout output), or did not parse.
/// One code for both regimes: the JDC's remedy is the same.
pub const ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS: &str =
    "invalid-job-param-value-coinbase_tx_outputs";

/// `invalid-job-param-value-declaration-mismatch` — the job differs from the one
/// the token was declared for (coinbase or merkle path). One code for every
/// field because the remedy is identical; the differing field is WARN-logged.
/// The check lives in [`crate::jdp::custom_job_binding`].
pub const ERR_INVALID_JOB_PARAM_DECLARATION_MISMATCH: &str =
    "invalid-job-param-value-declaration-mismatch";

/// `stale-payout-distribution` — the `distribution_id` referenced by this
/// `SetCustomMiningJob` is outside the acceptance window
/// (ext 0x0003/Grace Window + Implementation Notes). The JDC re-declares
/// against the latest distribution.
pub const ERR_STALE_PAYOUT_DISTRIBUTION: &str =
    crate::extensions::payout_distribution_error_codes::STALE_PAYOUT_DISTRIBUTION;

/// `invalid-payout-distribution` — the job's coinbase outputs violate
/// ext 0x0003/Payout Computation against the referenced distribution, or the
/// ext 0x0003/distribution_id TLV Field is missing on a negotiated
/// Coinbase-only custom job.
pub const ERR_INVALID_PAYOUT_DISTRIBUTION: &str =
    crate::extensions::payout_distribution_error_codes::INVALID_PAYOUT_DISTRIBUTION;

/// SV2 mining-side extensions: Worker-ID TLV (0x0002) and Non-Custodial Payouts
/// (0x0003), which ext 0x0003/Negotiation requires on BOTH the JDP and the
/// Mining connection; the mining side carries the distribution_id TLV.
pub const SUPPORTED_MINING_EXTENSIONS: &[u16] = &[
    SV2_EXTENSION_TYPE_WORKER_ID,
    SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS,
];

fn is_mining_extension_supported(ext: u16) -> bool {
    SUPPORTED_MINING_EXTENSIONS.contains(&ext)
}

// ── Inputs (typed wrappers over deserialized SV2 frames) ────────────

/// Inputs from a deserialized `OpenStandardMiningChannel` frame.
#[derive(Clone, Debug)]
pub struct OpenStandardMiningChannelInput {
    pub request_id: u32,
    pub user_identity: String,
    pub nominal_hash_rate: f32,
    /// 32-byte LE U256 — the miner's declared maximum target. Pool MUST
    /// NOT assign harder targets.
    pub max_target: [u8; 32],
}

/// Inputs from a deserialized `OpenExtendedMiningChannel` frame.
#[derive(Clone, Debug)]
pub struct OpenExtendedMiningChannelInput {
    pub request_id: u32,
    pub user_identity: String,
    pub nominal_hash_rate: f32,
    pub max_target: [u8; 32],
    pub min_extranonce_size: u16,
}

/// Inputs from a deserialized `UpdateChannel` frame.
#[derive(Clone, Debug)]
pub struct UpdateChannelInput {
    pub channel_id: u32,
    pub nominal_hash_rate: f32,
    pub maximum_target: [u8; 32],
}

/// Inputs from a deserialized `CloseChannel` frame.
#[derive(Clone, Debug)]
pub struct CloseChannelInput {
    pub channel_id: u32,
    pub reason_code: String,
}

// ── OutboundFrame ───────────────────────────────────────────────────

/// What the handler decided to send; the IO layer serializes it. A separate
/// enum keeps the handler free of the wire types' lifetimes.
#[derive(Clone, Debug, PartialEq)]
pub enum OutboundFrame {
    SetupConnectionSuccess {
        used_version: u16,
        flags: u32,
    },
    SetupConnectionError {
        flags: u32,
        error_code: String,
    },
    /// Ext 0x0001 success with the supported subset of the request. An empty
    /// request also gets `Success`: ext 0x0001/Implementation Notes only
    /// requires `Error` when NONE of the requested extensions are supported.
    RequestExtensionsSuccess {
        request_id: u16,
        supported_extensions: Vec<u16>,
    },
    /// Ext 0x0001 error: NONE of the requested extensions are supported.
    RequestExtensionsError {
        request_id: u16,
        unsupported_extensions: Vec<u16>,
        required_extensions: Vec<u16>,
    },
    OpenStandardMiningChannelSuccess {
        request_id: u32,
        channel_id: u32,
        target: [u8; 32],
        extranonce_prefix: Vec<u8>,
        /// 0 for un-grouped channels.
        group_channel_id: u32,
    },
    OpenExtendedMiningChannelSuccess {
        request_id: u32,
        channel_id: u32,
        target: [u8; 32],
        /// Rollable extranonce size only, NOT including the pool prefix.
        extranonce_size: u16,
        extranonce_prefix: Vec<u8>,
        /// Group this channel was assigned to (SV2 Mining/Group Channel), `0`
        /// when un-grouped. The downstream infers membership from this id; no
        /// `SetGroupChannel` is sent.
        group_channel_id: u32,
    },
    OpenMiningChannelError {
        request_id: u32,
        error_code: String,
    },
    SetTarget {
        channel_id: u32,
        maximum_target: [u8; 32],
    },
    /// SV2 Mining/SetExtranoncePrefix — applies to jobs sent *after* it, so the
    /// caller emits it right before the next job frame. Not valid on group
    /// channels.
    SetExtranoncePrefix {
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
    },
    /// SV2 Mining/SetNewPrevHash — activates the future job sent just before it
    /// on the same channel; `job_id` MUST match that frame.
    SetNewPrevHash {
        channel_id: u32,
        job_id: u32,
        prev_hash: [u8; 32],
        min_ntime: u32,
        n_bits: u32,
    },
    /// SV2 Mining/NewMiningJob — Standard channels only; the merkle root already
    /// includes the channel's extranonce prefix. `min_ntime: None` marks a
    /// FUTURE job activated by the following `SetNewPrevHash`; `Some` an active
    /// job on the current prev-hash, sent alone.
    NewMiningJob {
        channel_id: u32,
        job_id: u32,
        version: u32,
        merkle_root: [u8; 32],
        min_ntime: Option<u32>,
    },
    /// SV2 Mining/NewExtendedMiningJob — Extended channels only. `min_ntime`
    /// follows the same future (`None`) / active (`Some`) rule as `NewMiningJob`.
    NewExtendedMiningJob {
        channel_id: u32,
        job_id: u32,
        version: u32,
        version_rolling_allowed: bool,
        merkle_path: Vec<[u8; 32]>,
        coinbase_tx_prefix: Vec<u8>,
        coinbase_tx_suffix: Vec<u8>,
        min_ntime: Option<u32>,
    },
    SubmitSharesSuccess {
        channel_id: u32,
        last_sequence_number: u32,
        new_submits_accepted_count: u32,
        new_shares_sum: u64,
    },
    SubmitSharesError {
        channel_id: u32,
        sequence_number: u32,
        error_code: String,
    },
    UpdateChannelError {
        channel_id: u32,
        error_code: String,
    },
    /// `SetCustomMiningJob.Success`; `job_id` is channel-local and used in the
    /// JDC's subsequent `SubmitSharesExtended` frames.
    SetCustomMiningJobSuccess {
        channel_id: u32,
        request_id: u32,
        job_id: u32,
    },
    /// `SetCustomMiningJob.Error` with one of the `ERR_*` codes above
    /// (token ownership is checked via [`crate::bridge::JdpDeclaredJobRegistry`]).
    SetCustomMiningJobError {
        channel_id: u32,
        request_id: u32,
        error_code: String,
    },
}

// ── SessionEvent ────────────────────────────────────────────────────

/// What the handler decided about the session beyond the wire frames; the IO
/// layer drives the hooks (DB, stats, block-submit) from these.
#[derive(Clone, Debug)]
pub enum SessionEvent {
    /// `SetupConnection` completed.
    SetupComplete,
    /// Close the connection once the pending frames are on the wire, so the
    /// `SetupConnection.Error` goes out first (SV2 Overview/SetupConnection.Error).
    Disconnect { reason: String },
    /// A new mining channel opened.
    ChannelOpened {
        channel_id: u32,
        address: AddressId,
        worker: String,
        kind: ChannelKind,
    },
    /// Channel closed; the caller releases its extranonce prefix.
    ChannelClosed { channel_id: u32, reason: String },
    /// Channel difficulty changed (vardiff or `UpdateChannel`).
    DifficultyChanged { old: Difficulty, new: Difficulty },
    /// Share accepted, with the validation result for accounting and the
    /// block-found path.
    ShareAccepted {
        channel_id: u32,
        accept: Box<ShareAccept>,
    },
    /// Share rejected.
    ShareRejected {
        channel_id: u32,
        reject: ShareReject,
    },
}

// ── HandlerOutcome ──────────────────────────────────────────────────

/// What a single handler call produced; both empty for a silently ignored frame.
#[derive(Clone, Debug, Default)]
pub struct HandlerOutcome {
    pub outbound: Vec<OutboundFrame>,
    pub events: Vec<SessionEvent>,
}

impl HandlerOutcome {
    fn with_frame(frame: OutboundFrame) -> Self {
        Self {
            outbound: vec![frame],
            events: Vec::new(),
        }
    }

    fn push_frame(&mut self, frame: OutboundFrame) {
        self.outbound.push(frame);
    }

    fn push_event(&mut self, event: SessionEvent) {
        self.events.push(event);
    }
}

// ── MiningSessionState ──────────────────────────────────────────────

/// All per-connection mutable state for the mining sub-protocol.
///
/// Difficulty is per channel: each has its own vardiff engine and max target,
/// so channels never pool their share rate. The first channel locks `address`.
pub struct MiningSessionState<C: Clock> {
    // Identity
    pub session_id: u32,
    pub network: Network,
    pub address: Option<AddressId>,
    pub worker_name: String,
    /// User agent derived from the SetupConnection `vendor`; `None` when the
    /// vendor normalises to nothing.
    pub user_agent: Option<String>,
    /// TDP template stream, fixed at OpenChannel so the block-submit handle
    /// always matches the template the job was built on. A mid-connection mode
    /// change does NOT move it; see [`Self::accounting_stream`].
    pub stream: StreamKind,
    /// Which accounting the shares enter, re-resolved on every `SetCustomMiningJob`.
    /// Diverges from [`Self::stream`] after a live mode change or when the alt
    /// stream is unwired. Every accounting question reads this one; only template
    /// and submit routing read `stream`.
    pub accounting_stream: StreamKind,

    // Negotiated state from SetupConnection
    pub setup_complete: bool,
    // No `version_rolling` field: every job serves `VERSION_ROLLING_ALLOWED`.
    pub work_selection: bool,
    pub requires_standard_jobs: bool,
    pub is_tdp_client: bool,

    // Extensions negotiated via ext 0x0001. A `Vec`, not a set: the read loop
    // hands it to the frame parser as `&[u16]` on every inbound frame.
    pub negotiated_extensions: Vec<u16>,

    // Channels
    pub channels: HashMap<u32, ChannelState>,
    pub primary_channel: Option<u32>,
    /// Connection-local channel-id counter. Also the source of
    /// `group_channel_id`s, which share the namespace (SV2 Mining/Group Channel).
    pub next_channel_id: u32,
    /// SV2 group channels: Extended channels of a non-`REQUIRES_STANDARD_JOBS`
    /// connection grouped by full extranonce size, so the broadcast sends ONE
    /// job per group. Empty for standard-jobs / TDP / JDC connections.
    pub groups: GroupChannelRegistry,

    // Vardiff state
    /// One vardiff engine per channel id, so several channels on one connection
    /// don't combine into one inflated share rate.
    pub vardiff: HashMap<u32, VarDiffEngine<C>>,

    // Clock + per-port config
    pub clock: C,
    pub min_difficulty: Difficulty,
    /// Port start difficulty (already raised to `min_difficulty`). Floors the
    /// initial assigned difficulty so a miner that under-reports
    /// `nominal_hash_rate` is never pinned to a trivial target.
    pub initial_difficulty: Difficulty,
    pub target_shares_per_minute: f64,
    /// Cadence of the connection's vardiff tick in milliseconds.
    pub vardiff_interval_ms: u64,
    /// Job lifecycle handed to every channel this connection opens.
    pub job_lifecycle: LifecycleConfig,
    /// Clock reading of the last vardiff evaluation, timer or inline; see
    /// [`Self::vardiff_cooldown_elapsed`].
    pub last_difficulty_check_ms: u64,

    /// Per-share diagnostic logging toggle (`stratum_share_logs`).
    pub share_logs: bool,

    /// `true` once a customer extranonce override was found at channel-open.
    /// Lets the broadcast hot path skip the override logic with one bool test
    /// for every other connection.
    pub uses_custom_extranonce: bool,
}

/// Per-port config slice passed at construction.
#[derive(Clone, Copy, Debug)]
pub struct PortConfig {
    pub network: Network,
    /// Hard floor — vardiff never retargets below this.
    pub min_difficulty: Difficulty,
    /// First difficulty advertised on channel open.
    pub initial_difficulty: Difficulty,
    pub target_shares_per_minute: f64,
    /// Cadence of the vardiff check loop in milliseconds.
    pub vardiff_interval_ms: u64,
    /// Job lifecycle every channel opened on this port ages its jobs under.
    pub job_lifecycle: LifecycleConfig,
}

impl<C: Clock + Clone> MiningSessionState<C> {
    pub fn new(clock: C, session_id: u32, port: PortConfig) -> Self {
        Self {
            session_id,
            network: port.network,
            address: None,
            worker_name: String::new(),
            user_agent: None,
            stream: StreamKind::Pplns,
            accounting_stream: StreamKind::Pplns,
            setup_complete: false,
            work_selection: false,
            requires_standard_jobs: false,
            is_tdp_client: false,
            negotiated_extensions: Vec::new(),
            channels: HashMap::new(),
            primary_channel: None,
            next_channel_id: 1,
            groups: GroupChannelRegistry::new(),
            vardiff: HashMap::new(),
            clock,
            min_difficulty: port.min_difficulty,
            initial_difficulty: Difficulty(
                port.initial_difficulty
                    .as_f64()
                    .max(port.min_difficulty.as_f64()),
            ),
            target_shares_per_minute: port.target_shares_per_minute,
            vardiff_interval_ms: port.vardiff_interval_ms,
            job_lifecycle: port.job_lifecycle,
            last_difficulty_check_ms: 0,
            share_logs: false,
            uses_custom_extranonce: false,
        }
    }

    /// Put this connection on `stream`, template routing and accounting
    /// together, so a caller cannot set one and leave the other on the boot value.
    pub fn set_stream(&mut self, stream: StreamKind) {
        self.stream = stream;
        self.accounting_stream = stream;
    }

    /// Whether the post-share inline vardiff check may run again, so not every
    /// share re-sweeps every engine. The timer arm is deliberately NOT gated:
    /// it is the only trigger that fires when no shares arrive.
    pub fn vardiff_cooldown_elapsed(&self) -> bool {
        self.clock
            .now_ms()
            .saturating_sub(self.last_difficulty_check_ms)
            >= self.vardiff_interval_ms
    }

    /// Stamp the current clock reading as the last vardiff evaluation.
    pub fn mark_vardiff_checked(&mut self) {
        self.last_difficulty_check_ms = self.clock.now_ms();
    }

    /// Register an opened channel with its vardiff engine; the first one
    /// becomes the primary channel.
    fn add_channel(&mut self, channel_id: u32, channel: ChannelState, difficulty: Difficulty) {
        self.channels.insert(channel_id, channel);
        let engine = self.new_channel_vardiff(difficulty);
        self.vardiff.insert(channel_id, engine);
        if self.primary_channel.is_none() {
            self.primary_channel = Some(channel_id);
        }
    }

    /// A fresh vardiff engine for a newly opened channel, opening at the
    /// difficulty the channel was assigned.
    fn new_channel_vardiff(&self, assigned_difficulty: Difficulty) -> VarDiffEngine<C> {
        VarDiffEngine::new(
            self.clock.clone(),
            self.target_shares_per_minute,
            self.min_difficulty.as_f64(),
            assigned_difficulty.as_f64(),
        )
    }
}

// ── Handler: SetupConnection ────────────────────────────────────────

/// `SetupConnection.Error` plus the request to close. The frame goes out before
/// the close (SV2 Overview/SetupConnection.Error), or the client never learns why.
fn setup_rejected(error_code: &str, reason: String) -> HandlerOutcome {
    let mut outcome = HandlerOutcome::with_frame(OutboundFrame::SetupConnectionError {
        flags: 0,
        error_code: error_code.to_string(),
    });
    outcome.events.push(SessionEvent::Disconnect { reason });
    outcome
}

/// `"{vendor}/sv2"`: the user agent a connection's SetupConnection `vendor`
/// is recorded under (`bitaxe/sv2`, `NerdQAxe++/sv2`), with the vendor
/// normalised the way SV1 normalises its user agent
/// ([`bp_common::normalize_user_agent`]); `None` when that leaves nothing.
pub(crate) fn vendor_user_agent(vendor: &str) -> Option<String> {
    let normalized = bp_common::normalize_user_agent(vendor);
    (!normalized.is_empty()).then(|| format!("{normalized}/sv2"))
}

/// Handle `SetupConnection`: a version range without a common version or an
/// unknown sub-protocol is refused; otherwise `SetupConnectionSuccess`, whose
/// `flags` are the server capability bits, built fresh.
pub fn handle_setup_connection<C: Clock>(
    state: &mut MiningSessionState<C>,
    input: &SetupConnectionInput,
) -> HandlerOutcome {
    let Some(used_version) = negotiate_version(input.min_version, input.max_version) else {
        return setup_rejected(
            crate::codec_common::ERR_PROTOCOL_VERSION_MISMATCH,
            format!(
                "version range {}–{} does not include {MIN_PROTOCOL_VERSION}",
                input.min_version, input.max_version
            ),
        );
    };

    // Mining (0) and TDP-only (2) are accepted. A TDP-only session gets no
    // mining jobs (`apply_template_broadcast` returns early) and is never
    // grouped.
    match input.protocol {
        PROTOCOL_MINING => {}
        PROTOCOL_TEMPLATE_DISTRIBUTION => {
            state.is_tdp_client = true;
        }
        other => {
            return setup_rejected(
                crate::codec_common::ERR_UNSUPPORTED_PROTOCOL,
                format!("protocol {other} is not served on this port"),
            );
        }
    }

    state.setup_complete = true;
    state.user_agent = vendor_user_agent(&input.vendor);
    state.requires_standard_jobs = (input.flags & FLAG_REQUIRES_STANDARD_JOBS) != 0;
    state.work_selection = (input.flags & FLAG_REQUIRES_WORK_SELECTION) != 0;

    // Build `Success.flags` fresh, NEVER echo `input.flags`: an echo would map
    // REQUIRES_STANDARD_JOBS onto REQUIRES_FIXED_VERSION. A work-selection
    // connection can only carry custom jobs on an Extended channel, so it gets
    // REQUIRES_EXTENDED_CHANNELS.
    let response_flags = if state.work_selection {
        FLAG_SUCCESS_REQUIRES_EXTENDED_CHANNELS
    } else {
        0
    };

    HandlerOutcome {
        outbound: vec![OutboundFrame::SetupConnectionSuccess {
            used_version,
            flags: response_flags,
        }],
        events: vec![SessionEvent::SetupComplete],
    }
}

// ── Handler: RequestExtensions (ext 0x0001) ─────────────────────────

/// Handle `RequestExtensions` (ext 0x0001) against [`SUPPORTED_MINING_EXTENSIONS`].
/// A pre-setup request is silently dropped: ext 0x0001/Implementation Notes
/// requires it after `SetupConnection.Success`, and answering would let a client
/// skip the handshake.
pub fn handle_request_extensions<C: Clock>(
    state: &mut MiningSessionState<C>,
    input: &RequestExtensions,
) -> HandlerOutcome {
    if !state.setup_complete {
        return HandlerOutcome::default();
    }

    let mut supported = Vec::new();
    let mut unsupported = Vec::new();
    for &ext in &input.requested_extensions {
        if is_mining_extension_supported(ext) {
            supported.push(ext);
            if !state.negotiated_extensions.contains(&ext) {
                state.negotiated_extensions.push(ext);
            }
        } else {
            unsupported.push(ext);
        }
    }

    if supported.is_empty() && !input.requested_extensions.is_empty() {
        return HandlerOutcome::with_frame(OutboundFrame::RequestExtensionsError {
            request_id: input.request_id,
            unsupported_extensions: unsupported,
            required_extensions: Vec::new(),
        });
    }

    HandlerOutcome::with_frame(OutboundFrame::RequestExtensionsSuccess {
        request_id: input.request_id,
        supported_extensions: supported,
    })
}

// ── Handler: OpenStandardMiningChannel ──────────────────────────────

/// Handle `OpenStandardMiningChannel`. The IO layer allocates
/// `extranonce_prefix`, because allocations are pool-global.
pub fn handle_open_standard_mining_channel<C: Clock + Clone>(
    state: &mut MiningSessionState<C>,
    input: &OpenStandardMiningChannelInput,
    extranonce_prefix: Vec<u8>,
) -> HandlerOutcome {
    let ctx = match resolve_open_context(
        state,
        &input.user_identity,
        input.nominal_hash_rate,
        input.max_target,
        input.request_id,
    ) {
        Ok(c) => c,
        Err(err_frame) => return HandlerOutcome::with_frame(err_frame),
    };

    let channel_id = state.next_channel_id;
    state.next_channel_id = state.next_channel_id.saturating_add(1);

    let channel = ChannelState::new_standard(
        channel_id,
        extranonce_prefix.clone(),
        ctx.assigned_difficulty,
        input.max_target,
        state.job_lifecycle,
    );
    state.add_channel(channel_id, channel, ctx.assigned_difficulty);

    // Standard channels are never grouped: a header-only device can't process
    // the group-addressed `NewExtendedMiningJob` a group rides.
    HandlerOutcome {
        outbound: vec![OutboundFrame::OpenStandardMiningChannelSuccess {
            request_id: input.request_id,
            channel_id,
            target: difficulty_to_target(ctx.assigned_difficulty).to_le_bytes(),
            extranonce_prefix,
            group_channel_id: 0,
        }],
        events: vec![SessionEvent::ChannelOpened {
            channel_id,
            address: ctx.address,
            worker: ctx.worker,
            kind: ChannelKind::Standard,
        }],
    }
}

/// Eager SV2 group assignment (SV2 Mining/Group Channel): Extended channels of a
/// connection without `REQUIRES_STANDARD_JOBS`, TDP or work selection are grouped
/// by full extranonce size, so the broadcast sends ONE job per group. Returns the
/// `group_channel_id` (from the channel-id namespace, so never colliding), or `0`.
fn assign_channel_to_group<C: Clock>(
    state: &mut MiningSessionState<C>,
    channel_id: u32,
    full_extranonce_size: usize,
) -> u32 {
    if state.requires_standard_jobs || state.is_tdp_client || state.work_selection {
        return 0;
    }
    let next_channel_id = &mut state.next_channel_id;
    state
        .groups
        .join_group_for_size(channel_id, full_extranonce_size, || {
            let gid = *next_channel_id;
            *next_channel_id = next_channel_id.saturating_add(1);
            gid
        })
}

// ── Handler: OpenExtendedMiningChannel ──────────────────────────────

/// Handle `OpenExtendedMiningChannel`. The rollable region is exactly the
/// requested `min_extranonce_size`, up to [`MAX_EXTENDED_ROLLABLE`]; a larger
/// request gets [`ERR_MIN_EXTRANONCE_SIZE_TOO_LARGE`].
pub fn handle_open_extended_mining_channel<C: Clock + Clone>(
    state: &mut MiningSessionState<C>,
    input: &OpenExtendedMiningChannelInput,
    extranonce_prefix: Vec<u8>,
) -> HandlerOutcome {
    let prefix_len = extranonce_prefix.len();
    // Prefix + rollable must never exceed the SV2 32-byte cap.
    let rollable_cap = MAX_EXTENDED_ROLLABLE.min(32usize.saturating_sub(prefix_len));
    let requested = input.min_extranonce_size as usize;
    if requested > rollable_cap {
        return HandlerOutcome::with_frame(OutboundFrame::OpenMiningChannelError {
            request_id: input.request_id,
            error_code: ERR_MIN_EXTRANONCE_SIZE_TOO_LARGE.to_string(),
        });
    }
    // Grant exactly the requested minimum, never the cap: over-granting could
    // misfeed firmware that assumes a fixed rollable width, while an
    // aggregating proxy still gets the full size it asks for.
    let rollable_size = requested as u8;

    let ctx = match resolve_open_context(
        state,
        &input.user_identity,
        input.nominal_hash_rate,
        input.max_target,
        input.request_id,
    ) {
        Ok(c) => c,
        Err(err_frame) => return HandlerOutcome::with_frame(err_frame),
    };

    let channel_id = state.next_channel_id;
    state.next_channel_id = state.next_channel_id.saturating_add(1);

    let channel = ChannelState::new_extended(
        channel_id,
        extranonce_prefix.clone(),
        rollable_size,
        ctx.assigned_difficulty,
        input.max_target,
        state.job_lifecycle,
    );
    state.add_channel(channel_id, channel, ctx.assigned_difficulty);

    let group_channel_id =
        assign_channel_to_group(state, channel_id, prefix_len + rollable_size as usize);

    HandlerOutcome {
        outbound: vec![OutboundFrame::OpenExtendedMiningChannelSuccess {
            request_id: input.request_id,
            channel_id,
            target: difficulty_to_target(ctx.assigned_difficulty).to_le_bytes(),
            extranonce_size: rollable_size as u16,
            extranonce_prefix,
            group_channel_id,
        }],
        events: vec![SessionEvent::ChannelOpened {
            channel_id,
            address: ctx.address,
            worker: ctx.worker,
            kind: ChannelKind::Extended,
        }],
    }
}

// ── Open-mining-channel shared helper ────────────────────────────────

/// Round a difficulty about to be ASSIGNED to a downstream to a power of two,
/// always UP — [`bp_vardiff::round_up_to_power_of_two`] says why (a translating
/// proxy rounds a crooked target itself and the pool then under-credits the
/// miner). A deliberately sub-1 configured difficulty is left alone.
fn power_of_two_difficulty(diff: Difficulty) -> Difficulty {
    let v = diff.as_f64();
    if !v.is_finite() || v < 1.0 {
        return diff;
    }
    Difficulty(bp_vardiff::round_up_to_power_of_two(v))
}

/// Captured context the kind-specific closure needs.
struct OpenContext {
    address: AddressId,
    worker: String,
    assigned_difficulty: Difficulty,
}

/// Shared Standard/Extended open: address parse and lock, initial difficulty.
/// `Err` is the `OpenMiningChannelError` frame to send.
fn resolve_open_context<C: Clock>(
    state: &mut MiningSessionState<C>,
    user_identity: &str,
    nominal_hash_rate: f32,
    max_target_bytes: [u8; 32],
    request_id: u32,
) -> Result<OpenContext, OutboundFrame> {
    let err = |code: &str| OutboundFrame::OpenMiningChannelError {
        request_id,
        error_code: code.to_string(),
    };

    let (address_part, worker_part) = bp_common::split_user_identity(user_identity);
    if address_part.is_empty() {
        return Err(err(ERR_UNKNOWN_USER));
    }

    // `normalize_btc_address` only normalizes whitespace/casing;
    // `address_to_script` verifies the address parses and matches the network.
    let normalized = normalize_btc_address(address_part);
    if normalized.is_empty() {
        return Err(err(ERR_UNKNOWN_USER));
    }
    address_to_script(state.network, &normalized).map_err(|_| err(ERR_UNKNOWN_USER))?;
    let address = AddressId::new(normalized).map_err(|_| err(ERR_UNKNOWN_USER))?;

    // Later channels MUST resolve to the first channel's address.
    if let Some(existing) = &state.address {
        if existing != &address {
            return Err(err(ERR_ADDRESS_LOCKED));
        }
    }

    let worker = match worker_part {
        Some(w) if !w.is_empty() => w.to_string(),
        _ => "default".to_string(),
    };

    // A positive `nominal_hash_rate` is honoured, bounded only by
    // `min_difficulty`: flooring it at the port's start difficulty would pin a
    // small device well above its own rate. `<= 0` declares nothing, so the
    // configured start applies.
    let floored = if nominal_hash_rate > 0.0 {
        Difficulty(
            hash_rate_to_difficulty(nominal_hash_rate as f64, state.target_shares_per_minute)
                .as_f64()
                .max(state.min_difficulty.as_f64()),
        )
    } else {
        Difficulty(
            state
                .initial_difficulty
                .as_f64()
                .max(state.min_difficulty.as_f64()),
        )
    };
    let clamped = clamp_difficulty_to_max_target(floored, &Target::from_le_bytes(max_target_bytes));
    let assigned_difficulty = if clamped.as_f64() > MAX_REASONABLE_DIFFICULTY {
        return Err(err(ERR_MAX_TARGET_OUT_OF_RANGE));
    } else {
        // Power of two, so a translating proxy has nothing to round on the way
        // to the miner and both sides account for the same number.
        power_of_two_difficulty(clamped)
    };

    if state.address.is_none() {
        state.address = Some(address.clone());
        state.worker_name = worker.clone();
    }

    Ok(OpenContext {
        address,
        worker,
        assigned_difficulty,
    })
}

// ── Handler: SubmitSharesStandard ───────────────────────────────────

/// Vardiff grace: validate against the LOWER of the job's send-time difficulty
/// and the channel's current one, so shares in flight across a retarget in
/// EITHER direction are not lost. Crediting uses the same lower difficulty.
fn graced_validation_difficulty(job_frozen: Difficulty, session: Difficulty) -> Difficulty {
    Difficulty(job_frozen.as_f64().min(session.as_f64()))
}

/// Feed the channel's vardiff with a validated share. An accepted share counts
/// at its credited difficulty, an older job's lower one included.
fn feed_vardiff<C: Clock>(
    state: &mut MiningSessionState<C>,
    channel_id: u32,
    validation: &ShareValidation,
) {
    let Some(engine) = state.vardiff.get_mut(&channel_id) else {
        return;
    };
    match validation {
        ShareValidation::Accepted(accept) => {
            engine.note_share_accepted(accept.effective_difficulty.as_f64());
        }
        ShareValidation::Rejected(reject) => {
            // Only a stale share counts as an arrival (see
            // `VarDiffEngine::note_stale_share`): an unknown job, a duplicate
            // and a below-target or malformed share say nothing about the rate,
            // and SV1 treats them the same way.
            let counts_as_arrival = match reject.reason {
                RejectReason::StaleShare => true,
                RejectReason::InvalidJobId
                | RejectReason::DuplicateShare
                | RejectReason::DifficultyTooLow
                | RejectReason::BadExtranonceSize
                | RejectReason::NtimeOutOfRange
                | RejectReason::NonRollableVersionBit => false,
            };
            if counts_as_arrival {
                engine.note_stale_share();
            }
        }
    }
}

/// The submitting channel, or the error frame: an unknown channel is
/// `invalid-channel-id`, a submit of the other channel kind `invalid-job-id`.
fn submit_channel(
    channels: &mut HashMap<u32, ChannelState>,
    channel_id: u32,
    sequence_number: u32,
    kind: ChannelKind,
) -> Result<&mut ChannelState, HandlerOutcome> {
    let Some(channel) = channels.get_mut(&channel_id) else {
        return Err(submit_error(
            channel_id,
            sequence_number,
            ERR_INVALID_CHANNEL_ID,
        ));
    };
    if channel.kind != kind {
        return Err(submit_error(
            channel_id,
            sequence_number,
            ERR_INVALID_JOB_ID,
        ));
    }
    Ok(channel)
}

/// Handle `SubmitSharesStandard` via [`validate_submit_standard`]. Validation
/// uses the [`StandardTemplateSnapshot`] stored at send time, not the current
/// template, so shares for retired jobs hash against what the miner mined under.
pub fn handle_submit_shares_standard<C: Clock>(
    state: &mut MiningSessionState<C>,
    submission: &SubmitSharesStandardInput,
    now_ms: u64,
) -> HandlerOutcome {
    let channel = match submit_channel(
        &mut state.channels,
        submission.channel_id,
        submission.sequence_number,
        ChannelKind::Standard,
    ) {
        Ok(channel) => channel,
        Err(refused) => return refused,
    };

    // Classify first so retired-but-known jobs get `stale-share`; `None` (never
    // sent or aged past retention) is the real `invalid-job-id`.
    let Some(classification) = channel.standard_jobs.classify(submission.job_id, now_ms) else {
        let reject = ShareReject::from(RejectReason::InvalidJobId);
        return submit_error_with_event(submission.channel_id, submission.sequence_number, reject);
    };

    // The clone lets the validator borrow the channel mutably.
    let entry = channel
        .standard_jobs
        .entry_of(submission.job_id)
        .cloned()
        .expect("classify Some => entry_of Some");

    let job_ctx = StandardJobContext {
        template_version: entry.template_snapshot.version as i32,
        prev_hash: entry.template_snapshot.prev_hash,
        n_bits: entry.template_snapshot.n_bits,
        ntime_start: entry.template_snapshot.ntime_start,
        classification,
        payouts_fingerprint: entry.payouts_fingerprint,
        template_id: entry.template_id,
        coinbase_stratum: &entry.coinbase_stratum,
        coinbase_tx_value_remaining: entry.template_snapshot.coinbase_tx_value_remaining,
    };

    let graced = graced_validation_difficulty(entry.difficulty, channel.session_difficulty);
    let validation =
        validate_submit_standard(channel, submission, graced, &entry.merkle_root, &job_ctx);
    feed_vardiff(state, submission.channel_id, &validation);
    finalize_submit(
        submission.channel_id,
        submission.sequence_number,
        validation,
    )
}

/// Re-export of [`crate::mining::jobs::StandardTemplateSnapshot`].
pub use crate::mining::jobs::StandardTemplateSnapshot;

// ── Handler: SubmitSharesExtended ───────────────────────────────────

/// Handle `SubmitSharesExtended` via [`validate_submit_extended`].
pub fn handle_submit_shares_extended<C: Clock>(
    state: &mut MiningSessionState<C>,
    submission: &SubmitSharesExtendedInput,
    now_ms: u64,
) -> HandlerOutcome {
    let ext_0x0002_negotiated = state
        .negotiated_extensions
        .contains(&crate::extensions::SV2_EXTENSION_TYPE_WORKER_ID);
    let share_logs = state.share_logs;
    let channel = match submit_channel(
        &mut state.channels,
        submission.channel_id,
        submission.sequence_number,
        ChannelKind::Extended,
    ) {
        Ok(channel) => channel,
        Err(refused) => return refused,
    };

    let Some(frozen_difficulty) = channel
        .extended_jobs
        .get(&submission.job_id)
        .map(|j| j.difficulty)
    else {
        let reject = ShareReject::from(RejectReason::InvalidJobId);
        return submit_error_with_event(submission.channel_id, submission.sequence_number, reject);
    };
    let job_difficulty =
        graced_validation_difficulty(frozen_difficulty, channel.session_difficulty);
    // Target first, while `channel` is unborrowed, so the validator gets
    // disjoint borrows and no per-share job clone is needed.
    let job_target = channel.target_for(job_difficulty);
    let ext_job = channel
        .extended_jobs
        .get(&submission.job_id)
        .expect("ext_job presence checked above");
    // The prefix comes off `ext_job`, not the channel: a new prefix only applies
    // from the next job on (SV2 Mining/SetExtranoncePrefix).
    let view = ExtendedChannelView {
        kind: channel.kind,
        extranonce_size: channel.extranonce_size,
        job_target,
        job_lifecycle: *channel.standard_jobs.lifecycle(),
    };

    let validation = validate_submit_extended(
        &mut channel.seen_shares,
        &view,
        submission,
        ext_job,
        job_difficulty,
        now_ms,
        ext_0x0002_negotiated,
        share_logs,
    );
    feed_vardiff(state, submission.channel_id, &validation);
    finalize_submit(
        submission.channel_id,
        submission.sequence_number,
        validation,
    )
}

fn submit_error(channel_id: u32, sequence_number: u32, code: &str) -> HandlerOutcome {
    HandlerOutcome::with_frame(OutboundFrame::SubmitSharesError {
        channel_id,
        sequence_number,
        error_code: code.to_string(),
    })
}

fn submit_error_with_event(
    channel_id: u32,
    sequence_number: u32,
    reject: ShareReject,
) -> HandlerOutcome {
    HandlerOutcome {
        outbound: vec![OutboundFrame::SubmitSharesError {
            channel_id,
            sequence_number,
            error_code: reject.wire_code.to_string(),
        }],
        events: vec![SessionEvent::ShareRejected { channel_id, reject }],
    }
}

fn finalize_submit(
    channel_id: u32,
    sequence_number: u32,
    validation: ShareValidation,
) -> HandlerOutcome {
    match validation {
        ShareValidation::Accepted(accept) => HandlerOutcome {
            outbound: vec![OutboundFrame::SubmitSharesSuccess {
                channel_id,
                last_sequence_number: sequence_number,
                new_submits_accepted_count: 1,
                new_shares_sum: accept.effective_difficulty.as_f64() as u64,
            }],
            events: vec![SessionEvent::ShareAccepted { channel_id, accept }],
        },
        ShareValidation::Rejected(reject) => {
            submit_error_with_event(channel_id, sequence_number, reject)
        }
    }
}

// ── Handler: UpdateChannel ──────────────────────────────────────────

/// Handle `UpdateChannel`: recompute the difficulty from the declared rate and
/// `maximum_target`, `SetTarget` if it changed. The spec defines no success
/// response; unknown channel ids get `UpdateChannelError`.
pub fn handle_update_channel<C: Clock>(
    state: &mut MiningSessionState<C>,
    input: &UpdateChannelInput,
) -> HandlerOutcome {
    let target_shares_per_minute = state.target_shares_per_minute;
    let min_difficulty = state.min_difficulty;
    // What the accumulated silence rules out; `None` for a fresh channel, so a
    // proxy's first real declaration passes untouched.
    let silence_ceiling = state
        .vardiff
        .get(&input.channel_id)
        .and_then(|e| e.silence_implied_max_difficulty());

    let Some(channel) = state.channels.get_mut(&input.channel_id) else {
        return HandlerOutcome::with_frame(OutboundFrame::UpdateChannelError {
            channel_id: input.channel_id,
            error_code: ERR_INVALID_CHANNEL_ID.to_string(),
        });
    };

    channel.declared_max_target = input.maximum_target;

    // A translator re-sends the same claim on a timer; a proxy whose workers
    // just attached sends a DIFFERENT number. Silence can refute only the
    // re-assertion of an old claim, never a new one.
    let repeated_claim = channel.last_declared_hash_rate == Some(input.nominal_hash_rate);
    channel.last_declared_hash_rate = Some(input.nominal_hash_rate);

    let mut raw = hash_rate_to_difficulty(input.nominal_hash_rate as f64, target_shares_per_minute);
    if let Some(ceiling) = silence_ceiling.filter(|_| repeated_claim) {
        if raw.as_f64() > ceiling {
            // Silence rules the repeated claim out; without this cap a
            // translator's re-send would undo the descent every time. Applied
            // before the max-target clamp so the SV2 Mining/UpdateChannel MUST
            // on `maximum_target` still wins.
            raw = Difficulty(ceiling);
        }
    }
    let clamped = clamp_difficulty_to_max_target(raw, &Target::from_le_bytes(input.maximum_target));
    let new_diff = if clamped.as_f64() > MAX_REASONABLE_DIFFICULTY {
        // Keep the existing difficulty rather than accept an unreasonable one.
        return HandlerOutcome::default();
    } else {
        // Power of two as on open, the floor included, so a translating proxy
        // has nothing to round; rounding up keeps it above the floor.
        power_of_two_difficulty(if clamped < min_difficulty {
            min_difficulty
        } else {
            clamped
        })
    };

    if (new_diff.as_f64() - channel.session_difficulty.as_f64()).abs() < f64::EPSILON {
        return HandlerOutcome::default();
    }
    let old = channel.session_difficulty;
    channel.session_difficulty = new_diff;
    if let Some(engine) = state.vardiff.get_mut(&input.channel_id) {
        engine.note_difficulty_assigned(new_diff.as_f64());
    }
    HandlerOutcome {
        outbound: vec![OutboundFrame::SetTarget {
            channel_id: input.channel_id,
            maximum_target: difficulty_to_target(new_diff).to_le_bytes(),
        }],
        events: vec![SessionEvent::DifficultyChanged { old, new: new_diff }],
    }
}

// ── Handler: CloseChannel ───────────────────────────────────────────

/// Handle `CloseChannel`; the connection survives an empty channel set. Closing
/// a group id closes ALL its members (SV2 Mining/CloseChannel), with one
/// [`SessionEvent::ChannelClosed`] each so every extranonce prefix is released.
pub fn handle_close_channel<C: Clock>(
    state: &mut MiningSessionState<C>,
    input: &CloseChannelInput,
) -> HandlerOutcome {
    if state.groups.get(input.channel_id).is_some() {
        let members: Vec<u32> = state
            .groups
            .get(input.channel_id)
            .map(|g| g.channel_ids.iter().copied().collect())
            .unwrap_or_default();
        let mut events = Vec::with_capacity(members.len());
        for member_id in members {
            if state.channels.remove(&member_id).is_some() {
                state.vardiff.remove(&member_id);
                events.push(SessionEvent::ChannelClosed {
                    channel_id: member_id,
                    reason: input.reason_code.clone(),
                });
            }
        }
        state.groups.remove_group(input.channel_id);
        if let Some(pc) = state.primary_channel {
            if !state.channels.contains_key(&pc) {
                state.primary_channel = state.channels.keys().copied().next();
            }
        }
        return HandlerOutcome {
            outbound: Vec::new(),
            events,
        };
    }

    if !state.channels.contains_key(&input.channel_id) {
        // CloseChannel has no wire response.
        return HandlerOutcome::default();
    }
    state.channels.remove(&input.channel_id);
    state.vardiff.remove(&input.channel_id);
    // An emptied group persists; a re-opened same-size channel re-joins it.
    state.groups.remove_channel(input.channel_id);
    if state.primary_channel == Some(input.channel_id) {
        state.primary_channel = state.channels.keys().copied().next();
    }
    HandlerOutcome {
        outbound: Vec::new(),
        events: vec![SessionEvent::ChannelClosed {
            channel_id: input.channel_id,
            reason: input.reason_code.clone(),
        }],
    }
}

// ── apply_vardiff_check ─────────────────────────────────────────────

/// Periodic vardiff tick: each channel retargets from its own
/// [`bp_vardiff::VarDiffEngine::suggested_difficulty`], clamped to its declared
/// max target. JDCs go through the same path: they forward only shares meeting
/// the `SetTarget`, which is the same signal a direct miner produces.
pub fn apply_vardiff_check<C: Clock>(state: &mut MiningSessionState<C>) -> HandlerOutcome {
    let mut outcome = HandlerOutcome::default();
    let MiningSessionState {
        channels, vardiff, ..
    } = state;
    for channel in channels.values_mut() {
        let Some(engine) = vardiff.get_mut(&channel.channel_id) else {
            continue;
        };
        let Some(suggested) = engine.suggested_difficulty(channel.session_difficulty.as_f64())
        else {
            continue;
        };
        // The engine already rounds to a power of two, but the clamp against a
        // declared max_target can land anywhere, so round again after it.
        let clamped = power_of_two_difficulty(clamp_difficulty_to_max_target(
            Difficulty(suggested),
            &Target::from_le_bytes(channel.declared_max_target),
        ));
        if (clamped.as_f64() - channel.session_difficulty.as_f64()).abs() >= f64::EPSILON {
            let old = channel.session_difficulty;
            channel.session_difficulty = clamped;
            // Tell the engine what was assigned, not what it suggested: clamp
            // and rounding sit between, and silence is measured against this.
            engine.note_difficulty_assigned(clamped.as_f64());
            outcome.push_frame(OutboundFrame::SetTarget {
                channel_id: channel.channel_id,
                maximum_target: difficulty_to_target(clamped).to_le_bytes(),
            });
            outcome.push_event(SessionEvent::DifficultyChanged { old, new: clamped });
        }
    }
    outcome
}

// ── MiningJobInputs ─────────────────────────────────────────────────

/// Pre-resolved inputs for [`apply_template_broadcast`]: coinbase template plus
/// the payouts the IO layer resolved once per template via
/// [`crate::hooks::PayoutResolver`]. Each channel gets a [`MiningJob`] sized for
/// its own extranonce slot.
#[derive(Clone, Debug)]
pub struct MiningJobInputs {
    pub network: Network,
    pub payouts: Vec<PayoutEntry>,
    /// Settlement-snapshot identity of the distribution behind `payouts`
    /// (zeroed = no snapshot). Part of the job-cache key.
    pub payouts_fingerprint: [u8; 32],
    pub pool_identifier: String,
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_tx_version: u32,
    pub coinbase_tx_input_sequence: u32,
    pub coinbase_tx_value_remaining: u64,
    pub coinbase_tx_outputs: Vec<u8>,
    pub coinbase_tx_outputs_count: u32,
    pub coinbase_tx_locktime: u32,
    /// Pool-wide job memo keyed on ALL fields above plus the slot size, so
    /// payout sets that differ per finder stay distinct by construction.
    pub job_cache: Arc<MiningJobCache>,
}

impl MiningJobInputs {
    /// Build (or fetch the memoized) [`MiningJob`] with `extranonce_slot_size`
    /// bytes reserved at the tail of the scriptsig.
    pub fn build(&self, extranonce_slot_size: usize) -> Result<Arc<MiningJob>, MiningJobError> {
        let tdp = TdpCoinbaseTemplate {
            coinbase_prefix: &self.coinbase_prefix,
            coinbase_tx_version: self.coinbase_tx_version,
            coinbase_tx_input_sequence: self.coinbase_tx_input_sequence,
            coinbase_tx_value_remaining: self.coinbase_tx_value_remaining,
            coinbase_tx_outputs: &self.coinbase_tx_outputs,
            coinbase_tx_outputs_count: self.coinbase_tx_outputs_count,
            coinbase_tx_locktime: self.coinbase_tx_locktime,
        };
        self.job_cache.get_or_build(
            self.network,
            &self.payouts,
            &tdp,
            &self.pool_identifier,
            extranonce_slot_size,
            self.payouts_fingerprint,
        )
    }
}

/// `(group job template, coinbase_tx_prefix, coinbase_tx_suffix, merkle_path)`
/// from the group-template builder in `apply_template_broadcast`.
type GroupTemplateParts = (ExtendedJob, Vec<u8>, Vec<u8>, Vec<[u8; 32]>);

/// A new block: retire the channel's jobs, age out the expired ones, move
/// the duplicate guard to the new tip (the old tip's hashes stay while its
/// jobs can still be credited) and record the block context later extended
/// jobs carry.
fn retire_for_new_block(
    channel: &mut ChannelState,
    template: &bp_template_distribution::ActiveTemplate,
    now_ms: u64,
) {
    channel.standard_jobs.retire(now_ms);
    channel.standard_jobs.cleanup_expired(now_ms);
    retire_extended_jobs(&mut channel.extended_jobs, now_ms);
    cleanup_retired_extended_jobs(
        &mut channel.extended_jobs,
        now_ms,
        channel.standard_jobs.lifecycle(),
    );
    let lifecycle = *channel.standard_jobs.lifecycle();
    channel
        .seen_shares
        .on_tip(&template.prev_hash, now_ms, &lifecycle);
    channel.latest_extended_prev_hash = Some(template.prev_hash);
    channel.latest_extended_n_bits = Some(template.n_bits);
}

/// The pool-built extended job for `template`, as stored for share validation.
fn extended_job(
    template: &bp_template_distribution::ActiveTemplate,
    mining_job: &MiningJob,
    extranonce_prefix: Vec<u8>,
    difficulty: Difficulty,
    now_ms: u64,
) -> ExtendedJob {
    ExtendedJob {
        coinbase_prefix: mining_job.coinbase_prefix().to_vec(),
        coinbase_suffix: mining_job.coinbase_suffix().to_vec(),
        payouts_fingerprint: *mining_job.payouts_fingerprint(),
        merkle_path: template.merkle_path.clone(),
        version: template.version,
        prev_hash: template.prev_hash,
        n_bits: template.n_bits,
        min_ntime: template.header_timestamp,
        extranonce_prefix,
        difficulty,
        coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
        template_id: Some(template.template_id),
        jdp_claims_the_block: false,
        created_at: now_ms,
        retired_at: None,
    }
}

/// `(merkle_root, coinbase_stratum)` for a Standard channel: its 4-byte prefix
/// plus 8 zero bytes (a Standard channel can't roll) spliced into the
/// [`EXTRANONCE_SLOT_LEN`] slot. The coinbase is kept for the block-found path.
fn standard_member_root_and_coinbase(
    coinbase_prefix: &[u8],
    coinbase_suffix: &[u8],
    extranonce_prefix: &[u8],
    merkle_path: &[[u8; 32]],
) -> ([u8; 32], Vec<u8>) {
    let mut enonce1 = [0u8; 4];
    let copy_len = extranonce_prefix.len().min(4);
    enonce1[..copy_len].copy_from_slice(&extranonce_prefix[..copy_len]);
    let enonce2 = [0u8; 8];

    let mut coinbase_stratum =
        Vec::with_capacity(coinbase_prefix.len() + EXTRANONCE_SLOT_LEN + coinbase_suffix.len());
    coinbase_stratum.extend_from_slice(coinbase_prefix);
    coinbase_stratum.extend_from_slice(&enonce1);
    coinbase_stratum.extend_from_slice(&enonce2);
    coinbase_stratum.extend_from_slice(coinbase_suffix);

    let coinbase_txid = sha256d(&coinbase_stratum);
    let merkle_root = merkle_root_from_coinbase(&coinbase_txid, merkle_path);
    (merkle_root, coinbase_stratum)
}

// ── apply_template_broadcast ────────────────────────────────────────

/// Content signature of everything the miner hashes over, deliberately
/// EXCLUDING `min_ntime`, so a clock-only refresh counts as identical work.
/// Re-issuing identical work under a fresh `job_id` freezes strict firmware
/// that resets its pipeline on every new job.
fn job_content_signature(
    version: u32,
    prev_hash: &[u8; 32],
    n_bits: u32,
    merkle_root: Option<&[u8; 32]>,
    merkle_path: &[[u8; 32]],
    coinbase_prefix: &[u8],
    coinbase_suffix: &[u8],
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    version.hash(&mut h);
    prev_hash.hash(&mut h);
    n_bits.hash(&mut h);
    merkle_root.hash(&mut h);
    merkle_path.hash(&mut h);
    coinbase_prefix.hash(&mut h);
    coinbase_suffix.hash(&mut h);
    h.finish()
}

/// Fan a [`TemplateBroadcast`] out to this connection's channels, building a
/// [`MiningJob`] per extranonce-slot size. On [`TemplateChange::NewBlock`] jobs
/// are retired (not cleared) so in-flight shares stay classifiable, and the job
/// goes out as a future job followed by [`OutboundFrame::SetNewPrevHash`].
pub fn apply_template_broadcast<C: Clock>(
    state: &mut MiningSessionState<C>,
    broadcast: &TemplateBroadcast,
    mining_job_inputs: &MiningJobInputs,
    now_ms: u64,
    only_channel: Option<u32>,
) -> HandlerOutcome {
    let mut outcome = HandlerOutcome::default();

    if state.is_tdp_client {
        return outcome;
    }

    let template = &broadcast.template;
    let is_new_block = matches!(broadcast.change, TemplateChange::NewBlock);

    // `only_channel = Some(id)` sends a freshly opened channel its first job
    // without re-emitting frames to the existing ones.
    let channel_ids: Vec<u32> = match only_channel {
        Some(id) => vec![id],
        None => state.channels.keys().copied().collect(),
    };

    // Grouped channels' work rides ONE job addressed to the group id
    // (SV2 Mining/Group Channel); un-grouped channels take the per-channel path.
    let mut groups_to_process: Vec<u32> = Vec::new();
    let mut ungrouped: Vec<u32> = Vec::new();
    for cid in channel_ids {
        match state.groups.group_for_channel(cid) {
            Some(gid) => {
                if !groups_to_process.contains(&gid) {
                    groups_to_process.push(gid);
                }
            }
            None => ungrouped.push(cid),
        }
    }

    for channel_id in ungrouped {
        let Some(channel) = state.channels.get_mut(&channel_id) else {
            continue;
        };
        if is_new_block {
            retire_for_new_block(channel, template, now_ms);
        }

        let job_id = channel.next_job_id;
        channel.next_job_id = channel.next_job_id.wrapping_add(1);

        // On a block change: a FUTURE job with empty `min_ntime`, activated by
        // the `SetNewPrevHash` after it. Strict miners reject a job carrying
        // `min_ntime` that a SetNewPrevHash also references.
        let wire_min_ntime = if is_new_block {
            None
        } else {
            Some(template.header_timestamp)
        };

        match channel.kind {
            ChannelKind::Standard => {
                let mining_job = match mining_job_inputs.build(EXTRANONCE_SLOT_LEN) {
                    Ok(j) => j,
                    Err(err) => {
                        tracing::warn!(
                            ?err,
                            channel_id,
                            "skipping Standard channel: mining-job build failed"
                        );
                        continue;
                    }
                };

                let (merkle_root, coinbase_stratum) = standard_member_root_and_coinbase(
                    mining_job.coinbase_prefix(),
                    mining_job.coinbase_suffix(),
                    &channel.extranonce_prefix,
                    &template.merkle_path,
                );

                // Suppress an identical same-block refresh (see
                // `job_content_signature`); a block change is always sent.
                let sig = job_content_signature(
                    template.version,
                    &template.prev_hash,
                    template.n_bits,
                    Some(&merkle_root),
                    &[],
                    &[],
                    &[],
                );
                if !is_new_block && channel.last_sent_job_signature == Some(sig) {
                    continue;
                }
                channel.last_sent_job_signature = Some(sig);

                let template_snapshot = StandardTemplateSnapshot {
                    version: template.version,
                    prev_hash: template.prev_hash,
                    n_bits: template.n_bits,
                    ntime_start: template.header_timestamp,
                    coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
                };
                channel.standard_jobs.record_send(
                    job_id,
                    channel.session_difficulty,
                    merkle_root,
                    template_snapshot,
                    coinbase_stratum,
                    *mining_job.payouts_fingerprint(),
                    Some(template.template_id),
                    now_ms,
                );

                outcome.push_frame(OutboundFrame::NewMiningJob {
                    channel_id,
                    job_id,
                    version: template.version,
                    merkle_root,
                    min_ntime: wire_min_ntime,
                });
            }
            ChannelKind::Extended => {
                let extranonce_slot_size =
                    channel.extranonce_prefix.len() + channel.extranonce_size as usize;
                let mining_job = match mining_job_inputs.build(extranonce_slot_size) {
                    Ok(j) => j,
                    Err(err) => {
                        tracing::warn!(
                            ?err,
                            channel_id,
                            extranonce_slot_size,
                            "skipping Extended channel: mining-job build failed"
                        );
                        continue;
                    }
                };

                // `coinbase_tx_prefix` MUST NOT include the channel's
                // extranonce prefix: the miner inserts it itself, and
                // `validate_submit_extended` mirrors this split.
                let tx_prefix = mining_job.coinbase_prefix().to_vec();
                let tx_suffix = mining_job.coinbase_suffix().to_vec();
                let merkle_path = template.merkle_path.clone();

                // Same identical-refresh suppression as the Standard arm.
                let sig = job_content_signature(
                    template.version,
                    &template.prev_hash,
                    template.n_bits,
                    None,
                    &merkle_path,
                    &tx_prefix,
                    &tx_suffix,
                );
                if !is_new_block && channel.last_sent_job_signature == Some(sig) {
                    continue;
                }
                channel.last_sent_job_signature = Some(sig);

                let ext_job = extended_job(
                    template,
                    &mining_job,
                    channel.extranonce_prefix.clone(),
                    channel.session_difficulty,
                    now_ms,
                );
                channel.extended_jobs.insert(job_id, ext_job);

                outcome.push_frame(OutboundFrame::NewExtendedMiningJob {
                    channel_id,
                    job_id,
                    version: template.version,
                    version_rolling_allowed: VERSION_ROLLING_ALLOWED,
                    merkle_path,
                    coinbase_tx_prefix: tx_prefix,
                    coinbase_tx_suffix: tx_suffix,
                    min_ntime: wire_min_ntime,
                });
            }
        }

        // After the job, so the miner already holds what `job_id` refers to.
        if is_new_block {
            outcome.push_frame(OutboundFrame::SetNewPrevHash {
                channel_id,
                job_id,
                prev_hash: template.prev_hash,
                min_ntime: template.header_timestamp,
                n_bits: template.n_bits,
            });
        }
    }

    // ── Grouped channels (SV2 Mining/Group Channel) ───
    // On open, the new member gets a job to its OWN id (a group-addressed frame
    // would disturb the others); on a template broadcast, ONE group-addressed job.

    // The group's shared job; `difficulty` and `extranonce_prefix` are
    // placeholders overridden per member.
    let session_id = state.session_id;
    let build_group_template = |gid: u32, full_size: usize| -> Option<GroupTemplateParts> {
        let mining_job = mining_job_inputs
            .build(full_size)
            .inspect_err(|err| {
                tracing::warn!(
                    ?err,
                    session_id,
                    gid,
                    full_size,
                    "skipping group: mining-job build failed"
                );
            })
            .ok()?;
        let tmpl = extended_job(template, &mining_job, Vec::new(), Difficulty(0.0), now_ms);
        let (tx_prefix, tx_suffix, merkle_path) = (
            tmpl.coinbase_prefix.clone(),
            tmpl.coinbase_suffix.clone(),
            tmpl.merkle_path.clone(),
        );
        Some((tmpl, tx_prefix, tx_suffix, merkle_path))
    };

    for gid in groups_to_process {
        // Snapshot, so the groups borrow ends before channels are mutated.
        let (full_size, members, current_job_id, current_job_template): (
            usize,
            Vec<u32>,
            Option<u32>,
            Option<ExtendedJob>,
        ) = match state.groups.get(gid) {
            Some(g) => (
                g.full_extranonce_size,
                g.channel_ids.iter().copied().collect(),
                g.current_job_id(),
                g.current_job().cloned(),
            ),
            None => continue,
        };
        if members.is_empty() {
            continue;
        }

        // ── OPEN: a per-channel job to the new member's OWN id. ──
        if let Some(new_id) = only_channel {
            if members.contains(&new_id) {
                // Reuse the group's current job, or establish the first one.
                let resolved: Option<(u32, ExtendedJob)> =
                    match (current_job_id, current_job_template) {
                        (Some(jid), Some(tmpl)) => Some((jid, tmpl)),
                        _ => match (
                            build_group_template(gid, full_size),
                            state.groups.alloc_job_id(gid),
                        ) {
                            (Some((tmpl, _, _, _)), Some(jid)) => {
                                if let Some(g) = state.groups.get_mut(gid) {
                                    g.set_current_job(tmpl.clone());
                                }
                                Some((jid, tmpl))
                            }
                            _ => None,
                        },
                    };
                // Grouped members are always Extended; guarded defensively.
                let new_is_extended = matches!(
                    state.channels.get(&new_id).map(|c| c.kind),
                    Some(ChannelKind::Extended)
                );
                if let (Some((jid, tmpl)), true) = (resolved, new_is_extended) {
                    if let Some(ch) = state.channels.get_mut(&new_id) {
                        let mut job = tmpl.clone();
                        job.difficulty = ch.session_difficulty;
                        job.extranonce_prefix = ch.extranonce_prefix.clone();
                        job.created_at = now_ms;
                        ch.latest_extended_prev_hash = Some(job.prev_hash);
                        ch.latest_extended_n_bits = Some(job.n_bits);
                        let (pv, nt, nb, ver) =
                            (job.prev_hash, job.min_ntime, job.n_bits, job.version);
                        let mp = job.merkle_path.clone();
                        let cp = job.coinbase_prefix.clone();
                        let cs = job.coinbase_suffix.clone();
                        ch.extended_jobs.insert(jid, job);
                        // Future job first, then the activating SetNewPrevHash.
                        outcome.push_frame(OutboundFrame::NewExtendedMiningJob {
                            channel_id: new_id,
                            job_id: jid,
                            version: ver,
                            version_rolling_allowed: VERSION_ROLLING_ALLOWED,
                            merkle_path: mp,
                            coinbase_tx_prefix: cp,
                            coinbase_tx_suffix: cs,
                            min_ntime: None,
                        });
                        outcome.push_frame(OutboundFrame::SetNewPrevHash {
                            channel_id: new_id,
                            job_id: jid,
                            prev_hash: pv,
                            min_ntime: nt,
                            n_bits: nb,
                        });
                    }
                }
            }
            continue;
        }

        // ── TEMPLATE broadcast (only_channel == None): ONE group job. ──
        let Some((group_template, tx_prefix, tx_suffix, merkle_path)) =
            build_group_template(gid, full_size)
        else {
            continue;
        };
        let group_job_id = match state.groups.alloc_job_id(gid) {
            Some(id) => id,
            None => continue,
        };

        for &member_id in &members {
            let Some(channel) = state.channels.get_mut(&member_id) else {
                continue;
            };
            if is_new_block {
                retire_for_new_block(channel, template, now_ms);
            }
            // Store the shared job under the group job_id on every member, so
            // per-member `SubmitSharesExtended` validation finds it.
            if channel.kind == ChannelKind::Extended {
                let mut ext_job = group_template.clone();
                ext_job.difficulty = channel.session_difficulty;
                ext_job.extranonce_prefix = channel.extranonce_prefix.clone();
                channel.extended_jobs.insert(group_job_id, ext_job);
            }
        }

        // Kept for members that open later.
        if let Some(g) = state.groups.get_mut(gid) {
            g.set_current_job(group_template);
        }

        // Same future-job / SetNewPrevHash ordering as the per-channel path.
        outcome.push_frame(OutboundFrame::NewExtendedMiningJob {
            channel_id: gid,
            job_id: group_job_id,
            version: template.version,
            version_rolling_allowed: VERSION_ROLLING_ALLOWED,
            merkle_path,
            coinbase_tx_prefix: tx_prefix,
            coinbase_tx_suffix: tx_suffix,
            min_ntime: if is_new_block {
                None
            } else {
                Some(template.header_timestamp)
            },
        });
        if is_new_block {
            outcome.push_frame(OutboundFrame::SetNewPrevHash {
                channel_id: gid,
                job_id: group_job_id,
                prev_hash: template.prev_hash,
                min_ntime: template.header_timestamp,
                n_bits: template.n_bits,
            });
        }
    }

    note_work_available(state);
    outcome
}

/// Tell the vardiff of every channel that holds a job that it has work; only
/// the first report per channel has an effect.
fn note_work_available<C: Clock>(state: &mut MiningSessionState<C>) {
    let MiningSessionState {
        channels, vardiff, ..
    } = state;
    for (channel_id, channel) in channels.iter() {
        if channel.standard_jobs.is_empty() && channel.extended_jobs.is_empty() {
            continue;
        }
        if let Some(engine) = vardiff.get_mut(channel_id) {
            engine.note_work_available();
        }
    }
}

// ── handle_set_custom_mining_job ────────────────────────────────────

/// Inputs from a deserialized `SetCustomMiningJob` frame; the JDC built the
/// coinbase itself. `coinbase_prefix` is only the scriptSig bytes before the
/// extranonce slot; `coinbase_tx_outputs` is the count varint plus the
/// serialized `TxOut`s.
#[derive(Clone, Debug)]
pub struct SetCustomMiningJobInput {
    pub channel_id: u32,
    pub request_id: u32,
    pub mining_job_token: crate::tokens::Token,
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub min_ntime: u32,
    pub n_bits: u32,
    pub coinbase_tx_version: u32,
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_tx_input_n_sequence: u32,
    pub coinbase_tx_outputs: Vec<u8>,
    pub coinbase_tx_locktime: u32,
    pub merkle_path: Vec<[u8; 32]>,
    /// The ext 0x0003/distribution_id TLV Field as it arrived, NOT filtered by
    /// the negotiated set: ext 0x0003/Negotiation requires a TLV from a
    /// non-negotiated client to be rejected, and the handler owns that check.
    pub distribution_id: Option<u64>,
}

/// Handle `SetCustomMiningJob`, with the token context the IO layer resolved
/// (`bridge_job`, `allocation`, `distribution`). What AUTHORISES the token
/// ([`crate::bridge::TokenBacking`]) and what PINS its payout split are two
/// independent exhaustive `match`es; a token with no backing is refused.
pub fn handle_set_custom_mining_job<C: Clock>(
    state: &mut MiningSessionState<C>,
    input: &SetCustomMiningJobInput,
    bridge_job: Option<&crate::bridge::BridgeJobRef>,
    allocation: Option<&crate::bridge::AllocatedTokenRef>,
    distribution: Option<&crate::bridge::DistributionAcceptance>,
    now_ms: u64,
) -> HandlerOutcome {
    let reject = |error_code: &str| {
        HandlerOutcome::with_frame(OutboundFrame::SetCustomMiningJobError {
            channel_id: input.channel_id,
            request_id: input.request_id,
            error_code: error_code.to_string(),
        })
    };

    let Some(channel) = state.channels.get_mut(&input.channel_id) else {
        return reject(ERR_INVALID_CHANNEL_ID);
    };
    if channel.kind != ChannelKind::Extended {
        return reject(ERR_INVALID_JOB_ID);
    }
    let full_extranonce_size = channel.full_extranonce_size();
    // A Coinbase-only job has no declaration, so the pool's last tip for this
    // channel is the only tip it can be held to.
    let channel_prev_hash = channel.latest_extended_prev_hash;
    let channel_n_bits = channel.latest_extended_n_bits;

    // `n_bits` sets the block-candidate threshold, so it must be the pool's
    // (see [`ERR_INVALID_NBITS`]). Before the channel's first job there is
    // nothing to compare against: refused, never waved through, with the
    // retryable `stale-chain-tip` since it is a transient not-ready state.
    let (Some(expected), Some(tip)) = (channel_n_bits, channel_prev_hash) else {
        tracing::warn!(
            channel_id = input.channel_id,
            job_n_bits = input.n_bits,
            "sv2: custom job on a channel the pool has served no extended job yet — rejecting \
             retryably (nothing to pin its block-candidate threshold to)"
        );
        return reject(ERR_STALE_CHAIN_TIP);
    };
    if input.n_bits != expected {
        let on_our_tip = input.prev_hash == tip;
        tracing::warn!(
            channel_id = input.channel_id,
            job_n_bits = input.n_bits,
            pool_n_bits = expected,
            on_our_tip,
            "sv2: custom job carries an n_bits the pool is not working on — rejecting (its \
             block-candidate threshold would come from the client). Off our tip this is the \
             ordinary retarget race, not a client fault."
        );
        return reject(if on_our_tip {
            ERR_INVALID_NBITS
        } else {
            ERR_STALE_CHAIN_TIP
        });
    }

    // Full-Template JDCs put `distribution_id` on `DeclareMiningJob`, not here
    // (ext 0x0003/distribution_id TLV Field), so the reference may be inherited
    // from the declaration. Its acceptance is still re-checked against the
    // ext 0x0003/Grace Window + Implementation Notes window below.
    let distribution_ref = crate::bridge::resolve_distribution_reference(
        input.distribution_id,
        bridge_job,
        state
            .negotiated_extensions
            .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS),
    );

    // Fail-closed: unknown / expired / evicted tokens back nothing.
    let Some(backing) = crate::bridge::classify_backing(bridge_job, allocation) else {
        return reject(ERR_INVALID_MINING_JOB_TOKEN);
    };

    let channel_addr = state.address.as_ref().map(|a| a.as_str()).unwrap_or("");

    // A job on a past tip cannot produce a block, yet its shares would be
    // credited; off Solo that takes from everyone else in the window. Checked
    // ahead of the backing because it holds for all of them: a declaration
    // made on the previous tip is still on hand after the tip changes.
    if input.prev_hash != tip {
        return reject(ERR_STALE_CHAIN_TIP);
    }

    // The binding every allocate-backed job gets; one closure for both
    // Coinbase-only arms so the rule cannot drift apart.
    let bind_allocation = |token: &crate::bridge::AllocatedTokenRef| -> Option<&'static str> {
        if channel_addr != token.miner_address.as_str() {
            return Some(ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
        }
        None
    };

    // A `match`, so a new SV2 JDP/Job Declaration Modes entry must be answered
    // here rather than slip through.
    match backing {
        crate::bridge::TokenBacking::Declared(job) => {
            // Stops one miner claiming another's declared job.
            if channel_addr != job.miner_address.as_str() {
                return reject(ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
            }
            if input.prev_hash != job.declared_prev_hash {
                return reject(ERR_STALE_CHAIN_TIP);
            }

            // The mined job MUST be the declared one: it carries the
            // SV2 JDP/Job Declarator Server validation of the declared tx set
            // over, since nothing here re-examines what `merkle_path` commits to.
            let Some(binding) = job.binding.as_ref() else {
                // Internal inconsistency: nothing left to bind the job to.
                tracing::warn!(
                    channel_id = input.channel_id,
                    "sv2: declared job cannot be projected for binding — rejecting custom job"
                );
                return reject(ERR_INVALID_JOB_PARAM_DECLARATION_MISMATCH);
            };
            if let Err(violation) = crate::jdp::custom_job_binding::check_custom_job(
                binding,
                crate::jdp::custom_job_binding::MinedJobFields {
                    version: input.version,
                    coinbase_tx_version: input.coinbase_tx_version,
                    coinbase_prefix: &input.coinbase_prefix,
                    coinbase_tx_input_n_sequence: input.coinbase_tx_input_n_sequence,
                    coinbase_tx_outputs: &input.coinbase_tx_outputs,
                    coinbase_tx_locktime: input.coinbase_tx_locktime,
                    merkle_path: &input.merkle_path,
                    full_extranonce_size,
                },
            ) {
                tracing::warn!(
                    channel_id = input.channel_id,
                    ?violation,
                    "sv2: custom job does not match its declaration — rejecting"
                );
                return reject(ERR_INVALID_JOB_PARAM_DECLARATION_MISMATCH);
            }
        }
        // Base-protocol Coinbase-only (SV2 JDP/Coinbase-only Mode): the
        // allocate is the only record, so the job is held to the
        // SV2 JDP/AllocateMiningJobToken.Success designated output.
        crate::bridge::TokenBacking::BaseAllocation {
            token,
            payout_script,
        } => {
            if let Some(code) = bind_allocation(token) {
                return reject(code);
            }
            let outputs: Vec<bitcoin::TxOut> =
                match bitcoin::consensus::deserialize(&input.coinbase_tx_outputs) {
                    Ok(v) => v,
                    Err(_) => return reject(ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS),
                };
            if !crate::jdp::dynamic_outputs::pays_designated_output(&outputs, payout_script) {
                tracing::warn!(
                    channel_id = input.channel_id,
                    "sv2: base-protocol custom job allocates nothing to the pool's designated \
                     payout output (SV2 JDP/AllocateMiningJobToken.Success) — rejecting"
                );
                return reject(ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS);
            }
        }
        // Coinbase-only under ext 0x0003: no designated output; the coinbase is
        // judged by the ext 0x0003/Output Verification recompute below. That
        // covers the coinbase only, so the address still needs `bind_allocation`.
        crate::bridge::TokenBacking::DistributionAllocation(token) => {
            if let Some(code) = bind_allocation(token) {
                return reject(code);
            }
        }
    }

    // What pins the payout split, independent of the backing. The result is the
    // settlement fingerprint a found block is booked by; for Coinbase-only
    // ext 0x0003 this is its only carrier. `None` for base protocol and Solo.
    let settlement_fingerprint: Option<[u8; 32]> = match distribution_ref {
        // Base protocol pins ONE designated output: enough for Solo, where a
        // self-chosen split shortchanges only the miner. `accounting_stream`,
        // not `stream`: this asks whose money the block pays.
        None => {
            if state.accounting_stream != StreamKind::Solo {
                return reject(ERR_CUSTOM_JOB_REQUIRES_SOLO);
            }
            None
        }
        // ext 0x0003: the sole validation of the coinbase actually mined, and
        // it must run for Full-Template jobs too, since a declared distribution
        // can be superseded before the job arrives. Distributions are multi-use;
        // positional equality already confines the coinbase to one split.
        Some(reference) => {
            // ext 0x0003/Negotiation: a TLV from a non-negotiated extension is a
            // violation; only a `FromFrame` reference is a TLV the client sent.
            match reference {
                crate::bridge::DistributionReference::FromFrame { .. } => {
                    if !state
                        .negotiated_extensions
                        .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
                    {
                        return reject(ERR_INVALID_PAYOUT_DISTRIBUTION);
                    }
                }
                // An inherited reference only exists when this connection
                // negotiated (`resolve_distribution_reference` guarantees it).
                crate::bridge::DistributionReference::FromDeclaration { .. } => {}
            }
            let entry = match distribution {
                Some(crate::bridge::DistributionAcceptance::Accepted(entry)) => entry.clone(),
                _ => return reject(ERR_STALE_PAYOUT_DISTRIBUTION),
            };
            // The distribution must match the accounting THIS connection's
            // shares enter, decided over the pair (shared with the JDP declare
            // path) against `accounting_stream`: the template stream frozen at
            // OpenChannel would reject the correct plan after a mode change.
            if !crate::bridge::accounting_matches_stream(&entry.accounting, state.accounting_stream)
            {
                tracing::warn!(
                    channel_id = input.channel_id,
                    stream = ?state.accounting_stream,
                    accounting = ?entry.accounting,
                    "sv2: custom job references a distribution built for different \
                     accounting than this connection's — published against a stale or \
                     unresolved mode; rejecting rather than paying the wrong set of miners"
                );
                return reject(ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
            }
            // Only a tailored plan names an owner, the one cross-account guard
            // in Coinbase-only mode. A `match`, not `is_some()`, which would
            // read like a mode test while answering a different question.
            match &entry.accounting {
                crate::bridge::DistributionAccounting::Solo(owner)
                | crate::bridge::DistributionAccounting::GroupSolo(owner) => {
                    if channel_addr != owner.as_str() {
                        return reject(ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
                    }
                }
                // Pool-wide names nobody — every PPLNS connection shares it.
                crate::bridge::DistributionAccounting::PoolWide => {}
            }
            let declared: Vec<bitcoin::TxOut> =
                match bitcoin::consensus::deserialize(&input.coinbase_tx_outputs) {
                    Ok(v) => v,
                    Err(_) => return reject(ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS),
                };
            if crate::jdp::payout_distribution::validate_coinbase_outputs_against_distribution(
                &declared,
                &entry.built.pool_payout,
                &entry.built.payouts,
                &entry.built.dust_limits,
                &entry.built.additional_outputs,
            )
            .is_err()
            {
                return reject(ERR_INVALID_PAYOUT_DISTRIBUTION);
            }
            // Only past ext 0x0003/Output Verification: earlier it would name
            // a distribution this coinbase was never proven to pay.
            entry.built.payouts_fingerprint
        }
    };

    let channel = state
        .channels
        .get_mut(&input.channel_id)
        .expect("channel existence checked above");

    let full_extranonce_size = channel.full_extranonce_size();
    let script_sig_len = input.coinbase_prefix.len() + full_extranonce_size;

    let coinbase_tx_prefix = bp_mining_job::serialize_coinbase_prefix(
        input.coinbase_tx_version,
        &input.coinbase_prefix,
        script_sig_len,
    );

    let mut coinbase_tx_suffix = Vec::with_capacity(4 + input.coinbase_tx_outputs.len() + 4);
    coinbase_tx_suffix.extend_from_slice(&input.coinbase_tx_input_n_sequence.to_le_bytes());
    coinbase_tx_suffix.extend_from_slice(&input.coinbase_tx_outputs);
    coinbase_tx_suffix.extend_from_slice(&input.coinbase_tx_locktime.to_le_bytes());

    let job_id = channel.next_job_id;
    channel.next_job_id = channel.next_job_id.wrapping_add(1);
    if channel.next_job_id == 0 {
        // Never use 0 as a job ID.
        channel.next_job_id = 1;
    }

    channel.extended_jobs.insert(
        job_id,
        ExtendedJob {
            coinbase_prefix: coinbase_tx_prefix,
            coinbase_suffix: coinbase_tx_suffix,
            // Zeroed on the base protocol; under ext 0x0003 a found block
            // resolves its settlement inputs by this fingerprint.
            payouts_fingerprint: settlement_fingerprint.unwrap_or([0u8; 32]),
            merkle_path: input.merkle_path.clone(),
            version: input.version,
            prev_hash: input.prev_hash,
            n_bits: input.n_bits,
            min_ntime: input.min_ntime,
            extranonce_prefix: channel.extranonce_prefix.clone(),
            difficulty: channel.session_difficulty,
            // No pool template: the JDC builds and propagates the block itself.
            coinbase_tx_value_remaining: 0,
            template_id: None, // custom job — no pool-side template reference
            // Asks the DECLARATION's reference, the same field
            // `handle_push_solution` reads, so exactly one side records each
            // block. NOT `distribution_ref`, which can differ (Solo, or 0x0003
            // negotiated on the mining side only).
            jdp_claims_the_block: match backing {
                crate::bridge::TokenBacking::Declared(job) => job.distribution_id.is_some(),
                crate::bridge::TokenBacking::BaseAllocation { .. }
                | crate::bridge::TokenBacking::DistributionAllocation(_) => false,
            },
            created_at: now_ms,
            retired_at: None,
        },
    );

    note_work_available(state);
    HandlerOutcome::with_frame(OutboundFrame::SetCustomMiningJobSuccess {
        channel_id: input.channel_id,
        request_id: input.request_id,
        job_id,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mining::jobs::ExtendedJob;
    use bp_vardiff::TestClock;
    use std::collections::HashSet;
    use std::sync::Arc;

    /// Test shim mirroring the handler's projection into the validator's inputs.
    fn validate_ext(
        ch: &mut ChannelState,
        sub: &SubmitSharesExtendedInput,
        job: &ExtendedJob,
        job_difficulty: bp_share::Difficulty,
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

    fn port_cfg() -> PortConfig {
        PortConfig {
            network: Network::Regtest,
            min_difficulty: Difficulty(0.00001),
            initial_difficulty: Difficulty(1024.0),
            target_shares_per_minute: 6.0,
            vardiff_interval_ms: 60_000,
            job_lifecycle: LifecycleConfig::DEFAULT,
        }
    }

    fn fresh_session() -> MiningSessionState<Arc<TestClock>> {
        MiningSessionState::new(Arc::new(TestClock::new(0)), 1, port_cfg())
    }

    fn good_setup() -> SetupConnectionInput {
        SetupConnectionInput {
            protocol: PROTOCOL_MINING,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            vendor: "test-vendor".to_string(),
        }
    }

    fn open_std(req_id: u32, user: &str) -> OpenStandardMiningChannelInput {
        OpenStandardMiningChannelInput {
            request_id: req_id,
            user_identity: user.to_string(),
            // ~1000 derived at the fixture's 6 shares/min, rounding up to the
            // 1024 the surrounding tests expect.
            nominal_hash_rate: 429_496_729_600.0,
            max_target: [0xFF; 32],
        }
    }

    fn open_ext(req_id: u32, user: &str) -> OpenExtendedMiningChannelInput {
        OpenExtendedMiningChannelInput {
            request_id: req_id,
            user_identity: user.to_string(),
            nominal_hash_rate: 429_496_729_600.0,
            max_target: [0xFF; 32],
            min_extranonce_size: 8,
        }
    }

    // Regtest bech32 address — passes bp_common::normalize_btc_address.
    const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    // ── SetupConnection ────────────────────────────────────────────

    #[test]
    fn setup_connection_accepts_mining_protocol() {
        let mut s = fresh_session();
        let out = handle_setup_connection(&mut s, &good_setup());
        assert_eq!(out.outbound.len(), 1);
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetupConnectionSuccess {
                used_version: 2,
                ..
            }
        ));
        assert!(matches!(out.events[0], SessionEvent::SetupComplete));
        assert!(s.setup_complete);
    }

    /// `Success.flags` never echoes the client's request flags.
    #[test]
    fn setup_connection_success_flags_are_not_echoed() {
        let mut s = fresh_session();
        let mut input = good_setup();
        input.flags = FLAG_REQUIRES_STANDARD_JOBS | FLAG_REQUIRES_VERSION_ROLLING;
        let out = handle_setup_connection(&mut s, &input);
        match out.outbound[0] {
            OutboundFrame::SetupConnectionSuccess { flags, .. } => {
                assert_eq!(
                    flags, 0,
                    "Success.flags must be 0 (no FIXED_VERSION / EXTENDED_CHANNELS), not an echo"
                );
                assert_eq!(flags & FLAG_SUCCESS_REQUIRES_FIXED_VERSION, 0);
            }
            _ => panic!("expected SetupConnectionSuccess"),
        }
        // Request flags are still parsed into session state.
        assert!(s.requires_standard_jobs);
    }

    /// A work-selection connection gets REQUIRES_EXTENDED_CHANNELS, never REQUIRES_FIXED_VERSION.
    #[test]
    fn setup_connection_success_flags_extended_for_work_selection() {
        let mut s = fresh_session();
        let mut input = good_setup();
        input.flags = FLAG_REQUIRES_WORK_SELECTION | FLAG_REQUIRES_VERSION_ROLLING;
        let out = handle_setup_connection(&mut s, &input);
        match out.outbound[0] {
            OutboundFrame::SetupConnectionSuccess { flags, .. } => {
                assert_eq!(flags, FLAG_SUCCESS_REQUIRES_EXTENDED_CHANNELS);
                assert_eq!(flags & FLAG_SUCCESS_REQUIRES_FIXED_VERSION, 0);
            }
            _ => panic!("expected SetupConnectionSuccess"),
        }
        assert!(s.work_selection);
    }

    #[test]
    fn setup_connection_rejects_protocol_version_mismatch() {
        let mut s = fresh_session();
        let mut input = good_setup();
        input.min_version = 99;
        input.max_version = 99;
        let out = handle_setup_connection(&mut s, &input);
        match &out.outbound[0] {
            OutboundFrame::SetupConnectionError { error_code, .. } => {
                assert_eq!(
                    error_code,
                    crate::codec_common::ERR_PROTOCOL_VERSION_MISMATCH
                );
            }
            _ => panic!("expected error"),
        }
        // SV2 Overview/SetupConnection.Error: sent prior to closing.
        assert!(
            out.events
                .iter()
                .any(|e| matches!(e, SessionEvent::Disconnect { .. })),
            "a rejected setup must ask the IO layer to close"
        );
        assert!(!s.setup_complete);
    }

    /// A TDP-only setup (protocol 2) succeeds and sets `is_tdp_client`.
    #[test]
    fn setup_connection_accepts_tdp_subprotocol_and_flags_state() {
        let mut s = fresh_session();
        let mut input = good_setup();
        input.protocol = PROTOCOL_TEMPLATE_DISTRIBUTION;
        let out = handle_setup_connection(&mut s, &input);
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetupConnectionSuccess { .. }
        ));
        assert!(s.is_tdp_client, "TDP-only flag must be set");
        assert!(s.setup_complete);
    }

    /// Any other sub-protocol gets `unsupported-protocol`.
    #[test]
    fn setup_connection_rejects_unknown_subprotocol() {
        let mut s = fresh_session();
        let mut input = good_setup();
        input.protocol = 99;
        let out = handle_setup_connection(&mut s, &input);
        match &out.outbound[0] {
            OutboundFrame::SetupConnectionError { error_code, .. } => {
                assert_eq!(error_code, crate::codec_common::ERR_UNSUPPORTED_PROTOCOL);
            }
            _ => panic!("expected error"),
        }
        assert!(!s.is_tdp_client);
        assert!(!s.setup_complete);
        assert!(
            out.events
                .iter()
                .any(|e| matches!(e, SessionEvent::Disconnect { .. })),
            "a rejected setup must ask the IO layer to close"
        );
    }

    /// An accepted setup, including TDP-only, does not ask for a close.
    #[test]
    fn an_accepted_setup_does_not_ask_for_a_close() {
        for (label, input) in [
            ("mining", good_setup()),
            ("tdp-only", {
                let mut i = good_setup();
                i.protocol = PROTOCOL_TEMPLATE_DISTRIBUTION;
                i
            }),
        ] {
            let mut s = fresh_session();
            let out = handle_setup_connection(&mut s, &input);
            assert!(
                matches!(
                    out.outbound[0],
                    OutboundFrame::SetupConnectionSuccess { .. }
                ),
                "{label} must be accepted"
            );
            assert!(
                !out.events
                    .iter()
                    .any(|e| matches!(e, SessionEvent::Disconnect { .. })),
                "{label} must NOT be disconnected"
            );
        }
    }

    // ── OpenStandardMiningChannel ──────────────────────────────────

    #[test]
    fn open_standard_channel_succeeds_with_valid_address() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let out = handle_open_standard_mining_channel(
            &mut s,
            &open_std(7, &format!("{}.worker1", REGTEST_ADDR)),
            vec![0x01, 0x02, 0x03, 0x04],
        );
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::OpenStandardMiningChannelSuccess {
                request_id: 7,
                channel_id: 1,
                ..
            }
        ));
        assert_eq!(s.channels.len(), 1);
        assert_eq!(s.primary_channel, Some(1));
        assert_eq!(s.worker_name, "worker1");
        assert!(s.address.is_some());
    }

    /// No worker, or an empty one, opens as "default": the session row and
    /// every share carry that name, so the stats sinks never see "".
    #[test]
    fn a_channel_without_a_worker_name_opens_as_default() {
        for identity in [REGTEST_ADDR.to_string(), format!("{REGTEST_ADDR}.")] {
            let mut s = fresh_session();
            handle_setup_connection(&mut s, &good_setup());
            handle_open_standard_mining_channel(
                &mut s,
                &open_std(7, &identity),
                vec![0x01, 0x02, 0x03, 0x04],
            );
            assert_eq!(s.worker_name, "default", "{identity}");
        }
    }

    /// A declared `nominal_hash_rate` is bounded only by `min_difficulty`; 0 gets the port start.
    #[test]
    fn open_standard_honours_a_declaration_and_falls_back_without_one() {
        // A tiny declaration is bounded at min_difficulty, not the start value.
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let mut tiny = open_std(7, &format!("{REGTEST_ADDR}.w"));
        tiny.nominal_hash_rate = 1_000.0; // → ~2.3e-6 derived
        let _ = handle_open_standard_mining_channel(&mut s, &tiny, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            s.channels[&1].session_difficulty.as_f64(),
            port_cfg().min_difficulty.as_f64(),
            "a declaration below min_difficulty is bounded there, not at the start value"
        );

        // nominal_hash_rate = 0 → also the configured initial difficulty.
        let mut s0 = fresh_session();
        handle_setup_connection(&mut s0, &good_setup());
        let mut zero = open_std(8, &format!("{REGTEST_ADDR}.w"));
        zero.nominal_hash_rate = 0.0;
        let _ = handle_open_standard_mining_channel(&mut s0, &zero, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(s0.channels[&1].session_difficulty.as_f64(), 1024.0);

        // An honest high nominal (~5 PH/s) starts ABOVE the configured start.
        let mut sh = fresh_session();
        handle_setup_connection(&mut sh, &good_setup());
        let mut big = open_std(9, &format!("{REGTEST_ADDR}.w"));
        big.nominal_hash_rate = 5.0e15;
        let _ = handle_open_standard_mining_channel(&mut sh, &big, vec![0x01, 0x02, 0x03, 0x04]);
        assert!(
            sh.channels[&1].session_difficulty.as_f64() > 1024.0,
            "an honest high nominal must start above the configured start"
        );

        // A device that declares BELOW the configured start gets its own
        // rate, not the start value: at 6 shares/min, 100 GH/s derives ~233.
        let mut sl = fresh_session();
        handle_setup_connection(&mut sl, &good_setup());
        let mut small = open_std(10, &format!("{REGTEST_ADDR}.w"));
        small.nominal_hash_rate = 1.0e11;
        let _ = handle_open_standard_mining_channel(&mut sl, &small, vec![0x01, 0x02, 0x03, 0x04]);
        let got = sl.channels[&1].session_difficulty.as_f64();
        assert!(
            (233.0..1024.0).contains(&got),
            "a small honest declaration must be honoured, got {got}"
        );
    }

    #[test]
    fn open_standard_rejects_invalid_address() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let out = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, "not-a-bitcoin-address.worker"),
            vec![0x01, 0x02, 0x03, 0x04],
        );
        match &out.outbound[0] {
            OutboundFrame::OpenMiningChannelError { error_code, .. } => {
                assert_eq!(error_code, ERR_UNKNOWN_USER);
            }
            _ => panic!("expected unknown-user"),
        }
        assert_eq!(s.channels.len(), 0);
    }

    /// Two distinct valid P2WPKH regtest addresses, derived so no bech32
    /// literal has to be hand-checksummed.
    fn distinct_regtest_addresses() -> (String, String) {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        use bitcoin::{Address, CompressedPublicKey, PrivateKey};
        let secp = Secp256k1::new();
        let mk = |seed: u8| {
            let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
            let priv_key = PrivateKey::new(sk, Network::Regtest);
            let pub_key = CompressedPublicKey::from_private_key(&secp, &priv_key).unwrap();
            Address::p2wpkh(&pub_key, Network::Regtest).to_string()
        };
        (mk(1), mk(2))
    }

    #[test]
    fn open_standard_address_lock_rejects_different_address() {
        let (addr_a, addr_b) = distinct_regtest_addresses();
        assert_ne!(addr_a, addr_b);
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{addr_a}.workerA")),
            vec![0; 4],
        );
        let out = handle_open_standard_mining_channel(
            &mut s,
            &open_std(2, &format!("{addr_b}.workerB")),
            vec![0; 4],
        );
        match &out.outbound[0] {
            OutboundFrame::OpenMiningChannelError { error_code, .. } => {
                assert_eq!(error_code, ERR_ADDRESS_LOCKED);
            }
            _ => panic!("expected address-locked, got {:?}", out.outbound[0]),
        }
    }

    #[test]
    fn open_standard_clamps_difficulty_to_min_floor() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let mut input = open_std(1, &format!("{}.w", REGTEST_ADDR));
        input.nominal_hash_rate = 0.0001; // tiny → ratio below min_difficulty
        let _ = handle_open_standard_mining_channel(&mut s, &input, vec![0; 4]);
        let ch = s.channels.values().next().unwrap();
        assert!(ch.session_difficulty.as_f64() >= s.min_difficulty.as_f64());
    }

    // ── OpenExtendedMiningChannel ──────────────────────────────────

    /// The rollable extranonce is exactly the requested minimum.
    #[test]
    fn open_extended_channel_honors_requested_rollable_size() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let mut input = open_ext(1, &format!("{}.w", REGTEST_ADDR));
        input.min_extranonce_size = 10;
        let out = handle_open_extended_mining_channel(&mut s, &input, vec![0; 4]);
        match &out.outbound[0] {
            OutboundFrame::OpenExtendedMiningChannelSuccess {
                extranonce_size, ..
            } => assert_eq!(*extranonce_size, 10),
            _ => panic!("expected extended success"),
        }
        let ch = s.channels.values().next().unwrap();
        assert_eq!(ch.extranonce_size, 10);
        assert_eq!(ch.kind, ChannelKind::Extended);
    }

    /// The full 16 rollable bytes are granted to a proxy that requests them.
    #[test]
    fn open_extended_channel_grants_full_sixteen() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let mut input = open_ext(1, &format!("{}.w", REGTEST_ADDR));
        input.min_extranonce_size = MAX_EXTENDED_ROLLABLE as u16; // 16
        let out = handle_open_extended_mining_channel(&mut s, &input, vec![0; 4]);
        match &out.outbound[0] {
            OutboundFrame::OpenExtendedMiningChannelSuccess {
                extranonce_size, ..
            } => assert_eq!(*extranonce_size, 16),
            _ => panic!("expected extended success"),
        }
    }

    /// A request larger than the pool can grant is rejected, never under-granted.
    #[test]
    fn open_extended_channel_rejects_oversize_request() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let mut input = open_ext(1, &format!("{}.w", REGTEST_ADDR));
        input.min_extranonce_size = (MAX_EXTENDED_ROLLABLE + 1) as u16; // 17 > cap
        let out = handle_open_extended_mining_channel(&mut s, &input, vec![0; 4]);
        match &out.outbound[0] {
            OutboundFrame::OpenMiningChannelError { error_code, .. } => {
                assert_eq!(error_code, ERR_MIN_EXTRANONCE_SIZE_TOO_LARGE);
            }
            _ => panic!("expected OpenMiningChannelError, got {:?}", out.outbound[0]),
        }
        assert!(
            s.channels.is_empty(),
            "no channel must be inserted on a rejected open"
        );
    }

    /// A fractional derived difficulty is stored as a power of two.
    #[test]
    fn open_channel_assigns_a_power_of_two_difficulty() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        // 1.234 TH/s at the port's 6 spm yields a fractional raw diff.
        let nominal = 1.234e12_f32;
        let raw = hash_rate_to_difficulty(nominal as f64, s.target_shares_per_minute).as_f64();
        assert_ne!(
            raw.fract(),
            0.0,
            "precondition: test input must produce a fractional raw diff (got {raw})"
        );

        let mut input = open_ext(1, &format!("{}.w", REGTEST_ADDR));
        input.nominal_hash_rate = nominal;
        let _ = handle_open_extended_mining_channel(&mut s, &input, vec![0; 4]);

        let assigned = s
            .channels
            .values()
            .next()
            .unwrap()
            .session_difficulty
            .as_f64();
        assert_eq!(
            assigned.fract(),
            0.0,
            "assigned diff must be a whole integer"
        );
        assert_eq!(
            assigned,
            2_f64.powf(assigned.log2().round()),
            "assigned diff {assigned} (raw {raw}) must be a power of two"
        );
        // One of the two rungs bracketing the raw value.
        let lower = 2_f64.powf(raw.log2().floor());
        assert!(
            assigned == lower || assigned == lower * 2.0,
            "assigned {assigned} must bracket raw {raw}"
        );
    }

    #[test]
    fn assigned_difficulty_is_always_a_power_of_two() {
        // Always UP: a downstream that requested a difficulty rejects a lower
        // one as a protocol error and discards the assignment.
        for probe in [2887.8_f64, 950.3, 1536.0, 1025.0, 1.5, 3.0, 12345.6] {
            let d = power_of_two_difficulty(Difficulty(probe)).as_f64();
            assert!(
                d >= probe,
                "{d} is BELOW the requested {probe} — the downstream would discard it"
            );
            assert!(
                d < probe * 2.0,
                "{d} overshoots {probe} by more than one rung"
            );
        }
        assert_eq!(power_of_two_difficulty(Difficulty(2887.8)).as_f64(), 4096.0);
        assert_eq!(power_of_two_difficulty(Difficulty(950.3)).as_f64(), 1024.0);
        // Already a power of two: unchanged, never bumped to the next rung.
        assert_eq!(power_of_two_difficulty(Difficulty(1024.0)).as_f64(), 1024.0);
        assert_eq!(power_of_two_difficulty(Difficulty(4096.0)).as_f64(), 4096.0);
        // A deliberately low sub-1 difficulty passes through unchanged.
        assert_eq!(power_of_two_difficulty(Difficulty(0.7)).as_f64(), 0.7);
        // Non-positive / non-finite pass through for the caller's guards.
        assert_eq!(power_of_two_difficulty(Difficulty(0.0)).as_f64(), 0.0);
        assert!(power_of_two_difficulty(Difficulty(f64::NAN))
            .as_f64()
            .is_nan());

        // Nothing above 1 may leave this function as a non-power-of-two.
        for probe in [1.0, 3.7, 100.0, 5000.0, 1e6, 1e9] {
            let d = power_of_two_difficulty(Difficulty(probe)).as_f64();
            assert_eq!(
                d,
                2_f64.powf(d.log2().round()),
                "{d} (from {probe}) is not a power of two"
            );
        }
    }

    /// Vardiff grace takes the lower difficulty in both retarget directions.
    #[test]
    fn graced_validation_difficulty_takes_the_lower() {
        // Raise → the frozen low.
        assert_eq!(
            graced_validation_difficulty(Difficulty(1024.0), Difficulty(1536.0)).as_f64(),
            1024.0
        );
        // Lower → the new low.
        assert_eq!(
            graced_validation_difficulty(Difficulty(1536.0), Difficulty(512.0)).as_f64(),
            512.0
        );
        // Stable → unchanged.
        assert_eq!(
            graced_validation_difficulty(Difficulty(1024.0), Difficulty(1024.0)).as_f64(),
            1024.0
        );
    }

    // ── SubmitSharesStandard ───────────────────────────────────────

    fn snapshot() -> StandardTemplateSnapshot {
        StandardTemplateSnapshot {
            version: 0x2000_0000,
            prev_hash: [0xCC; 32],
            n_bits: 0x1d00_ffff,
            ntime_start: 0x6500_0000,
            coinbase_tx_value_remaining: 5_000_000_000,
        }
    }

    #[test]
    fn submit_standard_invalid_channel_id() {
        let mut s = fresh_session();
        let sub = SubmitSharesStandardInput {
            channel_id: 99,
            sequence_number: 1,
            job_id: 1,
            nonce: 0,
            version: 0x2000_0000,
            ntime: 0,
        };
        let out = handle_submit_shares_standard(&mut s, &sub, 0);
        match &out.outbound[0] {
            OutboundFrame::SubmitSharesError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_CHANNEL_ID);
            }
            _ => panic!("expected invalid-channel-id"),
        }
    }

    #[test]
    fn submit_standard_invalid_job_id_when_map_empty() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let channel_id = s.primary_channel.unwrap();
        let sub = SubmitSharesStandardInput {
            channel_id,
            sequence_number: 1,
            job_id: 42,
            nonce: 0,
            version: 0x2000_0000,
            ntime: 0,
        };
        let out = handle_submit_shares_standard(&mut s, &sub, 0);
        match &out.outbound[0] {
            OutboundFrame::SubmitSharesError { error_code, .. } => {
                assert_eq!(error_code, "invalid-job-id");
            }
            _ => panic!("expected invalid-job-id"),
        }
    }

    /// A valid Standard share against an easy job is accepted.
    #[test]
    fn submit_standard_accepted_share() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let channel_id = s.primary_channel.unwrap();
        // Pre-populate the standard_jobs map with an easy job.
        let easy = Difficulty(1.0 / 4_294_967_296.0);
        {
            let ch = s.channels.get_mut(&channel_id).unwrap();
            ch.standard_jobs
                .record_send_for_test(7, easy, [0xDD; 32], snapshot(), 0);
        }
        let sub = SubmitSharesStandardInput {
            channel_id,
            sequence_number: 1,
            job_id: 7,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
        };
        let out = handle_submit_shares_standard(&mut s, &sub, 0);
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SubmitSharesSuccess {
                channel_id: _,
                last_sequence_number: 1,
                ..
            }
        ));
        assert!(matches!(out.events[0], SessionEvent::ShareAccepted { .. }));
    }

    /// A share below the network target is accepted with `is_block_candidate = false`.
    #[test]
    fn submit_standard_sub_network_share_is_not_block_candidate() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let channel_id = s.primary_channel.unwrap();
        let easy = Difficulty(1.0 / 4_294_967_296.0);
        {
            let ch = s.channels.get_mut(&channel_id).unwrap();
            // Default snapshot() pins n_bits = difficulty 1 → unreachable.
            ch.standard_jobs
                .record_send_for_test(7, easy, [0xDD; 32], snapshot(), 0);
        }
        let sub = SubmitSharesStandardInput {
            channel_id,
            sequence_number: 1,
            job_id: 7,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
        };
        let out = handle_submit_shares_standard(&mut s, &sub, 0);
        match &out.events[0] {
            SessionEvent::ShareAccepted { accept, .. } => {
                assert!(
                    !accept.is_block_candidate,
                    "sub-network share must NOT be flagged as block-candidate \
                     — IO-layer would otherwise wire it to BlockSubmissionSink"
                );
            }
            ev => panic!("expected ShareAccepted, got {ev:?}"),
        }
    }

    /// A share meeting the network target is accepted with `is_block_candidate = true`.
    #[test]
    fn submit_standard_network_target_share_is_block_candidate() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let channel_id = s.primary_channel.unwrap();
        let easy = Difficulty(1.0 / 4_294_967_296.0);
        {
            let ch = s.channels.get_mut(&channel_id).unwrap();
            // Snapshot with a trivially-reachable target (`0xffff·2^240`)
            // so any accepted share is also a block candidate.
            let mut snap = snapshot();
            snap.n_bits = 0x2100_ffff;
            ch.standard_jobs
                .record_send_for_test(7, easy, [0xDD; 32], snap, 0);
        }
        let sub = SubmitSharesStandardInput {
            channel_id,
            sequence_number: 1,
            job_id: 7,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
        };
        let out = handle_submit_shares_standard(&mut s, &sub, 0);
        match &out.events[0] {
            SessionEvent::ShareAccepted { accept, .. } => {
                assert!(
                    accept.is_block_candidate,
                    "a hash meeting the network target must flag block-candidate \
                     so IO-layer fires BlockSubmissionSink"
                );
            }
            ev => panic!("expected ShareAccepted, got {ev:?}"),
        }
    }

    /// A job retired within the grace window is still credited.
    #[test]
    fn submit_standard_retired_within_grace_is_credited() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let channel_id = s.primary_channel.unwrap();
        let easy = Difficulty(1.0 / 4_294_967_296.0);
        {
            let ch = s.channels.get_mut(&channel_id).unwrap();
            ch.standard_jobs
                .record_send_for_test(7, easy, [0xDD; 32], snapshot(), 0);
            // Block change at t=1000 retires every entry.
            ch.standard_jobs.retire(1_000);
        }
        let sub = SubmitSharesStandardInput {
            channel_id,
            sequence_number: 1,
            job_id: 7,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
        };
        // Still inside the 5 s grace window.
        let out = handle_submit_shares_standard(&mut s, &sub, 2_000);
        assert!(
            matches!(out.outbound[0], OutboundFrame::SubmitSharesSuccess { .. }),
            "retired-within-grace must still emit SubmitSharesSuccess"
        );
        assert!(matches!(out.events[0], SessionEvent::ShareAccepted { .. }));
    }

    /// A job retired past grace gets `stale-share`, not `invalid-job-id`.
    #[test]
    fn submit_standard_retired_past_grace_emits_stale_share() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let channel_id = s.primary_channel.unwrap();
        let easy = Difficulty(1.0 / 4_294_967_296.0);
        {
            let ch = s.channels.get_mut(&channel_id).unwrap();
            ch.standard_jobs
                .record_send_for_test(7, easy, [0xDD; 32], snapshot(), 0);
            ch.standard_jobs.retire(1_000);
        }
        let sub = SubmitSharesStandardInput {
            channel_id,
            sequence_number: 1,
            job_id: 7,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
        };
        // 1 ms past the 5 s grace window.
        let out = handle_submit_shares_standard(&mut s, &sub, 1_000 + 5_000 + 1);
        match &out.outbound[0] {
            OutboundFrame::SubmitSharesError { error_code, .. } => {
                assert_eq!(
                    error_code, "stale-share",
                    "retired-past-grace must wire `stale-share`, not `invalid-job-id`"
                );
            }
            _ => panic!("expected SubmitSharesError"),
        }
        assert!(matches!(out.events[0], SessionEvent::ShareRejected { .. }));
    }

    /// A share on a job frozen at an older difficulty still feeds vardiff.
    #[test]
    fn submit_standard_feeds_vardiff_even_when_job_diff_differs_from_session() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let channel_id = s.primary_channel.unwrap();
        // Simulate a vardiff move: session target is high (1024) while the
        // in-flight job is frozen at an easy target the share can meet.
        let easy = Difficulty(1.0 / 4_294_967_296.0);
        {
            let ch = s.channels.get_mut(&channel_id).unwrap();
            ch.session_difficulty = Difficulty(1024.0);
            ch.standard_jobs
                .record_send_for_test(7, easy, [0xDD; 32], snapshot(), 0);
        }
        assert_eq!(
            s.vardiff[&channel_id].window_shares(),
            0,
            "window empty before any share"
        );
        let sub = SubmitSharesStandardInput {
            channel_id,
            sequence_number: 1,
            job_id: 7,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
        };
        let out = handle_submit_shares_standard(&mut s, &sub, 0);
        assert!(matches!(out.events[0], SessionEvent::ShareAccepted { .. }));
        assert_eq!(
            s.vardiff[&channel_id].window_shares(),
            1,
            "accepted Standard share must feed the vardiff window even when \
             its frozen job difficulty differs from the session target"
        );
    }

    // ── SubmitSharesExtended ───────────────────────────────────────

    #[test]
    fn submit_extended_invalid_job_id_when_map_empty() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let channel_id = s.primary_channel.unwrap();
        let sub = SubmitSharesExtendedInput {
            channel_id,
            sequence_number: 1,
            job_id: 1,
            nonce: 0,
            version: 0,
            ntime: 0,
            extranonce: ExtranonceBytes::from_slice(&[0; 8]),
            tlvs: Vec::new(),
        };
        let out = handle_submit_shares_extended(&mut s, &sub, 0);
        match &out.outbound[0] {
            OutboundFrame::SubmitSharesError { error_code, .. } => {
                assert_eq!(error_code, "invalid-job-id");
            }
            _ => panic!("expected invalid-job-id"),
        }
    }

    #[test]
    fn submit_extended_accepted_share() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let channel_id = s.primary_channel.unwrap();
        let easy = Difficulty(1.0 / 4_294_967_296.0);
        let job = ExtendedJob {
            payouts_fingerprint: [0u8; 32],
            coinbase_prefix: vec![0xAA; 8],
            coinbase_suffix: vec![0xBB; 8],
            merkle_path: vec![[0u8; 32]],
            // Matches the prefix the channel above was opened with — the
            // validator reconstructs the coinbase from the job's copy.
            extranonce_prefix: vec![0; 4],
            version: 0x2000_0000,
            prev_hash: [0xCC; 32],
            n_bits: 0x1d00_ffff,
            min_ntime: 0x6500_0000,
            difficulty: easy,
            coinbase_tx_value_remaining: 5_000_000_000,
            template_id: None,
            jdp_claims_the_block: false,
            created_at: 0,
            retired_at: None,
        };
        {
            let ch = s.channels.get_mut(&channel_id).unwrap();
            ch.extended_jobs.insert(7, job);
        }
        let sub = SubmitSharesExtendedInput {
            channel_id,
            sequence_number: 1,
            job_id: 7,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
            extranonce: ExtranonceBytes::from_slice(&[0x11; 8]),
            tlvs: Vec::new(),
        };
        let out = handle_submit_shares_extended(&mut s, &sub, 0);
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SubmitSharesSuccess { .. }
        ));
    }

    /// A share for a job issued under the old extranonce prefix is rebuilt with that prefix (by hash).
    #[test]
    fn submit_extended_accepts_share_for_job_issued_under_previous_prefix() {
        const OLD_PREFIX: [u8; 4] = [0xC0, 0xDE, 0xBA, 0xBE];
        const NEW_PREFIX: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

        // Hash of one fixed share for job 7 (issued under OLD_PREFIX) on a
        // channel whose current prefix is `channel_prefix`; a fresh session
        // per call keeps the dedup cache out of it.
        fn hash_for(channel_prefix: [u8; 4]) -> [u8; 32] {
            let mut s = fresh_session();
            handle_setup_connection(&mut s, &good_setup());
            let _ = handle_open_extended_mining_channel(
                &mut s,
                &open_ext(1, &format!("{}.w", REGTEST_ADDR)),
                OLD_PREFIX.to_vec(),
            );
            let channel_id = s.primary_channel.unwrap();
            let job = ExtendedJob {
                coinbase_prefix: vec![0xAA; 8],
                coinbase_suffix: vec![0xBB; 8],
                merkle_path: vec![[0u8; 32]],
                extranonce_prefix: OLD_PREFIX.to_vec(),
                version: 0x2000_0000,
                prev_hash: [0xCC; 32],
                n_bits: 0x1d00_ffff,
                min_ntime: 0x6500_0000,
                difficulty: Difficulty(1.0 / 4_294_967_296.0),
                coinbase_tx_value_remaining: 5_000_000_000,
                template_id: None,
                created_at: 0,
                retired_at: None,
                jdp_claims_the_block: false,
                payouts_fingerprint: [0u8; 32],
            };
            {
                let ch = s.channels.get_mut(&channel_id).unwrap();
                ch.extended_jobs.insert(7, job);
                ch.extranonce_prefix = channel_prefix.to_vec();
            }
            let sub = SubmitSharesExtendedInput {
                channel_id,
                sequence_number: 1,
                job_id: 7,
                nonce: 0x1234_5678,
                version: 0x2000_0000,
                ntime: 0x6500_0001,
                extranonce: ExtranonceBytes::from_slice(&[0x11; 8]),
                tlvs: Vec::new(),
            };
            let out = handle_submit_shares_extended(&mut s, &sub, 0);
            match out.events.first() {
                Some(SessionEvent::ShareAccepted { accept, .. }) => accept.hash,
                other => panic!("expected ShareAccepted, got {other:?}"),
            }
        }

        // Reference: the coinbase the miner hashed.
        let miner_hash = hash_for(OLD_PREFIX);
        // After a prefix change, job 7 must still validate to the same hash.
        let after_prefix_change = hash_for(NEW_PREFIX);
        assert_eq!(
            miner_hash, after_prefix_change,
            "changing the channel's extranonce prefix must not change how a \
             share for a job issued under the PREVIOUS prefix validates — \
             sourcing the prefix from the channel rebuilds a coinbase the miner \
             never hashed (SV2 Mining/SetExtranoncePrefix)"
        );
    }

    // ── UpdateChannel ──────────────────────────────────────────────

    #[test]
    fn update_channel_unknown_id_returns_error() {
        let mut s = fresh_session();
        let out = handle_update_channel(
            &mut s,
            &UpdateChannelInput {
                channel_id: 99,
                nominal_hash_rate: 1.0,
                maximum_target: [0xFF; 32],
            },
        );
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::UpdateChannelError { channel_id: 99, .. }
        ));
    }

    #[test]
    fn update_channel_emits_set_target_when_difficulty_changes() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let channel_id = s.primary_channel.unwrap();
        let out = handle_update_channel(
            &mut s,
            &UpdateChannelInput {
                channel_id,
                nominal_hash_rate: 1e9, // much higher than initial 1000
                maximum_target: [0xFF; 32],
            },
        );
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetTarget { channel_id: _, .. }
        ));
        assert!(matches!(
            out.events[0],
            SessionEvent::DifficultyChanged { .. }
        ));
    }

    /// `UpdateChannel` assigns a power of two, including from the configured floor.
    #[test]
    fn update_channel_assigns_a_power_of_two_even_through_the_floor() {
        let crooked_floor = Difficulty(3000.0);
        let mut s = MiningSessionState::new(
            Arc::new(TestClock::new(0)),
            1,
            PortConfig {
                min_difficulty: crooked_floor,
                ..port_cfg()
            },
        );
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let channel_id = s.primary_channel.unwrap();
        // A tiny reported hashrate drives the raw difficulty under the floor,
        // so the floor decides the outcome.
        let _ = handle_update_channel(
            &mut s,
            &UpdateChannelInput {
                channel_id,
                nominal_hash_rate: 1.0,
                maximum_target: [0xFF; 32],
            },
        );
        let assigned = s.channels[&channel_id].session_difficulty.as_f64();
        assert_eq!(
            assigned,
            2_f64.powf(assigned.log2().round()),
            "assigned {assigned} is not a power of two"
        );
        assert!(
            assigned >= crooked_floor.as_f64(),
            "assigned {assigned} fell below the configured floor"
        );
    }

    // ── CloseChannel ───────────────────────────────────────────────

    #[test]
    fn close_channel_drops_from_map_and_rotates_primary() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        // Open two channels — same address.
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(2, &format!("{}.w", REGTEST_ADDR)),
            vec![0x01; 4],
        );
        let first = s.primary_channel.unwrap();
        let out = handle_close_channel(
            &mut s,
            &CloseChannelInput {
                channel_id: first,
                reason_code: "miner-quit".to_string(),
            },
        );
        assert!(matches!(out.events[0], SessionEvent::ChannelClosed { .. }));
        assert_eq!(s.channels.len(), 1);
        assert_ne!(s.primary_channel, Some(first));
        assert!(s.primary_channel.is_some());
    }

    #[test]
    fn close_channel_unknown_id_is_silent() {
        let mut s = fresh_session();
        let out = handle_close_channel(
            &mut s,
            &CloseChannelInput {
                channel_id: 42,
                reason_code: "x".to_string(),
            },
        );
        assert!(out.outbound.is_empty());
        assert!(out.events.is_empty());
    }

    /// Closing a group id closes every member, one `ChannelClosed` each, and drops the group.
    #[test]
    fn close_channel_addressed_to_group_closes_all_members() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup()); // non-RSJ → grouped
        let out1 = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(1, &format!("{REGTEST_ADDR}.a")),
            vec![0xAA, 0xBB, 0xCC, 0xDD],
        );
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(2, &format!("{REGTEST_ADDR}.b")),
            vec![0x11, 0x22, 0x33, 0x44],
        );
        let gid = open_group_id(&out1);
        let members: HashSet<u32> = s.channels.keys().copied().collect();
        assert_eq!(members.len(), 2);

        let out = handle_close_channel(
            &mut s,
            &CloseChannelInput {
                channel_id: gid,
                reason_code: "bye".to_string(),
            },
        );

        assert!(s.channels.is_empty(), "group close must remove all members");
        assert!(s.groups.get(gid).is_none(), "group must be dropped");
        assert!(
            s.primary_channel.is_none(),
            "primary cleared when all channels are gone"
        );
        let closed: HashSet<u32> = out
            .events
            .iter()
            .filter_map(|e| match e {
                SessionEvent::ChannelClosed { channel_id, .. } => Some(*channel_id),
                _ => None,
            })
            .collect();
        assert_eq!(closed, members, "exactly one ChannelClosed per member");
    }

    /// Closing a grouped member by its own id removes only that member.
    #[test]
    fn close_grouped_member_by_own_id_leaves_other_members() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup()); // non-RSJ → grouped
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(1, &format!("{REGTEST_ADDR}.a")),
            vec![0xAA, 0xBB, 0xCC, 0xDD],
        );
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(2, &format!("{REGTEST_ADDR}.b")),
            vec![0x11, 0x22, 0x33, 0x44],
        );
        let ch1 = s.primary_channel.unwrap();
        let gid = s.groups.group_for_channel(ch1).unwrap();

        let out = handle_close_channel(
            &mut s,
            &CloseChannelInput {
                channel_id: ch1,
                reason_code: "bye".to_string(),
            },
        );

        assert_eq!(s.channels.len(), 1, "only the addressed member is closed");
        assert!(
            s.groups.get(gid).is_some(),
            "group survives a single-member close"
        );
        assert_eq!(
            s.groups.group_for_channel(ch1),
            None,
            "closed member dropped from group"
        );
        assert_eq!(
            out.events
                .iter()
                .filter(|e| matches!(e, SessionEvent::ChannelClosed { .. }))
                .count(),
            1,
            "single-member close emits exactly one ChannelClosed"
        );
    }

    // ── apply_vardiff_check ────────────────────────────────────────

    #[test]
    fn apply_vardiff_check_noop_without_samples() {
        let mut s = fresh_session();
        let out = apply_vardiff_check(&mut s);
        assert!(out.outbound.is_empty());
        assert!(out.events.is_empty());
    }

    /// Shares faster than the target rate ratchet the channel up with a `SetTarget`.
    #[test]
    fn apply_vardiff_check_retargets_up_when_share_rate_exceeds_target() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = MiningSessionState::new(clock.clone(), 1, port_cfg());
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let channel_id = s.primary_channel.unwrap();
        let initial = s.channels[&channel_id].session_difficulty.as_f64();

        // 1 share/s against a target of 1 per 10 s, over a full window.
        let tick_ms = 1_000_u64;
        for _ in 0..70 {
            clock.advance_ms(tick_ms);
            s.vardiff
                .get_mut(&channel_id)
                .unwrap()
                .note_share_accepted(initial);
        }
        clock.advance_ms(tick_ms);

        let out = apply_vardiff_check(&mut s);
        let new_diff = s.channels[&channel_id].session_difficulty.as_f64();
        assert!(
            new_diff > initial,
            "vardiff failed to ratchet up: initial={initial}, new={new_diff}"
        );
        assert!(
            out.outbound
                .iter()
                .any(|f| matches!(f, OutboundFrame::SetTarget { .. })),
            "no SetTarget emitted after retarget"
        );
        assert!(
            out.events
                .iter()
                .any(|e| matches!(e, SessionEvent::DifficultyChanged { .. })),
            "no DifficultyChanged event emitted after retarget"
        );
        // SetTarget alone: a fake SetNewPrevHash makes firmware reset and
        // re-mine the identical header.
        assert!(
            !out.outbound.iter().any(|f| matches!(
                f,
                OutboundFrame::SetNewPrevHash { .. }
                    | OutboundFrame::NewExtendedMiningJob { .. }
                    | OutboundFrame::NewMiningJob { .. }
            )),
            "vardiff retarget must emit SetTarget only — no job / SetNewPrevHash frame"
        );
    }

    /// Two channels on one connection retarget independently.
    #[test]
    fn vardiff_retargets_each_channel_independently() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = MiningSessionState::new(clock.clone(), 1, port_cfg());
        handle_setup_connection(&mut s, &good_setup());
        // Two channels on one connection (same locked address).
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(2, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let fast = 1u32;
        let idle = 2u32;
        let initial = s.channels[&fast].session_difficulty.as_f64();

        // Drive ONLY the fast channel well above the target rate.
        let tick_ms = 1_000_u64;
        for _ in 0..70 {
            clock.advance_ms(tick_ms);
            s.vardiff
                .get_mut(&fast)
                .unwrap()
                .note_share_accepted(initial);
        }
        clock.advance_ms(tick_ms);

        let out = apply_vardiff_check(&mut s);
        let fast_new = s.channels[&fast].session_difficulty.as_f64();
        let idle_new = s.channels[&idle].session_difficulty.as_f64();

        assert!(
            fast_new > initial,
            "fast channel must ratchet up from its own rate: {initial} -> {fast_new}"
        );
        assert!(
            idle_new < fast_new,
            "idle channel must NOT follow the fast channel's retarget \
             (independent per-channel vardiff): idle={idle_new}, fast={fast_new}"
        );
        let targets: Vec<u32> = out
            .outbound
            .iter()
            .filter_map(|f| match f {
                OutboundFrame::SetTarget { channel_id, .. } => Some(*channel_id),
                _ => None,
            })
            .collect();
        assert!(targets.contains(&fast), "fast channel must get a SetTarget");
    }

    // ── handle_request_extensions ──────────────────────────────────

    use crate::extensions::SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS;

    fn req_ext(req_id: u16, requested: Vec<u16>) -> RequestExtensions {
        RequestExtensions {
            request_id: req_id,
            requested_extensions: requested,
        }
    }

    /// Pre-SetupConnection RequestExtensions → silent drop.
    #[test]
    fn request_extensions_pre_setup_is_silent() {
        let mut s = fresh_session();
        let out = handle_request_extensions(&mut s, &req_ext(1, vec![0x0002]));
        assert!(out.outbound.is_empty());
        assert!(out.events.is_empty());
        // negotiated_extensions stays empty.
        assert!(s.negotiated_extensions.is_empty());
    }

    /// All requested extensions supported → Success + state-update.
    #[test]
    fn request_extensions_all_supported_emits_success() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let out = handle_request_extensions(&mut s, &req_ext(7, vec![0x0002]));
        match &out.outbound[0] {
            OutboundFrame::RequestExtensionsSuccess {
                request_id,
                supported_extensions,
            } => {
                assert_eq!(*request_id, 7);
                assert_eq!(supported_extensions, &vec![0x0002]);
            }
            _ => panic!("expected Success, got {:?}", out.outbound[0]),
        }
        assert!(s.negotiated_extensions.contains(&0x0002));
    }

    /// A mixed request gets Success with only the supported subset.
    #[test]
    fn request_extensions_mixed_emits_success_with_subset() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        // 0x00FF is bogus.
        let out = handle_request_extensions(&mut s, &req_ext(9, vec![0x0002, 0x0003, 0x00FF]));
        match &out.outbound[0] {
            OutboundFrame::RequestExtensionsSuccess {
                request_id,
                supported_extensions,
            } => {
                assert_eq!(*request_id, 9);
                assert_eq!(supported_extensions, &vec![0x0002, 0x0003]);
            }
            _ => panic!("expected Success-with-subset"),
        }
        assert!(s.negotiated_extensions.contains(&0x0002));
        assert!(s.negotiated_extensions.contains(&0x0003));
        assert!(!s.negotiated_extensions.contains(&0x00FF));
    }

    /// All requested unsupported AND request non-empty → Error.
    #[test]
    fn request_extensions_all_unsupported_emits_error() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let out = handle_request_extensions(&mut s, &req_ext(3, vec![0x00AA, 0x00BB]));
        match &out.outbound[0] {
            OutboundFrame::RequestExtensionsError {
                request_id,
                unsupported_extensions,
                required_extensions,
            } => {
                assert_eq!(*request_id, 3);
                assert_eq!(unsupported_extensions, &vec![0x00AA, 0x00BB]);
                assert!(required_extensions.is_empty());
            }
            _ => panic!("expected Error, got {:?}", out.outbound[0]),
        }
        // Nothing negotiated.
        assert!(s.negotiated_extensions.is_empty());
    }

    /// An empty request gets Success with an empty list.
    #[test]
    fn request_extensions_empty_request_emits_empty_success() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let out = handle_request_extensions(&mut s, &req_ext(1, vec![]));
        match &out.outbound[0] {
            OutboundFrame::RequestExtensionsSuccess {
                request_id,
                supported_extensions,
            } => {
                assert_eq!(*request_id, 1);
                assert!(supported_extensions.is_empty());
            }
            _ => panic!("expected empty Success"),
        }
    }

    // ── apply_template_broadcast ───────────────────────────────────

    use crate::mining::translator::TemplateBroadcast;
    use bp_mining_job::PayoutEntry;
    use bp_template_distribution::{ActiveTemplate, TemplateChange};

    fn payouts() -> Vec<PayoutEntry> {
        vec![PayoutEntry {
            address: REGTEST_ADDR.to_string(),
            sats: 5_000_000_000,
        }]
    }

    /// TDP-shaped `MiningJobInputs` fixture (height 200, one witness-commit OP_RETURN).
    fn synthetic_mining_job_inputs() -> MiningJobInputs {
        // BIP-34 height push for 200.
        let coinbase_prefix = vec![0x01, 0xC8];
        // 0-value witness-commitment OP_RETURN: [value:8 LE][scriptlen:0x26][script:38].
        let mut coinbase_tx_outputs = Vec::with_capacity(8 + 1 + 38);
        coinbase_tx_outputs.extend_from_slice(&0u64.to_le_bytes());
        coinbase_tx_outputs.push(0x26);
        coinbase_tx_outputs.push(0x6a); // OP_RETURN
        coinbase_tx_outputs.push(0x24); // OP_PUSHBYTES_36
        coinbase_tx_outputs.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]);
        coinbase_tx_outputs.extend_from_slice(&[0u8; 32]);
        MiningJobInputs {
            network: Network::Regtest,
            payouts: payouts(),
            payouts_fingerprint: [0u8; 32],
            pool_identifier: "blitzpool-test".to_string(),
            coinbase_prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFF_FFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
            job_cache: Arc::new(MiningJobCache::new()),
        }
    }

    fn active_template(template_id: u64, prev: [u8; 32]) -> ActiveTemplate {
        ActiveTemplate {
            template_id,
            version: 0x2000_0000,
            prev_hash: prev,
            n_bits: 0x1d00_ffff,
            header_timestamp: 0x6500_0001,
            coinbase_prefix: vec![0x03, 0xC8, 0x00, 0x00],
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xffff_ffff,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: vec![],
            coinbase_tx_outputs_count: 0,
            coinbase_tx_locktime: 0,
            merkle_path: vec![[0x11; 32], [0x22; 32]],
        }
    }

    fn broadcast(change: TemplateChange, prev: [u8; 32]) -> TemplateBroadcast {
        TemplateBroadcast {
            template: Arc::new(active_template(1, prev)),
            change,
        }
    }

    /// A fresh session with one Standard channel open.
    fn session_with_standard_channel() -> MiningSessionState<Arc<TestClock>> {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0x01, 0x02, 0x03, 0x04],
        );
        s
    }

    /// A session whose channel has a full equilibrium share window.
    fn session_with_full_window(clock: &Arc<TestClock>) -> MiningSessionState<Arc<TestClock>> {
        let mut s = MiningSessionState::new(clock.clone(), 1, port_cfg());
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let cid = s.primary_channel.unwrap();
        // 30 shares at the channel's own 1024, 10 s apart → equilibrium
        // window for the 6/min target.
        for _ in 0..30 {
            clock.advance_ms(10_000);
            s.vardiff.get_mut(&cid).unwrap().note_share_accepted(1024.0);
        }
        s
    }

    #[test]
    fn silence_eases_a_quiet_standard_channel_control() {
        // Control: with no submission, 400 s of silence DOES ease down.
        let clock = Arc::new(TestClock::new(0));
        let mut s = session_with_full_window(&clock);
        clock.advance_ms(400_000);
        let out = apply_vardiff_check(&mut s);
        assert!(
            out.outbound
                .iter()
                .any(|f| matches!(f, OutboundFrame::SetTarget { .. })),
            "control: a truly silent channel must ease down"
        );
    }

    /// Stale rejects at the channel's usual cadence are arrivals, so the same
    /// 400 s that ease a silent channel (see the control above) hold this one.
    #[test]
    fn stale_rejects_at_the_usual_cadence_hold_the_channel() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = session_with_full_window(&clock);
        let cid = s.primary_channel.unwrap();
        {
            let ch = s.channels.get_mut(&cid).unwrap();
            ch.standard_jobs
                .record_send_for_test(7, Difficulty(1024.0), [0xDD; 32], snapshot(), 0);
            ch.standard_jobs.retire(clock.now_ms());
        }
        for seq in 0..40u32 {
            clock.advance_ms(10_000);
            let sub = SubmitSharesStandardInput {
                channel_id: cid,
                sequence_number: seq,
                job_id: 7,
                nonce: seq,
                version: 0x2000_0000,
                ntime: 0x6500_0001,
            };
            let out = handle_submit_shares_standard(&mut s, &sub, clock.now_ms());
            assert!(
                matches!(
                    &out.outbound[0],
                    OutboundFrame::SubmitSharesError { error_code, .. }
                        if error_code == "stale-share"
                ),
                "precondition: submit #{seq} must be a stale reject"
            );
        }
        let out = apply_vardiff_check(&mut s);
        assert!(
            !out.outbound
                .iter()
                .any(|f| matches!(f, OutboundFrame::SetTarget { .. })),
            "stale rejects at the usual cadence must hold the channel"
        );
    }

    /// An invalid-job share is no arrival on either handler: it is refused
    /// before any duplicate check, so a resent one would inflate the rate.
    #[test]
    fn invalid_job_rejects_do_not_count_as_arrivals() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = session_with_full_window(&clock);
        let cid = s.primary_channel.unwrap();
        let before = s.vardiff[&cid].window_shares();
        let sub = SubmitSharesStandardInput {
            channel_id: cid,
            sequence_number: 1,
            job_id: 7, // never sent
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
        };
        let out = handle_submit_shares_standard(&mut s, &sub, clock.now_ms());
        assert!(
            matches!(
                &out.outbound[0],
                OutboundFrame::SubmitSharesError { error_code, .. }
                    if error_code == ERR_INVALID_JOB_ID
            ),
            "precondition: the submit must be an invalid-job reject"
        );
        assert_eq!(s.vardiff[&cid].window_shares(), before, "Standard");

        let mut s = MiningSessionState::new(clock.clone(), 1, port_cfg());
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let cid = s.primary_channel.unwrap();
        let sub = SubmitSharesExtendedInput {
            channel_id: cid,
            sequence_number: 1,
            job_id: 99,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
            extranonce: ExtranonceBytes::from_slice(&[0x11; 4]),
            tlvs: Vec::new(),
        };
        let out = handle_submit_shares_extended(&mut s, &sub, clock.now_ms());
        assert!(
            matches!(
                &out.outbound[0],
                OutboundFrame::SubmitSharesError { error_code, .. }
                    if error_code == ERR_INVALID_JOB_ID
            ),
            "precondition: the submit must be an invalid-job reject"
        );
        assert_eq!(s.vardiff[&cid].window_shares(), 0, "Extended");
    }

    /// A bad-extranonce-size reject is malformed work, so it is no arrival and
    /// leaves the silence evidence alone.
    #[test]
    fn a_bad_extranonce_size_reject_leaves_the_silence_evidence() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = MiningSessionState::new(clock.clone(), 1, port_cfg());
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        send_first_job(&mut s);
        let cid = s.primary_channel.unwrap();
        let job = ExtendedJob {
            payouts_fingerprint: [0u8; 32],
            coinbase_prefix: vec![0xAA; 8],
            coinbase_suffix: vec![0xBB; 8],
            merkle_path: vec![[0u8; 32]],
            extranonce_prefix: vec![0; 4],
            version: 0x2000_0000,
            prev_hash: [0xCC; 32],
            n_bits: 0x1d00_ffff,
            min_ntime: 0x6500_0000,
            difficulty: Difficulty(1024.0),
            coinbase_tx_value_remaining: 5_000_000_000,
            template_id: None,
            jdp_claims_the_block: false,
            created_at: 0,
            retired_at: None,
        };
        s.channels
            .get_mut(&cid)
            .unwrap()
            .extended_jobs
            .insert(7, job);

        clock.advance_ms(120_000);
        let before = s.vardiff[&cid].silence_implied_max_difficulty();
        assert!(
            before.is_some(),
            "precondition: two silent minutes are evidence"
        );

        let sub = SubmitSharesExtendedInput {
            channel_id: cid,
            sequence_number: 1,
            job_id: 7,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
            extranonce: ExtranonceBytes::from_slice(&[0x11; 7]),
            tlvs: Vec::new(),
        };
        let out = handle_submit_shares_extended(&mut s, &sub, clock.now_ms());
        assert!(
            matches!(
                &out.outbound[0],
                OutboundFrame::SubmitSharesError { error_code, .. }
                    if error_code == crate::mining::submit::ERR_BAD_EXTRANONCE_SIZE
            ),
            "precondition: the submit must be a bad-extranonce-size reject"
        );
        assert_eq!(
            s.vardiff[&cid].silence_implied_max_difficulty(),
            before,
            "a reject that hashed nothing must not spend the silence evidence"
        );
    }

    // ── no-share descent ──────────────────────────────────────────

    /// A session whose channel has never submitted anything (opens at 1024).
    fn unproven_session(clock: &Arc<TestClock>) -> MiningSessionState<Arc<TestClock>> {
        let mut s = MiningSessionState::new(clock.clone(), 1, port_cfg());
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        send_first_job(&mut s);
        s
    }

    /// Send every channel a job, as the server does right after open.
    fn send_first_job(s: &mut MiningSessionState<Arc<TestClock>>) {
        let _ = apply_template_broadcast(
            s,
            &broadcast(TemplateChange::NewBlock, [0xAB; 32]),
            &synthetic_mining_job_inputs(),
            0,
            None,
        );
    }

    /// A channel is judged only once it got a job: ten minutes without one
    /// hold, and they do not count as silence once the job goes out.
    #[test]
    fn a_channel_is_eased_down_only_once_it_got_a_job() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = MiningSessionState::new(clock.clone(), 1, port_cfg());
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let cid = s.primary_channel.unwrap();
        clock.advance_ms(600_000);
        let out = apply_vardiff_check(&mut s);
        assert!(out.outbound.is_empty(), "no job yet, no retarget");

        send_first_job(&mut s);
        assert!(
            !s.channels[&cid].standard_jobs.is_empty(),
            "precondition: the broadcast stored a job"
        );
        clock.advance_ms(61_000);
        let _ = apply_vardiff_check(&mut s);
        // One silent minute at 1024 bounds the rate at 512; counting the ten
        // minutes before the job as well would read 64.
        assert_eq!(s.channels[&cid].session_difficulty, Difficulty(512.0));
    }

    #[test]
    fn a_channel_with_no_share_ever_is_eased_down_on_the_wire() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = unproven_session(&clock);
        let cid = s.primary_channel.unwrap();
        assert_eq!(s.channels[&cid].session_difficulty, Difficulty(1024.0));

        clock.advance_ms(61_000); // a full window, ~6 missed share gaps
        let out = apply_vardiff_check(&mut s);
        assert!(
            out.outbound
                .iter()
                .any(|f| matches!(f, OutboundFrame::SetTarget { .. })),
            "an unreachable difficulty must be walked down before the first share"
        );
        assert!(
            s.channels[&cid].session_difficulty < Difficulty(1024.0),
            "difficulty did not drop: {:?}",
            s.channels[&cid].session_difficulty
        );
    }

    /// A repeated `UpdateChannel` claim cannot undo the descent; a new, lower one is honoured.
    #[test]
    fn update_channel_cannot_raise_a_silent_channel_back_up_on_repeat() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = unproven_session(&clock);
        let cid = s.primary_channel.unwrap();
        let claim = UpdateChannelInput {
            channel_id: cid,
            nominal_hash_rate: 1e12, // derives ~4096
            maximum_target: [0xFF; 32],
        };
        // First time it is news, and news is honoured.
        let _ = handle_update_channel(&mut s, &claim);

        // Then total silence, and the descent walks it down.
        clock.advance_ms(61_000);
        let _ = apply_vardiff_check(&mut s);
        let descended = s.channels[&cid].session_difficulty;
        assert!(
            descended < Difficulty(4096.0),
            "precondition: descent moved"
        );

        // The very same claim, re-asserted on the translator's 60 s timer.
        let out = handle_update_channel(&mut s, &claim);
        assert!(
            out.outbound.is_empty(),
            "a repeated claim must not undo the descent"
        );
        assert_eq!(s.channels[&cid].session_difficulty, descended);
    }

    #[test]
    fn update_channel_may_still_lower_an_unproven_channel() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = unproven_session(&clock);
        let cid = s.primary_channel.unwrap();
        clock.advance_ms(61_000);
        let _ = apply_vardiff_check(&mut s);
        let descended = s.channels[&cid].session_difficulty;

        // A new, lower declaration is always honoured.
        let _ = handle_update_channel(
            &mut s,
            &UpdateChannelInput {
                channel_id: cid,
                nominal_hash_rate: 1_000.0,
                maximum_target: [0xFF; 32],
            },
        );
        assert!(
            s.channels[&cid].session_difficulty < descended,
            "a lower declaration must still be honoured"
        );
    }

    /// The SV2 Mining/UpdateChannel MUST on `maximum_target` still wins over the silence cap.
    #[test]
    fn update_channel_max_target_still_overrides_the_guard() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = unproven_session(&clock);
        let cid = s.primary_channel.unwrap();
        clock.advance_ms(61_000);
        let _ = apply_vardiff_check(&mut s);
        let descended = s.channels[&cid].session_difficulty;

        let _ = handle_update_channel(
            &mut s,
            &UpdateChannelInput {
                channel_id: cid,
                nominal_hash_rate: 1e12,
                maximum_target: difficulty_to_target(Difficulty(8192.0)).to_le_bytes(),
            },
        );
        assert!(
            s.channels[&cid].session_difficulty > descended,
            "maximum_target is a MUST and must survive the no-raise guard"
        );
    }

    /// After an accepted share the silence cap no longer applies.
    #[test]
    fn update_channel_raises_freely_once_a_share_was_accepted() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = unproven_session(&clock);
        let cid = s.primary_channel.unwrap();
        s.vardiff.get_mut(&cid).unwrap().note_share_accepted(1024.0);

        let out = handle_update_channel(
            &mut s,
            &UpdateChannelInput {
                channel_id: cid,
                nominal_hash_rate: 1e12,
                maximum_target: [0xFF; 32],
            },
        );
        assert!(
            !out.outbound.is_empty(),
            "a proven channel must follow its declaration again"
        );
        assert!(s.channels[&cid].session_difficulty > Difficulty(1024.0));
    }

    /// Across the whole silence range only a REPEATED declaration is capped.
    #[test]
    fn the_update_channel_cap_only_bites_on_a_repeated_declaration() {
        // A NEW declaration is honoured at every silence duration.
        for quiet_s in [10u64, 61, 120, 300, 600, 3_600] {
            let clock = Arc::new(TestClock::new(0));
            let mut s = unproven_session(&clock);
            let cid = s.primary_channel.unwrap();
            clock.advance_ms(quiet_s * 1_000);
            let before = s.channels[&cid].session_difficulty;
            let _ = handle_update_channel(
                &mut s,
                &UpdateChannelInput {
                    channel_id: cid,
                    nominal_hash_rate: 100e12, // news: rigs just attached
                    maximum_target: [0xFF; 32],
                },
            );
            assert!(
                s.channels[&cid].session_difficulty > before,
                "{quiet_s}s quiet: a NEW declaration must be honoured, \
                 stayed at {:?}",
                s.channels[&cid].session_difficulty
            );
        }

        // The same claim re-sent on a timer cannot hold the difficulty up.
        let clock = Arc::new(TestClock::new(0));
        let mut s = unproven_session(&clock);
        let cid = s.primary_channel.unwrap();
        let claim = UpdateChannelInput {
            channel_id: cid,
            nominal_hash_rate: 100e12,
            maximum_target: [0xFF; 32],
        };
        clock.advance_ms(10_000);
        let _ = handle_update_channel(&mut s, &claim); // honoured
        let peak = s.channels[&cid].session_difficulty;
        assert!(peak > Difficulty(1024.0));

        // Now it repeats it every 60 s while producing nothing at all.
        for _ in 0..10 {
            clock.advance_ms(60_000);
            let _ = handle_update_channel(&mut s, &claim);
        }
        assert!(
            s.channels[&cid].session_difficulty < peak,
            "a claim re-sent on a timer through total silence must stop \
             holding the difficulty up (still at {:?})",
            s.channels[&cid].session_difficulty
        );
    }

    /// A proxy's first real declaration after its rigs attach is honoured.
    #[test]
    fn update_channel_honours_a_fresh_channels_first_real_declaration() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = unproven_session(&clock);
        let cid = s.primary_channel.unwrap();
        assert_eq!(s.channels[&cid].session_difficulty, Difficulty(1024.0));

        // Rigs attach seconds later; the proxy declares 100 TH/s. No share
        // has been accepted and none could have been.
        clock.advance_ms(5_000);
        let out = handle_update_channel(
            &mut s,
            &UpdateChannelInput {
                channel_id: cid,
                nominal_hash_rate: 100e12,
                maximum_target: [0xFF; 32],
            },
        );
        assert!(
            !out.outbound.is_empty(),
            "a fresh channel's first honest declaration must be honoured"
        );
        assert!(
            s.channels[&cid].session_difficulty > Difficulty(1024.0),
            "farm pinned at the opening difficulty: {:?}",
            s.channels[&cid].session_difficulty
        );
    }

    /// Neither the floor nor the power-of-two round-up lifts a capped claim back up.
    #[test]
    fn the_no_raise_guard_survives_the_floor_and_the_rounding() {
        for min_diff in [0.00001, 0.3, 1.0, 500.0, 3000.0, 5000.0] {
            let clock = Arc::new(TestClock::new(0));
            let mut cfg = port_cfg();
            cfg.min_difficulty = Difficulty(min_diff);
            let mut s = MiningSessionState::new(clock.clone(), 1, cfg);
            handle_setup_connection(&mut s, &good_setup());
            let _ = handle_open_standard_mining_channel(
                &mut s,
                &open_std(1, &format!("{}.w", REGTEST_ADDR)),
                vec![0; 4],
            );
            send_first_job(&mut s);
            let cid = s.primary_channel.unwrap();
            let claim = UpdateChannelInput {
                channel_id: cid,
                nominal_hash_rate: 1e15,
                maximum_target: [0xFF; 32],
            };
            // State the claim once so later sends are repeats, then let
            // the descent run through total silence.
            let _ = handle_update_channel(&mut s, &claim);
            let claimed = s.channels[&cid].session_difficulty.as_f64();
            for _ in 0..6 {
                clock.advance_ms(60_000);
                let _ = apply_vardiff_check(&mut s);
            }
            let before = s.channels[&cid].session_difficulty.as_f64();
            assert!(
                before < claimed,
                "min_difficulty={min_diff}: precondition: the descent moved from {claimed}"
            );

            // Re-assert it repeatedly, as a translator does.
            for _ in 0..3 {
                let _ = handle_update_channel(&mut s, &claim);
                let after = s.channels[&cid].session_difficulty.as_f64();
                assert!(
                    after <= before,
                    "min_difficulty={min_diff}: unproven channel raised {before} -> {after} \
                     (the floor or the round-up stepped over the guard)"
                );
            }
        }
    }

    // ── inline vardiff cooldown ───────────────────────────────────

    /// The inline check runs at most once per `vardiff_interval_ms`.
    #[test]
    fn vardiff_cooldown_blocks_a_second_inline_check_inside_the_interval() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let mut s = MiningSessionState::new(clock.clone(), 1, port_cfg());
        assert_eq!(s.vardiff_interval_ms, 60_000, "fixture assumption");

        s.mark_vardiff_checked();
        assert!(
            !s.vardiff_cooldown_elapsed(),
            "a check that just ran must close the gate"
        );
        clock.advance_ms(59_999);
        assert!(
            !s.vardiff_cooldown_elapsed(),
            "one ms short of the interval"
        );
        clock.advance_ms(1);
        assert!(s.vardiff_cooldown_elapsed(), "exactly at the interval");
    }

    /// The gate paces repeats but never delays the first check.
    #[test]
    fn vardiff_cooldown_is_open_on_a_fresh_session() {
        let clock = Arc::new(TestClock::new(1_784_000_000_000));
        let s = MiningSessionState::new(clock, 1, port_cfg());
        assert_eq!(s.last_difficulty_check_ms, 0);
        assert!(s.vardiff_cooldown_elapsed());
    }

    /// A backwards clock step keeps the gate closed only until the clock catches up.
    #[test]
    fn vardiff_cooldown_survives_a_backwards_clock_step() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let mut s = MiningSessionState::new(clock.clone(), 1, port_cfg());
        s.mark_vardiff_checked();
        clock.set_ms(500_000);
        assert!(!s.vardiff_cooldown_elapsed(), "no panic, gate just closed");
        clock.set_ms(1_000_000 + 60_000);
        assert!(s.vardiff_cooldown_elapsed());
    }

    /// A session with one Extended channel the pool HAS served work on: tip and
    /// `n_bits` are set as `server.rs` does at open, matching the job fixtures.
    /// Cold-start tests clear them explicitly.
    fn session_with_extended_channel() -> MiningSessionState<Arc<TestClock>> {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0xAA, 0xBB, 0xCC, 0xDD],
        );
        if let Some(cid) = s.primary_channel {
            if let Some(ch) = s.channels.get_mut(&cid) {
                ch.latest_extended_prev_hash = Some([0xAB; 32]);
                ch.latest_extended_n_bits = Some(0x1d00_ffff);
            }
        }
        s
    }

    /// TDP-only sessions never receive mining-job frames.
    #[test]
    fn template_broadcast_skipped_for_tdp_client() {
        let mut s = session_with_standard_channel();
        s.is_tdp_client = true;
        let mj = synthetic_mining_job_inputs();
        let out = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xAB; 32]),
            &mj,
            1_000,
            None,
        );
        assert!(
            out.outbound.is_empty(),
            "TDP client must not receive any frames"
        );
        assert!(out.events.is_empty());
    }

    /// The Extended scriptsig_len varint is sized for the channel's own extranonce, not 12.
    #[test]
    fn template_broadcast_extended_uses_correctly_sized_scriptsig_len() {
        // 6-byte miner extranonce: total 4+6=10 < 12.
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let mut open = open_ext(1, &format!("{}.w", REGTEST_ADDR));
        open.min_extranonce_size = 6;
        let _ = handle_open_extended_mining_channel(&mut s, &open, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let cid = s.primary_channel.expect("channel opened");
        assert_eq!(
            s.channels.get(&cid).unwrap().extranonce_size,
            6,
            "test precondition: channel must use 6-byte extranonce"
        );

        let mj = synthetic_mining_job_inputs();
        // With a 10-byte slot the varint at offset 41 must be 2 less than
        // the 12-byte baseline.
        let baseline_job = mj.build(EXTRANONCE_SLOT_LEN).expect("baseline builds");
        let baseline_varint = baseline_job.coinbase_prefix()[41];

        let _ = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xAB; 32]),
            &mj,
            1_000,
            None,
        );

        let ext_job = s
            .channels
            .get(&cid)
            .expect("channel still present")
            .extended_jobs
            .values()
            .next()
            .expect("apply_template_broadcast must have stored an ExtendedJob");
        // Byte 41 is the scriptsig_len varint.
        let actual_varint = ext_job.coinbase_prefix[41];
        assert_eq!(
            actual_varint as i32,
            baseline_varint as i32 - 2,
            "scriptsig_len varint must be {} (baseline {} for 12-byte \
             slot, minus 2 for the 10-byte total extranonce = 4 prefix \
             + 6 miner)",
            baseline_varint - 2,
            baseline_varint
        );
    }

    /// NewBlock on a Standard channel sends a future job then `SetNewPrevHash`, storing the root.
    #[test]
    fn template_broadcast_standard_new_block_emits_set_prev_and_new_mining_job() {
        let mut s = session_with_standard_channel();
        let cid = s.primary_channel.unwrap();
        let mj = synthetic_mining_job_inputs();
        let out = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xAB; 32]),
            &mj,
            1_000,
            None,
        );
        assert_eq!(
            out.outbound.len(),
            2,
            "expect NewMiningJob (future job) + SetNewPrevHash"
        );
        // Future job first, then SetNewPrevHash activates it.
        let stored = match &out.outbound[0] {
            OutboundFrame::NewMiningJob {
                channel_id,
                job_id,
                version,
                merkle_root,
                min_ntime,
            } => {
                assert_eq!(*channel_id, cid);
                assert_eq!(*job_id, 1);
                assert_eq!(*version, 0x2000_0000);
                assert_eq!(*min_ntime, None, "block-change job must be a future job");
                *merkle_root
            }
            other => panic!("expected NewMiningJob, got {other:?}"),
        };
        match &out.outbound[1] {
            OutboundFrame::SetNewPrevHash {
                channel_id,
                job_id,
                prev_hash,
                n_bits,
                min_ntime,
            } => {
                assert_eq!(*channel_id, cid);
                assert_eq!(*job_id, 1);
                assert_eq!(*prev_hash, [0xAB; 32]);
                assert_eq!(*n_bits, 0x1d00_ffff);
                assert_eq!(*min_ntime, 0x6500_0001);
            }
            other => panic!("expected SetNewPrevHash, got {other:?}"),
        }
        let ch = s.channels.get(&cid).unwrap();
        let (diff, root) = ch.standard_jobs.lookup(1).expect("entry must exist");
        assert_eq!(root, stored, "stored merkle root must match emitted frame");
        assert_eq!(diff, ch.session_difficulty);
        // Block context cached for later Refresh.
        assert_eq!(ch.latest_extended_prev_hash, Some([0xAB; 32]));
        assert_eq!(ch.latest_extended_n_bits, Some(0x1d00_ffff));
    }

    /// A client without `REQUIRES_VERSION_ROLLING` still gets `version_rolling_allowed: true`.
    #[test]
    fn version_rolling_is_allowed_for_a_client_that_never_asked_for_it() {
        let mut s = fresh_session();
        let mut setup = good_setup();
        setup.flags = 0;
        // Precondition: the flag really is absent.
        assert_eq!(setup.flags & FLAG_REQUIRES_VERSION_ROLLING, 0);
        handle_setup_connection(&mut s, &setup);
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(1, &format!("{REGTEST_ADDR}.w")),
            vec![0xAA, 0xBB, 0xCC, 0xDD],
        );

        let mj = synthetic_mining_job_inputs();
        let out = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xCC; 32]),
            &mj,
            1_000,
            None,
        );
        let allowed = out.outbound.iter().find_map(|f| match f {
            OutboundFrame::NewExtendedMiningJob {
                version_rolling_allowed,
                ..
            } => Some(*version_rolling_allowed),
            _ => None,
        });
        assert_eq!(
            allowed,
            Some(true),
            "an extended job must allow BIP-323 rolling even when the client \
             never required it — SV2 Mining/SetupConnection Flags for Mining Protocol's flag says 'I need this', not 'I may'"
        );
    }

    /// NewBlock on an Extended channel splits the coinbase at the prefix and records an ExtendedJob.
    #[test]
    fn template_broadcast_extended_new_block_emits_set_prev_and_new_ext_mining_job() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        // The channel was grouped, so the job goes to its `group_channel_id`.
        let gid = s
            .groups
            .group_for_channel(cid)
            .expect("non-RSJ extended channel must be grouped");
        let mj = synthetic_mining_job_inputs();
        let out = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xCC; 32]),
            &mj,
            1_000,
            None,
        );
        assert_eq!(out.outbound.len(), 2);
        // SV2 future-job order: future job first, then activation.
        assert!(matches!(
            out.outbound[1],
            OutboundFrame::SetNewPrevHash { channel_id, .. } if channel_id == gid
        ));
        match &out.outbound[0] {
            OutboundFrame::NewExtendedMiningJob {
                channel_id,
                job_id,
                version,
                version_rolling_allowed,
                merkle_path,
                coinbase_tx_prefix,
                coinbase_tx_suffix,
                min_ntime,
            } => {
                assert_eq!(*channel_id, gid);
                assert_eq!(*job_id, 1);
                assert_eq!(*version, 0x2000_0000);
                // `VERSION_ROLLING_ALLOWED`, not a setup-flag echo.
                assert!(*version_rolling_allowed);
                assert_eq!(merkle_path.len(), 2);
                // The wire prefix MUST NOT include the channel's extranonce
                // prefix (`[0xAA,0xBB,0xCC,0xDD]` here); the miner inserts it.
                assert!(
                    !coinbase_tx_prefix.ends_with(&[0xAA, 0xBB, 0xCC, 0xDD]),
                    "tx_prefix must NOT include channel's extranonce_prefix \
                     (the miner appends it at coinbase-reconstruction time)"
                );
                assert!(!coinbase_tx_suffix.is_empty());
                assert_eq!(*min_ntime, None, "block-change job must be a future job");
            }
            other => panic!("expected NewExtendedMiningJob, got {other:?}"),
        }
        let ch = s.channels.get(&cid).unwrap();
        let stored = ch.extended_jobs.get(&1).expect("ext_job must be stored");
        assert_eq!(stored.template_id, Some(1));
        assert_eq!(stored.difficulty, ch.session_difficulty);
        assert!(stored.retired_at.is_none());
    }

    // ── Group channels (SV2 Mining/Group Channel) ───────────────────

    fn open_group_id(out: &HandlerOutcome) -> u32 {
        match &out.outbound[0] {
            OutboundFrame::OpenExtendedMiningChannelSuccess {
                group_channel_id, ..
            } => *group_channel_id,
            other => panic!("expected OpenExtendedMiningChannelSuccess, got {other:?}"),
        }
    }

    #[test]
    fn non_rsj_extended_channels_same_size_share_one_group() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup()); // non-RSJ
        let out1 = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(1, &format!("{REGTEST_ADDR}.a")),
            vec![0xAA, 0xBB, 0xCC, 0xDD],
        );
        let out2 = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(2, &format!("{REGTEST_ADDR}.b")),
            vec![0x11, 0x22, 0x33, 0x44],
        );
        let g1 = open_group_id(&out1);
        let g2 = open_group_id(&out2);
        assert_ne!(g1, 0, "non-RSJ extended channel must be grouped");
        assert_eq!(g1, g2, "same full extranonce size → one shared group");
        // The group id never collides with a channel id (SV2 Mining/Group Channel).
        assert!(
            !s.channels.contains_key(&g1),
            "group id must not be a channel id"
        );
        for cid in s.channels.keys().copied().collect::<Vec<_>>() {
            assert_eq!(s.groups.group_for_channel(cid), Some(g1));
        }
    }

    #[test]
    fn rsj_connection_does_not_group_extended_channel() {
        let mut s = fresh_session();
        let mut setup = good_setup();
        setup.flags |= FLAG_REQUIRES_STANDARD_JOBS;
        handle_setup_connection(&mut s, &setup);
        let out = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(1, &format!("{REGTEST_ADDR}.w")),
            vec![0xAA, 0xBB, 0xCC, 0xDD],
        );
        assert_eq!(open_group_id(&out), 0, "RSJ connection must never group");
        assert!(s.groups.is_empty());
    }

    #[test]
    fn grouped_broadcast_emits_one_job_with_shared_job_id_on_all_members() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(1, &format!("{REGTEST_ADDR}.a")),
            vec![0xAA, 0xBB, 0xCC, 0xDD],
        );
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(2, &format!("{REGTEST_ADDR}.b")),
            vec![0x11, 0x22, 0x33, 0x44],
        );
        let members: Vec<u32> = s.channels.keys().copied().collect();
        assert_eq!(members.len(), 2);
        let gid = s.groups.group_for_channel(members[0]).unwrap();

        let mj = synthetic_mining_job_inputs();
        let out = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xCC; 32]),
            &mj,
            1_000,
            None,
        );

        // Exactly ONE group-addressed job + ONE prev-hash — NOT one per member.
        let jobs: Vec<&OutboundFrame> = out
            .outbound
            .iter()
            .filter(|f| matches!(f, OutboundFrame::NewExtendedMiningJob { .. }))
            .collect();
        assert_eq!(jobs.len(), 1, "one group job, not one per channel");
        assert_eq!(
            out.outbound
                .iter()
                .filter(|f| matches!(f, OutboundFrame::SetNewPrevHash { .. }))
                .count(),
            1
        );
        let group_job_id = match jobs[0] {
            OutboundFrame::NewExtendedMiningJob {
                channel_id, job_id, ..
            } => {
                assert_eq!(*channel_id, gid, "job addressed to the group");
                *job_id
            }
            _ => unreachable!(),
        };
        // The same shared job_id is recorded on every member.
        for cid in members {
            assert!(
                s.channels
                    .get(&cid)
                    .unwrap()
                    .extended_jobs
                    .contains_key(&group_job_id),
                "shared group job must be stored on member {cid}"
            );
        }
    }

    /// A share against the shared group `job_id` validates on a member channel.
    #[test]
    fn grouped_member_share_against_group_job_id_validates() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup()); // non-RSJ → grouped
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(1, &format!("{REGTEST_ADDR}.a")),
            vec![0xAA, 0xBB, 0xCC, 0xDD],
        );
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(2, &format!("{REGTEST_ADDR}.b")),
            vec![0x11, 0x22, 0x33, 0x44],
        );
        let member = s.primary_channel.unwrap();

        let mj = synthetic_mining_job_inputs();
        let out = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xCC; 32]),
            &mj,
            1_000,
            None,
        );
        let group_job_id = out
            .outbound
            .iter()
            .find_map(|f| match f {
                OutboundFrame::NewExtendedMiningJob { job_id, .. } => Some(*job_id),
                _ => None,
            })
            .expect("group NewExtendedMiningJob emitted");

        // Cloned out to re-borrow the channel mutably below.
        let job = s
            .channels
            .get(&member)
            .unwrap()
            .extended_jobs
            .get(&group_job_id)
            .expect("group job stored on member channel")
            .clone();

        // Trivial difficulty: an Accept isolates the coinbase-reconstruction path.
        let sub = SubmitSharesExtendedInput {
            channel_id: member,
            sequence_number: 1,
            job_id: group_job_id,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
            extranonce: ExtranonceBytes::from_slice(&[0x11u8; 8]),
            tlvs: Vec::new(),
        };
        let member_ch = s.channels.get_mut(&member).unwrap();
        let res = validate_ext(
            member_ch,
            &sub,
            &job,
            Difficulty(1.0 / 4_294_967_296.0),
            2_000,
            false,
            false,
        );
        assert!(
            matches!(res, ShareValidation::Accepted(_)),
            "share against the shared group job_id must validate, got {res:?}"
        );
    }

    /// A second grouped channel gets the group's current job without disturbing the first.
    #[test]
    fn grouped_channel_onboard_reuses_current_job_without_disrupting_members() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup()); // non-RSJ
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(1, &format!("{REGTEST_ADDR}.a")),
            vec![0xAA, 0xBB, 0xCC, 0xDD],
        );
        let ch1 = s.primary_channel.unwrap();
        let mj = synthetic_mining_job_inputs();
        // IO layer sends ch1 its initial job (NewBlock + only_channel).
        let out1 = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xCC; 32]),
            &mj,
            1_000,
            Some(ch1),
        );
        let job1 = out1
            .outbound
            .iter()
            .find_map(|f| match f {
                OutboundFrame::NewExtendedMiningJob { job_id, .. } => Some(*job_id),
                _ => None,
            })
            .expect("ch1 initial job");

        // Second channel opens; IO layer sends ITS initial job.
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(2, &format!("{REGTEST_ADDR}.b")),
            vec![0x11, 0x22, 0x33, 0x44],
        );
        let ch2 = s.channels.keys().copied().find(|&c| c != ch1).unwrap();
        let gid = s.groups.group_for_channel(ch2).unwrap();
        let out2 = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xCC; 32]),
            &mj,
            2_000,
            Some(ch2),
        );
        let (onboard_job, onboard_channel) = out2
            .outbound
            .iter()
            .find_map(|f| match f {
                OutboundFrame::NewExtendedMiningJob {
                    job_id, channel_id, ..
                } => Some((*job_id, *channel_id)),
                _ => None,
            })
            .expect("ch2 onboard job");

        // New member reuses the CURRENT group job_id — not a fresh one.
        assert_eq!(
            onboard_job, job1,
            "onboard must reuse the current group job_id"
        );
        // Addressed to the new member's own id, never the group id.
        assert_eq!(
            onboard_channel, ch2,
            "onboard job must be addressed to the new member's own channel, not the group"
        );
        assert!(
            !out2.outbound.iter().any(|f| matches!(
                f,
                OutboundFrame::NewExtendedMiningJob { channel_id, .. }
                    | OutboundFrame::SetNewPrevHash { channel_id, .. }
                    if *channel_id == gid
            )),
            "onboard must not emit any group-addressed frame that would reach existing members"
        );
        // ch1's job survives and is NOT retired (no spurious new block on join).
        assert!(
            s.channels
                .get(&ch1)
                .unwrap()
                .extended_jobs
                .get(&job1)
                .unwrap()
                .retired_at
                .is_none(),
            "existing member's job must not be retired on a join"
        );
        // ch2 holds the same shared job.
        assert!(s
            .channels
            .get(&ch2)
            .unwrap()
            .extended_jobs
            .contains_key(&job1));
        // A share against the un-disrupted job still validates on ch1.
        let job = s
            .channels
            .get(&ch1)
            .unwrap()
            .extended_jobs
            .get(&job1)
            .unwrap()
            .clone();
        let sub = SubmitSharesExtendedInput {
            channel_id: ch1,
            sequence_number: 1,
            job_id: job1,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
            extranonce: ExtranonceBytes::from_slice(&[0x11u8; 8]),
            tlvs: Vec::new(),
        };
        let res = validate_ext(
            s.channels.get_mut(&ch1).unwrap(),
            &sub,
            &job,
            Difficulty(1.0 / 4_294_967_296.0),
            3_000,
            false,
            false,
        );
        assert!(
            matches!(res, ShareValidation::Accepted(_)),
            "ch1 share must still validate after a join, got {res:?}"
        );
    }

    /// [`standard_member_root_and_coinbase`] matches `MiningJob::coinbase_txid_with_extranonce`.
    #[test]
    fn standard_member_helper_matches_mining_job_splice() {
        let mj = synthetic_mining_job_inputs();
        let job = mj.build(EXTRANONCE_SLOT_LEN).unwrap();
        let prefix = vec![0xAB, 0xCD, 0xEF, 0x01];
        let merkle_path = vec![[0x33u8; 32], [0x44u8; 32]];

        let mut enonce1 = [0u8; 4];
        enonce1.copy_from_slice(&prefix);
        let enonce2 = [0u8; 8];
        let txid = job.coinbase_txid_with_extranonce(&enonce1, &enonce2);
        let expected_root = merkle_root_from_coinbase(&txid, &merkle_path);

        let (root, coinbase) = standard_member_root_and_coinbase(
            job.coinbase_prefix(),
            job.coinbase_suffix(),
            &prefix,
            &merkle_path,
        );
        assert_eq!(
            root, expected_root,
            "helper root must match the canonical MiningJob splice"
        );

        let mut expected_cb = Vec::new();
        expected_cb.extend_from_slice(job.coinbase_prefix());
        expected_cb.extend_from_slice(&enonce1);
        expected_cb.extend_from_slice(&enonce2);
        expected_cb.extend_from_slice(job.coinbase_suffix());
        assert_eq!(coinbase, expected_cb, "helper coinbase bytes must match");
    }

    /// A same-block refresh sends only an active NewMiningJob, retiring nothing.
    #[test]
    fn template_broadcast_refresh_skips_set_prev_hash_and_retire() {
        let mut s = session_with_standard_channel();
        let cid = s.primary_channel.unwrap();
        let mj = synthetic_mining_job_inputs();
        // First broadcast: NewBlock seeds an entry + caches prev-hash.
        let _ = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xAB; 32]),
            &mj,
            1_000,
            None,
        );
        // Different work, so it is not suppressed as an identical re-issue.
        let mut mj2 = synthetic_mining_job_inputs();
        mj2.coinbase_prefix = vec![0x01, 0xC9];
        let out = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::Refresh, [0xAB; 32]),
            &mj2,
            2_000,
            None,
        );
        assert_eq!(
            out.outbound.len(),
            1,
            "only NewMiningJob, no SetNewPrevHash"
        );
        // An ACTIVE job (`Some(min_ntime)`), not a future one.
        match &out.outbound[0] {
            OutboundFrame::NewMiningJob { min_ntime, .. } => assert!(
                min_ntime.is_some(),
                "a same-block refresh job must be active (Some(min_ntime))"
            ),
            other => panic!("expected NewMiningJob, got {other:?}"),
        }
        let ch = s.channels.get(&cid).unwrap();
        // The job_id=1 entry is still Active.
        assert_eq!(
            ch.standard_jobs.classify(1, 2_000),
            Some(bp_jobs_lifecycle::JobClassification::Active),
            "Refresh must not retire existing entries"
        );
    }

    /// An identical same-block refresh is suppressed; changed work and block changes are sent.
    #[test]
    fn template_broadcast_refresh_suppresses_byte_identical_reissue() {
        let mut s = session_with_standard_channel();
        let mj = synthetic_mining_job_inputs();
        // Seed the channel's last-job signature via a block change.
        let seed = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xAB; 32]),
            &mj,
            1_000,
            None,
        );
        assert!(seed
            .outbound
            .iter()
            .any(|f| matches!(f, OutboundFrame::NewMiningJob { .. })));

        // Byte-identical refresh → nothing on the wire.
        let dup = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::Refresh, [0xAB; 32]),
            &mj,
            2_000,
            None,
        );
        assert!(
            dup.outbound.is_empty(),
            "byte-identical refresh must not re-issue a job"
        );

        // Refresh with changed work → a fresh NewMiningJob.
        let mut mj2 = synthetic_mining_job_inputs();
        mj2.coinbase_prefix = vec![0x01, 0xC9];
        let changed = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::Refresh, [0xAB; 32]),
            &mj2,
            3_000,
            None,
        );
        assert!(
            changed
                .outbound
                .iter()
                .any(|f| matches!(f, OutboundFrame::NewMiningJob { .. })),
            "a refresh with changed work must be sent"
        );

        // A block change re-issues even if the work matches the last job.
        let block = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xCD; 32]),
            &mj2,
            4_000,
            None,
        );
        assert!(
            block
                .outbound
                .iter()
                .any(|f| matches!(f, OutboundFrame::NewMiningJob { .. })),
            "a block change must always be sent"
        );
    }

    /// A block change retires jobs of both kinds and keeps the old tip's
    /// accepted hashes, whose jobs are still creditable within grace.
    #[test]
    fn template_broadcast_new_block_retires_and_keeps_dedup() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        // Pre-seed an accepted hash on the old tip + a fake ExtendedJob.
        {
            let ch = s.channels.get_mut(&cid).unwrap();
            ch.seen_shares.record([0; 32], [0x11; 32]);
            ch.extended_jobs.insert(
                99,
                ExtendedJob {
                    payouts_fingerprint: [0u8; 32],
                    coinbase_prefix: vec![],
                    coinbase_suffix: vec![],
                    merkle_path: vec![],
                    extranonce_prefix: vec![],
                    version: 0,
                    prev_hash: [0; 32],
                    n_bits: 0,
                    min_ntime: 0x6500_0000,
                    difficulty: Difficulty(1.0),
                    coinbase_tx_value_remaining: 5_000_000_000,
                    template_id: None,
                    jdp_claims_the_block: false,
                    created_at: 500,
                    retired_at: None,
                },
            );
            // A Standard-side entry, to confirm retire covers standard_jobs too.
            ch.standard_jobs
                .record_send_for_test(7, Difficulty(1.0), [0u8; 32], snapshot(), 500);
        }
        let mj = synthetic_mining_job_inputs();
        let _ = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xCC; 32]),
            &mj,
            1_000,
            None,
        );
        let ch = s.channels.get(&cid).unwrap();
        assert_eq!(
            ch.seen_shares.check(&[0; 32], &[0x11; 32]),
            Err(bp_jobs_lifecycle::SeenShareRefusal::Duplicate),
            "the old tip's accepted hash must survive the block change"
        );
        // Old ExtendedJob is now retired (still present, retired_at set).
        let retired = ch.extended_jobs.get(&99).unwrap();
        assert_eq!(retired.retired_at, Some(1_000));
        // Old StandardJob entry retired.
        assert_eq!(
            ch.standard_jobs.classify(7, 1_000),
            Some(bp_jobs_lifecycle::JobClassification::StaleCreditable),
            "pre-existing standard entry must be retired (not deleted)"
        );
    }

    /// The port's job retention ages out retired extended jobs on the next block change.
    #[test]
    fn template_broadcast_ages_extended_jobs_under_configured_retention() {
        fn retired_job_survives(retention_ms: u64) -> bool {
            let mut s = MiningSessionState::new(
                Arc::new(TestClock::new(0)),
                1,
                PortConfig {
                    job_lifecycle: LifecycleConfig {
                        retention_ms,
                        ..LifecycleConfig::DEFAULT
                    },
                    ..port_cfg()
                },
            );
            handle_setup_connection(&mut s, &good_setup());
            let _ = handle_open_extended_mining_channel(
                &mut s,
                &open_ext(1, &format!("{}.w", REGTEST_ADDR)),
                vec![0xAA, 0xBB, 0xCC, 0xDD],
            );
            let cid = s.primary_channel.unwrap();
            let ch = s.channels.get_mut(&cid).unwrap();
            for (job_id, created_at) in [(90u32, 500u64), (91, 501), (92, 502), (93, 503)] {
                ch.extended_jobs.insert(
                    job_id,
                    ExtendedJob {
                        payouts_fingerprint: [0u8; 32],
                        coinbase_prefix: vec![],
                        coinbase_suffix: vec![],
                        merkle_path: vec![],
                        extranonce_prefix: vec![],
                        version: 0,
                        prev_hash: [0; 32],
                        n_bits: 0,
                        min_ntime: 0x6500_0000,
                        difficulty: Difficulty(1.0),
                        coinbase_tx_value_remaining: 5_000_000_000,
                        template_id: None,
                        jdp_claims_the_block: false,
                        created_at,
                        retired_at: Some(1_000),
                    },
                );
            }
            let _ = apply_template_broadcast(
                &mut s,
                &broadcast(TemplateChange::NewBlock, [0xCC; 32]),
                &synthetic_mining_job_inputs(),
                1_000 + 120_000,
                None,
            );
            s.channels[&cid].extended_jobs.contains_key(&90)
        }
        assert!(
            !retired_job_survives(60_000),
            "retired 120 s ago under a 60 s retention: must be aged out"
        );
        assert!(
            retired_job_survives(LifecycleConfig::DEFAULT.retention_ms),
            "retired 120 s ago under the 600 s default: must still be stored"
        );
    }

    /// The per-channel job_id allocator is monotonic across broadcasts.
    #[test]
    fn template_broadcast_job_id_monotonic_across_broadcasts() {
        let mut s = session_with_standard_channel();
        let mj = synthetic_mining_job_inputs();
        let out1 = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xAB; 32]),
            &mj,
            1_000,
            None,
        );
        let out2 = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xCD; 32]),
            &mj,
            2_000,
            None,
        );
        // Future-job order: NewMiningJob is frame [0], the
        // activating SetNewPrevHash is frame [1].
        let job1 = match out1.outbound[0] {
            OutboundFrame::NewMiningJob { job_id, .. } => job_id,
            _ => unreachable!(),
        };
        let job2 = match out2.outbound[0] {
            OutboundFrame::NewMiningJob { job_id, .. } => job_id,
            _ => unreachable!(),
        };
        assert_eq!(job1, 1);
        assert_eq!(job2, 2);
    }

    /// Each channel gets its own job_id and SetNewPrevHash.
    #[test]
    fn template_broadcast_multi_channel_independent_job_ids() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0x11, 0x22, 0x33, 0x44],
        );
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(2, &format!("{}.w", REGTEST_ADDR)),
            vec![0x55, 0x66, 0x77, 0x88],
        );
        assert_eq!(s.channels.len(), 2);
        let mj = synthetic_mining_job_inputs();
        let out = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xAB; 32]),
            &mj,
            1_000,
            None,
        );
        // 2 channels × (SetNewPrevHash + NewMiningJob) = 4 frames.
        assert_eq!(out.outbound.len(), 4);
        let job_ids: Vec<u32> = out
            .outbound
            .iter()
            .filter_map(|f| match f {
                OutboundFrame::NewMiningJob { job_id, .. } => Some(*job_id),
                _ => None,
            })
            .collect();
        assert_eq!(job_ids, vec![1, 1], "each channel's first job is id=1");
    }

    // ── handle_set_custom_mining_job ───────────────────────────────

    /// A declared job plus the JDP session that registered it, as the
    /// bridge receives them.
    #[derive(Clone)]
    pub(crate) struct RegisteredDeclaredJob {
        pub(crate) declared_job: JdpDeclaredJob,
        pub(crate) jdp_session_id: u32,
    }
    use crate::jdp::declarations::DeclaredJob as JdpDeclaredJob;
    use crate::tokens::Token;

    /// The scriptSig prefix every fixture below declares and mines (BIP-34 height push).
    const FIXTURE_SCRIPT_SIG_PREFIX: [u8; 3] = [0x03, 0xC8, 0x00];
    /// Extranonce slot the declaration reserves. MUST equal the test channel's
    /// `full_extranonce_size()`, which the binding compares it to.
    const FIXTURE_DECLARED_SLOT: usize = 12;

    /// Two decodable transactions; the merkle branch comes from their bytes.
    fn fixture_declared_txs() -> Vec<Vec<u8>> {
        let mut raw = Vec::new();
        for tag in [0xA1u8, 0xB2] {
            let tx = bitcoin::Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: {
                            use bitcoin::hashes::Hash as _;
                            bitcoin::Txid::from_byte_array([tag; 32])
                        },
                        vout: 0,
                    },
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                }],
                output: vec![bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(1_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }],
            };
            raw.push(bitcoin::consensus::serialize(&tx));
        }
        raw
    }

    /// The declared coinbase split around the extranonce slot, assembled as the handler does.
    fn fixture_declared_coinbase_parts(
        script_sig_prefix: &[u8],
        outputs_blob: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let script_sig_len = script_sig_prefix.len() + FIXTURE_DECLARED_SLOT;
        let prefix = bp_mining_job::serialize_coinbase_prefix(2, script_sig_prefix, script_sig_len);

        let mut suffix = Vec::new();
        suffix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // nSequence
        suffix.extend_from_slice(outputs_blob);
        suffix.extend_from_slice(&0u32.to_le_bytes()); // locktime
        (prefix, suffix)
    }

    /// The `SetCustomMiningJob` an honest JDC mining `entry` would send; binding
    /// tests start here and change exactly one field.
    pub(crate) fn custom_job_matching(
        channel_id: u32,
        entry: &RegisteredDeclaredJob,
    ) -> SetCustomMiningJobInput {
        let b = crate::jdp::custom_job_binding::binding_from_declared_job(&entry.declared_job)
            .expect("fixture declaration must project");
        SetCustomMiningJobInput {
            channel_id,
            request_id: 1,
            mining_job_token: entry.declared_job.new_token,
            version: b.version,
            prev_hash: entry.declared_job.prev_hash,
            min_ntime: 0x6500_0001,
            n_bits: 0x1d00_ffff,
            coinbase_tx_version: b.coinbase_tx_version,
            coinbase_prefix: b.coinbase_script_sig_prefix,
            coinbase_tx_input_n_sequence: b.coinbase_tx_input_n_sequence,
            coinbase_tx_outputs: b.coinbase_tx_outputs,
            coinbase_tx_locktime: b.coinbase_tx_locktime,
            merkle_path: b.merkle_path,
            distribution_id: None,
        }
    }

    /// Standard SetCustomMiningJob input, describing exactly the job
    /// [`bridge_entry_for`] declares.
    fn custom_job_input(channel_id: u32, token: Token) -> SetCustomMiningJobInput {
        custom_job_matching(channel_id, &bridge_entry_for(token, REGTEST_ADDR, 1))
    }

    pub(crate) fn bridge_entry_for(
        token: Token,
        address: &str,
        session_id: u32,
    ) -> RegisteredDeclaredJob {
        bridge_entry_declaring(
            token,
            address,
            session_id,
            &FIXTURE_SCRIPT_SIG_PREFIX,
            &[0x00], // empty output vector
        )
    }

    /// A bridge entry declaring a specific coinbase, so the binding check passes
    /// and the test reaches its real subject.
    fn bridge_entry_declaring(
        token: Token,
        address: &str,
        session_id: u32,
        script_sig_prefix: &[u8],
        outputs_blob: &[u8],
    ) -> RegisteredDeclaredJob {
        let (coinbase_tx_prefix, coinbase_tx_suffix) =
            fixture_declared_coinbase_parts(script_sig_prefix, outputs_blob);
        let raw_transactions = fixture_declared_txs();
        RegisteredDeclaredJob {
            declared_job: JdpDeclaredJob {
                new_token: token,
                miner_address: AddressId::new(address.to_string()).unwrap(),
                version: 0x2000_0000,
                coinbase_tx_prefix,
                coinbase_tx_suffix,
                raw_transactions,
                prev_hash: [0xAB; 32],
                declared_at_ms: 1_000,
                booking: None,
                distribution_id: None,
            },
            jdp_session_id: session_id,
        }
    }

    /// A Full-Template declaration accepted against `distribution_id`.
    fn declared_under_distribution(
        mut entry: RegisteredDeclaredJob,
        distribution_id: u64,
    ) -> RegisteredDeclaredJob {
        entry.declared_job.distribution_id = Some(distribution_id);
        entry.declared_job.booking = Some(crate::jdp::dynamic_outputs::PayoutBooking {
            distribution_id,
            payouts_fingerprint: [0u8; 32],
            reference_reward_sats: 312_500_000,
        });
        entry
    }

    /// The same declaration against an unbookable distribution: `booking` is
    /// empty while the reference is still recorded.
    fn declared_under_unbookable_distribution(
        mut entry: RegisteredDeclaredJob,
        distribution_id: u64,
    ) -> RegisteredDeclaredJob {
        entry.declared_job.distribution_id = Some(distribution_id);
        entry.declared_job.booking = None;
        entry
    }

    #[test]
    fn set_custom_mining_job_unknown_channel_emits_invalid_channel_id() {
        let mut s = fresh_session();
        let token = Token([1u8; 16]);
        let input = custom_job_input(99, token);
        let out = handle_set_custom_mining_job(&mut s, &input, None, None, None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_CHANNEL_ID);
            }
            _ => panic!("expected SetCustomMiningJobError"),
        }
    }

    #[test]
    fn set_custom_mining_job_standard_channel_emits_invalid_job_id() {
        let mut s = session_with_standard_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let input = custom_job_input(cid, token);
        let out = handle_set_custom_mining_job(&mut s, &input, None, None, None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_ID);
            }
            _ => panic!("expected SetCustomMiningJobError"),
        }
    }

    /// A JDC's declared job is work for the vardiff, like a pool-built one:
    /// before it the channel gathers no silence, after it it does. Normally a
    /// pool job came first; this covers a channel whose pool job failed to
    /// build.
    #[test]
    fn a_custom_job_gives_the_channel_work() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        assert!(
            s.channels[&cid].extended_jobs.is_empty(),
            "precondition: no job yet"
        );
        s.clock.advance_ms(120_000);
        assert_eq!(s.vardiff[&cid].silence_implied_max_difficulty(), None);

        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        let out = handle_set_custom_mining_job(
            &mut s,
            &custom_job_input(cid, token),
            Some(&job_ref_for(&entry)),
            None,
            None,
            1_000,
        );
        assert!(
            matches!(
                out.outbound[0],
                OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "precondition: the job was accepted"
        );
        s.clock.advance_ms(61_000);
        assert!(
            s.vardiff[&cid].silence_implied_max_difficulty().is_some(),
            "a minute of silence on a declared job is evidence"
        );
    }

    /// A declared job is accepted and stored with the assembled non-witness coinbase.
    #[test]
    fn set_custom_mining_job_extended_accepts_and_stores_ext_job() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        let input = custom_job_input(cid, token);
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&entry)),
            None,
            None,
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobSuccess {
                channel_id,
                request_id,
                job_id,
            } => {
                assert_eq!(*channel_id, cid);
                assert_eq!(*request_id, 1);
                assert_eq!(*job_id, 1, "first allocated job_id");
            }
            other => panic!("expected Success, got {other:?}"),
        }
        let ch = s.channels.get(&cid).unwrap();
        let ext = ch.extended_jobs.get(&1).expect("ext_job stored");
        // [version:4][input_count:1][null_outpoint:36][scriptSig_len_varint][scriptSig_prefix]
        assert_eq!(&ext.coinbase_prefix[0..4], &[0x02, 0x00, 0x00, 0x00]);
        assert_eq!(ext.coinbase_prefix[4], 0x01, "input_count = 1");
        // bytes 5..37: 32 zero bytes (prev_txid)
        assert!(ext.coinbase_prefix[5..37].iter().all(|b| *b == 0));
        // bytes 37..41: 0xFFFFFFFF (prev_vout LE)
        assert_eq!(&ext.coinbase_prefix[37..41], &[0xFF, 0xFF, 0xFF, 0xFF]);
        // byte 41: scriptSig_len = msg.coinbase_prefix.len(3) + full_extranonce(12) = 15 = 0x0F
        assert_eq!(ext.coinbase_prefix[41], 0x0F);
        // bytes 42..45: the JDC-supplied coinbase_prefix bytes
        assert_eq!(&ext.coinbase_prefix[42..45], &[0x03, 0xC8, 0x00]);
        assert_eq!(ext.coinbase_prefix.len(), 45);
        // Suffix: [sequence:4][outputs:1][locktime:4] = 9 bytes.
        assert_eq!(ext.coinbase_suffix.len(), 9);
        assert_eq!(&ext.coinbase_suffix[0..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(ext.coinbase_suffix[4], 0x00, "1-byte output blob");
        assert_eq!(&ext.coinbase_suffix[5..9], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(ext.merkle_path.len(), 2);
        assert_eq!(ext.template_id, None, "custom job carries no template");
        assert_eq!(ext.prev_hash, [0xAB; 32]);
        assert_eq!(ext.version, 0x2000_0000);
        assert_eq!(ext.created_at, 1_000);
    }

    /// What the IO layer hands the handler, taken from the real registry so the
    /// tests exercise its own projection.
    fn job_ref_for(entry: &RegisteredDeclaredJob) -> crate::bridge::BridgeJobRef {
        let mut registry = crate::bridge::JdpDeclaredJobRegistry::new();
        let token = entry.declared_job.new_token;
        registry.register(token, &entry.declared_job, entry.jdp_session_id);
        registry.job_ref(&token).expect("just registered")
    }

    /// Extended-channel session on the Solo stream, the only one where a
    /// base-protocol custom job is accepted.
    pub(crate) fn solo_session_with_extended_channel() -> MiningSessionState<Arc<TestClock>> {
        let mut s = session_with_extended_channel();
        s.set_stream(StreamKind::Solo);
        s
    }

    /// A declared job whose miner address matches the channel is accepted.
    #[test]
    fn set_custom_mining_job_bridge_entry_matching_address_accepts() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        let input = custom_job_input(cid, token);
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&entry)),
            None,
            None,
            1_000,
        );
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
    }

    /// A declaration made on the previous tip is still on hand after the tip
    /// changes; a job built from it must get `stale-chain-tip`, as it would
    /// without a declaration. On the declared tip it passes.
    #[test]
    fn a_declared_job_is_bound_to_the_tip_the_pool_last_served() {
        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        assert_eq!(entry.declared_job.prev_hash, [0xAB; 32]);

        for (pool_tip, expected) in [([0xAB; 32], None), ([0xCD; 32], Some(ERR_STALE_CHAIN_TIP))] {
            let mut s = solo_session_with_extended_channel();
            let cid = s.primary_channel.unwrap();
            s.channels.get_mut(&cid).unwrap().latest_extended_prev_hash = Some(pool_tip);
            let input = custom_job_input(cid, token);
            assert_eq!(input.prev_hash, entry.declared_job.prev_hash);

            let out = handle_set_custom_mining_job(
                &mut s,
                &input,
                Some(&job_ref_for(&entry)),
                None,
                None,
                1_000,
            );
            match (&out.outbound[0], expected) {
                (OutboundFrame::SetCustomMiningJobSuccess { .. }, None) => {}
                (OutboundFrame::SetCustomMiningJobError { error_code, .. }, Some(want)) => {
                    assert_eq!(error_code, want);
                    assert!(
                        s.channels.get(&cid).unwrap().extended_jobs.is_empty(),
                        "a job on a past tip must not be registered"
                    );
                }
                (other, want) => panic!("pool tip {pool_tip:?}: wanted {want:?}, got {other:?}"),
            }
        }
    }

    /// One miner cannot claim another's declared job.
    #[test]
    fn set_custom_mining_job_bridge_entry_mismatching_address_rejects() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let other_addr = "bcrt1qvs8k07ggszru23v9p42vpg4jxts9y2k8kkujja";
        let entry = bridge_entry_for(token, other_addr, 42);
        let input = custom_job_input(cid, token);
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&entry)),
            None,
            None,
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
            }
            _ => panic!("expected token-mismatch error"),
        }
        // No ExtendedJob inserted.
        let ch = s.channels.get(&cid).unwrap();
        assert!(ch.extended_jobs.is_empty());
    }

    /// A token backing nothing is rejected, never accepted as an unvalidated job.
    #[test]
    fn set_custom_mining_job_unknown_token_rejects() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let input = custom_job_input(cid, Token([0xEEu8; 16]));
        let out = handle_set_custom_mining_job(&mut s, &input, None, None, None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_MINING_JOB_TOKEN);
            }
            _ => panic!("expected invalid-mining-job-token error"),
        }
        let ch = s.channels.get(&cid).unwrap();
        assert!(ch.extended_jobs.is_empty(), "no job may be registered");
    }

    // ── Base-protocol Coinbase-only (SV2 JDP/Coinbase-only Mode) ────

    /// The script the pool designates for a Solo miner: its own address.
    fn designated_script(address: &str) -> Vec<u8> {
        bp_mining_job::address_to_script(bitcoin::Network::Regtest, address)
            .expect("fixture address must encode")
            .as_bytes()
            .to_vec()
    }

    /// The allocate an ext 0x0003 Coinbase-only JDC gets: on file, with no
    /// designated script because ext 0x0003/Negotiation empties the outputs.
    fn distribution_allocation(address: &str, session_id: u32) -> crate::bridge::AllocatedTokenRef {
        crate::bridge::AllocatedTokenRef {
            miner_address: AddressId::new(address.to_string()).unwrap(),
            kind: crate::bridge::AllocationKind::JudgedByDistribution,
            jdp_session_id: session_id,
            expires_at_ms: u64::MAX,
        }
    }

    fn base_allocation(address: &str, session_id: u32) -> crate::bridge::AllocatedTokenRef {
        crate::bridge::AllocatedTokenRef {
            miner_address: AddressId::new(address.to_string()).unwrap(),
            kind: crate::bridge::AllocationKind::DesignatedOutput(designated_script(address)),
            jdp_session_id: session_id,
            // Expiry is covered in the bridge.
            expires_at_ms: u64::MAX,
        }
    }

    /// A Coinbase-only custom job carrying `outputs`, derived from no declaration.
    fn coinbase_only_job(
        channel_id: u32,
        token: Token,
        outputs: &[bitcoin::TxOut],
    ) -> SetCustomMiningJobInput {
        SetCustomMiningJobInput {
            channel_id,
            request_id: 1,
            mining_job_token: token,
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            min_ntime: 0x6500_0001,
            n_bits: 0x1d00_ffff,
            coinbase_tx_version: 2,
            coinbase_prefix: FIXTURE_SCRIPT_SIG_PREFIX.to_vec(),
            coinbase_tx_input_n_sequence: 0xFFFF_FFFF,
            coinbase_tx_outputs: bitcoin::consensus::serialize(&outputs.to_vec()),
            coinbase_tx_locktime: 0,
            merkle_path: vec![],
            distribution_id: None,
        }
    }

    fn txout(sats: u64, script: Vec<u8>) -> bitcoin::TxOut {
        bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(sats),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(script),
        }
    }

    /// A base-protocol Solo job paying the designated output is served; the check is not positional.
    #[test]
    fn a_coinbase_only_solo_job_is_served_off_its_allocation() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([0x77u8; 16]);
        let alloc = base_allocation(REGTEST_ADDR, 42);
        let input = coinbase_only_job(
            cid,
            token,
            &[
                txout(0, vec![0x6A, 0x01, 0x42]),
                txout(312_500_000, designated_script(REGTEST_ADDR)),
            ],
        );
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&alloc), None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobSuccess { .. } => {}
            other => panic!("expected SetCustomMiningJobSuccess, got {other:?}"),
        }
        let ch = s.channels.get(&cid).unwrap();
        assert_eq!(ch.extended_jobs.len(), 1, "the job must be registered");
    }

    /// Negative control: the same job paying someone else is rejected.
    #[test]
    fn a_coinbase_only_job_that_skips_the_designated_output_is_rejected() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([0x77u8; 16]);
        let alloc = base_allocation(REGTEST_ADDR, 42);
        let stranger = designated_script("bcrt1qvs8k07ggszru23v9p42vpg4jxts9y2k8kkujja");
        let input = coinbase_only_job(cid, token, &[txout(312_500_000, stranger)]);
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&alloc), None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS);
            }
            other => panic!("expected coinbase-outputs error, got {other:?}"),
        }
        let ch = s.channels.get(&cid).unwrap();
        assert!(ch.extended_jobs.is_empty(), "no job may be registered");
    }

    /// One miner cannot mine against another's allocate token.
    #[test]
    fn a_coinbase_only_job_on_another_miners_token_is_rejected() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([0x77u8; 16]);
        let other = "bcrt1qvs8k07ggszru23v9p42vpg4jxts9y2k8kkujja";
        let alloc = base_allocation(other, 42);
        let input = coinbase_only_job(cid, token, &[txout(312_500_000, designated_script(other))]);
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&alloc), None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
            }
            other => panic!("expected token-mismatch error, got {other:?}"),
        }
    }

    /// A Coinbase-only job off the pool's last tip gets `stale-chain-tip`; on it, it passes.
    #[test]
    fn a_coinbase_only_job_is_bound_to_the_tip_the_pool_last_served() {
        let designated = designated_script(REGTEST_ADDR);
        let alloc = base_allocation(REGTEST_ADDR, 42);
        let outputs = [txout(312_500_000, designated)];

        for (job_tip, expected) in [([0xAB; 32], None), ([0xCD; 32], Some(ERR_STALE_CHAIN_TIP))] {
            let mut s = solo_session_with_extended_channel();
            let cid = s.primary_channel.unwrap();
            // The pool has served work on 0xAB.
            s.channels.get_mut(&cid).unwrap().latest_extended_prev_hash = Some([0xAB; 32]);

            let mut input = coinbase_only_job(cid, Token([0x77u8; 16]), &outputs);
            input.prev_hash = job_tip;
            let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&alloc), None, 1_000);
            match (&out.outbound[0], expected) {
                (OutboundFrame::SetCustomMiningJobSuccess { .. }, None) => {}
                (OutboundFrame::SetCustomMiningJobError { error_code, .. }, Some(want)) => {
                    assert_eq!(error_code, want);
                }
                (other, want) => panic!("tip {job_tip:?}: wanted {want:?}, got {other:?}"),
            }
        }
    }

    /// A custom job with an `n_bits` other than the pool's is refused; the pool's own passes.
    #[test]
    fn a_custom_job_must_use_the_difficulty_the_pool_is_working_on() {
        let alloc = base_allocation(REGTEST_ADDR, 42);
        let outputs = [txout(312_500_000, designated_script(REGTEST_ADDR))];
        const POOL_N_BITS: u32 = 0x1d00_ffff;
        // Regtest's "anything hashes" difficulty.
        const TRIVIAL: u32 = 0x207f_ffff;

        for (job_n_bits, expected) in [(POOL_N_BITS, None), (TRIVIAL, Some(ERR_INVALID_NBITS))] {
            let mut s = solo_session_with_extended_channel();
            let cid = s.primary_channel.unwrap();
            {
                let ch = s.channels.get_mut(&cid).unwrap();
                ch.latest_extended_prev_hash = Some([0xAB; 32]);
                ch.latest_extended_n_bits = Some(POOL_N_BITS);
            }
            let mut input = coinbase_only_job(cid, Token([0x77u8; 16]), &outputs);
            input.n_bits = job_n_bits;

            let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&alloc), None, 1_000);
            match (&out.outbound[0], expected) {
                (OutboundFrame::SetCustomMiningJobSuccess { .. }, None) => {}
                (OutboundFrame::SetCustomMiningJobError { error_code, .. }, Some(want)) => {
                    assert_eq!(error_code, want);
                    assert!(
                        s.channels.get(&cid).unwrap().extended_jobs.is_empty(),
                        "a job whose threshold the client chose must not be registered"
                    );
                }
                (other, want) => panic!("n_bits {job_n_bits:#x}: wanted {want:?}, got {other:?}"),
            }
        }
    }

    /// Before the pool served the channel anything, a custom job is refused retryably; after, accepted.
    #[test]
    fn a_custom_job_is_refused_while_the_pool_has_served_the_channel_nothing() {
        let alloc = base_allocation(REGTEST_ADDR, 42);
        let outputs = [txout(312_500_000, designated_script(REGTEST_ADDR))];
        const POOL_N_BITS: u32 = 0x1d00_ffff;
        const TRIVIAL: u32 = 0x207f_ffff;

        // Served nothing: both fields `None`; the job carries a trivial threshold.
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        {
            let ch = s.channels.get_mut(&cid).unwrap();
            ch.latest_extended_prev_hash = None;
            ch.latest_extended_n_bits = None;
        }
        let mut input = coinbase_only_job(cid, Token([0x77u8; 16]), &outputs);
        input.n_bits = TRIVIAL;
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&alloc), None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                // Not `invalid-nbits`: the client is not at fault, and a JDC retries this one.
                assert_eq!(error_code, ERR_STALE_CHAIN_TIP);
            }
            other => {
                panic!("a job the pool cannot pin a threshold to must be refused, got {other:?}")
            }
        }
        assert!(
            s.channels.get(&cid).unwrap().extended_jobs.is_empty(),
            "the job must not register — its block-candidate threshold would be the client's"
        );

        // Served: the conformant job goes through, so the refusal above is
        // about the missing reference point only.
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        {
            let ch = s.channels.get_mut(&cid).unwrap();
            ch.latest_extended_prev_hash = Some([0xAB; 32]);
            ch.latest_extended_n_bits = Some(POOL_N_BITS);
        }
        let mut input = coinbase_only_job(cid, Token([0x77u8; 16]), &outputs);
        input.n_bits = POOL_N_BITS;
        input.prev_hash = [0xAB; 32];
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&alloc), None, 1_000);
        assert!(
            matches!(
                out.outbound[0],
                OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "a job on a channel the pool HAS served must still be accepted, got {:?}",
            out.outbound[0]
        );
    }

    /// An `n_bits` mismatch off the pool's tip is the retarget race (`stale-chain-tip`), on it `invalid-nbits`.
    #[test]
    fn an_n_bits_mismatch_across_a_tip_change_is_the_retryable_verdict() {
        let alloc = base_allocation(REGTEST_ADDR, 42);
        let outputs = [txout(312_500_000, designated_script(REGTEST_ADDR))];
        const POOL_TIP: [u8; 32] = [0xAB; 32];
        const OTHER_TIP: [u8; 32] = [0xCD; 32];
        // A retarget moves `n_bits`; these two stand in for either side of one.
        const POOL_N_BITS: u32 = 0x1d00_ffff;
        const RETARGETED: u32 = 0x1c00_ffff;

        // (the tip the job builds on, the n_bits it carries, the verdict)
        for (job_tip, job_n_bits, want) in [
            // The JDC is ahead: its node retargeted first.
            (OTHER_TIP, RETARGETED, ERR_STALE_CHAIN_TIP),
            // The pool is ahead: an in-flight job for the tip it just left.
            (OTHER_TIP, POOL_N_BITS, ERR_STALE_CHAIN_TIP),
            // The pool's own tip: no race to excuse it.
            (POOL_TIP, RETARGETED, ERR_INVALID_NBITS),
        ] {
            let mut s = solo_session_with_extended_channel();
            let cid = s.primary_channel.unwrap();
            {
                let ch = s.channels.get_mut(&cid).unwrap();
                ch.latest_extended_prev_hash = Some(POOL_TIP);
                ch.latest_extended_n_bits = Some(POOL_N_BITS);
            }
            let mut input = coinbase_only_job(cid, Token([0x77u8; 16]), &outputs);
            input.prev_hash = job_tip;
            input.n_bits = job_n_bits;

            let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&alloc), None, 1_000);
            match &out.outbound[0] {
                OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                    assert_eq!(error_code, want, "tip {job_tip:?} / n_bits {job_n_bits:#x}");
                }
                other => panic!("tip {job_tip:?}: expected {want}, got {other:?}"),
            }
            assert!(
                s.channels.get(&cid).unwrap().extended_jobs.is_empty(),
                "a job whose threshold the pool cannot pin must not register"
            );
        }
    }

    /// An allocation does not make a shared-payout stream mineable on the base protocol.
    #[test]
    fn a_coinbase_only_job_off_solo_is_still_refused() {
        let mut s = session_with_extended_channel();
        assert_ne!(
            s.accounting_stream,
            StreamKind::Solo,
            "fixture must be non-Solo"
        );
        let cid = s.primary_channel.unwrap();
        let token = Token([0x77u8; 16]);
        let alloc = base_allocation(REGTEST_ADDR, 42);
        let input = coinbase_only_job(
            cid,
            token,
            &[txout(312_500_000, designated_script(REGTEST_ADDR))],
        );
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&alloc), None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_CUSTOM_JOB_REQUIRES_SOLO);
            }
            other => panic!("expected custom-jobs-require-solo, got {other:?}"),
        }
    }

    /// A declared job off its declaration's tip gets `stale-chain-tip`.
    #[test]
    fn set_custom_mining_job_declared_tip_mismatch_rejects_stale_chain_tip() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let mut entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        // Declared under a DIFFERENT tip than the job builds on (0xAB).
        entry.declared_job.prev_hash = [0xCD; 32];
        let input = custom_job_input(cid, token);
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&entry)),
            None,
            None,
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_CHAIN_TIP);
            }
            _ => panic!("expected stale-chain-tip error"),
        }
        let ch = s.channels.get(&cid).unwrap();
        assert!(ch.extended_jobs.is_empty(), "stale job must not register");
    }

    /// A base-protocol custom job on a non-Solo stream gets `custom-jobs-require-solo`.
    #[test]
    fn set_custom_mining_job_without_distribution_rejected_off_solo() {
        // Default-stream session = PPLNS.
        let mut s = session_with_extended_channel();
        assert_ne!(
            s.accounting_stream,
            StreamKind::Solo,
            "fixture must be non-Solo"
        );
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        let input = custom_job_input(cid, token);
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&entry)),
            None,
            None,
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_CUSTOM_JOB_REQUIRES_SOLO);
            }
            _ => panic!("expected custom-jobs-require-solo error"),
        }
        let ch = s.channels.get(&cid).unwrap();
        assert!(ch.extended_jobs.is_empty(), "no job may be registered");
    }

    // ── ext 0x0003 distribution validation on SetCustomMiningJob ───

    use crate::jdp::payout_distribution::{compute_payout_vector, WeightedOutput};

    /// Registry entry with one weight-9 miner slot behind a weight-1 pool output.
    fn distribution_entry(
        accounting: crate::bridge::DistributionAccounting,
    ) -> crate::bridge::PayoutDistributionEntry {
        crate::bridge::PayoutDistributionEntry {
            distribution_id: 9,
            built: crate::bridge::BuiltPayoutDistribution {
                pool_payout: WeightedOutput {
                    script_pubkey: vec![0x51],
                    weight: 1,
                },
                payouts: vec![WeightedOutput {
                    script_pubkey: vec![0x00, 0x14, 0xAA],
                    weight: 9,
                }],
                dust_limits: vec![1],
                additional_outputs: vec![],
                reference_reward_sats: 312_500_000,
                payouts_fingerprint: Some([0x5A; 32]),
                bookable: true,
            },
            accounting,
            jdp_session_id: None,
            published_at_ms: 1_000,
        }
    }

    /// ext 0x0003/Payout Computation-conformant `coinbase_tx_outputs` blob for
    /// `entry` at revenue `t`.
    fn conformant_outputs(entry: &crate::bridge::PayoutDistributionEntry, t: u64) -> Vec<u8> {
        let outputs = compute_payout_vector(
            &entry.built.pool_payout,
            &entry.built.payouts,
            &entry.built.dust_limits,
            &entry.built.additional_outputs,
            t,
        )
        .unwrap();
        bitcoin::consensus::serialize(&outputs)
    }

    fn accepted(
        entry: crate::bridge::PayoutDistributionEntry,
    ) -> crate::bridge::DistributionAcceptance {
        crate::bridge::DistributionAcceptance::Accepted(Arc::new(entry))
    }

    /// Extended-channel session with ext 0x0003 negotiated, on the default PPLNS stream.
    fn negotiated_session_with_extended_channel() -> MiningSessionState<Arc<TestClock>> {
        let mut s = session_with_extended_channel();
        s.negotiated_extensions
            .push(SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS);
        s
    }

    // ── Who records a block found on a custom job ──────────────────
    // `jdp_claims_the_block` wrong either way costs money: the block is
    // recorded nowhere or twice. The four cases below are the whole table.

    /// The registered job for a custom-job handler call that succeeded.
    fn stored_custom_job(
        s: &MiningSessionState<Arc<TestClock>>,
        cid: u32,
    ) -> &crate::mining::jobs::ExtendedJob {
        let ch = s.channels.get(&cid).expect("channel");
        assert_eq!(ch.extended_jobs.len(), 1, "the job must have been stored");
        ch.extended_jobs.values().next().unwrap()
    }

    /// Row 3, Coinbase-only + ext 0x0003: the mining side records it, carrying the fingerprint.
    #[test]
    fn a_coinbase_only_distribution_job_is_recorded_by_the_mining_side_and_bookable() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let fingerprint = entry
            .built
            .payouts_fingerprint
            .expect("fixture must carry one");
        let blob = conformant_outputs(&entry, 312_500_000);
        let acc = accepted(entry);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9); // ext 0x0003/distribution_id TLV Field: the TLV rides the FRAME in this mode
        input.coinbase_tx_outputs = blob;

        // No bridge entry: nothing was declared.
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            None,
            Some(&distribution_allocation(REGTEST_ADDR, 1)),
            Some(&acc),
            1_000,
        );
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
        let job = stored_custom_job(&s, cid);
        assert!(
            !job.jdp_claims_the_block,
            "Coinbase-only never declares, so PushSolution can never claim its block — \
             the mining side must record it"
        );
        assert_eq!(
            job.payouts_fingerprint, fingerprint,
            "the block must resolve the distribution it was proven to pay, or it is \
             recorded but not bookable"
        );
    }

    /// Row 1, declared with a distribution reference: the JDP side records it, on both streams.
    #[test]
    fn a_declared_distribution_job_is_left_to_the_jdp_path() {
        for (stream, accounting) in [
            (
                StreamKind::Pplns,
                crate::bridge::DistributionAccounting::PoolWide,
            ),
            (
                StreamKind::Solo,
                crate::bridge::DistributionAccounting::Solo(
                    AddressId::new(REGTEST_ADDR.to_string()).unwrap(),
                ),
            ),
        ] {
            let mut s = negotiated_session_with_extended_channel();
            s.set_stream(stream);
            let cid = s.primary_channel.unwrap();
            let entry = distribution_entry(accounting);
            // Declared with the conformant coinbase, so every check passes.
            let blob = conformant_outputs(&entry, 312_500_000);
            let bridge = declared_under_distribution(
                bridge_entry_declaring(
                    Token([1u8; 16]),
                    REGTEST_ADDR,
                    42,
                    &FIXTURE_SCRIPT_SIG_PREFIX,
                    &blob,
                ),
                9,
            );
            let acc = accepted(entry);
            // No frame TLV: Full-Template carries it on `DeclareMiningJob`.
            let input = custom_job_matching(cid, &bridge);

            let out = handle_set_custom_mining_job(
                &mut s,
                &input,
                Some(&job_ref_for(&bridge)),
                None,
                Some(&acc),
                1_000,
            );
            assert!(
                matches!(
                    out.outbound[0],
                    OutboundFrame::SetCustomMiningJobSuccess { .. }
                ),
                "{stream:?}: got {:?}",
                out.outbound[0]
            );
            assert!(
                stored_custom_job(&s, cid).jdp_claims_the_block,
                "{stream:?}: a declared job's solution arrives as PushSolution and is recorded \
                 there — recording it here as well would write the blocks_entity row twice"
            );
        }
    }

    /// A declaration without a reference is recorded mining-side even when the frame TLV resolved one.
    #[test]
    fn a_frame_tlv_does_not_hand_an_undeclared_distribution_to_the_jdp_path() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let blob = conformant_outputs(&entry, 312_500_000);
        // Declared WITHOUT a distribution — `distribution_id: None`.
        let bridge = bridge_entry_declaring(
            Token([1u8; 16]),
            REGTEST_ADDR,
            42,
            &FIXTURE_SCRIPT_SIG_PREFIX,
            &blob,
        );
        let acc = accepted(entry);
        let mut input = custom_job_matching(cid, &bridge);
        input.distribution_id = Some(9);

        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&bridge)),
            None,
            Some(&acc),
            1_000,
        );
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
        assert!(
            !stored_custom_job(&s, cid).jdp_claims_the_block,
            "PushSolution reads the DECLARATION's reference, and this one has none — leaving \
             the block to the JDP path records it nowhere"
        );
    }

    /// Rows 2 and 4, no distribution: recorded mining-side with a zeroed fingerprint.
    #[test]
    fn a_base_protocol_custom_job_is_always_the_mining_sides_to_record() {
        // Row 2 — declared, base protocol.
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let bridge = bridge_entry_for(Token([1u8; 16]), REGTEST_ADDR, 42);
        let input = custom_job_matching(cid, &bridge);
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&bridge)),
            None,
            None,
            1_000,
        );
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
        let job = stored_custom_job(&s, cid);
        assert!(
            !job.jdp_claims_the_block,
            "a declaration with no distribution stamps no booking, so PushSolution \
             records nothing and the mining side must"
        );
        assert_eq!(job.payouts_fingerprint, [0u8; 32]);

        // Row 4 — Coinbase-only, base protocol (served off its allocation).
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let alloc = base_allocation(REGTEST_ADDR, 42);
        let input = coinbase_only_job(
            cid,
            Token([0x77u8; 16]),
            &[txout(312_500_000, designated_script(REGTEST_ADDR))],
        );
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&alloc), None, 1_000);
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
        let job = stored_custom_job(&s, cid);
        assert!(!job.jdp_claims_the_block);
        assert_eq!(job.payouts_fingerprint, [0u8; 32]);
    }

    /// An ext 0x0003 Coinbase-only job is bound to the pool's tip and the token's miner address.
    #[test]
    fn a_distribution_backed_job_is_bound_to_the_tip_and_the_token() {
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let blob = conformant_outputs(&entry, 312_500_000);

        for (job_tip, alloc_addr, expected) in [
            ([0xAB; 32], REGTEST_ADDR, None),
            ([0xCD; 32], REGTEST_ADDR, Some(ERR_STALE_CHAIN_TIP)),
            (
                [0xAB; 32],
                "bcrt1qvs8k07ggszru23v9p42vpg4jxts9y2k8kkujja",
                Some(ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH),
            ),
        ] {
            let mut s = negotiated_session_with_extended_channel();
            let cid = s.primary_channel.unwrap();
            s.channels.get_mut(&cid).unwrap().latest_extended_prev_hash = Some([0xAB; 32]);

            let acc = accepted(entry.clone());
            let mut input = custom_job_input(cid, Token([1u8; 16]));
            input.distribution_id = Some(9);
            input.coinbase_tx_outputs = blob.clone();
            input.prev_hash = job_tip;
            let out = handle_set_custom_mining_job(
                &mut s,
                &input,
                None,
                Some(&distribution_allocation(alloc_addr, 1)),
                Some(&acc),
                1_000,
            );
            match (&out.outbound[0], expected) {
                (OutboundFrame::SetCustomMiningJobSuccess { .. }, None) => {}
                (OutboundFrame::SetCustomMiningJobError { error_code, .. }, Some(want)) => {
                    assert_eq!(error_code, want, "tip {job_tip:?} addr {alloc_addr}");
                }
                (other, want) => {
                    panic!("tip {job_tip:?} addr {alloc_addr}: want {want:?}, got {other:?}")
                }
            }
        }
    }

    /// A distribution reference does not stand in for an allocate the pool issued.
    #[test]
    fn a_distribution_reference_does_not_authorise_a_token_the_pool_never_issued() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let blob = conformant_outputs(&entry, 312_500_000);
        let acc = accepted(entry);
        let mut input = custom_job_input(cid, Token([0xEE; 16]));
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = blob;

        let out = handle_set_custom_mining_job(&mut s, &input, None, None, Some(&acc), 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_MINING_JOB_TOKEN);
            }
            other => panic!("an unissued token must be refused, got {other:?}"),
        }
        assert!(
            s.channels.get(&cid).unwrap().extended_jobs.is_empty(),
            "a refused job must not register"
        );
    }

    /// A coinbase positionally matching the distribution's payout vector is accepted.
    #[test]
    fn set_custom_mining_job_conformant_distribution_coinbase_accepts() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let blob = conformant_outputs(&entry, 312_500_000);
        let acc = accepted(entry);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = blob;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            None,
            Some(&distribution_allocation(REGTEST_ADDR, 1)),
            Some(&acc),
            1_000,
        );
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
    }

    /// A non-matching coinbase gets `invalid-payout-distribution` and stores no job.
    #[test]
    fn set_custom_mining_job_nonconformant_coinbase_rejects() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let acc = accepted(distribution_entry(
            crate::bridge::DistributionAccounting::PoolWide,
        ));
        // Empty outputs; the recompute always expects the pool output.
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            None,
            Some(&distribution_allocation(REGTEST_ADDR, 1)),
            Some(&acc),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_PAYOUT_DISTRIBUTION);
            }
            other => panic!("expected invalid-distribution error, got {other:?}"),
        }
        assert!(s.channels.get(&cid).unwrap().extended_jobs.is_empty());
    }

    /// An undecodable outputs blob is a parameter error, not a distribution violation.
    #[test]
    fn set_custom_mining_job_undecodable_coinbase_outputs_rejects() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let acc = accepted(distribution_entry(
            crate::bridge::DistributionAccounting::PoolWide,
        ));
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = vec![0x01]; // count=1, no TxOut bytes
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            None,
            Some(&distribution_allocation(REGTEST_ADDR, 1)),
            Some(&acc),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS);
            }
            other => panic!("expected coinbase-outputs error, got {other:?}"),
        }
    }

    /// A distribution outside the acceptance window gets `stale-payout-distribution`.
    #[test]
    fn set_custom_mining_job_stale_distribution_rejects() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let blob = conformant_outputs(&entry, 312_500_000);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = blob;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            None,
            Some(&distribution_allocation(REGTEST_ADDR, 1)),
            Some(&crate::bridge::DistributionAcceptance::Stale),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_PAYOUT_DISTRIBUTION);
            }
            other => panic!("expected stale error, got {other:?}"),
        }
        assert!(s.channels.get(&cid).unwrap().extended_jobs.is_empty());
    }

    /// A never-published `distribution_id` also gets `stale-payout-distribution`.
    #[test]
    fn set_custom_mining_job_unknown_distribution_rejects() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(77);
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            None,
            Some(&distribution_allocation(REGTEST_ADDR, 1)),
            Some(&crate::bridge::DistributionAcceptance::Unknown),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_PAYOUT_DISTRIBUTION);
            }
            other => panic!("expected stale error, got {other:?}"),
        }
    }

    /// A `distribution_id` TLV without negotiated 0x0003 is rejected even if it resolves.
    #[test]
    fn set_custom_mining_job_distribution_tlv_without_negotiation_rejects() {
        let mut s = session_with_extended_channel(); // 0x0003 NOT negotiated
        let cid = s.primary_channel.unwrap();
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let blob = conformant_outputs(&entry, 312_500_000);
        let acc = accepted(entry);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = blob;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            None,
            Some(&distribution_allocation(REGTEST_ADDR, 1)),
            Some(&acc),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_PAYOUT_DISTRIBUTION);
            }
            other => panic!("expected invalid-distribution error, got {other:?}"),
        }
    }

    /// A channel of another address may not reference a tailored distribution.
    #[test]
    fn set_custom_mining_job_tailored_owner_mismatch_rejects() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let other = "bcrt1qvs8k07ggszru23v9p42vpg4jxts9y2k8kkujja";
        let entry = distribution_entry(crate::bridge::DistributionAccounting::Solo(
            AddressId::new(other.to_string()).unwrap(),
        ));
        let blob = conformant_outputs(&entry, 312_500_000);
        let acc = accepted(entry);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = blob;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            None,
            Some(&distribution_allocation(REGTEST_ADDR, 1)),
            Some(&acc),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
            }
            other => panic!("expected token-mismatch error, got {other:?}"),
        }
    }

    /// The owning miner's channel may reference its tailored distribution.
    #[test]
    fn set_custom_mining_job_tailored_owner_match_accepts() {
        // Solo: a stream a tailored distribution is built for.
        let mut s = negotiated_session_with_extended_channel();
        s.set_stream(StreamKind::Solo);
        let cid = s.primary_channel.unwrap();
        let entry = distribution_entry(crate::bridge::DistributionAccounting::Solo(
            AddressId::new(REGTEST_ADDR.to_string()).unwrap(),
        ));
        let blob = conformant_outputs(&entry, 312_500_000);
        let acc = accepted(entry);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = blob;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            None,
            Some(&distribution_allocation(REGTEST_ADDR, 1)),
            Some(&acc),
            1_000,
        );
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
    }

    /// Every accounting/stream pair is decided by accounting, not by owner address.
    #[test]
    fn a_distribution_is_only_served_to_the_accounting_it_was_built_for() {
        use crate::bridge::DistributionAccounting as Acct;
        let me = || AddressId::new(REGTEST_ADDR.to_string()).unwrap();

        let cases = [
            (Acct::PoolWide, StreamKind::Pplns, true),
            (Acct::PoolWide, StreamKind::Solo, false),
            (Acct::PoolWide, StreamKind::GroupSolo, false),
            (Acct::PoolWide, StreamKind::Blockparty, false),
            (Acct::Solo(me()), StreamKind::Solo, true),
            (Acct::Solo(me()), StreamKind::Pplns, false),
            (Acct::Solo(me()), StreamKind::GroupSolo, false),
            (Acct::Solo(me()), StreamKind::Blockparty, false),
            (Acct::GroupSolo(me()), StreamKind::GroupSolo, true),
            (Acct::GroupSolo(me()), StreamKind::Pplns, false),
            (Acct::GroupSolo(me()), StreamKind::Solo, false),
            (Acct::GroupSolo(me()), StreamKind::Blockparty, false),
        ];

        for (accounting, stream, accepted_expected) in cases {
            let mut s = negotiated_session_with_extended_channel();
            s.set_stream(stream);
            let cid = s.primary_channel.unwrap();
            let entry = distribution_entry(accounting.clone());
            let blob = conformant_outputs(&entry, 312_500_000);
            let acc = accepted(entry);
            let mut input = custom_job_input(cid, Token([1u8; 16]));
            input.distribution_id = Some(9);
            input.coinbase_tx_outputs = blob;

            let out = handle_set_custom_mining_job(
                &mut s,
                &input,
                None,
                Some(&distribution_allocation(REGTEST_ADDR, 1)),
                Some(&acc),
                1_000,
            );
            match (&out.outbound[0], accepted_expected) {
                (OutboundFrame::SetCustomMiningJobSuccess { .. }, true) => {}
                (OutboundFrame::SetCustomMiningJobError { error_code, .. }, false) => {
                    assert_eq!(
                        error_code, ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH,
                        "{accounting:?} on {stream:?}"
                    );
                    assert!(
                        s.channels.get(&cid).unwrap().extended_jobs.is_empty(),
                        "{accounting:?} on {stream:?}: a refused job must not register"
                    );
                }
                (other, want) => {
                    panic!("{accounting:?} on {stream:?}: wanted accepted={want}, got {other:?}")
                }
            }
        }
    }

    /// On a matching stream the owner address must still match.
    #[test]
    fn a_matching_accounting_still_checks_the_owner() {
        use crate::bridge::DistributionAccounting as Acct;
        let stranger =
            AddressId::new("bcrt1qvs8k07ggszru23v9p42vpg4jxts9y2k8kkujja".to_string()).unwrap();

        let mut s = negotiated_session_with_extended_channel();
        s.set_stream(StreamKind::Solo);
        let cid = s.primary_channel.unwrap();
        let entry = distribution_entry(Acct::Solo(stranger));
        let blob = conformant_outputs(&entry, 312_500_000);
        let acc = accepted(entry);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = blob;

        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            None,
            Some(&distribution_allocation(REGTEST_ADDR, 1)),
            Some(&acc),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
            }
            other => panic!("another miner's Solo plan must be refused, got {other:?}"),
        }
    }

    /// A miner that joins a group while connected is judged by its current mode, not the open-time stream.
    #[test]
    fn a_mode_that_changes_mid_connection_decides_the_accounting() {
        use crate::bridge::DistributionAccounting as Acct;
        let me = || AddressId::new(REGTEST_ADDR.to_string()).unwrap();

        // Opened Solo, then joined a group: the gate says GroupSolo, the
        // template stream is still Solo.
        for (accounting, accept) in [(Acct::GroupSolo(me()), true), (Acct::Solo(me()), false)] {
            let mut s = negotiated_session_with_extended_channel();
            s.set_stream(StreamKind::Solo);
            s.accounting_stream = StreamKind::GroupSolo;
            let cid = s.primary_channel.unwrap();
            let entry = distribution_entry(accounting.clone());
            let blob = conformant_outputs(&entry, 312_500_000);
            let acc = accepted(entry);
            let mut input = custom_job_input(cid, Token([1u8; 16]));
            input.distribution_id = Some(9);
            input.coinbase_tx_outputs = blob;

            let out = handle_set_custom_mining_job(
                &mut s,
                &input,
                None,
                Some(&distribution_allocation(REGTEST_ADDR, 1)),
                Some(&acc),
                1_000,
            );
            match (&out.outbound[0], accept) {
                (OutboundFrame::SetCustomMiningJobSuccess { .. }, true) => {}
                (OutboundFrame::SetCustomMiningJobError { error_code, .. }, false) => {
                    assert_eq!(error_code, ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
                }
                (other, want) => {
                    panic!("{accounting:?} after the flip: wanted {want}, got {other:?}")
                }
            }
        }
    }

    /// The same mode flip on a Full-Template job, whose reference is inherited from the declaration.
    #[test]
    fn a_full_template_job_inherits_against_the_live_mode_not_the_frozen_stream() {
        use crate::bridge::DistributionAccounting as Acct;
        let me = || AddressId::new(REGTEST_ADDR.to_string()).unwrap();

        // Opened Solo, joined a group: the Group-Solo plan must be accepted.
        let mut s = negotiated_session_with_extended_channel();
        s.set_stream(StreamKind::Solo);
        s.accounting_stream = StreamKind::GroupSolo;
        let cid = s.primary_channel.unwrap();
        let entry = distribution_entry(Acct::GroupSolo(me()));
        let blob = conformant_outputs(&entry, 312_500_000);
        let declared = declared_under_distribution(
            bridge_entry_declaring(
                Token([1u8; 16]),
                REGTEST_ADDR,
                42,
                &FIXTURE_SCRIPT_SIG_PREFIX,
                &blob,
            ),
            9,
        );
        let acc = accepted(entry);
        let input = custom_job_matching(cid, &declared);
        assert_eq!(
            input.distribution_id, None,
            "a Full-Template JDC puts the TLV on the declare, not here — without that this \
             test would take the frame-TLV path and prove nothing"
        );
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&declared)),
            None,
            Some(&acc),
            1_000,
        );
        assert!(
            matches!(
                out.outbound[0],
                OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "the pool must not refuse the plan it published for this miner's own mode, got {:?}",
            out.outbound[0]
        );

        // Left the group: accounting Solo, template stream still GroupSolo;
        // the Solo plan must be mineable.
        let mut s = negotiated_session_with_extended_channel();
        s.set_stream(StreamKind::GroupSolo);
        s.accounting_stream = StreamKind::Solo;
        let cid = s.primary_channel.unwrap();
        let entry = distribution_entry(Acct::Solo(me()));
        let blob = conformant_outputs(&entry, 312_500_000);
        let declared = declared_under_distribution(
            bridge_entry_declaring(
                Token([2u8; 16]),
                REGTEST_ADDR,
                43,
                &FIXTURE_SCRIPT_SIG_PREFIX,
                &blob,
            ),
            9,
        );
        let acc = accepted(entry);
        let out = handle_set_custom_mining_job(
            &mut s,
            &custom_job_matching(cid, &declared),
            Some(&job_ref_for(&declared)),
            None,
            Some(&acc),
            1_000,
        );
        assert!(
            matches!(
                out.outbound[0],
                OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "the pool must not refuse the Solo plan of a miner that left its group, got {:?}",
            out.outbound[0]
        );
    }

    /// The base-protocol Solo gate refuses a miner that joined a group while connected.
    #[test]
    fn joining_a_group_closes_the_base_protocol_solo_gate() {
        let alloc = base_allocation(REGTEST_ADDR, 42);
        let job = |cid| {
            coinbase_only_job(
                cid,
                Token([0x77u8; 16]),
                &[txout(312_500_000, designated_script(REGTEST_ADDR))],
            )
        };

        // Precondition: on the Solo stream this exact job IS served.
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let out = handle_set_custom_mining_job(&mut s, &job(cid), None, Some(&alloc), None, 1_000);
        assert!(
            matches!(
                out.outbound[0],
                OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "fixture must be servable before the flip, got {:?}",
            out.outbound[0]
        );

        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        s.accounting_stream = StreamKind::GroupSolo;
        let out = handle_set_custom_mining_job(&mut s, &job(cid), None, Some(&alloc), None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_CUSTOM_JOB_REQUIRES_SOLO);
            }
            other => panic!("a group member must not be served a base-protocol job, got {other:?}"),
        }
    }

    /// A Full-Template job is checked on its submitted outputs, not passed for matching its declaration.
    #[test]
    fn set_custom_mining_job_full_template_nonconformant_coinbase_rejects() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        // Pays only the miner, and was declared that way, so only
        // ext 0x0003/Output Verification can catch it.
        let self_paying = bitcoin::consensus::serialize(&vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(312_500_000),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x00, 0x14, 0xBB]),
        }]);
        let bridge = bridge_entry_declaring(
            token,
            REGTEST_ADDR,
            42,
            &FIXTURE_SCRIPT_SIG_PREFIX,
            &self_paying,
        );
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let acc = accepted(entry);
        let mut input = custom_job_matching(cid, &bridge);
        input.distribution_id = Some(9);
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&bridge)),
            None,
            Some(&acc),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_PAYOUT_DISTRIBUTION);
            }
            other => panic!("a Full-Template job must still be ext 0x0003/Output Verification-checked, got {other:?}"),
        }
    }

    /// A Full-Template job whose outputs match the distribution is accepted.
    #[test]
    fn set_custom_mining_job_full_template_conformant_coinbase_accepts() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let blob = conformant_outputs(&entry, 312_500_000);
        let bridge =
            bridge_entry_declaring(token, REGTEST_ADDR, 42, &FIXTURE_SCRIPT_SIG_PREFIX, &blob);
        let acc = accepted(entry);
        let mut input = custom_job_matching(cid, &bridge);
        input.distribution_id = Some(9);
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&bridge)),
            None,
            Some(&acc),
            1_000,
        );
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
    }

    /// An invented `distribution_id` off Solo is rejected as stale.
    #[test]
    fn set_custom_mining_job_full_template_bogus_distribution_id_rejects() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let bridge = bridge_entry_for(token, REGTEST_ADDR, 42);
        let mut input = custom_job_input(cid, token);
        input.distribution_id = Some(4_242); // never published
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&bridge)),
            None,
            None, // unresolvable
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_PAYOUT_DISTRIBUTION);
            }
            other => panic!("a bogus distribution_id must not pass the Solo gate, got {other:?}"),
        }
    }

    /// A Full-Template job without a frame TLV inherits its declaration's reference.
    #[test]
    fn full_template_custom_job_inherits_its_declarations_distribution() {
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let blob = conformant_outputs(&entry, 312_500_000);
        let token = Token([1u8; 16]);
        let declared =
            bridge_entry_declaring(token, REGTEST_ADDR, 42, &FIXTURE_SCRIPT_SIG_PREFIX, &blob);

        // Declared under distribution 9, no TLV on the mining frame.
        let mut s = negotiated_session_with_extended_channel();
        assert_ne!(
            s.stream,
            StreamKind::Solo,
            "the Solo gate must be live, or this proves nothing"
        );
        let cid = s.primary_channel.unwrap();
        let with_booking = declared_under_distribution(declared.clone(), 9);
        let mut input = custom_job_matching(cid, &with_booking);
        input.distribution_id = None;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&with_booking)),
            None,
            Some(&accepted(entry.clone())),
            1_000,
        );
        assert!(
            matches!(
                out.outbound[0],
                OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "a Full-Template job must be judged by the distribution its \
             declaration referenced, got {:?}",
            out.outbound[0]
        );

        // Negative control: the declaration referenced nothing, so the Solo
        // gate must still bite.
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let mut input = custom_job_matching(cid, &declared);
        input.distribution_id = None;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&declared)),
            None,
            Some(&accepted(entry)),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_CUSTOM_JOB_REQUIRES_SOLO);
            }
            other => panic!("a declaration referencing nothing must not inherit, got {other:?}"),
        }
    }

    /// An inherited reference still runs Output Verification on the submitted outputs.
    #[test]
    fn inherited_distribution_still_validates_the_submitted_coinbase() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        // Declared (and mined) paying itself instead of the published weights.
        let self_paying = bitcoin::consensus::serialize(&vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(312_500_000),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x00, 0x14, 0xBB]),
        }]);
        let declared = declared_under_distribution(
            bridge_entry_declaring(
                token,
                REGTEST_ADDR,
                42,
                &FIXTURE_SCRIPT_SIG_PREFIX,
                &self_paying,
            ),
            9,
        );
        let mut input = custom_job_matching(cid, &declared);
        input.distribution_id = None;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&declared)),
            None,
            Some(&accepted(distribution_entry(
                crate::bridge::DistributionAccounting::PoolWide,
            ))),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_PAYOUT_DISTRIBUTION);
            }
            other => panic!("an inherited reference must still be ext 0x0003/Output Verification-checked, got {other:?}"),
        }
    }

    /// A job under an unbookable distribution is still served; the reference is not read off `booking`.
    #[test]
    fn an_unbookable_distribution_still_yields_a_mineable_job() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let blob = conformant_outputs(&entry, 312_500_000);
        let declared = declared_under_unbookable_distribution(
            bridge_entry_declaring(token, REGTEST_ADDR, 42, &FIXTURE_SCRIPT_SIG_PREFIX, &blob),
            9,
        );
        assert!(
            declared.declared_job.booking.is_none(),
            "the whole point is that this one carries no booking"
        );
        let mut input = custom_job_matching(cid, &declared);
        input.distribution_id = None;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&declared)),
            None,
            Some(&accepted(entry)),
            1_000,
        );
        assert!(
            matches!(
                out.outbound[0],
                OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "a non-bookable distribution must cost a booking, not the job, got {:?}",
            out.outbound[0]
        );
    }

    /// 0x0003 negotiated on the JDP side only gets `custom-jobs-require-solo` on the mining side.
    #[test]
    fn inherited_distribution_needs_the_extension_on_the_mining_connection() {
        let mut s = session_with_extended_channel(); // 0x0003 NOT negotiated here
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let blob = conformant_outputs(&entry, 312_500_000);
        let declared = declared_under_distribution(
            bridge_entry_declaring(token, REGTEST_ADDR, 42, &FIXTURE_SCRIPT_SIG_PREFIX, &blob),
            9,
        );
        let mut input = custom_job_matching(cid, &declared);
        input.distribution_id = None;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&declared)),
            None,
            Some(&accepted(entry)),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_CUSTOM_JOB_REQUIRES_SOLO);
            }
            other => panic!(
                "ext 0x0003/Negotiation requires negotiation on this connection too, got {other:?}"
            ),
        }
    }

    /// A Solo job declared without a reference is served with no acceptance window.
    #[test]
    fn a_solo_job_that_referenced_nothing_is_untouched_by_the_acceptance_window() {
        let mut s = solo_session_with_extended_channel();
        s.negotiated_extensions
            .push(SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS);
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        // Declared WITHOUT a distribution reference.
        let declared =
            bridge_entry_declaring(token, REGTEST_ADDR, 42, &FIXTURE_SCRIPT_SIG_PREFIX, &[0x00]);
        assert_eq!(
            declared.declared_job.distribution_id, None,
            "the subject is a declaration that referenced nothing"
        );
        let mut input = custom_job_matching(cid, &declared);
        input.distribution_id = None;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&declared)),
            None,
            None, // settled / superseded — nothing resolves
            1_000,
        );
        assert!(
            matches!(
                out.outbound[0],
                OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "a Solo job must not start failing on a window it never consulted, got {:?}",
            out.outbound[0]
        );
    }

    /// A pool-wide declaration is refused after the address flips to Solo, live or withdrawn plan.
    #[test]
    fn a_flipped_solo_accounting_may_not_mine_a_pool_wide_declaration() {
        for live in [true, false] {
            let mut s = negotiated_session_with_extended_channel();
            s.set_stream(StreamKind::Pplns);
            s.accounting_stream = StreamKind::Solo;
            let cid = s.primary_channel.unwrap();
            let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
            let blob = conformant_outputs(&entry, 312_500_000);
            let declared = declared_under_distribution(
                bridge_entry_declaring(
                    Token([1u8; 16]),
                    REGTEST_ADDR,
                    42,
                    &FIXTURE_SCRIPT_SIG_PREFIX,
                    &blob,
                ),
                9,
            );
            let acc = accepted(entry);
            let out = handle_set_custom_mining_job(
                &mut s,
                &custom_job_matching(cid, &declared),
                Some(&job_ref_for(&declared)),
                None,
                live.then_some(&acc),
                1_000,
            );
            match &out.outbound[0] {
                OutboundFrame::SetCustomMiningJobError { error_code, .. } => assert_eq!(
                    error_code,
                    if live {
                        ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH
                    } else {
                        ERR_STALE_PAYOUT_DISTRIBUTION
                    },
                    "live={live}"
                ),
                other => panic!(
                    "live={live}: a coinbase paying the PPLNS window must not be mined by a \
                     Solo accounting, got {other:?}"
                ),
            }
        }
    }

    /// An inherited reference that no longer resolves is refused on a shared stream.
    #[test]
    fn a_shared_accounting_stream_still_fails_on_an_unresolvable_inherited_id() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let blob = conformant_outputs(&entry, 312_500_000);
        let declared = declared_under_distribution(
            bridge_entry_declaring(token, REGTEST_ADDR, 42, &FIXTURE_SCRIPT_SIG_PREFIX, &blob),
            9,
        );
        assert_ne!(s.accounting_stream, StreamKind::Solo);
        let mut input = custom_job_matching(cid, &declared);
        input.distribution_id = None;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&declared)),
            None,
            None, // settled / superseded
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_PAYOUT_DISTRIBUTION);
            }
            other => panic!("a withdrawn distribution must not be mineable, got {other:?}"),
        }
    }

    /// A Group-Solo connection may not reference the pool-wide (PPLNS) distribution.
    #[test]
    fn set_custom_mining_job_pool_wide_distribution_off_pplns_stream_rejects() {
        for stream in [
            StreamKind::GroupSolo,
            StreamKind::Solo,
            StreamKind::Blockparty,
        ] {
            let mut s = negotiated_session_with_extended_channel();
            s.set_stream(stream);
            let cid = s.primary_channel.unwrap();
            let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
            let blob = conformant_outputs(&entry, 312_500_000);
            let acc = accepted(entry);
            let mut input = custom_job_input(cid, Token([1u8; 16]));
            input.distribution_id = Some(9);
            input.coinbase_tx_outputs = blob;
            let out = handle_set_custom_mining_job(
                &mut s,
                &input,
                None,
                Some(&distribution_allocation(REGTEST_ADDR, 1)),
                Some(&acc),
                1_000,
            );
            match &out.outbound[0] {
                OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                    assert_eq!(
                        error_code, ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH,
                        "{stream:?} must not reference the pool-wide distribution"
                    );
                }
                other => panic!("expected token-mismatch on {stream:?}, got {other:?}"),
            }
        }
    }

    /// Sequential custom jobs on one channel get monotonic job_ids.
    #[test]
    fn set_custom_mining_job_allocates_monotonic_job_ids() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        let job_ref = job_ref_for(&entry);
        let input1 = custom_job_input(cid, token);
        let out1 = handle_set_custom_mining_job(&mut s, &input1, Some(&job_ref), None, None, 1_000);
        let mut input2 = custom_job_input(cid, token);
        input2.request_id = 2;
        let out2 = handle_set_custom_mining_job(&mut s, &input2, Some(&job_ref), None, None, 2_000);
        let id1 = match out1.outbound[0] {
            OutboundFrame::SetCustomMiningJobSuccess { job_id, .. } => job_id,
            _ => unreachable!(),
        };
        let id2 = match out2.outbound[0] {
            OutboundFrame::SetCustomMiningJobSuccess { job_id, .. } => job_id,
            _ => unreachable!(),
        };
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    /// A scriptSig length of 265 encodes as the 3-byte varint `0xFD` + u16-LE.
    #[test]
    fn set_custom_mining_job_emits_3byte_varint_for_large_scriptsig() {
        // Coinbase-only path: a declared job cannot reach this length, but the
        // assembly must still encode one correctly.
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let blob = conformant_outputs(&entry, 312_500_000);
        let acc = accepted(entry);
        let mut input = custom_job_input(cid, token);
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = blob;
        input.coinbase_prefix = vec![0xAA; 253];
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            None,
            Some(&distribution_allocation(REGTEST_ADDR, 1)),
            Some(&acc),
            1_000,
        );
        assert!(
            matches!(
                out.outbound[0],
                OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "coinbase-only job must be accepted, got {:?}",
            out.outbound[0]
        );
        let ch = s.channels.get(&cid).unwrap();
        let ext = ch.extended_jobs.get(&1).expect("must be stored");
        // The varint at byte 41: 265 = 0x0109.
        assert_eq!(ext.coinbase_prefix[41], 0xFD);
        assert_eq!(&ext.coinbase_prefix[42..44], &[0x09, 0x01]);
        // Then the 253 JDC-prefix bytes.
        assert_eq!(ext.coinbase_prefix.len(), 41 + 3 + 253);
    }

    // ── Declaration binding ────────────────────────────────────────────

    /// Mining a conformant coinbase other than the declared one is caught by the binding alone.
    #[test]
    fn a_swapped_coinbase_paying_the_same_distribution_is_still_rejected() {
        let token = Token([1u8; 16]);
        let entry = distribution_entry(crate::bridge::DistributionAccounting::PoolWide);
        let declared_blob = conformant_outputs(&entry, 312_500_000);
        let halved_blob = conformant_outputs(&entry, 156_250_000);
        assert_ne!(declared_blob, halved_blob, "the two revenues must differ");

        // Premise: BOTH blobs pass ext 0x0003/Output Verification.
        for (label, blob) in [("declared", &declared_blob), ("halved", &halved_blob)] {
            let outputs: Vec<bitcoin::TxOut> =
                bitcoin::consensus::deserialize(blob).expect("conformant blob must decode");
            assert!(
                crate::jdp::payout_distribution::validate_coinbase_outputs_against_distribution(
                    &outputs,
                    &entry.built.pool_payout,
                    &entry.built.payouts,
                    &entry.built.dust_limits,
                    &entry.built.additional_outputs,
                )
                .is_ok(),
                "the {label} coinbase must be ext 0x0003/Output Verification-conformant, or this test \
                 proves nothing about the binding"
            );
        }
        let bridge = bridge_entry_declaring(
            token,
            REGTEST_ADDR,
            42,
            &FIXTURE_SCRIPT_SIG_PREFIX,
            &declared_blob,
        );

        // Positive control: mining what was declared is accepted.
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let mut honest = custom_job_matching(cid, &bridge);
        honest.distribution_id = Some(9);
        let out = handle_set_custom_mining_job(
            &mut s,
            &honest,
            Some(&job_ref_for(&bridge)),
            None,
            Some(&accepted(entry.clone())),
            1_000,
        );
        assert!(
            matches!(
                out.outbound[0],
                OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "the declared coinbase must still be accepted, got {:?}",
            out.outbound[0]
        );

        // The swap: same distribution, half the revenue.
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let mut swapped = custom_job_matching(cid, &bridge);
        swapped.distribution_id = Some(9);
        swapped.coinbase_tx_outputs = halved_blob;
        let out = handle_set_custom_mining_job(
            &mut s,
            &swapped,
            Some(&job_ref_for(&bridge)),
            None,
            Some(&accepted(entry)),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_DECLARATION_MISMATCH);
            }
            other => panic!("a swapped coinbase must not be minable, got {other:?}"),
        }
    }

    /// Same coinbase with a different transaction set is caught by the binding.
    #[test]
    fn a_swapped_merkle_path_is_rejected() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);

        let honest = custom_job_matching(cid, &entry);
        assert!(!honest.merkle_path.is_empty(), "fixture must commit to txs");
        let out = handle_set_custom_mining_job(
            &mut s,
            &honest,
            Some(&job_ref_for(&entry)),
            None,
            None,
            1_000,
        );
        assert!(
            matches!(
                out.outbound[0],
                OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "the declared transaction set must still be accepted"
        );

        let mut swapped = custom_job_matching(cid, &entry);
        swapped.merkle_path[0] = [0xEE; 32];
        let out = handle_set_custom_mining_job(
            &mut s,
            &swapped,
            Some(&job_ref_for(&entry)),
            None,
            None,
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_DECLARATION_MISMATCH);
            }
            other => panic!("a swapped transaction set must not be minable, got {other:?}"),
        }
    }

    /// The fixture declaration and channel reserve the same extranonce width.
    #[test]
    fn the_fixture_slot_matches_the_test_channel() {
        let s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        assert_eq!(
            s.channels.get(&cid).unwrap().full_extranonce_size(),
            FIXTURE_DECLARED_SLOT
        );
    }

    /// A channel extranonce width differing from the declared gap is refused.
    #[test]
    fn a_channel_extranonce_wider_than_the_declared_slot_is_rejected() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        let input = custom_job_matching(cid, &entry);

        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&entry)),
            None,
            None,
            1_000,
        );
        assert!(
            matches!(
                out.outbound[0],
                OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "matching widths must be accepted"
        );

        // Widen the channel's extranonce past the gap the declaration left.
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        s.channels.get_mut(&cid).unwrap().extranonce_size += 1;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&entry)),
            None,
            None,
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_DECLARATION_MISMATCH);
            }
            other => panic!("a mismatched extranonce width must be refused, got {other:?}"),
        }
    }

    /// A segwit-serialised declaration, as real JDCs send it, is accepted end to end.
    #[test]
    fn a_segwit_shaped_declaration_accepts_the_job_a_real_jdc_would_mine() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

        let script_sig_head = FIXTURE_SCRIPT_SIG_PREFIX;
        let mut script_sig = script_sig_head.to_vec();
        script_sig.extend_from_slice(&[0u8; FIXTURE_DECLARED_SLOT]);

        let mut witness = Witness::new();
        witness.push([0u8; 32]); // witness reserved value ⇒ segwit serialisation

        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(script_sig),
                sequence: Sequence(0xFFFF_FFFF),
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(312_500_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };

        // 4 version + 2 marker/flag + 1 input count + 32 outpoint hash
        // + 4 index + 1 scriptSig len.
        let raw = bitcoin::consensus::serialize(&tx);
        let index = 4 + 2 + 1 + 32 + 4 + 1 + script_sig_head.len();
        let raw_transactions = fixture_declared_txs();
        let token = Token([1u8; 16]);
        let entry = RegisteredDeclaredJob {
            declared_job: JdpDeclaredJob {
                new_token: token,
                miner_address: AddressId::new(REGTEST_ADDR).unwrap(),
                version: 0x2000_0000,
                coinbase_tx_prefix: raw[..index].to_vec(),
                coinbase_tx_suffix: raw[index + FIXTURE_DECLARED_SLOT..].to_vec(),
                raw_transactions,
                prev_hash: [0xAB; 32],
                declared_at_ms: 1_000,
                booking: None,
                distribution_id: None,
            },
            jdp_session_id: 42,
        };

        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        // Built from `tx`, independently of the projection under test. The
        // merkle_path still fits: it depends only on the transaction set.
        let mut input = custom_job_input(cid, token);
        input.version = 0x2000_0000;
        input.coinbase_tx_version = tx.version.0 as u32;
        input.coinbase_prefix = script_sig_head.to_vec();
        input.coinbase_tx_input_n_sequence = tx.input[0].sequence.0;
        input.coinbase_tx_outputs = bitcoin::consensus::serialize(&tx.output);
        input.coinbase_tx_locktime = tx.lock_time.to_consensus_u32();

        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&entry)),
            None,
            None,
            1_000,
        );
        assert!(
            matches!(
                out.outbound[0],
                OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "a segwit-shaped declaration must accept the job it declared, got {:?}",
            out.outbound[0]
        );
    }

    /// A declaration the projection cannot express authorises nothing.
    #[test]
    fn a_declaration_that_cannot_be_projected_is_rejected() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let mut entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        let input = custom_job_input(cid, token);
        // Truncate the declared coinbase past repair.
        entry.declared_job.coinbase_tx_prefix = vec![0x02, 0x00];
        let job_ref = job_ref_for(&entry);
        assert!(job_ref.binding.is_none(), "fixture must fail to project");
        let out = handle_set_custom_mining_job(&mut s, &input, Some(&job_ref), None, None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_DECLARATION_MISMATCH);
            }
            other => panic!("an unprojectable declaration must not authorise, got {other:?}"),
        }
    }
}
