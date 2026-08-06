// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure handler-layer for the SV2 mining-protocol per-connection state
//! machine. Mirrors the design of `bp_stratum_v1::client`
//! (pure-state, pure-handlers, `HandlerOutcome` and `SessionEvent`
//! for hook fan-out) — no I/O, no broadcasting, no DB writes.
//!
//! Each handler:
//! - Takes `&mut MiningSessionState<C>` + the deserialized input
//! - Mutates state in place
//! - Returns [`HandlerOutcome`] = `{ outbound: Vec<OutboundFrame>,
//!   events: Vec<SessionEvent> }`
//!
//! The IO layer (`server.rs`) drives a `tokio::select!` loop over the
//! Noise-wrapped TcpStream + the `TemplateBroadcast` receiver + the
//! vardiff timer + the cancel token. On each event it deserializes,
//! calls the matching handler, then serializes each [`OutboundFrame`]
//! to the wire via `stratum_core::codec_sv2` + dispatches each
//! [`SessionEvent`] to the configured `ServerHooks`.
//!
//! ## Scope of this commit
//!
//! Implemented:
//! - `handle_setup_connection` (mining-only `protocol = 0`)
//! - `handle_open_standard_mining_channel` /
//!   `handle_open_extended_mining_channel`
//! - `handle_submit_shares_standard` /
//!   `handle_submit_shares_extended`
//! - `handle_update_channel`
//! - `handle_close_channel`
//! - `apply_vardiff_check` (classic shares-per-minute via
//!   [`bp_vardiff::VarDiffEngine`])
//!
//! All implemented: `apply_template_broadcast` (MiningJob-build + PPLNS /
//! group-solo / solo mode-routing), `handle_request_extensions` (ext 0x0001
//! negotiation), `handle_set_custom_mining_job` (JDC integration), and
//! Standard-channel
//! retire-not-clear (block change stamps `retired_at_ms` so in-flight Standard
//! shares classify as the spec-correct `stale-share`, not `invalid-job-id`).
//!
//! Intentional non-goal: `protocol = 2` (template-distribution over the SV2
//! wire) is not accepted — the Rust pool sources templates via TDP-IPC, not
//! the SV2 TDP wire protocol. Architecture choice, not a missing feature.

use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::Network;
use bp_common::{AddressId, StreamKind};
use bp_mining_job::{
    address_to_script, merkle_root_from_coinbase, normalize_btc_address, MiningJob, MiningJobCache,
    MiningJobError, PayoutEntry, TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
};
use bp_share::{
    clamp_difficulty_to_max_target, difficulty_to_target, hash_rate_to_difficulty, sha256d,
    Difficulty, Target,
};
use bp_stats::MAX_REASONABLE_DIFFICULTY;
use bp_vardiff::{Clock, VarDiffEngine};

use crate::extensions::{
    RequestExtensions, SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS, SV2_EXTENSION_TYPE_WORKER_ID,
};

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
use super::translator::{TemplateBroadcast, TemplateChange};

// ── SetupConnection flags (BIP-310 / SV2 spec §4.1) ─────────────────

/// Protocol code for the mining sub-protocol (SV2 spec).
pub const PROTOCOL_MINING: u8 = 0;
/// Protocol code for the template-distribution sub-protocol (SV2 spec).
/// Intentionally NOT accepted over the wire — the Rust pool sources templates
/// via TDP-IPC, not the SV2 TDP wire protocol (architecture choice).
pub const PROTOCOL_TEMPLATE_DISTRIBUTION: u8 = 2;

/// Miner REQUIRES standard mining jobs (no extranonce rolling).
pub const FLAG_REQUIRES_STANDARD_JOBS: u32 = 1 << 0;
/// Miner REQUIRES work selection (BIP-310 §3 — JDC integration).
pub const FLAG_REQUIRES_WORK_SELECTION: u32 = 1 << 1;
/// Miner REQUIRES BIP-320 version-rolling support.
pub const FLAG_REQUIRES_VERSION_ROLLING: u32 = 1 << 2;

// `SetupConnection.Success.flags` (SV2 spec §5.3.2, server→client) is a
// SEPARATE capability bitset whose bit meanings are UNRELATED to the client
// request flags above — the two spaces merely reuse bit indices 0/1.
/// Server will NOT accept version-field changes. Per spec MUST NOT be set if
/// the client requested [`FLAG_REQUIRES_VERSION_ROLLING`].
pub const FLAG_SUCCESS_REQUIRES_FIXED_VERSION: u32 = 1 << 0;
/// Server will NOT accept opening of standard channels (extended channels only).
pub const FLAG_SUCCESS_REQUIRES_EXTENDED_CHANNELS: u32 = 1 << 1;

/// Maximum miner-rollable extranonce region (bytes) an Extended channel can be
/// granted. 16 matches the common pool default so an aggregating proxy has room
/// to subdivide the space among many downstream rigs; with our 4-byte pool
/// prefix the total extranonce is 20 bytes, well within the SV2 32-byte cap
/// (and the 100-byte coinbase scriptSig limit). A miner that requests more than
/// this in `OpenExtendedMiningChannel.min_extranonce_size` is rejected with
/// [`ERR_MIN_EXTRANONCE_SIZE_TOO_LARGE`] rather than silently under-granted.
pub const MAX_EXTENDED_ROLLABLE: usize = 16;

/// Minimum supported SV2 protocol version (currently 2 per the spec
/// finalisation).
pub const MIN_PROTOCOL_VERSION: u16 = 2;
/// Maximum supported SV2 protocol version. Bump when the spec adds a
/// new revision we support.
pub const MAX_PROTOCOL_VERSION: u16 = 2;

// ── Wire error codes (SV2 spec setup/open-channel error strings) ────

/// `protocol-version-mismatch` — miner's version range doesn't intersect
/// `[MIN_PROTOCOL_VERSION, MAX_PROTOCOL_VERSION]`.
pub const ERR_PROTOCOL_VERSION_MISMATCH: &str = "protocol-version-mismatch";

/// `unsupported-protocol` — we don't accept this sub-protocol value.
/// Used for `protocol = 2` (TDP-only) until that path is wired.
pub const ERR_UNSUPPORTED_PROTOCOL: &str = "unsupported-protocol";

/// `unknown-user` — the address parsed out of `user_identity` failed
/// `bp_mining_job::normalize_btc_address` validation.
pub const ERR_UNKNOWN_USER: &str = "unknown-user";

/// `max-target-out-of-range` — miner's declared `max_target` is below
/// the pool's enforced floor (would require a harder target than the
/// pool is willing to assign).
pub const ERR_MAX_TARGET_OUT_OF_RANGE: &str = "max-target-out-of-range";

/// `address-locked` — multi-channel connection sent an
/// `OpenMiningChannel` request whose `user_identity` resolves to a
/// different address than the connection's first channel.
pub const ERR_ADDRESS_LOCKED: &str = "address-locked";

/// `min-extranonce-size-too-large` — an `OpenExtendedMiningChannel`
/// requested a `min_extranonce_size` larger than the rollable region the
/// pool can grant ([`MAX_EXTENDED_ROLLABLE`] bytes, bounded so the total
/// extranonce stays within the SV2 32-byte cap). SV2 §5.3.2 requires the
/// server to grant at least the requested minimum or reject — we reject
/// rather than silently hand back a smaller region (which would make an
/// aggregating proxy tear down the upstream).
pub const ERR_MIN_EXTRANONCE_SIZE_TOO_LARGE: &str = "min-extranonce-size-too-large";

/// `invalid-channel-id` — `UpdateChannel` / `CloseChannel` referenced
/// an unknown channel on this connection.
pub const ERR_INVALID_CHANNEL_ID: &str = "invalid-channel-id";

/// `invalid-job-id` — used in `SetCustomMiningJob.Error` when the
/// channel kind isn't Extended (custom jobs are Extended-only per
/// SV2 spec — Standard channels don't have an extranonce slot).
pub const ERR_INVALID_JOB_ID: &str = "invalid-job-id";

/// `invalid-job-param-value-token-mismatch` — the
/// `SetCustomMiningJob.mining_job_token` was registered in the
/// bridge under a different miner address than the channel's locked
/// address. IO-layer cross-check for token validation. Caller passes
/// the bridge projection in via [`handle_set_custom_mining_job`]'s
/// `bridge_job` argument.
pub const ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH: &str = "invalid-job-param-value-token-mismatch";

/// `invalid-mining-job-token` — the `SetCustomMiningJob.mining_job_token`
/// resolves to no declared job (bridge) and the job references no
/// ext-0x0003 payout distribution: never declared here, expired, or
/// evicted with its JDP session. Fail-closed: without either there is
/// nothing a non-custodial pool could validate the coinbase against.
pub const ERR_INVALID_MINING_JOB_TOKEN: &str = "invalid-mining-job-token";

/// `stale-chain-tip` — the `SetCustomMiningJob.prev_hash` differs from the
/// tip its declaration was accepted under: the chain advanced between
/// declaration and submission. A benign race, not a protocol violation —
/// this exact string matters, because JDCs treat `stale-chain-tip` as
/// retryable and any other declaration error as fatal.
pub const ERR_STALE_CHAIN_TIP: &str = "stale-chain-tip";

/// `custom-jobs-require-solo` — a base-protocol custom job (no ext-0x0003
/// distribution reference) on a non-Solo stream. Off Solo the shares enter
/// SHARED accounting (PPLNS window / group), but nothing validates that the
/// self-built coinbase pays that accounting — the job's finder would collect
/// window share while contributing blocks that pay the pool's window
/// nothing. With a referenced distribution the §7.1 positional check forces
/// the coinbase to pay the published split, so non-Solo is legitimate there
/// (the whole point of the extension).
pub const ERR_CUSTOM_JOB_REQUIRES_SOLO: &str = "custom-jobs-require-solo";

/// `invalid-job-param-value-coinbase_tx_outputs` — the
/// `SetCustomMiningJob.coinbase_tx_outputs` doesn't carry one of the pool's
/// committed ext-0x0003 payout outputs (missing / modified / reduced /
/// under-counted vs a duplicate), or didn't parse. The mined coinbase MUST
/// carry the committed set (spec §4); passed in via `payout_set`.
pub const ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS: &str =
    "invalid-job-param-value-coinbase_tx_outputs";

/// `invalid-job-param-value-declaration-mismatch` — the job this
/// `SetCustomMiningJob` asks to mine is not the job the token was declared
/// for: a different coinbase, or a different transaction set (merkle path).
///
/// One code for every field, deliberately. The JDC's remedy is identical in
/// each case — declare and submit the same job — so a per-field code would
/// buy it nothing; which field disagreed is WARN-logged for the operator.
/// The check itself lives in [`crate::jdp::custom_job_binding`].
pub const ERR_INVALID_JOB_PARAM_DECLARATION_MISMATCH: &str =
    "invalid-job-param-value-declaration-mismatch";

/// `stale-payout-distribution` — the `distribution_id` referenced by this
/// `SetCustomMiningJob` is outside the acceptance window (ext 0x0003
/// §7.2/§10). The JDC re-declares against the latest distribution.
pub const ERR_STALE_PAYOUT_DISTRIBUTION: &str =
    crate::extensions::payout_distribution_error_codes::STALE_PAYOUT_DISTRIBUTION;

/// `invalid-payout-distribution` — the job's coinbase outputs violate
/// §4 against the referenced distribution, or the §6 TLV is missing on
/// a negotiated Coinbase-only custom job.
pub const ERR_INVALID_PAYOUT_DISTRIBUTION: &str =
    crate::extensions::payout_distribution_error_codes::INVALID_PAYOUT_DISTRIBUTION;

/// Set of SV2 mining-side extensions our pool supports:
/// - Worker-ID TLV (0x0002) for per-share worker attribution on
///   `SubmitSharesExtended`.
/// - Non-Custodial Payouts (0x0003): §2 requires negotiation on BOTH
///   the JDP and the Mining Protocol connection; the mining side
///   carries the §6 `distribution_id` TLV on `SetCustomMiningJob`.
pub const SUPPORTED_MINING_EXTENSIONS: &[u16] = &[
    SV2_EXTENSION_TYPE_WORKER_ID,
    SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS,
];

/// Convenience predicate. The mining-side handler only cares about
/// Worker-ID right now; `0x0003` is rejected here because it belongs
/// to JDP. Kept as a function (not a `const fn`) so adding more
/// supported extensions later is a one-line addition.
fn is_mining_extension_supported(ext: u16) -> bool {
    SUPPORTED_MINING_EXTENSIONS.contains(&ext)
}

// ── Inputs (typed wrappers over deserialized SV2 frames) ────────────

/// Inputs from a deserialized `SetupConnection` frame, narrowed to
/// what the handler actually reads.
#[derive(Clone, Debug)]
pub struct SetupConnectionInput {
    pub protocol: u8,
    pub min_version: u16,
    pub max_version: u16,
    pub flags: u32,
    pub vendor: String,
    pub firmware: String,
    pub hardware_version: String,
    pub device_id: String,
}

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

/// What the handler decided to send. The IO layer translates these
/// into `stratum_core::mining_sv2` / `common_messages_sv2` types and
/// serializes via `codec_sv2`. Kept as a separate enum so the handler
/// stays pure on session-state types (no lifetimes leaking through).
///
/// Variants are scoped to the handlers implemented in this commit;
/// add variants as new handlers land (e.g. `SetCustomMiningJobSuccess`
/// when the JDC path is wired).
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
    /// Ext 0x0001 negotiation success. `supported_extensions` is the
    /// intersection of the miner's requested set and our pool's
    /// `SUPPORTED_MINING_EXTENSIONS` — may be empty if the miner sent
    /// an empty request (legal under spec ext 0x0001 §4.1).
    RequestExtensionsSuccess {
        request_id: u16,
        supported_extensions: Vec<u16>,
    },
    /// Ext 0x0001 negotiation error. Emitted when NONE of the
    /// miner's requested extensions are supported (mixed requests
    /// still produce Success with the supported subset).
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
        /// 0 for un-grouped channels — group-channel support lives in
        /// `mining/groups.rs` (deferred).
        group_channel_id: u32,
    },
    OpenExtendedMiningChannelSuccess {
        request_id: u32,
        channel_id: u32,
        target: [u8; 32],
        /// Wire value: rollable extranonce size (miner-controlled bytes
        /// only, NOT including the pool prefix).
        extranonce_size: u16,
        extranonce_prefix: Vec<u8>,
        /// Group this channel was assigned to (spec §5.2.3), or `0` when
        /// un-grouped. Non-zero for Extended channels on a
        /// non-`REQUIRES_STANDARD_JOBS` connection — the downstream infers
        /// group membership from this id (we don't send `SetGroupChannel`).
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
    /// SV2 §5.3.10 `SetExtranoncePrefix` — changes a channel's extranonce
    /// prefix. Per spec it applies to all jobs sent *after* this message on the
    /// channel, so the caller emits it immediately before the next job frame
    /// (the same "announce, then next job" model as SV1's
    /// `mining.set_extranonce`). Valid only for explicitly opened standard /
    /// extended channels (not group channels); `extranonce_prefix` is 0–32
    /// bytes (`B0_32`).
    SetExtranoncePrefix {
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
    },
    /// SV2 §5.3.4 `SetNewPrevHash` — sent per-channel on a block change
    /// to ACTIVATE a future job, AFTER the matching `NewMiningJob` /
    /// `NewExtendedMiningJob` (which carried an empty `min_ntime`).
    /// `job_id` MUST match the immediately-preceding future-job frame on
    /// the same channel; miners pair the two to derive the 80-byte
    /// header and adopt this `min_ntime` as the job's activation time.
    SetNewPrevHash {
        channel_id: u32,
        job_id: u32,
        prev_hash: [u8; 32],
        min_ntime: u32,
        n_bits: u32,
    },
    /// SV2 §5.3.7 `NewMiningJob` — Standard channels only. The pool
    /// pre-spliced the channel's `extranonce_prefix` (and zero-padded
    /// the rollable slot, which is empty for Standard) into the
    /// coinbase before computing the merkle root, so the miner just
    /// hashes the 80-byte header with their chosen `nonce` / `ntime` /
    /// version-mask.
    ///
    /// `min_ntime`: `None` marks a FUTURE job (block change) — the job
    /// is sent first and activated by the immediately-following
    /// `SetNewPrevHash`, which supplies the ntime. `Some(ts)` marks an
    /// active job for the current prev-hash (same-block fee refresh),
    /// sent alone with no `SetNewPrevHash`.
    NewMiningJob {
        channel_id: u32,
        job_id: u32,
        version: u32,
        merkle_root: [u8; 32],
        min_ntime: Option<u32>,
    },
    /// SV2 §5.3.8 `NewExtendedMiningJob` — Extended channels only.
    /// Carries the pre/suffix split of the coinbase so the miner can
    /// roll their portion of the extranonce, plus the merkle path for
    /// recomputing the root. `min_ntime` follows the same future-job
    /// (`None`) vs active-job (`Some`) convention as `NewMiningJob`.
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
    /// SV2 mining-protocol `SetCustomMiningJob.Success` — JDC-side
    /// custom job accepted. `job_id` is channel-local (allocated from
    /// `next_job_id`); the JDC uses it in subsequent
    /// `SubmitSharesExtended` frames on the same channel.
    SetCustomMiningJobSuccess {
        channel_id: u32,
        request_id: u32,
        job_id: u32,
    },
    /// `SetCustomMiningJob.Error` — JDC's frame rejected. Wire codes:
    /// `invalid-channel-id` / `invalid-job-id` (channel kind isn't
    /// Extended) / `invalid-job-param-value-token-mismatch` (token's
    /// bridge entry doesn't match the connection's locked miner
    /// address — IO-layer cross-check via
    /// [`crate::bridge::JdpDeclaredJobRegistry`]).
    SetCustomMiningJobError {
        channel_id: u32,
        request_id: u32,
        error_code: String,
    },
}

// ── SessionEvent ────────────────────────────────────────────────────

/// What the handler decided about the session beyond the wire frames.
/// The IO layer uses these to drive the hooks layer (DB writes,
/// share-stats fan-out, notifications, block-submit) without
/// re-deriving state.
#[derive(Clone, Debug)]
pub enum SessionEvent {
    /// `SetupConnection` completed; the miner is authenticated at the
    /// connection level (we accepted its protocol version + vendor).
    /// Caller can register the connection in the live-clients registry.
    SetupComplete,
    /// A new mining channel opened. Caller can record per-channel
    /// metadata (DB, registry).
    ChannelOpened {
        channel_id: u32,
        address: AddressId,
        worker: String,
        kind: ChannelKind,
    },
    /// Channel closed. Caller releases the channel's extranonce_prefix
    /// allocation + drops it from any per-address registry.
    ChannelClosed { channel_id: u32, reason: String },
    /// Channel-difficulty changed (vardiff ratchet or `UpdateChannel`).
    /// Caller persists the new value.
    DifficultyChanged { old: Difficulty, new: Difficulty },
    /// Share accepted on a channel. Carries the validation result so
    /// the caller can fan to PPLNS / group-solo / per-mode counters /
    /// block-found path.
    ShareAccepted {
        channel_id: u32,
        accept: Box<ShareAccept>,
    },
    /// Share rejected. Caller records the rejection breakdown.
    ShareRejected {
        channel_id: u32,
        reject: ShareReject,
    },
}

// ── HandlerOutcome ──────────────────────────────────────────────────

/// What a single handler call produced. Both fields can be empty
/// (e.g. a silently-ignored frame) — that's a no-op outcome.
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

/// All per-connection mutable state for the mining sub-protocol. Owned
/// `&mut` by the connection task that drives the Noise-wrapped socket.
///
/// Multi-channel: connections can host any number of channels (typically
/// 1; multi-hashboard setups and aggregating proxies open several). SV2
/// difficulty is per channel: each channel carries its own classic vardiff
/// engine (see `vardiff`) and retargets from its own share rate, clamped
/// against its own `declared_max_target` — independent channels on one
/// connection never pool their share rate. All channels share `address` —
/// the first channel opened locks the address; subsequent channels must
/// match.
pub struct MiningSessionState<C: Clock> {
    // Identity
    pub session_id: u32,
    pub network: Network,
    pub address: Option<AddressId>,
    pub worker_name: String,
    pub vendor: String,
    /// TDP template stream this connection mines on. Resolved once from the
    /// OpenChannel address (`StreamKind::for_mode`) and then fixed, so the
    /// block-submit handle always matches the template the job was built on.
    pub stream: StreamKind,

    // Negotiated state from SetupConnection
    pub setup_complete: bool,
    pub used_version: u16,
    pub version_rolling: bool,
    pub work_selection: bool,
    pub requires_standard_jobs: bool,
    pub is_tdp_client: bool,

    // Extensions negotiated via ext 0x0001 (RequestExtensions) —
    // populated by `handle_request_extensions`; read by the submit-side
    // TLV resolver (e.g. ext 0x0002 Worker-ID). A deduped `Vec` (not a
    // set): the list is tiny (0–2 entries) and the read loop hands it
    // straight to the frame parser as `&[u16]` on EVERY inbound frame —
    // a set would force a fresh collect-to-Vec allocation per frame.
    pub negotiated_extensions: Vec<u16>,

    // Connection default/initial difficulty. Live retargeting is
    // per-channel and lives in `vardiff` (keyed by channel id).
    pub session_difficulty: Difficulty,

    // Channels
    pub channels: HashMap<u32, ChannelState>,
    pub primary_channel: Option<u32>,
    /// Connection-local channel-id counter — incremented on each
    /// `OpenChannel`. Channel-ids are scoped to a connection, not to
    /// the whole pool. Also the source of `group_channel_id`s (same
    /// namespace, must not collide — spec §5.2.3).
    pub next_channel_id: u32,
    /// SV2 group channels (spec §5.2.3) for this connection. Populated
    /// eagerly when a non-`REQUIRES_STANDARD_JOBS` connection opens
    /// Extended channels — they're grouped by full extranonce size so
    /// the broadcast sends ONE job per group. Empty for standard-jobs /
    /// TDP / JDC connections.
    pub groups: GroupChannelRegistry,

    // Vardiff state
    /// Classic vardiff, one engine per channel id. SV2 difficulty is per
    /// channel, so each channel tracks its own share rate independently;
    /// several channels on one connection (multi-board, aggregating proxy)
    /// don't combine into one inflated rate. Standard, Extended and
    /// job-declaration channels all retarget through it.
    pub vardiff: HashMap<u32, VarDiffEngine<C>>,

    // Clock + per-port config
    pub clock: C,
    pub min_difficulty: Difficulty,
    /// Operator-configured start difficulty for the port (already raised
    /// to `min_difficulty` if set lower). Channel-open uses this as the
    /// floor for the initial assigned difficulty so a miner that
    /// under-reports `nominal_hash_rate` is never pinned to a trivial
    /// target. Vardiff retargets from there.
    pub initial_difficulty: Difficulty,
    pub target_shares_per_minute: f64,
    /// Cadence of the connection's vardiff check loop in milliseconds.
    /// Drives the tick in `server::run_connection`; every channel on the
    /// connection is re-evaluated on it.
    pub vardiff_interval_ms: u64,
    /// Whether vardiff may use elapsed silence as evidence and walk a
    /// quiet channel's difficulty down (see [`bp_vardiff`]'s module doc,
    /// "Silence easing"). Off by default.
    pub vardiff_silence_easing: bool,
    /// Clock reading of the last vardiff evaluation, timer or inline.
    /// Gates the post-share inline check so it cannot run more often than
    /// `vardiff_interval_ms` — see [`Self::vardiff_cooldown_elapsed`].
    pub last_difficulty_check_ms: u64,

    /// Per-share diagnostic logging toggle (server-level
    /// `stratum_share_logs`). Set by the I/O layer after construction;
    /// gates the `🎯 Extended share difficulty` trace in the submit
    /// validator. Defaults to `false`.
    pub share_logs: bool,
}

/// Per-port config slice passed at construction. The full
/// [`crate::config`] layer will wrap this for the I/O layer.
#[derive(Clone, Copy, Debug)]
pub struct PortConfig {
    pub network: Network,
    /// Hard floor — vardiff never retargets below this.
    pub min_difficulty: Difficulty,
    /// First difficulty advertised on channel open. Vardiff retargets
    /// from this baseline up or down; never falls below `min_difficulty`.
    pub initial_difficulty: Difficulty,
    pub target_shares_per_minute: f64,
    /// Cadence of the vardiff check loop in milliseconds. Typical
    /// 60 000. Drives the connection's vardiff tick for every channel.
    pub vardiff_interval_ms: u64,
    /// Whether vardiff may use elapsed silence as evidence and walk a
    /// quiet channel's difficulty down. Off by default.
    pub vardiff_silence_easing: bool,
}

impl<C: Clock + Clone> MiningSessionState<C> {
    pub fn new(clock: C, session_id: u32, port: PortConfig) -> Self {
        Self {
            session_id,
            network: port.network,
            address: None,
            worker_name: String::new(),
            vendor: String::new(),
            stream: StreamKind::Pplns,
            setup_complete: false,
            used_version: 0,
            version_rolling: false,
            work_selection: false,
            requires_standard_jobs: false,
            is_tdp_client: false,
            negotiated_extensions: Vec::new(),
            // Start at the configured initial difficulty, raised to the
            // floor if the operator set initial < min. Vardiff retargets
            // from here and is bound by `min_difficulty`.
            session_difficulty: Difficulty(
                port.initial_difficulty
                    .as_f64()
                    .max(port.min_difficulty.as_f64()),
            ),
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
            vardiff_silence_easing: port.vardiff_silence_easing,
            last_difficulty_check_ms: 0,
            share_logs: false,
        }
    }

    /// Whether the post-share inline vardiff check may run again.
    ///
    /// SV1 has always gated its inline check this way
    /// (`bp-stratum-v1::server`); SV2 did not, so every accepted share
    /// re-swept EVERY channel's engine on the connection — a 30-sample sum
    /// per channel, on the share hot path, at whatever rate the miner
    /// submits. The timer arm is deliberately NOT gated: it is the only
    /// trigger that fires when no shares arrive.
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

    /// A fresh classic vardiff engine for a newly opened channel, seeded
    /// from the connection's configured target shares/min and difficulty
    /// floor, plus the difficulty the channel is actually opening at — the
    /// engine needs the latter to reason about a channel that has not yet
    /// produced a share, since that difficulty is the only thing its
    /// silence can be measured against.
    fn new_channel_vardiff(&self, assigned_difficulty: Difficulty) -> VarDiffEngine<C> {
        VarDiffEngine::new(
            self.clock.clone(),
            self.target_shares_per_minute,
            self.min_difficulty.as_f64(),
        )
        .with_silence_easing(self.vardiff_silence_easing)
        .with_initial_difficulty(assigned_difficulty.as_f64())
    }
}

// ── Handler: SetupConnection ────────────────────────────────────────

/// Handle `SetupConnection`. Implementation:
///
/// - Mismatched protocol version → `SetupConnectionError`
/// - Mismatched sub-protocol (we accept Mining only for now) →
///   `SetupConnectionError`
/// - Else → `SetupConnectionSuccess` whose `flags` are the SERVER
///   capability bits (SV2 §5.3.2), built fresh — NOT an echo of the
///   client's request flags (the two bitsets have different meanings).
///
/// SV2 spec returns `SetupConnectionError.flags` as the bitset of
/// flags we DON'T accept — for `protocol-version-mismatch` it's 0;
/// for unsupported flags it's the offending bits.
pub fn handle_setup_connection<C: Clock>(
    state: &mut MiningSessionState<C>,
    input: &SetupConnectionInput,
) -> HandlerOutcome {
    // Version range intersection check.
    if input.min_version > MAX_PROTOCOL_VERSION || input.max_version < MIN_PROTOCOL_VERSION {
        return HandlerOutcome::with_frame(OutboundFrame::SetupConnectionError {
            flags: 0,
            error_code: ERR_PROTOCOL_VERSION_MISMATCH.to_string(),
        });
    }

    // Sub-protocol gate. We accept Mining (0) and TDP-only (2). TDP
    // sessions don't open mining channels — they just want to drive
    // the Template-Distribution sub-protocol over the same Noise
    // pipe. `apply_template_broadcast` and the open-channel handlers
    // short-circuit when `is_tdp_client` is set. The IO-layer routes
    // protocol=2 wire frames to the TDP-specific dispatcher.
    match input.protocol {
        PROTOCOL_MINING => {}
        PROTOCOL_TEMPLATE_DISTRIBUTION => {
            state.is_tdp_client = true;
        }
        _ => {
            return HandlerOutcome::with_frame(OutboundFrame::SetupConnectionError {
                flags: 0,
                error_code: ERR_UNSUPPORTED_PROTOCOL.to_string(),
            });
        }
    }

    let used_version = input.max_version.min(MAX_PROTOCOL_VERSION);
    state.setup_complete = true;
    state.used_version = used_version;
    state.vendor = input.vendor.clone();
    state.requires_standard_jobs = (input.flags & FLAG_REQUIRES_STANDARD_JOBS) != 0;
    state.work_selection = (input.flags & FLAG_REQUIRES_WORK_SELECTION) != 0;
    state.version_rolling = (input.flags & FLAG_REQUIRES_VERSION_ROLLING) != 0;

    // Build `Success.flags` fresh — NEVER echo `input.flags`. The success
    // bitset (SV2 §5.3.2) is a distinct server-capability field: bit 0 is
    // REQUIRES_FIXED_VERSION, bit 1 is REQUIRES_EXTENDED_CHANNELS. Echoing the
    // request would map the client's REQUIRES_STANDARD_JOBS (bit 0) onto
    // REQUIRES_FIXED_VERSION and REQUIRES_WORK_SELECTION (bit 1) onto
    // REQUIRES_EXTENDED_CHANNELS. The spec forbids REQUIRES_FIXED_VERSION when
    // the client asked for version rolling, so an echo can tell a version-
    // rolling proxy it may not roll — a contradiction that makes strict
    // clients drop the connection right after setup/first job.
    //
    // We impose no fixed version (we serve version-rollable jobs) and we DO
    // accept standard channels, so both bits are 0 by default. A work-selection
    // (custom-job) connection can only carry its custom jobs on an Extended
    // channel, so we advertise REQUIRES_EXTENDED_CHANNELS for it.
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

/// Handle `RequestExtensions` (ext 0x0001 §4.1, msg_type 0x00 on
/// extension_type 0x0001). Negotiates which SV2 extensions the
/// connection has enabled.
///
/// Semantics:
///
/// - **Pre-setup**: spec ext 0x0001 §4.2 says `RequestExtensions`
///   MUST arrive after `SetupConnection.Success`. We **silently
///   drop** stray pre-setup requests (returning a `HandlerOutcome`
///   with no frames + no events) rather than answering — answering
///   would let a client skip the SetupConnection handshake. Do
///   the same.
/// - **All requested supported** → `Success` with the supported
///   list. State's `negotiated_extensions` adds every entry.
/// - **Mixed**: produce `Success` with the supported subset;
///   unsupported entries are silently ignored. Only error if the
///   supported intersection is empty.
/// - **All requested unsupported + non-empty request** → `Error`
///   with the unsupported list. `required_extensions` is empty (we
///   don't enforce server-side requirements).
/// - **Empty request** → `Success` with empty supported list. Not
///   strictly useful but the wire is well-defined.
///
/// Mining-side supports `0x0002` (Worker-ID TLV) only — see
/// [`SUPPORTED_MINING_EXTENSIONS`]. `0x0003` (Non-Custodial Pool
/// Payouts) belongs to JDP and is rejected here.
pub fn handle_request_extensions<C: Clock>(
    state: &mut MiningSessionState<C>,
    input: &RequestExtensions,
) -> HandlerOutcome {
    if !state.setup_complete {
        // Silent drop — no setup yet, silently ignore the request.
        // The I/O layer can log if it wants.
        return HandlerOutcome::default();
    }

    let mut supported = Vec::new();
    let mut unsupported = Vec::new();
    for &ext in &input.requested_extensions {
        if is_mining_extension_supported(ext) {
            supported.push(ext);
            // Dedup on insert — a re-negotiation of an already-active
            // extension must not grow the list.
            if !state.negotiated_extensions.contains(&ext) {
                state.negotiated_extensions.push(ext);
            }
        } else {
            unsupported.push(ext);
        }
    }

    // Only error when supported list is empty AND requested list was
    // non-empty. An empty requested list still produces Success
    // (with empty supported_extensions).
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

/// Handle `OpenStandardMiningChannel`. The `extranonce_prefix` is
/// allocated by the IO layer (via the global
/// `ExtranonceAllocator`) and passed in; the handler doesn't own the
/// allocator because allocations are pool-global, not session-local.
///
/// Flow:
/// 1. Parse `user_identity` into `(address, worker)`. Normalize address.
/// 2. If first channel: pin the address; else verify match.
/// 3. Compute initial difficulty from `nominal_hash_rate` (≈ network
///    rule of thumb), clamp against per-port `min_difficulty`, clamp
///    against the miner's declared `max_target`, sanity-cap to avoid
///    f64 overflow.
/// 4. Allocate `channel_id` (per-connection monotonic counter).
/// 5. Insert `ChannelState` (Standard kind, `extranonce_size = 0`).
/// 6. Emit `OpenStandardMiningChannelSuccess` + `ChannelOpened` event.
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
    );
    state.channels.insert(channel_id, channel);
    let engine = state.new_channel_vardiff(ctx.assigned_difficulty);
    state.vardiff.insert(channel_id, engine);
    if state.primary_channel.is_none() {
        state.primary_channel = Some(channel_id);
    }
    state.session_difficulty = ctx.assigned_difficulty;

    // Standard channels are never grouped: every template change must send a
    // per-channel `NewMiningJob` to the channel's own id (a header-only device
    // can't process the group-addressed `NewExtendedMiningJob` a group rides).
    // Group channels are an Extended-only optimisation here.
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

/// Eager SV2 group assignment (spec §5.2.3) for the Extended open handler.
/// A connection without `REQUIRES_STANDARD_JOBS` (and not a TDP-only /
/// work-selection connection) is a proxy that understands extended jobs +
/// group channels, so its Extended channels are grouped by full extranonce
/// size; the broadcast then emits ONE `NewExtendedMiningJob` per group
/// instead of one per member. Standard channels are never grouped.
///
/// Returns the assigned `group_channel_id`, or `0` when the connection must
/// not be grouped. The id is drawn from the session's channel-id namespace
/// (so it can never collide with a `channel_id` — spec §5.2.3 line 185) and
/// is communicated implicitly via the OpenChannel.Success message; we never
/// emit `SetGroupChannel`.
fn assign_channel_to_group<C: Clock>(
    state: &mut MiningSessionState<C>,
    channel_id: u32,
    full_extranonce_size: usize,
) -> u32 {
    if state.requires_standard_jobs || state.is_tdp_client || state.work_selection {
        return 0;
    }
    let gid = match state.groups.group_for_size(full_extranonce_size) {
        Some(gid) => gid,
        None => {
            let gid = state.next_channel_id;
            state.next_channel_id = state.next_channel_id.saturating_add(1);
            state.groups.create(gid, full_extranonce_size);
            gid
        }
    };
    // Matches by construction (looked up / created for `full_extranonce_size`).
    let _ = state
        .groups
        .add_channel(gid, channel_id, full_extranonce_size);
    gid
}

// ── Handler: OpenExtendedMiningChannel ──────────────────────────────

/// Handle `OpenExtendedMiningChannel`. Same flow as Standard plus:
///
/// - The miner-rollable extranonce region **exactly honors** the requested
///   `min_extranonce_size` (SV2 §5.3.2: the granted size must be at least the
///   requested minimum). We grant up to [`MAX_EXTENDED_ROLLABLE`] bytes so an
///   aggregating proxy has room to subdivide the space; a request larger than
///   that (or larger than the SV2 32-byte total-extranonce cap allows after
///   the pool prefix) is REJECTED with [`ERR_MIN_EXTRANONCE_SIZE_TOO_LARGE`]
///   rather than silently under-granted — silently handing back fewer bytes
///   than requested makes an aggregating proxy tear down the upstream.
/// - `extranonce_size = 0` in Standard is replaced by this rollable size for
///   Extended.
pub fn handle_open_extended_mining_channel<C: Clock + Clone>(
    state: &mut MiningSessionState<C>,
    input: &OpenExtendedMiningChannelInput,
    extranonce_prefix: Vec<u8>,
) -> HandlerOutcome {
    let prefix_len = extranonce_prefix.len();
    // Cap the rollable region at MAX_EXTENDED_ROLLABLE, further bounded so the
    // total extranonce (prefix + rollable) never exceeds the SV2 32-byte cap.
    let rollable_cap = MAX_EXTENDED_ROLLABLE.min(32usize.saturating_sub(prefix_len));
    let requested = input.min_extranonce_size as usize;
    if requested > rollable_cap {
        return HandlerOutcome::with_frame(OutboundFrame::OpenMiningChannelError {
            request_id: input.request_id,
            error_code: ERR_MIN_EXTRANONCE_SIZE_TOO_LARGE.to_string(),
        });
    }
    // Grant exactly the requested minimum. SV2 §5.3.2 only constrains the
    // granted size to be >= the requested minimum; the server picks the value.
    // Honoring the request (rather than always granting the cap) keeps the
    // granted size byte-identical to what every direct miner already receives
    // — e.g. Axe-class firmware requests a small size and mines with exactly
    // what the pool grants — so this only changes behaviour for aggregating
    // proxies that need more than the old cap. It also never over-grants, so it
    // can't misfeed firmware that assumes a fixed rollable width. An
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
    );
    state.channels.insert(channel_id, channel);
    let engine = state.new_channel_vardiff(ctx.assigned_difficulty);
    state.vardiff.insert(channel_id, engine);
    if state.primary_channel.is_none() {
        state.primary_channel = Some(channel_id);
    }
    state.session_difficulty = ctx.assigned_difficulty;

    // Eager group assignment (SV2 §5.2.3): an Extended channel on a
    // non-`REQUIRES_STANDARD_JOBS` proxy connection is grouped by its full
    // extranonce size (`prefix.len() + rollable`) so the broadcast sends ONE
    // `NewExtendedMiningJob` per group. See [`assign_channel_to_group`].
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

/// Floor a hashrate-derived worker difficulty to a whole integer.
///
/// `hash_rate_to_difficulty` yields fractional values (e.g. `931.31`).
/// SV2-native miners take the 32-byte target verbatim, but SV1 rigs
/// behind the translator receive `mining.set_difficulty(931.31)`,
/// truncate the decimal to `931`, and then submit shares that meet
/// integer diff `931` but not the fractional target `931.31` — which
/// the pool rejects as difficulty-too-low. Flooring here makes the
/// stored `session_difficulty` (used for share validation) and the
/// target bytes on the wire agree on an integer the miner can hit.
///
/// Floor (not round-to-nearest) is deliberate: it never makes the
/// target harder than the hashrate estimate, so a miner that meets the
/// integer diff exactly always passes. Result is bounded below by
/// `1.0` so a sub-1 computed diff can't round down to `0`.
///
/// This touches only the worker/share difficulty, which is a
/// pool-internal share-accounting threshold fully decoupled from block
/// validity (the block-candidate gate compares against the network
/// target, not this value) — so flooring can never affect found blocks.
/// Non-finite / non-positive inputs are returned unchanged for the
/// caller's existing min/ceiling guards to handle.
/// Round a difficulty we are about to ASSIGN to a downstream to a power of two.
///
/// Nothing in SV2 asks for this, and a miner handles a crooked target fine — the
/// firmware filters in software against the exact value it was given. A
/// translating proxy does not. The SRI translator rounds our target UP to a
/// power of two when it lowers it into an SV1 `mining.set_difficulty`
/// (`build_sv1_set_difficulty_from_sv2_target_with_integer_power_of_two_rounding`),
/// so the miner then works against a HIGHER difficulty than the one we keep
/// booking its shares at. Measured on a live pair: we assigned 2887, the miner
/// was given 4096, and 29.5 % of its work was never credited. The size of the
/// loss is just the distance to the next power of two — up to nearly half.
///
/// Assigning a power of two leaves such a proxy nothing to round, so both sides
/// account for the same number.
///
/// **Always UP, never to the nearest rung.** Rounding to the nearest goes down
/// as often as up, and a downstream that requested a difficulty via
/// `UpdateChannel` rejects a lower one as a protocol error: the translator logs
/// "SetTarget response has target which is higher than requested target …
/// Ignoring this pending update" and the miner keeps its previous difficulty
/// while we book against the new one. Rounding down therefore does not merely
/// mis-size the target, it throws the assignment away — measured, and worse than
/// the under-counting this function exists to fix. Rounding up is always
/// accepted and costs at most a factor of two in share rate.
fn power_of_two_difficulty(diff: Difficulty) -> Difficulty {
    let v = diff.as_f64();
    if !v.is_finite() || v < 1.0 {
        // Leave a deliberately sub-1 configured difficulty alone.
        return diff;
    }
    let lower = 2_f64.powf(v.log2().floor());
    // The tolerance matters: a value that is a power of two apart from
    // floating-point dust must stay on its rung rather than double.
    if v <= lower * (1.0 + 1e-9) {
        Difficulty(lower)
    } else {
        Difficulty(lower * 2.0)
    }
}

/// Captured context the kind-specific closure needs.
struct OpenContext {
    address: AddressId,
    worker: String,
    assigned_difficulty: Difficulty,
}

/// Pre-processing common to Standard + Extended: parse user_identity,
/// normalize address, multi-channel address-lock check, initial
/// difficulty math + clamp + floor + ceiling. On error returns
/// `Err(OpenMiningChannelError frame)`. On success returns
/// `Ok(OpenContext)` with the resolved values for the caller to
/// finalize channel insertion.
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

    // Parse `user_identity` → (address, worker). Format is
    // `address.worker_name` (single dot split). Multiple dots: worker_name
    // keeps the rest (split only on first dot).
    let (address_part, worker_part) = match user_identity.find('.') {
        Some(idx) => (&user_identity[..idx], &user_identity[idx + 1..]),
        None => (user_identity, ""),
    };
    if address_part.is_empty() {
        return Err(err(ERR_UNKNOWN_USER));
    }

    // `normalize_btc_address` is a whitespace/casing-only normalizer.
    // We then call `address_to_script` to actually verify the address
    // parses and matches the configured network.
    let normalized = normalize_btc_address(address_part);
    if normalized.is_empty() {
        return Err(err(ERR_UNKNOWN_USER));
    }
    address_to_script(state.network, &normalized).map_err(|_| err(ERR_UNKNOWN_USER))?;
    let address = AddressId::new(normalized).map_err(|_| err(ERR_UNKNOWN_USER))?;

    // Multi-channel address-lock check: subsequent channels MUST resolve
    // to the same address as the first one ("address-locked").
    if let Some(existing) = &state.address {
        if existing != &address {
            return Err(err(ERR_ADDRESS_LOCKED));
        }
    }

    let worker = if worker_part.is_empty() {
        "default".to_string()
    } else {
        worker_part.to_string()
    };

    // Initial difficulty. A positive `nominal_hash_rate` is the miner
    // telling us what it can do, and the difficulty derived from it is
    // therefore what it is asking to be given — the SV2 counterpart of
    // SV1 `mining.suggest_difficulty`, which this pool has always honoured
    // with no operator-side floor at all. Honour it the same way, bounded
    // only by `min_difficulty`.
    //
    // The configured start difficulty is chosen for the devices a port
    // expects, so flooring a declaration at it discarded every declaration
    // below that value — which is most of them: a 1 TH/s device derives
    // ~930 against a 2500 start and was pinned ~4× above its own rate until
    // vardiff walked it back. `handle_update_channel` already bounds a
    // declaration at `min_difficulty` only; channel-open was the outlier.
    //
    // `nominal_hash_rate <= 0` declares nothing, so the configured start
    // remains the only signal and still applies.
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
    // Clamp against the miner's declared max_target (raises the floor to
    // the miner's minimum acceptable difficulty if it declared one).
    let clamped = clamp_difficulty_to_max_target(floored, &Target::from_le_bytes(max_target_bytes));
    let assigned_difficulty = if clamped.as_f64() > MAX_REASONABLE_DIFFICULTY {
        return Err(err(ERR_MAX_TARGET_OUT_OF_RANGE));
    } else {
        // Power of two, so a translating proxy has nothing to round on the way
        // to the miner and both sides account for the same number.
        power_of_two_difficulty(clamped)
    };

    // Address-lock first time → store. The caller's ChannelOpened
    // event will carry the resolved address + worker.
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

/// Vardiff grace: the difficulty a submitted share is validated against
/// is the LOWER of the job's frozen send-time difficulty and the
/// channel's current target. Validating against the frozen per-job diff
/// alone graces a vardiff RAISE (a lagging miner's old-diff shares still
/// meet the lower frozen value), but a vardiff LOWER leaves the job
/// frozen ABOVE the miner's new (lower) target — its legitimate shares
/// would be rejected difficulty-too-low. Taking the minimum graces both
/// directions, so no share in flight across a difficulty change is lost.
/// The share is still CREDITED at its actual achieved difficulty, so
/// PPLNS weighting and block-candidacy are unaffected.
fn graced_validation_difficulty(job_frozen: Difficulty, session: Difficulty) -> Difficulty {
    Difficulty(job_frozen.as_f64().min(session.as_f64()))
}

/// Stamp the channel's vardiff liveness heartbeat for a submission that
/// arrived on `channel_id`, whatever its outcome. Both submit handlers call
/// this ONCE at the top, before any early-return reject (unknown/aged-out
/// job after a core restart, wrong channel kind) — so a reject burst from a
/// hashing miner is never misread as silence and eased down. The single
/// choke point for the "rejected shares count as alive" rule; a new submit
/// path that forgets it is the one way silence easing could regress.
/// No-op for an unknown channel (no engine) or when easing is off.
fn stamp_submission_heartbeat<C: Clock>(state: &mut MiningSessionState<C>, channel_id: u32) {
    if let Some(engine) = state.vardiff.get_mut(&channel_id) {
        engine.note_submission();
    }
}

/// Handle `SubmitSharesStandard`. Resolves the channel + per-job
/// context (stored merkle root + difficulty + template snapshot) and
/// delegates to [`validate_submit_standard`]. Emits
/// `SubmitSharesSuccess` / `SubmitSharesError` on the wire +
/// `ShareAccepted` / `ShareRejected` for the hooks layer.
///
/// SV2 §5.3.14 strict: validation runs against the
/// [`StandardTemplateSnapshot`] stored on the `StandardJobEntry` at
/// **send-time**, not the current template. This guarantees that
/// in-flight shares for retired-but-still-credited jobs hash against
/// the prev_hash / n_bits / version the miner actually mined under.
pub fn handle_submit_shares_standard<C: Clock>(
    state: &mut MiningSessionState<C>,
    submission: &SubmitSharesStandardInput,
    now_ms: u64,
) -> HandlerOutcome {
    // Liveness heartbeat before any early-return reject — see
    // `stamp_submission_heartbeat`.
    stamp_submission_heartbeat(state, submission.channel_id);
    let Some(channel) = state.channels.get_mut(&submission.channel_id) else {
        return submit_error(
            submission.channel_id,
            submission.sequence_number,
            ERR_INVALID_CHANNEL_ID,
        );
    };
    if channel.kind != ChannelKind::Standard {
        return submit_error(
            submission.channel_id,
            submission.sequence_number,
            "invalid-job-id",
        );
    }

    // SV2 §5.3.14 retire-not-clear: classify first so retired-but-
    // known jobs emit `stale-share`, not `invalid-job-id`. A `None`
    // return means the entry is genuinely missing (never sent or
    // aged past retention) — that's the real `invalid-job-id` case.
    let Some(classification) = channel.standard_jobs.classify(submission.job_id, now_ms) else {
        let reject = ShareReject::from(RejectReason::InvalidJobId);
        return submit_error_with_event(submission.channel_id, submission.sequence_number, reject);
    };

    // Safe to unwrap: classify returned Some, so the entry exists.
    // Clone the entry — `StandardJobEntry` no longer derives `Copy`
    // (`coinbase_stratum: Vec<u8>` forces heap storage). The clone
    // is cheap (single heap-vec move) and lets the validator borrow
    // the channel mutably without lifetime conflicts.
    let entry = channel
        .standard_jobs
        .entry_of(submission.job_id)
        .cloned()
        .expect("classify Some => entry_of Some");

    let job_ctx = StandardJobContext {
        template_version: entry.template_snapshot.version as i32,
        prev_hash: entry.template_snapshot.prev_hash,
        n_bits: entry.template_snapshot.n_bits,
        network_difficulty: entry.template_snapshot.network_difficulty,
        classification,
        payouts_fingerprint: entry.payouts_fingerprint,
        template_id: entry.template_id,
        coinbase_stratum: &entry.coinbase_stratum,
        coinbase_tx_value_remaining: entry.template_snapshot.coinbase_tx_value_remaining,
    };

    let graced = graced_validation_difficulty(entry.difficulty, channel.session_difficulty);
    let validation =
        validate_submit_standard(channel, submission, graced, &entry.merkle_root, &job_ctx);
    // Feed classic vardiff with EVERY accepted share (same as the Extended
    // path) so its submission cache fills and `suggested_difficulty` tracks
    // the real rate. The previous `is_current = effective == session` gate
    // went false after every vardiff change (Standard jobs are frozen at
    // their send-time difficulty, which diverges from the live session
    // target the moment vardiff moves), starving the sample cache — vardiff
    // then fell into its under-sampled fallback and drifted the difficulty
    // toward the floor. Extended never hit this because it always fed `true`.
    // Rejects stamped the liveness heartbeat at the top of the handler,
    // before the reason was known. Now that it IS known, a reject that
    // still cleared the assigned target also spends the no-share descent's
    // evidence — but `DifficultyTooLow` must not, because that reject IS
    // the over-assignment the descent has to correct, and letting it reset
    // the accumulator would pin the difficulty exactly where the miner
    // cannot reach it.
    match validation {
        ShareValidation::Accepted(ref accept) => {
            if let Some(engine) = state.vardiff.get_mut(&submission.channel_id) {
                // `update_hash_rate` folds in the target-reached reset —
                // it already holds the clock read.
                engine.update_hash_rate(accept.effective_difficulty.as_f64(), true);
            }
        }
        ShareValidation::Rejected(reject)
            if !matches!(reject.reason, RejectReason::DifficultyTooLow) =>
        {
            if let Some(engine) = state.vardiff.get_mut(&submission.channel_id) {
                engine.note_target_reached();
            }
        }
        ShareValidation::Rejected(_) => {}
    }
    let channel = state
        .channels
        .get_mut(&submission.channel_id)
        .expect("channel existed above");
    finalize_submit(
        channel,
        submission.channel_id,
        submission.sequence_number,
        validation,
    )
}

/// Re-export from [`crate::mining::jobs::StandardTemplateSnapshot`]
/// for callers + tests that built the snapshot under the old name.
pub use crate::mining::jobs::StandardTemplateSnapshot;

// ── Handler: SubmitSharesExtended ───────────────────────────────────

/// Handle `SubmitSharesExtended`. Resolves the channel, extended-job
/// and per-job difficulty (per-job if available, otherwise channel
/// session difficulty) and delegates to
/// [`validate_submit_extended`]. The `network_difficulty` argument and
/// the `now_ms` clock-read are caller-provided so the handler stays
/// pure.
pub fn handle_submit_shares_extended<C: Clock>(
    state: &mut MiningSessionState<C>,
    submission: &SubmitSharesExtendedInput,
    now_ms: u64,
) -> HandlerOutcome {
    let ext_0x0002_negotiated = state
        .negotiated_extensions
        .contains(&crate::extensions::SV2_EXTENSION_TYPE_WORKER_ID);
    let share_logs = state.share_logs;
    // Liveness heartbeat before any early-return reject — see
    // `stamp_submission_heartbeat`.
    stamp_submission_heartbeat(state, submission.channel_id);
    let Some(channel) = state.channels.get_mut(&submission.channel_id) else {
        return submit_error(
            submission.channel_id,
            submission.sequence_number,
            ERR_INVALID_CHANNEL_ID,
        );
    };
    if channel.kind != ChannelKind::Extended {
        return submit_error(
            submission.channel_id,
            submission.sequence_number,
            "invalid-job-id",
        );
    }

    // SV2 §5.3.14: per-job difficulty stored on ExtendedJob at send
    // time. Read it out by value (it's `Copy`) so the channel borrow is
    // released before computing the target memo below.
    let Some(frozen_difficulty) = channel
        .extended_jobs
        .get(&submission.job_id)
        .map(|j| j.difficulty)
    else {
        let reject = ShareReject::from(RejectReason::InvalidJobId);
        return submit_error_with_event(submission.channel_id, submission.sequence_number, reject);
    };
    // Vardiff grace (see `graced_validation_difficulty`): accept shares in
    // flight across a difficulty change in EITHER direction.
    let job_difficulty =
        graced_validation_difficulty(frozen_difficulty, channel.session_difficulty);
    // Compute the target memo first, while no field of `channel` is
    // borrowed (`target_for` takes `&mut self`); it returns a `Copy`
    // `Target`, so the borrow ends here. Afterwards we hand the validator
    // disjoint borrows: `&mut channel.submission_cache` for the dedup
    // write alongside a `&` borrow of the `ExtendedJob` that lives in
    // `channel.extended_jobs` — which a whole-`&mut channel` signature
    // could not express, forcing the old per-share job clone.
    let job_target = channel.target_for(job_difficulty);
    let view = ExtendedChannelView {
        kind: channel.kind,
        extranonce_prefix: &channel.extranonce_prefix,
        extranonce_size: channel.extranonce_size,
        job_target,
    };
    let ext_job = channel
        .extended_jobs
        .get(&submission.job_id)
        .expect("ext_job presence checked above");

    let validation = validate_submit_extended(
        &mut channel.submission_cache,
        &view,
        submission,
        ext_job,
        job_difficulty,
        now_ms,
        ext_0x0002_negotiated,
        share_logs,
    );
    // Feed classic vardiff with the accepted share so its submission
    // cache fills + `suggested_difficulty` can produce real retargets.
    // Drop the channel borrow first because state.vardiff is a sibling
    // field; re-borrow the channel below for finalize. Rejects stamped the
    // liveness heartbeat at the top of the handler; the target-reached
    // split below is the Standard path's rationale verbatim — a
    // `DifficultyTooLow` reject must not spend the no-share evidence.
    match validation {
        ShareValidation::Accepted(ref accept) => {
            if let Some(engine) = state.vardiff.get_mut(&submission.channel_id) {
                // `update_hash_rate` folds in the target-reached reset —
                // it already holds the clock read.
                engine.update_hash_rate(accept.effective_difficulty.as_f64(), true);
            }
        }
        ShareValidation::Rejected(reject)
            if !matches!(reject.reason, RejectReason::DifficultyTooLow) =>
        {
            if let Some(engine) = state.vardiff.get_mut(&submission.channel_id) {
                engine.note_target_reached();
            }
        }
        ShareValidation::Rejected(_) => {}
    }
    let channel = state
        .channels
        .get_mut(&submission.channel_id)
        .expect("channel existed above");
    finalize_submit(
        channel,
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
    channel: &mut ChannelState,
    channel_id: u32,
    sequence_number: u32,
    validation: ShareValidation,
) -> HandlerOutcome {
    match validation {
        ShareValidation::Accepted(accept) => {
            channel.record_accepted_share(accept.effective_difficulty);
            HandlerOutcome {
                outbound: vec![OutboundFrame::SubmitSharesSuccess {
                    channel_id,
                    last_sequence_number: sequence_number,
                    new_submits_accepted_count: 1,
                    new_shares_sum: accept.effective_difficulty.as_f64() as u64,
                }],
                events: vec![SessionEvent::ShareAccepted { channel_id, accept }],
            }
        }
        ShareValidation::Rejected(reject) => {
            submit_error_with_event(channel_id, sequence_number, reject)
        }
    }
}

// ── Handler: UpdateChannel ──────────────────────────────────────────

/// Handle `UpdateChannel`. SV2 spec: miner can request a new target
/// (lower difficulty means more shares) or report a new
/// `nominal_hash_rate` and `maximum_target`. Pool recomputes
/// difficulty, clamps, sends a fresh `SetTarget` if it changed. SV2
/// spec doesn't define a wire response for the success case — silence
/// is success. We do emit `UpdateChannelError` for unknown channel ids.
pub fn handle_update_channel<C: Clock>(
    state: &mut MiningSessionState<C>,
    input: &UpdateChannelInput,
) -> HandlerOutcome {
    let target_shares_per_minute = state.target_shares_per_minute;
    let min_difficulty = state.min_difficulty;
    let silence_easing = state.vardiff_silence_easing;

    // What the accumulated silence rules out, if anything. `None` unless
    // this channel has genuinely been quiet at a known difficulty for long
    // enough to say something — which a freshly opened proxy channel has
    // NOT, so its first real declaration passes untouched.
    let silence_ceiling = if silence_easing {
        state
            .vardiff
            .get(&input.channel_id)
            .and_then(|e| e.silence_implied_max_difficulty())
    } else {
        None
    };

    let Some(channel) = state.channels.get_mut(&input.channel_id) else {
        return HandlerOutcome::with_frame(OutboundFrame::UpdateChannelError {
            channel_id: input.channel_id,
            error_code: ERR_INVALID_CHANNEL_ID.to_string(),
        });
    };

    channel.declared_max_target = input.maximum_target;

    // Is this news, or the same claim on a timer? A translator re-sends
    // `UpdateChannel` unprompted every 60 s; a proxy whose workers just
    // attached sends a DIFFERENT number. Silence is evidence about what
    // this channel did in the past and cannot refute a statement about
    // what it is now — only the re-assertion of a claim we have already
    // outlived stays subject to it.
    let repeated_claim = channel.last_declared_hash_rate == Some(input.nominal_hash_rate);
    channel.last_declared_hash_rate = Some(input.nominal_hash_rate);

    let mut raw = hash_rate_to_difficulty(input.nominal_hash_rate as f64, target_shares_per_minute);
    if let Some(ceiling) = silence_ceiling.filter(|_| repeated_claim) {
        if raw.as_f64() > ceiling {
            // The declaration contradicts what we have observed: this
            // channel has been quiet long enough at a known difficulty that
            // the claimed rate is ruled out. A translator re-sends
            // `UpdateChannel` every 60 s, so without this it would overwrite
            // the descent once a minute and a miner behind a proxy would
            // never be rescued.
            //
            // Two conditions, and both are needed. Keyed on "no share yet"
            // alone it fired on the normal state of a proxy that had only
            // just gained workers. Keyed on the silence alone it still
            // fired ~60 s after channel open, because by then the quiet IS
            // statistically loud — and a proxy whose rigs take a minute to
            // attach would have had its first honest declaration capped.
            //
            // Sits before `clamp_difficulty_to_max_target` so the §5.3.7
            // MUST on `maximum_target` still wins, with the power-of-two
            // rounding still last. The ceiling is itself a floored,
            // rounding-safe value.
            raw = Difficulty(ceiling);
        }
    }
    let clamped = clamp_difficulty_to_max_target(raw, &Target::from_le_bytes(input.maximum_target));
    let new_diff = if clamped.as_f64() > MAX_REASONABLE_DIFFICULTY {
        // Keep the existing difficulty rather than accepting an
        // unreasonable value. Miner can retry with a larger max_target.
        return HandlerOutcome::default();
    } else {
        // Power of two — same rationale as the channel-open path. This is the
        // path that mattered in practice: a translator sends `UpdateChannel`
        // every 60 s, so it kept overwriting whatever the vardiff had rounded.
        //
        // The configured floor goes through the same rounding: an operator who
        // sets a crooked `min_difficulty` would otherwise hand a translating
        // proxy something to round up, which is the whole failure this rounding
        // exists to prevent. Rounding up can only raise it further above the
        // floor, so the floor still holds.
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

/// Handle `CloseChannel`. Removes the channel from the session map +
/// rotates `primary_channel` if it was the primary. SV2 spec §5.3.9:
/// the connection survives an empty channel set — we do NOT close
/// the socket here.
///
/// **Group close (spec §5.3.9 line 318):** if `channel_id` addresses a
/// **group** channel, ALL channels belonging to that group MUST be closed.
/// We emit one [`SessionEvent::ChannelClosed`] per removed member so the IO
/// layer releases each member's extranonce prefix (it drives the allocator
/// release off these events).
pub fn handle_close_channel<C: Clock>(
    state: &mut MiningSessionState<C>,
    input: &CloseChannelInput,
) -> HandlerOutcome {
    // Group-channel close: the id addresses a group (group ids never collide
    // with channel ids), so close every member and drop the group.
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
        // Rotate the primary if it was one of the closed members.
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
        // SV2 spec doesn't require a wire response for CloseChannel
        // (it's fire-and-forget from the miner side). We return
        // silently — empty outcome.
        return HandlerOutcome::default();
    }
    state.channels.remove(&input.channel_id);
    state.vardiff.remove(&input.channel_id);
    // Drop the channel from its group (no-op if un-grouped). The group
    // itself persists for the connection's lifetime even when empty —
    // harmless, and a re-opened same-size channel re-joins it.
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

/// Periodic vardiff tick. For each channel, reads that channel's
/// own [`bp_vardiff::VarDiffEngine::suggested_difficulty`] against the
/// channel's current difficulty; if a retarget is recommended it clamps
/// against the channel's `declared_max_target`, updates the channel's
/// difficulty, and emits `SetTarget` + `DifficultyChanged`. Each channel
/// retargets independently from its own share rate — SV2 difficulty is per
/// channel, so several channels on one connection never pool their rate.
///
/// Job-declaration clients are retargeted by this same path. A JDC runs no
/// vardiff of its own on the pool-facing channel — it only ever applies the
/// `SetTarget` we send it — and it pre-filters its downstream miners' shares
/// against exactly the target we assigned, forwarding only the ones that
/// meet it. What arrives here is therefore the same signal a direct miner
/// produces: shares at the difficulty we set, at the rate the aggregate
/// hashrate behind the client implies. The per-miner distribution behind a
/// JDC is invisible to us, but this estimator never needed it.
pub fn apply_vardiff_check<C: Clock>(state: &mut MiningSessionState<C>) -> HandlerOutcome {
    // Disjoint &mut borrows of the two sibling fields so each channel can
    // read+update its own vardiff engine and difficulty in one pass.
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
            // Tell the engine what was actually assigned, not what it
            // suggested: the max_target clamp and the rounding both sit
            // between the two, and a channel with no share yet measures
            // its own silence against this value.
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

/// Pre-resolved inputs for [`apply_template_broadcast`] — owns the
/// caller-side coinbase-template fields + the resolved payout list so
/// the handler can build a fresh [`MiningJob`] per channel with the
/// channel's negotiated extranonce-slot size baked into the scriptsig.
///
/// The IO layer resolves payouts asynchronously (via
/// [`crate::hooks::PayoutResolver`]) once per template, populates this
/// struct, and hands it in by reference. Each Extended channel gets a
/// `MiningJob` sized for its own `extranonce_prefix.len +
/// extranonce_size`, eliminating the previous "build for 12, patch
/// scriptsig_len varint for smaller slots" path.
#[derive(Clone, Debug)]
pub struct MiningJobInputs {
    pub network: Network,
    pub payouts: Vec<PayoutEntry>,
    /// Settlement-snapshot identity of the distribution `payouts` was
    /// derived from (zeroed = books without a snapshot). Carried onto
    /// every job built from these inputs and part of the job-cache key.
    pub payouts_fingerprint: [u8; 32],
    pub pool_identifier: String,
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_tx_version: u32,
    pub coinbase_tx_input_sequence: u32,
    pub coinbase_tx_value_remaining: u64,
    pub coinbase_tx_outputs: Vec<u8>,
    pub coinbase_tx_outputs_count: u32,
    pub coinbase_tx_locktime: u32,
    /// Pool-wide memoization of built jobs, shared across every
    /// connection. `build` is keyed on ALL of the fields above plus the
    /// slot size, so channels with the same payout set + slot share one
    /// `Arc<MiningJob>`; payout sets that differ per finder stay
    /// distinct by construction.
    pub job_cache: Arc<MiningJobCache>,
}

impl MiningJobInputs {
    /// Build (or fetch the memoized) [`MiningJob`] with
    /// `extranonce_slot_size` bytes reserved at the tail of the
    /// scriptsig.
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

/// `(coinbase template, coinbase_tx_prefix, coinbase_tx_suffix, merkle_path)`
/// returned by the group-template builder inside `apply_template_broadcast`.
/// The `ExtendedJob` carries the header fields + a placeholder difficulty;
/// the three byte vectors are the shared coinbase parts for the group job
/// frame.
type GroupTemplateParts = (ExtendedJob, Vec<u8>, Vec<u8>, Vec<[u8; 32]>);

/// Compute `(merkle_root, coinbase_stratum)` for a **Standard** channel's
/// share validation: splice the channel's extranonce prefix (padded/truncated
/// to the 4-byte enonce1) plus 8 non-rollable zero bytes (enonce2 — a Standard
/// channel can't roll the extranonce) into a coinbase whose prefix/suffix were
/// built for the pool-default [`EXTRANONCE_SLOT_LEN`] slot, then walk the
/// merkle path. Equivalent to `MiningJob::coinbase_txid_with_extranonce`, but
/// also returns the assembled non-witness coinbase for the block-found path.
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

/// Fan a [`TemplateBroadcast`] out to all mining channels on this
/// connection.
///
/// Caller pre-resolves payouts and packs the per-template coinbase
/// fields into a [`MiningJobInputs`]; this handler builds a fresh
/// [`MiningJob`] per channel with the channel-specific extranonce-slot
/// size baked into the scriptsig (Standard channels use the pool
/// default [`EXTRANONCE_SLOT_LEN`]; Extended channels use
/// `extranonce_prefix.len() + extranonce_size`). The handler still
/// owns the per-channel work: extranonce splicing, merkle root
/// assembly for Standard, prefix/suffix split for Extended, and the
/// retire-not-clear lifecycle bookkeeping on block change.
///
/// Per-channel decisions:
///
/// - JDC channels are skipped — they build their own jobs via
///   `SetCustomMiningJob`.
/// - TDP-only sessions (protocol=2) receive nothing — they don't open
///   mining channels at all in steady state, but the early-return
///   guards against any leftover state.
/// - On [`TemplateChange::NewBlock`]:
///   - `standard_jobs.retire(now_ms)` + `cleanup_expired(now_ms)`
///     (no clear — retired entries stay queryable until aged out).
///   - `retire_extended_jobs` + `cleanup_retired_extended_jobs` over
///     `extended_jobs`.
///   - `clear_submission_cache()` — the dedup-set keys are scoped to
///     the previous prev_hash and would block legitimate retries
///     against fresh jobs.
///   - Cache the new block context on `latest_extended_*` for any
///     subsequent `Refresh` broadcasts.
///   - Emit a per-channel [`OutboundFrame::SetNewPrevHash`] referring
///     to the upcoming job_id (SetNewPrevHash and the matching
///     `NewMiningJob` / `NewExtendedMiningJob` go out in adjacent frames).
/// - For every channel kind, allocate a fresh `channel.next_job_id`
///   and emit the kind-appropriate frame:
///   - **Standard**: splice the channel's 4-byte
///     [`ChannelState::extranonce_prefix`] + 8 zero bytes into the
///     coinbase slot, compute the txid, walk the template's merkle
///     path to derive the root, store the (difficulty, root) pair via
///     [`crate::mining::jobs::StandardJobMaps::record_send`], and emit
///     [`OutboundFrame::NewMiningJob`].
///   - **Extended**: build a per-channel `coinbase_tx_prefix`
///     (template prefix + channel's pool-side extranonce_prefix) +
///     `coinbase_tx_suffix` (template suffix unchanged), insert an
///     [`ExtendedJob`] into `channel.extended_jobs` so share submit
///     can reconstruct the coinbase, and emit
///     [`OutboundFrame::NewExtendedMiningJob`].
///
/// The handler emits no `SessionEvent` — broadcasts are pool-driven
/// and don't need a hook layer fan-out. Caller can derive any
/// observability it wants from the outbound frame stream.
/// Content signature of a job: everything the miner
/// hashes over — version, prev_hash, n_bits, plus the merkle root
/// (Standard) or merkle path + coinbase prefix/suffix (Extended).
/// Deliberately EXCLUDES `min_ntime`/timestamp so a refresh that only
/// bumps the clock is recognised as byte-identical work. Used to suppress
/// re-issuing identical work under a fresh `job_id`, which freezes strict
/// firmware (BraiinsOS resets its pipeline on every `NewMiningJob`).
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

pub fn apply_template_broadcast<C: Clock>(
    state: &mut MiningSessionState<C>,
    broadcast: &TemplateBroadcast,
    mining_job_inputs: &MiningJobInputs,
    now_ms: u64,
    only_channel: Option<u32>,
) -> HandlerOutcome {
    let mut outcome = HandlerOutcome::default();

    // TDP-only client (protocol=2) doesn't receive mining jobs.
    if state.is_tdp_client {
        return outcome;
    }

    let template = &broadcast.template;
    let is_new_block = matches!(broadcast.change, TemplateChange::NewBlock);
    // Snapshot connection-wide fields before the loop so they don't
    // interleave with the per-channel mutable borrows.
    let version_rolling = state.version_rolling;

    // `only_channel = Some(id)` restricts the fan-out to one channel
    // (used by the OpenChannel post-handler to send the initial job
    // pair to a freshly-opened channel without re-emitting frames to
    // existing channels). `None` is the broadcast case: every channel
    // gets the new template.
    let channel_ids: Vec<u32> = match only_channel {
        Some(id) => vec![id],
        None => state.channels.keys().copied().collect(),
    };

    // Partition into grouped vs un-grouped (SV2 §5.2.3). A grouped channel's
    // work rides ONE `NewExtendedMiningJob` addressed to its
    // `group_channel_id` (emitted once in `broadcast_group_job` below, even
    // when several members appear here); un-grouped channels keep the
    // per-channel path verbatim — zero change for the common single-channel
    // and standard-jobs cases.
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
            channel.standard_jobs.retire(now_ms);
            channel.standard_jobs.cleanup_expired(now_ms);
            retire_extended_jobs(&mut channel.extended_jobs, now_ms);
            cleanup_retired_extended_jobs(&mut channel.extended_jobs, now_ms);
            channel.clear_submission_cache();
            channel.latest_extended_prev_hash = Some(template.prev_hash);
            channel.latest_extended_n_bits = Some(template.n_bits);
            channel.latest_extended_min_ntime = Some(template.header_timestamp);
        }

        let job_id = channel.next_job_id;
        channel.next_job_id = channel.next_job_id.wrapping_add(1);

        // SV2 future-job protocol: on a block change the job is
        // a FUTURE job — sent with an empty `min_ntime` and activated by a
        // `SetNewPrevHash` emitted AFTER it (below). On a same-block refresh
        // the job is active immediately (`Some(header_timestamp)`, no
        // SetNewPrevHash). Strict miners (BraiinsOS) reject a job that
        // carries `min_ntime` while a SetNewPrevHash also references it.
        let wire_min_ntime = if is_new_block {
            None
        } else {
            Some(template.header_timestamp)
        };

        match channel.kind {
            ChannelKind::Standard => {
                // Standard: pool fills the entire 12-byte slot (4-byte
                // extranonce_prefix + 8 zero bytes; miner can't roll on
                // Standard).
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

                // Derive the merkle root + the full non-witness coinbase (the
                // latter for the submit-side block-found path).
                let (merkle_root, coinbase_stratum) = standard_member_root_and_coinbase(
                    mining_job.coinbase_prefix(),
                    mining_job.coinbase_suffix(),
                    &channel.extranonce_prefix,
                    &template.merkle_path,
                );

                // Suppress a same-block refresh that is
                // byte-identical to the last job sent — re-issuing it under a
                // fresh job_id freezes strict firmware (BraiinsOS). A block
                // change (is_new_block) is always sent.
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

                // Snapshot the template context at send-time. SV2
                // §5.3.14 strict: in-flight shares for this job hash
                // against the same prev_hash / n_bits / version
                // regardless of how many blocks have passed before
                // validation.
                let template_snapshot = StandardTemplateSnapshot {
                    version: template.version,
                    prev_hash: template.prev_hash,
                    n_bits: template.n_bits,
                    network_difficulty: template.network_difficulty,
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
                // Extended: build a fresh MiningJob whose scriptsig
                // reserves exactly the channel-negotiated extranonce
                // slot (`extranonce_prefix.len + extranonce_size`).
                // The scriptsig_len varint is correct by construction,
                // matching what standard miners expect on the wire — no
                // post-hoc patching needed.
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

                // SV2 Extended wire-frame convention: the miner
                // reconstructs the coinbase as
                //   coinbase_tx_prefix + channel.extranonce_prefix
                //                      + miner_extranonce
                //                      + coinbase_tx_suffix
                //
                // So coinbase_tx_prefix MUST NOT include
                // channel.extranonce_prefix — the miner appends it
                // itself (it received the bytes in
                // OpenExtendedMiningChannelSuccess.extranonce_prefix
                // and uses them at share-build time). Baking it into
                // the wire-frame prefix causes the miner to
                // double-include extranonce_prefix in the coinbase,
                // producing a totally different hash than our validator
                // computes (manifests as 100% diff-too-low rejections).
                //
                // Validator MUST mirror this split — the
                // reconstruction in `validate_submit_extended` uses
                // ext_job.coinbase_prefix + channel.extranonce_prefix
                // + submission.extranonce + ext_job.coinbase_suffix.
                let tx_prefix = mining_job.coinbase_prefix().to_vec();
                let tx_suffix = mining_job.coinbase_suffix().to_vec();
                let merkle_path = template.merkle_path.clone();

                // Suppress a same-block refresh that is byte-identical to the
                // last job sent — re-issuing it under a fresh job_id freezes
                // strict firmware (BraiinsOS). A block change is always sent.
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

                let ext_job = ExtendedJob {
                    coinbase_prefix: tx_prefix.clone(),
                    coinbase_suffix: tx_suffix.clone(),
                    payouts_fingerprint: *mining_job.payouts_fingerprint(),
                    merkle_path: merkle_path.clone(),
                    version: template.version,
                    prev_hash: template.prev_hash,
                    n_bits: template.n_bits,
                    min_ntime: template.header_timestamp,
                    difficulty: channel.session_difficulty,
                    network_difficulty: template.network_difficulty,
                    coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
                    template_id: Some(template.template_id),
                    created_at: now_ms,
                    retired_at: None,
                };
                channel.extended_jobs.insert(job_id, ext_job);

                outcome.push_frame(OutboundFrame::NewExtendedMiningJob {
                    channel_id,
                    job_id,
                    version: template.version,
                    version_rolling_allowed: version_rolling,
                    merkle_path,
                    coinbase_tx_prefix: tx_prefix,
                    coinbase_tx_suffix: tx_suffix,
                    min_ntime: wire_min_ntime,
                });
            }
        }

        // Activate the future job (sent above) on a block change. Emitted
        // AFTER the job per SV2 §7.4 so the miner already holds the job the
        // `job_id` refers to.
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

    // ── Grouped channels (SV2 §5.2.3) — Extended channels only ──
    // Two modes:
    //   • OPEN (`only_channel = Some(X)`): hand the freshly-opened member X a
    //     per-channel `NewExtendedMiningJob` addressed to its OWN id,
    //     establishing the group's shared job if X is the first member. NEVER
    //     a group-addressed frame — that would disturb the existing members.
    //   • TEMPLATE broadcast (`only_channel = None`): update every member and
    //     emit ONE group-addressed NewExtendedMiningJob to the group id (the
    //     downstream proxy fans it out to its own channels).

    // Build the group's shared coinbase template (coinbase parts + header
    // fields) for `full_size`. The `difficulty` placeholder is overridden per
    // member. `None` if the mining-job build fails.
    let build_group_template = |full_size: usize| -> Option<GroupTemplateParts> {
        let mining_job = mining_job_inputs.build(full_size).ok()?;
        let tx_prefix = mining_job.coinbase_prefix().to_vec();
        let tx_suffix = mining_job.coinbase_suffix().to_vec();
        let merkle_path = template.merkle_path.clone();
        let tmpl = ExtendedJob {
            coinbase_prefix: tx_prefix.clone(),
            coinbase_suffix: tx_suffix.clone(),
            payouts_fingerprint: *mining_job.payouts_fingerprint(),
            merkle_path: merkle_path.clone(),
            version: template.version,
            prev_hash: template.prev_hash,
            n_bits: template.n_bits,
            min_ntime: template.header_timestamp,
            difficulty: Difficulty(0.0),
            network_difficulty: template.network_difficulty,
            coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
            template_id: Some(template.template_id),
            created_at: now_ms,
            retired_at: None,
        };
        Some((tmpl, tx_prefix, tx_suffix, merkle_path))
    };

    for gid in groups_to_process {
        // Snapshot members + slot size + current job (id + coinbase template),
        // then drop the groups borrow before mutating channels / allocating a
        // job id.
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

        // ── OPEN: a single channel just opened. Give it a per-channel job to
        // its OWN id; a single-channel open never emits a group broadcast. ──
        if let Some(new_id) = only_channel {
            if members.contains(&new_id) {
                // Reuse the group's current job, or establish the FIRST one if
                // this is the first member to open.
                let resolved: Option<(u32, ExtendedJob)> =
                    match (current_job_id, current_job_template) {
                        (Some(jid), Some(tmpl)) => Some((jid, tmpl)),
                        _ => match (
                            build_group_template(full_size),
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
                // Grouped members are always Extended (Standard channels are
                // never grouped). Guard defensively, then emit the per-channel
                // job to the new member's OWN id.
                let new_is_extended = matches!(
                    state.channels.get(&new_id).map(|c| c.kind),
                    Some(ChannelKind::Extended)
                );
                if let (Some((jid, tmpl)), true) = (resolved, new_is_extended) {
                    if let Some(ch) = state.channels.get_mut(&new_id) {
                        let mut job = tmpl.clone();
                        job.difficulty = ch.session_difficulty;
                        job.created_at = now_ms;
                        ch.latest_extended_prev_hash = Some(job.prev_hash);
                        ch.latest_extended_n_bits = Some(job.n_bits);
                        ch.latest_extended_min_ntime = Some(job.min_ntime);
                        let (pv, nt, nb, ver) =
                            (job.prev_hash, job.min_ntime, job.n_bits, job.version);
                        let mp = job.merkle_path.clone();
                        let cp = job.coinbase_prefix.clone();
                        let cs = job.coinbase_suffix.clone();
                        ch.extended_jobs.insert(jid, job);
                        // Future job first (empty `min_ntime`), then the
                        // activating SetNewPrevHash — SV2 §7.4.
                        outcome.push_frame(OutboundFrame::NewExtendedMiningJob {
                            channel_id: new_id,
                            job_id: jid,
                            version: ver,
                            version_rolling_allowed: version_rolling,
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
            build_group_template(full_size)
        else {
            tracing::warn!(gid, full_size, "skipping group: mining-job build failed");
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
                channel.standard_jobs.retire(now_ms);
                channel.standard_jobs.cleanup_expired(now_ms);
                retire_extended_jobs(&mut channel.extended_jobs, now_ms);
                cleanup_retired_extended_jobs(&mut channel.extended_jobs, now_ms);
                channel.clear_submission_cache();
                channel.latest_extended_prev_hash = Some(template.prev_hash);
                channel.latest_extended_n_bits = Some(template.n_bits);
                channel.latest_extended_min_ntime = Some(template.header_timestamp);
            }
            // Grouped members are always Extended (Standard channels are never
            // grouped). Store the shared group job under the group job_id so
            // per-member `SubmitSharesExtended` validation keeps working.
            if channel.kind == ChannelKind::Extended {
                let mut ext_job = group_template.clone();
                ext_job.difficulty = channel.session_difficulty;
                channel.extended_jobs.insert(group_job_id, ext_job);
            }
        }

        // Record the template on the group for the onboard path.
        if let Some(g) = state.groups.get_mut(gid) {
            g.set_current_job(group_template);
        }

        // Future job first (empty `min_ntime` on a block change), then the
        // activating SetNewPrevHash — SV2 §7.4. A same-block
        // refresh sends an active job (`Some`) with no SetNewPrevHash.
        outcome.push_frame(OutboundFrame::NewExtendedMiningJob {
            channel_id: gid,
            job_id: group_job_id,
            version: template.version,
            version_rolling_allowed: version_rolling,
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

    outcome
}

// ── handle_set_custom_mining_job ────────────────────────────────────

/// Inputs from a deserialized `SetCustomMiningJob` frame (SV2
/// mining-protocol §5.3.18). The JDC builds the entire coinbase
/// itself (via its own Template Provider) and hands the pool the
/// raw fields to assemble + reference. The pool stores the resulting
/// [`ExtendedJob`] under a fresh channel-local job_id and replies
/// with `Success` so the JDC can submit shares against it.
///
/// `coinbase_prefix` here is **just the scriptSig prefix bytes**
/// (everything inside scriptSig BEFORE the extranonce slot). The
/// handler wraps it with the standard non-witness coinbase header
/// (version + input_count + null_outpoint + scriptSig_len_varint).
///
/// `coinbase_tx_outputs` carries the output_count varint + serialized
/// `TxOut`s as a single blob — the JDC pre-encodes per SV2 spec.
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
    /// The ext 0x0003 §6 `distribution_id` TLV, exactly as it arrived on this
    /// frame — extracted by the IO layer UNCONDITIONALLY, *not* filtered by
    /// the negotiated set.
    ///
    /// That is deliberate and load-bearing: §2 requires a TLV from a
    /// non-negotiated client to be rejected, and a field that were pre-filtered
    /// to `None` would make that gate unreachable and invite its deletion. The
    /// handler owns the check.
    pub distribution_id: Option<u64>,
}

/// Handle `SetCustomMiningJob`.
///
/// **Caller-resolved context**: the IO layer looks up the declared-job
/// entry for `mining_job_token` in [`crate::bridge::JdpDeclaredJobRegistry`]
/// and passes its projection as `bridge_job`
/// ([`crate::bridge::BridgeJobRef`] — address, declared tip, and the
/// declaration's own fields, but not its raw transactions). If `Some`, the
/// handler cross-checks the channel's locked miner address (mismatch →
/// `invalid-job-param-value-token-mismatch`), the tip binding — the custom
/// job MUST build on the tip its declaration was accepted under (drift →
/// `stale-chain-tip`, the retryable stale-race classification) — and the
/// declaration binding of [`crate::jdp::custom_job_binding`].
///
/// **Fail-closed token check**: a token that resolves to neither a bridge
/// entry nor a payout distribution is unknown (never declared here, expired,
/// or evicted with its JDP session) → `invalid-mining-job-token`. This
/// deliberately leaves base-protocol Coinbase-only custom jobs unsupported:
/// without a declared job or a published distribution, a non-custodial pool
/// has nothing to validate the coinbase against, and accepting would let
/// arbitrary self-built jobs feed the share pipeline.
///
/// **ext 0x0003 payout validation**: the IO layer resolves the job's
/// distribution reference — the §6 TLV on this frame (Coinbase-only) or the
/// one the declaration carried (Full-Template, where §6 puts the TLV on
/// `DeclareMiningJob` instead), via
/// [`crate::bridge::effective_distribution_id`] — against the bridge registry
/// and passes the [`DistributionAcceptance`]. The submitted
/// `coinbase_tx_outputs` MUST
/// match the §4 recompute positionally (§7.1), and for a tailored
/// distribution the channel address MUST match its owner (the sole
/// cross-account guard in Coinbase-only mode, where there is no
/// `RegisteredDeclaredJob`). Distributions are multi-use — under
/// positional equality a coinbase cannot pay anything but the published
/// split, so there is nothing to consume.
///
/// - Channel unknown → `SetCustomMiningJobError` with
///   `invalid-channel-id`.
/// - Channel kind ≠ Extended → `invalid-job-id` (Standard channels
///   don't carry an extranonce slot — custom jobs are
///   Extended-only).
/// - Token unknown (no bridge entry AND no distribution reference) →
///   `invalid-mining-job-token`.
/// - Bridge miner-address mismatch →
///   `invalid-job-param-value-token-mismatch`.
/// - Bridge declared-tip mismatch → `stale-chain-tip`.
/// - No distribution reference on the frame AND none on the declaration +
///   non-Solo stream → `custom-jobs-require-solo` (base custom jobs must not
///   feed shared accounting).
/// - Else: rebuild `coinbase_tx_prefix` + `coinbase_tx_suffix` from
///   the JDC's scriptSig fragments, allocate
///   `channel.next_job_id`, insert [`ExtendedJob`] (with
///   `template_id = None` — custom job), emit
///   `SetCustomMiningJobSuccess`.
pub fn handle_set_custom_mining_job<C: Clock>(
    state: &mut MiningSessionState<C>,
    input: &SetCustomMiningJobInput,
    bridge_job: Option<&crate::bridge::BridgeJobRef>,
    distribution: Option<&crate::bridge::DistributionAcceptance>,
    now_ms: u64,
) -> HandlerOutcome {
    // Every rejection path emits the same frame shape — factor it out.
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
    // Read before the borrow ends — the declaration binding below needs it,
    // and the assembly further down uses the same number.
    let full_extranonce_size = channel.full_extranonce_size();

    // Fail-closed token check: the token must resolve to SOMETHING we can
    // validate against — a declared job (Full-Template) or a referenced
    // distribution (ext 0x0003, either mode). Neither → unknown/expired/
    // evicted token; accepting would register an arbitrary self-built
    // job whose shares feed the pipeline with nothing backing the coinbase.
    if bridge_job.is_none() && input.distribution_id.is_none() {
        return reject(ERR_INVALID_MINING_JOB_TOKEN);
    }

    // ext 0x0003 §6 places the `distribution_id` TLV per Job Declaration mode,
    // and only Coinbase-only puts it on THIS message — a conformant
    // Full-Template JDC put it on `DeclareMiningJob`, where the JDP side
    // validated the declared coinbase against it and stored it with the
    // declaration. Reading the frame alone would see `None` for that JDC and
    // classify a fully-backed job as an unbacked self-built one.
    //
    // Inheriting the reference does NOT inherit its acceptance: the resolution
    // still runs against the §7.2/§10 window, so a declaration accepted under
    // a since-superseded or settlement-invalidated distribution is rejected
    // here exactly as a stale TLV would be.
    //
    // Inheritance is deliberately narrow — off Solo, and only where §2 lets
    // this connection use the extension at all. `resolve_distribution_reference`
    // owns both guards, and the IO layer resolved the acceptance above through
    // the same call, so the id validated here is the id that was resolved.
    let distribution_ref = crate::bridge::resolve_distribution_reference(
        input.distribution_id,
        bridge_job,
        state.stream,
        state
            .negotiated_extensions
            .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS),
    )
    .map(|reference| reference.distribution_id());

    // Channel-locked miner address — cross-checked below against the bridge
    // entry and/or the referenced distribution's owner.
    let channel_addr = state.address.as_ref().map(|a| a.as_str()).unwrap_or("");

    // Bridge cross-checks for a declared job.
    if let Some(job) = bridge_job {
        // The miner address MUST match the channel's locked address (stops
        // one miner claiming another's declared job).
        if channel_addr != job.miner_address.as_str() {
            return reject(ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
        }
        // Tip binding: the custom job MUST build on the tip its declaration
        // was accepted under. A mismatch is the stale-tip race (the chain
        // advanced between declare and submit) — classified retryable via
        // `stale-chain-tip`, never as a parameter violation. Unknowable
        // (`None`) when the pool had no tip at accept time.
        if let Some(declared) = job.declared_prev_hash {
            if input.prev_hash != declared {
                return reject(ERR_STALE_CHAIN_TIP);
            }
        }

        // Declaration binding: the job asked for here MUST be the job the
        // token was declared for. NOT a revenue check — how much a JDC's
        // template is worth is its own call. What it carries over is the
        // §6.1 node validation: `jdp_server` had bitcoin-core check the
        // DECLARED job, and nothing on this side re-examines the tx set the
        // `merkle_path` commits to. Without the comparison, "the node
        // approved the declaration" and "this coinbase pays the published
        // distribution" describe two jobs that need not be the same one.
        let Some(binding) = job.binding.as_ref() else {
            // A declaration that will not project. The coinbase half of that
            // is now caught where it belongs — `accept_declaration` refuses a
            // coinbase it cannot rebuild, on every connection, so the JDC
            // learns at declare time instead of being told Success and then
            // rejected on every job forever. What can still land here is the
            // transaction half: a declared raw tx that went missing or will
            // not decode between registration and this lookup. That is an
            // internal inconsistency, not a client error, and it leaves
            // nothing to establish about the job the token authorises.
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

    // Solo gate for base-protocol custom jobs: without an ext-0x0003
    // distribution reference, nothing validates that the self-built
    // coinbase pays the shared accounting its shares would enter — off
    // Solo that's freeloading on the PPLNS window / group. With a
    // distribution reference (validated below) the coinbase is bound to
    // the published weights, so non-Solo is legitimate.
    if distribution_ref.is_none() && state.stream != StreamKind::Solo {
        return reject(ERR_CUSTOM_JOB_REQUIRES_SOLO);
    }

    // ext 0x0003 (push model). This is the Pool's sole validation point
    // for the coinbase the miner will ACTUALLY mine: §2 requires the
    // extension negotiated on THIS (mining) connection, the referenced
    // distribution must sit in the acceptance window (§7.2/§10), and
    // the submitted outputs must match the §4 recompute POSITIONALLY
    // (§7.1).
    //
    // It runs for Full-Template jobs too, and must — for a reason the
    // declaration binding above does NOT cover, so do not delete it on the
    // strength of that binding.
    //
    // The binding answers "is this the job that was declared?". It says
    // nothing about whether the distribution that job referenced is still
    // live. A declaration accepted under distribution k can arrive here
    // after k was superseded or settlement-invalidated (§7.2/§10) — same
    // job, same bytes, binding satisfied, and a coinbase paying a
    // withdrawn split. Only the block below resolves the reference against
    // the acceptance window and re-checks the §4 recompute, and it is
    // `input.coinbase_tx_outputs` the `ExtendedJob` is assembled from.
    //
    // (Before the binding existed this block also carried the weight of
    // "nothing ties the mined coinbase to the declared one". That half has
    // moved; this half has not.)
    //
    // Distributions are multi-use by design: many jobs of one tip
    // legitimately reference one distribution, and double-paying two
    // distributions at once is structurally impossible under positional
    // equality — so nothing here is consumed.
    if distribution_ref.is_some() {
        if input.distribution_id.is_some()
            && !state
                .negotiated_extensions
                .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
        {
            // §2: TLV fields from a non-negotiated extension are a
            // protocol violation, not something to silently honour.
            //
            // Keyed on the FRAME's TLV, because that is what §2 speaks about
            // — "any job declaration carrying this extension's TLV fields".
            // An inherited reference is the pool's own inference and can only
            // exist when this connection negotiated
            // (`resolve_distribution_reference` refuses to synthesise one
            // otherwise), so judging it here would be judging ourselves.
            return reject(ERR_INVALID_PAYOUT_DISTRIBUTION);
        }
        let entry = match distribution {
            Some(crate::bridge::DistributionAcceptance::Accepted(entry)) => entry.clone(),
            _ => return reject(ERR_STALE_PAYOUT_DISTRIBUTION),
        };
        // The distribution must match the accounting THIS connection's
        // shares enter. A tailored entry names its miner. A pool-wide
        // entry (`owner: None`) is the PPLNS window's, so only a PPLNS
        // stream may reference it — "every connection may reference it"
        // is true of the acceptance window, not of the accounting.
        // Without the stream check a Group-Solo connection could point
        // at the pool-wide distribution: its blocks would pay the PPLNS
        // window while its shares kept earning a cut of the group's.
        match &entry.owner {
            Some(owner) if channel_addr != owner.as_str() => {
                return reject(ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
            }
            None if state.stream != StreamKind::Pplns => {
                return reject(ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
            }
            _ => {}
        }
        let declared: Vec<bitcoin::TxOut> =
            match bitcoin::consensus::deserialize(&input.coinbase_tx_outputs) {
                Ok(v) => v,
                Err(_) => return reject(ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS),
            };
        if crate::jdp::payout_distribution::validate_coinbase_outputs_against_distribution(
            &declared,
            &entry.pool_payout,
            &entry.payouts,
            &entry.dust_limits,
            &entry.additional_outputs,
        )
        .is_err()
        {
            return reject(ERR_INVALID_PAYOUT_DISTRIBUTION);
        }
    }

    // Re-borrow channel mutably (the bridge cross-check above used
    // an immutable reference to state.address; safe because we
    // already established the channel exists + is Extended).
    let channel = state
        .channels
        .get_mut(&input.channel_id)
        .expect("channel existence checked above");

    // Compute the scriptSig length: pool-side prefix (from the JDC)
    // + the full extranonce slot (pool prefix + miner-rollable).
    let full_extranonce_size = channel.full_extranonce_size();
    let script_sig_len = input.coinbase_prefix.len() + full_extranonce_size;
    let script_sig_len_varint = encode_varint(script_sig_len as u64);

    // Assemble the non-witness coinbase prefix.
    let mut coinbase_tx_prefix =
        Vec::with_capacity(4 + 1 + 36 + script_sig_len_varint.len() + input.coinbase_prefix.len());
    coinbase_tx_prefix.extend_from_slice(&input.coinbase_tx_version.to_le_bytes());
    coinbase_tx_prefix.push(0x01); // input_count varint = 1
                                   // null outpoint: 32 zero bytes (hash) + 0xFFFFFFFF (index, LE).
    coinbase_tx_prefix.extend_from_slice(&[0u8; 32]);
    coinbase_tx_prefix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    coinbase_tx_prefix.extend_from_slice(&script_sig_len_varint);
    coinbase_tx_prefix.extend_from_slice(&input.coinbase_prefix);

    // Assemble the non-witness coinbase suffix.
    let mut coinbase_tx_suffix = Vec::with_capacity(4 + input.coinbase_tx_outputs.len() + 4);
    coinbase_tx_suffix.extend_from_slice(&input.coinbase_tx_input_n_sequence.to_le_bytes());
    coinbase_tx_suffix.extend_from_slice(&input.coinbase_tx_outputs);
    coinbase_tx_suffix.extend_from_slice(&input.coinbase_tx_locktime.to_le_bytes());

    let job_id = channel.next_job_id;
    channel.next_job_id = channel.next_job_id.wrapping_add(1);
    if channel.next_job_id == 0 {
        // Skip 0 — wrap-around resets to 1, never use 0 as a job ID.
        channel.next_job_id = 1;
    }

    channel.extended_jobs.insert(
        job_id,
        ExtendedJob {
            coinbase_prefix: coinbase_tx_prefix,
            coinbase_suffix: coinbase_tx_suffix,
            // JDC-declared coinbase — the pool built no distribution for it,
            // so there is no snapshot to bind and nothing to look up.
            payouts_fingerprint: [0u8; 32],
            merkle_path: input.merkle_path.clone(),
            version: input.version,
            prev_hash: input.prev_hash,
            n_bits: input.n_bits,
            min_ntime: input.min_ntime,
            difficulty: channel.session_difficulty,
            // Custom (JDC-declared) job: derive the block-found gate's network
            // difficulty from the declared job's own n_bits (no pool template).
            network_difficulty: crate::mining::translator::network_difficulty_from_n_bits(
                input.n_bits,
            ),
            // No pool template → no reward to thread; the JDC owns block-submit
            // + accounting (block_sink early-returns on `template_id: None`).
            coinbase_tx_value_remaining: 0,
            template_id: None, // custom job — no pool-side template reference
            created_at: now_ms,
            retired_at: None,
        },
    );

    HandlerOutcome::with_frame(OutboundFrame::SetCustomMiningJobSuccess {
        channel_id: input.channel_id,
        request_id: input.request_id,
        job_id,
    })
}

/// Encode a `u64` as a Bitcoin varint (1 / 3 / 5 / 9 bytes). Pure
/// helper — kept private to this module since the only consumer is
/// [`handle_set_custom_mining_job`]'s scriptSig length encoding.
fn encode_varint(n: u64) -> Vec<u8> {
    if n < 0xFD {
        vec![n as u8]
    } else if n <= 0xFFFF {
        let mut buf = Vec::with_capacity(3);
        buf.push(0xFD);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
        buf
    } else if n <= 0xFFFF_FFFF {
        let mut buf = Vec::with_capacity(5);
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
        buf
    } else {
        let mut buf = Vec::with_capacity(9);
        buf.push(0xFF);
        buf.extend_from_slice(&n.to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mining::jobs::ExtendedJob;
    use bp_vardiff::TestClock;
    use std::collections::HashSet;
    use std::sync::Arc;

    /// Test shim mirroring the handler's inline projection: builds the
    /// `ExtendedChannelView` + `&mut submission_cache` the validator takes
    /// so existing `&mut channel`-style call sites keep their shape.
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

    fn port_cfg() -> PortConfig {
        PortConfig {
            network: Network::Regtest,
            min_difficulty: Difficulty(0.00001),
            initial_difficulty: Difficulty(1024.0),
            target_shares_per_minute: 6.0,
            vardiff_interval_ms: 60_000,
            vardiff_silence_easing: false,
        }
    }

    fn fresh_session() -> MiningSessionState<Arc<TestClock>> {
        MiningSessionState::new(Arc::new(TestClock::new(0)), 1, port_cfg())
    }

    /// The silence-easing switch flows PortConfig → session state (from
    /// where `new_channel_vardiff` hands it to every channel engine).
    /// The engine behaviour itself is unit-tested in bp-vardiff.
    #[test]
    fn silence_easing_flag_flows_from_port_config() {
        let mut cfg = port_cfg();
        cfg.vardiff_silence_easing = true;
        let s = MiningSessionState::new(Arc::new(TestClock::new(0)), 1, cfg);
        assert!(s.vardiff_silence_easing);
        assert!(!fresh_session().vardiff_silence_easing, "default off");
    }

    fn good_setup() -> SetupConnectionInput {
        SetupConnectionInput {
            protocol: PROTOCOL_MINING,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            vendor: "test-vendor".to_string(),
            firmware: "0.1".to_string(),
            hardware_version: "rev1".to_string(),
            device_id: "dev-1".to_string(),
        }
    }

    fn open_std(req_id: u32, user: &str) -> OpenStandardMiningChannelInput {
        OpenStandardMiningChannelInput {
            request_id: req_id,
            user_identity: user.to_string(),
            // ~1000 derived at the fixture's 6 shares/min, rounding up to the
            // 1024 the surrounding tests expect. A declaration is honoured
            // as-is now, so it has to be a realistic one.
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

    // Regtest bech32 address — passes bp_mining_job::normalize_btc_address.
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
        assert!(s.version_rolling);
    }

    /// SV2 §5.3.2: `Success.flags` is the SERVER bitset and MUST NOT echo the
    /// client's request flags. A miner that asked for REQUIRES_STANDARD_JOBS +
    /// REQUIRES_VERSION_ROLLING must NOT get REQUIRES_FIXED_VERSION (bit 0) or
    /// REQUIRES_EXTENDED_CHANNELS (bit 1) back — both are 0 for our pool (we
    /// serve rollable jobs and accept standard channels). Guards the flag-echo
    /// regression that told version-rolling proxies "fixed version required".
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
        assert!(s.version_rolling);
    }

    /// A work-selection (custom-job) connection can only carry custom jobs on
    /// an Extended channel, so the server advertises REQUIRES_EXTENDED_CHANNELS
    /// (bit 1) — and still NOT REQUIRES_FIXED_VERSION (bit 0).
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
                assert_eq!(error_code, ERR_PROTOCOL_VERSION_MISMATCH);
            }
            _ => panic!("expected error"),
        }
        assert!(!s.setup_complete);
    }

    /// TDP-only sub-protocol (protocol=2) is accepted — sets the
    /// `is_tdp_client` flag and returns SetupConnectionSuccess. The
    /// connection-task will route protocol=2 wire frames to a
    /// TDP-specific dispatcher.
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

    /// Unknown sub-protocol (e.g. 1 — JDP-server, 3 — reserved) still
    /// emits `unsupported-protocol`.
    #[test]
    fn setup_connection_rejects_unknown_subprotocol() {
        let mut s = fresh_session();
        let mut input = good_setup();
        input.protocol = 99;
        let out = handle_setup_connection(&mut s, &input);
        match &out.outbound[0] {
            OutboundFrame::SetupConnectionError { error_code, .. } => {
                assert_eq!(error_code, ERR_UNSUPPORTED_PROTOCOL);
            }
            _ => panic!("expected error"),
        }
        assert!(!s.is_tdp_client);
        assert!(!s.setup_complete);
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

    /// A miner that under-reports (tiny) or omits (0) `nominal_hash_rate`
    /// must start at the configured initial difficulty (1024 in the test
    /// port), never a trivial 1 / min — an honest higher rate starts above.
    #[test]
    fn open_standard_honours_a_declaration_and_falls_back_without_one() {
        // A tiny declaration is the miner asking for a tiny difficulty — the
        // SV2 counterpart of SV1 `mining.suggest_difficulty`, honoured and
        // bounded only by min_difficulty. Flooring it at the configured start
        // pinned every device below that start above its own rate.
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

        // The case the change is for: a device that declares BELOW the
        // configured start gets its own rate, not the start value. At the
        // fixture's 6 shares/min, 100 GH/s derives ~233 — previously pinned
        // to 1024, roughly 4x above what the device can sustain.
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

    /// Generate two distinct valid P2WPKH regtest addresses for the
    /// multi-channel address-lock test. Programmatic so we don't have
    /// to hand-checksum bech32 literals.
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

    /// The rollable extranonce EXACTLY honors the requested minimum (up to
    /// [`MAX_EXTENDED_ROLLABLE`]). An aggregating proxy that needs >8 bytes
    /// (the old cap) now gets what it asked for instead of a silently smaller
    /// region that made it tear down the upstream.
    #[test]
    fn open_extended_channel_honors_requested_rollable_size() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        // 10 bytes: previously capped to 8 (→ proxy fallback); now granted 10.
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

    /// The full SRI-parity size (16 rollable bytes) is granted for a proxy
    /// that requests it.
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

    /// A request larger than the pool can grant is REJECTED (SV2 §5.3.2 —
    /// grant the minimum or reject), never silently under-granted.
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

    /// `hash_rate_to_difficulty` produces fractional diffs (e.g. 931.31); the
    /// channel must store a power of two.
    ///
    /// A whole integer was the old requirement, so a decimal-truncating miner
    /// could not undershoot the target and the `[931, 931.31)` rejection band
    /// could not exist. A power of two keeps that property and adds the one a
    /// translating proxy needs: it rounds an assigned difficulty UP to a power
    /// of two on the way to the miner, so anything else arrives changed and
    /// every share booked against our value under-counts the work.
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
        // And it must be one of the two rungs bracketing the raw value, not
        // some unrelated rung.
        let lower = 2_f64.powf(raw.log2().floor());
        assert!(
            assigned == lower || assigned == lower * 2.0,
            "assigned {assigned} must bracket raw {raw}"
        );
    }

    #[test]
    fn assigned_difficulty_is_always_a_power_of_two() {
        // The two values measured against a live translator: it rounded each
        // one UP to the next power of two on the way to the miner while the
        // pool kept booking shares at the crooked value, losing 29.5 % and
        // 7.2 % of the work respectively. Assigning the rung directly leaves
        // nothing to round.
        // NEVER below the input. A downstream that requested a difficulty via
        // `UpdateChannel` rejects a lower one as a protocol error and discards
        // the assignment entirely, leaving the miner on its old difficulty —
        // observed live, and worse than the under-counting this fixes.
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
        // Sub-1 diffs pass through unchanged — neither rounded to 0 nor
        // forced up to 1.0 (an intentionally low configured difficulty).
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

    /// Vardiff grace: validate against the LOWER of the job's frozen diff
    /// and the current session target, so neither a raise nor a lower
    /// rejects in-flight shares.
    #[test]
    fn graced_validation_difficulty_takes_the_lower() {
        // Raise (job frozen low, session raised) → grace at the frozen low,
        // so a miner still on the old target is accepted.
        assert_eq!(
            graced_validation_difficulty(Difficulty(1024.0), Difficulty(1536.0)).as_f64(),
            1024.0
        );
        // Lower (job frozen high, session lowered) → grace at the new low,
        // so the miner's lowered-target shares are accepted.
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
            network_difficulty: Difficulty(1e15),
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

    /// Happy-path submit: pre-populate the channel's standard_jobs map
    /// with an easy-difficulty entry, send a share that validates.
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
        // Channel counter bumped.
        let ch = s.channels.get(&channel_id).unwrap();
        assert_eq!(ch.accepted_share_count, 1);
    }

    /// Block-submit gating: a share whose submission-difficulty is below
    /// the network target emits `ShareAccepted` with
    /// `is_block_candidate = false`, so the IO-layer
    /// (`server.rs::apply_session_events`) does NOT fire the
    /// `BlockSubmissionSink`. Non-block shares are not submitted to
    /// the block submission handler.
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
            // Default snapshot() pins network_difficulty=1e15 → unreachable.
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

    /// Companion to the gating test: a share whose submission-difficulty
    /// meets the configured network-difficulty emits `ShareAccepted`
    /// with `is_block_candidate = true`. IO-layer reads this flag to
    /// fire the `BlockSubmissionSink` (which submits block candidates
    /// for upstream processing).
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
            // Snapshot with trivially-reachable network_difficulty so
            // any accepted share is also a block candidate.
            let mut snap = snapshot();
            snap.network_difficulty = easy;
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
                    "submission ≥ network must flag block-candidate so \
                     IO-layer fires BlockSubmissionSink"
                );
            }
            ev => panic!("expected ShareAccepted, got {ev:?}"),
        }
    }

    /// SV2 §5.3.14 retire-not-clear: a job that was retired ≤ grace
    /// ago must still be credited. The handler reads classification
    /// from `standard_jobs`, so `retire(now_ms)` before submit must
    /// flow through to `StaleCreditable` → accept.
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

    /// SV2 §5.3.14: a job retired past grace emits wire-code
    /// `stale-share`, NOT `invalid-job-id`. This ensures shares are
    /// credited when submitted within the grace window, even as the job
    /// map is being managed. See feedback memory
    /// `feedback-sv2-standard-stale-share-spec-conform`.
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

    /// Regression: an accepted Standard share whose frozen job difficulty
    /// differs from the live session difficulty MUST still feed the
    /// vardiff submission cache. Standard jobs are frozen at send-time
    /// difficulty, so the moment vardiff moves the session target, every
    /// in-flight job's difficulty diverges from it. If accepted shares on
    /// those jobs are withheld from the cache, it starves below the sample
    /// threshold, `suggested_difficulty` falls into its under-sampled
    /// fallback (`client_difficulty / target_shares_per_minute`), and the
    /// difficulty ratchets toward the floor on every check. Feeding every
    /// accepted share keeps the rate estimate honest.
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
        s.session_difficulty = Difficulty(1024.0);
        {
            let ch = s.channels.get_mut(&channel_id).unwrap();
            ch.session_difficulty = Difficulty(1024.0);
            ch.standard_jobs
                .record_send_for_test(7, easy, [0xDD; 32], snapshot(), 0);
        }
        assert_eq!(
            s.vardiff[&channel_id].cache_len(),
            0,
            "cache empty before any share"
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
            s.vardiff[&channel_id].cache_len(),
            1,
            "accepted Standard share must feed the vardiff submission cache \
             even when its frozen job difficulty differs from the session \
             target — otherwise vardiff starves and drifts to the floor"
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
            tail_tlvs: Vec::new(),
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
            version: 0x2000_0000,
            prev_hash: [0xCC; 32],
            n_bits: 0x1d00_ffff,
            min_ntime: 0,
            difficulty: easy,
            network_difficulty: Difficulty(1e15),
            coinbase_tx_value_remaining: 5_000_000_000,
            template_id: None,
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
            tail_tlvs: Vec::new(),
        };
        let out = handle_submit_shares_extended(&mut s, &sub, 0);
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SubmitSharesSuccess { .. }
        ));
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

    /// Everything `UpdateChannel` can assign is a power of two — including the
    /// value that comes out of the configured floor.
    ///
    /// A crooked `min_difficulty` would otherwise reach a translating proxy
    /// unrounded, which is exactly the case this rounding exists to prevent, and
    /// this is the path that matters in practice: a translator sends
    /// `UpdateChannel` every 60 s.
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

    /// Spec §5.3.9 line 318: a `CloseChannel` addressed to a `group_channel_id`
    /// closes ALL channels in that group and drops the group. One
    /// `ChannelClosed` event per member (the IO layer releases each member's
    /// extranonce prefix off these).
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

    /// Closing a grouped member by its OWN channel id (not the group id) is a
    /// normal single-channel close — only that member is removed; the group
    /// and the other members survive.
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

    /// Vardiff retarget under load: after a channel's submission cache
    /// fills with shares faster than the target rate, apply_vardiff_check
    /// must ratchet THAT channel's difficulty upward and emit a `SetTarget`.
    #[test]
    fn apply_vardiff_check_retargets_up_when_share_rate_exceeds_target() {
        // Clock starts at 0; advance by `tick_ms` between every fed
        // share so the engine has a positive `diff_seconds` window.
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

        // Feed 10 shares of diff=1024 over 10 seconds — share rate of
        // 1/s ≫ target (target_shares_per_minute=6 → 1 share / 10 s).
        // suggested_difficulty should propose ~10× the current diff,
        // which crosses the 2× clamp and triggers a power-of-2-rounded
        // ratchet.
        let tick_ms = 1_000_u64;
        for _ in 0..10 {
            clock.advance_ms(tick_ms);
            s.vardiff
                .get_mut(&channel_id)
                .unwrap()
                .update_hash_rate(initial, true);
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
        // A difficulty change must NEVER carry a job or a prev-hash frame.
        // SetTarget alone is the complete SV2 mechanism. A synthetic
        // TemplateChange::NewBlock re-broadcast on retarget (previously run
        // in the connection loop) emitted a fake SetNewPrevHash with a frozen
        // header_timestamp + a new job_id, which made firmware reset and
        // re-mine the identical header — freezing session best-difficulty.
        // This locks the invariant at the handler boundary so it can't creep
        // back in.
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

    /// SV2 difficulty is per channel: a fast channel and an idle channel on
    /// the SAME connection retarget INDEPENDENTLY. The fast channel ratchets
    /// up from its own share rate while the idle channel does not follow it.
    /// A single per-connection vardiff engine would push the fast channel's
    /// rate onto both — this guards against that.
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
        for _ in 0..10 {
            clock.advance_ms(tick_ms);
            s.vardiff
                .get_mut(&fast)
                .unwrap()
                .update_hash_rate(initial, true);
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

    /// Mixed (some supported, some not) → Success with the subset.
    /// Unsupported entries are silently dropped from the supported list,
    /// the client just doesn't get them echoed back.
    #[test]
    fn request_extensions_mixed_emits_success_with_subset() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        // 0x0002 and 0x0003 are supported mining-side (Worker-ID TLVs +
        // the §6 distribution_id TLV on SetCustomMiningJob); 0x00FF is
        // bogus.
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

    /// Empty requested list → Success with empty supported list.
    /// An empty request short-circuits to Success (different from the
    /// error case where requested-but-unsupported is non-empty).
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

    use crate::mining::translator::{ActiveSV2Template, TemplateBroadcast, TemplateChange};
    use bp_mining_job::PayoutEntry;

    fn payouts() -> Vec<PayoutEntry> {
        vec![PayoutEntry {
            address: REGTEST_ADDR.to_string(),
            sats: 5_000_000_000,
        }]
    }

    /// `MiningJobInputs` fixture for the SV2 apply_template_broadcast
    /// tests: same payouts + pool identifier as the previous
    /// CoinbaseTemplate-driven `synthetic_mining_job`, but supplied as
    /// raw TDP-shaped fields so the handler builds a per-channel
    /// `MiningJob` with the right extranonce-slot size baked in
    /// (BIP-34 height push for height 200, version 2, sequence
    /// 0xFFFFFFFF, locktime 0, single witness-commit OP_RETURN).
    fn synthetic_mining_job_inputs() -> MiningJobInputs {
        // BIP-34 height push for 200: [0x01, 0xC8] (single CScriptNum
        // byte with the high bit clear → no sign disambiguator).
        let coinbase_prefix = vec![0x01, 0xC8];
        // Single TDP-side TxOut: 0-value OP_RETURN OP_PUSHBYTES_36
        // (0xaa21a9ed || 32-zero commit). [value:8 LE][scriptlen:0x26][script:38].
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

    fn active_template(template_id: u64, prev: [u8; 32]) -> ActiveSV2Template {
        ActiveSV2Template {
            template_id,
            version: 0x2000_0000,
            prev_hash: prev,
            n_bits: 0x1d00_ffff,
            header_timestamp: 0x6500_0001,
            network_target: [0xFF; 32],
            network_difficulty: Difficulty(1.0),
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

    /// Open one Standard channel against a fresh session and return the
    /// channel_id, ready for apply_template_broadcast.
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

    /// Review regression (v2 max review, bug 1): an SV2 Standard submit
    /// against an unknown/aged-out job early-returns InvalidJobId BEFORE
    /// the old vardiff match arm, so the reject-storm liveness heartbeat
    /// was skipped and silence easing walked a hashing miner down. The fix
    /// stamps note_submission at the top of the handler. Proof: build an
    /// eased session whose channel WOULD ease on silence; a control run
    /// eases, and the same setup with an invalid-job submit mid-silence
    /// holds — showing the heartbeat fired on the early-return path.
    fn eased_session_with_full_window(
        clock: &Arc<TestClock>,
    ) -> MiningSessionState<Arc<TestClock>> {
        let mut cfg = port_cfg();
        cfg.vardiff_silence_easing = true;
        let mut s = MiningSessionState::new(clock.clone(), 1, cfg);
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
            s.vardiff
                .get_mut(&cid)
                .unwrap()
                .update_hash_rate(1024.0, true);
        }
        s
    }

    #[test]
    fn silence_eases_a_quiet_standard_channel_control() {
        // Control: with no submission, 400 s of silence DOES ease down.
        let clock = Arc::new(TestClock::new(0));
        let mut s = eased_session_with_full_window(&clock);
        clock.advance_ms(400_000);
        let out = apply_vardiff_check(&mut s);
        assert!(
            out.outbound
                .iter()
                .any(|f| matches!(f, OutboundFrame::SetTarget { .. })),
            "control: a truly silent channel must ease down"
        );
    }

    #[test]
    fn invalid_job_reject_stamps_heartbeat_and_holds() {
        // The fix: an invalid-job submit mid-silence stamps the liveness
        // heartbeat (top of handler, before the early return), so the
        // silence tail restarts and the channel HOLDS instead of easing.
        let clock = Arc::new(TestClock::new(0));
        let mut s = eased_session_with_full_window(&clock);
        let cid = s.primary_channel.unwrap();

        clock.advance_ms(390_000);
        // No job was ever sent → job_id 7 is unknown → InvalidJobId early
        // return. The heartbeat must fire despite that early return.
        let sub = SubmitSharesStandardInput {
            channel_id: cid,
            sequence_number: 1,
            job_id: 7,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
        };
        let out = handle_submit_shares_standard(&mut s, &sub, clock.now_ms());
        assert!(
            matches!(
                out.outbound.first(),
                Some(OutboundFrame::SubmitSharesError { .. })
            ),
            "precondition: the submit must be an invalid-job reject"
        );
        // 10 s later — total silence tail since the submit is 10 s, not
        // 400 s — the channel must hold (the control proves 400 s eases).
        clock.advance_ms(10_000);
        let out = apply_vardiff_check(&mut s);
        assert!(
            !out.outbound
                .iter()
                .any(|f| matches!(f, OutboundFrame::SetTarget { .. })),
            "an invalid-job reject must stamp the heartbeat and hold, not ease"
        );
    }

    // ── no-share descent ──────────────────────────────────────────

    /// An eased session whose channel has NEVER submitted anything. Opens
    /// at the fixture's 1024.
    fn unproven_session(
        clock: &Arc<TestClock>,
        easing: bool,
    ) -> MiningSessionState<Arc<TestClock>> {
        let mut cfg = port_cfg();
        cfg.vardiff_silence_easing = easing;
        let mut s = MiningSessionState::new(clock.clone(), 1, cfg);
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        s
    }

    #[test]
    fn a_channel_with_no_share_ever_is_eased_down_on_the_wire() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = unproven_session(&clock, true);
        let cid = s.primary_channel.unwrap();
        assert_eq!(s.channels[&cid].session_difficulty, Difficulty(1024.0));

        clock.advance_ms(61_000); // past warmup, ~6 missed share gaps
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

    #[test]
    fn a_channel_with_no_share_ever_holds_when_the_switch_is_off() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = unproven_session(&clock, false);
        let cid = s.primary_channel.unwrap();
        for _ in 0..15 {
            clock.advance_ms(60_000);
            let out = apply_vardiff_check(&mut s);
            assert!(
                out.outbound.is_empty(),
                "default-off must be byte-identical to the pre-descent behaviour"
            );
        }
        assert_eq!(s.channels[&cid].session_difficulty, Difficulty(1024.0));
    }

    /// The reason the descent needs a guard at all: a translator re-sends
    /// `UpdateChannel` every 60 s. Without this it overwrites the descent
    /// once a minute and the miner behind the proxy is never rescued.
    #[test]
    fn update_channel_cannot_raise_a_silent_channel_back_up_on_repeat() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = unproven_session(&clock, true);
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
        // It carries nothing we have not already outlived.
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
        let mut s = unproven_session(&clock, true);
        let cid = s.primary_channel.unwrap();
        clock.advance_ms(61_000);
        let _ = apply_vardiff_check(&mut s);
        let descended = s.channels[&cid].session_difficulty;

        // A proxy that now declares LESS is telling us something new, and
        // it points the same way the evidence does. Always honoured.
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

    /// The guard sits BEFORE the max_target clamp, so the spec MUST in
    /// §5.3.7 still wins: a downstream that requests a harder target gets
    /// it even while the channel is unproven.
    #[test]
    fn update_channel_max_target_still_overrides_the_guard() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = unproven_session(&clock, true);
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

    /// Once a share IS accepted the channel is proven and the ordinary
    /// `UpdateChannel` behaviour returns — the guard must not become a
    /// permanent ceiling.
    #[test]
    fn update_channel_raises_freely_once_a_share_was_accepted() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = unproven_session(&clock, true);
        let cid = s.primary_channel.unwrap();
        s.vardiff
            .get_mut(&cid)
            .unwrap()
            .update_hash_rate(1024.0, true);

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

    /// Characterisation of the `UpdateChannel` cap across the WHOLE silence
    /// range, not just the two ends. The unit tests covered "fresh channel"
    /// and "long silence"; the interesting behaviour is in between, and it
    /// is decided by a number nobody had looked at.
    ///
    /// Written to document the boundary, it found a live defect: keyed on
    /// the silence alone, the cap starts biting ~60 s after channel open
    /// (at difficulty 1024 and 6 shares/min the ceiling is already 504 by
    /// then), so a proxy whose rigs take a minute to attach would have had
    /// its first honest declaration capped — finding 2 in a milder form.
    /// Hence the second condition: only a REPEATED declaration is subject
    /// to it.
    #[test]
    fn the_update_channel_cap_only_bites_on_a_repeated_declaration() {
        // Sample the whole range. A NEW declaration is honoured at every
        // silence duration, including the ones where the ceiling is low.
        for quiet_s in [10u64, 61, 120, 300, 600, 3_600] {
            let clock = Arc::new(TestClock::new(0));
            let mut s = unproven_session(&clock, true);
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

        // The same claim re-sent on a timer is not news. Once the silence
        // has outlived it, it stops being able to hold the difficulty up.
        let clock = Arc::new(TestClock::new(0));
        let mut s = unproven_session(&clock, true);
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

    /// Review regression (finding 2): a proxy opens its extended channel
    /// BEFORE any downstream rig has connected, so it declares little or
    /// nothing and gets the port's initial difficulty. Rigs then attach and
    /// it declares the real aggregate. "No accepted share yet" is the
    /// normal state at that moment — refusing the declaration on that basis
    /// pinned a whole farm at the opening difficulty and produced a
    /// multi-minute share flood.
    #[test]
    fn update_channel_honours_a_fresh_channels_first_real_declaration() {
        let clock = Arc::new(TestClock::new(0));
        let mut s = unproven_session(&clock, true);
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

    /// The guard clamps `raw` to the session difficulty, but TWO more
    /// steps run after it: the `min_difficulty` floor and the power-of-two
    /// round-up. Either could in principle lift the result back above the
    /// value the guard just pinned — which is exactly how a clamp has been
    /// destroyed by a later rounding twice before in this crate.
    ///
    /// Swept across crooked floors and both sides of the sub-1.0 boundary
    /// (`power_of_two_difficulty` deliberately leaves values below 1.0
    /// alone, so the rounding is not even uniform).
    #[test]
    fn the_no_raise_guard_survives_the_floor_and_the_rounding() {
        for min_diff in [0.00001, 0.3, 1.0, 500.0, 3000.0, 5000.0] {
            let clock = Arc::new(TestClock::new(0));
            let mut cfg = port_cfg();
            cfg.vardiff_silence_easing = true;
            cfg.min_difficulty = Difficulty(min_diff);
            let mut s = MiningSessionState::new(clock.clone(), 1, cfg);
            handle_setup_connection(&mut s, &good_setup());
            let _ = handle_open_standard_mining_channel(
                &mut s,
                &open_std(1, &format!("{}.w", REGTEST_ADDR)),
                vec![0; 4],
            );
            let cid = s.primary_channel.unwrap();
            let claim = UpdateChannelInput {
                channel_id: cid,
                nominal_hash_rate: 1e15,
                maximum_target: [0xFF; 32],
            };
            // State the claim once so later sends are repeats, then let
            // the descent run through total silence.
            let _ = handle_update_channel(&mut s, &claim);
            for _ in 0..6 {
                clock.advance_ms(60_000);
                let _ = apply_vardiff_check(&mut s);
            }
            let before = s.channels[&cid].session_difficulty.as_f64();

            // Now re-assert it, repeatedly — a translator does this every
            // 60 s.
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

    /// The inline (post-share) check must not run more often than
    /// `vardiff_interval_ms`. Before this gate existed, every accepted
    /// share re-swept every channel's engine on the connection.
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

    /// A fresh session has never been checked, so the first accepted share
    /// is allowed to bring the retarget forward — the gate paces repeats,
    /// it does not delay the first one. (`last_difficulty_check_ms` starts
    /// at 0 against a wall-clock reading, so the difference is enormous;
    /// SV1 has the same property.)
    #[test]
    fn vardiff_cooldown_is_open_on_a_fresh_session() {
        let clock = Arc::new(TestClock::new(1_784_000_000_000));
        let s = MiningSessionState::new(clock, 1, port_cfg());
        assert_eq!(s.last_difficulty_check_ms, 0);
        assert!(s.vardiff_cooldown_elapsed());
    }

    /// A backwards clock step must not wedge the gate shut forever —
    /// `saturating_sub` floors the elapsed time at 0, so the gate simply
    /// stays closed until the clock catches back up.
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

    /// Open one Extended channel against a fresh session.
    fn session_with_extended_channel() -> MiningSessionState<Arc<TestClock>> {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_extended_mining_channel(
            &mut s,
            &open_ext(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0xAA, 0xBB, 0xCC, 0xDD],
        );
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

    /// `apply_template_broadcast` Extended branch must build the
    /// `mining_job.coinbase_prefix` with a scriptsig_len varint sized
    /// for the channel's actual extranonce (`prefix.len() +
    /// extranonce_size`), not the pool-default 12. Without this,
    /// miners (BitAxe and others) compute share hashes against a
    /// different scriptsig_len than our validator — manifesting as
    /// intermittent 'difficulty-too-low' rejections — and the
    /// resulting witness_coinbase fails bitcoin-core's consensus parse
    /// with `OversizedVarInt` on submit_solution.
    #[test]
    fn template_broadcast_extended_uses_correctly_sized_scriptsig_len() {
        // Force a 6-byte miner extranonce (= BitAxe; total 4+6=10 < 12).
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
        // Baseline: build the MiningJob with the pool-default 12-byte
        // slot. The Extended branch will rebuild with a 10-byte slot
        // (4 prefix + 6 miner), so the scriptsig_len varint at offset
        // 41 must come out 2 less than the baseline.
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
        // `coinbase_prefix` carries `mining_job.coinbase_prefix +
        // channel.extranonce_prefix(4 bytes)`. Byte 41 is the
        // scriptsig_len varint inside the inner mining-job prefix.
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

    /// NewBlock against a Standard channel emits
    /// `SetNewPrevHash` + `NewMiningJob` with a non-trivial merkle
    /// root that's been stored on-channel for later submit-validation.
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
        // SV2 future-job order: the job comes FIRST with an empty
        // `min_ntime`, then SetNewPrevHash activates it.
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

    /// NewBlock against an Extended channel splits the coinbase at the
    /// channel's extranonce-prefix boundary + records an ExtendedJob
    /// per-channel so later share submit can reconstruct.
    #[test]
    fn template_broadcast_extended_new_block_emits_set_prev_and_new_ext_mining_job() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        // Eager grouping (SV2 §5.2.3): the channel opened on a
        // non-REQUIRES_STANDARD_JOBS connection, so it was grouped — the job
        // is addressed to its `group_channel_id`, not the channel id, and the
        // shared group `job_id` starts at 1.
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
                assert!(
                    *version_rolling_allowed,
                    "version-rolling flag set in setup"
                );
                assert_eq!(merkle_path.len(), 2);
                // The miner reconstructs the coinbase as
                //   coinbase_tx_prefix + channel.extranonce_prefix
                //                      + miner_extranonce
                //                      + coinbase_tx_suffix
                // So the wire-frame prefix MUST NOT include
                // channel.extranonce_prefix (=`[0xAA,0xBB,0xCC,0xDD]`
                // for this fixture). The validator re-inserts the
                // bytes in `validate_submit_extended` from
                // channel state.
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

    // ── Group channels (SV2 §5.2.3) ────────────────────────────────

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
        // The group id is drawn from the channel-id namespace and never
        // collides with a channel id (spec §5.2.3 line 185).
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
        // The SAME shared job_id is recorded on EVERY member channel so
        // per-member SubmitSharesExtended validation keeps working.
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

    /// End-to-end (handler level): a non-RSJ proxy opens two equal-size
    /// Extended channels (grouped), the pool broadcasts ONE group-addressed
    /// job, and a `SubmitSharesExtended` against the SHARED group `job_id` on a
    /// member channel reconstructs the coinbase (the member's own
    /// extranonce_prefix spliced into the group's shared coinbase parts) and
    /// VALIDATES. This is the grouping-critical path: it proves the broadcast
    /// stored the job so that per-member submit lookup + validation works — the
    /// only grouping-specific risk being the shared-job_id storage/lookup.
    /// Downstream fan-out to the proxy's devices is the proxy's job and cannot
    /// be exercised in-tree.
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

        // The shared group job is stored on the member channel under the group
        // job_id — clone it out so we can re-borrow the channel mutably below.
        let job = s
            .channels
            .get(&member)
            .unwrap()
            .extended_jobs
            .get(&group_job_id)
            .expect("group job stored on member channel")
            .clone();

        // Well-formed share on the member channel against the group job_id.
        // A trivially-small share difficulty (1/2^32) means any hash beats the
        // target — so an Accept isolates the coinbase-reconstruction path.
        let sub = SubmitSharesExtendedInput {
            channel_id: member,
            sequence_number: 1,
            job_id: group_job_id,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
            extranonce: ExtranonceBytes::from_slice(&[0x11u8; 8]),
            tail_tlvs: Vec::new(),
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

    /// Onboarding a second grouped channel (each open triggers an
    /// `only_channel` initial-job broadcast) must NOT disrupt the first
    /// member: the new channel receives the group's CURRENT job (same job_id,
    /// reused — not a fresh one), and the existing member's job is neither
    /// retired nor re-issued. Guards against the spurious-new-block-on-join
    /// regression.
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
        // The onboard job + prev-hash are addressed to the new member's OWN
        // channel_id, never the group id — so the existing member receives
        // nothing and its work is not restarted.
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
            tail_tlvs: Vec::new(),
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

    /// Pin the byte-identity of [`standard_member_root_and_coinbase`] against
    /// the canonical `MiningJob::coinbase_txid_with_extranonce` splice — the
    /// Standard broadcast path routes through the helper, so this guards it
    /// from silently diverging from the MiningJob splice.
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

    /// Refresh keeps prev-hash side-effects out: no SetNewPrevHash, no
    /// retire/clear, just a fresh NewMiningJob.
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
        // Now Refresh with DIFFERENT work (varied coinbase → different merkle
        // root) so it is not suppressed as a byte-identical re-issue: existing
        // entry stays Active (not retired).
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
        // Same-block refresh: an ACTIVE job (`Some(min_ntime)`), NOT a future
        // job — the inverse of the block-change case.
        match &out.outbound[0] {
            OutboundFrame::NewMiningJob { min_ntime, .. } => assert!(
                min_ntime.is_some(),
                "a same-block refresh job must be active (Some(min_ntime))"
            ),
            other => panic!("expected NewMiningJob, got {other:?}"),
        }
        let ch = s.channels.get(&cid).unwrap();
        // The job_id=1 entry from NewBlock is still Active (not retired
        // by Refresh).
        assert_eq!(
            ch.standard_jobs.classify(1, 2_000),
            Some(bp_jobs_lifecycle::JobClassification::Active),
            "Refresh must not retire existing entries"
        );
    }

    /// A same-block refresh that is byte-identical to the last job sent is
    /// NOT re-issued (strict firmware resets its pipeline on every job). A
    /// refresh with changed work, and any block change, ARE sent.
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

    /// Block change retires previously-active jobs (both kinds) +
    /// clears the dedup cache.
    #[test]
    fn template_broadcast_new_block_retires_and_clears_dedup() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        // Pre-seed a dedup-cache entry + a fake ExtendedJob.
        {
            let ch = s.channels.get_mut(&cid).unwrap();
            ch.submission_cache
                .insert_extended(crate::mining::channel::ExtendedDedupKey {
                    job_id: 99,
                    nonce: 1,
                    ntime: 1,
                    version: 1,
                    extranonce: ExtranonceBytes::from_slice(&[0; 8]),
                });
            ch.extended_jobs.insert(
                99,
                ExtendedJob {
                    payouts_fingerprint: [0u8; 32],
                    coinbase_prefix: vec![],
                    coinbase_suffix: vec![],
                    merkle_path: vec![],
                    version: 0,
                    prev_hash: [0; 32],
                    n_bits: 0,
                    min_ntime: 0,
                    difficulty: Difficulty(1.0),
                    network_difficulty: Difficulty(1e15),
                    coinbase_tx_value_remaining: 5_000_000_000,
                    template_id: None,
                    created_at: 500,
                    retired_at: None,
                },
            );
            // Pre-existing Standard-side entry on this Extended channel
            // (e.g. left over from a previous Standard-phase) — confirm
            // retire applies to standard_jobs too.
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
        assert!(
            ch.submission_cache.is_empty(),
            "dedup cache cleared on block change"
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

    /// Per-channel `next_job_id` allocator is monotonic across
    /// broadcasts — second NewBlock bumps to job_id=2.
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

    /// Multi-channel session: each channel gets its own SetNewPrevHash +
    /// job_id (channel-local, not shared).
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

    // ── handle_set_custom_mining_job (Item E) ──────────────────────

    use crate::bridge::RegisteredDeclaredJob;
    use crate::jdp::declarations::DeclaredJob as JdpDeclaredJob;
    use crate::tokens::Token;
    use std::collections::HashMap as Map;

    /// The scriptSig prefix every fixture below declares and mines: a
    /// BIP-34 height push.
    const FIXTURE_SCRIPT_SIG_PREFIX: [u8; 3] = [0x03, 0xC8, 0x00];
    /// Extranonce slot the DECLARATION reserves. MUST equal the test
    /// channel's `full_extranonce_size()` — the binding compares the two,
    /// because `handle_push_solution` splices the channel's extranonce into
    /// the declared gap. `the_fixture_slot_matches_the_test_channel` pins it,
    /// so a change to the channel fixture cannot drift away from this
    /// silently.
    const FIXTURE_DECLARED_SLOT: usize = 12;

    /// Two consensus-decodable transactions standing in for a declared set,
    /// returned as `(wtxid_list, raw_transactions)`.
    ///
    /// The wtxids are opaque tags — only the LIST LENGTH and the raw bytes
    /// feed the merkle branch, and the branch is built from the txids the
    /// raw bytes hash to.
    fn fixture_declared_txs() -> (Vec<[u8; 32]>, Map<u32, Vec<u8>>) {
        let mut raw = Map::new();
        let mut wtxids = Vec::new();
        for (position, tag) in [0xA1u8, 0xB2].into_iter().enumerate() {
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
            raw.insert(position as u32, bitcoin::consensus::serialize(&tx));
            wtxids.push([tag; 32]);
        }
        (wtxids, raw)
    }

    /// The declared coinbase as SV2 splits it: everything before the
    /// extranonce slot, and everything after. Same assembly the handler
    /// performs on the mining side, so the two describe one transaction.
    fn fixture_declared_coinbase_parts(
        script_sig_prefix: &[u8],
        outputs_blob: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let script_sig_len = script_sig_prefix.len() + FIXTURE_DECLARED_SLOT;
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&2u32.to_le_bytes()); // coinbase_tx_version
        prefix.push(0x01); // input count
        prefix.extend_from_slice(&[0u8; 32]); // null outpoint hash
        prefix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // outpoint index
        prefix.extend_from_slice(&encode_varint(script_sig_len as u64));
        prefix.extend_from_slice(script_sig_prefix);

        let mut suffix = Vec::new();
        suffix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // nSequence
        suffix.extend_from_slice(outputs_blob);
        suffix.extend_from_slice(&0u32.to_le_bytes()); // locktime
        (prefix, suffix)
    }

    /// The `SetCustomMiningJob` an HONEST JDC mining `entry` would send:
    /// every bound field taken from the declaration itself.
    ///
    /// Tests that want a binding violation start here and change exactly one
    /// field, so what they prove is that field and not fixture drift. The
    /// projection is shared with production deliberately; what pins the
    /// projection ITSELF is
    /// `custom_job_binding::tests::branch_folds_back_to_the_full_tree_root`,
    /// which recomputes the root by a different algorithm.
    fn custom_job_matching(
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
            prev_hash: entry.declared_job.prev_hash.unwrap_or([0xAB; 32]),
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

    fn bridge_entry_for(token: Token, address: &str, session_id: u32) -> RegisteredDeclaredJob {
        bridge_entry_declaring(
            token,
            address,
            session_id,
            &FIXTURE_SCRIPT_SIG_PREFIX,
            &[0x00], // empty output vector
        )
    }

    /// A bridge entry declaring a specific coinbase — for tests whose subject
    /// is the mined coinbase, which must be DECLARED that way too or the
    /// binding check fires before they reach what they mean to test.
    fn bridge_entry_declaring(
        token: Token,
        address: &str,
        session_id: u32,
        script_sig_prefix: &[u8],
        outputs_blob: &[u8],
    ) -> RegisteredDeclaredJob {
        let (coinbase_tx_prefix, coinbase_tx_suffix) =
            fixture_declared_coinbase_parts(script_sig_prefix, outputs_blob);
        let (wtxid_list, raw_transactions) = fixture_declared_txs();
        RegisteredDeclaredJob {
            declared_job: JdpDeclaredJob {
                new_token: token,
                version: 0x2000_0000,
                coinbase_tx_prefix,
                coinbase_tx_suffix,
                wtxid_list,
                raw_transactions,
                prev_hash: Some([0xAB; 32]),
                declared_at_ms: 1_000,
                booking: None,
                distribution_id: None,
            },
            miner_address: AddressId::new(address.to_string()).unwrap(),
            jdp_session_id: session_id,
        }
    }

    /// A Full-Template declaration accepted against `distribution_id` — what
    /// the JDP side writes when the §6 TLV rode on `DeclareMiningJob` and the
    /// coinbase recomputed against that distribution.
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

    /// The same declaration against a distribution whose settlement snapshot
    /// never landed (`bookable: false`): fully validated and served, but a
    /// found block is reported instead of booked, so the JDP side leaves
    /// `booking` empty while still recording what was referenced.
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
        let out = handle_set_custom_mining_job(&mut s, &input, None, None, 1_000);
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
        let out = handle_set_custom_mining_job(&mut s, &input, None, None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_ID);
            }
            _ => panic!("expected SetCustomMiningJobError"),
        }
    }

    /// Extended channel + declared-job bridge hit → accept. Verify the
    /// ExtendedJob is stored with assembled non-witness coinbase
    /// prefix/suffix.
    #[test]
    fn set_custom_mining_job_extended_accepts_and_stores_ext_job() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        let input = custom_job_input(cid, token);
        let out =
            handle_set_custom_mining_job(&mut s, &input, Some(&job_ref_for(&entry)), None, 1_000);
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
        // Non-witness coinbase prefix layout:
        // [version:4][input_count:1][null_outpoint:36][scriptSig_len_varint][scriptSig_prefix].
        // version = 2 LE = [0x02, 0x00, 0x00, 0x00]
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

    /// What the IO layer hands the handler — produced by REGISTERING the
    /// entry and asking the real registry, not by rebuilding the projection
    /// here. A hand-rolled copy would be a second implementation of the one
    /// thing these tests exist to exercise, free to drift from the registry
    /// while every assertion below stayed green.
    fn job_ref_for(entry: &RegisteredDeclaredJob) -> crate::bridge::BridgeJobRef {
        let mut registry = crate::bridge::JdpDeclaredJobRegistry::new();
        let token = entry.declared_job.new_token;
        registry.register(token, entry.clone());
        registry.job_ref(&token).expect("just registered")
    }

    /// Extended-channel session on the SOLO stream — the only stream where a
    /// base-protocol custom job (no ext-0x0003 distribution reference) is
    /// accepted. The ext-0x0003 tests deliberately keep the default (PPLNS)
    /// stream, which doubles as proof that a distribution-referenced custom
    /// job passes off Solo.
    fn solo_session_with_extended_channel() -> MiningSessionState<Arc<TestClock>> {
        let mut s = session_with_extended_channel();
        s.stream = StreamKind::Solo;
        s
    }

    /// Bridge entry whose miner_address matches the channel's locked
    /// address → accept. Verifies the cross-check.
    #[test]
    fn set_custom_mining_job_bridge_entry_matching_address_accepts() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        let input = custom_job_input(cid, token);
        let out =
            handle_set_custom_mining_job(&mut s, &input, Some(&job_ref_for(&entry)), None, 1_000);
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
    }

    /// Bridge entry with DIFFERENT miner_address → reject. This is
    /// the security cross-check: stops one miner from claiming
    /// another's declared job.
    #[test]
    fn set_custom_mining_job_bridge_entry_mismatching_address_rejects() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let other_addr = "bcrt1q9h6ks0scwrsvz8ku4eqkxh5sx5xkw6vqxttzva";
        let entry = bridge_entry_for(token, other_addr, 42);
        let input = custom_job_input(cid, token);
        let out =
            handle_set_custom_mining_job(&mut s, &input, Some(&job_ref_for(&entry)), None, 1_000);
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

    /// Fail-closed token check: a token resolving to no bridge entry, with
    /// no distribution reference either (never declared / expired /
    /// evicted), is rejected — never accepted as an unvalidated self-built
    /// job.
    #[test]
    fn set_custom_mining_job_unknown_token_rejects() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let input = custom_job_input(cid, Token([0xEEu8; 16]));
        let out = handle_set_custom_mining_job(&mut s, &input, None, None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_MINING_JOB_TOKEN);
            }
            _ => panic!("expected invalid-mining-job-token error"),
        }
        let ch = s.channels.get(&cid).unwrap();
        assert!(ch.extended_jobs.is_empty(), "no job may be registered");
    }

    /// Tip binding: the custom job's `prev_hash` must equal the tip its
    /// declaration was accepted under; drift → `stale-chain-tip` (the
    /// retryable classification — NOT a parameter error, which JDCs treat
    /// as fatal).
    #[test]
    fn set_custom_mining_job_declared_tip_mismatch_rejects_stale_chain_tip() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let mut entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        // Declared under a DIFFERENT tip than the job builds on (0xAB).
        entry.declared_job.prev_hash = Some([0xCD; 32]);
        let input = custom_job_input(cid, token);
        let out =
            handle_set_custom_mining_job(&mut s, &input, Some(&job_ref_for(&entry)), None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_CHAIN_TIP);
            }
            _ => panic!("expected stale-chain-tip error"),
        }
        let ch = s.channels.get(&cid).unwrap();
        assert!(ch.extended_jobs.is_empty(), "stale job must not register");
    }

    /// Solo gate: a base-protocol custom job (valid declared token, but NO
    /// ext-0x0003 distribution reference) on a non-Solo stream is rejected —
    /// its shares would enter shared accounting with an unvalidated
    /// coinbase. The ext-0x0003 acceptance tests below run on the default
    /// (PPLNS) stream, proving a distribution-referenced job passes exactly
    /// where this one fails.
    #[test]
    fn set_custom_mining_job_without_distribution_rejected_off_solo() {
        // Default-stream session = PPLNS.
        let mut s = session_with_extended_channel();
        assert_ne!(s.stream, StreamKind::Solo, "fixture must be non-Solo");
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        let input = custom_job_input(cid, token);
        let out =
            handle_set_custom_mining_job(&mut s, &input, Some(&job_ref_for(&entry)), None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_CUSTOM_JOB_REQUIRES_SOLO);
            }
            _ => panic!("expected custom-jobs-require-solo error"),
        }
        let ch = s.channels.get(&cid).unwrap();
        assert!(ch.extended_jobs.is_empty(), "no job may be registered");
    }

    /// A declaration accepted while the pool had no tip (`None`) is not
    /// checkable — the tip binding is skipped, not failed.
    #[test]
    fn set_custom_mining_job_unknowable_declared_tip_accepts() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let mut entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        entry.declared_job.prev_hash = None;
        let input = custom_job_input(cid, token);
        let out =
            handle_set_custom_mining_job(&mut s, &input, Some(&job_ref_for(&entry)), None, 1_000);
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
    }

    // ── ext 0x0003 distribution validation on SetCustomMiningJob ───

    use crate::jdp::payout_distribution::{compute_payout_vector, WeightedOutput};

    /// Registry entry with one weight-9 miner slot behind a weight-1 pool
    /// output. `owner: None` = pool-wide, `Some` = tailored (§3.1).
    fn distribution_entry(owner: Option<AddressId>) -> crate::bridge::PayoutDistributionEntry {
        crate::bridge::PayoutDistributionEntry {
            distribution_id: 9,
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
            owner,
            jdp_session_id: None,
            published_at_ms: 1_000,
        }
    }

    /// §4-conformant `coinbase_tx_outputs` blob for `entry` at revenue `t`.
    fn conformant_outputs(entry: &crate::bridge::PayoutDistributionEntry, t: u64) -> Vec<u8> {
        let outputs = compute_payout_vector(
            &entry.pool_payout,
            &entry.payouts,
            &entry.dust_limits,
            &entry.additional_outputs,
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

    /// Extended-channel session with ext 0x0003 negotiated on the mining
    /// connection (the §2 gate for the `distribution_id` TLV). Stays on
    /// the default (PPLNS) stream — a distribution-referenced custom job
    /// is legitimate off Solo, exactly where the base-protocol job above
    /// is rejected.
    fn negotiated_session_with_extended_channel() -> MiningSessionState<Arc<TestClock>> {
        let mut s = session_with_extended_channel();
        s.negotiated_extensions
            .push(SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS);
        s
    }

    /// §7.1 recompute-and-compare: a coinbase positionally matching the
    /// referenced distribution's §4 vector is accepted.
    #[test]
    fn set_custom_mining_job_conformant_distribution_coinbase_accepts() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let entry = distribution_entry(None);
        let blob = conformant_outputs(&entry, 312_500_000);
        let acc = accepted(entry);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = blob;
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&acc), 1_000);
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
    }

    /// §7.1: a coinbase that does not reproduce the §4 vector is rejected
    /// `invalid-payout-distribution`; no ExtendedJob is stored.
    #[test]
    fn set_custom_mining_job_nonconformant_coinbase_rejects() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let acc = accepted(distribution_entry(None));
        // Default input carries an empty `coinbase_tx_outputs` ([0x00]) —
        // the recomputed vector always expects at least the pool output.
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&acc), 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_PAYOUT_DISTRIBUTION);
            }
            other => panic!("expected invalid-distribution error, got {other:?}"),
        }
        assert!(s.channels.get(&cid).unwrap().extended_jobs.is_empty());
    }

    /// A `coinbase_tx_outputs` blob that fails consensus decode is a
    /// parameter error, not a distribution violation.
    #[test]
    fn set_custom_mining_job_undecodable_coinbase_outputs_rejects() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let acc = accepted(distribution_entry(None));
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = vec![0x01]; // count=1, no TxOut bytes
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&acc), 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS);
            }
            other => panic!("expected coinbase-outputs error, got {other:?}"),
        }
    }

    /// §7.2/§10: a referenced distribution outside the acceptance window
    /// (superseded or settlement-invalidated) → `stale-payout-distribution`.
    #[test]
    fn set_custom_mining_job_stale_distribution_rejects() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let entry = distribution_entry(None);
        let blob = conformant_outputs(&entry, 312_500_000);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = blob;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            None,
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

    /// A never-published `distribution_id` reads the same on the wire as a
    /// superseded one — `stale-payout-distribution` (the JDC re-fetches and
    /// re-declares either way).
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

    /// §2: a `distribution_id` TLV on a connection that never negotiated
    /// 0x0003 is a protocol violation — rejected even when the referenced
    /// distribution would resolve.
    #[test]
    fn set_custom_mining_job_distribution_tlv_without_negotiation_rejects() {
        let mut s = session_with_extended_channel(); // 0x0003 NOT negotiated
        let cid = s.primary_channel.unwrap();
        let entry = distribution_entry(None);
        let blob = conformant_outputs(&entry, 312_500_000);
        let acc = accepted(entry);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = blob;
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&acc), 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_PAYOUT_DISTRIBUTION);
            }
            other => panic!("expected invalid-distribution error, got {other:?}"),
        }
    }

    /// A tailored distribution belongs to one miner; a channel locked to a
    /// DIFFERENT address may not reference it (cross-account guard in
    /// Coinbase-only mode).
    #[test]
    fn set_custom_mining_job_tailored_owner_mismatch_rejects() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let other = "bcrt1q9h6ks0scwrsvz8ku4eqkxh5sx5xkw6vqxttzva";
        let entry = distribution_entry(Some(AddressId::new(other.to_string()).unwrap()));
        let blob = conformant_outputs(&entry, 312_500_000);
        let acc = accepted(entry);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = blob;
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&acc), 1_000);
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
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let entry = distribution_entry(Some(AddressId::new(REGTEST_ADDR.to_string()).unwrap()));
        let blob = conformant_outputs(&entry, 312_500_000);
        let acc = accepted(entry);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = blob;
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&acc), 1_000);
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
    }

    /// A Full-Template job (bridge entry present) must be §7.1-validated on
    /// the outputs it SUBMITS, not waved through because it matches its
    /// declaration.
    ///
    /// The declaration binding cannot stand in for this. It proves the job
    /// is the one that was declared — and a JDC whose own template pays
    /// itself declares and mines exactly that, consistently. What §7.1 adds
    /// is the question the binding never asks: does this coinbase pay the
    /// distribution the pool published? The `ExtendedJob` is assembled from
    /// the SUBMITTED outputs, so without the check those are whatever the
    /// JDC chose, while its shares earn in the shared window.
    #[test]
    fn set_custom_mining_job_full_template_nonconformant_coinbase_rejects() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        // Pays a single output to the miner instead of the published
        // weights. DECLARED that way too, so the declaration binding passes
        // and §7.1 is what has to catch it — a JDC whose own template pays
        // itself, rather than one that swapped after declaring.
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
        let entry = distribution_entry(None);
        let acc = accepted(entry);
        let mut input = custom_job_matching(cid, &bridge);
        input.distribution_id = Some(9);
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&bridge)),
            Some(&acc),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_PAYOUT_DISTRIBUTION);
            }
            other => panic!("a Full-Template job must still be §7.1-checked, got {other:?}"),
        }
    }

    /// The mirror: a Full-Template job whose submitted outputs DO match
    /// the referenced distribution is still accepted, so the check above
    /// is a conformance rule and not a blanket ban on the mode.
    #[test]
    fn set_custom_mining_job_full_template_conformant_coinbase_accepts() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = distribution_entry(None);
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
            Some(&acc),
            1_000,
        );
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
    }

    /// An invented `distribution_id` must not buy passage past the Solo
    /// gate. The gate keys on the TLV being PRESENT, so a bogus id on a
    /// non-Solo stream used to slip through whenever a bridge entry
    /// existed; it now fails to resolve and is rejected as stale.
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

    /// ext 0x0003 §6 places the `distribution_id` TLV per Job Declaration
    /// mode, and Full-Template puts it on `DeclareMiningJob` — NOT on
    /// `SetCustomMiningJob`. So a conformant Full-Template JDC arrives here
    /// with no TLV at all, and the reference has to come from its
    /// declaration.
    ///
    /// Both directions in one test on purpose: the accept alone would also
    /// pass if the Solo gate had simply stopped gating, and the reject alone
    /// would pass on a fixture that never referenced anything. Together they
    /// pin it to the inheritance.
    #[test]
    fn full_template_custom_job_inherits_its_declarations_distribution() {
        let entry = distribution_entry(None);
        let blob = conformant_outputs(&entry, 312_500_000);
        let token = Token([1u8; 16]);
        let declared =
            bridge_entry_declaring(token, REGTEST_ADDR, 42, &FIXTURE_SCRIPT_SIG_PREFIX, &blob);

        // Declared under distribution 9, no TLV on the mining frame — the
        // shape a spec-conformant Full-Template JDC actually sends.
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

        // Negative control: same job, same absent TLV, but the declaration
        // referenced nothing (base-protocol JDP). Then there is genuinely
        // nothing backing the coinbase and the Solo gate must still bite.
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let mut input = custom_job_matching(cid, &declared);
        input.distribution_id = None;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&declared)),
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

    /// Inheriting the reference must not inherit a pass. The §7.1 recompute
    /// runs on the SUBMITTED outputs either way — otherwise Full-Template
    /// would be the one mode where dropping the TLV skips the check.
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
            Some(&accepted(distribution_entry(None))),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_PAYOUT_DISTRIBUTION);
            }
            other => panic!("an inherited reference must still be §7.1-checked, got {other:?}"),
        }
    }

    /// A distribution whose settlement snapshot never landed is still served:
    /// the declaration is validated, accepted, and mineable — only a found
    /// block is reported instead of booked.
    ///
    /// Reading the reference off `booking` would silently turn that into a
    /// hard refusal, i.e. a snapshot-write failure would stop the JDC from
    /// mining at all instead of costing one booking. For an SRI JDC a refusal
    /// here is fatal (solo fallback), so the degradation must stay a
    /// degradation.
    #[test]
    fn an_unbookable_distribution_still_yields_a_mineable_job() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = distribution_entry(None);
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

    /// §2: the extension must be negotiated on BOTH connections, and a client
    /// that negotiated on only one MUST NOT use it. A declaration that
    /// negotiated 0x0003 on its JDP connection therefore does not license a
    /// mining connection that never did.
    ///
    /// The refusal is the base-protocol one — `custom-jobs-require-solo`,
    /// exactly what this connection got before the inheritance path existed.
    /// NOT `invalid-payout-distribution`: that code says "your TLV is a
    /// protocol violation", and this client sent no TLV. Answering it here
    /// would be blaming the JDC for a reference the pool inferred.
    #[test]
    fn inherited_distribution_needs_the_extension_on_the_mining_connection() {
        let mut s = session_with_extended_channel(); // 0x0003 NOT negotiated here
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = distribution_entry(None);
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
            Some(&accepted(entry)),
            1_000,
        );
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_CUSTOM_JOB_REQUIRES_SOLO);
            }
            other => panic!("§2 requires negotiation on this connection too, got {other:?}"),
        }
    }

    /// A Solo stream has always been served a reference-less custom job, and
    /// this commit must not change that. The inherited reference would drag it
    /// into the §7.2/§10 acceptance window for the first time — so a pool
    /// block settling between `DeclareMiningJobSuccess` and this frame, or any
    /// supersession, would answer `stale-payout-distribution` where the job
    /// used to be served. Fatal for an SRI jd-client.
    ///
    /// The unresolvable acceptance is the point: it is what a settled or
    /// superseded distribution looks like here.
    #[test]
    fn a_solo_stream_is_untouched_by_its_declarations_distribution() {
        let mut s = solo_session_with_extended_channel();
        s.negotiated_extensions
            .push(SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS);
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = distribution_entry(None);
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

    /// The mirror of the Solo carve-out: a stream whose shares DO enter shared
    /// accounting must still be refused when its inherited reference no longer
    /// resolves. Without this the carve-out could widen into "inherited
    /// references skip the window", which is the freeloading direction.
    #[test]
    fn a_shared_accounting_stream_still_fails_on_an_unresolvable_inherited_id() {
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = distribution_entry(None);
        let blob = conformant_outputs(&entry, 312_500_000);
        let declared = declared_under_distribution(
            bridge_entry_declaring(token, REGTEST_ADDR, 42, &FIXTURE_SCRIPT_SIG_PREFIX, &blob),
            9,
        );
        assert_ne!(s.stream, StreamKind::Solo);
        let mut input = custom_job_matching(cid, &declared);
        input.distribution_id = None;
        let out = handle_set_custom_mining_job(
            &mut s,
            &input,
            Some(&job_ref_for(&declared)),
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

    /// A pool-wide distribution (`owner: None`) is the PPLNS window's.
    /// A Group-Solo connection referencing it would mine blocks paying
    /// PPLNS while its shares earned a cut of the group's round.
    #[test]
    fn set_custom_mining_job_pool_wide_distribution_off_pplns_stream_rejects() {
        for stream in [
            StreamKind::GroupSolo,
            StreamKind::Solo,
            StreamKind::Blockparty,
        ] {
            let mut s = negotiated_session_with_extended_channel();
            s.stream = stream;
            let cid = s.primary_channel.unwrap();
            let entry = distribution_entry(None);
            let blob = conformant_outputs(&entry, 312_500_000);
            let acc = accepted(entry);
            let mut input = custom_job_input(cid, Token([1u8; 16]));
            input.distribution_id = Some(9);
            input.coinbase_tx_outputs = blob;
            let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&acc), 1_000);
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

    /// Sequential SetCustomMiningJob frames on the same channel
    /// allocate monotonic job_ids.
    #[test]
    fn set_custom_mining_job_allocates_monotonic_job_ids() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        let job_ref = job_ref_for(&entry);
        let input1 = custom_job_input(cid, token);
        let out1 = handle_set_custom_mining_job(&mut s, &input1, Some(&job_ref), None, 1_000);
        let mut input2 = custom_job_input(cid, token);
        input2.request_id = 2;
        let out2 = handle_set_custom_mining_job(&mut s, &input2, Some(&job_ref), None, 2_000);
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

    /// Pin the varint encoding of larger scriptSig lengths. Coinbase
    /// prefix length of 253 means scriptSig = 253 + 12 = 265 → 3-byte
    /// varint (0xFD + u16-LE).
    #[test]
    fn set_custom_mining_job_emits_3byte_varint_for_large_scriptsig() {
        // Driven through the Coinbase-only path (a referenced distribution, no
        // declaration). A DECLARED job cannot reach this length any more: the
        // reconstruction refuses a scriptSig past the consensus 100-byte
        // maximum, so a bound job's prefix stops well short of a 3-byte
        // CompactSize. The assembly itself still has to encode one correctly.
        let mut s = negotiated_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = distribution_entry(None);
        let blob = conformant_outputs(&entry, 312_500_000);
        let acc = accepted(entry);
        let mut input = custom_job_input(cid, token);
        input.distribution_id = Some(9);
        input.coinbase_tx_outputs = blob;
        input.coinbase_prefix = vec![0xAA; 253];
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&acc), 1_000);
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
        // After 4(version) + 1(input_count) + 36(null_outpoint) = 41
        // bytes comes the varint. 0xFD prefix indicates 2-byte LE
        // length follows: 265 = 0x0109.
        assert_eq!(ext.coinbase_prefix[41], 0xFD);
        assert_eq!(&ext.coinbase_prefix[42..44], &[0x09, 0x01]);
        // Then the 253 JDC-prefix bytes.
        assert_eq!(ext.coinbase_prefix.len(), 41 + 3 + 253);
    }

    // ── Declaration binding ────────────────────────────────────────────

    /// Both coinbases are §7.1-conformant against the same distribution —
    /// they differ only in the `T` they divide, so the payout check passes
    /// either way and cannot tell a declared job from a substituted one.
    /// That is what makes this the case worth pinning: the binding is the
    /// only thing that notices the substitution.
    ///
    /// Note what is NOT asserted here. Mining for a lower `T` is not itself
    /// an offence — a JDC picks its own template, and settlement books from
    /// whatever the coinbase actually paid. What must not happen is a job
    /// arriving on the mining connection that is not the one the node
    /// validated at declare time.
    ///
    /// Both directions in one test, so it cannot pass on a precondition
    /// that silently did not hold: the declared coinbase is accepted, the
    /// substituted one is rejected.
    #[test]
    fn a_swapped_coinbase_paying_the_same_distribution_is_still_rejected() {
        let token = Token([1u8; 16]);
        let entry = distribution_entry(None);
        let declared_blob = conformant_outputs(&entry, 312_500_000);
        let halved_blob = conformant_outputs(&entry, 156_250_000);
        assert_ne!(declared_blob, halved_blob, "the two revenues must differ");

        // Pin the premise the whole test rests on: BOTH blobs satisfy §7.1
        // against this distribution, so the payout check cannot tell them
        // apart and only the binding can. Left implicit, a later change to
        // dust pruning or rounding could make the halved vector
        // non-conformant — §7.1 would then be the thing rejecting it, except
        // it never gets the chance, because the binding runs first. The test
        // would stay green and stop demonstrating anything.
        for (label, blob) in [("declared", &declared_blob), ("halved", &halved_blob)] {
            let outputs: Vec<bitcoin::TxOut> =
                bitcoin::consensus::deserialize(blob).expect("conformant blob must decode");
            assert!(
                crate::jdp::payout_distribution::validate_coinbase_outputs_against_distribution(
                    &outputs,
                    &entry.pool_payout,
                    &entry.payouts,
                    &entry.dust_limits,
                    &entry.additional_outputs,
                )
                .is_ok(),
                "the {label} coinbase must be §7.1-conformant, or this test \
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

    /// The case this module exists for: leave the coinbase alone and change
    /// the transaction set. §7.1 sees an untouched coinbase and passes, and
    /// nothing else on the mining side looks at the `merkle_path` — so the
    /// node validation `jdp_server` ran over the DECLARED set would carry
    /// over to a set no one checked.
    #[test]
    fn a_swapped_merkle_path_is_rejected() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);

        let honest = custom_job_matching(cid, &entry);
        assert!(!honest.merkle_path.is_empty(), "fixture must commit to txs");
        let out =
            handle_set_custom_mining_job(&mut s, &honest, Some(&job_ref_for(&entry)), None, 1_000);
        assert!(
            matches!(
                out.outbound[0],
                OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "the declared transaction set must still be accepted"
        );

        let mut swapped = custom_job_matching(cid, &entry);
        swapped.merkle_path[0] = [0xEE; 32];
        let out =
            handle_set_custom_mining_job(&mut s, &swapped, Some(&job_ref_for(&entry)), None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_DECLARATION_MISMATCH);
            }
            other => panic!("a swapped transaction set must not be minable, got {other:?}"),
        }
    }

    /// The fixture declaration and the fixture channel must reserve the same
    /// extranonce width, or every binding test below would be exercising a
    /// rejection instead of the case it means to test. Pinned rather than
    /// assumed: the channel's width comes from `session_with_extended_channel`
    /// and could be changed there without anyone noticing here.
    #[test]
    fn the_fixture_slot_matches_the_test_channel() {
        let s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        assert_eq!(
            s.channels.get(&cid).unwrap().full_extranonce_size(),
            FIXTURE_DECLARED_SLOT
        );
    }

    /// The declaration reserves a gap for the extranonce; the mining channel
    /// sizes its own. Nothing else in the binding compares the two — the
    /// committed scriptSig prefix stops exactly where the gap begins. But a
    /// found block is reassembled as declared_prefix || channel extranonce ||
    /// declared_suffix, and the declared prefix's scriptSig length covers the
    /// DECLARED gap, so a different width yields a coinbase that contradicts
    /// its own length field and a block lost at submit.
    ///
    /// Both directions: the matching width is accepted, a job whose channel
    /// disagrees with the declaration is refused at accept time.
    #[test]
    fn a_channel_extranonce_wider_than_the_declared_slot_is_rejected() {
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        let input = custom_job_matching(cid, &entry);

        let out =
            handle_set_custom_mining_job(&mut s, &input, Some(&job_ref_for(&entry)), None, 1_000);
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
        let out =
            handle_set_custom_mining_job(&mut s, &input, Some(&job_ref_for(&entry)), None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_DECLARATION_MISMATCH);
            }
            other => panic!("a mismatched extranonce width must be refused, got {other:?}"),
        }
    }

    /// The shape a REAL JDC declares in, accepted end to end.
    ///
    /// Every other binding fixture builds the witness-less coinbase our own
    /// builder emits. `channels_sv2::JobFactory` — what an SRI jd-client
    /// declares with — slices a SEGWIT-serialised one: marker+flag inside
    /// `coinbase_tx_prefix`, the witness inside `coinbase_tx_suffix`. Only
    /// the OUTPUTS were pinned for that shape (in `dynamic_outputs`);
    /// nothing pinned the scriptSig prefix, nSequence, locktime, the
    /// re-serialised output blob or the slot width.
    ///
    /// That gap was the dangerous kind: the binding fails closed, so a
    /// projection that read any of those differently would reject every real
    /// JDC's first job — dropping it into the fatal solo fallback — while the
    /// whole suite stayed green.
    ///
    /// The mined side here is built from the ORIGINAL transaction, not from
    /// the projection, so the two sides reach their bytes independently and
    /// the test can actually disagree.
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

        // Sliced exactly as JobFactory does: 4 version + 2 marker/flag
        // + 1 input count + 32 outpoint hash + 4 index + 1 scriptSig len.
        let raw = bitcoin::consensus::serialize(&tx);
        let index = 4 + 2 + 1 + 32 + 4 + 1 + script_sig_head.len();
        let (wtxid_list, raw_transactions) = fixture_declared_txs();
        let token = Token([1u8; 16]);
        let entry = RegisteredDeclaredJob {
            declared_job: JdpDeclaredJob {
                new_token: token,
                version: 0x2000_0000,
                coinbase_tx_prefix: raw[..index].to_vec(),
                coinbase_tx_suffix: raw[index + FIXTURE_DECLARED_SLOT..].to_vec(),
                wtxid_list,
                raw_transactions,
                prev_hash: Some([0xAB; 32]),
                declared_at_ms: 1_000,
                booking: None,
                distribution_id: None,
            },
            miner_address: AddressId::new(REGTEST_ADDR.to_string()).unwrap(),
            jdp_session_id: 42,
        };

        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        // Built from `tx`, independently of the projection under test. The
        // merkle_path carried over from `custom_job_input` is right for this
        // declaration too: the branch is the SIBLINGS of leaf 0, so it turns
        // on the transaction set (same `fixture_declared_txs`) and never on
        // the coinbase itself.
        let mut input = custom_job_input(cid, token);
        input.version = 0x2000_0000;
        input.coinbase_tx_version = tx.version.0 as u32;
        input.coinbase_prefix = script_sig_head.to_vec();
        input.coinbase_tx_input_n_sequence = tx.input[0].sequence.0;
        input.coinbase_tx_outputs = bitcoin::consensus::serialize(&tx.output);
        input.coinbase_tx_locktime = tx.lock_time.to_consensus_u32();

        let out =
            handle_set_custom_mining_job(&mut s, &input, Some(&job_ref_for(&entry)), None, 1_000);
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
    /// Reachable because a base-protocol declaration is stored without its
    /// coinbase ever being parsed — only the ext-0x0003 path does that at
    /// declare time.
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
        let out = handle_set_custom_mining_job(&mut s, &input, Some(&job_ref), None, 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_DECLARATION_MISMATCH);
            }
            other => panic!("an unprojectable declaration must not authorise, got {other:?}"),
        }
    }
}
