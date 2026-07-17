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
//! negotiation), `handle_set_custom_mining_job` (JDC integration), the
//! `JdcVardiff` variant in `apply_vardiff_check`, and Standard-channel
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

use crate::extensions::{RequestExtensions, SV2_EXTENSION_TYPE_WORKER_ID};

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
use super::vardiff::JdcVardiff;

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
/// the bridge miner-address in via [`handle_set_custom_mining_job`]'s
/// `bridge_miner_address` argument; pass `None` to skip validation.
pub const ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH: &str = "invalid-job-param-value-token-mismatch";

/// `invalid-job-param-value-coinbase_tx_outputs` — the
/// `SetCustomMiningJob.coinbase_tx_outputs` doesn't carry one of the pool's
/// committed ext-0x0003 payout outputs (missing / modified / reduced /
/// under-counted vs a duplicate), or didn't parse. The mined coinbase MUST
/// carry the committed set (spec §4); passed in via `payout_set`.
pub const ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS: &str =
    "invalid-job-param-value-coinbase_tx_outputs";

/// `stale-payout-outputs` — the ext-0x0003 payout set referenced by this
/// `SetCustomMiningJob` was already consumed (single-use, spec §4). The JDC
/// must request a fresh set and re-declare.
pub const ERR_STALE_PAYOUT_OUTPUTS: &str =
    crate::extensions::payout_outputs_error_codes::STALE_PAYOUT_OUTPUTS;

/// Set of SV2 mining-side extensions our pool supports:
/// Worker-ID TLV (0x0002)
/// — Worker-ID TLV for per-share worker attribution on
/// `SubmitSharesExtended`. The Non-Custodial-Pool-Payouts extension
/// (`0x0003`) is JDP-side, not mining-side; it negotiates over the
/// JDP connection and lives in `jdp::client` (deferred).
pub const SUPPORTED_MINING_EXTENSIONS: &[u16] = &[SV2_EXTENSION_TYPE_WORKER_ID];

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

    // Connection default/initial difficulty; also the JDC vardiff base.
    // Classic per-channel vardiff lives in `vardiff` (keyed by channel id).
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
    /// don't combine into one inflated rate. Standard + Extended channels;
    /// JDC channels retarget via `jdc_vardiff` instead.
    pub vardiff: HashMap<u32, VarDiffEngine<C>>,
    pub jdc_vardiff: JdcVardiff,

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
    /// JDC-vardiff check cadence (ms). 0 disables JDC vardiff entirely
    /// (defensive — JDC `check()` already no-ops on `interval_ms == 0`).
    pub vardiff_interval_ms: u64,

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
    /// Cadence of the JDC vardiff check loop in milliseconds.
    /// Typical 60 000. Classic vardiff reads its own cadence from
    /// [`bp_vardiff`] and ignores this.
    pub vardiff_interval_ms: u64,
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
            jdc_vardiff: JdcVardiff::new(),
            clock,
            min_difficulty: port.min_difficulty,
            initial_difficulty: Difficulty(
                port.initial_difficulty
                    .as_f64()
                    .max(port.min_difficulty.as_f64()),
            ),
            target_shares_per_minute: port.target_shares_per_minute,
            vardiff_interval_ms: port.vardiff_interval_ms,
            share_logs: false,
        }
    }

    /// A fresh classic vardiff engine for a newly opened channel, seeded
    /// from the connection's configured target shares/min and difficulty
    /// floor.
    fn new_channel_vardiff(&self) -> VarDiffEngine<C> {
        VarDiffEngine::new(
            self.clock.clone(),
            self.target_shares_per_minute,
            self.min_difficulty.as_f64(),
        )
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
    let engine = state.new_channel_vardiff();
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
    let engine = state.new_channel_vardiff();
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
fn floor_assigned_difficulty(diff: Difficulty) -> Difficulty {
    let v = diff.as_f64();
    if !v.is_finite() || v < 1.0 {
        // Non-finite, or an intentionally sub-1 difficulty (a tiny
        // configured min/initial, e.g. on regtest): leave it untouched.
        // Flooring would zero it; forcing it up to 1.0 would override the
        // operator's configured difficulty. The integer floor below only
        // applies once there is a whole share's worth to round.
        return diff;
    }
    Difficulty(v.floor())
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

    // Initial difficulty. SV2 miners advertise `nominal_hash_rate`; derive
    // from it when present, but never start below the operator-configured
    // initial difficulty. Some firmware under-reports (or reports 0) its
    // rate — without the floor that pins the channel to a trivial target
    // that wastes share bandwidth (and, on strict firmware, can stall)
    // until vardiff catches up. `nominal_hash_rate <= 0` starts at the
    // configured initial difficulty; an honest higher rate starts above it.
    let derived = if nominal_hash_rate > 0.0 {
        hash_rate_to_difficulty(nominal_hash_rate as f64, state.target_shares_per_minute)
    } else {
        state.initial_difficulty
    };
    let floored = Difficulty(
        derived
            .as_f64()
            .max(state.initial_difficulty.as_f64())
            .max(state.min_difficulty.as_f64()),
    );
    // Clamp against the miner's declared max_target (raises the floor to
    // the miner's minimum acceptable difficulty if it declared one).
    let clamped = clamp_difficulty_to_max_target(floored, &Target::from_le_bytes(max_target_bytes));
    let assigned_difficulty = if clamped.as_f64() > MAX_REASONABLE_DIFFICULTY {
        return Err(err(ERR_MAX_TARGET_OUT_OF_RANGE));
    } else {
        // Whole-integer floor so decimal-truncating miners (SV1 via
        // translator) don't undershoot a fractional target.
        floor_assigned_difficulty(clamped)
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
    if let ShareValidation::Accepted(ref accept) = validation {
        if let Some(engine) = state.vardiff.get_mut(&submission.channel_id) {
            engine.update_hash_rate(accept.effective_difficulty.as_f64(), true);
        }
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
    let ext_job = channel
        .extended_jobs
        .get(&submission.job_id)
        .expect("ext_job presence checked above");
    // The prefix is no longer part of the view: the validator reads it off
    // `ext_job` itself (SV2 §5.3.10 — a new prefix only takes effect from the
    // next job on, so a share for an older job must be reconstructed with the
    // prefix that job went out under). Sourcing it from the channel here is
    // what would silently reject every in-flight share after a change.
    let view = ExtendedChannelView {
        kind: channel.kind,
        extranonce_size: channel.extranonce_size,
        job_target,
    };

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
    // field; re-borrow the channel below for finalize.
    if let ShareValidation::Accepted(ref accept) = validation {
        if let Some(engine) = state.vardiff.get_mut(&submission.channel_id) {
            engine.update_hash_rate(accept.effective_difficulty.as_f64(), true);
        }
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
            // Cache the actual solved difficulty (post-hash) so the JDC
            // vardiff branch can cap retargets at proven work.
            channel.last_submission_difficulty = Some(accept.submission_difficulty);
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

    let Some(channel) = state.channels.get_mut(&input.channel_id) else {
        return HandlerOutcome::with_frame(OutboundFrame::UpdateChannelError {
            channel_id: input.channel_id,
            error_code: ERR_INVALID_CHANNEL_ID.to_string(),
        });
    };

    channel.declared_max_target = input.maximum_target;

    let raw = hash_rate_to_difficulty(input.nominal_hash_rate as f64, target_shares_per_minute);
    let clamped = clamp_difficulty_to_max_target(raw, &Target::from_le_bytes(input.maximum_target));
    let new_diff = if clamped < min_difficulty {
        min_difficulty
    } else if clamped.as_f64() > MAX_REASONABLE_DIFFICULTY {
        // Keep the existing difficulty rather than accepting an
        // unreasonable value. Miner can retry with a larger max_target.
        return HandlerOutcome::default();
    } else {
        // Whole-integer floor — same rationale as the channel-open path.
        floor_assigned_difficulty(clamped)
    };

    if (new_diff.as_f64() - channel.session_difficulty.as_f64()).abs() < f64::EPSILON {
        return HandlerOutcome::default();
    }
    let old = channel.session_difficulty;
    channel.session_difficulty = new_diff;
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

/// Periodic vardiff tick. For each non-JDC channel, reads that channel's
/// own [`bp_vardiff::VarDiffEngine::suggested_difficulty`] against the
/// channel's current difficulty; if a retarget is recommended it clamps
/// against the channel's `declared_max_target`, updates the channel's
/// difficulty, and emits `SetTarget` + `DifficultyChanged`. Each channel
/// retargets independently from its own share rate — SV2 difficulty is per
/// channel, so several channels on one connection never pool their rate.
///
/// JDC channels (`is_jdc=true`) are skipped here — they retarget via
/// [`crate::mining::vardiff::JdcVardiff::check`] on a different cadence
/// (share-count-based instead of sample-window based).
pub fn apply_vardiff_check<C: Clock>(state: &mut MiningSessionState<C>) -> HandlerOutcome {
    // SV2 vardiff has two algorithms — see `mining/vardiff.rs` for the
    // why. If the primary channel is a Job-Declaration-Client, use
    // the JDC-specific algorithm; otherwise fall through to classic
    // shares-per-minute via [`bp_vardiff::VarDiffEngine`].
    let primary_is_jdc = state
        .primary_channel
        .and_then(|cid| state.channels.get(&cid))
        .map(|ch| ch.is_jdc)
        .unwrap_or(false);
    if primary_is_jdc {
        return apply_jdc_vardiff_check(state);
    }

    // Disjoint &mut borrows of the two sibling fields so each channel can
    // read+update its own vardiff engine and difficulty in one pass.
    let mut outcome = HandlerOutcome::default();
    let MiningSessionState {
        channels, vardiff, ..
    } = state;
    for channel in channels.values_mut() {
        if channel.is_jdc {
            continue;
        }
        let Some(engine) = vardiff.get_mut(&channel.channel_id) else {
            continue;
        };
        let Some(suggested) = engine.suggested_difficulty(channel.session_difficulty.as_f64())
        else {
            continue;
        };
        let clamped = clamp_difficulty_to_max_target(
            Difficulty(suggested),
            &Target::from_le_bytes(channel.declared_max_target),
        );
        if (clamped.as_f64() - channel.session_difficulty.as_f64()).abs() >= f64::EPSILON {
            let old = channel.session_difficulty;
            channel.session_difficulty = clamped;
            outcome.push_frame(OutboundFrame::SetTarget {
                channel_id: channel.channel_id,
                maximum_target: difficulty_to_target(clamped).to_le_bytes(),
            });
            outcome.push_event(SessionEvent::DifficultyChanged { old, new: clamped });
        }
    }
    outcome
}

/// JDC variant of [`apply_vardiff_check`]. Runs only when the primary
/// channel is JDC-flagged. Reads the primary channel's
/// `accepted_share_count` + `last_submission_difficulty` snapshot,
/// asks [`JdcVardiff::check`] for a target, then propagates to every
/// JDC channel (clamped per-channel against `declared_max_target`).
///
/// Non-JDC channels on the same connection are untouched — the
/// classic-vardiff loop next tick handles them. In practice JDC and
/// non-JDC channels don't share a connection, so this is just
/// defensive.
fn apply_jdc_vardiff_check<C: Clock>(state: &mut MiningSessionState<C>) -> HandlerOutcome {
    use crate::mining::vardiff::JdcVardiffOutcome;

    let Some(primary_id) = state.primary_channel else {
        return HandlerOutcome::default();
    };
    let Some(primary) = state.channels.get(&primary_id) else {
        return HandlerOutcome::default();
    };
    let accepted = primary.accepted_share_count;
    let latest_submit = primary
        .last_submission_difficulty
        .map(|d| d.as_f64())
        .unwrap_or(0.0);

    let outcome = state.jdc_vardiff.check(
        accepted,
        state.session_difficulty.as_f64(),
        state.target_shares_per_minute,
        state.vardiff_interval_ms,
        latest_submit,
    );
    let new_diff = match outcome {
        JdcVardiffOutcome::NoChange => return HandlerOutcome::default(),
        JdcVardiffOutcome::Retarget(d) => Difficulty(d),
    };

    let old = state.session_difficulty;
    state.session_difficulty = new_diff;

    let mut result = HandlerOutcome::default();
    for channel in state.channels.values_mut() {
        if !channel.is_jdc {
            continue;
        }
        let clamped = clamp_difficulty_to_max_target(
            new_diff,
            &Target::from_le_bytes(channel.declared_max_target),
        );
        if (clamped.as_f64() - channel.session_difficulty.as_f64()).abs() >= f64::EPSILON {
            channel.session_difficulty = clamped;
            result.push_frame(OutboundFrame::SetTarget {
                channel_id: channel.channel_id,
                maximum_target: difficulty_to_target(clamped).to_le_bytes(),
            });
        }
    }
    result.push_event(SessionEvent::DifficultyChanged { old, new: new_diff });
    result
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
        if channel.is_jdc {
            continue;
        }

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
                    merkle_path: merkle_path.clone(),
                    version: template.version,
                    prev_hash: template.prev_hash,
                    n_bits: template.n_bits,
                    min_ntime: template.header_timestamp,
                    extranonce_prefix: channel.extranonce_prefix.clone(),
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
    // fields) for `full_size`. The `difficulty` and `extranonce_prefix`
    // placeholders are overridden per member — members share the job but each
    // holds its own prefix. `None` if the mining-job build fails.
    let build_group_template = |full_size: usize| -> Option<GroupTemplateParts> {
        let mining_job = mining_job_inputs.build(full_size).ok()?;
        let tx_prefix = mining_job.coinbase_prefix().to_vec();
        let tx_suffix = mining_job.coinbase_suffix().to_vec();
        let merkle_path = template.merkle_path.clone();
        let tmpl = ExtendedJob {
            coinbase_prefix: tx_prefix.clone(),
            coinbase_suffix: tx_suffix.clone(),
            merkle_path: merkle_path.clone(),
            version: template.version,
            prev_hash: template.prev_hash,
            n_bits: template.n_bits,
            min_ntime: template.header_timestamp,
            extranonce_prefix: Vec::new(),
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
                        job.extranonce_prefix = ch.extranonce_prefix.clone();
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
                ext_job.extranonce_prefix = channel.extranonce_prefix.clone();
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
}

/// Handle `SetCustomMiningJob`.
///
/// **Caller-resolved context**: the IO layer looks up the declared-job
/// entry for `mining_job_token` in [`crate::bridge::JdpDeclaredJobRegistry`]
/// and passes only its `miner_address` as `bridge_miner_address` (cloning
/// the address, not the whole entry — the handler doesn't need the job
/// payload). If `Some(addr)`, the handler cross-checks the channel's locked
/// miner address against it; mismatch → reject
/// `invalid-job-param-value-token-mismatch`. `None` skips the check.
///
/// **ext 0x0003 payout validation**: the IO layer also passes the issued
/// payout set (`payout_set`) for `mining_job_token`, if any. When present,
/// the submitted `coinbase_tx_outputs` MUST carry every pool-committed
/// output (multiset, spec §4), the set MUST be unused (single-use), and the
/// channel address MUST match the set's miner (the sole cross-account guard
/// in Coinbase-only mode, where there is no `RegisteredDeclaredJob`). The IO
/// layer single-use-consumes the set after a `Success`. `None` → no payout
/// enforcement (non-0x0003 / base-protocol custom job).
///
/// - Channel unknown → `SetCustomMiningJobError` with
///   `invalid-channel-id`.
/// - Channel kind ≠ Extended → `invalid-job-id` (Standard channels
///   don't carry an extranonce slot — custom jobs are
///   Extended-only).
/// - Bridge miner-address present + mismatch →
///   `invalid-job-param-value-token-mismatch`.
/// - Else: rebuild `coinbase_tx_prefix` + `coinbase_tx_suffix` from
///   the JDC's scriptSig fragments, allocate
///   `channel.next_job_id`, insert [`ExtendedJob`] (with
///   `template_id = None` — custom job), emit
///   `SetCustomMiningJobSuccess`.
pub fn handle_set_custom_mining_job<C: Clock>(
    state: &mut MiningSessionState<C>,
    input: &SetCustomMiningJobInput,
    bridge_miner_address: Option<&AddressId>,
    payout_set: Option<&crate::bridge::IssuedPayoutSet>,
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

    // Channel-locked miner address — cross-checked below against the bridge
    // entry and/or the issued payout set.
    let channel_addr = state.address.as_ref().map(|a| a.as_str()).unwrap_or("");

    // Optional bridge cross-check: a declared-job hit's miner address MUST
    // match the channel's locked address (stops one miner claiming another's
    // declared job).
    if let Some(bridge_addr) = bridge_miner_address {
        if channel_addr != bridge_addr.as_str() {
            return reject(ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
        }
    }

    // ext 0x0003 (Non-Custodial Pool Payouts): when a payout set was issued
    // for this token, the submitted coinbase is the one the miner actually
    // hashes, so it MUST carry every pool-committed output (multiset, spec §4)
    // — binding the mined coinbase to the set (Full-Template) and the Pool's
    // sole validation point (Coinbase-only, §5.3). Single-use; the channel
    // address MUST match the set's miner (the only cross-account guard without
    // a declared-job entry); and the set MUST NOT be from a superseded epoch.
    // The IO layer consumes the set after this returns Success.
    if let Some(set) = payout_set {
        if set.used {
            return reject(ERR_STALE_PAYOUT_OUTPUTS);
        }
        // Epoch staleness (spec §4 MAY): if the job builds on a different tip
        // than the set was issued under, the distribution is superseded. A JDC
        // can't dodge this — a faked prev_hash orphans the block. Closes the
        // request→submit window in both JD modes (Full-Template's per-connection
        // check stops at declare).
        if let Some(issued) = set.issued_prev_hash {
            if input.prev_hash != issued {
                return reject(ERR_STALE_PAYOUT_OUTPUTS);
            }
        }
        if channel_addr != set.miner_address.as_str() {
            return reject(ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
        }
        // `coinbase_tx_outputs` is the clean consensus `Vec<TxOut>` blob — parse
        // both sides and compare the multiset. Fail closed on a parse error.
        let declared: Vec<bitcoin::TxOut> =
            match bitcoin::consensus::deserialize(&input.coinbase_tx_outputs) {
                Ok(v) => v,
                Err(_) => return reject(ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS),
            };
        let committed: Vec<bitcoin::TxOut> = match bitcoin::consensus::deserialize(&set.outputs) {
            Ok(v) => v,
            Err(_) => return reject(ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS),
        };
        if crate::jdp::dynamic_outputs::first_uncovered_committed_output(&declared, &committed)
            .is_some()
        {
            return reject(ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS);
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
            merkle_path: input.merkle_path.clone(),
            version: input.version,
            prev_hash: input.prev_hash,
            n_bits: input.n_bits,
            min_ntime: input.min_ntime,
            extranonce_prefix: channel.extranonce_prefix.clone(),
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
            firmware: "0.1".to_string(),
            hardware_version: "rev1".to_string(),
            device_id: "dev-1".to_string(),
        }
    }

    fn open_std(req_id: u32, user: &str) -> OpenStandardMiningChannelInput {
        OpenStandardMiningChannelInput {
            request_id: req_id,
            user_identity: user.to_string(),
            nominal_hash_rate: 1_000.0,
            max_target: [0xFF; 32],
        }
    }

    fn open_ext(req_id: u32, user: &str) -> OpenExtendedMiningChannelInput {
        OpenExtendedMiningChannelInput {
            request_id: req_id,
            user_identity: user.to_string(),
            nominal_hash_rate: 1_000_000.0,
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
    fn open_standard_floors_initial_difficulty_at_configured_start() {
        // Tiny nominal (1000 H/s → sub-1 derived) → floored to initial 1024.
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(7, &format!("{REGTEST_ADDR}.w")),
            vec![0x01, 0x02, 0x03, 0x04],
        );
        assert_eq!(
            s.channels[&1].session_difficulty.as_f64(),
            1024.0,
            "tiny nominal must floor to the configured initial difficulty"
        );

        // nominal_hash_rate = 0 → also the configured initial difficulty.
        let mut s0 = fresh_session();
        handle_setup_connection(&mut s0, &good_setup());
        let mut zero = open_std(8, &format!("{REGTEST_ADDR}.w"));
        zero.nominal_hash_rate = 0.0;
        let _ = handle_open_standard_mining_channel(&mut s0, &zero, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(s0.channels[&1].session_difficulty.as_f64(), 1024.0);

        // An honest high nominal (~5 PH/s) starts ABOVE the floor.
        let mut sh = fresh_session();
        handle_setup_connection(&mut sh, &good_setup());
        let mut big = open_std(9, &format!("{REGTEST_ADDR}.w"));
        big.nominal_hash_rate = 5.0e15;
        let _ = handle_open_standard_mining_channel(&mut sh, &big, vec![0x01, 0x02, 0x03, 0x04]);
        assert!(
            sh.channels[&1].session_difficulty.as_f64() > 1024.0,
            "an honest high nominal must start above the configured floor"
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

    /// `hash_rate_to_difficulty` produces fractional diffs (e.g.
    /// 931.31); the channel must store the integer floor so a
    /// decimal-truncating miner can't undershoot the target. Once the
    /// stored diff is a whole integer, the `[931, 931.31)` rejection
    /// band cannot exist at all.
    #[test]
    fn open_channel_assigns_integer_difficulty() {
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
        assert_eq!(assigned, raw.floor());
    }

    #[test]
    fn floor_assigned_difficulty_floors_and_bounds() {
        // Typical fractional case from hash_rate_to_difficulty.
        assert_eq!(
            floor_assigned_difficulty(Difficulty(931.31)).as_f64(),
            931.0
        );
        // Already-integer values pass through.
        assert_eq!(
            floor_assigned_difficulty(Difficulty(1024.0)).as_f64(),
            1024.0
        );
        // Sub-1 diffs pass through unchanged — neither floored to 0 nor
        // forced up to 1.0 (an intentionally low configured difficulty).
        assert_eq!(floor_assigned_difficulty(Difficulty(0.7)).as_f64(), 0.7);
        // Non-positive / non-finite pass through for the caller's guards.
        assert_eq!(floor_assigned_difficulty(Difficulty(0.0)).as_f64(), 0.0);
        assert!(floor_assigned_difficulty(Difficulty(f64::NAN))
            .as_f64()
            .is_nan());
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
            coinbase_prefix: vec![0xAA; 8],
            coinbase_suffix: vec![0xBB; 8],
            merkle_path: vec![[0u8; 32]],
            // Matches the prefix the channel above was opened with — the
            // validator reconstructs the coinbase from the job's copy.
            extranonce_prefix: vec![0; 4],
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

    /// A share for a job issued under the OLD extranonce prefix stays valid
    /// after the channel's prefix changes.
    ///
    /// SV2 §5.3.10: `SetExtranoncePrefix` takes effect from the NEXT job on,
    /// so a miner still working an older job keeps building its coinbase with
    /// the prefix that job went out under. The validator has to reconstruct
    /// with that same prefix — reading the channel's current one instead makes
    /// the coinbase diverge and rejects every in-flight share as diff-too-low.
    ///
    /// Pins the reason `ExtendedJob::extranonce_prefix` exists: source the
    /// prefix from `channel.extranonce_prefix` in the validator and this fails.
    ///
    /// Asserts on the derived HASH, not on accept/reject. The job difficulty
    /// here is trivial (target ≈ MAX), so a coinbase reconstructed from the
    /// wrong prefix still hashes to something that clears the target and gets
    /// accepted — accept/reject cannot tell the two apart. The hash can: it is
    /// a direct fingerprint of which coinbase the validator actually built.
    #[test]
    fn submit_extended_accepts_share_for_job_issued_under_previous_prefix() {
        const OLD_PREFIX: [u8; 4] = [0xC0, 0xDE, 0xBA, 0xBE];
        const NEW_PREFIX: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

        // Validate one fixed share for job 7 — always issued under OLD_PREFIX —
        // against a channel whose CURRENT prefix is `channel_prefix`. Returns
        // the hash the validator derived. Each call gets its own session so the
        // dedup cache never sees the submission twice.
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
                min_ntime: 0,
                difficulty: Difficulty(1.0 / 4_294_967_296.0),
                network_difficulty: Difficulty(1e15),
                coinbase_tx_value_remaining: 5_000_000_000,
                template_id: None,
                created_at: 0,
                retired_at: None,
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
                tail_tlvs: Vec::new(),
            };
            let out = handle_submit_shares_extended(&mut s, &sub, 0);
            match out.events.first() {
                Some(SessionEvent::ShareAccepted { accept, .. }) => accept.hash,
                other => panic!("expected ShareAccepted, got {other:?}"),
            }
        }

        // Reference: nothing changed yet — the channel still holds the prefix
        // job 7 went out under, so this is the coinbase the miner hashed.
        let miner_hash = hash_for(OLD_PREFIX);
        // Now the prefix changes mid-session. Job 7 predates the change, so per
        // SV2 §5.3.10 the miner keeps hashing OLD_PREFIX until the next job —
        // validation must land on exactly the same hash.
        let after_prefix_change = hash_for(NEW_PREFIX);
        assert_eq!(
            miner_hash, after_prefix_change,
            "changing the channel's extranonce prefix must not change how a \
             share for a job issued under the PREVIOUS prefix validates — \
             sourcing the prefix from the channel rebuilds a coinbase the miner \
             never hashed (SV2 §5.3.10)"
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
        // 0x0002 is supported (mining-side); 0x0003 is JDP-side
        // (rejected here); 0x00FF is bogus.
        let out = handle_request_extensions(&mut s, &req_ext(9, vec![0x0002, 0x0003, 0x00FF]));
        match &out.outbound[0] {
            OutboundFrame::RequestExtensionsSuccess {
                request_id,
                supported_extensions,
            } => {
                assert_eq!(*request_id, 9);
                assert_eq!(supported_extensions, &vec![0x0002]);
            }
            _ => panic!("expected Success-with-subset"),
        }
        assert!(s.negotiated_extensions.contains(&0x0002));
        assert!(!s.negotiated_extensions.contains(&0x0003));
        assert!(!s.negotiated_extensions.contains(&0x00FF));
    }

    /// All requested unsupported AND request non-empty → Error.
    #[test]
    fn request_extensions_all_unsupported_emits_error() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let out = handle_request_extensions(
            &mut s,
            &req_ext(
                3,
                vec![0x00AA, 0x00BB, SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS],
            ),
        );
        match &out.outbound[0] {
            OutboundFrame::RequestExtensionsError {
                request_id,
                unsupported_extensions,
                required_extensions,
            } => {
                assert_eq!(*request_id, 3);
                assert_eq!(
                    unsupported_extensions,
                    &vec![0x00AA, 0x00BB, SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS]
                );
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

    /// JDC-flagged channels are skipped (they get jobs via
    /// `SetCustomMiningJob` instead).
    #[test]
    fn template_broadcast_skips_jdc_channels() {
        let mut s = session_with_standard_channel();
        let cid = s.primary_channel.unwrap();
        s.channels.get_mut(&cid).unwrap().is_jdc = true;
        let mj = synthetic_mining_job_inputs();
        let out = apply_template_broadcast(
            &mut s,
            &broadcast(TemplateChange::NewBlock, [0xAB; 32]),
            &mj,
            1_000,
            None,
        );
        assert!(out.outbound.is_empty(), "JDC channel must be skipped");
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
                    coinbase_prefix: vec![],
                    coinbase_suffix: vec![],
                    merkle_path: vec![],
                    extranonce_prefix: vec![],
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

    // ── apply_vardiff_check JDC branch ─────────────────────────────

    /// When the primary channel is JDC-flagged, the JDC algorithm
    /// fires and emits SetTarget for JDC channels. The accepted-share
    /// counter on the primary drives the JDC algorithm; we pre-seed
    /// 12 accepted shares over a 60-s window → ratio 2.0 (boundary) →
    /// retarget to 2× current_diff capped at latest_submit.
    #[test]
    fn apply_vardiff_check_jdc_branch_retargets_when_primary_jdc() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        s.session_difficulty = Difficulty(1024.0);
        {
            let ch = s.channels.get_mut(&cid).unwrap();
            ch.is_jdc = true;
            ch.session_difficulty = Difficulty(1024.0);
            ch.accepted_share_count = 12;
            ch.last_submission_difficulty = Some(Difficulty(4096.0));
        }
        let out = apply_vardiff_check(&mut s);
        // Ratio = 12 spm / 6 spm target = 2.0 → boundary retarget.
        // 1024 * 2.0 = 2048; cap = 4096; step(2048) = 2048.
        assert_eq!(s.session_difficulty, Difficulty(2048.0));
        // Emitted a SetTarget for the JDC channel.
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetTarget { channel_id: emitted_cid, .. } if emitted_cid == cid
        ));
        assert!(out
            .events
            .iter()
            .any(|e| matches!(e, SessionEvent::DifficultyChanged { .. })));
    }

    /// JDC branch returns NoChange when share count below
    /// `JDC_MIN_SHARES_PER_INTERVAL = 2`.
    #[test]
    fn apply_vardiff_check_jdc_branch_no_change_when_below_min_shares() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        s.session_difficulty = Difficulty(1024.0);
        {
            let ch = s.channels.get_mut(&cid).unwrap();
            ch.is_jdc = true;
            ch.session_difficulty = Difficulty(1024.0);
            ch.accepted_share_count = 1;
            ch.last_submission_difficulty = Some(Difficulty(4096.0));
        }
        let out = apply_vardiff_check(&mut s);
        assert!(out.outbound.is_empty());
        assert_eq!(s.session_difficulty, Difficulty(1024.0));
    }

    /// `last_submission_difficulty` gets populated on each accepted
    /// share — the JDC vardiff branch depends on this snapshot.
    #[test]
    fn accepted_submit_caches_last_submission_difficulty() {
        let mut s = fresh_session();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_open_standard_mining_channel(
            &mut s,
            &open_std(1, &format!("{}.w", REGTEST_ADDR)),
            vec![0; 4],
        );
        let cid = s.primary_channel.unwrap();
        let easy = Difficulty(1.0 / 4_294_967_296.0);
        {
            let ch = s.channels.get_mut(&cid).unwrap();
            ch.standard_jobs
                .record_send_for_test(7, easy, [0xDD; 32], snapshot(), 0);
        }
        let sub = SubmitSharesStandardInput {
            channel_id: cid,
            sequence_number: 1,
            job_id: 7,
            nonce: 0x1234_5678,
            version: 0x2000_0000,
            ntime: 0x6500_0001,
        };
        let _ = handle_submit_shares_standard(&mut s, &sub, 0);
        let ch = s.channels.get(&cid).unwrap();
        assert!(
            ch.last_submission_difficulty.is_some(),
            "submission_difficulty must be cached after accept"
        );
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

    /// Standard SetCustomMiningJob input with one minimal scriptSig
    /// prefix byte + a 1-byte output blob. Per-test override-able.
    fn custom_job_input(channel_id: u32, token: Token) -> SetCustomMiningJobInput {
        SetCustomMiningJobInput {
            channel_id,
            request_id: 1,
            mining_job_token: token,
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            min_ntime: 0x6500_0001,
            n_bits: 0x1d00_ffff,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![0x03, 0xC8, 0x00], // BIP-34 height push
            coinbase_tx_input_n_sequence: 0xFFFF_FFFF,
            coinbase_tx_outputs: vec![0x00], // empty output count varint
            coinbase_tx_locktime: 0,
            merkle_path: vec![[0x11; 32], [0x22; 32]],
        }
    }

    fn bridge_entry_for(token: Token, address: &str, session_id: u32) -> RegisteredDeclaredJob {
        RegisteredDeclaredJob {
            declared_job: JdpDeclaredJob {
                new_token: token,
                original_token: Token([0u8; 16]),
                request_id: 1,
                version: 0x2000_0000,
                coinbase_tx_prefix: vec![],
                coinbase_tx_suffix: vec![],
                wtxid_list: vec![],
                raw_transactions: Map::new(),
                prev_hash: Some([0xAB; 32]),
                declared_at_ms: 1_000,
            },
            miner_address: AddressId::new(address.to_string()).unwrap(),
            jdp_session_id: session_id,
            registered_at_ms: 1_000,
        }
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

    /// Extended channel + no bridge entry → accept without validation.
    /// Verify ExtendedJob is stored with assembled non-witness
    /// coinbase prefix/suffix.
    #[test]
    fn set_custom_mining_job_extended_accepts_and_stores_ext_job() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let input = custom_job_input(cid, token);
        let out = handle_set_custom_mining_job(&mut s, &input, None, None, 1_000);
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

    /// Bridge entry whose miner_address matches the channel's locked
    /// address → accept. Verifies the cross-check.
    #[test]
    fn set_custom_mining_job_bridge_entry_matching_address_accepts() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let entry = bridge_entry_for(token, REGTEST_ADDR, 42);
        let input = custom_job_input(cid, token);
        let out =
            handle_set_custom_mining_job(&mut s, &input, Some(&entry.miner_address), None, 1_000);
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
            handle_set_custom_mining_job(&mut s, &input, Some(&entry.miner_address), None, 1_000);
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

    // ── ext 0x0003 payout-set validation on SetCustomMiningJob ─────

    /// Consensus `Vec<TxOut>` blob paying `sats` to the channel's locked
    /// regtest address — used as both the committed set and (when carried)
    /// the submitted `coinbase_tx_outputs`.
    fn payout_outputs_blob(sats: i64) -> Vec<u8> {
        use crate::jdp::dynamic_outputs::{encode_coinbase_outputs, DynamicOutput};
        use bp_common::Sats;
        encode_coinbase_outputs(
            bitcoin::Network::Regtest,
            &[DynamicOutput {
                address: AddressId::new(REGTEST_ADDR.to_string()).unwrap(),
                sats: Sats(sats),
            }],
        )
        .unwrap()
    }

    fn issued_payout_set(
        outputs: Vec<u8>,
        address: &str,
        used: bool,
    ) -> crate::bridge::IssuedPayoutSet {
        crate::bridge::IssuedPayoutSet {
            outputs,
            miner_address: AddressId::new(address.to_string()).unwrap(),
            jdp_session_id: 42,
            registered_at_ms: 1_000,
            // Matches custom_job_input's prev_hash → fresh (not stale).
            issued_prev_hash: Some([0xAB; 32]),
            used,
        }
    }

    /// Submitted coinbase carries the committed payout output → accept.
    #[test]
    fn set_custom_mining_job_payout_set_carried_accepts() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let committed = payout_outputs_blob(600);
        let set = issued_payout_set(committed.clone(), REGTEST_ADDR, false);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.coinbase_tx_outputs = committed;
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&set), 1_000);
        assert!(matches!(
            out.outbound[0],
            OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
    }

    /// Submitted coinbase omits the committed payout output → reject; no
    /// ExtendedJob stored.
    #[test]
    fn set_custom_mining_job_payout_set_missing_output_rejects() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let set = issued_payout_set(payout_outputs_blob(600), REGTEST_ADDR, false);
        // Default input carries an empty `coinbase_tx_outputs` ([0x00]).
        let input = custom_job_input(cid, Token([1u8; 16]));
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&set), 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS);
            }
            other => panic!("expected coinbase-outputs error, got {other:?}"),
        }
        assert!(s.channels.get(&cid).unwrap().extended_jobs.is_empty());
    }

    /// An already-consumed (single-use) payout set → reject stale.
    #[test]
    fn set_custom_mining_job_used_payout_set_rejects_stale() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let committed = payout_outputs_blob(600);
        let set = issued_payout_set(committed.clone(), REGTEST_ADDR, true);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.coinbase_tx_outputs = committed;
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&set), 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_PAYOUT_OUTPUTS);
            }
            other => panic!("expected stale error, got {other:?}"),
        }
    }

    /// Payout set bound to a DIFFERENT miner than the channel → reject
    /// (cross-account guard, the only such check in Coinbase-only mode).
    #[test]
    fn set_custom_mining_job_payout_set_address_mismatch_rejects() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let committed = payout_outputs_blob(600);
        let other = "bcrt1q9h6ks0scwrsvz8ku4eqkxh5sx5xkw6vqxttzva";
        let set = issued_payout_set(committed.clone(), other, false);
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.coinbase_tx_outputs = committed;
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&set), 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH);
            }
            other => panic!("expected token-mismatch error, got {other:?}"),
        }
    }

    /// ext 0x0003 §4 (MAY): a payout set issued under a different pool tip
    /// than the submitted job's prev_hash is stale → reject. Closes the
    /// request→SetCustomMiningJob window in both JD modes.
    #[test]
    fn set_custom_mining_job_stale_payout_set_rejects() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let committed = payout_outputs_blob(600);
        // Issued under tip 0xCC; the job (custom_job_input) builds on 0xAB.
        let set = crate::bridge::IssuedPayoutSet {
            outputs: committed.clone(),
            miner_address: AddressId::new(REGTEST_ADDR.to_string()).unwrap(),
            jdp_session_id: 42,
            registered_at_ms: 1_000,
            issued_prev_hash: Some([0xCC; 32]),
            used: false,
        };
        let mut input = custom_job_input(cid, Token([1u8; 16]));
        input.coinbase_tx_outputs = committed;
        let out = handle_set_custom_mining_job(&mut s, &input, None, Some(&set), 1_000);
        match &out.outbound[0] {
            OutboundFrame::SetCustomMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_PAYOUT_OUTPUTS);
            }
            other => panic!("expected stale error, got {other:?}"),
        }
    }

    /// Sequential SetCustomMiningJob frames on the same channel
    /// allocate monotonic job_ids.
    #[test]
    fn set_custom_mining_job_allocates_monotonic_job_ids() {
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let input1 = custom_job_input(cid, token);
        let out1 = handle_set_custom_mining_job(&mut s, &input1, None, None, 1_000);
        let mut input2 = custom_job_input(cid, token);
        input2.request_id = 2;
        let out2 = handle_set_custom_mining_job(&mut s, &input2, None, None, 2_000);
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
        let mut s = session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let token = Token([1u8; 16]);
        let mut input = custom_job_input(cid, token);
        input.coinbase_prefix = vec![0xAA; 253];
        let _ = handle_set_custom_mining_job(&mut s, &input, None, None, 1_000);
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
}
