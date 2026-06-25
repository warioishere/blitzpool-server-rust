// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure handler-layer for the JDP-server per-connection state machine.
//!
//! Wraps the four pure-logic leafs ([`crate::tokens`],
//! [`crate::jdp::declarations`], [`crate::jdp::tx_validation`],
//! [`crate::jdp::dynamic_outputs`]) plus the [`crate::extensions`]
//! codecs into a connection-scoped state struct + a set of
//! [`handle_*`] functions. Mirrors the design of
//! [`crate::mining::client`]: pure-state, pure-handlers,
//! [`JdpHandlerOutcome`] + [`JdpSessionEvent`] for hook fan-out — no
//! I/O, no broadcasting, no DB writes.
//!
//! Each handler:
//! - Takes `&mut JdpSessionState` + the deserialized input + any
//!   caller-pre-resolved async-hook results (analogous to
//!   `apply_template_broadcast`'s pre-built `MiningJob` — see the
//!   per-handler doc for what the caller must resolve)
//! - Mutates state in place
//! - Returns [`JdpHandlerOutcome`] = `{ outbound: Vec<JdpOutboundFrame>,
//!   events: Vec<JdpSessionEvent> }`
//!
//! The IO layer (`jdp_server.rs`) drives a `tokio::select!`
//! loop over the Noise-wrapped TcpStream + per-connection inputs. On
//! each frame it deserializes, resolves any async hooks (mempool
//! validation / template-tx cache snapshot / dynamic-outputs
//! resolution), calls the matching handler, then serializes each
//! [`JdpOutboundFrame`] back to the wire + dispatches each
//! [`JdpSessionEvent`] to the configured hooks (block submission,
//! job-declared notification, etc.).
//!
//! Pure handler-layer for JDP per-connection state management. The handlers
//! follow these design principles:
//!
//! - **Async hooks resolved by the caller**. Our handlers stay pure by
//!   accepting the resolved payload as an argument (caller pre-fetches
//!   via the hook trait at the IO layer). Keeps test-fixtures simple
//!   and lets the same handler-layer drive both production wiring +
//!   regtest.
//! - **No socket destruction inside the handler**. We emit
//!   [`JdpSessionEvent::Disconnect`] on protocol mismatch and let the
//!   IO layer handle the close.
//!
//! ## Implementation strategy
//!
//! Each handler is independently testable: state transitions are
//! pinned by unit tests with synthetic inputs, the [`crate::tokens`]
//! `set_rng` hook gives deterministic tokens for assertion-friendly
//! comparisons.

use std::collections::{HashMap, HashSet};

use bp_common::AddressId;
use bp_mining_job::normalize_btc_address;

use crate::extensions::{RequestExtensions, SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS};
use crate::tokens::{Token, TokenAllocError, TokenStore};

use super::declarations::{DeclaredJob, DeclaredJobStore};
use super::dynamic_outputs::{DeclareOutputsCheck, EmittedPayoutOutputs, PayoutOutputsTracker};
use super::tx_validation::{
    merge_provided_with_known, partition_against_template, PendingDeclaration,
};

// ── Constants ────────────────────────────────────────────────────────

/// SV2 protocol code for the Job-Declaration sub-protocol (spec 6.4.1).
pub const PROTOCOL_JOB_DECLARATION: u8 = 1;

/// Minimum supported SV2 protocol version. JDP spec pins v2.
pub const MIN_PROTOCOL_VERSION: u16 = 2;
/// Maximum supported SV2 protocol version.
pub const MAX_PROTOCOL_VERSION: u16 = 2;

/// `DECLARE_TX_DATA` flag (bit 0 of `SetupConnection.flags`). When
/// set, the JDC sends a full `DeclareMiningJob` before any
/// `SetCustomMiningJob` (Full-Template mode). When clear, the JDC
/// sends `SetCustomMiningJob` directly (Coinbase-only mode — the
/// JDS doesn't validate the full transaction set).
pub const FLAG_DECLARE_TX_DATA: u32 = 1 << 0;

/// Set of JDP-side SV2 extensions this server supports. Currently 0x0003
/// (Non-Custodial Pool Payouts).
pub const SUPPORTED_JDP_EXTENSIONS: &[u16] = &[SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS];

fn is_jdp_extension_supported(ext: u16) -> bool {
    SUPPORTED_JDP_EXTENSIONS.contains(&ext)
}

// ── Wire error codes ─────────────────────────────────────────────────

/// `unsupported-protocol` — `SetupConnection.protocol` was something
/// other than JOB_DECLARATION (1).
pub const ERR_UNSUPPORTED_PROTOCOL: &str = "unsupported-protocol";

/// `unsupported-version` — `SetupConnection.min_version`/`max_version`
/// didn't include 2.
pub const ERR_UNSUPPORTED_VERSION: &str = "unsupported-version";

/// `unsupported-feature-flags` — JDC sent `DeclareMiningJob` without
/// negotiating `DECLARE_TX_DATA` (Full-Template mode).
pub const ERR_UNSUPPORTED_FEATURE_FLAGS: &str = "unsupported-feature-flags";

/// `invalid-mining-job-token` — the token referenced doesn't exist or
/// has expired. Used in `RequestPayoutOutputs.Error` (ext 0x0003 §2.3)
/// and `DeclareMiningJob.Error`.
pub const ERR_INVALID_MINING_JOB_TOKEN: &str = "invalid-mining-job-token";

/// `invalid-job-param-value-coinbase_tx_outputs` — the declared
/// coinbase doesn't carry the pool's committed payout outputs verbatim
/// (an output is missing, modified, or reduced — spec §4).
pub const ERR_INVALID_JOB_PARAM_COINBASE: &str = "invalid-job-param-value-coinbase_tx_outputs";

/// `stale-payout-outputs` — the declared job's payout output set is
/// stale, superseded, unknown, or already used (spec §4). Emitted on
/// `DeclareMiningJob.Error`; the JDC SHOULD request a fresh payout set
/// before retrying. Single source of truth lives in the ext-0x0003
/// codec module.
pub const ERR_STALE_PAYOUT_OUTPUTS: &str =
    crate::extensions::payout_outputs_error_codes::STALE_PAYOUT_OUTPUTS;

// ── Inputs (typed wrappers over deserialized SV2 frames) ────────────

/// Inputs from a deserialized JDP `SetupConnection` frame. Analogous to
/// [`crate::mining::client::SetupConnectionInput`] but scoped to the
/// JDP sub-protocol.
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

/// Inputs from a deserialized `AllocateMiningJobToken` frame.
#[derive(Clone, Debug)]
pub struct AllocateMiningJobTokenInput {
    pub request_id: u32,
    /// JDC-supplied identifier. The handler tries
    /// `normalize_btc_address` on it first; if that fails, the
    /// caller's `fallback_miner_address` argument takes over.
    pub user_identifier: String,
}

/// Inputs from a deserialized ext 0x0003 `RequestPayoutOutputs`
/// frame (spec §2.1). No `prev_hash`: freshness is validator-side
/// (single-use payout sets, spec §4), not signalled per-request.
#[derive(Clone, Debug)]
pub struct RequestPayoutOutputsInput {
    pub request_id: u32,
    pub mining_job_token: Token,
    /// Amount (sats) the returned output set MUST distribute (spec
    /// §2.1). The JDC derives it from `coinbase_tx_value_remaining`
    /// after accounting for any outputs it adds itself. The JDS's
    /// emitted set MUST satisfy `Σ amount[i] == available_payout_value`.
    pub available_payout_value: u64,
}

/// Inputs from a deserialized `DeclareMiningJob` frame. Mirrors the
/// fields the handler reads — wire serialization belongs to a
/// codec module the IO layer will wire up.
#[derive(Clone, Debug)]
pub struct DeclareMiningJobInput {
    pub request_id: u32,
    pub mining_job_token: Token,
    pub version: u32,
    pub coinbase_tx_prefix: Vec<u8>,
    pub coinbase_tx_suffix: Vec<u8>,
    pub wtxid_list: Vec<[u8; 32]>,
}

/// Inputs from a deserialized `ProvideMissingTransactions.Success`
/// frame. The transactions are positioned to match the previously
/// requested `missing_positions` index-for-index.
#[derive(Clone, Debug)]
pub struct ProvideMissingTransactionsSuccessInput {
    pub request_id: u32,
    pub transaction_list: Vec<Vec<u8>>,
}

/// Inputs from a deserialized `PushSolution` frame (JDP §6.4.9).
#[derive(Clone, Debug)]
pub struct PushSolutionInput {
    pub extranonce: Vec<u8>,
    pub prev_hash: [u8; 32],
    pub ntime: u32,
    pub nonce: u32,
    pub n_bits: u32,
    pub version: u32,
}

// ── Pre-resolved hook arguments (caller-supplied) ───────────────────

/// Payload the caller resolves between the wire frame arriving and
/// invoking [`handle_allocate_token`]. The IO layer:
///
/// 1. Calls a `MinerLookup` hook with the connection's remote IP if
///    the JDC's `user_identifier` doesn't parse as a BTC address.
/// 2. Resolves the pool's payout addresses via a `PayoutResolver`
///    hook — typically just the miner's address (single-output,
///    §6.4.3 fallback).
/// 3. Encodes the resolved address list into a consensus-serialised
///    `Vec<TxOut>` blob via
///    [`crate::jdp::dynamic_outputs::encode_coinbase_outputs`].
/// 4. Passes the resolved `(miner_address, coinbase_outputs)` here.
#[derive(Clone, Debug)]
pub struct AllocateTokenContext {
    pub miner_address: AddressId,
    pub coinbase_outputs: Vec<u8>,
}

/// Resolved result for [`handle_request_payout_outputs`]. The IO
/// layer calls a `PayoutOutputsResolver` hook and feeds the typed
/// result here. The handler stays free of the async / mode-routing
/// layer.
#[derive(Clone, Debug)]
pub enum PayoutOutputsResolution {
    Success { request_id: u32, outputs: Vec<u8> },
    Error { request_id: u32, error_code: String },
}

// ── OutboundFrame ───────────────────────────────────────────────────

/// What the JDP handler decided to send. The IO layer translates
/// these into `stratum_core::job_declaration_sv2` / `common_messages_sv2`
/// types and serialises via `codec_sv2`. Kept as a separate enum so
/// the handler stays pure on session-state types (no lifetimes
/// leaking through).
#[derive(Clone, Debug, PartialEq)]
pub enum JdpOutboundFrame {
    SetupConnectionSuccess {
        used_version: u16,
        flags: u32,
    },
    SetupConnectionError {
        flags: u32,
        error_code: String,
    },
    RequestExtensionsSuccess {
        request_id: u16,
        supported_extensions: Vec<u16>,
    },
    RequestExtensionsError {
        request_id: u16,
        unsupported_extensions: Vec<u16>,
        required_extensions: Vec<u16>,
    },
    AllocateMiningJobTokenSuccess {
        request_id: u32,
        mining_job_token: Token,
        coinbase_outputs: Vec<u8>,
    },
    RequestPayoutOutputsSuccess {
        request_id: u32,
        coinbase_outputs: Vec<u8>,
    },
    RequestPayoutOutputsError {
        request_id: u32,
        error_code: String,
    },
    DeclareMiningJobSuccess {
        request_id: u32,
        new_mining_job_token: Token,
    },
    DeclareMiningJobError {
        request_id: u32,
        error_code: String,
        error_details: Vec<u8>,
    },
    ProvideMissingTransactions {
        request_id: u32,
        unknown_tx_position_list: Vec<u32>,
    },
}

// ── SessionEvent ────────────────────────────────────────────────────

/// What the handler decided about the session beyond the wire frames.
/// The IO layer uses these to drive hooks (block submission, job
/// declared notification, miner registration) without re-deriving
/// state.
#[derive(Clone, Debug)]
pub enum JdpSessionEvent {
    /// `SetupConnection` completed. Caller can register the JDP
    /// connection in the live-connection registry.
    SetupComplete { full_template_mode: bool },
    /// A token was allocated. Caller can persist (e.g. for cross-
    /// connection coinbase-outputs lookups via the
    /// `findEmittedOutputsForJob`-equivalent).
    TokenAllocated {
        token: Token,
        miner_address: AddressId,
    },
    /// An ext-0x0003 payout output set was issued for a token
    /// (`RequestPayoutOutputs.Success`). The IO layer records it in the
    /// shared bridge (`register_payout_set`) so a later `SetCustomMiningJob`
    /// on the mining connection can validate + single-use-consume the JDC's
    /// coinbase outputs against the pool-committed set (spec §4, §5.3).
    PayoutOutputsIssued {
        token: Token,
        /// Consensus-serialised `Vec<TxOut>` returned to the JDC.
        outputs: Vec<u8>,
        miner_address: AddressId,
        /// Pool chain-tip when issued — lets the mining-side
        /// `SetCustomMiningJob` validator reject a stale/superseded set.
        issued_prev_hash: Option<[u8; 32]>,
    },
    /// A `DeclareMiningJob` was accepted. Caller fans out to the
    /// mining-protocol bridge to build a `SetCustomMiningJob` for
    /// the matching JDC miner.
    JobDeclared {
        new_token: Token,
        original_token: Token,
        miner_address: AddressId,
        prev_hash: Option<[u8; 32]>,
    },
    /// A `PushSolution` has been resolved against a declared job —
    /// the IO layer assembles the final block (merkle root + 80-byte
    /// header) from these components and hands it to
    /// bitcoin-core's `submitblock` RPC. The JDC also submits the
    /// same block via its own Template Provider in parallel; the
    /// `submitblock` RPC is idempotent so the double-submit is safe.
    ///
    /// Block-bytes assembly (merkle root walk + header layout +
    /// consensus-encode) belongs to the IO layer because it needs
    /// rust-bitcoin's consensus codec which is awkward to thread
    /// through a pure handler without leaking lifetimes. The pure
    /// handler stops at "here are the raw transactions + the
    /// solution fields; reconstruct from there".
    BlockSubmissionCandidate {
        miner_address: AddressId,
        new_token: Token,
        /// Reconstructed non-witness coinbase (prefix + extranonce +
        /// suffix). IO layer parses this back into a
        /// `bitcoin::Transaction` for merkle-root computation.
        coinbase_raw: Vec<u8>,
        /// Raw transaction bytes for positions 1..=N of the block,
        /// in `wtxid_list` order (NOT including the coinbase). May
        /// include witness data; the IO layer strips for merkle-root
        /// computation if needed.
        transactions: Vec<Vec<u8>>,
        /// 32-byte prev hash from the solution.
        prev_hash: [u8; 32],
        /// Block-header `version` field (BIP-320 version-rolled).
        version: u32,
        /// Block-header `ntime` field.
        ntime: u32,
        /// Block-header `nonce` field.
        nonce: u32,
        /// Block-header `n_bits` field.
        n_bits: u32,
    },
    /// The connection should be closed. Emitted on protocol /
    /// version mismatch in `SetupConnection`. IO layer closes the
    /// socket after dispatching any preceding outbound frame.
    Disconnect { reason: String },
}

// ── HandlerOutcome ──────────────────────────────────────────────────

/// What a single handler call produced. Both fields can be empty
/// (e.g. a silently-ignored frame) — that's a no-op outcome.
#[derive(Clone, Debug, Default)]
pub struct JdpHandlerOutcome {
    pub outbound: Vec<JdpOutboundFrame>,
    pub events: Vec<JdpSessionEvent>,
}

impl JdpHandlerOutcome {
    fn with_frame(frame: JdpOutboundFrame) -> Self {
        Self {
            outbound: vec![frame],
            events: Vec::new(),
        }
    }

    fn push_event(&mut self, event: JdpSessionEvent) {
        self.events.push(event);
    }
}

// ── JdpSessionState ─────────────────────────────────────────────────

/// All per-connection mutable state for the JDP sub-protocol. Owned
/// `&mut` by the JDP-server's per-connection task.
///
/// Constructor responsibility is split between this module and the IO
/// layer: this module owns the connection-scoped pure state (token
/// store + declared-jobs store + payout-outputs tracker + negotiation
/// flags); the IO layer wires in the Noise session, the per-connection
/// task channel, the hook adapters, and the disconnect handle.
pub struct JdpSessionState {
    pub session_id: u32,

    // Negotiated state from SetupConnection.
    pub setup_complete: bool,
    pub full_template_mode: bool,
    pub used_version: u16,
    pub vendor: String,

    /// Extensions the JDC has negotiated via ext 0x0001
    /// (RequestExtensions). Populated in
    /// [`handle_request_extensions`]. Empty until then — pre-setup
    /// behaviour is base-spec only.
    pub negotiated_extensions: HashSet<u16>,

    /// Token bookkeeping (allocation rate-limit, expiry, lookup).
    pub tokens: TokenStore,

    /// Per-connection declared-jobs store (FIFO `MAX_DECLARED_JOBS`).
    pub declared_jobs: DeclaredJobStore,

    /// Per-connection single-use tracker of issued `RequestPayoutOutputs.Success`
    /// payout sets (spec §4). Used in declare-job validation to confirm
    /// the JDC's coinbase carries what the JDS committed to, and to
    /// enforce single-use + epoch-staleness.
    pub payout_outputs_tracker: PayoutOutputsTracker,

    /// In-flight `DeclareMiningJob` waiting for a
    /// `ProvideMissingTransactions.Success` response. At most one per
    /// connection; a second `DeclareMiningJob` arriving while a
    /// pending one is in-flight overwrites it.
    pub pending_declaration: Option<PendingState>,
}

/// In-flight declaration state — wraps [`PendingDeclaration`] with
/// the original `DeclareMiningJobInput` so `acceptDeclaration` can
/// run after the missing-tx round-trip.
#[derive(Clone, Debug)]
pub struct PendingState {
    pub input: DeclareMiningJobInput,
    pub pending: PendingDeclaration,
    pub original_token: Token,
    pub miner_address: AddressId,
}

impl JdpSessionState {
    pub fn new(session_id: u32) -> Self {
        Self {
            session_id,
            setup_complete: false,
            full_template_mode: false,
            used_version: 0,
            vendor: String::new(),
            negotiated_extensions: HashSet::new(),
            tokens: TokenStore::new(),
            declared_jobs: DeclaredJobStore::new(),
            payout_outputs_tracker: PayoutOutputsTracker::new(),
            pending_declaration: None,
        }
    }

    /// Test/IO-layer hook to inject a deterministic RNG into the
    /// underlying [`TokenStore`]. Production paths use the default
    /// `getrandom` source.
    pub fn set_token_rng(&mut self, rng: Option<Box<crate::tokens::RngFn>>) {
        self.tokens.set_rng(rng);
    }
}

// ── Handler: SetupConnection ────────────────────────────────────────

/// Handle a JDP `SetupConnection`.
///
/// - Protocol mismatch (`!= JOB_DECLARATION`) → `SetupConnectionError`
///   with `unsupported-protocol` + [`JdpSessionEvent::Disconnect`].
/// - Version range outside `[MIN_PROTOCOL_VERSION, MAX_PROTOCOL_VERSION]`
///   → `SetupConnectionError` with `unsupported-version` + Disconnect.
/// - Else → `SetupConnectionSuccess` echoing the negotiated
///   `DECLARE_TX_DATA` flag (bit 0). Other flag bits are masked off.
pub fn handle_setup_connection(
    state: &mut JdpSessionState,
    input: &SetupConnectionInput,
) -> JdpHandlerOutcome {
    if input.protocol != PROTOCOL_JOB_DECLARATION {
        let mut outcome = JdpHandlerOutcome::with_frame(JdpOutboundFrame::SetupConnectionError {
            flags: input.flags,
            error_code: ERR_UNSUPPORTED_PROTOCOL.to_string(),
        });
        outcome.push_event(JdpSessionEvent::Disconnect {
            reason: format!("protocol mismatch: got {}", input.protocol),
        });
        return outcome;
    }
    if input.min_version > MAX_PROTOCOL_VERSION || input.max_version < MIN_PROTOCOL_VERSION {
        let mut outcome = JdpHandlerOutcome::with_frame(JdpOutboundFrame::SetupConnectionError {
            flags: input.flags,
            error_code: ERR_UNSUPPORTED_VERSION.to_string(),
        });
        outcome.push_event(JdpSessionEvent::Disconnect {
            reason: format!(
                "version range {}–{} doesn't include {}",
                input.min_version, input.max_version, MIN_PROTOCOL_VERSION
            ),
        });
        return outcome;
    }

    let negotiated_flags = input.flags & FLAG_DECLARE_TX_DATA;
    let full_template_mode = negotiated_flags != 0;
    state.setup_complete = true;
    state.full_template_mode = full_template_mode;
    state.used_version = input.max_version.min(MAX_PROTOCOL_VERSION);
    state.vendor = input.vendor.clone();

    JdpHandlerOutcome {
        outbound: vec![JdpOutboundFrame::SetupConnectionSuccess {
            used_version: state.used_version,
            flags: negotiated_flags,
        }],
        events: vec![JdpSessionEvent::SetupComplete { full_template_mode }],
    }
}

// ── Handler: RequestExtensions (ext 0x0001) ─────────────────────────

/// Handle ext 0x0001 `RequestExtensions`.
///
/// - Pre-setup → silently dropped (returns empty outcome). Stray
///   pre-setup requests are ignored to prevent skipping the
///   SetupConnection handshake.
/// - Supported subset non-empty → `RequestExtensionsSuccess` with the
///   intersection of requested + [`SUPPORTED_JDP_EXTENSIONS`].
///   Negotiated entries added to `state.negotiated_extensions`.
/// - Empty request → `Success` with empty list (always respond).
///   Same shape as the mining-side handler.
/// - Non-empty request, zero supported → `RequestExtensionsError`
///   with the unsupported list.
pub fn handle_request_extensions(
    state: &mut JdpSessionState,
    input: &RequestExtensions,
) -> JdpHandlerOutcome {
    if !state.setup_complete {
        return JdpHandlerOutcome::default();
    }

    let mut supported: Vec<u16> = Vec::new();
    let mut unsupported: Vec<u16> = Vec::new();
    for ext in &input.requested_extensions {
        if is_jdp_extension_supported(*ext) {
            supported.push(*ext);
            state.negotiated_extensions.insert(*ext);
        } else {
            unsupported.push(*ext);
        }
    }

    if supported.is_empty() && !input.requested_extensions.is_empty() {
        return JdpHandlerOutcome::with_frame(JdpOutboundFrame::RequestExtensionsError {
            request_id: input.request_id,
            unsupported_extensions: unsupported,
            required_extensions: Vec::new(),
        });
    }

    JdpHandlerOutcome::with_frame(JdpOutboundFrame::RequestExtensionsSuccess {
        request_id: input.request_id,
        supported_extensions: supported,
    })
}

// ── Handler: AllocateMiningJobToken ─────────────────────────────────

/// Handle `AllocateMiningJobToken`.
///
/// **Caller-resolved context**: the IO layer pre-resolves
/// [`AllocateTokenContext`] before invoking — typically by parsing
/// the JDC's `user_identifier` as a BTC address and falling back to
/// an IP-based lookup hook if that fails. The handler doesn't see
/// the connection's IP. The caller also pre-encodes the pool's
/// `coinbase_outputs` blob (consensus-serialised `Vec<TxOut>`) via
/// [`crate::jdp::dynamic_outputs::encode_coinbase_outputs`].
///
/// - Pre-setup → silently dropped.
/// - Rate-limited → silently dropped. The [`TokenStore::allocate`]
///   call already enforces this; we map the `RateLimited` error into a
///   no-op outcome.
/// - Token allocation success → `AllocateMiningJobTokenSuccess` +
///   [`JdpSessionEvent::TokenAllocated`].
pub fn handle_allocate_token(
    state: &mut JdpSessionState,
    input: &AllocateMiningJobTokenInput,
    context: AllocateTokenContext,
    now_ms: u64,
) -> JdpHandlerOutcome {
    if !state.setup_complete {
        return JdpHandlerOutcome::default();
    }

    let alloc = match state.tokens.allocate(
        now_ms,
        context.miner_address.clone(),
        context.coinbase_outputs,
    ) {
        Ok(entry) => entry,
        Err(TokenAllocError::RateLimited { .. }) => return JdpHandlerOutcome::default(),
        Err(_) => return JdpHandlerOutcome::default(),
    };

    let token = alloc.token;
    let outputs = alloc.coinbase_outputs.clone();
    let miner_address = alloc.miner_address.clone();

    JdpHandlerOutcome {
        outbound: vec![JdpOutboundFrame::AllocateMiningJobTokenSuccess {
            request_id: input.request_id,
            mining_job_token: token,
            coinbase_outputs: outputs,
        }],
        events: vec![JdpSessionEvent::TokenAllocated {
            token,
            miner_address,
        }],
    }
}

/// Helper for the IO layer: try to parse `user_identifier` as a BTC
/// address. Returns the normalised `AddressId` when valid (any
/// network is accepted at this layer — Mainnet/Testnet/Regtest split
/// is the resolver's job). The caller falls back to an IP-based
/// lookup when this returns `None`.
pub fn parse_user_identifier_as_address(user_identifier: &str) -> Option<AddressId> {
    let trimmed = user_identifier.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Stratum `address.worker` convention (single-dot split; the worker
    // name keeps any further dots). Strip the worker suffix so only the
    // payout address is validated and carried downstream — otherwise the
    // trailing `.worker` makes `address_to_script` reject the address at
    // coinbase-output encode time, collapsing the pool payout to an empty
    // output set (`coinbase_tx_outputs = 0x00`). Same split as the
    // mining channel-open parse (`address.worker_name`, first dot).
    let address_part = match trimmed.find('.') {
        Some(idx) => &trimmed[..idx],
        None => trimmed,
    };
    if address_part.is_empty() {
        return None;
    }
    let normalised = normalize_btc_address(address_part);
    AddressId::new(normalised).ok()
}

// ── Handler: RequestPayoutOutputs (ext 0x0003) ──────────────────────

/// Handle ext 0x0003 `RequestPayoutOutputs`.
///
/// **Caller-resolved context**: the IO layer:
///
/// 1. Confirms the token exists + isn't expired (we re-check here as
///    a defence in depth).
/// 2. Calls a `PayoutOutputsResolver` hook and feeds the typed
///    [`PayoutOutputsResolution`] result here.
/// 3. Reads the pool's `current_prev_hash` (its own chain-tip view, NOT
///    a wire field) so the tracker can stamp the freshly-issued set
///    under the current epoch.
///
/// - Not negotiated → silently dropped.
/// - Unknown / expired token → `RequestPayoutOutputsError` with
///   `invalid-mining-job-token`.
/// - Resolution `Success` → `RequestPayoutOutputsSuccess` + record the
///   set as single-use pending in the [`PayoutOutputsTracker`] for
///   later declare-job validation (spec §4).
/// - Resolution `Error` → `RequestPayoutOutputsError` with the
///   resolver-supplied code (`coinbase-size-budget-exceeded`,
///   `revenue-too-large`, `internal`, …).
pub fn handle_request_payout_outputs(
    state: &mut JdpSessionState,
    input: &RequestPayoutOutputsInput,
    resolution: PayoutOutputsResolution,
    current_prev_hash: Option<[u8; 32]>,
    now_ms: u64,
) -> JdpHandlerOutcome {
    if !state
        .negotiated_extensions
        .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
    {
        return JdpHandlerOutcome::default();
    }

    let miner_address = match state.tokens.lookup_active(&input.mining_job_token, now_ms) {
        Some(entry) => entry.miner_address.clone(),
        None => {
            return JdpHandlerOutcome::with_frame(JdpOutboundFrame::RequestPayoutOutputsError {
                request_id: input.request_id,
                error_code: ERR_INVALID_MINING_JOB_TOKEN.to_string(),
            });
        }
    };

    match resolution {
        PayoutOutputsResolution::Success {
            request_id: _,
            outputs,
        } => {
            // Stamp the current epoch BEFORE recording so the fresh set
            // isn't immediately flagged stale; a later chain-tip advance
            // marks it superseded.
            if let Some(prev) = current_prev_hash {
                state.payout_outputs_tracker.observe_epoch(prev);
            }
            // Echo the request's own id (spec §2.2: "Echoed from the
            // request"), never the resolver-supplied one.
            state.payout_outputs_tracker.record(
                input.mining_job_token,
                EmittedPayoutOutputs {
                    request_id: input.request_id,
                    outputs: outputs.clone(),
                    emitted_at_ms: now_ms,
                    used: false,
                    stale: false,
                },
            );
            // Surface the issued set so the IO layer records it in the
            // shared bridge — the mining-side SetCustomMiningJob handler
            // validates + single-use-consumes the JDC's coinbase against it.
            let mut outcome =
                JdpHandlerOutcome::with_frame(JdpOutboundFrame::RequestPayoutOutputsSuccess {
                    request_id: input.request_id,
                    coinbase_outputs: outputs.clone(),
                });
            outcome.push_event(JdpSessionEvent::PayoutOutputsIssued {
                token: input.mining_job_token,
                outputs,
                miner_address,
                issued_prev_hash: current_prev_hash,
            });
            outcome
        }
        PayoutOutputsResolution::Error {
            request_id: _,
            error_code,
        } => JdpHandlerOutcome::with_frame(JdpOutboundFrame::RequestPayoutOutputsError {
            request_id: input.request_id,
            error_code,
        }),
    }
}

// ── Handler: DeclareMiningJob ───────────────────────────────────────

/// Handle `DeclareMiningJob`.
///
/// **Caller-resolved context**: the IO layer snapshots the JDS's
/// local template-tx cache (`wtxid → raw_tx` map) and passes it in
/// via `template_txs`. The handler does the wtxid partition + decides
/// whether to round-trip via `ProvideMissingTransactions` or accept
/// the declaration immediately.
///
/// - Coinbase-only mode (`!full_template_mode`) → `DeclareMiningJobError`
///   with `unsupported-feature-flags`.
/// - Unknown / expired token → `DeclareMiningJobError` with
///   `invalid-mining-job-token`.
/// - Partition is fully covered → accept declaration immediately
///   (emits `DeclareMiningJobSuccess` + `JobDeclared` event).
/// - Some wtxids missing → emit `ProvideMissingTransactions` and
///   stash a [`PendingState`] for the follow-up Success frame.
pub fn handle_declare_mining_job(
    state: &mut JdpSessionState,
    input: &DeclareMiningJobInput,
    template_txs: &HashMap<[u8; 32], Vec<u8>>,
    current_prev_hash: Option<[u8; 32]>,
    now_ms: u64,
) -> JdpHandlerOutcome {
    if !state.full_template_mode {
        return JdpHandlerOutcome::with_frame(JdpOutboundFrame::DeclareMiningJobError {
            request_id: input.request_id,
            error_code: ERR_UNSUPPORTED_FEATURE_FLAGS.to_string(),
            error_details: b"DeclareMiningJob requires Full-Template mode (DECLARE_TX_DATA flag)"
                .to_vec(),
        });
    }

    let allocated = match state.tokens.lookup_active(&input.mining_job_token, now_ms) {
        Some(entry) => entry.clone(),
        None => {
            return JdpHandlerOutcome::with_frame(JdpOutboundFrame::DeclareMiningJobError {
                request_id: input.request_id,
                error_code: ERR_INVALID_MINING_JOB_TOKEN.to_string(),
                error_details: b"Token not found or expired".to_vec(),
            });
        }
    };

    let original_token = allocated.token;
    let miner_address = allocated.miner_address.clone();

    let partition = partition_against_template(&input.wtxid_list, template_txs);

    if partition.fully_covered() {
        return accept_declaration(
            state,
            input,
            partition.known_raw_txs,
            original_token,
            miner_address,
            current_prev_hash,
            now_ms,
        );
    }

    let outcome = JdpHandlerOutcome::with_frame(JdpOutboundFrame::ProvideMissingTransactions {
        request_id: input.request_id,
        unknown_tx_position_list: partition.missing_positions.clone(),
    });
    state.pending_declaration = Some(PendingState {
        input: input.clone(),
        pending: PendingDeclaration {
            request_id: input.request_id,
            missing_positions: partition.missing_positions,
            known_raw_txs: partition.known_raw_txs,
        },
        original_token,
        miner_address,
    });
    // Epoch staleness is observed in `accept_declaration` (the path that
    // actually validates the payout set), reached here once the
    // `ProvideMissingTransactions.Success` round-trip completes.
    outcome
}

// ── Handler: ProvideMissingTransactions.Success ─────────────────────

/// Handle `ProvideMissingTransactions.Success`.
///
/// - No pending declaration → silently dropped (a spurious Success
///   without a pending request indicates a JDC bug).
/// - Position-count mismatch ([`merge_provided_with_known`] errors
///   with `MergeError::PositionCountMismatch`) → silently dropped.
/// - Successful merge → accept the declaration (same path as the
///   fully-covered case in [`handle_declare_mining_job`]).
pub fn handle_provide_missing_transactions_success(
    state: &mut JdpSessionState,
    input: &ProvideMissingTransactionsSuccessInput,
    current_prev_hash: Option<[u8; 32]>,
    now_ms: u64,
) -> JdpHandlerOutcome {
    let pending = match state.pending_declaration.take() {
        Some(p) => p,
        None => return JdpHandlerOutcome::default(),
    };
    if pending.pending.request_id != input.request_id {
        // Mismatched request_id — restore the pending state so a
        // later matching Success can resolve it.
        state.pending_declaration = Some(pending);
        return JdpHandlerOutcome::default();
    }
    let merged = match merge_provided_with_known(pending.pending, input.transaction_list.clone()) {
        Ok(m) => m,
        Err(_) => return JdpHandlerOutcome::default(),
    };
    accept_declaration(
        state,
        &pending.input,
        merged,
        pending.original_token,
        pending.miner_address,
        current_prev_hash,
        now_ms,
    )
}

// ── Internal: accept_declaration ────────────────────────────────────

fn accept_declaration(
    state: &mut JdpSessionState,
    input: &DeclareMiningJobInput,
    raw_transactions: HashMap<u32, Vec<u8>>,
    original_token: Token,
    miner_address: AddressId,
    current_prev_hash: Option<[u8; 32]>,
    now_ms: u64,
) -> JdpHandlerOutcome {
    // Reject genuinely-empty coinbases up front (spec §6.4.3 — the coinbase
    // MUST carry the pool's committed payout outputs).
    if input.coinbase_tx_prefix.is_empty() && input.coinbase_tx_suffix.is_empty() {
        return JdpHandlerOutcome::with_frame(JdpOutboundFrame::DeclareMiningJobError {
            request_id: input.request_id,
            error_code: ERR_INVALID_JOB_PARAM_COINBASE.to_string(),
            error_details: b"Empty coinbase transaction".to_vec(),
        });
    }

    // Full payout-output validation (SV2 ext 0x0003 §4). When the JDC
    // negotiated 0x0003, every declared job MUST carry a payout set that
    // was freshly requested for this token via RequestPayoutOutputs: the
    // declared coinbase MUST carry every pool output (multiset), the set
    // MUST be single-use, and MUST NOT be superseded by a chain-tip
    // advance. A negotiated connection that declares without first
    // requesting a set (NoneIssued) is rejected — there is no base
    // coinbase-output backstop, so falling through would let a JDC keep
    // the full reward. When 0x0003 wasn't negotiated at all, this is a
    // plain base-protocol declaration and the block below is skipped.
    if state
        .negotiated_extensions
        .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
    {
        // Observe the pool's own current tip first so a set issued
        // against a now-superseded payout window is flagged stale.
        if let Some(prev) = current_prev_hash {
            state.payout_outputs_tracker.observe_epoch(prev);
        }
        let check = state
            .payout_outputs_tracker
            .validate_and_consume_for_declare(&original_token, &input.coinbase_tx_suffix);
        match check {
            DeclareOutputsCheck::Ok => {}
            DeclareOutputsCheck::NoneIssued => {
                // 0x0003 is negotiated, so every declared job MUST carry a
                // freshly-requested payout set (spec §4: the JDC "MUST
                // request a fresh payout output set for each custom job"; the
                // validator "MUST reject the job if the payout output set is
                // unknown"). None was issued for this token → reject; the JDC
                // requests one and re-declares.
                tracing::warn!(
                    request_id = input.request_id,
                    "jdp: 0x0003 negotiated but no payout set issued for this token — rejecting (JDC must RequestPayoutOutputs first)"
                );
                return JdpHandlerOutcome::with_frame(JdpOutboundFrame::DeclareMiningJobError {
                    request_id: input.request_id,
                    error_code: ERR_STALE_PAYOUT_OUTPUTS.to_string(),
                    error_details: b"no payout output set issued for this token; request one first"
                        .to_vec(),
                });
            }
            DeclareOutputsCheck::MissingOutput { .. }
            | DeclareOutputsCheck::UnparsablePoolOutputs
            | DeclareOutputsCheck::UnparsableDeclaredCoinbase => {
                tracing::warn!(
                    request_id = input.request_id,
                    ?check,
                    "jdp: declared coinbase missing pool-committed outputs — rejecting declaration"
                );
                return JdpHandlerOutcome::with_frame(JdpOutboundFrame::DeclareMiningJobError {
                    request_id: input.request_id,
                    error_code: ERR_INVALID_JOB_PARAM_COINBASE.to_string(),
                    error_details: b"declared coinbase missing pool-committed outputs".to_vec(),
                });
            }
            DeclareOutputsCheck::AlreadyUsed | DeclareOutputsCheck::Stale => {
                tracing::warn!(
                    request_id = input.request_id,
                    ?check,
                    "jdp: payout set stale / already-used — rejecting declaration (JDC should re-request)"
                );
                return JdpHandlerOutcome::with_frame(JdpOutboundFrame::DeclareMiningJobError {
                    request_id: input.request_id,
                    error_code: ERR_STALE_PAYOUT_OUTPUTS.to_string(),
                    error_details: b"payout output set stale or already used".to_vec(),
                });
            }
        }
    }

    // Allocate a fresh token for the declared job via the shared
    // TokenStore for consistency + rate-limit accounting.
    let new_token = match state
        .tokens
        .allocate(now_ms, miner_address.clone(), Vec::new())
    {
        Ok(entry) => entry.token,
        Err(_) => {
            // Rate-limited / entropy failure — drop silently, the JDC
            // will retry on the next declaration.
            return JdpHandlerOutcome::default();
        }
    };

    state.declared_jobs.insert(DeclaredJob {
        new_token,
        original_token,
        request_id: input.request_id,
        version: input.version,
        coinbase_tx_prefix: input.coinbase_tx_prefix.clone(),
        coinbase_tx_suffix: input.coinbase_tx_suffix.clone(),
        wtxid_list: input.wtxid_list.clone(),
        raw_transactions,
        prev_hash: current_prev_hash,
        declared_at_ms: now_ms,
    });

    JdpHandlerOutcome {
        outbound: vec![JdpOutboundFrame::DeclareMiningJobSuccess {
            request_id: input.request_id,
            new_mining_job_token: new_token,
        }],
        events: vec![JdpSessionEvent::JobDeclared {
            new_token,
            original_token,
            miner_address,
            prev_hash: current_prev_hash,
        }],
    }
}

// ── Handler: PushSolution ───────────────────────────────────────────

/// Handle `PushSolution`.
///
/// Match the solution to a declared job via
/// [`DeclaredJobStore::match_for_solution`] (prefers prev_hash match,
/// falls back to most-recent). Reconstruct the coinbase from
/// `prefix + extranonce + suffix`, build the transaction list in
/// block order, derive the 80-byte block header, and emit a
/// [`JdpSessionEvent::BlockSubmissionCandidate`] for the IO layer to
/// hand to bitcoin-core's `submitblock` RPC.
///
/// - Not in full-template mode → silently dropped.
/// - No matching declared job → silently dropped.
/// - Missing raw-tx data for any wtxid position → silently dropped.
pub fn handle_push_solution(
    state: &mut JdpSessionState,
    input: &PushSolutionInput,
    miner_address: AddressId,
) -> JdpHandlerOutcome {
    if !state.full_template_mode {
        return JdpHandlerOutcome::default();
    }
    let job = match state.declared_jobs.match_for_solution(&input.prev_hash) {
        Some(j) => j,
        None => return JdpHandlerOutcome::default(),
    };

    // Snapshot the fields we'll emit + the new_token (immutable
    // lookup before we drop the borrow). `match_for_solution`
    // already returned a reference into `state.declared_jobs`; we
    // copy out the bytes we need so the borrow can drop before
    // building the outcome.
    let new_token = job.new_token;
    let coinbase_prefix = job.coinbase_tx_prefix.clone();
    let coinbase_suffix = job.coinbase_tx_suffix.clone();
    let wtxid_count = job.wtxid_list.len();
    let mut transactions: Vec<Vec<u8>> = Vec::with_capacity(wtxid_count);
    for i in 0..wtxid_count {
        match job.raw_transactions.get(&(i as u32)) {
            Some(raw) => transactions.push(raw.clone()),
            None => return JdpHandlerOutcome::default(),
        }
    }

    // Reconstruct coinbase = prefix + extranonce + suffix.
    let mut coinbase_raw =
        Vec::with_capacity(coinbase_prefix.len() + input.extranonce.len() + coinbase_suffix.len());
    coinbase_raw.extend_from_slice(&coinbase_prefix);
    coinbase_raw.extend_from_slice(&input.extranonce);
    coinbase_raw.extend_from_slice(&coinbase_suffix);

    JdpHandlerOutcome {
        outbound: Vec::new(),
        events: vec![JdpSessionEvent::BlockSubmissionCandidate {
            miner_address,
            new_token,
            coinbase_raw,
            transactions,
            prev_hash: input.prev_hash,
            version: input.version,
            ntime: input.ntime,
            nonce: input.nonce,
            n_bits: input.n_bits,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::RequestExtensions;

    // ── Fixtures ───────────────────────────────────────────────────

    /// Regtest bech32 address — same one used in mining/client tests.
    const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    fn addr() -> AddressId {
        AddressId::new(ADDR.to_string()).unwrap()
    }

    fn fresh() -> JdpSessionState {
        let mut s = JdpSessionState::new(1);
        // Deterministic RNG so tokens are byte-predictable. Counter
        // increments per allocation; suffix bytes are zero-filled.
        s.set_token_rng(Some(Box::new(|buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = 0;
            }
            Ok(())
        })));
        s
    }

    fn good_setup() -> SetupConnectionInput {
        SetupConnectionInput {
            protocol: PROTOCOL_JOB_DECLARATION,
            min_version: 2,
            max_version: 2,
            flags: FLAG_DECLARE_TX_DATA,
            vendor: "test-jdc".to_string(),
            firmware: "0.1".to_string(),
            hardware_version: "rev1".to_string(),
            device_id: "dev-1".to_string(),
        }
    }

    fn good_alloc(req_id: u32) -> AllocateMiningJobTokenInput {
        AllocateMiningJobTokenInput {
            request_id: req_id,
            user_identifier: ADDR.to_string(),
        }
    }

    fn alloc_ctx() -> AllocateTokenContext {
        AllocateTokenContext {
            miner_address: addr(),
            coinbase_outputs: vec![0u8],
        }
    }

    fn declare(req_id: u32, token: Token, wtxids: Vec<[u8; 32]>) -> DeclareMiningJobInput {
        DeclareMiningJobInput {
            request_id: req_id,
            mining_job_token: token,
            version: 0x2000_0000,
            coinbase_tx_prefix: vec![0xAA; 8],
            coinbase_tx_suffix: vec![0xBB; 8],
            wtxid_list: wtxids,
        }
    }

    /// Wrap a consensus `Vec<TxOut>` blob as a realistic coinbase suffix
    /// (`nSequence(4) + outputs + nLockTime(4)`) — what the declare-time
    /// payout-output validation parses.
    fn coinbase_suffix(outputs_consensus: &[u8]) -> Vec<u8> {
        let mut s = 0xFFFF_FFFFu32.to_le_bytes().to_vec();
        s.extend_from_slice(outputs_consensus);
        s.extend_from_slice(&0u32.to_le_bytes());
        s
    }

    /// Open one allocated token on a setup-complete session, return
    /// the new token.
    fn complete_setup_and_allocate(s: &mut JdpSessionState) -> Token {
        let _ = handle_setup_connection(s, &good_setup());
        let out = handle_allocate_token(s, &good_alloc(1), alloc_ctx(), 1_000);
        match out.outbound[0] {
            JdpOutboundFrame::AllocateMiningJobTokenSuccess {
                mining_job_token, ..
            } => mining_job_token,
            _ => panic!("expected AllocateMiningJobTokenSuccess"),
        }
    }

    // ── SetupConnection ────────────────────────────────────────────

    #[test]
    fn setup_protocol_mismatch_emits_error_and_disconnect() {
        let mut s = fresh();
        let mut input = good_setup();
        input.protocol = 0; // mining, not JDP
        let out = handle_setup_connection(&mut s, &input);
        match &out.outbound[0] {
            JdpOutboundFrame::SetupConnectionError { error_code, .. } => {
                assert_eq!(error_code, ERR_UNSUPPORTED_PROTOCOL);
            }
            _ => panic!("expected SetupConnectionError"),
        }
        assert!(out
            .events
            .iter()
            .any(|e| matches!(e, JdpSessionEvent::Disconnect { .. })));
        assert!(!s.setup_complete);
    }

    #[test]
    fn setup_version_mismatch_emits_error() {
        let mut s = fresh();
        let mut input = good_setup();
        input.min_version = 3;
        input.max_version = 3;
        let out = handle_setup_connection(&mut s, &input);
        match &out.outbound[0] {
            JdpOutboundFrame::SetupConnectionError { error_code, .. } => {
                assert_eq!(error_code, ERR_UNSUPPORTED_VERSION);
            }
            _ => panic!("expected SetupConnectionError"),
        }
    }

    #[test]
    fn setup_success_sets_full_template_mode_when_flag_set() {
        let mut s = fresh();
        let out = handle_setup_connection(&mut s, &good_setup());
        assert!(matches!(
            out.outbound[0],
            JdpOutboundFrame::SetupConnectionSuccess {
                used_version: 2,
                flags: 1
            }
        ));
        assert!(s.setup_complete);
        assert!(s.full_template_mode);
        assert!(matches!(
            out.events[0],
            JdpSessionEvent::SetupComplete {
                full_template_mode: true
            }
        ));
    }

    #[test]
    fn setup_success_coinbase_only_mode_when_flag_clear() {
        let mut s = fresh();
        let mut input = good_setup();
        input.flags = 0;
        let out = handle_setup_connection(&mut s, &input);
        assert!(matches!(
            out.outbound[0],
            JdpOutboundFrame::SetupConnectionSuccess { flags: 0, .. }
        ));
        assert!(!s.full_template_mode);
    }

    // ── RequestExtensions ──────────────────────────────────────────

    #[test]
    fn request_extensions_pre_setup_is_silently_dropped() {
        let mut s = fresh();
        let req = RequestExtensions {
            request_id: 1,
            requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS],
        };
        let out = handle_request_extensions(&mut s, &req);
        assert!(out.outbound.is_empty());
        assert!(out.events.is_empty());
        assert!(s.negotiated_extensions.is_empty());
    }

    #[test]
    fn request_extensions_supported_ext_0x0003_returns_success() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let req = RequestExtensions {
            request_id: 7,
            requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS],
        };
        let out = handle_request_extensions(&mut s, &req);
        match &out.outbound[0] {
            JdpOutboundFrame::RequestExtensionsSuccess {
                request_id,
                supported_extensions,
            } => {
                assert_eq!(*request_id, 7);
                assert_eq!(
                    supported_extensions,
                    &vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS]
                );
            }
            _ => panic!("expected RequestExtensionsSuccess"),
        }
        assert!(s
            .negotiated_extensions
            .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS));
    }

    #[test]
    fn request_extensions_unsupported_only_returns_error() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let req = RequestExtensions {
            request_id: 8,
            requested_extensions: vec![0x9999],
        };
        let out = handle_request_extensions(&mut s, &req);
        match &out.outbound[0] {
            JdpOutboundFrame::RequestExtensionsError {
                request_id,
                unsupported_extensions,
                ..
            } => {
                assert_eq!(*request_id, 8);
                assert_eq!(unsupported_extensions, &vec![0x9999]);
            }
            _ => panic!("expected RequestExtensionsError"),
        }
    }

    #[test]
    fn request_extensions_mixed_returns_success_with_subset() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let req = RequestExtensions {
            request_id: 9,
            requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS, 0x9999],
        };
        let out = handle_request_extensions(&mut s, &req);
        match &out.outbound[0] {
            JdpOutboundFrame::RequestExtensionsSuccess {
                supported_extensions,
                ..
            } => {
                assert_eq!(supported_extensions.len(), 1);
            }
            _ => panic!("expected Success"),
        }
    }

    // ── AllocateMiningJobToken ─────────────────────────────────────

    #[test]
    fn allocate_pre_setup_is_silently_dropped() {
        let mut s = fresh();
        let out = handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 0);
        assert!(out.outbound.is_empty());
        assert!(s.tokens.is_empty());
    }

    #[test]
    fn allocate_success_emits_token_and_event() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let out = handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 1_000);
        match &out.outbound[0] {
            JdpOutboundFrame::AllocateMiningJobTokenSuccess {
                request_id,
                mining_job_token,
                coinbase_outputs,
            } => {
                assert_eq!(*request_id, 1);
                assert_eq!(coinbase_outputs.as_slice(), &[0u8]);
                // Counter prefix = 1 BE, then 12 zero bytes (deterministic RNG).
                assert_eq!(&mining_job_token.0[..4], &[0, 0, 0, 1]);
            }
            _ => panic!("expected Success"),
        }
        assert!(matches!(
            out.events[0],
            JdpSessionEvent::TokenAllocated { .. }
        ));
    }

    #[test]
    fn allocate_rate_limited_is_silently_dropped() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 1_000);
        // 999ms later — below 1s rate-limit window.
        let out = handle_allocate_token(&mut s, &good_alloc(2), alloc_ctx(), 1_999);
        assert!(out.outbound.is_empty(), "rate-limited alloc must drop");
    }

    // ── parse_user_identifier_as_address ──────────────────────────

    #[test]
    fn parse_user_identifier_accepts_bech32_address() {
        let out = parse_user_identifier_as_address(ADDR);
        assert_eq!(out.map(|a| a.as_str().to_string()), Some(ADDR.to_string()));
    }

    #[test]
    fn parse_user_identifier_rejects_garbage() {
        // Spaces, control chars, oversize → InvalidAddress.
        let out = parse_user_identifier_as_address(&"x".repeat(200));
        assert!(out.is_none());
    }

    #[test]
    fn parse_user_identifier_strips_worker_suffix() {
        // `address.worker` must yield only the address — the trailing
        // `.worker` would otherwise reach `address_to_script` and collapse
        // the JDP coinbase outputs to an empty set.
        let out = parse_user_identifier_as_address(&format!("{ADDR}.gitgab"));
        assert_eq!(out.map(|a| a.as_str().to_string()), Some(ADDR.to_string()));
        // Worker name keeps further dots; only the first split matters.
        let out2 = parse_user_identifier_as_address(&format!("{ADDR}.rig.1"));
        assert_eq!(out2.map(|a| a.as_str().to_string()), Some(ADDR.to_string()));
        // A leading dot (empty address) is rejected.
        assert!(parse_user_identifier_as_address(".worker").is_none());
    }

    // ── RequestPayoutOutputs ───────────────────────────────────────

    #[test]
    fn request_payout_outputs_not_negotiated_is_silently_dropped() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let token = complete_setup_and_allocate(&mut s);
        let input = RequestPayoutOutputsInput {
            request_id: 1,
            mining_job_token: token,
            available_payout_value: 5_000_000_000,
        };
        let resolution = PayoutOutputsResolution::Success {
            request_id: 1,
            outputs: vec![0u8; 32],
        };
        let out =
            handle_request_payout_outputs(&mut s, &input, resolution, Some([0xAB; 32]), 2_000);
        assert!(out.outbound.is_empty(), "0x0003 must be negotiated first");
    }

    /// Negotiate 0x0003 + allocate, then request — Success records
    /// the set as single-use pending and emits the wire frame.
    #[test]
    fn request_payout_outputs_success_records_pending_and_emits() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_request_extensions(
            &mut s,
            &RequestExtensions {
                request_id: 1,
                requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS],
            },
        );
        let token = handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 1_000)
            .outbound
            .into_iter()
            .find_map(|f| match f {
                JdpOutboundFrame::AllocateMiningJobTokenSuccess {
                    mining_job_token, ..
                } => Some(mining_job_token),
                _ => None,
            })
            .unwrap();
        let input = RequestPayoutOutputsInput {
            request_id: 2,
            mining_job_token: token,
            available_payout_value: 5_000_000_000,
        };
        let resolution = PayoutOutputsResolution::Success {
            request_id: 2,
            outputs: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let out =
            handle_request_payout_outputs(&mut s, &input, resolution, Some([0xAB; 32]), 2_000);
        match &out.outbound[0] {
            JdpOutboundFrame::RequestPayoutOutputsSuccess {
                request_id,
                coinbase_outputs,
            } => {
                assert_eq!(*request_id, 2);
                assert_eq!(coinbase_outputs, &vec![0xDE, 0xAD, 0xBE, 0xEF]);
            }
            _ => panic!("expected Success"),
        }
        // The set is now tracked as single-use pending for the token.
        assert_eq!(s.payout_outputs_tracker.entries_for_token(&token), 1);
        // ...and surfaced to the IO layer for the shared-bridge registry.
        assert!(
            out.events.iter().any(|e| matches!(
                e,
                JdpSessionEvent::PayoutOutputsIssued { token: t, .. } if *t == token
            )),
            "Success must emit PayoutOutputsIssued for the bridge"
        );
    }

    /// Spec §2.2: the Success frame (and the recorded set) echo the
    /// REQUEST's `request_id`, never a divergent resolver-supplied one.
    #[test]
    fn request_payout_outputs_echoes_request_id_not_resolver() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_request_extensions(
            &mut s,
            &RequestExtensions {
                request_id: 1,
                requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS],
            },
        );
        let token = handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 1_000)
            .outbound
            .into_iter()
            .find_map(|f| match f {
                JdpOutboundFrame::AllocateMiningJobTokenSuccess {
                    mining_job_token, ..
                } => Some(mining_job_token),
                _ => None,
            })
            .unwrap();
        let input = RequestPayoutOutputsInput {
            request_id: 77,
            mining_job_token: token,
            available_payout_value: 5_000_000_000,
        };
        // Resolver hands back a WRONG id (999) — the handler must ignore it.
        let resolution = PayoutOutputsResolution::Success {
            request_id: 999,
            outputs: vec![0xAB; 4],
        };
        let out =
            handle_request_payout_outputs(&mut s, &input, resolution, Some([0xAB; 32]), 2_000);
        match &out.outbound[0] {
            JdpOutboundFrame::RequestPayoutOutputsSuccess { request_id, .. } => {
                assert_eq!(*request_id, 77, "must echo the request's id, not 999");
            }
            f => panic!("expected Success, got {f:?}"),
        }
    }

    #[test]
    fn request_payout_outputs_unknown_token_emits_invalid_mining_job_token() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_request_extensions(
            &mut s,
            &RequestExtensions {
                request_id: 1,
                requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS],
            },
        );
        let bogus_token = Token([0u8; 16]);
        let input = RequestPayoutOutputsInput {
            request_id: 5,
            mining_job_token: bogus_token,
            available_payout_value: 0,
        };
        let resolution = PayoutOutputsResolution::Success {
            request_id: 5,
            outputs: vec![],
        };
        let out = handle_request_payout_outputs(&mut s, &input, resolution, None, 0);
        match &out.outbound[0] {
            JdpOutboundFrame::RequestPayoutOutputsError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_MINING_JOB_TOKEN);
            }
            _ => panic!("expected Error"),
        }
    }

    // ── DeclareMiningJob ───────────────────────────────────────────

    #[test]
    fn declare_in_coinbase_only_mode_returns_unsupported_feature_flags() {
        let mut s = fresh();
        let mut setup = good_setup();
        setup.flags = 0; // Coinbase-only mode
        handle_setup_connection(&mut s, &setup);
        // Need a token first — but we can't allocate in coinbase-only?
        // The handler runs the full-template check FIRST so it doesn't
        // need a valid token to test this path.
        let bogus_token = Token([0u8; 16]);
        let input = declare(1, bogus_token, vec![]);
        let out = handle_declare_mining_job(&mut s, &input, &HashMap::new(), None, 0);
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_UNSUPPORTED_FEATURE_FLAGS);
            }
            _ => panic!("expected DeclareMiningJobError"),
        }
    }

    #[test]
    fn declare_unknown_token_returns_invalid_mining_job_token() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let bogus = Token([1u8; 16]);
        let input = declare(2, bogus, vec![]);
        let out = handle_declare_mining_job(&mut s, &input, &HashMap::new(), None, 0);
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_MINING_JOB_TOKEN);
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn declare_fully_covered_accepts_immediately() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let wtxid_a = [0x01; 32];
        let wtxid_b = [0x02; 32];
        let mut tpl = HashMap::new();
        tpl.insert(wtxid_a, vec![0xCA; 16]);
        tpl.insert(wtxid_b, vec![0xFE; 16]);
        let input = declare(3, token, vec![wtxid_a, wtxid_b]);
        let out = handle_declare_mining_job(&mut s, &input, &tpl, Some([0xAB; 32]), 3_000);
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobSuccess {
                request_id,
                new_mining_job_token,
            } => {
                assert_eq!(*request_id, 3);
                assert_ne!(new_mining_job_token.0, [0u8; 16]);
            }
            _ => panic!("expected Success, got {:?}", out.outbound[0]),
        }
        assert!(matches!(out.events[0], JdpSessionEvent::JobDeclared { .. }));
        assert_eq!(s.declared_jobs.len(), 1);
        assert!(s.pending_declaration.is_none());
    }

    /// SV2 §6.4.3 / ext 0x0003: a declaration whose coinbase omits the pool's
    /// committed outputs is rejected; one that carries them is accepted.
    #[test]
    fn declare_validates_committed_coinbase_outputs() {
        use crate::jdp::dynamic_outputs::{encode_coinbase_outputs, DynamicOutput};
        use bp_common::Sats;

        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        // Negotiate ext 0x0003 so RequestPayoutOutputs records a pending set.
        let _ = handle_request_extensions(
            &mut s,
            &RequestExtensions {
                request_id: 1,
                requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS],
            },
        );
        let token =
            match handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 1_000).outbound[0] {
                JdpOutboundFrame::AllocateMiningJobTokenSuccess {
                    mining_job_token, ..
                } => mining_job_token,
                ref f => panic!("expected alloc success, got {f:?}"),
            };
        let prev_hash = [0xAB; 32];
        let pool_outputs = encode_coinbase_outputs(
            bitcoin::Network::Regtest,
            &[DynamicOutput {
                address: AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string())
                    .unwrap(),
                sats: Sats(600),
            }],
        )
        .unwrap();
        let _ = handle_request_payout_outputs(
            &mut s,
            &RequestPayoutOutputsInput {
                request_id: 2,
                mining_job_token: token,
                available_payout_value: 5_000_000_000,
            },
            PayoutOutputsResolution::Success {
                request_id: 2,
                outputs: pool_outputs.clone(),
            },
            Some(prev_hash),
            2_000,
        );

        // Reject: the default declare suffix doesn't carry the committed output.
        let bad = declare(3, token, vec![]);
        let out = handle_declare_mining_job(&mut s, &bad, &HashMap::new(), Some(prev_hash), 3_000);
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_COINBASE);
            }
            f => panic!("expected DeclareMiningJobError, got {f:?}"),
        }
        assert_eq!(
            s.declared_jobs.len(),
            0,
            "rejected declaration must not be stored"
        );

        // Accept: a real coinbase suffix carrying the committed output passes.
        let mut good = declare(4, token, vec![]);
        good.coinbase_tx_suffix = coinbase_suffix(&pool_outputs);
        let out = handle_declare_mining_job(&mut s, &good, &HashMap::new(), Some(prev_hash), 4_000);
        assert!(
            matches!(
                out.outbound[0],
                JdpOutboundFrame::DeclareMiningJobSuccess { .. }
            ),
            "declaration carrying the committed outputs must be accepted, got {:?}",
            out.outbound[0]
        );
        assert_eq!(s.declared_jobs.len(), 1);
    }

    /// ext 0x0003 §4 single-use / staleness: when the pool's chain tip
    /// advances between `RequestPayoutOutputs` and `DeclareMiningJob`,
    /// the pending set is superseded and the declaration is rejected
    /// with `stale-payout-outputs` (the JDC should re-request).
    #[test]
    fn declare_rejects_stale_payout_set_after_tip_advance() {
        use crate::jdp::dynamic_outputs::{encode_coinbase_outputs, DynamicOutput};
        use bp_common::Sats;

        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_request_extensions(
            &mut s,
            &RequestExtensions {
                request_id: 1,
                requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS],
            },
        );
        let token =
            match handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 1_000).outbound[0] {
                JdpOutboundFrame::AllocateMiningJobTokenSuccess {
                    mining_job_token, ..
                } => mining_job_token,
                ref f => panic!("expected alloc success, got {f:?}"),
            };
        let pool_outputs = encode_coinbase_outputs(
            bitcoin::Network::Regtest,
            &[DynamicOutput {
                address: AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string())
                    .unwrap(),
                sats: Sats(600),
            }],
        )
        .unwrap();
        // Issue the payout set under prev_hash A.
        let _ = handle_request_payout_outputs(
            &mut s,
            &RequestPayoutOutputsInput {
                request_id: 2,
                mining_job_token: token,
                available_payout_value: 5_000_000_000,
            },
            PayoutOutputsResolution::Success {
                request_id: 2,
                outputs: pool_outputs.clone(),
            },
            Some([0xAA; 32]),
            2_000,
        );

        // Declare under prev_hash B (tip advanced) — even with the
        // committed outputs carried, the set is now stale.
        let mut good = declare(3, token, vec![]);
        good.coinbase_tx_suffix = coinbase_suffix(&pool_outputs);
        let out =
            handle_declare_mining_job(&mut s, &good, &HashMap::new(), Some([0xBB; 32]), 3_000);
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_PAYOUT_OUTPUTS);
            }
            f => panic!("expected stale DeclareMiningJobError, got {f:?}"),
        }
        assert_eq!(s.declared_jobs.len(), 0);
    }

    /// ext 0x0003 §4: with the extension negotiated, declaring a job for a
    /// token that never had a `RequestPayoutOutputs` is rejected — the JDC
    /// must request a fresh payout set per declared job. Guards the
    /// "negotiate then skip the request" bypass (no base-protocol backstop).
    #[test]
    fn declare_without_payout_request_rejected_when_negotiated() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let _ = handle_request_extensions(
            &mut s,
            &RequestExtensions {
                request_id: 1,
                requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS],
            },
        );
        let token =
            match handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 1_000).outbound[0] {
                JdpOutboundFrame::AllocateMiningJobTokenSuccess {
                    mining_job_token, ..
                } => mining_job_token,
                ref f => panic!("expected alloc success, got {f:?}"),
            };
        // Declare without ever calling RequestPayoutOutputs for this token.
        let good = declare(2, token, vec![]);
        let out =
            handle_declare_mining_job(&mut s, &good, &HashMap::new(), Some([0xAB; 32]), 2_000);
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_PAYOUT_OUTPUTS);
            }
            f => panic!("expected DeclareMiningJobError, got {f:?}"),
        }
        assert_eq!(
            s.declared_jobs.len(),
            0,
            "rejected declaration must not be stored"
        );
    }

    #[test]
    fn declare_partial_coverage_emits_provide_missing_and_stashes_pending() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let wtxid_a = [0x01; 32];
        let wtxid_b = [0x02; 32]; // NOT in template
        let mut tpl = HashMap::new();
        tpl.insert(wtxid_a, vec![0xCA; 16]);
        let input = declare(4, token, vec![wtxid_a, wtxid_b]);
        let out = handle_declare_mining_job(&mut s, &input, &tpl, Some([0xAB; 32]), 3_000);
        match &out.outbound[0] {
            JdpOutboundFrame::ProvideMissingTransactions {
                request_id,
                unknown_tx_position_list,
            } => {
                assert_eq!(*request_id, 4);
                assert_eq!(unknown_tx_position_list, &vec![1]);
            }
            _ => panic!("expected ProvideMissingTransactions"),
        }
        assert!(s.pending_declaration.is_some());
        assert_eq!(s.declared_jobs.len(), 0, "not accepted yet");
    }

    // ── ProvideMissingTransactions.Success ────────────────────────

    #[test]
    fn provide_missing_with_pending_accepts_declaration() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let wtxid_a = [0x01; 32];
        let wtxid_b = [0x02; 32];
        let mut tpl = HashMap::new();
        tpl.insert(wtxid_a, vec![0xCA; 16]);
        let input = declare(5, token, vec![wtxid_a, wtxid_b]);
        let _ = handle_declare_mining_job(&mut s, &input, &tpl, Some([0xAB; 32]), 3_000);
        let success = ProvideMissingTransactionsSuccessInput {
            request_id: 5,
            transaction_list: vec![vec![0xFE; 16]],
        };
        let out =
            handle_provide_missing_transactions_success(&mut s, &success, Some([0xAB; 32]), 4_000);
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobSuccess { request_id, .. } => {
                assert_eq!(*request_id, 5);
            }
            _ => panic!("expected DeclareMiningJobSuccess"),
        }
        assert_eq!(s.declared_jobs.len(), 1);
        assert!(s.pending_declaration.is_none());
    }

    #[test]
    fn provide_missing_without_pending_is_silently_dropped() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let success = ProvideMissingTransactionsSuccessInput {
            request_id: 99,
            transaction_list: vec![vec![]],
        };
        let out = handle_provide_missing_transactions_success(&mut s, &success, None, 0);
        assert!(out.outbound.is_empty());
    }

    #[test]
    fn provide_missing_length_mismatch_is_silently_dropped() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let wtxid_a = [0x01; 32];
        let wtxid_b = [0x02; 32];
        let input = declare(6, token, vec![wtxid_a, wtxid_b]);
        let _ = handle_declare_mining_job(&mut s, &input, &HashMap::new(), Some([0xAB; 32]), 3_000);
        // Pending expects 2 missing (positions 0,1) but we provide 1.
        let bad_success = ProvideMissingTransactionsSuccessInput {
            request_id: 6,
            transaction_list: vec![vec![0xFE; 16]],
        };
        let out = handle_provide_missing_transactions_success(
            &mut s,
            &bad_success,
            Some([0xAB; 32]),
            4_000,
        );
        assert!(out.outbound.is_empty());
    }

    // ── PushSolution ───────────────────────────────────────────────

    #[test]
    fn push_solution_not_full_template_mode_is_dropped() {
        let mut s = fresh();
        let mut setup = good_setup();
        setup.flags = 0;
        handle_setup_connection(&mut s, &setup);
        let solution = PushSolutionInput {
            extranonce: vec![0; 8],
            prev_hash: [0xAB; 32],
            ntime: 0,
            nonce: 0,
            n_bits: 0,
            version: 0,
        };
        let out = handle_push_solution(&mut s, &solution, addr());
        assert!(out.outbound.is_empty());
        assert!(out.events.is_empty());
    }

    #[test]
    fn push_solution_no_declared_job_is_dropped() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let solution = PushSolutionInput {
            extranonce: vec![0; 8],
            prev_hash: [0xAB; 32],
            ntime: 0,
            nonce: 0,
            n_bits: 0,
            version: 0,
        };
        let out = handle_push_solution(&mut s, &solution, addr());
        assert!(out.events.is_empty());
    }

    /// Happy-path: declare a job → push solution that matches its
    /// prev_hash → emit BlockSubmissionCandidate with reconstructed
    /// coinbase.
    #[test]
    fn push_solution_emits_block_submission_candidate() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let wtxid_a = [0x01; 32];
        let mut tpl = HashMap::new();
        tpl.insert(wtxid_a, vec![0xCA; 8]);
        let input = declare(7, token, vec![wtxid_a]);
        let _ = handle_declare_mining_job(&mut s, &input, &tpl, Some([0xAB; 32]), 3_000);
        let extranonce = vec![0xEE; 8];
        let solution = PushSolutionInput {
            extranonce: extranonce.clone(),
            prev_hash: [0xAB; 32],
            ntime: 0x6500_0001,
            nonce: 0x1234_5678,
            n_bits: 0x1d00_ffff,
            version: 0x2000_0000,
        };
        let out = handle_push_solution(&mut s, &solution, addr());
        assert!(out.outbound.is_empty());
        match &out.events[0] {
            JdpSessionEvent::BlockSubmissionCandidate {
                coinbase_raw,
                transactions,
                prev_hash,
                ntime,
                ..
            } => {
                // prefix(8) + extranonce(8) + suffix(8) = 24
                assert_eq!(coinbase_raw.len(), 24);
                assert_eq!(&coinbase_raw[8..16], &extranonce[..]);
                assert_eq!(transactions.len(), 1, "1 non-coinbase tx");
                assert_eq!(transactions[0], vec![0xCA; 8]);
                assert_eq!(*prev_hash, [0xAB; 32]);
                assert_eq!(*ntime, 0x6500_0001);
            }
            _ => panic!("expected BlockSubmissionCandidate"),
        }
    }

    #[test]
    fn push_solution_missing_raw_tx_drops_silently() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let wtxid_a = [0x01; 32];
        let wtxid_b = [0x02; 32];
        let mut tpl = HashMap::new();
        tpl.insert(wtxid_a, vec![0xCA; 8]);
        // wtxid_b is in declared list but NOT in template → goes
        // into pending. Without ProvideMissingTransactions.Success,
        // raw_transactions[1] never gets populated.
        let input = declare(8, token, vec![wtxid_a, wtxid_b]);
        let _ = handle_declare_mining_job(&mut s, &input, &tpl, Some([0xAB; 32]), 3_000);
        // No declared_jobs entry yet (still pending) → push_solution
        // can't find a matching job → drops. Pin that path.
        assert_eq!(s.declared_jobs.len(), 0);
        let solution = PushSolutionInput {
            extranonce: vec![0; 8],
            prev_hash: [0xAB; 32],
            ntime: 0,
            nonce: 0,
            n_bits: 0,
            version: 0,
        };
        let out = handle_push_solution(&mut s, &solution, addr());
        assert!(out.events.is_empty());
    }
}
