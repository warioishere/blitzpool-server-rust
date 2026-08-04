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

use crate::bridge::DistributionAcceptance;

use super::declarations::{DeclaredJob, DeclaredJobStore};
use super::dynamic_outputs::{declared_coinbase_outputs, PayoutBooking};
use super::payout_distribution::validate_coinbase_outputs_against_distribution;
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
/// has expired (`DeclareMiningJob.Error`).
pub const ERR_INVALID_MINING_JOB_TOKEN: &str = "invalid-mining-job-token";

/// `invalid-job-param-value-coinbase_tx_outputs` — the declared
/// coinbase doesn't carry the pool's committed payout outputs verbatim
/// (an output is missing, modified, or reduced — spec §4).
pub const ERR_INVALID_JOB_PARAM_COINBASE: &str = "invalid-job-param-value-coinbase_tx_outputs";

/// `stale-payout-distribution` — the referenced `distribution_id` is
/// outside the acceptance window: superseded past the §7.2 grace slot,
/// settlement-invalidated (§10), or never published. The JDC SHOULD
/// re-declare against the latest received distribution.
pub const ERR_STALE_PAYOUT_DISTRIBUTION: &str =
    crate::extensions::payout_distribution_error_codes::STALE_PAYOUT_DISTRIBUTION;

/// `invalid-payout-distribution` — the declared coinbase violates §4
/// against the referenced distribution (positional recompute mismatch),
/// or the `distribution_id` TLV is missing/malformed while the
/// extension is negotiated.
pub const ERR_INVALID_PAYOUT_DISTRIBUTION: &str =
    crate::extensions::payout_distribution_error_codes::INVALID_PAYOUT_DISTRIBUTION;

/// `stale-chain-tip` — the chain tip advanced while this declaration was
/// in flight (between the initial `DeclareMiningJob` and the completion of
/// its `ProvideMissingTransactions` round-trip), so the declared job
/// references a superseded template. A benign race, not a protocol
/// violation — this exact string matters, because JDCs treat
/// `stale-chain-tip` as retryable and any other declaration error as fatal.
pub const ERR_STALE_CHAIN_TIP: &str = "stale-chain-tip";

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
    /// The ext 0x0003 §6 `distribution_id` TLV, when present and the
    /// extension is negotiated (the IO layer extracts it from the
    /// frame's trailing TLVs).
    pub distribution_id: Option<u64>,
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
    /// Ext 0x0003 §3.1 push: the JDS-initiated distribution frame.
    /// Emitted by the IO layer (connection-open, publisher tick,
    /// tailored push) — never by an inbound handler.
    SetPayoutDistribution(crate::extensions::SetPayoutDistribution),
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
        /// How to book this block, carried from the declare-time proof that
        /// the JDC's coinbase pays the pool's issued payout set. `None` →
        /// report the block, book nothing.
        booking: Option<PayoutBooking>,
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
    /// One outbound frame, no events. Public twin of [`Self::with_frame`] for
    /// the IO layer, which rejects a declaration before the pure handler runs.
    pub fn with_frame_pub(frame: JdpOutboundFrame) -> Self {
        Self::with_frame(frame)
    }

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
    /// Pool chain-tip when the `DeclareMiningJob` arrived. Compared against
    /// the tip when `ProvideMissingTransactions.Success` completes the
    /// round-trip — drift means the declared job references a superseded
    /// template and is rejected `stale-chain-tip` instead of accepted (and
    /// stamped with a tip it was never built for).
    pub prev_hash_at_declare: Option<[u8; 32]>,
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
///
/// `distribution_available` — whether the pool can actually publish a
/// `SetPayoutDistribution` right now (ext 0x0003 §3.1 makes it the
/// FIRST message after this exchange). When it can't (no PPLNS engine,
/// no template yet), 0x0003 is simply not offered: negotiating an
/// extension whose mandatory first push can't happen would break the
/// §3.1 ordering contract.
pub fn handle_request_extensions(
    state: &mut JdpSessionState,
    input: &RequestExtensions,
    distribution_available: bool,
) -> JdpHandlerOutcome {
    if !state.setup_complete {
        return JdpHandlerOutcome::default();
    }

    let mut supported: Vec<u16> = Vec::new();
    let mut unsupported: Vec<u16> = Vec::new();
    for ext in &input.requested_extensions {
        let offerable = is_jdp_extension_supported(*ext)
            && (*ext != SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS || distribution_available);
        if offerable {
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
    distribution: Option<DistributionAcceptance>,
    now_ms: u64,
) -> JdpHandlerOutcome {
    // §2: a distribution reference from a client that never negotiated
    // ext 0x0003 MUST be rejected. The IO layer captures the TLV
    // unconditionally (not filtered by the negotiated set) precisely so
    // this gate can see it.
    if input.distribution_id.is_some()
        && !state
            .negotiated_extensions
            .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
    {
        return JdpHandlerOutcome::with_frame(JdpOutboundFrame::DeclareMiningJobError {
            request_id: input.request_id,
            error_code: ERR_INVALID_PAYOUT_DISTRIBUTION.to_string(),
            error_details: b"distribution_id TLV requires negotiated ext 0x0003".to_vec(),
        });
    }
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
            distribution,
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
        prev_hash_at_declare: current_prev_hash,
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
///
/// `distribution` — RE-resolved by the IO layer at THIS point, not
/// carried over from declare time: the referenced distribution may have
/// been superseded or settlement-invalidated during the round-trip, and
/// §7.2/§10 are judged when the declaration is actually accepted.
pub fn handle_provide_missing_transactions_success(
    state: &mut JdpSessionState,
    input: &ProvideMissingTransactionsSuccessInput,
    current_prev_hash: Option<[u8; 32]>,
    distribution: Option<DistributionAcceptance>,
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
    // Tip-drift check: if the chain advanced during the missing-transactions
    // round-trip, the declared job references a superseded template. Reject
    // `stale-chain-tip` (retryable — the JDC re-declares against its new
    // template) instead of accepting a job stamped with a tip it was never
    // built for.
    if pending.prev_hash_at_declare != current_prev_hash {
        return JdpHandlerOutcome::with_frame(JdpOutboundFrame::DeclareMiningJobError {
            request_id: input.request_id,
            error_code: ERR_STALE_CHAIN_TIP.to_string(),
            error_details: b"chain tip advanced during the missing-transactions round-trip"
                .to_vec(),
        });
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
        distribution,
        now_ms,
    )
}

/// Lowercase hex of a 32-byte hash for log lines. Hand-rolled like
/// `Token::to_hex` — the `hex` crate is a dev-only dependency here.
fn hash_hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

// ── Internal: accept_declaration ────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn accept_declaration(
    state: &mut JdpSessionState,
    input: &DeclareMiningJobInput,
    raw_transactions: HashMap<u32, Vec<u8>>,
    original_token: Token,
    miner_address: AddressId,
    current_prev_hash: Option<[u8; 32]>,
    distribution: Option<DistributionAcceptance>,
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

    // Ext 0x0003 §7 validation (push model). When the JDC negotiated
    // 0x0003, every declared job MUST reference a published distribution
    // via the §6 `distribution_id` TLV, and the declared coinbase MUST
    // match the §4 recompute POSITIONALLY (§7.1) — the spec fixes the
    // output order, so there is no multiset containment to play with.
    // When 0x0003 wasn't negotiated, this is a plain base-protocol
    // declaration and the block below is skipped.
    let mut declared_booking: Option<PayoutBooking> = None;
    if state
        .negotiated_extensions
        .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
    {
        if input.distribution_id.is_none() {
            // §6: the TLV is mandatory on a negotiated connection — the
            // allocate carried no outputs (§2), so a declaration without
            // a distribution reference pays nobody the pool knows.
            tracing::warn!(
                request_id = input.request_id,
                "jdp: 0x0003 negotiated but DeclareMiningJob carries no distribution_id TLV — rejecting"
            );
            return JdpHandlerOutcome::with_frame(JdpOutboundFrame::DeclareMiningJobError {
                request_id: input.request_id,
                error_code: ERR_INVALID_PAYOUT_DISTRIBUTION.to_string(),
                error_details: b"missing distribution_id TLV (ext 0x0003 is negotiated)".to_vec(),
            });
        }
        let entry = match distribution {
            Some(DistributionAcceptance::Accepted(entry)) => entry,
            Some(DistributionAcceptance::Stale) | Some(DistributionAcceptance::Unknown) => {
                // §7.2/§7.3: outside the acceptance window (superseded,
                // settlement-invalidated, or never published) — the JDC
                // re-declares against the latest received distribution.
                tracing::warn!(
                    request_id = input.request_id,
                    distribution_id = input.distribution_id,
                    "jdp: declared distribution_id outside the acceptance window — rejecting"
                );
                return JdpHandlerOutcome::with_frame(JdpOutboundFrame::DeclareMiningJobError {
                    request_id: input.request_id,
                    error_code: ERR_STALE_PAYOUT_DISTRIBUTION.to_string(),
                    error_details: b"distribution_id not accepted (superseded or unknown)".to_vec(),
                });
            }
            None => {
                // IO-layer contract breach: a negotiated declare must
                // arrive with a resolved acceptance. Fail closed.
                tracing::warn!(
                    request_id = input.request_id,
                    "jdp: negotiated declare arrived without a resolved distribution acceptance — rejecting"
                );
                return JdpHandlerOutcome::with_frame(JdpOutboundFrame::DeclareMiningJobError {
                    request_id: input.request_id,
                    error_code: ERR_STALE_PAYOUT_DISTRIBUTION.to_string(),
                    error_details: b"distribution_id not accepted (superseded or unknown)".to_vec(),
                });
            }
        };
        let Some(declared_outputs) =
            declared_coinbase_outputs(&input.coinbase_tx_prefix, &input.coinbase_tx_suffix)
        else {
            tracing::warn!(
                request_id = input.request_id,
                "jdp: declared coinbase suffix failed to parse — rejecting declaration"
            );
            return JdpHandlerOutcome::with_frame(JdpOutboundFrame::DeclareMiningJobError {
                request_id: input.request_id,
                error_code: ERR_INVALID_JOB_PARAM_COINBASE.to_string(),
                error_details: b"declared coinbase suffix is not a parseable output vector"
                    .to_vec(),
            });
        };
        match validate_coinbase_outputs_against_distribution(
            &declared_outputs,
            &entry.pool_payout,
            &entry.payouts,
            &entry.dust_limits,
            &entry.additional_outputs,
        ) {
            Ok(_declared_revenue) => {
                // Vouch for booking only when the distribution's
                // settlement snapshot actually landed.
                if entry.bookable {
                    declared_booking = Some(PayoutBooking {
                        distribution_id: entry.distribution_id,
                        payouts_fingerprint: entry.payouts_fingerprint.unwrap_or([0u8; 32]),
                        reference_reward_sats: entry.reference_reward_sats,
                    });
                } else {
                    tracing::warn!(
                        request_id = input.request_id,
                        distribution_id = entry.distribution_id,
                        "jdp: declaration accepted but distribution is not bookable — a found \
                         block will be reported, not booked"
                    );
                }
            }
            Err(violation) => {
                tracing::warn!(
                    request_id = input.request_id,
                    distribution_id = entry.distribution_id,
                    ?violation,
                    "jdp: declared coinbase violates §4 against the referenced distribution — rejecting"
                );
                return JdpHandlerOutcome::with_frame(JdpOutboundFrame::DeclareMiningJobError {
                    request_id: input.request_id,
                    error_code: ERR_INVALID_PAYOUT_DISTRIBUTION.to_string(),
                    error_details: b"declared coinbase does not match the referenced distribution"
                        .to_vec(),
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
        booking: declared_booking,
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
    // The drops below are WARN-logged: a PushSolution is a found BLOCK, and
    // discarding one silently would make a lost pool-side block booking
    // undiagnosable. (The block itself is safe either way — the JDC submits
    // through its own node too.)
    if !state.full_template_mode {
        tracing::warn!(
            prev_hash = %hash_hex(&input.prev_hash),
            "jdp: PushSolution dropped — connection not in Full-Template mode"
        );
        return JdpHandlerOutcome::default();
    }
    let job = match state.declared_jobs.match_for_solution(&input.prev_hash) {
        Some(j) => j,
        None => {
            tracing::warn!(
                prev_hash = %hash_hex(&input.prev_hash),
                "jdp: PushSolution dropped — no matching declared job (reconnect gap or stale solution)"
            );
            return JdpHandlerOutcome::default();
        }
    };

    // Snapshot the fields we'll emit + the new_token (immutable
    // lookup before we drop the borrow). `match_for_solution`
    // already returned a reference into `state.declared_jobs`; we
    // copy out the bytes we need so the borrow can drop before
    // building the outcome.
    let new_token = job.new_token;
    let booking = job.booking;
    let coinbase_prefix = job.coinbase_tx_prefix.clone();
    let coinbase_suffix = job.coinbase_tx_suffix.clone();
    let wtxid_count = job.wtxid_list.len();
    let mut transactions: Vec<Vec<u8>> = Vec::with_capacity(wtxid_count);
    for i in 0..wtxid_count {
        match job.raw_transactions.get(&(i as u32)) {
            Some(raw) => transactions.push(raw.clone()),
            None => {
                tracing::warn!(
                    prev_hash = %hash_hex(&input.prev_hash),
                    position = i,
                    "jdp: PushSolution dropped — declared job is missing raw tx data"
                );
                return JdpHandlerOutcome::default();
            }
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
            booking,
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
    use crate::jdp::payout_distribution::{compute_payout_vector, WeightedOutput};

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
            coinbase_tx_prefix: coinbase_prefix(),
            coinbase_tx_suffix: vec![0xBB; 8],
            wtxid_list: wtxids,
            distribution_id: None,
        }
    }

    /// A realistic declared `coinbase_tx_prefix`: coinbase header, a BIP-34
    /// height push, and a 12-byte extranonce slot the prefix stops at. The
    /// declare-time validation rebuilds the transaction from this plus the
    /// suffix, so a placeholder blob no longer works — it used to, because the
    /// old parser only ever looked at the suffix.
    const EXTRANONCE_SLOT: usize = 12;
    fn coinbase_prefix() -> Vec<u8> {
        use bitcoin::consensus::Encodable;
        let script_sig_head: [u8; 3] = [0x03, 0xC8, 0x00];
        let mut p = Vec::new();
        p.extend_from_slice(&2u32.to_le_bytes()); // version
        p.push(0x01); // input count
        p.extend_from_slice(&[0u8; 32]); // prevout txid
        p.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // prevout index
        bitcoin::VarInt((script_sig_head.len() + EXTRANONCE_SLOT) as u64)
            .consensus_encode(&mut p)
            .unwrap();
        p.extend_from_slice(&script_sig_head);
        p
    }

    /// Wrap a consensus `Vec<TxOut>` blob as a realistic coinbase suffix
    /// (`nSequence(4) + outputs + nLockTime(4)`) — what the declare-time
    /// payout-output validation parses, paired with [`coinbase_prefix`].
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

    /// Negotiate ext 0x0003 on a setup-complete session.
    fn negotiate_0x0003(s: &mut JdpSessionState) {
        let out = handle_request_extensions(
            s,
            &RequestExtensions {
                request_id: 1,
                requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS],
            },
            true,
        );
        assert!(
            matches!(
                out.outbound[0],
                JdpOutboundFrame::RequestExtensionsSuccess { .. }
            ),
            "0x0003 negotiation must succeed in fixtures"
        );
    }

    /// A minimal §3.1 distribution: pool slot (weight 1) + one miner
    /// payout slot (weight 9), no pruning, no additional outputs.
    fn distribution_entry(id: u64) -> crate::bridge::PayoutDistributionEntry {
        crate::bridge::PayoutDistributionEntry {
            distribution_id: id,
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
            payouts_fingerprint: Some([id as u8; 32]),
            bookable: true,
            owner: None,
            jdp_session_id: None,
            published_at_ms: 1_000,
        }
    }

    fn accepted(entry: crate::bridge::PayoutDistributionEntry) -> Option<DistributionAcceptance> {
        Some(DistributionAcceptance::Accepted(std::sync::Arc::new(entry)))
    }

    /// A coinbase suffix whose outputs are the §4 recompute for `entry`
    /// at revenue `t` — passes the §7.1 positional validation by
    /// construction.
    fn matching_suffix(entry: &crate::bridge::PayoutDistributionEntry, t: u64) -> Vec<u8> {
        let outputs = compute_payout_vector(
            &entry.pool_payout,
            &entry.payouts,
            &entry.dust_limits,
            &entry.additional_outputs,
            t,
        )
        .unwrap();
        coinbase_suffix(&bitcoin::consensus::serialize(&outputs))
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
        let out = handle_request_extensions(&mut s, &req, true);
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
        let out = handle_request_extensions(&mut s, &req, true);
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
        let out = handle_request_extensions(&mut s, &req, true);
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
        let out = handle_request_extensions(&mut s, &req, true);
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

    /// §3.1 makes `SetPayoutDistribution` the FIRST message after the
    /// extension exchange — when the pool cannot publish one yet, 0x0003
    /// is not offered and the request errors as unsupported.
    #[test]
    fn request_extensions_0x0003_not_offered_when_distribution_unavailable() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let req = RequestExtensions {
            request_id: 4,
            requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS],
        };
        let out = handle_request_extensions(&mut s, &req, false);
        match &out.outbound[0] {
            JdpOutboundFrame::RequestExtensionsError {
                request_id,
                unsupported_extensions,
                ..
            } => {
                assert_eq!(*request_id, 4);
                assert_eq!(
                    unsupported_extensions,
                    &vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS]
                );
            }
            f => panic!("expected RequestExtensionsError, got {f:?}"),
        }
        assert!(
            s.negotiated_extensions.is_empty(),
            "an unofferable extension must not be recorded as negotiated"
        );
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
        let out = handle_declare_mining_job(&mut s, &input, &HashMap::new(), None, None, 0);
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
        let out = handle_declare_mining_job(&mut s, &input, &HashMap::new(), None, None, 0);
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
        let out = handle_declare_mining_job(&mut s, &input, &tpl, Some([0xAB; 32]), None, 3_000);
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

    /// §6: on a 0x0003-negotiated connection every `DeclareMiningJob`
    /// MUST reference a published distribution — a declaration without
    /// the `distribution_id` TLV pays nobody the pool knows and is
    /// rejected `invalid-payout-distribution`.
    #[test]
    fn declare_negotiated_without_distribution_tlv_rejected() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        negotiate_0x0003(&mut s);
        // `declare()` carries no distribution_id TLV.
        let input = declare(2, token, vec![]);
        let out = handle_declare_mining_job(
            &mut s,
            &input,
            &HashMap::new(),
            Some([0xAB; 32]),
            None,
            3_000,
        );
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_PAYOUT_DISTRIBUTION);
            }
            f => panic!("expected DeclareMiningJobError, got {f:?}"),
        }
        assert_eq!(
            s.declared_jobs.len(),
            0,
            "rejected declaration must not be stored"
        );
    }

    /// §7.2/§7.3: a `distribution_id` outside the acceptance window is
    /// rejected `stale-payout-distribution`. `Unknown` folds into the
    /// same wire code — a JDC can't distinguish "superseded" from
    /// "never published", both mean "re-declare against the latest".
    #[test]
    fn declare_with_stale_or_unknown_distribution_rejected() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        negotiate_0x0003(&mut s);
        let mut input = declare(2, token, vec![]);
        input.distribution_id = Some(7);
        for acceptance in [
            DistributionAcceptance::Stale,
            DistributionAcceptance::Unknown,
        ] {
            let out = handle_declare_mining_job(
                &mut s,
                &input,
                &HashMap::new(),
                Some([0xAB; 32]),
                Some(acceptance),
                3_000,
            );
            match &out.outbound[0] {
                JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                    assert_eq!(error_code, ERR_STALE_PAYOUT_DISTRIBUTION);
                }
                f => panic!("expected stale DeclareMiningJobError, got {f:?}"),
            }
        }
        assert_eq!(s.declared_jobs.len(), 0);
    }

    /// A negotiated declare must arrive with a caller-resolved
    /// acceptance; `None` is an IO-contract breach and fails closed
    /// with the stale code.
    #[test]
    fn declare_negotiated_with_unresolved_acceptance_fails_closed() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        negotiate_0x0003(&mut s);
        let mut input = declare(2, token, vec![]);
        input.distribution_id = Some(7);
        let out = handle_declare_mining_job(
            &mut s,
            &input,
            &HashMap::new(),
            Some([0xAB; 32]),
            None,
            3_000,
        );
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_PAYOUT_DISTRIBUTION);
            }
            f => panic!("expected DeclareMiningJobError, got {f:?}"),
        }
        assert_eq!(s.declared_jobs.len(), 0);
    }

    /// §7.1 recompute-and-compare: a declared coinbase matching the
    /// referenced distribution positionally is accepted and the job is
    /// stamped with a booking; one paying the right scripts and the
    /// right sum in the WRONG positions is rejected
    /// `invalid-payout-distribution` (the spec fixes the output order).
    #[test]
    fn declare_validates_coinbase_against_distribution() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        negotiate_0x0003(&mut s);
        let entry = distribution_entry(7);

        // Reject: swap the pool/payout positions, Σ preserved.
        let mut swapped = compute_payout_vector(
            &entry.pool_payout,
            &entry.payouts,
            &entry.dust_limits,
            &entry.additional_outputs,
            5_000_000_000,
        )
        .unwrap();
        swapped.swap(0, 1);
        let mut bad = declare(3, token, vec![]);
        bad.distribution_id = Some(7);
        bad.coinbase_tx_suffix = coinbase_suffix(&bitcoin::consensus::serialize(&swapped));
        let out = handle_declare_mining_job(
            &mut s,
            &bad,
            &HashMap::new(),
            Some([0xAB; 32]),
            accepted(distribution_entry(7)),
            3_000,
        );
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_PAYOUT_DISTRIBUTION);
            }
            f => panic!("expected DeclareMiningJobError, got {f:?}"),
        }
        assert_eq!(
            s.declared_jobs.len(),
            0,
            "rejected declaration must not be stored"
        );

        // Accept: the §4 vector as recomputed validates by construction.
        let mut good = declare(4, token, vec![]);
        good.distribution_id = Some(7);
        good.coinbase_tx_suffix = matching_suffix(&entry, 5_000_000_000);
        let out = handle_declare_mining_job(
            &mut s,
            &good,
            &HashMap::new(),
            Some([0xAB; 32]),
            accepted(distribution_entry(7)),
            4_000,
        );
        assert!(
            matches!(
                out.outbound[0],
                JdpOutboundFrame::DeclareMiningJobSuccess { .. }
            ),
            "declaration matching the distribution must be accepted, got {:?}",
            out.outbound[0]
        );
        assert_eq!(s.declared_jobs.len(), 1);
        let job = s.declared_jobs.iter().next().unwrap();
        assert_eq!(
            job.booking,
            Some(PayoutBooking {
                distribution_id: 7,
                payouts_fingerprint: [7u8; 32],
                reference_reward_sats: 312_500_000,
            }),
            "a validated coinbase stamps the job with its booking"
        );
    }

    /// A negotiated declare whose suffix is not a parseable output
    /// vector fails closed (never accept an output set we cannot
    /// verify).
    #[test]
    fn declare_unparseable_suffix_rejected_when_negotiated() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        negotiate_0x0003(&mut s);
        // `declare()`'s default suffix is 8 opaque bytes — strips to an
        // empty body, which is not a consensus TxOut vector.
        let mut input = declare(3, token, vec![]);
        input.distribution_id = Some(7);
        let out = handle_declare_mining_job(
            &mut s,
            &input,
            &HashMap::new(),
            Some([0xAB; 32]),
            accepted(distribution_entry(7)),
            3_000,
        );
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_JOB_PARAM_COINBASE);
            }
            f => panic!("expected DeclareMiningJobError, got {f:?}"),
        }
        assert_eq!(s.declared_jobs.len(), 0);
    }

    /// §2: a distribution reference from a client that never negotiated
    /// ext 0x0003 MUST be rejected — the IO layer captures the TLV
    /// unconditionally so this gate fires in production too.
    #[test]
    fn declare_with_tlv_but_no_negotiation_rejected() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let mut input = declare(2, token, vec![]);
        input.distribution_id = Some(7);
        let out = handle_declare_mining_job(
            &mut s,
            &input,
            &HashMap::new(),
            Some([0xAB; 32]),
            accepted(distribution_entry(7)),
            3_000,
        );
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_INVALID_PAYOUT_DISTRIBUTION);
            }
            other => panic!("expected DeclareMiningJobError, got {other:?}"),
        }
        assert_eq!(s.declared_jobs.len(), 0, "nothing may be declared");
    }

    /// `bookable = false` (settlement snapshot missing): the
    /// declaration is still accepted, but no booking is stamped — a
    /// found block is reported, not booked.
    #[test]
    fn declare_unbookable_distribution_accepted_without_booking() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        negotiate_0x0003(&mut s);
        let mut entry = distribution_entry(7);
        entry.bookable = false;
        let mut input = declare(3, token, vec![]);
        input.distribution_id = Some(7);
        input.coinbase_tx_suffix = matching_suffix(&entry, 5_000_000_000);
        let out = handle_declare_mining_job(
            &mut s,
            &input,
            &HashMap::new(),
            Some([0xAB; 32]),
            accepted(entry),
            3_000,
        );
        assert!(
            matches!(
                out.outbound[0],
                JdpOutboundFrame::DeclareMiningJobSuccess { .. }
            ),
            "unbookable distribution still serves the job, got {:?}",
            out.outbound[0]
        );
        assert_eq!(s.declared_jobs.iter().next().unwrap().booking, None);
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
        let out = handle_declare_mining_job(&mut s, &input, &tpl, Some([0xAB; 32]), None, 3_000);
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
        let _ = handle_declare_mining_job(&mut s, &input, &tpl, Some([0xAB; 32]), None, 3_000);
        let success = ProvideMissingTransactionsSuccessInput {
            request_id: 5,
            transaction_list: vec![vec![0xFE; 16]],
        };
        let out = handle_provide_missing_transactions_success(
            &mut s,
            &success,
            Some([0xAB; 32]),
            None,
            4_000,
        );
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobSuccess { request_id, .. } => {
                assert_eq!(*request_id, 5);
            }
            _ => panic!("expected DeclareMiningJobSuccess"),
        }
        assert_eq!(s.declared_jobs.len(), 1);
        assert!(s.pending_declaration.is_none());
    }

    /// Chain tip advances during the missing-transactions round-trip →
    /// the declaration is rejected `stale-chain-tip` (retryable) instead
    /// of being accepted and stamped with a tip it was never built for.
    #[test]
    fn provide_missing_with_tip_drift_rejects_stale_chain_tip() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let wtxid_a = [0x01; 32];
        let wtxid_b = [0x02; 32];
        let mut tpl = HashMap::new();
        tpl.insert(wtxid_a, vec![0xCA; 16]);
        let input = declare(5, token, vec![wtxid_a, wtxid_b]);
        // Declared under tip 0xAB…
        let _ = handle_declare_mining_job(&mut s, &input, &tpl, Some([0xAB; 32]), None, 3_000);
        let success = ProvideMissingTransactionsSuccessInput {
            request_id: 5,
            transaction_list: vec![vec![0xFE; 16]],
        };
        // …but the round-trip completes under tip 0xCD.
        let out = handle_provide_missing_transactions_success(
            &mut s,
            &success,
            Some([0xCD; 32]),
            None,
            4_000,
        );
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError {
                request_id,
                error_code,
                ..
            } => {
                assert_eq!(*request_id, 5);
                assert_eq!(error_code, ERR_STALE_CHAIN_TIP);
            }
            f => panic!("expected DeclareMiningJobError, got {f:?}"),
        }
        assert_eq!(s.declared_jobs.len(), 0, "stale job must not be stored");
        assert!(
            s.pending_declaration.is_none(),
            "pending state is consumed — the JDC re-declares fresh"
        );
    }

    /// §7.2/§10 are judged when the declaration is ACCEPTED: a
    /// distribution superseded during the missing-transactions
    /// round-trip rejects the declaration `stale-payout-distribution`
    /// even though it was accepted at declare time.
    #[test]
    fn provide_missing_re_resolves_distribution_at_acceptance() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        negotiate_0x0003(&mut s);
        let wtxid_a = [0x01; 32];
        let wtxid_b = [0x02; 32]; // NOT in template → round-trip
        let mut tpl = HashMap::new();
        tpl.insert(wtxid_a, vec![0xCA; 16]);
        let entry = distribution_entry(7);
        let mut input = declare(5, token, vec![wtxid_a, wtxid_b]);
        input.distribution_id = Some(7);
        input.coinbase_tx_suffix = matching_suffix(&entry, 5_000_000_000);
        // Accepted at declare time…
        let _ = handle_declare_mining_job(
            &mut s,
            &input,
            &tpl,
            Some([0xAB; 32]),
            accepted(entry),
            3_000,
        );
        assert!(s.pending_declaration.is_some());
        let success = ProvideMissingTransactionsSuccessInput {
            request_id: 5,
            transaction_list: vec![vec![0xFE; 16]],
        };
        // …but superseded during the round-trip.
        let out = handle_provide_missing_transactions_success(
            &mut s,
            &success,
            Some([0xAB; 32]),
            Some(DistributionAcceptance::Stale),
            4_000,
        );
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_PAYOUT_DISTRIBUTION);
            }
            f => panic!("expected stale DeclareMiningJobError, got {f:?}"),
        }
        assert_eq!(s.declared_jobs.len(), 0);
    }

    /// The round-trip path runs the same §7.1 validation as the
    /// immediate path: a still-accepted distribution plus matching
    /// coinbase completes with a booking-stamped job.
    #[test]
    fn provide_missing_accepts_negotiated_declaration_with_booking() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        negotiate_0x0003(&mut s);
        let wtxid_a = [0x01; 32];
        let wtxid_b = [0x02; 32];
        let mut tpl = HashMap::new();
        tpl.insert(wtxid_a, vec![0xCA; 16]);
        let entry = distribution_entry(7);
        let mut input = declare(5, token, vec![wtxid_a, wtxid_b]);
        input.distribution_id = Some(7);
        input.coinbase_tx_suffix = matching_suffix(&entry, 5_000_000_000);
        let _ = handle_declare_mining_job(
            &mut s,
            &input,
            &tpl,
            Some([0xAB; 32]),
            accepted(distribution_entry(7)),
            3_000,
        );
        let success = ProvideMissingTransactionsSuccessInput {
            request_id: 5,
            transaction_list: vec![vec![0xFE; 16]],
        };
        let out = handle_provide_missing_transactions_success(
            &mut s,
            &success,
            Some([0xAB; 32]),
            accepted(distribution_entry(7)),
            4_000,
        );
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobSuccess { request_id, .. } => {
                assert_eq!(*request_id, 5);
            }
            f => panic!("expected DeclareMiningJobSuccess, got {f:?}"),
        }
        assert_eq!(s.declared_jobs.len(), 1);
        assert_eq!(
            s.declared_jobs.iter().next().unwrap().booking,
            Some(PayoutBooking {
                distribution_id: 7,
                payouts_fingerprint: [7u8; 32],
                reference_reward_sats: 312_500_000,
            })
        );
    }

    #[test]
    fn provide_missing_without_pending_is_silently_dropped() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let success = ProvideMissingTransactionsSuccessInput {
            request_id: 99,
            transaction_list: vec![vec![]],
        };
        let out = handle_provide_missing_transactions_success(&mut s, &success, None, None, 0);
        assert!(out.outbound.is_empty());
    }

    #[test]
    fn provide_missing_length_mismatch_is_silently_dropped() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let wtxid_a = [0x01; 32];
        let wtxid_b = [0x02; 32];
        let input = declare(6, token, vec![wtxid_a, wtxid_b]);
        let _ = handle_declare_mining_job(
            &mut s,
            &input,
            &HashMap::new(),
            Some([0xAB; 32]),
            None,
            3_000,
        );
        // Pending expects 2 missing (positions 0,1) but we provide 1.
        let bad_success = ProvideMissingTransactionsSuccessInput {
            request_id: 6,
            transaction_list: vec![vec![0xFE; 16]],
        };
        let out = handle_provide_missing_transactions_success(
            &mut s,
            &bad_success,
            Some([0xAB; 32]),
            None,
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
        let _ = handle_declare_mining_job(&mut s, &input, &tpl, Some([0xAB; 32]), None, 3_000);
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
                // The candidate is the declared prefix + the miner's extranonce
                // + the declared suffix, spliced in that order.
                let plen = coinbase_prefix().len();
                assert_eq!(coinbase_raw.len(), plen + extranonce.len() + 8);
                assert_eq!(&coinbase_raw[..plen], &coinbase_prefix()[..]);
                assert_eq!(
                    &coinbase_raw[plen..plen + extranonce.len()],
                    &extranonce[..]
                );
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
        let _ = handle_declare_mining_job(&mut s, &input, &tpl, Some([0xAB; 32]), None, 3_000);
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
