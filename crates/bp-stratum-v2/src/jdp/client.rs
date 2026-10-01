// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure handler-layer for the JDP-server per-connection state machine.
//!
//! Wraps [`crate::tokens`], [`crate::jdp::declarations`],
//! [`crate::jdp::tx_validation`], [`crate::jdp::dynamic_outputs`] and the
//! [`crate::extensions`] codecs into a connection-scoped state struct plus
//! `handle_*` functions, in the style of [`crate::mining::client`]: each
//! handler mutates `&mut JdpSessionState` and returns a
//! [`JdpHandlerOutcome`] (outbound frames + [`JdpSessionEvent`]s). No I/O,
//! no broadcasting, no DB writes.
//!
//! The IO layer (`jdp_server.rs`) resolves any async hooks (mempool
//! validation, template-tx snapshot, dynamic outputs) before calling a
//! handler, so the handlers stay pure and testable with synthetic inputs.
//! Handlers never close the socket: they emit
//! [`JdpSessionEvent::Disconnect`] and the IO layer writes the pending
//! `SetupConnection.Error` before closing, per SV2
//! Overview/SetupConnection.Error.

use std::collections::{HashMap, HashSet};

use bitcoin::hex::DisplayHex;
use bp_common::normalize_btc_address;
use bp_common::AddressId;

use crate::codec_common::SetupConnectionInput;
use crate::extensions::{RequestExtensions, SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS};
use crate::protocol_version::{negotiate_version, MIN_PROTOCOL_VERSION};
use crate::tokens::{Token, TokenAllocError, TokenStore};

use crate::bridge::DistributionAcceptance;

use super::declarations::{DeclaredJob, DeclaredJobStore};
use super::dynamic_outputs::{declared_coinbase_tx, CandidateBacking, PayoutBooking};
use super::payout_distribution::validate_coinbase_outputs_against_distribution;
use super::tx_validation::{merge_provided_with_known, PartitionResult, PendingDeclaration};

// ── Constants ────────────────────────────────────────────────────────

/// SV2 protocol code for the Job-Declaration sub-protocol — the
/// `protocol` field of SV2 Overview/SetupConnection, not a JDP flag.
pub const PROTOCOL_JOB_DECLARATION: u8 = 1;

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

/// `unsupported-feature-flags` — JDC sent `DeclareMiningJob` without
/// negotiating `DECLARE_TX_DATA` (Full-Template mode).
///
/// Borrowed from `SetupConnection.Error`: SV2 JDP/DeclareMiningJob.Error
/// enumerates no codes, and no job-declaration code says "flag never
/// negotiated" more precisely. Pinned in `tests/wire_error_parity.rs`.
/// ⚠️ Never answer this with `stale-chain-tip`: that invites a retry
/// against a condition only a new connection can resolve.
pub const ERR_UNSUPPORTED_FEATURE_FLAGS: &str = "unsupported-feature-flags";

/// `invalid-mining-job-token` — the token referenced was never issued, has
/// expired, or was already SPENT by an earlier declaration
/// (`DeclareMiningJob.Error`). The last is the common one: a token authorises
/// one declaration.
pub const ERR_INVALID_MINING_JOB_TOKEN: &str = "invalid-mining-job-token";

/// `invalid-job-param-value-coinbase_tx_outputs` — the declared coinbase
/// doesn't carry the pool's committed payout outputs verbatim (an output is
/// missing, modified, or reduced — ext 0x0003/Payout Computation).
pub const ERR_INVALID_JOB_PARAM_COINBASE: &str = "invalid-job-param-value-coinbase_tx_outputs";

/// `stale-payout-distribution` — the referenced `distribution_id` is outside
/// the acceptance window: superseded past the ext 0x0003/Grace Window,
/// settlement-invalidated (ext 0x0003/Implementation Notes), or never
/// published. The JDC SHOULD re-declare against the latest received
/// distribution.
pub const ERR_STALE_PAYOUT_DISTRIBUTION: &str =
    crate::extensions::payout_distribution_error_codes::STALE_PAYOUT_DISTRIBUTION;

/// `invalid-payout-distribution` — the declared coinbase violates
/// ext 0x0003/Payout Computation against the referenced distribution
/// (positional recompute mismatch), or the `distribution_id` TLV is
/// missing/malformed while the extension is negotiated.
pub const ERR_INVALID_PAYOUT_DISTRIBUTION: &str =
    crate::extensions::payout_distribution_error_codes::INVALID_PAYOUT_DISTRIBUTION;

/// `stale-chain-tip` — the chain tip advanced while this declaration was
/// in flight (between the initial `DeclareMiningJob` and the completion of
/// its `ProvideMissingTransactions` round-trip), so the declared job
/// references a superseded template. A benign race, not a protocol
/// violation — this exact string matters, because JDCs treat
/// `stale-chain-tip` as retryable and any other declaration error as fatal.
pub const ERR_STALE_CHAIN_TIP: &str = "stale-chain-tip";

/// `missing-txs` — the declaration is complete (its
/// `ProvideMissingTransactions.Success` has arrived) and the pool's node still
/// cannot resolve every declared wtxid. The node only resolves a transaction
/// by the wtxid it hashes to, so a supplied transaction that does not match
/// its position stays missing — and a declaration the node never saw whole
/// was never validated.
pub const ERR_MISSING_TXS: &str = "missing-txs";

/// How many declarations one connection may have waiting for their
/// `ProvideMissingTransactions.Success` at once. A JDC declares per template,
/// so a second one can be in flight before the first round-trip returns; the
/// bound only stops a JDC that never answers from growing the session. Same
/// size as the declared-job store (`MAX_DECLARED_JOBS`).
pub const MAX_PENDING_DECLARATIONS: usize = 3;

// ── Inputs (typed wrappers over deserialized SV2 frames) ────────────

/// Inputs from a deserialized `AllocateMiningJobToken` frame.
#[derive(Clone, Debug)]
pub struct AllocateMiningJobTokenInput {
    pub request_id: u32,
    /// JDC-supplied identifier. The handler tries
    /// `normalize_btc_address` on it first; if that fails, the
    /// caller's `fallback_miner_address` argument takes over.
    pub user_identifier: String,
}

/// Inputs from a deserialized `DeclareMiningJob` frame: the fields the
/// handler reads.
#[derive(Clone, Debug)]
pub struct DeclareMiningJobInput {
    pub request_id: u32,
    pub mining_job_token: Token,
    pub version: u32,
    pub coinbase_tx_prefix: Vec<u8>,
    pub coinbase_tx_suffix: Vec<u8>,
    pub wtxid_list: Vec<[u8; 32]>,
    /// The ext 0x0003/distribution_id TLV Field, when
    /// present and the extension is negotiated (the IO layer extracts it from
    /// the frame's trailing TLVs).
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

/// The block-header fields a `PushSolution` carries.
///
/// Named fields rather than loose arguments: four of the five are `u32`, and
/// a swap at any call site on the way to block reassembly compiles, passes
/// tests, and yields a header that hashes to nothing.
///
/// No `merkle_root`: it follows from the reassembled transaction set.
#[derive(Clone, Copy, Debug)]
pub struct SolutionHeader {
    /// Tip the solution was mined on.
    pub prev_hash: [u8; 32],
    /// Block-header `version` field (BIP-320 version-rolled).
    pub version: u32,
    /// Block-header `ntime` field.
    pub ntime: u32,
    /// Block-header `nonce` field.
    pub nonce: u32,
    /// Block-header `nBits` field, as the JDC sent it. Never used as a
    /// threshold — the pool checks work against its OWN target.
    pub n_bits: u32,
}

/// Which declaration a pushed solution came from, and on which JDP session.
///
/// The block-found path needs both: the session id is what
/// `blocks_entity."sessionId"` records, the token is what diagnostics name.
#[derive(Clone, Copy, Debug)]
pub struct DeclarationRef {
    /// The `new_mining_job_token` the JDS issued in `DeclareMiningJobSuccess`.
    pub new_token: Token,
    /// The JDP connection the declaration was accepted on.
    ///
    /// This is what the durable block record stores, as `{:08x}` — the same
    /// eight hex characters SV1 and SV2 put in that column, and the same id
    /// `run_jdp_connection` logs as `jdp-{id:08x}`, so a found block can be
    /// joined back to its connection.
    pub jdp_session_id: u32,
}

/// Inputs from a deserialized `PushSolution` frame (SV2 JDP/PushSolution).
#[derive(Clone, Debug)]
pub struct PushSolutionInput {
    pub extranonce: Vec<u8>,
    pub header: SolutionHeader,
}

// ── Pre-resolved hook arguments (caller-supplied) ───────────────────

/// Payload the caller resolves between the wire frame arriving and
/// invoking [`handle_allocate_token`]. The IO layer:
///
/// 1. Calls a `MinerLookup` hook with the connection's remote IP if
///    the JDC's `user_identifier` doesn't parse as a BTC address.
/// 2. Resolves the pool's payout addresses via a `PayoutResolver`
///    hook — typically just the miner's address (single-output,
///    SV2 JDP/AllocateMiningJobToken.Success fallback).
/// 3. Encodes the designated payout script into the one-output
///    consensus-serialised `Vec<TxOut>` blob via
///    [`crate::jdp::dynamic_outputs::designated_output_blob`].
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
    /// ext 0x0003/SetPayoutDistribution push: the JDS-initiated distribution
    /// frame. Emitted by the IO layer (connection-open, publisher tick,
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
    /// connection in the live-connection registry. The negotiated
    /// Full-Template flag is not carried: it lives on
    /// [`JdpSessionState::full_template_mode`], which is what every
    /// gate reads.
    SetupComplete,
    /// A token was allocated. The IO layer registers it in the
    /// cross-connection bridge so the mining side can resolve the token
    /// when its `SetCustomMiningJob` arrives without a declaration
    /// (base-protocol Coinbase-only mode).
    TokenAllocated {
        token: Token,
        miner_address: AddressId,
        /// SV2 JDP/AllocateMiningJobToken.Success's designated pool payout
        /// output, read back off the blob this allocate answered with
        /// ([`crate::jdp::dynamic_outputs::designated_payout_script`]).
        ///
        /// `None` on an ext 0x0003 session, where ext 0x0003/Negotiation
        /// requires the outputs to be empty and the published distribution
        /// replaces the base convention entirely — a custom job is then judged
        /// by the ext 0x0003/Output Verification recompute, never by this
        /// script.
        payout_script: Option<Vec<u8>>,
        /// The token's own expiry, so the bridge entry cannot outlive the
        /// token it mirrors. Carried on the event rather than looked up
        /// later: the token store is the JDP session's, and a lookup that
        /// missed would have to invent an expiry.
        expires_at_ms: u64,
    },
    /// A `DeclareMiningJob` was accepted. Caller fans out to the
    /// mining-protocol bridge to build a `SetCustomMiningJob` for
    /// the matching JDC miner.
    ///
    /// Carries only the key. Everything else about the job — the miner
    /// and the declared tip included — is read off the stored
    /// [`DeclaredJob`] under `new_token`, so nothing here can disagree
    /// with it.
    JobDeclared { new_token: Token },
    /// A `PushSolution` has been resolved against a declared job. The IO
    /// layer assembles the block (merkle root, header, consensus encoding)
    /// and calls `submitblock`. The JDC submits the same block through its
    /// own Template Provider; `submitblock` is idempotent, so that is safe.
    BlockSubmissionCandidate {
        miner_address: AddressId,
        /// Which declaration this solution belongs to — see
        /// [`DeclarationRef`].
        declaration: DeclarationRef,
        /// Reconstructed non-witness coinbase (prefix + extranonce +
        /// suffix). IO layer parses this back into a
        /// `bitcoin::Transaction` for merkle-root computation.
        coinbase_raw: Vec<u8>,
        /// Raw transaction bytes for positions 1..=N of the block,
        /// in `wtxid_list` order (NOT including the coinbase). May
        /// include witness data; the IO layer strips for merkle-root
        /// computation if needed.
        transactions: Vec<Vec<u8>>,
        /// The header fields the JDC solved with, as one value — see
        /// [`SolutionHeader`].
        header: SolutionHeader,
        /// What the declaration behind this solution was backed by, carried
        /// from the declare-time ext 0x0003/Output Verification proof. Decides
        /// BOTH whether the block is booked and whether the
        /// ext 0x0003/Implementation Notes settle fires — which are not the
        /// same question, see [`CandidateBacking`].
        backing: CandidateBacking,
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
    /// A `DeclareMiningJob.Error` and nothing else. The refusal paths share
    /// this construction but stay separate, since some differ only in what
    /// they log.
    pub(crate) fn declare_error(request_id: u32, error_code: &str, error_details: &[u8]) -> Self {
        Self::with_frame(JdpOutboundFrame::DeclareMiningJobError {
            request_id,
            error_code: error_code.to_string(),
            error_details: error_details.to_vec(),
        })
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

    /// In-flight `DeclareMiningJob`s waiting for their
    /// `ProvideMissingTransactions.Success`, by `request_id`.
    pub pending_declarations: PendingDeclarations,
}

/// The declarations waiting for their `ProvideMissingTransactions.Success`,
/// oldest first, at most [`MAX_PENDING_DECLARATIONS`].
#[derive(Debug, Default)]
pub struct PendingDeclarations(std::collections::VecDeque<PendingState>);

impl PendingDeclarations {
    /// Hold `pending`, replacing one under the same `request_id`. Returns the
    /// declaration it pushed out when the bound was already reached.
    fn insert(&mut self, pending: PendingState) -> Option<PendingState> {
        self.0
            .retain(|held| held.pending.request_id != pending.pending.request_id);
        let evicted = if self.0.len() >= MAX_PENDING_DECLARATIONS {
            self.0.pop_front()
        } else {
            None
        };
        self.0.push_back(pending);
        evicted
    }

    pub fn get(&self, request_id: u32) -> Option<&PendingState> {
        self.0
            .iter()
            .find(|held| held.pending.request_id == request_id)
    }

    pub fn take(&mut self, request_id: u32) -> Option<PendingState> {
        let position = self
            .0
            .iter()
            .position(|held| held.pending.request_id == request_id)?;
        self.0.remove(position)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// In-flight declaration state — wraps [`PendingDeclaration`] with
/// the original `DeclareMiningJobInput` so `acceptDeclaration` can
/// run after the missing-tx round-trip.
#[derive(Clone, Debug)]
pub struct PendingState {
    pub input: DeclareMiningJobInput,
    pub pending: PendingDeclaration,
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
            pending_declarations: PendingDeclarations::default(),
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
///   → `SetupConnectionError` with `protocol-version-mismatch` + Disconnect.
/// - Else → `SetupConnectionSuccess` echoing the negotiated
///   `DECLARE_TX_DATA` flag (bit 0). Other flag bits are masked off.
pub fn handle_setup_connection(
    state: &mut JdpSessionState,
    input: &SetupConnectionInput,
) -> JdpHandlerOutcome {
    if input.protocol != PROTOCOL_JOB_DECLARATION {
        let mut outcome = JdpHandlerOutcome::with_frame(JdpOutboundFrame::SetupConnectionError {
            flags: input.flags,
            error_code: crate::codec_common::ERR_UNSUPPORTED_PROTOCOL.to_string(),
        });
        outcome.push_event(JdpSessionEvent::Disconnect {
            reason: format!("protocol mismatch: got {}", input.protocol),
        });
        return outcome;
    }
    let Some(used_version) = negotiate_version(input.min_version, input.max_version) else {
        let mut outcome = JdpHandlerOutcome::with_frame(JdpOutboundFrame::SetupConnectionError {
            flags: input.flags,
            error_code: crate::codec_common::ERR_PROTOCOL_VERSION_MISMATCH.to_string(),
        });
        outcome.push_event(JdpSessionEvent::Disconnect {
            reason: format!(
                "version range {}–{} doesn't include {}",
                input.min_version, input.max_version, MIN_PROTOCOL_VERSION
            ),
        });
        return outcome;
    };

    let negotiated_flags = input.flags & FLAG_DECLARE_TX_DATA;
    let full_template_mode = negotiated_flags != 0;
    state.setup_complete = true;
    state.full_template_mode = full_template_mode;
    state.used_version = used_version;
    state.vendor = input.vendor.clone();

    JdpHandlerOutcome {
        outbound: vec![JdpOutboundFrame::SetupConnectionSuccess {
            used_version: state.used_version,
            flags: negotiated_flags,
        }],
        events: vec![JdpSessionEvent::SetupComplete],
    }
}

// ── Handler: RequestExtensions (ext 0x0001) ─────────────────────────

/// Handle ext 0x0001 `RequestExtensions`.
///
/// - Pre-setup → silently dropped, so nothing bypasses the
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
/// `SetPayoutDistribution` right now (ext 0x0003/SetPayoutDistribution makes
/// it the FIRST message after this exchange). When it can't (no PPLNS engine,
/// no template yet), 0x0003 is simply not offered: negotiating an extension
/// whose mandatory first push can't happen would break the
/// ext 0x0003/SetPayoutDistribution ordering contract.
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
/// [`AllocateTokenContext`] before invoking by parsing the JDC's
/// `user_identifier` as a BTC address. The caller also pre-encodes the pool's
/// `coinbase_outputs` blob (consensus-serialised `Vec<TxOut>`) via
/// [`crate::jdp::dynamic_outputs::designated_output_blob`].
///
/// - Pre-setup → silently dropped.
/// - Rate-limited (enforced by [`TokenStore::allocate`]) → silently
///   dropped. Silence here means the rate limit and nothing else.
/// - Entropy failure or a saturated counter → dropped too, but logged at
///   `error!`. Both are pool-side faults the JDC can neither act on nor see,
///   and SV2 defines no answer for them, so the allocate goes unanswered.
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
        // Silent by design: SV2 JDP/AllocateMiningJobToken asks for the limit
        // and defines no wire answer for hitting it, so there is nothing to
        // send and nothing an operator needs to see.
        Err(TokenAllocError::RateLimited { .. }) => return JdpHandlerOutcome::default(),
        // Entropy failure or a saturated counter: pool-side faults with no
        // SV2 error, so the allocate goes unanswered. Logged loudly (as in
        // `mint_for_declaration`) so it is not mistaken for the rate limit.
        Err(err) => {
            tracing::error!(
                %err,
                request_id = input.request_id,
                "jdp: could not allocate a mining-job token — dropping \
                 AllocateMiningJobToken with no response"
            );
            return JdpHandlerOutcome::default();
        }
    };

    let token = alloc.token;
    let outputs = alloc.coinbase_outputs.clone();
    let miner_address = alloc.miner_address.clone();
    let expires_at_ms = alloc.expires_at_ms;
    // Derived from the very bytes this frame carries, so the script the
    // mining side holds a custom job to is the script the JDC was sent.
    let payout_script = super::dynamic_outputs::designated_payout_script(&outputs);

    JdpHandlerOutcome {
        outbound: vec![JdpOutboundFrame::AllocateMiningJobTokenSuccess {
            request_id: input.request_id,
            mining_job_token: token,
            coinbase_outputs: outputs,
        }],
        events: vec![JdpSessionEvent::TokenAllocated {
            token,
            miner_address,
            payout_script,
            expires_at_ms,
        }],
    }
}

/// Helper for the IO layer: try to parse `user_identifier` as a BTC
/// address. Returns the normalised `AddressId` when valid (any
/// network is accepted at this layer — Mainnet/Testnet/Regtest split
/// is the resolver's job). On `None` the allocate is dropped silently.
pub fn parse_user_identifier_as_address(user_identifier: &str) -> Option<AddressId> {
    let trimmed = user_identifier.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Stratum `address.worker` convention, split at the first dot as in the
    // mining channel-open parse. Only the address is carried downstream: a
    // trailing `.worker` would fail `address_to_script` and leave the pool
    // payout with an empty output set.
    let (address_part, _worker) = bp_common::split_user_identity(trimmed);
    if address_part.is_empty() {
        return None;
    }
    let normalised = normalize_btc_address(address_part);
    AddressId::new(normalised).ok()
}

// ── Handler: DeclareMiningJob ───────────────────────────────────────

// ── Caller-resolved per-frame context ───────────────────────────────

/// What the IO layer resolved off the pool's live state for THIS frame.
///
/// Each value is read when a declaration frame arrives and can differ between
/// the two legs of a `ProvideMissingTransactions` round-trip. Named fields
/// keep `current_prev_hash` apart from
/// [`PendingState::prev_hash_at_declare`]: same type, opposite meaning.
///
/// ⚠️ **Per-frame, never stored.** `ProvideMissingTransactions.Success` builds
/// a fresh one: during the round-trip the distribution may have been
/// superseded or settlement-invalidated, and the address's mode may have moved.
#[derive(Clone, Debug)]
pub struct DeclarationContext {
    /// The chain tip the pool builds on right now. Compared against
    /// [`PendingState::prev_hash_at_declare`] — the tip the declaration's
    /// FIRST leg was accepted under — to catch a tip move mid-round-trip.
    pub current_prev_hash: Option<[u8; 32]>,
    /// Whether the `distribution_id` the declaration references is inside the
    /// ext 0x0003 acceptance window right now. `None` when the declaration
    /// carries no reference at all; on a negotiated connection that is an
    /// IO-layer contract breach and fails closed.
    pub distribution: Option<DistributionAcceptance>,
    /// The stream the declaring address's accounting maps to right now, or
    /// `None` when the pool has no live mining session for it. Resolved from
    /// the token's address, not from whichever address allocated last on the
    /// connection.
    pub current_mode: Option<bp_common::StreamKind>,
    /// Frame arrival time — token expiry and the declaration's own stamp.
    pub now_ms: u64,
}

/// The two refusals a `DeclareMiningJob` earns from the SESSION alone.
///
/// Checked before the caller spends the token, so a misconfigured connection
/// sees the real reason rather than a follow-up `invalid-mining-job-token`.
///
/// - a `distribution_id` TLV on a connection that never negotiated ext 0x0003
///   → `invalid-payout-distribution`. The IO layer captures the TLV
///   regardless of the negotiated set so this check can see it.
/// - Coinbase-only mode (`!full_template_mode`) → `unsupported-feature-flags`.
pub fn declare_refused_by_session(
    state: &JdpSessionState,
    input: &DeclareMiningJobInput,
) -> Option<JdpHandlerOutcome> {
    if input.distribution_id.is_some()
        && !state
            .negotiated_extensions
            .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
    {
        return Some(JdpHandlerOutcome::declare_error(
            input.request_id,
            ERR_INVALID_PAYOUT_DISTRIBUTION,
            b"distribution_id TLV requires negotiated ext 0x0003",
        ));
    }
    if !state.full_template_mode {
        return Some(JdpHandlerOutcome::declare_error(
            input.request_id,
            ERR_UNSUPPORTED_FEATURE_FLAGS,
            b"DeclareMiningJob requires Full-Template mode (DECLARE_TX_DATA flag)",
        ));
    }
    None
}

/// Handle `DeclareMiningJob`.
///
/// **Caller-resolved context.** The IO layer has already run
/// [`declare_refused_by_session`], resolved the `mining_job_token` by
/// SPENDING it ([`crate::tokens::TokenStore::take_active`]) and partitioned
/// the declared wtxids against its template cache. The handler decides
/// whether to round-trip via `ProvideMissingTransactions` or accept the
/// declaration immediately.
///
/// The node round-trip sits between those steps and this handler, and only a
/// valid unspent token may pay for it. The partition arrives by value because
/// the caller needs it too.
///
/// `declaring_miner` is the address the spent token was issued to, never the
/// connection's: a session may hold tokens for several addresses, and the
/// allocate is what carries one.
///
/// - Partition is fully covered → accept declaration immediately
///   (emits `DeclareMiningJobSuccess` + `JobDeclared` event).
/// - Some wtxids missing → emit `ProvideMissingTransactions` and
///   stash a [`PendingState`] for the follow-up Success frame.
pub fn handle_declare_mining_job(
    state: &mut JdpSessionState,
    input: &DeclareMiningJobInput,
    declaring_miner: &AddressId,
    partition: PartitionResult,
    ctx: DeclarationContext,
) -> JdpHandlerOutcome {
    let miner_address = declaring_miner.clone();

    if partition.fully_covered() {
        return accept_declaration(state, input, partition.known_raw_txs, miner_address, ctx);
    }

    let outcome = JdpHandlerOutcome::with_frame(JdpOutboundFrame::ProvideMissingTransactions {
        request_id: input.request_id,
        unknown_tx_position_list: partition.missing_positions.clone(),
    });
    let evicted = state.pending_declarations.insert(PendingState {
        input: input.clone(),
        pending: PendingDeclaration {
            request_id: input.request_id,
            missing_positions: partition.missing_positions,
            known_raw_txs: partition.known_raw_txs,
        },
        miner_address,
        prev_hash_at_declare: ctx.current_prev_hash,
    });
    // Past MAX_PENDING_DECLARATIONS unanswered round-trips the oldest is
    // dropped and its `request_id` never answered; log it.
    if let Some(dropped) = evicted {
        tracing::warn!(
            dropped_request_id = dropped.pending.request_id,
            request_id = input.request_id,
            "jdp: too many declarations waiting for ProvideMissingTransactions.Success — \
             the oldest is dropped and its request_id will never be answered"
        );
    }
    // Epoch staleness is observed in `accept_declaration` (the path that
    // actually validates the payout set), reached here once the
    // `ProvideMissingTransactions.Success` round-trip completes.
    outcome
}

// ── Handler: ProvideMissingTransactions.Success ─────────────────────

/// Handle `ProvideMissingTransactions.Success`.
///
/// - No pending declaration under its `request_id` → silently dropped (a
///   spurious Success indicates a JDC bug).
/// - Position-count mismatch ([`merge_provided_with_known`] errors
///   with `MergeError::PositionCountMismatch`) → `missing-txs`.
/// - Successful merge → accept the declaration (same path as the
///   fully-covered case in [`handle_declare_mining_job`]).
///
/// The [`DeclarationContext`] is RE-resolved by the IO layer at THIS point,
/// never carried over from declare time — see the type's own warning for why.
/// ext 0x0003/Grace Window + Implementation Notes are judged when the
/// declaration is actually accepted, which is here.
pub fn handle_provide_missing_transactions_success(
    state: &mut JdpSessionState,
    input: &ProvideMissingTransactionsSuccessInput,
    ctx: DeclarationContext,
) -> JdpHandlerOutcome {
    let Some(pending) = state.pending_declarations.take(input.request_id) else {
        return JdpHandlerOutcome::default();
    };
    // If the chain advanced during the round-trip, the job references a
    // superseded template: reject `stale-chain-tip`, which the JDC retries
    // against its new template.
    if pending.prev_hash_at_declare != ctx.current_prev_hash {
        return JdpHandlerOutcome::declare_error(
            input.request_id,
            ERR_STALE_CHAIN_TIP,
            b"chain tip advanced during the missing-transactions round-trip",
        );
    }
    let merged = match merge_provided_with_known(pending.pending, input.transaction_list.clone()) {
        Ok(m) => m,
        Err(err) => {
            tracing::warn!(
                request_id = input.request_id,
                %err,
                "jdp: ProvideMissingTransactions.Success does not fit the positions asked for — \
                 rejecting the declaration"
            );
            return JdpHandlerOutcome::declare_error(
                input.request_id,
                ERR_MISSING_TXS,
                b"ProvideMissingTransactions.Success does not carry one transaction per \
                  requested position",
            );
        }
    };
    accept_declaration(state, &pending.input, merged, pending.miner_address, ctx)
}

// ── Internal: accept_declaration ────────────────────────────────────

fn accept_declaration(
    state: &mut JdpSessionState,
    input: &DeclareMiningJobInput,
    raw_transactions: HashMap<u32, Vec<u8>>,
    miner_address: AddressId,
    ctx: DeclarationContext,
) -> JdpHandlerOutcome {
    // A declaration is bound to the tip the pool is on: the mining side holds
    // every `SetCustomMiningJob` built on it to that tip. Without one (the
    // pool has not seen its first template yet) there is nothing to bind to,
    // so it is refused with the one code a JD-client retries.
    let Some(prev_hash) = ctx.current_prev_hash else {
        tracing::warn!(
            request_id = input.request_id,
            "jdp: declaration arrived before the pool knows a chain tip — rejecting retryably"
        );
        return JdpHandlerOutcome::declare_error(
            input.request_id,
            ERR_STALE_CHAIN_TIP,
            b"the pool has no chain tip yet",
        );
    };

    // The coinbase must rebuild on EVERY connection, not just 0x0003 ones:
    // the mining-side binding (`crate::jdp::custom_job_binding`) projects from
    // this reconstruction, so a declaration it cannot express (e.g. scriptSig
    // bytes after the extranonce slot, see [`declared_coinbase_tx`]) would
    // succeed here and then fail every `SetCustomMiningJob`. Refusing now
    // tells the JDC while it can still change something.
    let Some(declared_coinbase) =
        declared_coinbase_tx(&input.coinbase_tx_prefix, &input.coinbase_tx_suffix)
    else {
        tracing::warn!(
            request_id = input.request_id,
            "jdp: declared coinbase cannot be reconstructed — rejecting the declaration"
        );
        return JdpHandlerOutcome::declare_error(
            input.request_id,
            ERR_INVALID_JOB_PARAM_COINBASE,
            b"declared coinbase does not rebuild from prefix + slot + suffix",
        );
    };

    // ext 0x0003/Validation (push model). With 0x0003 negotiated, every
    // declared job MUST reference a published distribution via the
    // ext 0x0003/distribution_id TLV Field, and the coinbase MUST match the
    // ext 0x0003/Payout Computation recompute POSITIONALLY
    // (ext 0x0003/Output Verification). Without it, this is a plain
    // base-protocol declaration and the block below is skipped.
    let mut declared_booking: Option<PayoutBooking> = None;
    // Which distribution this declaration was accepted against. Set on every
    // accepted 0x0003 declaration, including the non-bookable ones — see
    // `DeclaredJob::distribution_id` for why the two must not be conflated.
    let mut declared_distribution_id: Option<u64> = None;
    if state
        .negotiated_extensions
        .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
    {
        if input.distribution_id.is_none() {
            // ext 0x0003/distribution_id TLV Field: the TLV is mandatory on a
            // negotiated connection — the allocate carried no outputs
            // (ext 0x0003/Negotiation), so a declaration without a
            // distribution reference pays nobody the pool knows.
            tracing::warn!(
                request_id = input.request_id,
                "jdp: 0x0003 negotiated but DeclareMiningJob carries no distribution_id TLV — rejecting"
            );
            return JdpHandlerOutcome::declare_error(
                input.request_id,
                ERR_INVALID_PAYOUT_DISTRIBUTION,
                b"missing distribution_id TLV (ext 0x0003 is negotiated)",
            );
        }
        let entry = match ctx.distribution {
            Some(DistributionAcceptance::Accepted(entry)) => entry,
            Some(DistributionAcceptance::Stale) | Some(DistributionAcceptance::Unknown) => {
                // ext 0x0003/Grace Window + Error Codes: outside the
                // acceptance window (superseded, settlement-invalidated, or
                // never published) — the JDC re-declares against the latest
                // received distribution.
                tracing::warn!(
                    request_id = input.request_id,
                    distribution_id = input.distribution_id,
                    "jdp: declared distribution_id outside the acceptance window — rejecting"
                );
                return JdpHandlerOutcome::declare_error(
                    input.request_id,
                    ERR_STALE_PAYOUT_DISTRIBUTION,
                    b"distribution_id not accepted (superseded or unknown)",
                );
            }
            None => {
                // IO-layer contract breach: a negotiated declare must
                // arrive with a resolved acceptance. Fail closed.
                tracing::warn!(
                    request_id = input.request_id,
                    "jdp: negotiated declare arrived without a resolved distribution acceptance — rejecting"
                );
                return JdpHandlerOutcome::declare_error(
                    input.request_id,
                    ERR_STALE_PAYOUT_DISTRIBUTION,
                    b"distribution_id not accepted (superseded or unknown)",
                );
            }
        };
        // The plan must belong to the accounting this address is on RIGHT
        // NOW. This is the only place that is asked for a block found through
        // `PushSolution`, which books from the declaration alone: a Solo plan
        // left standing after its owner joined a group would otherwise pay
        // the finder a block the group earned, and Group-Solo keeps no ledger
        // to repair it. `accounting_fits_mode` is shared with the JDP loop's
        // rebuild decision so both judge staleness identically.
        if !crate::bridge::accounting_fits_mode(&entry.accounting, ctx.current_mode) {
            tracing::warn!(
                request_id = input.request_id,
                distribution_id = entry.distribution_id,
                accounting = ?entry.accounting,
                current_mode = ?ctx.current_mode,
                "jdp: declared against a distribution built for a different accounting than \
                 this address is on now — its mode moved mid-session; rejecting rather than \
                 blessing a coinbase that pays the wrong set of miners"
            );
            return JdpHandlerOutcome::declare_error(
                input.request_id,
                ERR_STALE_PAYOUT_DISTRIBUTION,
                b"distribution was built for a different payout mode",
            );
        }
        match validate_coinbase_outputs_against_distribution(
            &declared_coinbase.tx.output,
            &entry.built.pool_payout,
            &entry.built.payouts,
            &entry.built.dust_limits,
            &entry.built.additional_outputs,
        ) {
            Ok(_declared_revenue) => {
                // The coinbase pays this distribution — record it as the
                // declaration's reference regardless of bookability, so the
                // mining side can judge the custom job against it.
                declared_distribution_id = Some(entry.distribution_id);
                // Vouch for booking only when the distribution's
                // settlement snapshot actually landed.
                if entry.built.bookable {
                    declared_booking = Some(PayoutBooking {
                        distribution_id: entry.distribution_id,
                        payouts_fingerprint: entry.built.payouts_fingerprint.unwrap_or([0u8; 32]),
                        reference_reward_sats: entry.built.reference_reward_sats,
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
                    "jdp: declared coinbase violates ext 0x0003/Payout Computation against the referenced distribution — rejecting"
                );
                return JdpHandlerOutcome::declare_error(
                    input.request_id,
                    ERR_INVALID_PAYOUT_DISTRIBUTION,
                    b"declared coinbase does not match the referenced distribution",
                );
            }
        }
    }
    // No base-protocol designated-output check here, deliberately
    // (SV2 JDP/AllocateMiningJobToken.Success; the mining side applies it in
    // Coinbase-only mode). A base-protocol custom job is Solo-only, where the
    // designated output is the declaring miner's own address, so the check
    // would protect nobody while adding a declare error that JD-clients treat
    // as fatal. ⚠️ If a base-protocol job is ever served off Solo, this must
    // change.

    // Mint the `new_mining_job_token` through the shared TokenStore so it has
    // the same shape as an allocated one, but outside `allocate`: the
    // SV2 JDP/AllocateMiningJobToken rate limit applies to client allocates,
    // and a declaration that follows an allocate within the limit window must
    // still be answered. The token is held by `state.declared_jobs` and the
    // bridge, never the token store. See `mint_for_declaration`.
    let new_token = match state.tokens.mint_for_declaration() {
        Ok(token) => token,
        Err(err) => {
            // Entropy failure or a saturated counter: pool-side faults with
            // no SV2 error, so log loudly.
            tracing::error!(
                %err,
                request_id = input.request_id,
                "jdp: could not mint a declaration token — dropping DeclareMiningJob \
                 with no response; the JDC will treat this as an unresponsive JDS"
            );
            return JdpHandlerOutcome::default();
        }
    };

    state.declared_jobs.insert(DeclaredJob {
        new_token,
        miner_address: miner_address.clone(),
        version: input.version,
        coinbase_tx_prefix: input.coinbase_tx_prefix.clone(),
        coinbase_tx_suffix: input.coinbase_tx_suffix.clone(),
        wtxid_list: input.wtxid_list.clone(),
        raw_transactions,
        prev_hash,
        declared_at_ms: ctx.now_ms,
        booking: declared_booking,
        distribution_id: declared_distribution_id,
    });

    JdpHandlerOutcome {
        outbound: vec![JdpOutboundFrame::DeclareMiningJobSuccess {
            request_id: input.request_id,
            new_mining_job_token: new_token,
        }],
        events: vec![JdpSessionEvent::JobDeclared { new_token }],
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
/// The block is booked against the matched declaration's own
/// [`DeclaredJob::miner_address`], so it cannot name a different miner than
/// the job it belongs to.
///
/// - Coinbase-only mode → dropped; the NORMAL case, not a fault.
/// - No matching declared job → dropped.
/// - Missing raw-tx data for any wtxid position → dropped.
pub fn handle_push_solution(
    state: &mut JdpSessionState,
    input: &PushSolutionInput,
) -> JdpHandlerOutcome {
    // The drops below are WARN-logged: a PushSolution is a found block, and a
    // silent drop would make a lost pool-side booking undiagnosable (the block
    // itself still propagates through the JDC's own node).
    //
    // Coinbase-only logs at INFO: JD-clients send `PushSolution` in that mode
    // too, but per SV2 JDP/Coinbase-only Mode there is no declaration, so the
    // pool holds no transaction list and cannot reassemble the block. The JDC's
    // node propagates it and the mining side records it
    // (`ExtendedJob::jdp_claims_the_block`).
    if !state.full_template_mode {
        tracing::info!(
            prev_hash = %input.header.prev_hash.as_hex(),
            "jdp: PushSolution from a Coinbase-only session — no declaration to reassemble the \
             block from; the JDC propagates it and the mining side records it"
        );
        return JdpHandlerOutcome::default();
    }
    let job = match state
        .declared_jobs
        .match_for_solution(&input.header.prev_hash)
    {
        Some(j) => j,
        None => {
            tracing::warn!(
                prev_hash = %input.header.prev_hash.as_hex(),
                "jdp: PushSolution dropped — no matching declared job (reconnect gap or stale solution)"
            );
            return JdpHandlerOutcome::default();
        }
    };

    // Copy out what the outcome needs so the borrow into
    // `state.declared_jobs` can end.
    let new_token = job.new_token;
    let miner_address = job.miner_address.clone();
    // `match` over BOTH fields rather than `booking.is_some()`, which reads
    // like "was a distribution involved?" but answers a different question.
    let backing = match (job.booking, job.distribution_id) {
        (Some(booking), _) => CandidateBacking::Bookable(booking),
        // Validated against a published distribution whose settlement
        // snapshot never landed (`bookable == false`). The coinbase still pays
        // the published split on-chain, but this block gets no ledger entry
        // and nothing parks the inputs; deliberately not built, since it needs
        // a Redis outage and a block find in the same interval. The error log
        // is the whole mitigation.
        //
        // The ext 0x0003/Implementation Notes settle must still fire. See
        // `CandidateBacking`.
        (None, Some(distribution_id)) => {
            tracing::error!(
                prev_hash = %input.header.prev_hash.as_hex(),
                distribution_id,
                "jdp: BLOCK FOUND on a validated distribution that was never bookable — \
                 its coinbase pays miners on-chain but this block gets NO ledger entry, \
                 and nothing preserves the inputs to add one later. Settlement snapshot \
                 write must have failed when the distribution was published. The \
                 distribution IS settled, so nothing is paid twice."
            );
            CandidateBacking::UnbookableDistribution { distribution_id }
        }
        // Base-protocol declaration: nothing published, nothing to book, and
        // nothing to settle.
        (None, None) => CandidateBacking::BaseProtocol,
    };
    let coinbase_prefix = job.coinbase_tx_prefix.clone();
    let coinbase_suffix = job.coinbase_tx_suffix.clone();
    let wtxid_count = job.wtxid_list.len();
    let mut transactions: Vec<Vec<u8>> = Vec::with_capacity(wtxid_count);
    for i in 0..wtxid_count {
        match job.raw_transactions.get(&(i as u32)) {
            Some(raw) => transactions.push(raw.clone()),
            None => {
                tracing::warn!(
                    prev_hash = %input.header.prev_hash.as_hex(),
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
            declaration: DeclarationRef {
                new_token,
                jdp_session_id: state.session_id,
            },
            backing,
            coinbase_raw,
            transactions,
            header: input.header,
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
            // A real suffix: every declaration has to rebuild, so a blob that
            // is not an output vector is refused on the base path too.
            coinbase_tx_suffix: coinbase_suffix(&one_output_blob()),
            wtxid_list: wtxids,
            distribution_id: None,
        }
    }

    /// A realistic declared `coinbase_tx_prefix`: coinbase header, a BIP-34
    /// height push, and a 12-byte extranonce slot the prefix stops at. The
    /// declare-time validation rebuilds the transaction from this plus the
    /// suffix, so it must be well-formed.
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

    /// One consensus-serialised output, enough to make a rebuildable coinbase.
    fn one_output_blob() -> Vec<u8> {
        let mut b = vec![0x01]; // output count
        b.extend_from_slice(&312_500_000u64.to_le_bytes());
        b.push(0x01); // script length
        b.push(0x51); // OP_TRUE
        b
    }

    /// Wrap a consensus `Vec<TxOut>` blob as a realistic coinbase suffix
    /// (`nSequence(4) + outputs + nLockTime(4)`), paired with
    /// [`coinbase_prefix`].
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
        allocate_another(s, 1, 1_000)
    }

    /// One more token on an already-set-up session. A JDC that declares
    /// twice allocates twice — that is what a token IS — and
    /// SV2 JDP/AllocateMiningJobToken rate-limits allocation to 1/s, so the
    /// caller has to move `now_ms` on by at least that.
    fn allocate_another(s: &mut JdpSessionState, request_id: u32, now_ms: u64) -> Token {
        let out = handle_allocate_token(s, &good_alloc(request_id), alloc_ctx(), now_ms);
        match out.outbound.first() {
            Some(JdpOutboundFrame::AllocateMiningJobTokenSuccess {
                mining_job_token, ..
            }) => *mining_job_token,
            other => panic!("expected AllocateMiningJobTokenSuccess, got {other:?}"),
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

    /// A minimal ext 0x0003/SetPayoutDistribution distribution: pool slot
    /// (weight 1) + one miner payout slot (weight 9), no pruning, no
    /// additional outputs.
    fn distribution_entry(id: u64) -> crate::bridge::PayoutDistributionEntry {
        crate::bridge::PayoutDistributionEntry {
            distribution_id: id,
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
                payouts_fingerprint: Some([id as u8; 32]),
                bookable: true,
            },
            accounting: crate::bridge::DistributionAccounting::PoolWide,
            jdp_session_id: None,
            published_at_ms: 1_000,
        }
    }

    fn accepted(entry: crate::bridge::PayoutDistributionEntry) -> Option<DistributionAcceptance> {
        Some(DistributionAcceptance::Accepted(std::sync::Arc::new(entry)))
    }

    /// The IO-resolved [`DeclarationContext`] a test frame arrives with, at
    /// the tip these tests build on. A call site names only what it actually
    /// varies: `DeclarationContext { distribution: accepted(e), ..ctx(3_000) }`.
    fn ctx(now_ms: u64) -> DeclarationContext {
        DeclarationContext {
            current_prev_hash: Some([0xAB; 32]),
            distribution: None,
            current_mode: None,
            now_ms,
        }
    }

    /// Stand-in for the three things the IO layer does ahead of the handler:
    /// the session-shape gates, resolving the `mining_job_token` by SPENDING
    /// it ([`TokenStore::take_active`]), and the wtxid partition.
    ///
    /// Calls the same functions the dispatch calls. Declaring twice on one
    /// token panics in the `expect`, so a test cannot do it by accident.
    fn declared(
        s: &mut JdpSessionState,
        input: &DeclareMiningJobInput,
        template_txs: &HashMap<[u8; 32], Vec<u8>>,
        ctx: DeclarationContext,
    ) -> JdpHandlerOutcome {
        if let Some(refusal) = declare_refused_by_session(s, input) {
            return refusal;
        }
        let declaring = s
            .tokens
            .take_active(&input.mining_job_token, ctx.now_ms)
            .expect("a declaration must name a token the pool issued and has not spent");
        let partition =
            crate::jdp::tx_validation::partition_against_template(&input.wtxid_list, template_txs);
        handle_declare_mining_job(s, input, &declaring.miner_address, partition, ctx)
    }

    /// A coinbase suffix whose outputs are the ext 0x0003/Payout Computation
    /// recompute for `entry` at revenue `t` — passes the
    /// ext 0x0003/Output Verification positional validation by construction.
    fn matching_suffix(entry: &crate::bridge::PayoutDistributionEntry, t: u64) -> Vec<u8> {
        let outputs = compute_payout_vector(
            &entry.built.pool_payout,
            &entry.built.payouts,
            &entry.built.dust_limits,
            &entry.built.additional_outputs,
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
                assert_eq!(error_code, crate::codec_common::ERR_UNSUPPORTED_PROTOCOL);
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
                assert_eq!(
                    error_code,
                    crate::codec_common::ERR_PROTOCOL_VERSION_MISMATCH
                );
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
        // The negotiated mode lives on the session state — that is what
        // the Declare and PushSolution gates read.
        assert!(s.full_template_mode);
        assert!(matches!(out.events[0], JdpSessionEvent::SetupComplete));
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

    /// ext 0x0003/SetPayoutDistribution makes `SetPayoutDistribution` the
    /// FIRST message after the extension exchange — when the pool cannot
    /// publish one yet, 0x0003 is not offered and the request errors as
    /// unsupported.
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
        let _ = handle_allocate_token(&mut s, &good_alloc(2), alloc_ctx(), 1_000);
        // 999ms later — the burst is spent and nothing has refilled yet.
        let out = handle_allocate_token(&mut s, &good_alloc(3), alloc_ctx(), 1_999);
        assert!(out.outbound.is_empty(), "rate-limited alloc must drop");
    }

    /// Two back-to-back allocates at connect are both answered: JD-clients
    /// start that way and never re-request a dropped one.
    #[test]
    fn the_reference_clients_two_token_start_is_answered_in_full() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        for request_id in 1..=2 {
            let out = handle_allocate_token(&mut s, &good_alloc(request_id), alloc_ctx(), 1_000);
            assert!(
                matches!(
                    out.outbound.first(),
                    Some(JdpOutboundFrame::AllocateMiningJobTokenSuccess { .. })
                ),
                "allocate {request_id} of the start burst must be answered"
            );
        }
    }

    /// An entropy failure drops the allocate with no frame and no event, like
    /// the rate limit; the two differ only in what they log.
    #[test]
    fn an_entropy_failure_drops_the_allocate_without_a_frame() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        s.set_token_rng(Some(Box::new(|_| Err("no entropy".to_string()))));
        let out = handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 1_000);
        assert!(
            out.outbound.is_empty() && out.events.is_empty(),
            "an allocate the pool cannot answer must produce no frame and no event"
        );
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
        // Allocation is not mode-gated, so a Coinbase-only session can hold a
        // token.
        let token = allocate_another(&mut s, 1, 1_000);
        let input = declare(1, token, vec![]);
        let out = declared(
            &mut s,
            &input,
            &HashMap::new(),
            DeclarationContext {
                current_prev_hash: None,
                ..ctx(0)
            },
        );
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_UNSUPPORTED_FEATURE_FLAGS);
            }
            _ => panic!("expected DeclareMiningJobError"),
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
        let out = declared(&mut s, &input, &tpl, ctx(3_000));
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
        assert!(s.pending_declarations.is_empty());
    }

    /// A declaration the pool cannot pin to a chain tip is not accepted: it
    /// is answered `stale-chain-tip`, the one code a JD-client retries, and
    /// the next template brings the tip. Without a tip the mining side would
    /// have nothing to bind `SetCustomMiningJob.prev_hash` to.
    ///
    /// Both directions: the identical declaration with a tip is accepted.
    #[test]
    fn a_declaration_before_the_pool_knows_a_tip_is_refused_retryably() {
        let wtxid = [0x01; 32];
        let mut tpl = HashMap::new();
        tpl.insert(wtxid, vec![0xCA; 16]);
        let declare_on = |current_prev_hash: Option<[u8; 32]>| {
            let mut s = fresh();
            let token = complete_setup_and_allocate(&mut s);
            let ctx = DeclarationContext {
                current_prev_hash,
                ..ctx(3_000)
            };
            let out = declared(&mut s, &declare(3, token, vec![wtxid]), &tpl, ctx);
            (out, s.declared_jobs.len())
        };

        let (refused, stored) = declare_on(None);
        match &refused.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_CHAIN_TIP);
            }
            other => panic!("expected DeclareMiningJobError, got {other:?}"),
        }
        assert_eq!(stored, 0, "nothing may be stored without a tip");

        let (accepted, stored) = declare_on(Some([0xAB; 32]));
        assert!(
            matches!(
                accepted.outbound[0],
                JdpOutboundFrame::DeclareMiningJobSuccess { .. }
            ),
            "negative control: with a tip the same declaration is accepted"
        );
        assert_eq!(stored, 1);
    }

    /// INTEROP: a declaration in the same second as an allocate must be
    /// answered.
    ///
    /// The SV2 JDP/AllocateMiningJobToken rate limit applies to client
    /// allocates only, not to minting the `new_mining_job_token`. An
    /// unanswered declare makes the JDC switch pools
    /// (SV2 JDP/Job Declarator Client), and JD-clients routinely allocate on
    /// the same block change that produces a declaration.
    #[test]
    fn a_declaration_in_the_same_second_as_an_allocate_is_still_answered() {
        let mut s = fresh();
        let _ = handle_setup_connection(&mut s, &good_setup());
        // Allocate at t=1000 — this is what stamps the
        // SV2 JDP/AllocateMiningJobToken budget.
        let out = handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 1_000);
        let token = match out.outbound[0] {
            JdpOutboundFrame::AllocateMiningJobTokenSuccess {
                mining_job_token, ..
            } => mining_job_token,
            _ => panic!("expected AllocateMiningJobTokenSuccess"),
        };

        // Declare 100 ms later — well inside the 1 s allocate limit.
        let wtxid = [0x01; 32];
        let mut tpl = HashMap::new();
        tpl.insert(wtxid, vec![0xCA; 16]);
        let input = declare(3, token, vec![wtxid]);
        let out = declared(&mut s, &input, &tpl, ctx(1_100));

        assert!(
            !out.outbound.is_empty(),
            "the declaration must be ANSWERED — dropping it leaves the JDC waiting on a \
             frame that never arrives, which SV2 JDP/Job Declarator Client turns into a pool switch"
        );
        assert!(
            matches!(
                out.outbound[0],
                JdpOutboundFrame::DeclareMiningJobSuccess { .. }
            ),
            "got {:?}",
            out.outbound[0]
        );
        assert_eq!(s.declared_jobs.len(), 1);
    }

    /// A declaration token is not kept in the token store: minting it is not
    /// rate-limited, so storing it there would let the store grow unbounded.
    /// `declared_jobs` (FIFO, `MAX_DECLARED_JOBS`) holds it instead.
    #[test]
    fn a_declaration_mints_a_token_without_growing_the_token_store() {
        let mut s = fresh();
        let _ = handle_setup_connection(&mut s, &good_setup());
        let out = handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 1_000);
        let token = match out.outbound[0] {
            JdpOutboundFrame::AllocateMiningJobTokenSuccess {
                mining_job_token, ..
            } => mining_job_token,
            _ => panic!("expected AllocateMiningJobTokenSuccess"),
        };
        assert_eq!(s.tokens.len(), 1, "precondition: the allocate IS stored");

        let wtxid = [0x01; 32];
        let mut tpl = HashMap::new();
        tpl.insert(wtxid, vec![0xCA; 16]);
        let mut token = token;
        for request_id in 3..13u32 {
            let now = 1_000 + u64::from(request_id) * 1_100;
            let out = declared(
                &mut s,
                &declare(request_id, token, vec![wtxid]),
                &tpl,
                ctx(now),
            );
            assert!(
                matches!(
                    out.outbound[0],
                    JdpOutboundFrame::DeclareMiningJobSuccess { .. }
                ),
                "declaration {request_id} must be answered"
            );
            // Checked per step, not as a net figure at the end: one allocate
            // in, one out, the declaration token in neither direction.
            assert_eq!(
                s.tokens.len(),
                0,
                "declaration {request_id} spent its allocate and stored nothing of its own"
            );
            token = allocate_another(&mut s, request_id, now + 100);
            assert_eq!(s.tokens.len(), 1, "and the refill puts back exactly one");
        }
        assert_eq!(
            s.declared_jobs.len(),
            crate::jdp::declarations::MAX_DECLARED_JOBS,
            "and the FIFO that DOES hold them is the one that caps them"
        );
    }

    /// The allocate map is bounded by rate × TTL only if expired entries are
    /// swept; `take_active` touches just the token it was asked about, so
    /// allocating sweeps the rest.
    #[test]
    fn allocating_sweeps_the_tokens_that_outlived_their_ttl() {
        let mut s = fresh();
        let _ = handle_setup_connection(&mut s, &good_setup());
        let _ = handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 1_000);
        let _ = handle_allocate_token(&mut s, &good_alloc(2), alloc_ctx(), 2_100);
        assert_eq!(s.tokens.len(), 2, "precondition: both are live");

        // Past both TTLs — the third allocate must not find company.
        let past_ttl = 2_100 + crate::tokens::DEFAULT_TOKEN_TTL_MS + 1;
        let _ = handle_allocate_token(&mut s, &good_alloc(3), alloc_ctx(), past_ttl);
        assert_eq!(
            s.tokens.len(),
            1,
            "the two expired tokens must be gone, leaving only the fresh one"
        );
    }

    /// The client's allocate stays rate-limited, and minting a declaration
    /// token in between does not move that budget.
    #[test]
    fn the_client_facing_allocate_limit_survives_a_declaration() {
        let mut s = fresh();
        let _ = handle_setup_connection(&mut s, &good_setup());
        let out = handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 1_000);
        let token = match out.outbound[0] {
            JdpOutboundFrame::AllocateMiningJobTokenSuccess {
                mining_job_token, ..
            } => mining_job_token,
            _ => panic!("expected AllocateMiningJobTokenSuccess"),
        };
        let wtxid = [0x01; 32];
        let mut tpl = HashMap::new();
        tpl.insert(wtxid, vec![0xCA; 16]);
        // The rest of the start burst, at the same instant.
        let _ = handle_allocate_token(&mut s, &good_alloc(4), alloc_ctx(), 1_000);
        let _ = declared(&mut s, &declare(3, token, vec![wtxid]), &tpl, ctx(1_100));

        // The burst is spent and still inside the second: refused, as
        // SV2 JDP/AllocateMiningJobToken asks.
        let out = handle_allocate_token(&mut s, &good_alloc(2), alloc_ctx(), 1_500);
        assert!(
            out.outbound.is_empty(),
            "an allocate past the burst inside 1 s must still be rate-limited"
        );
        // And past the second it is served again — measured from the
        // ALLOCATES at 1_000, not from the declaration at 1_100.
        let out = handle_allocate_token(&mut s, &good_alloc(5), alloc_ctx(), 2_050);
        assert!(
            matches!(
                out.outbound[0],
                JdpOutboundFrame::AllocateMiningJobTokenSuccess { .. }
            ),
            "the declaration must not have pushed the allocate budget forward"
        );
    }

    /// ext 0x0003/distribution_id TLV Field: on a 0x0003-negotiated connection
    /// every `DeclareMiningJob` MUST reference a published distribution — a
    /// declaration without the `distribution_id` TLV pays nobody the pool
    /// knows and is rejected `invalid-payout-distribution`.
    #[test]
    fn declare_negotiated_without_distribution_tlv_rejected() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        negotiate_0x0003(&mut s);
        // `declare()` carries no distribution_id TLV.
        let input = declare(2, token, vec![]);
        let out = declared(&mut s, &input, &HashMap::new(), ctx(3_000));
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

    /// ext 0x0003/Grace Window + Error Codes: a `distribution_id` outside the
    /// acceptance window is rejected `stale-payout-distribution`. `Unknown`
    /// folds into the same wire code — a JDC can't distinguish "superseded"
    /// from "never published", both mean "re-declare against the latest".
    #[test]
    fn declare_with_stale_or_unknown_distribution_rejected() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        negotiate_0x0003(&mut s);
        let mut token = token;
        for (attempt, acceptance) in [
            DistributionAcceptance::Stale,
            DistributionAcceptance::Unknown,
        ]
        .into_iter()
        .enumerate()
        {
            let mut input = declare(2, token, vec![]);
            input.distribution_id = Some(7);
            let out = declared(
                &mut s,
                &input,
                &HashMap::new(),
                DeclarationContext {
                    distribution: Some(acceptance),
                    ..ctx(3_000)
                },
            );
            match &out.outbound[0] {
                JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                    assert_eq!(error_code, ERR_STALE_PAYOUT_DISTRIBUTION);
                }
                f => panic!("expected stale DeclareMiningJobError, got {f:?}"),
            }
            // A refusal spends the token too, so the next attempt allocates.
            token = allocate_another(&mut s, 3 + attempt as u32, 2_100 + attempt as u64 * 1_100);
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
        let out = declared(&mut s, &input, &HashMap::new(), ctx(3_000));
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_PAYOUT_DISTRIBUTION);
            }
            f => panic!("expected DeclareMiningJobError, got {f:?}"),
        }
        assert_eq!(s.declared_jobs.len(), 0);
    }

    /// A plan built for one payout mode must not bless a coinbase once the
    /// address is on another. A Full-Template block is booked from its
    /// declaration, so this is the only place that can be caught.
    ///
    /// All three answers:
    /// - the mode it was built for → accepted, or the pool refuses its own
    ///   correct plan on every declare,
    /// - a DIFFERENT mode → refused,
    /// - no mode at all → accepted. "The gate has never heard of this address"
    ///   is the absence of an answer, not a changed one; treating it as a
    ///   change would refuse every declare whose miner briefly dropped.
    #[test]
    fn a_declare_is_judged_against_the_mode_the_address_is_on_now() {
        use bp_common::StreamKind as Sk;
        let tailored = |id: u64| crate::bridge::PayoutDistributionEntry {
            accounting: crate::bridge::DistributionAccounting::Solo(addr()),
            ..distribution_entry(id)
        };
        let conformant = {
            let e = tailored(7);
            let outputs = compute_payout_vector(
                &e.built.pool_payout,
                &e.built.payouts,
                &e.built.dust_limits,
                &e.built.additional_outputs,
                312_500_000,
            )
            .unwrap();
            coinbase_suffix(&bitcoin::consensus::serialize(&outputs))
        };

        for (mode, accept) in [
            (Some(Sk::Solo), true),
            (None, true),
            (Some(Sk::GroupSolo), false),
            (Some(Sk::Pplns), false),
            (Some(Sk::Blockparty), false),
        ] {
            let mut s = fresh();
            let token = complete_setup_and_allocate(&mut s);
            negotiate_0x0003(&mut s);
            let mut input = declare(3, token, vec![]);
            input.distribution_id = Some(7);
            input.coinbase_tx_suffix = conformant.clone();
            let out = declared(
                &mut s,
                &input,
                &HashMap::new(),
                DeclarationContext {
                    distribution: accepted(tailored(7)),
                    current_mode: mode,
                    ..ctx(3_000)
                },
            );
            match (&out.outbound[0], accept) {
                (JdpOutboundFrame::DeclareMiningJobSuccess { .. }, true) => {
                    // Accepting is only half of it: the booking stamped here
                    // is what a `PushSolution` books the block from.
                    assert_eq!(s.declared_jobs.len(), 1, "{mode:?}");
                }
                (JdpOutboundFrame::DeclareMiningJobError { error_code, .. }, false) => {
                    assert_eq!(error_code, ERR_STALE_PAYOUT_DISTRIBUTION, "{mode:?}");
                    assert_eq!(
                        s.declared_jobs.len(),
                        0,
                        "{mode:?}: a refused declaration must leave nothing bookable"
                    );
                }
                (other, want) => panic!("{mode:?}: wanted accept={want}, got {other:?}"),
            }
        }
    }

    /// ext 0x0003/Output Verification recompute-and-compare: a declared
    /// coinbase matching the referenced distribution positionally is accepted
    /// and the job is stamped with a booking; one paying the right scripts and
    /// the right sum in the WRONG positions is rejected
    /// `invalid-payout-distribution` (the spec fixes the output order).
    #[test]
    fn declare_validates_coinbase_against_distribution() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        negotiate_0x0003(&mut s);
        let entry = distribution_entry(7);

        // Reject: swap the pool/payout positions, Σ preserved.
        let mut swapped = compute_payout_vector(
            &entry.built.pool_payout,
            &entry.built.payouts,
            &entry.built.dust_limits,
            &entry.built.additional_outputs,
            5_000_000_000,
        )
        .unwrap();
        swapped.swap(0, 1);
        let mut bad = declare(3, token, vec![]);
        bad.distribution_id = Some(7);
        bad.coinbase_tx_suffix = coinbase_suffix(&bitcoin::consensus::serialize(&swapped));
        let out = declared(
            &mut s,
            &bad,
            &HashMap::new(),
            DeclarationContext {
                distribution: accepted(distribution_entry(7)),
                ..ctx(3_000)
            },
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

        // Accept: the ext 0x0003/Payout Computation vector as recomputed
        // validates by construction. A refused declaration spends its token
        // just as an accepted one does, so the retry brings its own.
        let token = allocate_another(&mut s, 2, 2_100);
        let mut good = declare(4, token, vec![]);
        good.distribution_id = Some(7);
        good.coinbase_tx_suffix = matching_suffix(&entry, 5_000_000_000);
        let out = declared(
            &mut s,
            &good,
            &HashMap::new(),
            DeclarationContext {
                distribution: accepted(distribution_entry(7)),
                ..ctx(4_000)
            },
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

    /// A declare whose suffix is not a parseable output vector fails closed
    /// on both connection kinds: an output set that cannot be verified is
    /// never accepted, and on a base connection the mining-side binding
    /// could not express it.
    #[test]
    fn declare_unrebuildable_coinbase_rejected_on_either_connection() {
        for negotiated in [false, true] {
            let mut s = fresh();
            let token = complete_setup_and_allocate(&mut s);
            let mut input = declare(3, token, vec![]);
            // 8 opaque bytes: strips to an empty body, not a TxOut vector.
            input.coinbase_tx_suffix = vec![0xBB; 8];
            let distribution = if negotiated {
                negotiate_0x0003(&mut s);
                input.distribution_id = Some(7);
                accepted(distribution_entry(7))
            } else {
                None
            };
            let out = declared(
                &mut s,
                &input,
                &HashMap::new(),
                DeclarationContext {
                    distribution,
                    ..ctx(3_000)
                },
            );
            match &out.outbound[0] {
                JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                    assert_eq!(error_code, ERR_INVALID_JOB_PARAM_COINBASE);
                }
                f => panic!("expected DeclareMiningJobError (negotiated={negotiated}), got {f:?}"),
            }
            assert_eq!(s.declared_jobs.len(), 0);
        }
    }

    /// Positive control: a coinbase that DOES rebuild is accepted on a plain
    /// base-protocol connection, with no distribution in sight.
    #[test]
    fn declare_rebuildable_coinbase_accepted_on_a_base_connection() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let out = declared(
            &mut s,
            &declare(3, token, vec![]),
            &HashMap::new(),
            ctx(3_000),
        );
        assert!(
            matches!(
                out.outbound[0],
                JdpOutboundFrame::DeclareMiningJobSuccess { .. }
            ),
            "got {:?}",
            out.outbound[0]
        );
        assert_eq!(s.declared_jobs.len(), 1);
    }

    /// ext 0x0003/Negotiation: a distribution reference from a client that
    /// never negotiated ext 0x0003 MUST be rejected — the IO layer captures
    /// the TLV unconditionally so this gate fires in production too.
    #[test]
    fn declare_with_tlv_but_no_negotiation_rejected() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let mut input = declare(2, token, vec![]);
        input.distribution_id = Some(7);
        let out = declared(
            &mut s,
            &input,
            &HashMap::new(),
            DeclarationContext {
                distribution: accepted(distribution_entry(7)),
                ..ctx(3_000)
            },
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
    ///
    /// It MUST still record which distribution it was accepted against: the
    /// mining side inherits that reference for a Full-Template job
    /// (ext 0x0003/distribution_id TLV Field sits on this message, not on
    /// `SetCustomMiningJob`). Without it every later custom job would be
    /// refused `custom-jobs-require-solo`, which JD-clients treat as fatal.
    #[test]
    fn declare_unbookable_distribution_accepted_without_booking() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        negotiate_0x0003(&mut s);
        let mut entry = distribution_entry(7);
        entry.built.bookable = false;
        let mut input = declare(3, token, vec![]);
        input.distribution_id = Some(7);
        input.coinbase_tx_suffix = matching_suffix(&entry, 5_000_000_000);
        let out = declared(
            &mut s,
            &input,
            &HashMap::new(),
            DeclarationContext {
                distribution: accepted(entry),
                ..ctx(3_000)
            },
        );
        assert!(
            matches!(
                out.outbound[0],
                JdpOutboundFrame::DeclareMiningJobSuccess { .. }
            ),
            "unbookable distribution still serves the job, got {:?}",
            out.outbound[0]
        );
        let declared = s.declared_jobs.iter().next().unwrap();
        assert_eq!(declared.booking, None);
        assert_eq!(
            declared.distribution_id,
            Some(7),
            "the reference must survive a non-bookable distribution — it is \
             what a Full-Template SetCustomMiningJob inherits"
        );
    }

    /// A coinbase that does not rebuild is refused whichever part is empty or
    /// malformed, with a positive control so "everything is refused" cannot
    /// pass for "these are refused".
    #[test]
    fn a_coinbase_that_will_not_rebuild_is_refused() {
        for (label, prefix, suffix) in [
            ("both empty", vec![], vec![]),
            ("empty prefix", vec![], coinbase_suffix(&one_output_blob())),
            ("empty suffix", coinbase_prefix(), vec![]),
            (
                "garbage prefix",
                vec![0xAA; 8],
                coinbase_suffix(&one_output_blob()),
            ),
        ] {
            let mut s = fresh();
            let token = complete_setup_and_allocate(&mut s);
            let mut input = declare(4, token, vec![]);
            input.coinbase_tx_prefix = prefix;
            input.coinbase_tx_suffix = suffix;
            let out = declared(&mut s, &input, &HashMap::new(), ctx(3_000));
            match &out.outbound[0] {
                JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                    assert_eq!(error_code, ERR_INVALID_JOB_PARAM_COINBASE, "{label}");
                }
                other => panic!("{label} must be refused, got {other:?}"),
            }
            assert_eq!(s.declared_jobs.len(), 0, "{label} must not be stored");
        }

        // Positive control: the honest coinbase from the same fixtures is
        // accepted, so the refusals above are about the coinbase.
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let out = declared(
            &mut s,
            &declare(5, token, vec![]),
            &HashMap::new(),
            ctx(3_000),
        );
        assert!(matches!(
            out.outbound[0],
            JdpOutboundFrame::DeclareMiningJobSuccess { .. }
        ));
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
        let out = declared(&mut s, &input, &tpl, ctx(3_000));
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
        assert!(!s.pending_declarations.is_empty());
        assert_eq!(s.declared_jobs.len(), 0, "not accepted yet");
    }

    /// Declare one job that needs a round-trip, on a fresh token allocated at
    /// `now_ms`, and assert the round-trip went out.
    fn declare_pending(s: &mut JdpSessionState, request_id: u32, now_ms: u64) {
        let known = [0x01; 32];
        let missing = [0x02; 32];
        let mut tpl = HashMap::new();
        tpl.insert(known, vec![0xCA; 16]);
        let token = allocate_another(s, 100 + request_id, now_ms);
        let out = declared(
            s,
            &declare(request_id, token, vec![known, missing]),
            &tpl,
            ctx(now_ms),
        );
        assert!(
            matches!(
                out.outbound.first(),
                Some(JdpOutboundFrame::ProvideMissingTransactions { .. })
            ),
            "precondition: declaration {request_id} needs a round-trip"
        );
    }

    /// Complete the round-trip of `request_id` and return what it answered.
    fn complete(s: &mut JdpSessionState, request_id: u32, now_ms: u64) -> Option<JdpOutboundFrame> {
        handle_provide_missing_transactions_success(
            s,
            &ProvideMissingTransactionsSuccessInput {
                request_id,
                transaction_list: vec![vec![0xBB; 16]],
            },
            ctx(now_ms),
        )
        .outbound
        .into_iter()
        .next()
    }

    fn accepted_as(frame: Option<JdpOutboundFrame>, expected: u32) -> bool {
        matches!(
            frame,
            Some(JdpOutboundFrame::DeclareMiningJobSuccess { request_id, .. })
                if request_id == expected
        )
    }

    /// A JDC may declare again before it has answered the first
    /// `ProvideMissingTransactions`, so pending declarations are kept by
    /// `request_id`. Both complete, in whichever order the JDC answers.
    #[test]
    fn two_declarations_in_flight_both_complete() {
        let mut s = fresh();
        let _ = handle_setup_connection(&mut s, &good_setup());
        declare_pending(&mut s, 4, 1_000);
        declare_pending(&mut s, 5, 2_000);

        assert!(accepted_as(complete(&mut s, 5, 2_100), 5), "the later one");
        assert!(
            accepted_as(complete(&mut s, 4, 2_200), 4),
            "and the earlier one"
        );
        assert_eq!(s.declared_jobs.len(), 2);
    }

    /// Pending declarations are bounded: past [`MAX_PENDING_DECLARATIONS`]
    /// the oldest is dropped, so a JDC that never answers cannot grow the
    /// session. The ones still held complete normally.
    #[test]
    fn past_the_bound_the_oldest_pending_declaration_is_dropped() {
        let mut s = fresh();
        let _ = handle_setup_connection(&mut s, &good_setup());
        let over = MAX_PENDING_DECLARATIONS as u32 + 1;
        for request_id in 1..=over {
            declare_pending(&mut s, request_id, u64::from(request_id) * 1_000);
        }

        let now = u64::from(over + 1) * 1_000;
        assert_eq!(complete(&mut s, 1, now), None, "the oldest was dropped");
        for request_id in 2..=over {
            assert!(
                accepted_as(complete(&mut s, request_id, now), request_id),
                "pending declaration {request_id} must still complete"
            );
        }
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
        let _ = declared(&mut s, &input, &tpl, ctx(3_000));
        let success = ProvideMissingTransactionsSuccessInput {
            request_id: 5,
            transaction_list: vec![vec![0xFE; 16]],
        };
        let out = handle_provide_missing_transactions_success(&mut s, &success, ctx(4_000));
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobSuccess { request_id, .. } => {
                assert_eq!(*request_id, 5);
            }
            _ => panic!("expected DeclareMiningJobSuccess"),
        }
        assert_eq!(s.declared_jobs.len(), 1);
        assert!(s.pending_declarations.is_empty());
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
        let _ = declared(&mut s, &input, &tpl, ctx(3_000));
        let success = ProvideMissingTransactionsSuccessInput {
            request_id: 5,
            transaction_list: vec![vec![0xFE; 16]],
        };
        // …but the round-trip completes under tip 0xCD.
        let out = handle_provide_missing_transactions_success(
            &mut s,
            &success,
            DeclarationContext {
                current_prev_hash: Some([0xCD; 32]),
                ..ctx(4_000)
            },
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
            s.pending_declarations.is_empty(),
            "pending state is consumed — the JDC re-declares fresh"
        );
    }

    /// ext 0x0003/Grace Window + Implementation Notes are judged when the
    /// declaration is ACCEPTED: a distribution superseded during the
    /// missing-transactions round-trip rejects the declaration
    /// `stale-payout-distribution` even though it was accepted at declare
    /// time.
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
        let _ = declared(
            &mut s,
            &input,
            &tpl,
            DeclarationContext {
                distribution: accepted(entry),
                ..ctx(3_000)
            },
        );
        assert!(!s.pending_declarations.is_empty());
        let success = ProvideMissingTransactionsSuccessInput {
            request_id: 5,
            transaction_list: vec![vec![0xFE; 16]],
        };
        // …but superseded during the round-trip.
        let out = handle_provide_missing_transactions_success(
            &mut s,
            &success,
            DeclarationContext {
                distribution: Some(DistributionAcceptance::Stale),
                ..ctx(4_000)
            },
        );
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError { error_code, .. } => {
                assert_eq!(error_code, ERR_STALE_PAYOUT_DISTRIBUTION);
            }
            f => panic!("expected stale DeclareMiningJobError, got {f:?}"),
        }
        assert_eq!(s.declared_jobs.len(), 0);
    }

    /// The round-trip path runs the same ext 0x0003/Output Verification
    /// validation as the immediate path: a still-accepted distribution plus
    /// matching coinbase completes with a booking-stamped job.
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
        let _ = declared(
            &mut s,
            &input,
            &tpl,
            DeclarationContext {
                distribution: accepted(distribution_entry(7)),
                ..ctx(3_000)
            },
        );
        let success = ProvideMissingTransactionsSuccessInput {
            request_id: 5,
            transaction_list: vec![vec![0xFE; 16]],
        };
        let out = handle_provide_missing_transactions_success(
            &mut s,
            &success,
            DeclarationContext {
                distribution: accepted(distribution_entry(7)),
                ..ctx(4_000)
            },
        );
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobSuccess { request_id, .. } => {
                assert_eq!(*request_id, 5);
            }
            f => panic!("expected DeclareMiningJobSuccess, got {f:?}"),
        }
        assert_eq!(s.declared_jobs.len(), 1);
        let declared = s.declared_jobs.iter().next().unwrap();
        assert_eq!(
            declared.booking,
            Some(PayoutBooking {
                distribution_id: 7,
                payouts_fingerprint: [7u8; 32],
                reference_reward_sats: 312_500_000,
            })
        );
        // The mining side inherits this, not `booking` — the two are separate
        // claims and only this one survives a non-bookable distribution.
        assert_eq!(declared.distribution_id, Some(7));
    }

    #[test]
    fn provide_missing_without_pending_is_silently_dropped() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let success = ProvideMissingTransactionsSuccessInput {
            request_id: 99,
            transaction_list: vec![vec![]],
        };
        let out = handle_provide_missing_transactions_success(
            &mut s,
            &success,
            DeclarationContext {
                current_prev_hash: None,
                ..ctx(0)
            },
        );
        assert!(out.outbound.is_empty());
    }

    /// A `ProvideMissingTransactions.Success` that does not carry one
    /// transaction per requested position is answered `missing-txs`, so the
    /// JDC is not left waiting on a declaration that cannot complete.
    #[test]
    fn provide_missing_length_mismatch_is_refused_missing_txs() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let wtxid_a = [0x01; 32];
        let wtxid_b = [0x02; 32];
        let input = declare(6, token, vec![wtxid_a, wtxid_b]);
        let _ = declared(&mut s, &input, &HashMap::new(), ctx(3_000));
        // Pending expects 2 missing (positions 0,1) but only 1 is provided.
        let bad_success = ProvideMissingTransactionsSuccessInput {
            request_id: 6,
            transaction_list: vec![vec![0xFE; 16]],
        };
        let out = handle_provide_missing_transactions_success(&mut s, &bad_success, ctx(4_000));
        match out.outbound.first() {
            Some(JdpOutboundFrame::DeclareMiningJobError {
                request_id,
                error_code,
                ..
            }) => {
                assert_eq!(*request_id, 6);
                assert_eq!(error_code, ERR_MISSING_TXS);
            }
            other => panic!("expected DeclareMiningJobError, got {other:?}"),
        }
        assert!(s.declared_jobs.is_empty());
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
            header: SolutionHeader {
                prev_hash: [0xAB; 32],
                version: 0,
                ntime: 0,
                nonce: 0,
                n_bits: 0,
            },
        };
        let out = handle_push_solution(&mut s, &solution);
        assert!(out.outbound.is_empty());
        assert!(out.events.is_empty());
    }

    #[test]
    fn push_solution_no_declared_job_is_dropped() {
        let mut s = fresh();
        handle_setup_connection(&mut s, &good_setup());
        let solution = PushSolutionInput {
            extranonce: vec![0; 8],
            header: SolutionHeader {
                prev_hash: [0xAB; 32],
                version: 0,
                ntime: 0,
                nonce: 0,
                n_bits: 0,
            },
        };
        let out = handle_push_solution(&mut s, &solution);
        assert!(out.events.is_empty());
    }

    /// The block is booked against the DECLARATION's miner, and the
    /// declaration alone decides who that is, even with the token store
    /// emptied underneath it.
    #[test]
    fn a_pushed_solution_is_booked_against_its_declarations_miner() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let wtxid_a = [0x01; 32];
        let mut tpl = HashMap::new();
        tpl.insert(wtxid_a, vec![0xCA; 8]);
        let _ = declared(&mut s, &declare(7, token, vec![wtxid_a]), &tpl, ctx(3_000));

        // Drop every token the session holds — the declaration must still
        // know whose it is.
        s.tokens = TokenStore::new();

        let solution = PushSolutionInput {
            extranonce: vec![0xEE; 8],
            header: SolutionHeader {
                prev_hash: [0xAB; 32],
                version: 0x2000_0000,
                ntime: 0x6500_0001,
                nonce: 0x1234_5678,
                n_bits: 0x1d00_ffff,
            },
        };
        let out = handle_push_solution(&mut s, &solution);
        match &out.events[0] {
            JdpSessionEvent::BlockSubmissionCandidate { miner_address, .. } => {
                assert_eq!(
                    miner_address,
                    &addr(),
                    "the candidate must name the declaring miner, never a stand-in"
                );
                assert_ne!(
                    miner_address.as_str(),
                    "unknown",
                    "a fabricated address resolves to Solo and books nothing"
                );
            }
            other => panic!("expected BlockSubmissionCandidate, got {other:?}"),
        }
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
        let _ = declared(&mut s, &input, &tpl, ctx(3_000));
        let extranonce = vec![0xEE; 8];
        let solution = PushSolutionInput {
            extranonce: extranonce.clone(),
            header: SolutionHeader {
                prev_hash: [0xAB; 32],
                version: 0x2000_0000,
                ntime: 0x6500_0001,
                nonce: 0x1234_5678,
                n_bits: 0x1d00_ffff,
            },
        };
        let out = handle_push_solution(&mut s, &solution);
        assert!(out.outbound.is_empty());
        match &out.events[0] {
            JdpSessionEvent::BlockSubmissionCandidate {
                coinbase_raw,
                transactions,
                header,
                ..
            } => {
                // The candidate is the declared prefix + the miner's extranonce
                // + the declared suffix, spliced in that order.
                let plen = coinbase_prefix().len();
                let slen = coinbase_suffix(&one_output_blob()).len();
                assert_eq!(coinbase_raw.len(), plen + extranonce.len() + slen);
                assert_eq!(&coinbase_raw[..plen], &coinbase_prefix()[..]);
                assert_eq!(
                    &coinbase_raw[plen..plen + extranonce.len()],
                    &extranonce[..]
                );
                assert_eq!(transactions.len(), 1, "1 non-coinbase tx");
                assert_eq!(transactions[0], vec![0xCA; 8]);
                assert_eq!(header.prev_hash, [0xAB; 32]);
                assert_eq!(header.ntime, 0x6500_0001);
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
        let _ = declared(&mut s, &input, &tpl, ctx(3_000));
        // No declared_jobs entry yet (still pending) → push_solution
        // can't find a matching job → drops. Pin that path.
        assert_eq!(s.declared_jobs.len(), 0);
        let solution = PushSolutionInput {
            extranonce: vec![0; 8],
            header: SolutionHeader {
                prev_hash: [0xAB; 32],
                version: 0,
                ntime: 0,
                nonce: 0,
                n_bits: 0,
            },
        };
        let out = handle_push_solution(&mut s, &solution);
        assert!(out.events.is_empty());
    }
}
