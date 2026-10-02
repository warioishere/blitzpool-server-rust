// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure handler layer for the JDP-server connection state machine: each
//! `handle_*` mutates the session and returns a [`JdpHandlerOutcome`]. Handlers
//! never close the socket; they emit [`JdpSessionEvent::Disconnect`] so the IO
//! layer writes the pending `SetupConnection.Error` first.

use std::collections::HashSet;

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
use super::tx_validation::DeclaredTxs;

// ── Constants ────────────────────────────────────────────────────────

/// `protocol` field of SV2 Overview/SetupConnection for Job Declaration.
pub const PROTOCOL_JOB_DECLARATION: u8 = 1;

/// `DECLARE_TX_DATA` (bit 0 of `SetupConnection.flags`): set = Full-Template
/// mode (`DeclareMiningJob` first), clear = Coinbase-only mode.
pub const FLAG_DECLARE_TX_DATA: u32 = 1 << 0;

/// JDP-side SV2 extensions this server supports.
pub const SUPPORTED_JDP_EXTENSIONS: &[u16] = &[SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS];

fn is_jdp_extension_supported(ext: u16) -> bool {
    SUPPORTED_JDP_EXTENSIONS.contains(&ext)
}

// ── Wire error codes ─────────────────────────────────────────────────

/// `DeclareMiningJob` without negotiated `DECLARE_TX_DATA`. Borrowed from
/// `SetupConnection.Error` (pinned in `tests/wire_error_parity.rs`); never
/// `stale-chain-tip`, which would invite a retry only a new connection fixes.
pub const ERR_UNSUPPORTED_FEATURE_FLAGS: &str = "unsupported-feature-flags";

/// Token never issued, expired, or already spent (one token, one declaration).
pub const ERR_INVALID_MINING_JOB_TOKEN: &str = "invalid-mining-job-token";

/// Declared coinbase lacks the pool's committed payout outputs verbatim.
pub const ERR_INVALID_JOB_PARAM_COINBASE: &str = "invalid-job-param-value-coinbase_tx_outputs";

/// `distribution_id` outside the ext 0x0003/Grace Window, settlement-invalidated,
/// or never published; the JDC SHOULD re-declare against the latest.
pub const ERR_STALE_PAYOUT_DISTRIBUTION: &str =
    crate::extensions::payout_distribution_error_codes::STALE_PAYOUT_DISTRIBUTION;

/// Coinbase fails the ext 0x0003/Payout Computation recompute, or the
/// `distribution_id` TLV is missing/malformed while negotiated.
pub const ERR_INVALID_PAYOUT_DISTRIBUTION: &str =
    crate::extensions::payout_distribution_error_codes::INVALID_PAYOUT_DISTRIBUTION;

/// The tip moved while the declaration was in flight. The exact string matters:
/// JDCs retry `stale-chain-tip` and treat every other declaration error as fatal.
pub const ERR_STALE_CHAIN_TIP: &str = "stale-chain-tip";

/// After `ProvideMissingTransactions.Success` the node still cannot resolve
/// every declared wtxid; an unseen declaration is never validated.
pub const ERR_MISSING_TXS: &str = "missing-txs";

/// Declarations one connection may have awaiting
/// `ProvideMissingTransactions.Success`; bounds a JDC that never answers.
pub const MAX_PENDING_DECLARATIONS: usize = 3;

// ── Inputs (typed wrappers over deserialized SV2 frames) ────────────

/// Inputs from a deserialized `AllocateMiningJobToken` frame.
#[derive(Clone, Debug)]
pub struct AllocateMiningJobTokenInput {
    pub request_id: u32,
    /// Used as the miner address if it normalizes; otherwise the fallback is.
    pub user_identifier: String,
}

/// Inputs from a deserialized `DeclareMiningJob` frame.
#[derive(Clone, Debug)]
pub struct DeclareMiningJobInput {
    pub request_id: u32,
    pub mining_job_token: Token,
    pub version: u32,
    pub coinbase_tx_prefix: Vec<u8>,
    pub coinbase_tx_suffix: Vec<u8>,
    pub wtxid_list: Vec<[u8; 32]>,
    /// The ext 0x0003/distribution_id TLV Field, when present and negotiated.
    pub distribution_id: Option<u64>,
}

/// Inputs from a `ProvideMissingTransactions.Success` frame, index-aligned
/// with the requested `missing_positions`.
#[derive(Clone, Debug)]
pub struct ProvideMissingTransactionsSuccessInput {
    pub request_id: u32,
    pub transaction_list: Vec<Vec<u8>>,
}

/// The block-header fields a `PushSolution` carries. Named fields because four
/// are `u32` and a swap compiles fine but hashes to nothing.
#[derive(Clone, Copy, Debug)]
pub struct SolutionHeader {
    /// Tip the solution was mined on.
    pub prev_hash: [u8; 32],
    /// BIP-320 version-rolled header version.
    pub version: u32,
    pub ntime: u32,
    pub nonce: u32,
    /// As the JDC sent it; never a threshold (the pool checks its OWN target).
    pub n_bits: u32,
}

/// Which declaration a pushed solution came from, and on which JDP session.
#[derive(Clone, Copy, Debug)]
pub struct DeclarationRef {
    /// The `new_mining_job_token` from `DeclareMiningJobSuccess`.
    pub new_token: Token,
    /// Stored in `blocks_entity."sessionId"` as `{:08x}`, matching the
    /// `jdp-{id:08x}` connection logs.
    pub jdp_session_id: u32,
}

/// Inputs from a deserialized `PushSolution` frame (SV2 JDP/PushSolution).
#[derive(Clone, Debug)]
pub struct PushSolutionInput {
    pub extranonce: Vec<u8>,
    pub header: SolutionHeader,
}

// ── Pre-resolved hook arguments (caller-supplied) ───────────────────

/// What the IO layer resolves before [`handle_allocate_token`]: the miner and
/// the one-output blob from
/// [`crate::jdp::dynamic_outputs::designated_output_blob`].
#[derive(Clone, Debug)]
pub struct AllocateTokenContext {
    pub miner_address: AddressId,
    pub coinbase_outputs: Vec<u8>,
}

// ── OutboundFrame ───────────────────────────────────────────────────

/// What the JDP handler decided to send; the IO layer encodes it.
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
    /// ext 0x0003/SetPayoutDistribution push; emitted by the IO layer only.
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
#[derive(Clone, Debug)]
pub enum JdpSessionEvent {
    /// `SetupConnection` completed; the negotiated mode lives on
    /// [`JdpSessionState::full_template_mode`].
    SetupComplete,
    /// A token was allocated; the IO layer mirrors it into the bridge for
    /// Coinbase-only `SetCustomMiningJob`.
    TokenAllocated {
        token: Token,
        miner_address: AddressId,
        /// The designated payout output of SV2 JDP/AllocateMiningJobToken.Success.
        /// `None` on an ext 0x0003 session: there the outputs are empty and a
        /// custom job is judged by the ext 0x0003/Output Verification recompute.
        payout_script: Option<Vec<u8>>,
        /// The token's own expiry, so the bridge entry cannot outlive it.
        expires_at_ms: u64,
    },
    /// A `DeclareMiningJob` was accepted. Only the key: the rest is read off
    /// the stored [`DeclaredJob`], so nothing here can disagree with it.
    JobDeclared { new_token: Token },
    /// A `PushSolution` resolved against a declared job; the IO layer builds
    /// the block and calls `submitblock` (idempotent, the JDC submits too).
    BlockSubmissionCandidate {
        miner_address: AddressId,
        declaration: DeclarationRef,
        /// Non-witness coinbase: prefix + extranonce + suffix.
        coinbase_raw: Vec<u8>,
        /// Positions 1..=N in `wtxid_list` order, coinbase excluded; may carry
        /// witness data.
        transactions: Vec<Vec<u8>>,
        header: SolutionHeader,
        /// From the declare-time ext 0x0003/Output Verification proof; decides
        /// both booking and settlement, see [`CandidateBacking`].
        backing: CandidateBacking,
    },
    /// Close the connection after any preceding outbound frame is sent.
    Disconnect { reason: String },
}

// ── HandlerOutcome ──────────────────────────────────────────────────

/// What a single handler call produced; both fields may be empty.
#[derive(Clone, Debug, Default)]
pub struct JdpHandlerOutcome {
    pub outbound: Vec<JdpOutboundFrame>,
    pub events: Vec<JdpSessionEvent>,
}

impl JdpHandlerOutcome {
    /// A `DeclareMiningJob.Error` and nothing else.
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

/// All pure per-connection state for the JDP sub-protocol, owned by the
/// connection task; I/O handles live in the IO layer.
pub struct JdpSessionState {
    pub session_id: u32,

    // Negotiated state from SetupConnection.
    pub setup_complete: bool,
    pub full_template_mode: bool,

    /// Extensions negotiated via ext 0x0001 in [`handle_request_extensions`].
    pub negotiated_extensions: HashSet<u16>,

    pub tokens: TokenStore,

    /// FIFO, bounded by `MAX_DECLARED_JOBS`.
    pub declared_jobs: DeclaredJobStore,

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
            .retain(|held| held.input.request_id != pending.input.request_id);
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
            .find(|held| held.input.request_id == request_id)
    }

    pub fn take(&mut self, request_id: u32) -> Option<PendingState> {
        let position = self
            .0
            .iter()
            .position(|held| held.input.request_id == request_id)?;
        self.0.remove(position)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// An in-flight declaration: the original input kept for acceptance after the
/// missing-tx round-trip.
#[derive(Clone, Debug)]
pub struct PendingState {
    pub input: DeclareMiningJobInput,
    /// Gaps at the positions asked for in `ProvideMissingTransactions`.
    pub txs: DeclaredTxs,
    pub miner_address: AddressId,
    /// Pool tip when `DeclareMiningJob` arrived; a different tip at completion
    /// means `stale-chain-tip`.
    pub prev_hash_at_declare: Option<[u8; 32]>,
}

impl JdpSessionState {
    pub fn new(session_id: u32) -> Self {
        Self {
            session_id,
            setup_complete: false,
            full_template_mode: false,
            negotiated_extensions: HashSet::new(),
            tokens: TokenStore::new(),
            declared_jobs: DeclaredJobStore::new(),
            pending_declarations: PendingDeclarations::default(),
        }
    }

    /// Inject a deterministic RNG into the [`TokenStore`] (tests).
    pub fn set_token_rng(&mut self, rng: Option<Box<crate::tokens::RngFn>>) {
        self.tokens.set_rng(rng);
    }
}

// ── Handler: SetupConnection ────────────────────────────────────────

/// Handle a JDP `SetupConnection`: wrong protocol or version → error +
/// Disconnect; else success echoing only the `DECLARE_TX_DATA` bit.
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

    JdpHandlerOutcome {
        outbound: vec![JdpOutboundFrame::SetupConnectionSuccess {
            used_version,
            flags: negotiated_flags,
        }],
        events: vec![JdpSessionEvent::SetupComplete],
    }
}

// ── Handler: RequestExtensions (ext 0x0001) ─────────────────────────

/// Dropped before setup; `Error` only when a non-empty request has nothing
/// supported. 0x0003 is offered only if `distribution_available`: ext
/// 0x0003/SetPayoutDistribution must be the FIRST message after this exchange.
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

/// Handle `AllocateMiningJobToken`. Pre-setup, rate-limited and pool-side
/// allocation failures go unanswered (SV2 defines no error); only the last is logged.
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
        // SV2 JDP/AllocateMiningJobToken defines no wire answer for the limit.
        Err(TokenAllocError::RateLimited { .. }) => return JdpHandlerOutcome::default(),
        // Pool-side fault; logged so it is not mistaken for the rate limit.
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
    // From the very bytes sent, so the mining side checks what the JDC got.
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

/// Parse `user_identifier` as a BTC address of any network; the network check
/// is the resolver's job.
pub fn parse_user_identifier_as_address(user_identifier: &str) -> Option<AddressId> {
    let trimmed = user_identifier.trim();
    if trimmed.is_empty() {
        return None;
    }
    // `address.worker`: a trailing `.worker` would fail `address_to_script`.
    let (address_part, _worker) = bp_common::split_user_identity(trimmed);
    if address_part.is_empty() {
        return None;
    }
    let normalised = normalize_btc_address(address_part);
    AddressId::new(normalised).ok()
}

// ── Handler: DeclareMiningJob ───────────────────────────────────────

// ── Caller-resolved per-frame context ───────────────────────────────

/// The pool's live state as resolved for THIS declaration frame.
///
/// ⚠️ Per-frame, never stored: `ProvideMissingTransactions.Success` resolves a
/// fresh one, since distribution, mode and tip may move during the round-trip.
#[derive(Clone, Debug)]
pub struct DeclarationContext {
    /// Tip now; compared with [`PendingState::prev_hash_at_declare`].
    pub current_prev_hash: Option<[u8; 32]>,
    /// The referenced `distribution_id`'s acceptance now; `None` = no reference,
    /// which fails closed on a negotiated connection.
    pub distribution: Option<DistributionAcceptance>,
    /// The token address's stream now, `None` without a live mining session.
    pub current_mode: Option<bp_common::StreamKind>,
    pub now_ms: u64,
}

/// Refusals from the session alone, checked before the token is spent so the
/// JDC sees the real reason: a `distribution_id` TLV without negotiated ext
/// 0x0003, or Coinbase-only mode.
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

/// Handle `DeclareMiningJob` after the caller spent the token
/// ([`crate::tokens::TokenStore::take_active`]) and matched the wtxids
/// against the template:
/// accept now, or ask via `ProvideMissingTransactions` and stash a [`PendingState`].
/// `declaring_miner` is the spent token's address, never the connection's.
pub fn handle_declare_mining_job(
    state: &mut JdpSessionState,
    input: &DeclareMiningJobInput,
    declaring_miner: &AddressId,
    txs: DeclaredTxs,
    ctx: DeclarationContext,
) -> JdpHandlerOutcome {
    let miner_address = declaring_miner.clone();

    let txs = match txs.into_complete() {
        Ok(raw) => return accept_declaration(state, input, raw, miner_address, ctx),
        Err(gapped) => gapped,
    };

    let outcome = JdpHandlerOutcome::with_frame(JdpOutboundFrame::ProvideMissingTransactions {
        request_id: input.request_id,
        unknown_tx_position_list: txs.missing_positions(),
    });
    let evicted = state.pending_declarations.insert(PendingState {
        input: input.clone(),
        txs,
        miner_address,
        prev_hash_at_declare: ctx.current_prev_hash,
    });
    if let Some(dropped) = evicted {
        tracing::warn!(
            dropped_request_id = dropped.input.request_id,
            request_id = input.request_id,
            "jdp: too many declarations waiting for ProvideMissingTransactions.Success — \
             the oldest is dropped and its request_id will never be answered"
        );
    }
    outcome
}

// ── Handler: ProvideMissingTransactions.Success ─────────────────────

/// Handle `ProvideMissingTransactions.Success`: unknown `request_id` dropped,
/// a list that does not fill the gaps ([`DeclaredTxs::complete_with`]) →
/// `missing-txs`, else accept under a freshly resolved [`DeclarationContext`].
pub fn handle_provide_missing_transactions_success(
    state: &mut JdpSessionState,
    input: ProvideMissingTransactionsSuccessInput,
    ctx: DeclarationContext,
) -> JdpHandlerOutcome {
    let Some(pending) = state.pending_declarations.take(input.request_id) else {
        return JdpHandlerOutcome::default();
    };
    // Tip moved during the round-trip: the JDC retries `stale-chain-tip`.
    if pending.prev_hash_at_declare != ctx.current_prev_hash {
        return JdpHandlerOutcome::declare_error(
            input.request_id,
            ERR_STALE_CHAIN_TIP,
            b"chain tip advanced during the missing-transactions round-trip",
        );
    }
    let merged = match pending.txs.complete_with(input.transaction_list) {
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
    raw_transactions: Vec<Vec<u8>>,
    miner_address: AddressId,
    ctx: DeclarationContext,
) -> JdpHandlerOutcome {
    // A declaration binds to the pool's tip; before the first template there
    // is none, so refuse with the one code a JD-client retries.
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

    // Must rebuild on EVERY connection: `crate::jdp::custom_job_binding`
    // projects from it, so an unbuildable one would fail every custom job later.
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

    // ext 0x0003/Validation: a negotiated declaration MUST reference a published
    // distribution and match its recompute positionally (ext 0x0003/Output Verification).
    let mut declared_booking: Option<PayoutBooking> = None;
    // Set even when not bookable; see `DeclaredJob::distribution_id`.
    let mut declared_distribution_id: Option<u64> = None;
    if state
        .negotiated_extensions
        .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
    {
        if input.distribution_id.is_none() {
            // ext 0x0003/distribution_id TLV Field: mandatory once negotiated.
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
                // ext 0x0003/Grace Window: the JDC re-declares against the latest.
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
                // IO-layer contract breach; fail closed.
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
        // The plan must fit the address's accounting NOW: a `PushSolution` block
        // books from the declaration alone, and a stale Solo plan would pay the
        // finder a block the group earned (Group-Solo has no ledger to repair it).
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
                declared_distribution_id = Some(entry.distribution_id);
                // Book only when the settlement snapshot actually landed.
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
    // No base-protocol designated-output check: such jobs are Solo-only, where
    // that output is the declarer's own. ⚠️ Must change if served off Solo.

    // Minted outside `allocate`, so the allocate rate limit cannot block it.
    let new_token = match state.tokens.mint_for_declaration() {
        Ok(token) => token,
        Err(err) => {
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

/// Handle `PushSolution`: match a declared job
/// ([`DeclaredJobStore::match_for_solution`]), rebuild the coinbase and emit a
/// [`JdpSessionEvent::BlockSubmissionCandidate`] booked to that job's own miner.
pub fn handle_push_solution(
    state: &mut JdpSessionState,
    input: &PushSolutionInput,
) -> JdpHandlerOutcome {
    // Drops are WARN-logged: this is a found block. Coinbase-only is normal
    // (SV2 JDP/Coinbase-only Mode, no declaration) and the mining side records it.
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

    let new_token = job.new_token;
    let miner_address = job.miner_address.clone();
    // `match` over BOTH fields: `booking.is_some()` answers a different question.
    let backing = match (job.booking, job.distribution_id) {
        (Some(booking), _) => CandidateBacking::Bookable(booking),
        // Snapshot never landed: no ledger entry, but the ext 0x0003
        // settle must still fire (see `CandidateBacking`).
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
        // Base-protocol: nothing to book or settle.
        (None, None) => CandidateBacking::BaseProtocol,
    };
    let coinbase_prefix = job.coinbase_tx_prefix.clone();
    let coinbase_suffix = job.coinbase_tx_suffix.clone();
    let transactions = job.raw_transactions.clone();

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
    use std::collections::HashMap;

    // ── Fixtures ───────────────────────────────────────────────────

    const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    fn addr() -> AddressId {
        AddressId::new(ADDR.to_string()).unwrap()
    }

    fn fresh() -> JdpSessionState {
        let mut s = JdpSessionState::new(1);
        // Deterministic, byte-predictable tokens.
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
            // Real suffix: every declaration must rebuild.
            coinbase_tx_suffix: coinbase_suffix(&one_output_blob()),
            wtxid_list: wtxids,
            distribution_id: None,
        }
    }

    /// A well-formed `coinbase_tx_prefix`: header, BIP-34 height push, and a
    /// 12-byte extranonce slot the prefix stops at.
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

    /// `nSequence + outputs + nLockTime`, paired with [`coinbase_prefix`].
    fn coinbase_suffix(outputs_consensus: &[u8]) -> Vec<u8> {
        let mut s = 0xFFFF_FFFFu32.to_le_bytes().to_vec();
        s.extend_from_slice(outputs_consensus);
        s.extend_from_slice(&0u32.to_le_bytes());
        s
    }

    /// Set up a session and allocate one token.
    fn complete_setup_and_allocate(s: &mut JdpSessionState) -> Token {
        let _ = handle_setup_connection(s, &good_setup());
        allocate_another(s, 1, 1_000)
    }

    /// One more token; the 1/s allocate rate limit means `now_ms` must advance.
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

    /// Minimal distribution: pool weight 1 + one miner weight 9.
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

    /// Default [`DeclarationContext`] at the tests' tip; override with `..ctx(t)`.
    fn ctx(now_ms: u64) -> DeclarationContext {
        DeclarationContext {
            current_prev_hash: Some([0xAB; 32]),
            distribution: None,
            current_mode: None,
            now_ms,
        }
    }

    /// The IO layer's pre-handler steps: session gates, spending the token
    /// ([`TokenStore::take_active`]), template match. Panics on a reused token.
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
        let txs = DeclaredTxs::against_template(&input.wtxid_list, template_txs);
        handle_declare_mining_job(s, input, &declaring.miner_address, txs, ctx)
    }

    /// Suffix carrying the ext 0x0003/Payout Computation recompute for `entry` at `t`.
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

    /// 0x0003 is not offered while no distribution can be published first.
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

    /// Two allocates at connect are both answered; JD-clients never re-request.
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

    /// An entropy failure drops the allocate with no frame and no event.
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
        let out = parse_user_identifier_as_address(&"x".repeat(200));
        assert!(out.is_none());
    }

    #[test]
    fn parse_user_identifier_strips_worker_suffix() {
        let out = parse_user_identifier_as_address(&format!("{ADDR}.gitgab"));
        assert_eq!(out.map(|a| a.as_str().to_string()), Some(ADDR.to_string()));
        let out2 = parse_user_identifier_as_address(&format!("{ADDR}.rig.1"));
        assert_eq!(out2.map(|a| a.as_str().to_string()), Some(ADDR.to_string()));
        assert!(parse_user_identifier_as_address(".worker").is_none());
    }

    // ── DeclareMiningJob ───────────────────────────────────────────

    #[test]
    fn declare_in_coinbase_only_mode_returns_unsupported_feature_flags() {
        let mut s = fresh();
        let mut setup = good_setup();
        setup.flags = 0; // Coinbase-only mode
        handle_setup_connection(&mut s, &setup);
        // Allocation is not mode-gated.
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

    /// No pool tip yet → retryable `stale-chain-tip`; with a tip, accepted.
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

    /// INTEROP: the allocate rate limit never blocks a declaration; an
    /// unanswered declare makes the JDC switch pools (SV2 JDP/Job Declarator Client).
    #[test]
    fn a_declaration_in_the_same_second_as_an_allocate_is_still_answered() {
        let mut s = fresh();
        let _ = handle_setup_connection(&mut s, &good_setup());
        let out = handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 1_000);
        let token = match out.outbound[0] {
            JdpOutboundFrame::AllocateMiningJobTokenSuccess {
                mining_job_token, ..
            } => mining_job_token,
            _ => panic!("expected AllocateMiningJobTokenSuccess"),
        };

        // 100 ms later, inside the 1 s allocate limit.
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

    /// Declaration tokens live in the capped `declared_jobs`, never the
    /// unbounded-by-mint token store.
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
            // Per step, not net: one allocate in, one out.
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

    /// Allocating sweeps expired tokens, keeping the map bounded by rate × TTL.
    #[test]
    fn allocating_sweeps_the_tokens_that_outlived_their_ttl() {
        let mut s = fresh();
        let _ = handle_setup_connection(&mut s, &good_setup());
        let _ = handle_allocate_token(&mut s, &good_alloc(1), alloc_ctx(), 1_000);
        let _ = handle_allocate_token(&mut s, &good_alloc(2), alloc_ctx(), 2_100);
        assert_eq!(s.tokens.len(), 2, "precondition: both are live");

        let past_ttl = 2_100 + crate::tokens::DEFAULT_TOKEN_TTL_MS + 1;
        let _ = handle_allocate_token(&mut s, &good_alloc(3), alloc_ctx(), past_ttl);
        assert_eq!(
            s.tokens.len(),
            1,
            "the two expired tokens must be gone, leaving only the fresh one"
        );
    }

    /// Minting a declaration token does not move the allocate budget.
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
        let _ = handle_allocate_token(&mut s, &good_alloc(4), alloc_ctx(), 1_000);
        let _ = declared(&mut s, &declare(3, token, vec![wtxid]), &tpl, ctx(1_100));

        let out = handle_allocate_token(&mut s, &good_alloc(2), alloc_ctx(), 1_500);
        assert!(
            out.outbound.is_empty(),
            "an allocate past the burst inside 1 s must still be rate-limited"
        );
        // Measured from the allocates at 1_000, not the declaration at 1_100.
        let out = handle_allocate_token(&mut s, &good_alloc(5), alloc_ctx(), 2_050);
        assert!(
            matches!(
                out.outbound[0],
                JdpOutboundFrame::AllocateMiningJobTokenSuccess { .. }
            ),
            "the declaration must not have pushed the allocate budget forward"
        );
    }

    /// ext 0x0003/distribution_id TLV Field: missing TLV once negotiated is rejected.
    #[test]
    fn declare_negotiated_without_distribution_tlv_rejected() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        negotiate_0x0003(&mut s);
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

    /// ext 0x0003/Grace Window: `Stale` and `Unknown` both → `stale-payout-distribution`.
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
            // A refusal spends the token too.
            token = allocate_another(&mut s, 3 + attempt as u32, 2_100 + attempt as u64 * 1_100);
        }
        assert_eq!(s.declared_jobs.len(), 0);
    }

    /// An unresolved acceptance on a negotiated declare fails closed.
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

    /// A plan is refused once the address is on a different mode; its own mode
    /// or no known mode (miner briefly dropped) is accepted.
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

    /// ext 0x0003/Output Verification: matching outputs are accepted and booked;
    /// the same outputs in the wrong order are rejected.
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

        // Accept: the recomputed vector; the refusal spent the token.
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

    /// An unparseable output suffix fails closed on base and 0x0003 connections.
    #[test]
    fn declare_unrebuildable_coinbase_rejected_on_either_connection() {
        for negotiated in [false, true] {
            let mut s = fresh();
            let token = complete_setup_and_allocate(&mut s);
            let mut input = declare(3, token, vec![]);
            // Not a TxOut vector.
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

    /// Positive control: a rebuildable coinbase is accepted on a base connection.
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

    /// ext 0x0003/Negotiation: a `distribution_id` TLV without negotiation is rejected.
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

    /// `bookable = false`: accepted without booking, but the `distribution_id`
    /// is kept; the Full-Template `SetCustomMiningJob` inherits it.
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

    /// A coinbase that does not rebuild is refused whichever part is broken.
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

        // Positive control.
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

    /// Declare one job that needs a round-trip, on a fresh token.
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
            ProvideMissingTransactionsSuccessInput {
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

    /// Two pending declarations both complete, in either order.
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

    /// Past [`MAX_PENDING_DECLARATIONS`] the oldest is dropped; the rest complete.
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
        let out = handle_provide_missing_transactions_success(&mut s, success, ctx(4_000));
        match &out.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobSuccess { request_id, .. } => {
                assert_eq!(*request_id, 5);
            }
            _ => panic!("expected DeclareMiningJobSuccess"),
        }
        assert_eq!(s.declared_jobs.len(), 1);
        assert!(s.pending_declarations.is_empty());
    }

    /// A tip move during the round-trip → `stale-chain-tip`.
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
            success,
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

    /// ext 0x0003/Grace Window is judged at acceptance: superseded mid-round-trip
    /// → `stale-payout-distribution`.
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
            success,
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

    /// The round-trip path validates like the immediate one and stamps the booking.
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
            success,
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
            success,
            DeclarationContext {
                current_prev_hash: None,
                ..ctx(0)
            },
        );
        assert!(out.outbound.is_empty());
    }

    /// A Success with the wrong transaction count is answered `missing-txs`.
    #[test]
    fn provide_missing_length_mismatch_is_refused_missing_txs() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let wtxid_a = [0x01; 32];
        let wtxid_b = [0x02; 32];
        let input = declare(6, token, vec![wtxid_a, wtxid_b]);
        let _ = declared(&mut s, &input, &HashMap::new(), ctx(3_000));
        // Two positions asked for, one provided.
        let bad_success = ProvideMissingTransactionsSuccessInput {
            request_id: 6,
            transaction_list: vec![vec![0xFE; 16]],
        };
        let out = handle_provide_missing_transactions_success(&mut s, bad_success, ctx(4_000));
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

    /// The block is booked to the declaration's miner, even with the token store emptied.
    #[test]
    fn a_pushed_solution_is_booked_against_its_declarations_miner() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let wtxid_a = [0x01; 32];
        let mut tpl = HashMap::new();
        tpl.insert(wtxid_a, vec![0xCA; 8]);
        let _ = declared(&mut s, &declare(7, token, vec![wtxid_a]), &tpl, ctx(3_000));

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

    /// A matching solution yields a candidate with the reconstructed coinbase.
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
    fn push_solution_on_a_still_pending_declaration_submits_nothing() {
        let mut s = fresh();
        let token = complete_setup_and_allocate(&mut s);
        let wtxid_a = [0x01; 32];
        let wtxid_b = [0x02; 32];
        let mut tpl = HashMap::new();
        tpl.insert(wtxid_a, vec![0xCA; 8]);
        // wtxid_b is not in the template, so the declaration stays pending.
        let input = declare(8, token, vec![wtxid_a, wtxid_b]);
        let _ = declared(&mut s, &input, &tpl, ctx(3_000));
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
