// SPDX-License-Identifier: AGPL-3.0-or-later

//! JDP-port server: handle + per-connection task.
//!
//! Mirrors [`crate::server`]'s shape but for the Job-Declaration
//! sub-protocol. Different from the mining server:
//!
//! - **No TemplateBroadcast arm**: JDP doesn't broadcast templates;
//!   the JDC builds its own and declares them. The pool-side
//!   `current_prev_hash` snapshot comes from a separate
//!   [`CurrentPrevHashProvider`] hook (typically backed by
//!   `bp-template-distribution::TdpHandle`).
//! - **No vardiff-tick**: JDP doesn't have vardiff (the JDC chooses
//!   its own work).
//! - **JobDeclared → bridge.register**: each accepted
//!   `DeclareMiningJob` produces a [`crate::jdp::client::JdpSessionEvent::JobDeclared`]
//!   which the IO layer turns into a
//!   `bridge.register(token, RegisteredDeclaredJob)` call so the
//!   mining server's `SetCustomMiningJob` handler can cross-check the
//!   token later.
//! - **Async-heavy hooks**: AllocateMiningJobToken needs a
//!   miner-address + encoded-coinbase-outputs resolution before the
//!   handler can run; DeclareMiningJob needs a template-tx-snapshot
//!   plus current-prev-hash; ProvideMissingTransactionsSuccess needs
//!   current-prev-hash again; PushSolution emits a
//!   BlockSubmissionCandidate event that fans out to a JDP-specific
//!   block-submission sink.
//!
//! ## Notes
//!
//! - **ext 0x0003 (Non-Custodial Pool Payouts)** messages aren't in
//!   `stratum-core::AnyMessage`; the per-connection task pre-decodes them via a
//!   raw-bytes path (inbound) and serialises the Success/Error responses the
//!   same way (outbound) — see the noise-read arm + `write_jdp_outbound_frames`.
//! - **Full payout-output validation** in `accept_declaration` is wired: the
//!   declared coinbase is matched against the `PayoutOutputsTracker` single-use
//!   set the pool committed via `RequestPayoutOutputs`.
//! - **Full-block assembly + submitblock** is split by design — the handler
//!   emits a `BlockSubmissionCandidate` event carrying the raw components; the
//!   bin's production hook reconstructs the block via rust-bitcoin and submits
//!   via `TdpHandle::submit_solution`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bp_common::AddressId;
use stratum_core::codec_sv2::StandardSv2Frame;
use stratum_core::framing_sv2::framing::Frame;
use stratum_core::parsers_sv2::{parse_message_frame_with_tlvs, AnyMessage};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::bridge::{IssuedPayoutSet, JdpDeclaredJobRegistry, RegisteredDeclaredJob};
use crate::jdp::client::{
    handle_allocate_token, handle_declare_mining_job, handle_provide_missing_transactions_success,
    handle_push_solution, handle_request_extensions, handle_request_payout_outputs,
    handle_setup_connection, parse_user_identifier_as_address, AllocateTokenContext,
    JdpHandlerOutcome, JdpOutboundFrame, JdpSessionEvent, JdpSessionState,
};
use crate::jdp_server_codec::{
    decode_jdp_inbound, decode_jdp_inbound_ext_0x0003, encode_jdp_outbound,
    encode_jdp_outbound_ext_0x0003, InboundJdpFrame, EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS,
};
use crate::noise::{accept_pool_noise, NoiseConfig, NoiseTcpWriteHalf};
use crate::server::ServerConfig;
use crate::server_codec::CodecError;
use crate::tokens::Token;

// ── JDP-server hooks ────────────────────────────────────────────────

/// Resolve `(miner_address, encoded_coinbase_outputs)` for an
/// inbound `AllocateMiningJobToken`. Production wiring parses
/// `user_identifier` as a BTC address (or falls back to an IP-based
/// lookup), then computes the pool's payout outputs via
/// [`crate::hooks::PayoutResolver`] + [`crate::jdp::dynamic_outputs::encode_coinbase_outputs`].
/// Tests use a no-op + a custom fixture.
#[async_trait]
pub trait JdpAllocateResolver: Send + Sync {
    /// `remote_addr` is the connection's remote IP (string form, e.g.
    /// `"127.0.0.1:48292"`). Caller provides it so IP-based miner
    /// lookup is possible without leaking sockets into the handler.
    async fn resolve_allocate_context(
        &self,
        user_identifier: &str,
        remote_addr: &str,
    ) -> Option<AllocateTokenContext>;
}

/// Snapshot the pool's template-tx cache (`wtxid → raw_tx`) for the
/// JDP-server's `DeclareMiningJob` partition step. Production wiring
/// pulls from the same template state that drives the mining server's
/// translator; tests can return an empty map (the handler then
/// requests all txs via `ProvideMissingTransactions`).
#[async_trait]
pub trait TemplateTxProvider: Send + Sync {
    async fn snapshot(&self) -> HashMap<[u8; 32], Vec<u8>>;
}

/// Provide the pool's current `prev_hash`. Used by `DeclareMiningJob`
/// to stamp the declared job's prev_hash (matched later by PushSolution).
#[async_trait]
pub trait CurrentPrevHashProvider: Send + Sync {
    async fn current_prev_hash(&self) -> Option<[u8; 32]>;
}

/// Resolve the per-job payout output set for an ext 0x0003
/// `RequestPayoutOutputs` (spec §2.1). The resolver gets the
/// miner-address bound to the token (from `JdpSessionState.tokens`)
/// and the JDC-reported `available_payout_value`; it returns a fresh,
/// distribution-correct output set summing exactly to that value
/// (spec §2.2) OR a wire error code.
///
/// Production wiring routes through
/// [`crate::hooks::PayoutResolver`] (mode-gate-driven: solo /
/// PPLNS / Group-Solo) and serialises the result via
/// [`crate::jdp::dynamic_outputs::encode_coinbase_outputs`]. Tests
/// supply a fixture.
///
/// When the extension is not negotiated by the JDC, this hook is
/// never invoked (the standard `AllocateMiningJobToken.coinbase_outputs`
/// path applies per the base Job Declaration Protocol).
///
/// `committed_outputs` is the consensus-serialised `Vec<TxOut>` blob the
/// JDS returned in this token's `AllocateMiningJobToken.Success`. Per the
/// coinbase-reservation invariant (spec §6), the resolver MUST return a
/// set whose serialised size does not exceed it so the JDC's coinbase
/// reservation — sized from exactly these bytes — always fits.
#[async_trait]
pub trait PayoutOutputsResolver: Send + Sync {
    async fn resolve_payout_outputs(
        &self,
        miner_address: &AddressId,
        committed_outputs: &[u8],
        available_payout_value: u64,
        request_id: u32,
    ) -> crate::jdp::client::PayoutOutputsResolution;
}

/// Block-submission sink for `PushSolution` candidates. Production
/// wiring reconstructs the block via rust-bitcoin's `Block` + calls
/// `TdpHandle::submit_solution`; tests use a recording sink.
#[async_trait]
pub trait JdpBlockSubmissionSink: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn submit_block_candidate(
        &self,
        miner_address: AddressId,
        new_token: Token,
        coinbase_raw: Vec<u8>,
        transactions: Vec<Vec<u8>>,
        prev_hash: [u8; 32],
        version: u32,
        ntime: u32,
        nonce: u32,
        n_bits: u32,
    );
}

#[derive(Clone)]
pub struct JdpServerHooks {
    pub allocate_resolver: Arc<dyn JdpAllocateResolver>,
    pub template_tx_provider: Arc<dyn TemplateTxProvider>,
    pub prev_hash_provider: Arc<dyn CurrentPrevHashProvider>,
    pub block_submission_sink: Arc<dyn JdpBlockSubmissionSink>,
    /// ext 0x0003 per-job payout-outputs resolver. Wired in
    /// production by `bin/blitzpool::jdp_hooks` to route through
    /// `PayoutResolver` (mode-gate aware: solo / PPLNS / Group-Solo);
    /// tests use the [`NoOpJdpHooks`] which echoes the token-time
    /// committed output set.
    pub payout_outputs_resolver: Arc<dyn PayoutOutputsResolver>,
}

impl JdpServerHooks {
    pub fn no_op() -> Self {
        let n: Arc<NoOpJdpHooks> = Arc::new(NoOpJdpHooks);
        Self {
            allocate_resolver: n.clone(),
            template_tx_provider: n.clone(),
            prev_hash_provider: n.clone(),
            block_submission_sink: n.clone(),
            payout_outputs_resolver: n,
        }
    }
}

/// Drop-in no-op implementation for tests + the regtest harness.
pub struct NoOpJdpHooks;

#[async_trait]
impl JdpAllocateResolver for NoOpJdpHooks {
    async fn resolve_allocate_context(
        &self,
        user_identifier: &str,
        _remote_addr: &str,
    ) -> Option<AllocateTokenContext> {
        // Pure parse — no IP fallback. Production wiring overrides.
        parse_user_identifier_as_address(user_identifier).map(|addr| AllocateTokenContext {
            miner_address: addr,
            coinbase_outputs: vec![0u8],
        })
    }
}

#[async_trait]
impl TemplateTxProvider for NoOpJdpHooks {
    async fn snapshot(&self) -> HashMap<[u8; 32], Vec<u8>> {
        HashMap::new()
    }
}

#[async_trait]
impl CurrentPrevHashProvider for NoOpJdpHooks {
    async fn current_prev_hash(&self) -> Option<[u8; 32]> {
        None
    }
}

#[async_trait]
impl JdpBlockSubmissionSink for NoOpJdpHooks {
    async fn submit_block_candidate(
        &self,
        _: AddressId,
        _: Token,
        _: Vec<u8>,
        _: Vec<Vec<u8>>,
        _: [u8; 32],
        _: u32,
        _: u32,
        _: u32,
        _: u32,
    ) {
    }
}

#[async_trait]
impl PayoutOutputsResolver for NoOpJdpHooks {
    async fn resolve_payout_outputs(
        &self,
        miner_address: &AddressId,
        committed_outputs: &[u8],
        _available_payout_value: u64,
        request_id: u32,
    ) -> crate::jdp::client::PayoutOutputsResolution {
        // Echo the token-time committed bytes verbatim — trivially
        // satisfies the size invariant without needing a
        // `bitcoin::Network` context to re-encode. Production wiring
        // re-scales the values to `available_payout_value`.
        let _ = miner_address;
        crate::jdp::client::PayoutOutputsResolution::Success {
            request_id,
            outputs: committed_outputs.to_vec(),
        }
    }
}

// ── StratumV2JdpServer ──────────────────────────────────────────────

#[derive(Clone)]
pub struct StratumV2JdpServer {
    inner: Arc<Inner>,
}

struct Inner {
    // Carried for future production wiring (pool_identifier, network,
    // shutdown_drain_timeout). Currently only the cancel-token is
    // consumed; suppress the dead-code warning explicitly.
    #[allow(dead_code)]
    server_config: Arc<ServerConfig>,
    noise_config: NoiseConfig,
    hooks: JdpServerHooks,
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    cancel: CancellationToken,
    next_session_id: Mutex<u32>,
}

impl StratumV2JdpServer {
    pub fn spawn(
        server_config: ServerConfig,
        noise_config: NoiseConfig,
        hooks: JdpServerHooks,
        bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                server_config: Arc::new(server_config),
                noise_config,
                hooks,
                bridge,
                cancel: CancellationToken::new(),
                next_session_id: Mutex::new(1),
            }),
        }
    }

    /// Per-connection task. The TCP-accept loop calls this for
    /// each socket identified as JDP by `bp_protocol_detect`.
    pub fn accept_connection(&self, socket: TcpStream, remote_addr: String) -> JoinHandle<()> {
        let noise_config = self.inner.noise_config.clone();
        let hooks = self.inner.hooks.clone();
        let bridge = self.inner.bridge.clone();
        let cancel = self.inner.cancel.clone();
        let session_id = self.alloc_session_id();
        tokio::spawn(async move {
            let res = run_jdp_connection(
                session_id,
                noise_config,
                hooks,
                bridge,
                socket,
                remote_addr,
                cancel,
            )
            .await;
            if let Err(err) = res {
                debug!("jdp connection ended: {err}");
            }
        })
    }

    pub async fn shutdown(&self) {
        self.inner.cancel.cancel();
    }

    fn alloc_session_id(&self) -> u32 {
        let mut g = self.inner.next_session_id.lock().expect("poisoned");
        let id = *g;
        *g = g.wrapping_add(1).max(1);
        id
    }
}

// ── Per-connection task ─────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn run_jdp_connection(
    session_id: u32,
    noise_config: NoiseConfig,
    hooks: JdpServerHooks,
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    socket: TcpStream,
    remote_addr: String,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let session_id_hex = format!("jdp-{session_id:08x}");

    let noise = match accept_pool_noise::<AnyMessage<'static>>(socket, &noise_config).await {
        Ok(n) => n,
        Err(err) => {
            debug!("jdp {session_id_hex} noise handshake failed: {err:?}");
            return Ok(());
        }
    };
    let (mut reader, mut writer) = noise.into_split();

    let mut state = JdpSessionState::new(session_id);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            frame_recv = reader.read_frame() => {
                let frame = match frame_recv {
                    Ok(f) => f,
                    Err(err) => {
                        debug!("jdp {session_id_hex} read_frame: {err:?}");
                        break;
                    }
                };
                let mut sv2_frame = match frame {
                    Frame::Sv2(f) => f,
                    Frame::HandShake(_) => {
                        warn!("jdp {session_id_hex} unexpected HandShakeFrame post-setup");
                        continue;
                    }
                };
                let header = match sv2_frame.get_header() {
                    Some(h) => h,
                    None => {
                        warn!("jdp {session_id_hex} frame missing header");
                        continue;
                    }
                };
                // ext 0x0003 (Non-Custodial Pool Payouts) frames are NOT
                // in `stratum-core::AnyMessage`. Pre-decode here via
                // the raw-bytes path before the AnyMessage parser
                // (which would error on the unknown extension_type).
                let ext_type = header.ext_type_without_channel_msg();
                let msg_type = header.msg_type();
                let inbound = if ext_type == 0x0003 {
                    let payload_copy = sv2_frame.payload().to_vec();
                    match decode_jdp_inbound_ext_0x0003(ext_type, msg_type, &payload_copy) {
                        Ok(Some(f)) => f,
                        Ok(None) => {
                            debug!(
                                "jdp {session_id_hex} ext 0x0003 unhandled msg_type 0x{msg_type:02x}"
                            );
                            continue;
                        }
                        Err(err) => {
                            warn!("jdp {session_id_hex} ext 0x0003 decode: {err}");
                            continue;
                        }
                    }
                } else {
                    let negotiated: Vec<u16> =
                        state.negotiated_extensions.iter().copied().collect();
                    let (any_message, _tlvs) = match parse_message_frame_with_tlvs(
                        header,
                        sv2_frame.payload(),
                        &negotiated,
                    ) {
                        Ok(parsed) => parsed,
                        Err(err) => {
                            warn!("jdp {session_id_hex} parse: {err:?}");
                            continue;
                        }
                    };
                    match decode_jdp_inbound(any_message) {
                        Ok(Some(f)) => f,
                        Ok(None) => {
                            debug!("jdp {session_id_hex} non-JDP frame, ignoring");
                            continue;
                        }
                        Err(err) => {
                            warn!("jdp {session_id_hex} decode: {err}");
                            continue;
                        }
                    }
                };
                // Silence unused-import lint on the message-type
                // constant — referenced symbolically in error logs only.
                let _ = EXT_0X0003_MSG_TYPE_REQUEST_PAYOUT_OUTPUTS;
                let outcome = dispatch_jdp_inbound(
                    &mut state,
                    inbound,
                    &hooks,
                    &remote_addr,
                    now_ms(),
                )
                .await;
                if let Err(err) = write_jdp_outbound_frames(&mut writer, outcome.outbound).await {
                    warn!("jdp {session_id_hex} write: {err:?}");
                    break;
                }
                // Register declared jobs in the bridge BEFORE
                // fan_out_events: the bridge gives the mining-server
                // its SetCustomMiningJob lookup, so it must be
                // populated by the time the JobDeclared event is
                // visible to other hooks.
                register_declared_jobs_in_bridge(
                    &state,
                    &bridge,
                    session_id,
                    now_ms(),
                    &outcome.events,
                );
                fan_out_events(outcome.events, &session_id, &bridge, &hooks, now_ms()).await;
            }
        }
    }

    // On disconnect: evict all of this JDP-session's bridge entries so
    // the mining server doesn't keep stale `RegisteredDeclaredJob`s.
    let evicted = bridge
        .write()
        .expect("bridge RwLock poisoned")
        .evict_for_jdp_session(session_id);
    if evicted > 0 {
        debug!("jdp {session_id_hex} disconnect evicted {evicted} declared jobs from bridge");
    }
    let _ = writer.shutdown().await;
    Ok(())
}

/// Dispatch one inbound JDP frame to the matching `handle_*` function.
/// Resolves async-hook context per-variant before calling the (sync)
/// handler.
async fn dispatch_jdp_inbound(
    state: &mut JdpSessionState,
    inbound: InboundJdpFrame,
    hooks: &JdpServerHooks,
    remote_addr: &str,
    now_ms: u64,
) -> JdpHandlerOutcome {
    match inbound {
        InboundJdpFrame::SetupConnection(input) => handle_setup_connection(state, &input),
        InboundJdpFrame::RequestExtensions(input) => handle_request_extensions(state, &input),
        InboundJdpFrame::AllocateMiningJobToken(input) => {
            let Some(ctx) = hooks
                .allocate_resolver
                .resolve_allocate_context(&input.user_identifier, remote_addr)
                .await
            else {
                // Couldn't resolve a miner address — drop silently
                // (return default outcome, no error frame).
                return JdpHandlerOutcome::default();
            };
            handle_allocate_token(state, &input, ctx, now_ms)
        }
        InboundJdpFrame::DeclareMiningJob(input) => {
            let template_txs = hooks.template_tx_provider.snapshot().await;
            let current_prev_hash = hooks.prev_hash_provider.current_prev_hash().await;
            handle_declare_mining_job(state, &input, &template_txs, current_prev_hash, now_ms)
        }
        InboundJdpFrame::ProvideMissingTransactionsSuccess(input) => {
            let current_prev_hash = hooks.prev_hash_provider.current_prev_hash().await;
            handle_provide_missing_transactions_success(state, &input, current_prev_hash, now_ms)
        }
        InboundJdpFrame::PushSolution(input) => {
            // The miner_address is bound to the declared job's
            // RegisteredDeclaredJob in the bridge; but the
            // push-solution handler accepts it as an argument
            // because the JDP-session itself doesn't carry the
            // address (multi-token-per-connection means different
            // pushes might map to different addresses, but in
            // practice one connection = one miner). Lookup via the
            // declared_jobs store (already has prev_hash matching).
            let miner_address = state
                .declared_jobs
                .match_for_solution(&input.prev_hash)
                .map(|j| j.new_token)
                .and_then(|token| state.tokens.lookup(&token).map(|a| a.miner_address.clone()))
                .unwrap_or_else(|| {
                    AddressId::new("unknown".to_string()).unwrap_or_else(|_| {
                        // AddressId::new requires non-empty + valid
                        // chars; "unknown" passes. Defensive fallback.
                        AddressId::new("u".to_string()).expect("'u' is a valid AddressId")
                    })
                });
            handle_push_solution(state, &input, miner_address)
        }
        InboundJdpFrame::RequestPayoutOutputs(input) => {
            // Look up the miner_address bound to this token so the
            // resolver can route through the mode-gate. If the token
            // is unknown the pure-logic handler returns the
            // `invalid-mining-job-token` wire error directly — we
            // bridge by feeding it a Success-shaped resolution it will
            // never use (the handler short-circuits on the token miss).
            let token_ctx = state
                .tokens
                .lookup_active(&input.mining_job_token, now_ms)
                .map(|a| (a.miner_address.clone(), a.coinbase_outputs.clone()));
            let resolution = match token_ctx {
                Some((addr, committed_outputs)) => {
                    hooks
                        .payout_outputs_resolver
                        .resolve_payout_outputs(
                            &addr,
                            &committed_outputs,
                            input.available_payout_value,
                            input.request_id,
                        )
                        .await
                }
                None => {
                    // Stub; the handler's token-existence check fires
                    // first and emits `invalid-mining-job-token`.
                    crate::jdp::client::PayoutOutputsResolution::Error {
                        request_id: input.request_id,
                        error_code:
                            crate::extensions::payout_outputs_error_codes::INVALID_MINING_JOB_TOKEN
                                .to_string(),
                    }
                }
            };
            // The pool's own chain-tip view stamps the issued set's
            // epoch (NOT a wire field) so a later tip advance flags it
            // stale at declare-time (spec §4 freshness is validator-side).
            let current_prev_hash = hooks.prev_hash_provider.current_prev_hash().await;
            handle_request_payout_outputs(state, &input, resolution, current_prev_hash, now_ms)
        }
    }
}

/// Fan out [`JdpSessionEvent`]s: TokenAllocated is informational,
/// JobDeclared registers in the bridge for the mining server's
/// SetCustomMiningJob lookup, BlockSubmissionCandidate goes to the
/// block-submission sink, Disconnect closes the connection (caller
/// handles via the cancel-token path).
async fn fan_out_events(
    events: Vec<JdpSessionEvent>,
    jdp_session_id: &u32,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    hooks: &JdpServerHooks,
    now_ms: u64,
) {
    for event in events {
        match event {
            JdpSessionEvent::SetupComplete { .. } => {}
            JdpSessionEvent::TokenAllocated { .. } => {}
            // Bridge bookkeeping only — handled in
            // `register_declared_jobs_in_bridge`, nothing to fan out.
            JdpSessionEvent::PayoutOutputsIssued { .. } => {}
            JdpSessionEvent::JobDeclared {
                new_token,
                original_token,
                miner_address,
                prev_hash,
            } => {
                // Pull the full DeclaredJob out of the session store
                // so the bridge entry carries the complete payload
                // for the mining-side SetCustomMiningJob handler.
                // We can't read the session here (we don't have it),
                // so we register a stub and rely on the mining-handler
                // to consult the bridge for cross-check only. For
                // full data, the IO-layer needs to thread the
                // session-state reference through; deferred.
                let _ = (
                    new_token,
                    original_token,
                    miner_address,
                    prev_hash,
                    bridge,
                    jdp_session_id,
                    now_ms,
                );
                // Note: full bridge.register requires the DeclaredJob
                // payload from `state.declared_jobs[new_token]`. This
                // is doable but requires either an `Arc<Mutex>` on
                // the session state or threading the registration
                // back into `run_jdp_connection`'s scope. For now:
                // bridge registration happens inline in
                // `run_jdp_connection` via `register_declared_job`
                // (see below) — events fan-out only logs.
            }
            JdpSessionEvent::BlockSubmissionCandidate {
                miner_address,
                new_token,
                coinbase_raw,
                transactions,
                prev_hash,
                version,
                ntime,
                nonce,
                n_bits,
            } => {
                hooks
                    .block_submission_sink
                    .submit_block_candidate(
                        miner_address,
                        new_token,
                        coinbase_raw,
                        transactions,
                        prev_hash,
                        version,
                        ntime,
                        nonce,
                        n_bits,
                    )
                    .await;
            }
            JdpSessionEvent::Disconnect { .. } => {
                // Disconnect signal — connection-task break-condition.
                // The select-loop already broke once we hit this; no
                // additional action.
            }
        }
    }
}

/// Serialise + write each [`JdpOutboundFrame`] through the noise
/// stream. Same pattern as `server::write_outbound_frames`. ext 0x0003
/// frames (RequestPayoutOutputs Success/Error) take the manual raw-bytes
/// path below (they're not in `AnyMessage`); all other frames go through
/// `encode_jdp_outbound`.
async fn write_jdp_outbound_frames(
    writer: &mut NoiseTcpWriteHalf<AnyMessage<'static>>,
    outbound: Vec<JdpOutboundFrame>,
) -> Result<(), WriteError> {
    for frame in outbound {
        // ext 0x0003 (Non-Custodial Pool Payouts) frames take the
        // raw-bytes path — they're not in `AnyMessage`. Build the SV2
        // frame manually: 6-byte header (ext_type LE16 + msg_type +
        // msg_length LE24) + payload.
        if let Some((msg_type, payload)) = encode_jdp_outbound_ext_0x0003(&frame) {
            let mut bytes = Vec::with_capacity(6 + payload.len());
            // ext_type = 0x0003 LE
            bytes.extend_from_slice(&0x0003u16.to_le_bytes());
            bytes.push(msg_type);
            // msg_length = payload.len() as LE U24 (3 bytes)
            let msg_len = payload.len() as u32;
            if msg_len > 0x00FF_FFFF {
                return Err(WriteError::Codec(CodecError::Conversion(format!(
                    "ext 0x0003 payload too large: {} bytes (max 16M-1)",
                    payload.len()
                ))));
            }
            bytes.push((msg_len & 0xFF) as u8);
            bytes.push(((msg_len >> 8) & 0xFF) as u8);
            bytes.push(((msg_len >> 16) & 0xFF) as u8);
            bytes.extend_from_slice(&payload);

            // Sv2Frame::from_bytes_unchecked wraps pre-serialised
            // bytes; the phantom `AnyMessage` type isn't actually
            // touched because `serialized = Some(...)` short-circuits
            // the encoder.
            let sv2_frame: StandardSv2Frame<AnyMessage<'static>> =
                StandardSv2Frame::from_bytes_unchecked(bytes.into());
            writer
                .write_frame(Frame::Sv2(sv2_frame))
                .await
                .map_err(WriteError::Io)?;
            continue;
        }

        let any_message = match encode_jdp_outbound(frame) {
            Ok(m) => m,
            Err(CodecError::EncodeUnimplemented(what)) => {
                debug!("jdp write: skipping unimplemented frame ({what})");
                continue;
            }
            Err(e) => return Err(WriteError::Codec(e)),
        };
        let sv2_frame: StandardSv2Frame<AnyMessage<'static>> =
            any_message
                .try_into()
                .map_err(|e: stratum_core::parsers_sv2::ParserError| {
                    WriteError::Codec(CodecError::Conversion(format!("{e:?}")))
                })?;
        writer
            .write_frame(Frame::Sv2(sv2_frame))
            .await
            .map_err(WriteError::Io)?;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    #[error("noise io: {0:?}")]
    Io(crate::noise::NoiseError),
}

/// Register the latest declared job in the bridge so the mining
/// server's `SetCustomMiningJob` handler can find it. Called from
/// the per-connection task after `dispatch_jdp_inbound` returns —
/// at that point `state.declared_jobs` has the fresh entry keyed by
/// `new_token` (the handler's accept-path inserted it).
///
/// Public-`pub(crate)` so unit tests can drive it without spinning
/// up a real connection.
pub(crate) fn register_declared_jobs_in_bridge(
    state: &JdpSessionState,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    jdp_session_id: u32,
    now_ms: u64,
    events: &[JdpSessionEvent],
) {
    let mut reg = bridge.write().expect("bridge RwLock poisoned");
    for event in events {
        match event {
            JdpSessionEvent::PayoutOutputsIssued {
                token,
                outputs,
                miner_address,
                issued_prev_hash,
            } => {
                // ext 0x0003: record the committed payout set so the mining
                // server can validate + single-use-consume the JDC's
                // SetCustomMiningJob coinbase against it (both JD modes), and
                // reject it as stale if the job's tip has moved on.
                reg.register_payout_set(
                    *token,
                    IssuedPayoutSet {
                        outputs: outputs.clone(),
                        miner_address: miner_address.clone(),
                        jdp_session_id,
                        registered_at_ms: now_ms,
                        issued_prev_hash: *issued_prev_hash,
                        used: false,
                    },
                );
            }
            JdpSessionEvent::JobDeclared {
                new_token,
                original_token,
                miner_address,
                ..
            } => {
                if let Some(declared_job) = state.declared_jobs.get(new_token) {
                    reg.register(
                        *new_token,
                        RegisteredDeclaredJob {
                            declared_job: declared_job.clone(),
                            miner_address: miner_address.clone(),
                            jdp_session_id,
                            registered_at_ms: now_ms,
                        },
                    );
                }
                // Full-Template: re-key the payout set issued under the
                // allocation token to the new mining-job token, so the JDC's
                // SetCustomMiningJob (which carries the new token) resolves it.
                reg.rekey_payout_set(original_token, new_token);
            }
            _ => {}
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── Public re-export for the IO-layer wire-up ───────────────────────

/// Drain timeout placeholder — re-exported to match
/// `ServerConfig::shutdown_drain_timeout` semantics. Not yet wired:
/// `StratumV2JdpServer::shutdown` is fire-and-forget for now (the
/// cancel-token causes all per-connection tasks to exit on their
/// next select tick).
pub const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jdp::client::AllocateMiningJobTokenInput;
    use bitcoin::Network;

    const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    fn noise_cfg() -> NoiseConfig {
        NoiseConfig::parse_strings(
            "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72",
            "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n",
            crate::noise::DEFAULT_CERT_VALIDITY,
        )
        .unwrap()
    }

    fn fresh_bridge() -> Arc<RwLock<JdpDeclaredJobRegistry>> {
        Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()))
    }

    fn fresh_session() -> JdpSessionState {
        let mut s = JdpSessionState::new(1);
        // Deterministic RNG so allocated tokens are predictable.
        s.set_token_rng(Some(Box::new(|buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = 0;
            }
            Ok(())
        })));
        s
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_handle_is_cloneable_and_shutdown_idempotent() {
        let bridge = fresh_bridge();
        let server = StratumV2JdpServer::spawn(
            ServerConfig::defaults_for(Network::Regtest),
            noise_cfg(),
            JdpServerHooks::no_op(),
            bridge,
        );
        let _clone = server.clone();
        server.shutdown().await;
        server.shutdown().await; // idempotent
    }

    #[tokio::test(flavor = "current_thread")]
    async fn allocate_session_ids_monotonic_per_handle() {
        let bridge = fresh_bridge();
        let server = StratumV2JdpServer::spawn(
            ServerConfig::defaults_for(Network::Regtest),
            noise_cfg(),
            JdpServerHooks::no_op(),
            bridge,
        );
        assert_eq!(server.alloc_session_id(), 1);
        assert_eq!(server.alloc_session_id(), 2);
        assert_eq!(server.alloc_session_id(), 3);
        server.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_op_allocate_resolver_parses_user_identifier_as_address() {
        let hooks = NoOpJdpHooks;
        let ctx = hooks.resolve_allocate_context(ADDR, "1.2.3.4:1234").await;
        assert!(ctx.is_some());
        assert_eq!(ctx.unwrap().miner_address.as_str(), ADDR);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_op_allocate_resolver_rejects_garbage_user_identifier() {
        let hooks = NoOpJdpHooks;
        let ctx = hooks
            .resolve_allocate_context(&"x".repeat(200), "1.2.3.4:1234")
            .await;
        assert!(ctx.is_none(), "garbage user-identifier yields None");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dispatch_allocate_token_emits_success_with_resolver() {
        let mut state = fresh_session();
        // Need setup_complete first.
        let setup_input = crate::jdp::client::SetupConnectionInput {
            protocol: crate::jdp::client::PROTOCOL_JOB_DECLARATION,
            min_version: 2,
            max_version: 2,
            flags: crate::jdp::client::FLAG_DECLARE_TX_DATA,
            vendor: "v".to_string(),
            firmware: "f".to_string(),
            hardware_version: "h".to_string(),
            device_id: "d".to_string(),
        };
        let _ = handle_setup_connection(&mut state, &setup_input);
        let hooks = JdpServerHooks::no_op();
        let outcome = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::AllocateMiningJobToken(AllocateMiningJobTokenInput {
                request_id: 7,
                user_identifier: ADDR.to_string(),
            }),
            &hooks,
            "1.2.3.4:5555",
            1_000,
        )
        .await;
        match &outcome.outbound[0] {
            JdpOutboundFrame::AllocateMiningJobTokenSuccess {
                request_id,
                mining_job_token: _,
                coinbase_outputs,
            } => {
                assert_eq!(*request_id, 7);
                assert_eq!(coinbase_outputs.as_slice(), &[0u8]);
            }
            _ => panic!("expected AllocateMiningJobTokenSuccess"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dispatch_setup_connection_emits_success() {
        let mut state = fresh_session();
        let hooks = JdpServerHooks::no_op();
        let outcome = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::SetupConnection(crate::jdp::client::SetupConnectionInput {
                protocol: crate::jdp::client::PROTOCOL_JOB_DECLARATION,
                min_version: 2,
                max_version: 2,
                flags: 1,
                vendor: "v".to_string(),
                firmware: "f".to_string(),
                hardware_version: "h".to_string(),
                device_id: "d".to_string(),
            }),
            &hooks,
            "1.2.3.4:5555",
            0,
        )
        .await;
        assert!(matches!(
            outcome.outbound[0],
            JdpOutboundFrame::SetupConnectionSuccess { .. }
        ));
        assert!(state.setup_complete);
    }

    /// `register_declared_jobs_in_bridge` pulls the declared-job
    /// payload out of the session state and writes a
    /// `RegisteredDeclaredJob` into the cross-server bridge.
    #[tokio::test(flavor = "current_thread")]
    async fn register_declared_jobs_in_bridge_pushes_to_registry() {
        use crate::jdp::declarations::DeclaredJob;
        let mut state = fresh_session();
        let token = Token([0xAA; 16]);
        let job = DeclaredJob {
            new_token: token,
            original_token: Token([0xBB; 16]),
            request_id: 1,
            version: 0,
            coinbase_tx_prefix: vec![],
            coinbase_tx_suffix: vec![],
            wtxid_list: vec![],
            raw_transactions: HashMap::new(),
            prev_hash: Some([0xCC; 32]),
            declared_at_ms: 500,
        };
        state.declared_jobs.insert(job);
        let bridge = fresh_bridge();
        let events = vec![JdpSessionEvent::JobDeclared {
            new_token: token,
            original_token: Token([0xBB; 16]),
            miner_address: AddressId::new(ADDR.to_string()).unwrap(),
            prev_hash: Some([0xCC; 32]),
        }];
        register_declared_jobs_in_bridge(&state, &bridge, 42, 1_000, &events);
        let r = bridge.read().unwrap();
        let entry = r.lookup(&token).expect("must be registered");
        assert_eq!(entry.jdp_session_id, 42);
        assert_eq!(entry.miner_address.as_str(), ADDR);
        assert_eq!(entry.declared_job.prev_hash, Some([0xCC; 32]));
    }

    /// A `PayoutOutputsIssued` event registers the committed set in the
    /// shared bridge under the allocation token; a later `JobDeclared`
    /// re-keys it to the new mining-job token, so a Full-Template
    /// `SetCustomMiningJob` (which carries the new token) resolves it.
    #[tokio::test(flavor = "current_thread")]
    async fn payout_set_registered_then_rekeyed_on_job_declared() {
        use crate::jdp::declarations::DeclaredJob;
        let mut state = fresh_session();
        let alloc_token = Token([0xBB; 16]);
        let new_token = Token([0xAA; 16]);
        let bridge = fresh_bridge();

        // RequestPayoutOutputs.Success → PayoutOutputsIssued (alloc token).
        let issued = vec![JdpSessionEvent::PayoutOutputsIssued {
            token: alloc_token,
            outputs: vec![0x01, 0x02, 0x03],
            miner_address: AddressId::new(ADDR.to_string()).unwrap(),
            issued_prev_hash: Some([0xCC; 32]),
        }];
        register_declared_jobs_in_bridge(&state, &bridge, 42, 1_000, &issued);
        assert!(bridge
            .read()
            .unwrap()
            .lookup_payout_set(&alloc_token)
            .is_some());

        // DeclareMiningJob.Success → register declared job + re-key the set.
        state.declared_jobs.insert(DeclaredJob {
            new_token,
            original_token: alloc_token,
            request_id: 1,
            version: 0,
            coinbase_tx_prefix: vec![],
            coinbase_tx_suffix: vec![],
            wtxid_list: vec![],
            raw_transactions: HashMap::new(),
            prev_hash: Some([0xCC; 32]),
            declared_at_ms: 500,
        });
        let declared = vec![JdpSessionEvent::JobDeclared {
            new_token,
            original_token: alloc_token,
            miner_address: AddressId::new(ADDR.to_string()).unwrap(),
            prev_hash: Some([0xCC; 32]),
        }];
        register_declared_jobs_in_bridge(&state, &bridge, 42, 2_000, &declared);
        let r = bridge.read().unwrap();
        assert!(
            r.lookup_payout_set(&alloc_token).is_none(),
            "re-keyed away from the allocation token"
        );
        assert!(
            r.lookup_payout_set(&new_token).is_some(),
            "now resolvable under the new mining-job token"
        );
        assert!(
            r.lookup(&new_token).is_some(),
            "declared job registered too"
        );
    }
}
