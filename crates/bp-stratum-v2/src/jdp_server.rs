// SPDX-License-Identifier: AGPL-3.0-or-later

//! JDP-port server: handle + per-connection task. No template broadcast and no
//! vardiff; each accepted `DeclareMiningJob` is registered in the bridge so the
//! mining server's `SetCustomMiningJob` handler can cross-check the token.
//!
//! - ext 0x0003 is push-only: `SetPayoutDistribution` goes out as a raw frame
//!   right after `RequestExtensions.Success`, then on every publish.
//! - Declared payouts are compared positionally against the distribution the
//!   `distribution_id` TLV names (ext 0x0003/Output Verification).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use bp_common::AddressId;
use bp_vardiff::{Clock, SystemClock};
use stratum_core::job_declaration_sv2::MESSAGE_TYPE_DECLARE_MINING_JOB;
use stratum_core::parsers_sv2::parse_message_frame_with_tlvs;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::bridge::{
    AllocatedTokenRef, AllocationKind, DistributionAcceptance, DistributionAccounting,
    DistributionScope, JdpDeclaredJobRegistry, PayoutDistributionEntry, RegisteredDeclaredJob,
};
use crate::codec_common::{write_message, write_raw_frame, WriteError};
use crate::extensions::{
    parse_distribution_id_tlv, SetPayoutDistribution, SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS,
};
use crate::jdp::client::{
    declare_refused_by_session, handle_allocate_token, handle_declare_mining_job,
    handle_provide_missing_transactions_success, handle_push_solution, handle_request_extensions,
    handle_setup_connection, parse_user_identifier_as_address, AllocateTokenContext,
    DeclarationContext, DeclarationRef, JdpHandlerOutcome, JdpOutboundFrame, JdpSessionEvent,
    JdpSessionState, SolutionHeader,
};
use crate::jdp::dynamic_outputs::CandidateBacking;
use crate::jdp::tx_validation::{merge_provided_with_known, partition_against_template};
use crate::jdp_server_codec::{
    decode_jdp_inbound, encode_jdp_outbound, InboundJdpFrame, JdpWireFrame,
};
use crate::noise::{accept_pool_noise, NoiseConfig, NoiseTcpWriteHalf};

// ── JDP-server hooks ────────────────────────────────────────────────

/// Resolve `(miner_address, encoded_coinbase_outputs)` for an inbound
/// `AllocateMiningJobToken`.
#[async_trait]
pub trait JdpAllocateResolver: Send + Sync {
    /// With ext 0x0003 negotiated, ext 0x0003/Negotiation REQUIRES empty
    /// `coinbase_tx_outputs`.
    async fn resolve_allocate_context(
        &self,
        user_identifier: &str,
        payout_distribution_negotiated: bool,
    ) -> AllocateOutcome;
}

/// What the pool does with an `AllocateMiningJobToken`. SV2 gives it no error
/// message, so refusing means closing the connection.
pub enum AllocateOutcome {
    Granted(AllocateTokenContext),
    /// Close the connection, so the JDC's fallback (SV2 JDP/Job Declarator
    /// Client) fires immediately instead of after a timeout.
    Refused {
        reason: &'static str,
    },
    /// Nothing resolvable (unparseable `user_identifier`); dropped silently.
    Ignored,
}

/// The pool's template-tx cache (`wtxid → raw_tx`); an empty map makes the
/// handler request every tx via `ProvideMissingTransactions`.
#[async_trait]
pub trait TemplateTxProvider: Send + Sync {
    async fn snapshot(&self) -> HashMap<[u8; 32], Vec<u8>>;
}

/// The pool's current `prev_hash`, stamped on declared jobs for `PushSolution`.
#[async_trait]
pub trait CurrentPrevHashProvider: Send + Sync {
    async fn current_prev_hash(&self) -> Option<[u8; 32]>;
}

use crate::bridge::BuiltPayoutDistribution;

/// Floor the publish interval at 1s: `tokio::time::interval` panics on zero,
/// which in the detached publisher would silently stop all publishing.
fn sane_publish_interval(interval: Duration) -> Duration {
    if interval.is_zero() {
        warn!(
            "jdp: payout-distribution interval of 0 is not a valid period — using 1s. \
             Set [sv2].jdp_payout_distribution_interval_secs to a positive value."
        );
        return Duration::from_secs(1);
    }
    interval
}

/// What the pool can publish for one JDP session's miner. PPLNS gets
/// `PoolWide`, Solo and Group-Solo `Built`, Blockparty `Unavailable` (not
/// offered over JDP). A failed tailored build must never fall back to
/// `PoolWide`, or a Solo / Group-Solo block would pay the PPLNS window.
#[derive(Debug)]
pub enum TailoredDistribution {
    PoolWide,
    /// The accounting travels with the build: Solo and Group-Solo pay the same
    /// address differently.
    Built {
        accounting: DistributionAccounting,
        built: Box<BuiltPayoutDistribution>,
    },
    /// Build failed; the session is served nothing until a later build succeeds.
    Unavailable,
    /// Mode not known yet (normal at JDC startup, before its mining channel
    /// exists); the caller retries. Guessing is a money error either way.
    ModeUnknown,
}

/// Builds the pool's payout distributions for the ext 0x0003 push model.
#[async_trait]
pub trait PayoutDistributionSource: Send + Sync {
    /// `None` ⇒ nothing publishable yet; ext 0x0003 is then not offered.
    async fn build_pool_wide(&self) -> Option<BuiltPayoutDistribution>;
    /// `PoolWide` and `Unavailable` are NOT interchangeable.
    async fn build_for_miner(&self, miner_address: &AddressId) -> TailoredDistribution;
    /// The address's accounting right now, building nothing; `None` without a
    /// live mining session. Cheap enough to re-check per inbound frame.
    async fn current_mode(&self, miner_address: &AddressId) -> Option<bp_common::StreamKind>;
    /// Strictly increasing, pool-global id; `None` skips the publish.
    async fn next_distribution_id(&self) -> Option<u64>;
}

/// Block-submission sink for `PushSolution` candidates.
#[async_trait]
pub trait JdpBlockSubmissionSink: Send + Sync {
    async fn submit_block_candidate(
        &self,
        miner_address: AddressId,
        declaration: DeclarationRef,
        backing: CandidateBacking,
        coinbase_raw: Vec<u8>,
        transactions: Vec<Vec<u8>>,
        header: SolutionHeader,
    );
}

/// `position → raw_tx` flattened into declaration order.
fn ordered_raw_txs(by_position: &std::collections::HashMap<u32, Vec<u8>>) -> Vec<Vec<u8>> {
    let mut positions: Vec<&u32> = by_position.keys().collect();
    positions.sort_unstable();
    positions
        .into_iter()
        .filter_map(|p| by_position.get(p).cloned())
        .collect()
}

/// Hands a declared job to a Bitcoin node for a verdict (SV2 JDP/Job
/// Declarator Server). `None` in [`JdpServerHooks::job_validator`] trusts the JDC.
#[async_trait]
pub trait DeclaredJobValidator: Send + Sync {
    async fn validate_declaration(&self, job: DeclaredJobToValidate<'_>) -> JobVerdict;

    /// Drop whatever the validator keeps for this session.
    fn session_closed(&self, session_id: u32);
}

/// One declared job, in the shape a node-side validator needs.
pub struct DeclaredJobToValidate<'a> {
    /// The validator keeps per-session state; must be the declaring connection.
    pub session_id: u32,
    pub version: u32,
    pub coinbase_tx_prefix: &'a [u8],
    pub coinbase_tx_suffix: &'a [u8],
    /// Declaration order, wire byte order.
    pub wtxid_list: &'a [[u8; 32]],
    /// Raw txs the pool can supply; the node reports what it still misses.
    pub known_raw_txs: &'a [Vec<u8>],
    pub leg: DeclarationLeg,
}

#[derive(Debug)]
pub enum JobVerdict {
    Accepted,
    /// Carries the SV2 error code for `DeclareMiningJob.Error`.
    Rejected(String),
    /// Not a rejection on the declare leg (`ProvideMissingTransactions` fetches
    /// them); `missing-txs` on the second leg.
    NeedsTransactions,
}

#[derive(Clone)]
pub struct JdpServerHooks {
    pub allocate_resolver: Arc<dyn JdpAllocateResolver>,
    pub template_tx_provider: Arc<dyn TemplateTxProvider>,
    pub prev_hash_provider: Arc<dyn CurrentPrevHashProvider>,
    pub block_submission_sink: Arc<dyn JdpBlockSubmissionSink>,
    pub distribution_source: Arc<dyn PayoutDistributionSource>,
    /// `None` → every declaration is accepted on the JDC's word.
    pub job_validator: Option<Arc<dyn DeclaredJobValidator>>,
}

impl JdpServerHooks {
    pub fn no_op() -> Self {
        let n: Arc<NoOpJdpHooks> = Arc::new(NoOpJdpHooks);
        Self {
            allocate_resolver: n.clone(),
            template_tx_provider: n.clone(),
            prev_hash_provider: n.clone(),
            block_submission_sink: n.clone(),
            distribution_source: n,
            job_validator: None,
        }
    }
}

/// No-op hooks for tests and the regtest harness.
pub struct NoOpJdpHooks;

#[async_trait]
impl JdpAllocateResolver for NoOpJdpHooks {
    async fn resolve_allocate_context(
        &self,
        user_identifier: &str,
        payout_distribution_negotiated: bool,
    ) -> AllocateOutcome {
        let Some(addr) = parse_user_identifier_as_address(user_identifier) else {
            return AllocateOutcome::Ignored;
        };
        if payout_distribution_negotiated {
            return AllocateOutcome::Granted(AllocateTokenContext {
                miner_address: addr,
                coinbase_outputs: Vec::new(), // ext 0x0003/Negotiation MUST: empty under 0x0003
            });
        }
        // SV2 JDP/AllocateMiningJobToken.Success wants ONE designated 0-sat
        // output; empty would refuse every job. No network check: none configured.
        let Ok(parsed) = addr.as_str().parse::<bitcoin::Address<_>>() else {
            return AllocateOutcome::Ignored;
        };
        AllocateOutcome::Granted(AllocateTokenContext {
            miner_address: addr,
            coinbase_outputs: crate::jdp::dynamic_outputs::designated_output_blob(
                &parsed.assume_checked().script_pubkey(),
            ),
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
        _: DeclarationRef,
        _: CandidateBacking,
        _: Vec<u8>,
        _: Vec<Vec<u8>>,
        _: SolutionHeader,
    ) {
    }
}

#[async_trait]
impl PayoutDistributionSource for NoOpJdpHooks {
    async fn build_pool_wide(&self) -> Option<BuiltPayoutDistribution> {
        None
    }
    async fn build_for_miner(&self, _miner_address: &AddressId) -> TailoredDistribution {
        TailoredDistribution::PoolWide
    }
    async fn current_mode(&self, _miner_address: &AddressId) -> Option<bp_common::StreamKind> {
        None
    }
    async fn next_distribution_id(&self) -> Option<u64> {
        None
    }
}

// ── StratumV2JdpServer ──────────────────────────────────────────────

#[derive(Clone)]
pub struct StratumV2JdpServer {
    inner: Arc<Inner>,
}

struct Inner {
    noise_config: NoiseConfig,
    hooks: JdpServerHooks,
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    cancel: CancellationToken,
    next_session_id: Mutex<u32>,
    /// Latest pool-wide `distribution_id` published (0 = none yet); connections
    /// watch it to push the fresh distribution.
    dist_watch: tokio::sync::watch::Sender<u64>,
    /// Forces an immediate publish after a settlement.
    refresh: Arc<tokio::sync::Notify>,
}

/// Settlement hook (ext 0x0003/Implementation Notes): a booked block
/// invalidates every published distribution and forces a fresh publish.
#[derive(Clone)]
pub struct DistributionInvalidationHandle {
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    refresh: Arc<tokio::sync::Notify>,
}

impl DistributionInvalidationHandle {
    pub fn settle(&self) {
        self.bridge
            .write()
            .expect("bridge RwLock poisoned")
            .invalidate_all_distributions();
        self.refresh.notify_one();
    }
}

impl StratumV2JdpServer {
    pub fn spawn(
        noise_config: NoiseConfig,
        hooks: JdpServerHooks,
        bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
        payout_distribution_interval: Duration,
    ) -> Self {
        let (dist_watch, _) = tokio::sync::watch::channel(0u64);
        let server = Self {
            inner: Arc::new(Inner {
                noise_config,
                hooks,
                bridge,
                cancel: CancellationToken::new(),
                next_session_id: Mutex::new(1),
                dist_watch,
                refresh: Arc::new(tokio::sync::Notify::new()),
            }),
        };
        server.spawn_distribution_publisher(sane_publish_interval(payout_distribution_interval));
        server
    }

    /// The settlement hook for the block-booking sink.
    pub fn distribution_handle(&self) -> DistributionInvalidationHandle {
        DistributionInvalidationHandle {
            bridge: self.inner.bridge.clone(),
            refresh: self.inner.refresh.clone(),
        }
    }

    /// The pool-wide publisher (ext 0x0003/Update Policy). Skips a tick when
    /// the payouts fingerprint is unchanged, so a quiet window stays quiet.
    fn spawn_distribution_publisher(&self, interval: Duration) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last_fingerprint: Option<[u8; 32]> = None;
            // A forced pass that aborts MUST stay owed: after a settlement the
            // registry holds nothing, so "unchanged" would leave 0x0003 unoffered.
            let mut force_pending = false;
            loop {
                let forced = tokio::select! {
                    biased;
                    _ = inner.cancel.cancelled() => break,
                    _ = inner.refresh.notified() => true,
                    _ = tick.tick() => false,
                };
                force_pending |= forced;
                let Some(built) = inner.hooks.distribution_source.build_pool_wide().await else {
                    continue;
                };
                if !force_pending
                    && built.payouts_fingerprint.is_some()
                    && built.payouts_fingerprint == last_fingerprint
                {
                    continue;
                }
                let Some(distribution_id) =
                    inner.hooks.distribution_source.next_distribution_id().await
                else {
                    warn!("jdp publisher: distribution-id allocator unavailable — publish skipped");
                    continue;
                };
                last_fingerprint = built.payouts_fingerprint;
                let entry = PayoutDistributionEntry {
                    distribution_id,
                    built,
                    accounting: DistributionAccounting::PoolWide,
                    jdp_session_id: None,
                    published_at_ms: SystemClock.now_ms(),
                };
                inner
                    .bridge
                    .write()
                    .expect("bridge RwLock poisoned")
                    .publish_pool_wide(entry);
                force_pending = false;
                let _ = inner.dist_watch.send(distribution_id);
                debug!(
                    distribution_id,
                    "jdp publisher: pool-wide distribution published"
                );
            }
        });
    }

    /// Per-connection task for one accepted socket.
    pub fn accept_connection(&self, socket: TcpStream) -> JoinHandle<()> {
        let noise_config = self.inner.noise_config.clone();
        let hooks = self.inner.hooks.clone();
        let bridge = self.inner.bridge.clone();
        let cancel = self.inner.cancel.clone();
        let dist_rx = self.inner.dist_watch.subscribe();
        let session_id = self.alloc_session_id();
        tokio::spawn(async move {
            let res = run_jdp_connection(
                session_id,
                noise_config,
                hooks,
                bridge,
                socket,
                cancel,
                dist_rx,
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

mod payout_session;

#[allow(clippy::too_many_arguments)]
async fn run_jdp_connection(
    session_id: u32,
    noise_config: NoiseConfig,
    hooks: JdpServerHooks,
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    socket: TcpStream,
    cancel: CancellationToken,
    mut dist_rx: tokio::sync::watch::Receiver<u64>,
) -> std::io::Result<()> {
    let session_id_hex = format!("jdp-{session_id:08x}");

    let noise = match accept_pool_noise(socket, &noise_config).await {
        Ok(n) => n,
        Err(err) => {
            debug!("jdp {session_id_hex} noise handshake failed: {err:?}");
            return Ok(());
        }
    };
    let (mut reader, mut writer) = noise.into_split();

    let mut state = JdpSessionState::new(session_id);
    let mut payouts = payout_session::PayoutSession::new(session_id, &session_id_hex);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            changed = dist_rx.changed() => {
                if changed.is_err() {
                    break; // publisher gone = server shutting down
                }
                let negotiated = payout_session::negotiated(&state);
                let pushed = payouts.on_publish(negotiated, &hooks, &bridge, &mut writer).await;
                if pushed.is_err() {
                    break;
                }
            }
            frame_recv = reader.read_frame() => {
                let mut sv2_frame = match frame_recv {
                    Ok(f) => f,
                    Err(err) => {
                        debug!("jdp {session_id_hex} read_frame: {err:?}");
                        break;
                    }
                };
                let header = sv2_frame.header();
                let Some(tlv_extensions) = payouts.tlv_extensions(
                    &state,
                    header.ext_type_without_channel_msg(),
                    header.msg_type(),
                ) else {
                    continue;
                };
                let (any_message, tlvs) = match parse_message_frame_with_tlvs(
                    header,
                    sv2_frame.payload(),
                    &tlv_extensions,
                ) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        warn!("jdp {session_id_hex} parse: {err:?}");
                        continue;
                    }
                };
                let mut inbound = match decode_jdp_inbound(any_message) {
                    Ok(Some(f)) => f,
                    Ok(None) => {
                        debug!("jdp {session_id_hex} non-JDP frame, ignoring");
                        continue;
                    }
                    Err(err) => {
                        warn!("jdp {session_id_hex} decode: {err}");
                        continue;
                    }
                };
                payout_session::PayoutSession::attach_distribution_id(
                    &mut inbound,
                    tlvs.as_deref(),
                );
                let probe = payouts
                    .probe(payout_session::negotiated(&state), &inbound, &hooks)
                    .await;
                let mut outcome = dispatch_jdp_inbound(
                    &mut state,
                    inbound,
                    &hooks,
                    &bridge,
                    session_id,
                    SystemClock.now_ms(),
                )
                .await;
                payouts.append_first_push(&state, &bridge, &probe, &mut outcome);
                // SV2 Overview/SetupConnection.Error: the error goes out "prior
                // to closing the connection", so close only after the write.
                let disconnect = outcome.events.iter().find_map(|e| match e {
                    JdpSessionEvent::Disconnect { reason } => Some(reason.clone()),
                    _ => None,
                });
                // Register in the bridge BEFORE writing (and before
                // `fan_out_events`): once `DeclareMiningJobSuccess` is out, the
                // JDC's mining connection may send `SetCustomMiningJob`, and a
                // miss answers `invalid-mining-job-token`, fatal for a JDC.
                register_bridge_entries(&state, &bridge, session_id, &outcome.events);
                if let Err(err) = write_jdp_outbound_frames(&mut writer, outcome.outbound).await {
                    warn!("jdp {session_id_hex} write: {err:?}");
                    break;
                }
                if let Some(reason) = disconnect {
                    debug!("jdp {session_id_hex} closing: {reason}");
                    break;
                }
                payouts
                    .after_frame(
                        payout_session::negotiated(&state),
                        &hooks,
                        &bridge,
                        &mut writer,
                        &outcome.events,
                        &probe,
                    )
                    .await;
                fan_out_events(outcome.events, &hooks).await;
            }
        }
    }

    // Evict this session's declared jobs so the mining server keeps no stale ones.
    let evicted = bridge
        .write()
        .expect("bridge RwLock poisoned")
        .evict_for_jdp_session(session_id);
    if evicted > 0 {
        debug!("jdp {session_id_hex} disconnect evicted {evicted} declared jobs from bridge");
    }
    if let Some(validator) = hooks.job_validator.as_ref() {
        validator.session_closed(session_id);
    }
    let _ = writer.shutdown().await;
    Ok(())
}

/// Resolve async hook context, then call the matching sync `handle_*` function.
#[allow(clippy::too_many_arguments)]
async fn dispatch_jdp_inbound(
    state: &mut JdpSessionState,
    inbound: InboundJdpFrame,
    hooks: &JdpServerHooks,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    session_id: u32,
    now_ms: u64,
) -> JdpHandlerOutcome {
    match inbound {
        InboundJdpFrame::SetupConnection(input) => handle_setup_connection(state, &input),
        InboundJdpFrame::RequestExtensions(input) => {
            // ext 0x0003/SetPayoutDistribution: the first push is mandatory,
            // so offer 0x0003 only when one is publishable.
            let distribution_available = bridge
                .read()
                .expect("bridge RwLock poisoned")
                .current_pool_wide()
                .is_some();
            handle_request_extensions(state, &input, distribution_available)
        }
        InboundJdpFrame::AllocateMiningJobToken(input) => {
            let negotiated = state
                .negotiated_extensions
                .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS);
            match hooks
                .allocate_resolver
                .resolve_allocate_context(&input.user_identifier, negotiated)
                .await
            {
                AllocateOutcome::Granted(ctx) => handle_allocate_token(state, &input, ctx, now_ms),
                AllocateOutcome::Refused { reason } => {
                    warn!(
                        session_id,
                        user_identifier = %input.user_identifier,
                        reason,
                        "jdp: refusing to allocate a token — closing the connection"
                    );
                    JdpHandlerOutcome {
                        outbound: Vec::new(),
                        events: vec![JdpSessionEvent::Disconnect {
                            reason: format!("allocate refused: {reason}"),
                        }],
                    }
                }
                AllocateOutcome::Ignored => JdpHandlerOutcome::default(),
            }
        }
        InboundJdpFrame::DeclareMiningJob(input) => {
            // Authorise before the expensive work below. One token allows ONE
            // declaration attempt (SV2 JDP/Full-Template Mode: "some unique
            // work"), so `take_active` resolves and spends it in one act.
            // Session-level refusals come first and cost no token.
            if let Some(refusal) = declare_refused_by_session(state, &input) {
                return refusal;
            }
            let Some(declaring) = state.tokens.take_active(&input.mining_job_token, now_ms) else {
                return JdpHandlerOutcome::declare_error(
                    input.request_id,
                    crate::jdp::client::ERR_INVALID_MINING_JOB_TOKEN,
                    b"mining_job_token was never issued, has expired, or was already used \
                      to declare a job",
                );
            };
            let template_txs = hooks.template_tx_provider.snapshot().await;
            // Computed once for node and handler: it clones megabytes of raw txs.
            let partition = partition_against_template(&input.wtxid_list, &template_txs);
            // SV2 JDP/Job Declarator Server: the node judges before anything is
            // registered, so a rejection needs no rollback.
            if let Some(validator) = hooks.job_validator.as_ref() {
                if let Some(refusal) = node_refuses_declaration(
                    validator,
                    session_id,
                    &input,
                    &ordered_raw_txs(&partition.known_raw_txs),
                    DeclarationLeg::Declare,
                    "jdp: node rejected the declared job — not accepting it",
                )
                .await
                {
                    return refusal;
                }
            }
            let current_prev_hash = hooks.prev_hash_provider.current_prev_hash().await;
            let distribution =
                resolve_distribution_acceptance(bridge, session_id, input.distribution_id);
            // The mode of THIS TOKEN's address: a session may hold tokens for
            // several addresses.
            let current_mode = hooks
                .distribution_source
                .current_mode(&declaring.miner_address)
                .await;
            handle_declare_mining_job(
                state,
                &input,
                &declaring.miner_address,
                partition,
                DeclarationContext {
                    current_prev_hash,
                    distribution,
                    current_mode,
                    now_ms,
                },
            )
        }
        InboundJdpFrame::ProvideMissingTransactionsSuccess(input) => {
            // Second leg: re-ask the node with the full set, or an invalid tx
            // could hide among the ones the pool was missing. An unknown
            // `request_id` gets no merge and no node call; the handler refuses it.
            let completed = hooks.job_validator.as_ref().and_then(|validator| {
                let pending = state.pending_declarations.get(input.request_id)?;
                let merged = merge_provided_with_known(
                    pending.pending.clone(),
                    input.transaction_list.clone(),
                )
                .ok()?;
                Some((validator, pending.input.clone(), ordered_raw_txs(&merged)))
            });
            if let Some((validator, declared, known)) = completed {
                if let Some(refusal) = node_refuses_declaration(
                    validator,
                    session_id,
                    &declared,
                    &known,
                    DeclarationLeg::Completed,
                    "jdp: node rejected the completed declaration — not accepting it",
                )
                .await
                {
                    state.pending_declarations.take(input.request_id);
                    return refusal;
                }
            }
            let current_prev_hash = hooks.prev_hash_provider.current_prev_hash().await;
            // ext 0x0003/Grace Window is judged at ACCEPTANCE: re-resolve to
            // catch a supersession or settlement during the round-trip.
            let pending_distribution_id = state
                .pending_declarations
                .get(input.request_id)
                .and_then(|p| p.input.distribution_id);
            let distribution =
                resolve_distribution_acceptance(bridge, session_id, pending_distribution_id);
            // The pending declaration's miner, as on the declare leg.
            let pending_miner = state
                .pending_declarations
                .get(input.request_id)
                .map(|p| p.miner_address.clone());
            let current_mode = match pending_miner {
                Some(miner) => hooks.distribution_source.current_mode(&miner).await,
                None => None,
            };
            handle_provide_missing_transactions_success(
                state,
                &input,
                DeclarationContext {
                    current_prev_hash,
                    distribution,
                    current_mode,
                    now_ms,
                },
            )
        }
        InboundJdpFrame::PushSolution(input) => handle_push_solution(state, &input),
    }
}

/// Ask the node about a declaration (both legs) and turn a rejection into the
/// answer frame. `None` means nothing objected (see [`JobVerdict::NeedsTransactions`]).
async fn node_refuses_declaration(
    validator: &Arc<dyn DeclaredJobValidator>,
    session_id: u32,
    declared: &crate::jdp::client::DeclareMiningJobInput,
    known_raw_txs: &[Vec<u8>],
    leg: DeclarationLeg,
    log_message: &'static str,
) -> Option<JdpHandlerOutcome> {
    let verdict = validator
        .validate_declaration(DeclaredJobToValidate {
            session_id,
            version: declared.version,
            coinbase_tx_prefix: &declared.coinbase_tx_prefix,
            coinbase_tx_suffix: &declared.coinbase_tx_suffix,
            wtxid_list: &declared.wtxid_list,
            known_raw_txs,
            leg,
        })
        .await;
    let (error_code, error_details): (String, &[u8]) = match (verdict, leg) {
        (JobVerdict::Rejected(code), _) => {
            (code, b"declared job rejected by the pool's bitcoin node")
        }
        // Nothing left to fetch, e.g. a tx whose bytes miss its declared wtxid.
        (JobVerdict::NeedsTransactions, DeclarationLeg::Completed) => (
            crate::jdp::client::ERR_MISSING_TXS.to_string(),
            b"the pool's bitcoin node still lacks declared transactions after \
              ProvideMissingTransactions.Success",
        ),
        (JobVerdict::Accepted, _) | (JobVerdict::NeedsTransactions, DeclarationLeg::Declare) => {
            return None
        }
    };
    warn!(session_id, error_code, "{}", log_message);
    Some(JdpHandlerOutcome::declare_error(
        declared.request_id,
        &error_code,
        error_details,
    ))
}

/// Leg of the SV2 JDP/ProvideMissingTransactions round-trip; decides whether
/// "the node lacks transactions" is still open or a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclarationLeg {
    /// `DeclareMiningJob`: missing txs can still be fetched.
    Declare,
    /// `ProvideMissingTransactions.Success`: nothing left to fetch.
    Completed,
}

/// Resolve an ext 0x0003/distribution_id TLV Field reference against the
/// bridge's acceptance window. No TLV → `None`; the handler judges that.
fn resolve_distribution_acceptance(
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    session_id: u32,
    distribution_id: Option<u64>,
) -> Option<DistributionAcceptance> {
    distribution_id.map(|id| {
        bridge
            .read()
            .expect("bridge RwLock poisoned")
            .distribution_acceptance(id, DistributionScope::JdpSession(session_id))
    })
}

/// The ext 0x0003/SetPayoutDistribution wire form of a registry entry.
fn wire_from_entry(entry: &PayoutDistributionEntry) -> SetPayoutDistribution {
    SetPayoutDistribution {
        distribution_id: entry.distribution_id,
        pool_payout: entry.built.pool_payout.to_wire_txout(),
        payouts: entry
            .built
            .payouts
            .iter()
            .map(|p| p.to_wire_txout())
            .collect(),
        dust_limits: entry.built.dust_limits.clone(),
        additional_outputs: entry.built.additional_outputs.clone(),
    }
}

/// Fan out [`JdpSessionEvent`]s; only block candidates are acted on here.
async fn fan_out_events(events: Vec<JdpSessionEvent>, hooks: &JdpServerHooks) {
    for event in events {
        match event {
            JdpSessionEvent::SetupComplete => {}
            // Registered by `register_bridge_entries` before the write.
            JdpSessionEvent::TokenAllocated { .. } => {}
            JdpSessionEvent::JobDeclared { .. } => {}
            JdpSessionEvent::BlockSubmissionCandidate {
                miner_address,
                declaration,
                backing,
                coinbase_raw,
                transactions,
                header,
            } => {
                hooks
                    .block_submission_sink
                    .submit_block_candidate(
                        miner_address,
                        declaration,
                        backing,
                        coinbase_raw,
                        transactions,
                        header,
                    )
                    .await;
            }
            // The connection loop owns the socket and closes after the write.
            JdpSessionEvent::Disconnect { .. } => {}
        }
    }
}

/// Serialise and write each [`JdpOutboundFrame`]; ext 0x0003 is hand-framed.
async fn write_jdp_outbound_frames(
    writer: &mut NoiseTcpWriteHalf,
    outbound: Vec<JdpOutboundFrame>,
) -> Result<(), WriteError> {
    for frame in outbound {
        match encode_jdp_outbound(frame)? {
            JdpWireFrame::Message(message) => write_message(writer, message).await?,
            JdpWireFrame::Ext0x0003 { msg_type, payload } => {
                write_raw_frame(
                    writer,
                    SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS,
                    msg_type,
                    payload,
                )
                .await?
            }
        }
    }
    Ok(())
}

/// What the bridge does with an allocate token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllocationDisposition<'a> {
    /// Coinbase-only never declares (SV2 JDP/Coinbase-only Mode), so the
    /// allocate is the only record and pins the custom job's payout script.
    Register { payout_script: &'a [u8] },
    /// Full-Template: registering the token would let the JDC skip
    /// `DeclareMiningJob`, where the node validates its tx set.
    LeftToTheDeclaration,
    /// ext 0x0003: no designated script; judged by ext 0x0003/Output
    /// Verification. Registered as [`AllocationKind::JudgedByDistribution`].
    JudgedByTheDistribution,
    /// A base-protocol allocate that designated nothing: a pool fault.
    DesignatedNothing,
}

/// Classify an allocate token; pure and total.
pub(crate) fn classify_allocation(
    payout_script: Option<&[u8]>,
    full_template_mode: bool,
    payout_distribution_negotiated: bool,
) -> AllocationDisposition<'_> {
    match (
        payout_script,
        full_template_mode,
        payout_distribution_negotiated,
    ) {
        (Some(payout_script), false, false) => AllocationDisposition::Register { payout_script },
        (_, true, _) => AllocationDisposition::LeftToTheDeclaration,
        (_, false, true) => AllocationDisposition::JudgedByTheDistribution,
        (None, false, false) => AllocationDisposition::DesignatedNothing,
    }
}

/// Register declared jobs and allocate tokens in the bridge for the mining
/// server's `SetCustomMiningJob`. Runs after `dispatch_jdp_inbound`.
pub(crate) fn register_bridge_entries(
    state: &JdpSessionState,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    jdp_session_id: u32,
    events: &[JdpSessionEvent],
) {
    let mut reg = bridge.write().expect("bridge RwLock poisoned");
    for event in events {
        match event {
            JdpSessionEvent::JobDeclared { new_token } => {
                if let Some(declared_job) = state.declared_jobs.get(new_token) {
                    reg.register(
                        *new_token,
                        RegisteredDeclaredJob {
                            declared_job: declared_job.clone(),
                            jdp_session_id,
                        },
                    );
                }
            }
            // Negotiation is asked explicitly, not inferred from
            // `payout_script: None`: a 0x0003 allocate has empty outputs too.
            JdpSessionEvent::TokenAllocated {
                token,
                miner_address,
                payout_script,
                expires_at_ms,
            } => match classify_allocation(
                payout_script.as_deref(),
                state.full_template_mode,
                state
                    .negotiated_extensions
                    .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS),
            ) {
                AllocationDisposition::Register { payout_script } => {
                    reg.register_allocation(
                        *token,
                        AllocatedTokenRef {
                            miner_address: miner_address.clone(),
                            kind: AllocationKind::DesignatedOutput(payout_script.to_vec()),
                            jdp_session_id,
                            expires_at_ms: *expires_at_ms,
                        },
                        SystemClock.now_ms(),
                    );
                }
                AllocationDisposition::JudgedByTheDistribution => {
                    reg.register_allocation(
                        *token,
                        AllocatedTokenRef {
                            miner_address: miner_address.clone(),
                            kind: AllocationKind::JudgedByDistribution,
                            jdp_session_id,
                            expires_at_ms: *expires_at_ms,
                        },
                        SystemClock.now_ms(),
                    );
                }
                AllocationDisposition::LeftToTheDeclaration => {}
                AllocationDisposition::DesignatedNothing => {
                    warn!(
                        session_id = jdp_session_id,
                        "jdp: base-protocol allocate designated no payout output — the token \
                         cannot back a custom job (every SetCustomMiningJob on it will be \
                         refused)"
                    );
                }
            },
            // No wildcard, so a new event has to be classified here.
            JdpSessionEvent::SetupComplete
            | JdpSessionEvent::BlockSubmissionCandidate { .. }
            | JdpSessionEvent::Disconnect { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jdp::client::AllocateMiningJobTokenInput;
    use crate::jdp::payout_distribution::WeightedOutput;
    use crate::tokens::Token;

    const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    fn noise_cfg() -> NoiseConfig {
        NoiseConfig::new(
            "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
                .parse()
                .unwrap(),
            "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
                .parse()
                .unwrap(),
        )
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

    fn jdp_setup() -> crate::codec_common::SetupConnectionInput {
        crate::codec_common::SetupConnectionInput {
            protocol: crate::jdp::client::PROTOCOL_JOB_DECLARATION,
            min_version: 2,
            max_version: 2,
            flags: crate::jdp::client::FLAG_DECLARE_TX_DATA,
            vendor: "v".to_string(),
            firmware: "f".to_string(),
            hardware_version: "h".to_string(),
            device_id: "d".to_string(),
        }
    }

    /// Minimal registry entry: one weight-9 miner behind a weight-1 pool output.
    fn test_distribution(id: u64) -> PayoutDistributionEntry {
        PayoutDistributionEntry {
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
                dust_limits: vec![546],
                additional_outputs: vec![],
                reference_reward_sats: 312_500_000,
                payouts_fingerprint: Some([id as u8; 32]),
                bookable: true,
            },
            accounting: DistributionAccounting::PoolWide,
            jdp_session_id: None,
            published_at_ms: 1_000,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_handle_is_cloneable_and_shutdown_idempotent() {
        let bridge = fresh_bridge();
        let server = StratumV2JdpServer::spawn(
            noise_cfg(),
            JdpServerHooks::no_op(),
            bridge,
            Duration::from_secs(3600),
        );
        let _clone = server.clone();
        server.shutdown().await;
        server.shutdown().await; // idempotent
    }

    #[tokio::test(flavor = "current_thread")]
    async fn allocate_session_ids_monotonic_per_handle() {
        let bridge = fresh_bridge();
        let server = StratumV2JdpServer::spawn(
            noise_cfg(),
            JdpServerHooks::no_op(),
            bridge,
            Duration::from_secs(3600),
        );
        assert_eq!(server.alloc_session_id(), 1);
        assert_eq!(server.alloc_session_id(), 2);
        assert_eq!(server.alloc_session_id(), 3);
        server.shutdown().await;
    }

    fn granted(outcome: AllocateOutcome) -> AllocateTokenContext {
        match outcome {
            AllocateOutcome::Granted(ctx) => ctx,
            AllocateOutcome::Refused { reason } => panic!("refused: {reason}"),
            AllocateOutcome::Ignored => panic!("ignored"),
        }
    }

    /// The no-op hook designates one payout output, like production.
    #[tokio::test(flavor = "current_thread")]
    async fn no_op_allocate_resolver_designates_the_miners_own_output() {
        let hooks = NoOpJdpHooks;
        let ctx = granted(hooks.resolve_allocate_context(ADDR, false).await);
        assert_eq!(ctx.miner_address.as_str(), ADDR);
        let outputs: Vec<bitcoin::TxOut> =
            bitcoin::consensus::deserialize(&ctx.coinbase_outputs).expect("outputs decode");
        assert_eq!(
            outputs.len(),
            1,
            "SV2 JDP/AllocateMiningJobToken.Success designates ONE payout output"
        );
        assert_eq!(outputs[0].value, bitcoin::Amount::ZERO);
        assert_eq!(
            crate::jdp::dynamic_outputs::designated_payout_script(&ctx.coinbase_outputs).as_deref(),
            Some(outputs[0].script_pubkey.as_bytes()),
            "the blob must yield a designated script the bridge can register"
        );
    }

    /// ext 0x0003/Negotiation: negotiated ⇒ empty `coinbase_tx_outputs`.
    #[tokio::test(flavor = "current_thread")]
    async fn no_op_allocate_resolver_empty_outputs_when_0x0003_negotiated() {
        let hooks = NoOpJdpHooks;
        let ctx = granted(hooks.resolve_allocate_context(ADDR, true).await);
        assert_eq!(ctx.miner_address.as_str(), ADDR);
        assert!(ctx.coinbase_outputs.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_op_allocate_resolver_rejects_garbage_user_identifier() {
        let hooks = NoOpJdpHooks;
        let outcome = hooks
            .resolve_allocate_context(&"x".repeat(200), false)
            .await;
        assert!(
            matches!(outcome, AllocateOutcome::Ignored),
            "garbage user-identifier is ignored, not refused — the connection stays open"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dispatch_allocate_token_emits_success_with_resolver() {
        let mut state = fresh_session();
        // Need setup_complete first.
        let _ = handle_setup_connection(&mut state, &jdp_setup());
        let hooks = JdpServerHooks::no_op();
        let bridge = fresh_bridge();
        let outcome = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::AllocateMiningJobToken(AllocateMiningJobTokenInput {
                request_id: 7,
                user_identifier: ADDR.to_string(),
            }),
            &hooks,
            &bridge,
            1,
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
                // SV2 JDP/AllocateMiningJobToken.Success: one 0-sat output.
                let outputs: Vec<bitcoin::TxOut> =
                    bitcoin::consensus::deserialize(coinbase_outputs).expect("outputs decode");
                assert_eq!(outputs.len(), 1);
                assert_eq!(outputs[0].value, bitcoin::Amount::ZERO);
            }
            _ => panic!("expected AllocateMiningJobTokenSuccess"),
        }
    }

    // ── SV2 JDP/Job Declarator Server node-side validation of declared jobs ───

    /// Marks the node gate's rejections apart from handler errors.
    const NODE_REFUSAL: &[u8] = b"declared job rejected by the pool's bitcoin node";

    fn refused_by_node(outcome: &JdpHandlerOutcome) -> bool {
        outcome.outbound.iter().any(|f| {
            matches!(
                f,
                JdpOutboundFrame::DeclareMiningJobError { error_details, .. }
                    if error_details.as_slice() == NODE_REFUSAL
            )
        })
    }

    /// Fake node: scripted verdicts, then `Accepted`; records each call.
    struct StubValidator {
        verdicts: std::sync::Mutex<std::collections::VecDeque<JobVerdict>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl StubValidator {
        fn new(verdict: JobVerdict) -> Arc<Self> {
            Self::answering(vec![verdict])
        }
        fn answering(verdicts: Vec<JobVerdict>) -> Arc<Self> {
            Arc::new(Self {
                verdicts: std::sync::Mutex::new(verdicts.into()),
                calls: std::sync::atomic::AtomicUsize::new(0),
            })
        }
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl DeclaredJobValidator for StubValidator {
        async fn validate_declaration(&self, _job: DeclaredJobToValidate<'_>) -> JobVerdict {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.verdicts
                .lock()
                .expect("verdict lock")
                .pop_front()
                .unwrap_or(JobVerdict::Accepted)
        }

        fn session_closed(&self, _session_id: u32) {}
    }

    /// Issue a real token to `ADDR` on this session.
    fn issue_token(state: &mut JdpSessionState, now_ms: u64) -> Token {
        state
            .tokens
            .allocate(now_ms, AddressId::new(ADDR.to_string()).unwrap(), vec![0u8])
            .expect("allocate")
            .token
    }

    fn declare_input(token: Token) -> crate::jdp::client::DeclareMiningJobInput {
        crate::jdp::client::DeclareMiningJobInput {
            request_id: 11,
            mining_job_token: token,
            version: 0x2000_0000,
            coinbase_tx_prefix: vec![0xBB; 8],
            coinbase_tx_suffix: vec![0xCC; 8],
            wtxid_list: vec![[0x11; 32]],
            distribution_id: None,
        }
    }

    /// A node rejection answers `DeclareMiningJob.Error` and registers nothing.
    #[tokio::test(flavor = "current_thread")]
    async fn a_node_rejected_declaration_is_refused() {
        let mut state = fresh_session();
        let _ = handle_setup_connection(&mut state, &jdp_setup());
        state.full_template_mode = true;
        let token = issue_token(&mut state, 1_000);
        let validator = StubValidator::new(JobVerdict::Rejected("invalid-coinbase-tx".to_string()));
        let mut hooks = JdpServerHooks::no_op();
        hooks.job_validator = Some(validator.clone() as Arc<dyn DeclaredJobValidator>);
        let bridge = fresh_bridge();

        let outcome = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::DeclareMiningJob(declare_input(token)),
            &hooks,
            &bridge,
            1,
            1_000,
        )
        .await;

        assert_eq!(validator.calls(), 1, "the node must actually be consulted");
        match &outcome.outbound[0] {
            JdpOutboundFrame::DeclareMiningJobError {
                request_id,
                error_code,
                ..
            } => {
                assert_eq!(*request_id, 11);
                assert_eq!(error_code, "invalid-coinbase-tx");
            }
            other => panic!("expected DeclareMiningJobError, got {other:?}"),
        }
        assert!(
            state.pending_declarations.is_empty(),
            "a refused declaration must leave no half-finished round-trip behind"
        );
    }

    /// Without a validator, declarations are taken on the JDC's word.
    #[tokio::test(flavor = "current_thread")]
    async fn without_a_validator_the_declaration_is_not_refused() {
        let mut state = fresh_session();
        let _ = handle_setup_connection(&mut state, &jdp_setup());
        state.full_template_mode = true;
        let token = issue_token(&mut state, 1_000);
        let hooks = JdpServerHooks::no_op();
        assert!(hooks.job_validator.is_none());
        let bridge = fresh_bridge();

        let outcome = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::DeclareMiningJob(declare_input(token)),
            &hooks,
            &bridge,
            1,
            1_000,
        )
        .await;

        assert!(
            !refused_by_node(&outcome),
            "no validator must mean no node-driven rejection: {:?}",
            outcome.outbound
        );
    }

    /// `NeedsTransactions` on the declare leg starts the round-trip, not a rejection.
    #[tokio::test(flavor = "current_thread")]
    async fn needs_transactions_is_not_a_rejection() {
        let mut state = fresh_session();
        let _ = handle_setup_connection(&mut state, &jdp_setup());
        state.full_template_mode = true;
        let token = issue_token(&mut state, 1_000);
        let validator = StubValidator::new(JobVerdict::NeedsTransactions);
        let mut hooks = JdpServerHooks::no_op();
        hooks.job_validator = Some(validator.clone() as Arc<dyn DeclaredJobValidator>);
        let bridge = fresh_bridge();

        let outcome = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::DeclareMiningJob(declare_input(token)),
            &hooks,
            &bridge,
            1,
            1_000,
        )
        .await;

        assert_eq!(validator.calls(), 1);
        assert!(
            !refused_by_node(&outcome),
            "a node that lacks transactions must not fail the declaration: {:?}",
            outcome.outbound
        );
    }

    fn refused_for_token(outcome: &JdpHandlerOutcome) -> bool {
        outcome.outbound.iter().any(|f| {
            matches!(
                f,
                JdpOutboundFrame::DeclareMiningJobError { error_code, .. }
                    if error_code == crate::jdp::client::ERR_INVALID_MINING_JOB_TOKEN
            )
        })
    }

    fn declare_error_code(outcome: &JdpHandlerOutcome) -> &str {
        match outcome.outbound.first() {
            Some(JdpOutboundFrame::DeclareMiningJobError { error_code, .. }) => error_code,
            other => panic!("expected a DeclareMiningJobError, got {other:?}"),
        }
    }

    async fn declare_with(
        state: &mut JdpSessionState,
        hooks: &JdpServerHooks,
        bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
        token: Token,
        now_ms: u64,
    ) -> JdpHandlerOutcome {
        dispatch_jdp_inbound(
            state,
            InboundJdpFrame::DeclareMiningJob(declare_input(token)),
            hooks,
            bridge,
            1,
            now_ms,
        )
        .await
    }

    /// A second declaration on one token is refused `invalid-mining-job-token`
    /// before the node is asked.
    #[tokio::test(flavor = "current_thread")]
    async fn one_allocate_token_carries_exactly_one_declaration() {
        let mut state = fresh_session();
        let _ = handle_setup_connection(&mut state, &jdp_setup());
        state.full_template_mode = true;
        let token = issue_token(&mut state, 1_000);
        let validator = StubValidator::new(JobVerdict::Accepted);
        let mut hooks = JdpServerHooks::no_op();
        hooks.job_validator = Some(validator.clone() as Arc<dyn DeclaredJobValidator>);
        let bridge = fresh_bridge();

        let first = declare_with(&mut state, &hooks, &bridge, token, 1_100).await;
        assert_eq!(
            validator.calls(),
            1,
            "precondition: the first declaration DID reach the node"
        );
        assert!(
            !refused_for_token(&first),
            "precondition: the first declaration's token resolved, got {:?}",
            first.outbound
        );

        let second = declare_with(&mut state, &hooks, &bridge, token, 1_200).await;
        assert_eq!(
            declare_error_code(&second),
            crate::jdp::client::ERR_INVALID_MINING_JOB_TOKEN,
            "a second declaration on a spent allocate token must be refused"
        );
        assert_eq!(
            validator.calls(),
            1,
            "and refused without asking the node a second time"
        );
    }

    /// A `ProvideMissingTransactions.Success` with an unknown `request_id` does
    /// not reach the node; the matching one does.
    #[tokio::test(flavor = "current_thread")]
    async fn a_provide_missing_success_for_another_request_never_reaches_the_node() {
        let mut state = fresh_session();
        let _ = handle_setup_connection(&mut state, &jdp_setup());
        state.full_template_mode = true;
        let token = issue_token(&mut state, 1_000);
        let validator = StubValidator::new(JobVerdict::Accepted);
        let mut hooks = JdpServerHooks::no_op();
        hooks.job_validator = Some(validator.clone() as Arc<dyn DeclaredJobValidator>);
        let bridge = fresh_bridge();

        // No template txs wired, so the declared wtxid is missing.
        let first = declare_with(&mut state, &hooks, &bridge, token, 1_100).await;
        assert!(
            matches!(
                first.outbound.first(),
                Some(JdpOutboundFrame::ProvideMissingTransactions { .. })
            ),
            "precondition: a round-trip must be in flight, got {:?}",
            first.outbound
        );
        assert_eq!(
            validator.calls(),
            1,
            "precondition: the declare reached the node"
        );

        let answer = |request_id| {
            InboundJdpFrame::ProvideMissingTransactionsSuccess(
                crate::jdp::client::ProvideMissingTransactionsSuccessInput {
                    request_id,
                    transaction_list: vec![vec![0xAB; 32]],
                },
            )
        };

        // Wrong request_id: no node call, no frame, round-trip still pending.
        let out = dispatch_jdp_inbound(&mut state, answer(9_999), &hooks, &bridge, 1, 1_200).await;
        assert!(out.outbound.is_empty(), "got {:?}", out.outbound);
        assert_eq!(
            validator.calls(),
            1,
            "a Success for another request must not be handed to the node"
        );
        assert!(
            !state.pending_declarations.is_empty(),
            "precondition for the loop this guards: the round-trip survives"
        );

        // The real answer still goes through.
        let _ = dispatch_jdp_inbound(&mut state, answer(11), &hooks, &bridge, 1, 1_300).await;
        assert_eq!(
            validator.calls(),
            2,
            "the matching Success must be re-validated"
        );
    }

    /// `NeedsTransactions` on the second leg is refused `missing-txs`; the
    /// same round-trip with the node accepting is not.
    #[tokio::test(flavor = "current_thread")]
    async fn a_completed_declaration_the_node_still_lacks_transactions_for_is_refused() {
        let complete = |second_leg: JobVerdict| async move {
            let mut state = fresh_session();
            let _ = handle_setup_connection(&mut state, &jdp_setup());
            state.full_template_mode = true;
            let token = issue_token(&mut state, 1_000);
            let validator =
                StubValidator::answering(vec![JobVerdict::NeedsTransactions, second_leg]);
            let mut hooks = JdpServerHooks::no_op();
            hooks.job_validator = Some(validator.clone() as Arc<dyn DeclaredJobValidator>);
            let bridge = fresh_bridge();

            let first = declare_with(&mut state, &hooks, &bridge, token, 1_100).await;
            assert!(
                matches!(
                    first.outbound.first(),
                    Some(JdpOutboundFrame::ProvideMissingTransactions { .. })
                ),
                "precondition: a round-trip must be in flight, got {:?}",
                first.outbound
            );
            let second = dispatch_jdp_inbound(
                &mut state,
                InboundJdpFrame::ProvideMissingTransactionsSuccess(
                    crate::jdp::client::ProvideMissingTransactionsSuccessInput {
                        request_id: 11,
                        transaction_list: vec![vec![0xAB; 32]],
                    },
                ),
                &hooks,
                &bridge,
                1,
                1_200,
            )
            .await;
            assert_eq!(
                validator.calls(),
                2,
                "precondition: both legs reached the node"
            );
            (second, state)
        };

        let (refused, state) = complete(JobVerdict::NeedsTransactions).await;
        assert_eq!(
            declare_error_code(&refused),
            crate::jdp::client::ERR_MISSING_TXS
        );
        assert!(
            !refused
                .events
                .iter()
                .any(|e| matches!(e, JdpSessionEvent::JobDeclared { .. })),
            "a declaration the node never saw whole must not be declared"
        );
        assert!(state.declared_jobs.is_empty());
        assert!(
            state.pending_declarations.is_empty(),
            "a refused declaration must leave no half-finished round-trip behind"
        );

        let (accepted, _) = complete(JobVerdict::Accepted).await;
        assert!(
            !accepted.outbound.iter().any(|f| matches!(
                f,
                JdpOutboundFrame::DeclareMiningJobError { error_code, .. }
                    if error_code == crate::jdp::client::ERR_MISSING_TXS
            )),
            "negative control: a node that accepts the complete set must not be refused \
             missing-txs, got {:?}",
            accepted.outbound
        );
    }

    /// A session-level refusal costs no token, so the same reason repeats.
    #[tokio::test(flavor = "current_thread")]
    async fn a_declaration_refused_by_the_session_shape_costs_no_token() {
        let mut state = fresh_session();
        let mut setup = jdp_setup();
        setup.flags = 0; // Coinbase-only: DeclareMiningJob is never used
        let _ = handle_setup_connection(&mut state, &setup);
        let token = issue_token(&mut state, 1_000);
        let validator = StubValidator::new(JobVerdict::Accepted);
        let mut hooks = JdpServerHooks::no_op();
        hooks.job_validator = Some(validator.clone() as Arc<dyn DeclaredJobValidator>);
        let bridge = fresh_bridge();

        for request in 1..=2 {
            let outcome = declare_with(&mut state, &hooks, &bridge, token, 1_100).await;
            assert_eq!(
                declare_error_code(&outcome),
                crate::jdp::client::ERR_UNSUPPORTED_FEATURE_FLAGS,
                "declare {request}: the reason must stay the same reason"
            );
        }
        assert_eq!(
            state.tokens.len(),
            1,
            "a refusal the token had nothing to do with must not spend it"
        );
        assert_eq!(validator.calls(), 0, "and must not reach the node");
    }

    /// A token nobody was issued is refused before the node is asked.
    #[tokio::test(flavor = "current_thread")]
    async fn a_token_nobody_was_issued_never_reaches_the_node() {
        let mut state = fresh_session();
        let _ = handle_setup_connection(&mut state, &jdp_setup());
        state.full_template_mode = true;
        let validator = StubValidator::new(JobVerdict::Accepted);
        let mut hooks = JdpServerHooks::no_op();
        hooks.job_validator = Some(validator.clone() as Arc<dyn DeclaredJobValidator>);
        let bridge = fresh_bridge();

        let outcome = declare_with(&mut state, &hooks, &bridge, Token([0xEE; 16]), 1_100).await;

        assert_eq!(
            declare_error_code(&outcome),
            crate::jdp::client::ERR_INVALID_MINING_JOB_TOKEN
        );
        assert_eq!(validator.calls(), 0, "the node must not be asked at all");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dispatch_setup_connection_emits_success() {
        let mut state = fresh_session();
        let hooks = JdpServerHooks::no_op();
        let bridge = fresh_bridge();
        let outcome = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::SetupConnection(jdp_setup()),
            &hooks,
            &bridge,
            1,
            0,
        )
        .await;
        assert!(matches!(
            outcome.outbound[0],
            JdpOutboundFrame::SetupConnectionSuccess { .. }
        ));
        assert!(state.setup_complete);
    }

    /// 0x0003 is offered only while a pool-wide distribution is publishable.
    #[tokio::test(flavor = "current_thread")]
    async fn dispatch_request_extensions_offers_0x0003_only_when_publishable() {
        let mut state = fresh_session();
        let _ = handle_setup_connection(&mut state, &jdp_setup());
        let hooks = JdpServerHooks::no_op();
        let bridge = fresh_bridge();
        let request = |id: u16| {
            InboundJdpFrame::RequestExtensions(crate::extensions::RequestExtensions {
                request_id: id,
                requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS],
            })
        };

        let outcome = dispatch_jdp_inbound(&mut state, request(1), &hooks, &bridge, 1, 1_000).await;
        match &outcome.outbound[0] {
            JdpOutboundFrame::RequestExtensionsError {
                unsupported_extensions,
                ..
            } => {
                assert!(unsupported_extensions.contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS))
            }
            other => panic!("expected RequestExtensionsError, got {other:?}"),
        }
        assert!(!state
            .negotiated_extensions
            .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS));

        bridge
            .write()
            .unwrap()
            .publish_pool_wide(test_distribution(1));
        let outcome = dispatch_jdp_inbound(&mut state, request(2), &hooks, &bridge, 1, 2_000).await;
        match &outcome.outbound[0] {
            JdpOutboundFrame::RequestExtensionsSuccess {
                supported_extensions,
                ..
            } => assert!(supported_extensions.contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)),
            other => panic!("expected RequestExtensionsSuccess, got {other:?}"),
        }
        assert!(state
            .negotiated_extensions
            .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS));
    }

    /// The declare's mode is looked up for the TOKEN's address, not the
    /// session's latest; otherwise A's plan is refused against B's mode.
    #[tokio::test]
    async fn a_declares_mode_comes_from_its_own_tokens_address() {
        /// Records which address the mode was asked about.
        struct AskedAbout(std::sync::Mutex<Vec<String>>);
        #[async_trait]
        impl PayoutDistributionSource for AskedAbout {
            async fn build_pool_wide(&self) -> Option<BuiltPayoutDistribution> {
                None
            }
            async fn build_for_miner(&self, _: &AddressId) -> TailoredDistribution {
                TailoredDistribution::ModeUnknown
            }
            async fn current_mode(&self, miner: &AddressId) -> Option<bp_common::StreamKind> {
                self.0.lock().unwrap().push(miner.as_str().to_string());
                Some(bp_common::StreamKind::Solo)
            }
            async fn next_distribution_id(&self) -> Option<u64> {
                None
            }
        }
        let source = Arc::new(AskedAbout(std::sync::Mutex::new(Vec::new())));
        let mut hooks = JdpServerHooks::no_op();
        hooks.distribution_source = source.clone();
        let bridge = fresh_bridge();

        let other = "bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vaxwd45v";
        let mut state = fresh_session();
        let _ = handle_setup_connection(&mut state, &jdp_setup());
        state.full_template_mode = true;
        let a = state
            .tokens
            .allocate(1_000, AddressId::new(ADDR.to_string()).unwrap(), vec![0u8])
            .expect("token for A")
            .token;
        // B allocates LAST, so a session-scoped answer would name B.
        let b = state
            .tokens
            .allocate(3_000, AddressId::new(other.to_string()).unwrap(), vec![0u8])
            .expect("token for B")
            .token;

        let _ = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::DeclareMiningJob(declare_input(a)),
            &hooks,
            &bridge,
            1,
            3_000,
        )
        .await;
        assert_eq!(
            source.0.lock().unwrap().as_slice(),
            [ADDR.to_string()],
            "A's declaration must be judged by A's mode, even though B allocated last"
        );

        // B's token resolves to B, so a constant answer cannot pass.
        let _ = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::DeclareMiningJob(declare_input(b)),
            &hooks,
            &bridge,
            1,
            3_000,
        )
        .await;
        assert_eq!(
            source.0.lock().unwrap().as_slice(),
            [ADDR.to_string(), other.to_string()],
            "two tokens on one session must resolve to two addresses"
        );

        // An unissued token is refused before any mode lookup.
        let _ = dispatch_jdp_inbound(
            &mut state,
            InboundJdpFrame::DeclareMiningJob(declare_input(Token([0xEE; 16]))),
            &hooks,
            &bridge,
            1,
            3_000,
        )
        .await;
        assert_eq!(
            source.0.lock().unwrap().len(),
            2,
            "an unknown token has no address to ask about"
        );
    }

    /// The denial is readable without the write lock.
    #[test]
    fn a_denial_can_be_read_before_deciding_to_write_it() {
        let mut reg = JdpDeclaredJobRegistry::new();
        assert!(!reg.is_pool_wide_denied(7), "a fresh session is not denied");
        reg.deny_pool_wide(7);
        assert!(reg.is_pool_wide_denied(7));
        reg.deny_pool_wide(7);
        assert!(
            reg.is_pool_wide_denied(7),
            "denying twice is a no-op, not a flip"
        );
        reg.allow_pool_wide(7);
        assert!(!reg.is_pool_wide_denied(7));
    }

    /// The wire form mirrors the registry entry; weights ride in the amount field.
    #[test]
    fn wire_from_entry_carries_weights_and_dust_limits() {
        let entry = test_distribution(7);
        let wire = wire_from_entry(&entry);
        assert_eq!(wire.distribution_id, 7);
        assert_eq!(wire.pool_payout, entry.built.pool_payout.to_wire_txout());
        assert_eq!(wire.payouts.len(), 1);
        assert_eq!(wire.payouts[0], entry.built.payouts[0].to_wire_txout());
        assert_eq!(wire.dust_limits, vec![546]);
        assert!(wire.additional_outputs.is_empty());
    }

    /// `register_bridge_entries` writes the declared job into the bridge.
    #[tokio::test(flavor = "current_thread")]
    async fn register_bridge_entries_pushes_declared_jobs_to_registry() {
        use crate::jdp::declarations::DeclaredJob;
        let mut state = fresh_session();
        let token = Token([0xAA; 16]);
        let job = DeclaredJob {
            new_token: token,
            miner_address: AddressId::new(ADDR.to_string()).unwrap(),
            version: 0,
            coinbase_tx_prefix: vec![],
            coinbase_tx_suffix: vec![],
            wtxid_list: vec![],
            raw_transactions: HashMap::new(),
            prev_hash: [0xCC; 32],
            declared_at_ms: 500,
            booking: None,
            distribution_id: None,
        };
        state.declared_jobs.insert(job);
        let bridge = fresh_bridge();
        let events = vec![JdpSessionEvent::JobDeclared { new_token: token }];
        register_bridge_entries(&state, &bridge, 42, &events);
        let r = bridge.read().unwrap();
        let entry = r.job_ref(&token).expect("must be registered");
        assert_eq!(entry.jdp_session_id, 42);
        assert_eq!(entry.miner_address.as_str(), ADDR);
        assert_eq!(entry.declared_prev_hash, [0xCC; 32]);
    }

    /// Both Coinbase-only allocate kinds register; one that designated nothing
    /// does not. The 0x0003 case needs its own negotiated session.
    #[tokio::test(flavor = "current_thread")]
    async fn register_bridge_entries_pushes_both_coinbase_only_kinds() {
        let bridge = fresh_bridge();
        let base = Token([0xBB; 16]);
        let broken = Token([0xDD; 16]);
        let negotiated = Token([0xCC; 16]);

        let plain = fresh_session();
        register_bridge_entries(
            &plain,
            &bridge,
            42,
            &[
                JdpSessionEvent::TokenAllocated {
                    token: base,
                    miner_address: AddressId::new(ADDR.to_string()).unwrap(),
                    payout_script: Some(vec![0x00, 0x14, 0xAB]),
                    expires_at_ms: u64::MAX,
                },
                // Base protocol, no designated output: nothing to register.
                JdpSessionEvent::TokenAllocated {
                    token: broken,
                    miner_address: AddressId::new(ADDR.to_string()).unwrap(),
                    payout_script: None,
                    expires_at_ms: u64::MAX,
                },
            ],
        );

        let mut ext_session = fresh_session();
        ext_session
            .negotiated_extensions
            .insert(SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS);
        register_bridge_entries(
            &ext_session,
            &bridge,
            43,
            &[JdpSessionEvent::TokenAllocated {
                token: negotiated,
                miner_address: AddressId::new(ADDR.to_string()).unwrap(),
                // ext 0x0003/Negotiation requires the outputs empty.
                payout_script: None,
                expires_at_ms: u64::MAX,
            }],
        );

        let r = bridge.read().unwrap();
        let entry = r.allocation_ref(&base, 0).expect("base allocate registers");
        assert_eq!(entry.jdp_session_id, 42);
        assert_eq!(entry.miner_address.as_str(), ADDR);
        assert_eq!(
            entry.kind,
            AllocationKind::DesignatedOutput(vec![0x00, 0x14, 0xAB])
        );
        assert!(
            r.allocation_ref(&broken, 0).is_none(),
            "a base-protocol allocate that designated nothing has nothing to hold a coinbase to"
        );
        // The ext 0x0003 allocate registers as its own kind.
        let ext = r
            .allocation_ref(&negotiated, 1_000)
            .expect("an ext 0x0003 allocate is still a token the pool issued");
        assert_eq!(ext.kind, AllocationKind::JudgedByDistribution);
        assert_eq!(ext.miner_address.as_str(), ADDR);
        assert_eq!(ext.jdp_session_id, 43);
    }

    /// All eight combinations; only one is a fault, and
    /// `(None, Coinbase-only, negotiated)` is NOT it.
    #[test]
    fn an_allocate_is_classified_by_all_three_flags() {
        use AllocationDisposition as D;
        const SCRIPT: &[u8] = &[0x00, 0x14, 0xAB];

        // (payout_script, full_template_mode, negotiated) → disposition
        let cases: [(Option<&[u8]>, bool, bool, D); 8] = [
            // Coinbase-only, base protocol: the one row judged by a script.
            (
                Some(SCRIPT),
                false,
                false,
                D::Register {
                    payout_script: SCRIPT,
                },
            ),
            // Coinbase-only + ext 0x0003: NOT a fault (ext 0x0003/Negotiation).
            (None, false, true, D::JudgedByTheDistribution),
            // Negotiated: the distribution judges even when a script is present.
            (Some(SCRIPT), false, true, D::JudgedByTheDistribution),
            // Full-Template: the declaration is the record.
            (Some(SCRIPT), true, false, D::LeftToTheDeclaration),
            (Some(SCRIPT), true, true, D::LeftToTheDeclaration),
            (None, true, false, D::LeftToTheDeclaration),
            (None, true, true, D::LeftToTheDeclaration),
            // The only fault: a base allocate the pool designated nothing in.
            (None, false, false, D::DesignatedNothing),
        ];

        for (script, full_template, negotiated, want) in cases {
            assert_eq!(
                classify_allocation(script, full_template, negotiated),
                want,
                "script={:?} full_template={full_template} negotiated={negotiated}",
                script.map(|s| s.len())
            );
        }
    }
}
