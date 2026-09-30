// SPDX-License-Identifier: AGPL-3.0-or-later

//! JDP-port server: handle + per-connection task.
//!
//! Same shape as [`crate::server`], but for the Job-Declaration
//! sub-protocol: no template broadcast and no vardiff (the JDC builds and
//! declares its own work). Each accepted `DeclareMiningJob` produces a
//! [`crate::jdp::client::JdpSessionEvent::JobDeclared`] that is registered in
//! the bridge, so the mining server's `SetCustomMiningJob` handler can
//! cross-check the token.
//!
//! - **ext 0x0003** is push-only: `SetPayoutDistribution` is not in
//!   `stratum-core::AnyMessage`, so it is written as a raw frame, first right
//!   after `RequestExtensions.Success` (ext 0x0003/SetPayoutDistribution),
//!   then again on every publish.
//! - **Payout validation** in `accept_declaration` recomputes and compares
//!   positionally (ext 0x0003/Output Verification) against the distribution
//!   the declaration's `distribution_id` TLV names.
//! - **Block assembly** happens in the bin: the handler emits the raw
//!   components, the production sink rebuilds the block and submits it.

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
/// `AllocateMiningJobToken`. Production parses `user_identifier` as a BTC
/// address and computes the payout outputs via [`crate::hooks::PayoutResolver`]
/// + [`crate::jdp::dynamic_outputs::designated_output_blob`].
#[async_trait]
pub trait JdpAllocateResolver: Send + Sync {
    /// `payout_distribution_negotiated`: ext 0x0003 is active on this
    /// connection, and ext 0x0003/Negotiation then REQUIRES
    /// `coinbase_tx_outputs` to be empty, so the resolver builds no outputs.
    async fn resolve_allocate_context(
        &self,
        user_identifier: &str,
        payout_distribution_negotiated: bool,
    ) -> AllocateOutcome;
}

/// What the pool does with an `AllocateMiningJobToken`.
///
/// The two negative arms differ: SV2 gives `AllocateMiningJobToken` no error
/// message, so the only way to tell a client "not here" is to close the
/// connection. [`Self::Refused`] does that; [`Self::Ignored`] drops the frame
/// for an identifier that resolves to nothing at all.
pub enum AllocateOutcome {
    /// Issue a token with these outputs.
    Granted(AllocateTokenContext),
    /// The pool cannot serve this miner on this protocol at all. Closing the
    /// connection makes the JDC's SV2 JDP/Job Declarator Client fallback
    /// ("JDC is responsible for switching to a new Pool+JDS or solo mining")
    /// fire immediately instead of after a timeout.
    Refused { reason: &'static str },
    /// Nothing resolvable (unparseable `user_identifier`); dropped silently.
    Ignored,
}

/// Snapshot the pool's template-tx cache (`wtxid → raw_tx`) for the
/// `DeclareMiningJob` partition step. An empty map makes the handler request
/// every tx via `ProvideMissingTransactions`.
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

use crate::bridge::BuiltPayoutDistribution;

/// Floor the publish interval at 1s.
///
/// `tokio::time::interval` panics on a zero period, and in the detached
/// publisher task that panic would silently stop all publishing, so 0x0003
/// would never be offered. A 0 reads as "as fast as possible", so clamp and
/// warn rather than refuse to boot.
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

/// What the pool can publish for one JDP session's miner.
///
/// The cases are deliberately distinct: a failed tailored build must never
/// fall back to the pool-wide distribution, or a Solo / Group-Solo block
/// would pay the PPLNS window.
///
/// PPLNS rides `PoolWide`; Solo and Group-Solo get `Built`. Blockparty is not
/// offered over JDP and resolves to `Unavailable`: its coinbase is split by
/// fixed per-member percentages, so a job-declaring client adds nothing.
#[derive(Debug)]
pub enum TailoredDistribution {
    /// PPLNS-mode miner: the pool-wide distribution IS their accounting.
    PoolWide,
    /// A distribution tailored to this miner, with the accounting it was
    /// built for. The kind travels with the build because Solo and Group-Solo
    /// produce different payouts for the same address, so the address alone
    /// cannot tell them apart later (see [`DistributionAccounting`]).
    Built {
        accounting: DistributionAccounting,
        built: Box<BuiltPayoutDistribution>,
    },
    /// The tailored build failed. This miner's shares are not in the PPLNS
    /// window, so the session is served nothing until a later build succeeds.
    Unavailable,
    /// The pool does not know this address's payout mode yet, so it cannot
    /// know which distribution is right. Unlike `Unavailable` this resolves
    /// by itself once a mining session registers, so the caller retries.
    ///
    /// This is the normal state at JDC startup: the mode is known only from
    /// the port a mining session connects to, and a JDC allocates before its
    /// mining channel exists. Guessing is a money error in either direction.
    ModeUnknown,
}

/// Build the pool's payout distributions for the ext 0x0003 push model.
///
/// The publisher task calls [`Self::build_pool_wide`] on its interval and
/// after a settlement; the per-connection task calls
/// [`Self::build_for_miner`] once an allocate reveals the miner.
/// [`Self::next_distribution_id`] allocates the strictly increasing,
/// pool-global id of ext 0x0003/SetPayoutDistribution; it is infra-backed so
/// this crate stays free of Redis.
#[async_trait]
pub trait PayoutDistributionSource: Send + Sync {
    /// `None` ⇒ nothing publishable right now (no PPLNS engine / no
    /// template yet) — ext 0x0003 is then not offered in negotiation.
    async fn build_pool_wide(&self) -> Option<BuiltPayoutDistribution>;
    /// What this session's miner should be served. See
    /// [`TailoredDistribution`] — `PoolWide` and `Unavailable` are NOT
    /// interchangeable.
    async fn build_for_miner(&self, miner_address: &AddressId) -> TailoredDistribution;
    /// Which accounting this address is on right now, without building
    /// anything. `None` when the pool has no live mining session for it.
    ///
    /// A live miner can move between Solo and Group-Solo when its group
    /// membership changes, without a reconnect, so the plan a session serves
    /// is re-checked per inbound frame. Polling rather than pushing means a
    /// missed check simply happens again on the next frame; this lookup
    /// builds nothing, which is what makes per-frame affordable.
    async fn current_mode(&self, miner_address: &AddressId) -> Option<bp_common::StreamKind>;
    /// `None` ⇒ the allocator is unavailable; the publish is skipped
    /// (the previously-published distribution stays valid).
    async fn next_distribution_id(&self) -> Option<u64>;
}

/// Block-submission sink for `PushSolution` candidates. Production rebuilds
/// the block and submits it via `TdpHandle::submit_solution`.
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

/// `position → raw_tx` in declaration order. The node-side validator wants a
/// plain list; the position map is how the pool tracks the round-trip.
fn ordered_raw_txs(by_position: &std::collections::HashMap<u32, Vec<u8>>) -> Vec<Vec<u8>> {
    let mut positions: Vec<&u32> = by_position.keys().collect();
    positions.sort_unstable();
    positions
        .into_iter()
        .filter_map(|p| by_position.get(p).cloned())
        .collect()
}

/// Hands a declared job to a Bitcoin node for a real verdict. Full-Template
/// mode exists so the pool can check what Coinbase-only mode takes on trust
/// (SV2 JDP/Job Declarator Server, SV2 JDP/Coinbase-only Mode).
///
/// `None` in [`JdpServerHooks::job_validator`] accepts every declaration on
/// the JDC's word.
#[async_trait]
pub trait DeclaredJobValidator: Send + Sync {
    /// Ask the node whether this declared job is valid.
    async fn validate_declaration(&self, job: DeclaredJobToValidate<'_>) -> JobVerdict;

    /// The JDP session is gone; drop whatever the validator keeps for it.
    fn session_closed(&self, session_id: u32);
}

/// One declared job, in the shape a node-side validator needs.
pub struct DeclaredJobToValidate<'a> {
    /// The JDP session the declaration came in on. A node-side validator keeps
    /// per-downstream state, so declarations must not be attributed to the
    /// wrong connection.
    pub session_id: u32,
    pub version: u32,
    pub coinbase_tx_prefix: &'a [u8],
    pub coinbase_tx_suffix: &'a [u8],
    /// Declared wtxids in declaration order (wire byte order).
    pub wtxid_list: &'a [[u8; 32]],
    /// Raw transactions the pool can already supply. The node reports back
    /// whatever it still misses rather than guessing.
    pub known_raw_txs: &'a [Vec<u8>],
    /// Which leg of the round-trip this is. A node-side validator that keeps
    /// state between the two legs needs to know where a declaration starts.
    pub leg: DeclarationLeg,
}

/// What the node said about a declared job.
#[derive(Debug)]
pub enum JobVerdict {
    /// Validated — the node accepts the job.
    Accepted,
    /// Rejected. Carries the SV2 error code for `DeclareMiningJob.Error`.
    Rejected(String),
    /// The node is missing transactions the pool did not supply. On the
    /// declare leg this is not a rejection (the `ProvideMissingTransactions`
    /// round-trip fetches them); on the second leg it is one (`missing-txs`),
    /// see `node_refuses_declaration`.
    NeedsTransactions,
}

#[derive(Clone)]
pub struct JdpServerHooks {
    pub allocate_resolver: Arc<dyn JdpAllocateResolver>,
    pub template_tx_provider: Arc<dyn TemplateTxProvider>,
    pub prev_hash_provider: Arc<dyn CurrentPrevHashProvider>,
    pub block_submission_sink: Arc<dyn JdpBlockSubmissionSink>,
    /// ext 0x0003 distribution source (push model). [`NoOpJdpHooks`] returns
    /// `None` everywhere, so the extension is not offered.
    pub distribution_source: Arc<dyn PayoutDistributionSource>,
    /// Node-side validation of declared jobs (SV2 JDP/Job Declarator Server).
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

/// Drop-in no-op implementation for tests + the regtest harness.
pub struct NoOpJdpHooks;

#[async_trait]
impl JdpAllocateResolver for NoOpJdpHooks {
    async fn resolve_allocate_context(
        &self,
        user_identifier: &str,
        payout_distribution_negotiated: bool,
    ) -> AllocateOutcome {
        // Pure parse. Production wiring overrides.
        let Some(addr) = parse_user_identifier_as_address(user_identifier) else {
            return AllocateOutcome::Ignored;
        };
        if payout_distribution_negotiated {
            return AllocateOutcome::Granted(AllocateTokenContext {
                miner_address: addr,
                coinbase_outputs: Vec::new(), // ext 0x0003/Negotiation MUST: empty under 0x0003
            });
        }
        // SV2 JDP/AllocateMiningJobToken.Success wants ONE designated payout
        // output at 0 sats; an empty vector designates nothing and every job
        // would be refused. Paying the miner matches production Solo.
        //
        // Not `bp_mining_job::address_to_script`: that enforces a configured
        // network, which a no-op hook does not have.
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
        // No distribution to publish → ext 0x0003 is never offered.
        None
    }
    async fn build_for_miner(&self, _miner_address: &AddressId) -> TailoredDistribution {
        // Nothing wired: no tailored distribution and no pool-wide one
        // either, so there is nothing to fall back TO.
        TailoredDistribution::PoolWide
    }
    async fn current_mode(&self, _miner_address: &AddressId) -> Option<bp_common::StreamKind> {
        // No mode gate wired: "no answer" leaves a session's plan alone.
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
    /// Latest pool-wide `distribution_id` published (0 = none yet).
    /// Connections watch this and push the fresh distribution to every
    /// negotiated JDC.
    dist_watch: tokio::sync::watch::Sender<u64>,
    /// Nudges the publisher out of its interval sleep — settlement
    /// invalidation (ext 0x0003/Implementation Notes) must be followed by an
    /// immediate publish.
    refresh: Arc<tokio::sync::Notify>,
}

/// Settlement hook (ext 0x0003/Implementation Notes): a booked block
/// invalidates every published distribution at once; the publisher then pushes
/// a fresh one immediately. Handed to the block-booking sink via
/// [`StratumV2JdpServer::distribution_handle`].
#[derive(Clone)]
pub struct DistributionInvalidationHandle {
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    refresh: Arc<tokio::sync::Notify>,
}

impl DistributionInvalidationHandle {
    /// ext 0x0003/Implementation Notes settlement invalidation + forced fresh
    /// publish.
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

    /// The ext 0x0003/Implementation Notes settlement hook for the
    /// block-booking sink.
    pub fn distribution_handle(&self) -> DistributionInvalidationHandle {
        DistributionInvalidationHandle {
            bridge: self.inner.bridge.clone(),
            refresh: self.inner.refresh.clone(),
        }
    }

    /// The pool-wide publisher (ext 0x0003/Update Policy): builds the current
    /// distribution on the interval (and forced after a settlement),
    /// publishes it into the bridge, and nudges every connection via
    /// the watch channel. Skips a tick when the settlement identity is
    /// unchanged — the wire stays quiet while the window is quiet.
    fn spawn_distribution_publisher(&self, interval: Duration) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last_fingerprint: Option<[u8; 32]> = None;
            // A forced pass (settlement) that aborts before publishing MUST
            // stay owed: `last_fingerprint` is what this task last published,
            // not what the registry holds, and after a settlement the registry
            // holds nothing usable. Skipping as "unchanged" would leave 0x0003
            // unoffered until the window's weights move.
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
                    // No template yet / PPLNS build failed. Retry on the
                    // next tick with the debt still owed.
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
                // Only now is a forced republish actually discharged.
                force_pending = false;
                let _ = inner.dist_watch.send(distribution_id);
                debug!(
                    distribution_id,
                    "jdp publisher: pool-wide distribution published"
                );
            }
        });
    }

    /// Per-connection task. The accept loop on the dedicated JDP port
    /// calls this for every accepted socket.
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
                // SV2 Overview/SetupConnection.Error: the error is sent "prior
                // to closing the connection". Read the request before the
                // write consumes the batch, act on it after, so the client
                // still receives the frame telling it why.
                let disconnect = outcome.events.iter().find_map(|e| match e {
                    JdpSessionEvent::Disconnect { reason } => Some(reason.clone()),
                    _ => None,
                });
                // Register declared jobs in the bridge BEFORE the frames go
                // out: once `DeclareMiningJobSuccess` is on the wire, the JDC's
                // separate mining connection may send `SetCustomMiningJob` for
                // that token, and everything backing the job (declaration and
                // distribution reference, see ext 0x0003/distribution_id TLV
                // Field) lives only in the bridge entry. A miss answers
                // `invalid-mining-job-token`, which a JDC treats as fatal. An
                // entry whose Success frame fails to send just expires unused.
                // It also has to precede `fan_out_events`.
                register_bridge_entries(&state, &bridge, session_id, &outcome.events);
                if let Err(err) = write_jdp_outbound_frames(&mut writer, outcome.outbound).await {
                    warn!("jdp {session_id_hex} write: {err:?}");
                    break;
                }
                if let Some(reason) = disconnect {
                    // A refused `SetupConnection` (its Error frame was written
                    // above) or a refused allocate, for which SV2 defines no
                    // error frame, so the close IS the answer.
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

    // On disconnect: evict all of this JDP-session's bridge entries so
    // the mining server doesn't keep stale `RegisteredDeclaredJob`s.
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

/// Dispatch one inbound JDP frame to the matching `handle_*` function.
/// Resolves async-hook context per-variant before calling the (sync)
/// handler.
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
            // ext 0x0003/SetPayoutDistribution makes `SetPayoutDistribution`
            // the mandatory first push after this exchange — only offer 0x0003
            // when one is actually publishable right now.
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
                // SV2 has no `AllocateMiningJobToken.Error`; closing triggers
                // the SV2 JDP/Job Declarator Client fallback instead of an
                // indefinite wait.
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
                // Couldn't resolve a miner address — drop silently
                // (return default outcome, no error frame).
                AllocateOutcome::Ignored => JdpHandlerOutcome::default(),
            }
        }
        InboundJdpFrame::DeclareMiningJob(input) => {
            // A declaration is authorised before it is judged: the snapshot,
            // the partition and the node validation below are all expensive.
            // One allocate token authorises exactly ONE declaration attempt
            // (SV2 JDP/Full-Template Mode: a token identifies "some unique
            // work"), so resolving and spending it is one act, `take_active`.
            //
            // The session-level refusals need no token and come first, so a
            // misconfigured connection gets one consistent error code.
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
            // Computed once for both the node and the handler: it clones the
            // raw bytes of every known transaction, megabytes on mainnet.
            let partition = partition_against_template(&input.wtxid_list, &template_txs);
            // SV2 JDP/Job Declarator Server: the node judges the declaration
            // before the pool commits to it. Known transactions are supplied,
            // so the node reports only what it truly lacks. A rejection
            // returns before anything is registered, so nothing rolls back.
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
            // The mode of the address THIS TOKEN belongs to, not of whichever
            // address allocated last: one session may hold tokens for several
            // addresses, since the allocate carries the address.
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
            // Second leg: the JDC filled the gaps, so the node now sees the
            // whole set. Asking again is required, or an invalid transaction
            // could hide among the ones the pool was missing.
            //
            // Gated on a wired validator before the merge, which clones the
            // whole declared transaction set. The `request_id` lookup is also
            // here, before any expensive work: a `Success` for a request the
            // session never made gets no node round-trip. `None` from any step
            // means nothing to re-validate; the handler then refuses the frame
            // on its own grounds.
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
                    // Drop the pending declaration with it, otherwise the
                    // session keeps a half-finished round-trip.
                    state.pending_declarations.take(input.request_id);
                    return refusal;
                }
            }
            let current_prev_hash = hooks.prev_hash_provider.current_prev_hash().await;
            // ext 0x0003/Grace Window + Implementation Notes are judged when
            // the declaration is ACCEPTED, so re-resolve the pending declare's
            // id to see a supersession or settlement during the round-trip.
            let pending_distribution_id = state
                .pending_declarations
                .get(input.request_id)
                .and_then(|p| p.input.distribution_id);
            let distribution =
                resolve_distribution_acceptance(bridge, session_id, pending_distribution_id);
            // Same rule as the declare above: the miner is the one the pending
            // declaration was accepted for, which `accept_declaration` reads
            // back out of it.
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
        // The handler matches the solution to a declaration and reads the
        // miner off that same declaration, so there is nothing to resolve
        // here.
        InboundJdpFrame::PushSolution(input) => handle_push_solution(state, &input),
    }
}

/// Hand a declaration to the node, if one is wired, and turn a rejection into
/// the frame to answer with.
///
/// Shared by both legs of the round-trip. The second leg must not be skipped,
/// or an invalid transaction could hide among the ones the pool was missing.
///
/// `None` means nothing objected: the node accepted, or (declare leg only) it
/// still wants transactions, which the round-trip then fetches (see
/// [`JobVerdict::NeedsTransactions`]). Whether a validator is wired is the
/// caller's gate, because both callers have expensive work to skip with it.
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
        // Nothing is left to fetch and the node still cannot see the whole
        // set, e.g. a transaction whose bytes do not hash to its declared wtxid.
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

/// Which leg of the SV2 JDP/ProvideMissingTransactions round-trip a node
/// verdict answers — it decides whether "the node lacks transactions" is a
/// question still open or a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclarationLeg {
    /// The `DeclareMiningJob` itself. Whatever the node lacks, the pool can
    /// still ask the JDC for.
    Declare,
    /// `ProvideMissingTransactions.Success`: the JDC has supplied everything
    /// it was asked for, so there is nothing left to fetch.
    Completed,
}

/// Resolve an ext 0x0003/distribution_id TLV Field reference
/// against the bridge's acceptance window, under the declare path's session
/// scope. `None` TLV → `None` (the handler decides whether that's an error —
/// it is, on a negotiated connection).
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

/// Fan out [`JdpSessionEvent`]s: SetupComplete is informational,
/// TokenAllocated and JobDeclared were registered in the bridge before the
/// outbound write, BlockSubmissionCandidate goes to the
/// block-submission sink. Disconnect is not handled here — the
/// connection loop reads it off the outcome and breaks after the write.
async fn fan_out_events(events: Vec<JdpSessionEvent>, hooks: &JdpServerHooks) {
    for event in events {
        match event {
            JdpSessionEvent::SetupComplete => {}
            // Already registered before the outbound write by
            // `register_bridge_entries`; do not register here as well.
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
            // Acted on in the connection loop, which owns the socket —
            // it breaks once the rejection frame is written.
            JdpSessionEvent::Disconnect { .. } => {}
        }
    }
}

/// Serialise + write each [`JdpOutboundFrame`] through the noise
/// stream. Same pattern as `server::write_outbound_frames`, plus the
/// hand-framed path for ext 0x0003 (`stratum-core` has no type for it).
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
///
/// A value rather than inline match arms, because several cases share an
/// outcome while only one of them is a fault; as a value each reason is
/// testable on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllocationDisposition<'a> {
    /// Base-protocol Coinbase-only: the allocate is the pool's ONLY record of
    /// this token (SV2 JDP/Coinbase-only Mode — that mode never declares), so
    /// the mining side resolves it here and holds the custom job's coinbase to
    /// this script.
    Register { payout_script: &'a [u8] },
    /// Full-Template: the declaration is the record. Registering the allocate
    /// token too would let the JDC skip `DeclareMiningJob`, where the node
    /// validates its transaction set (SV2 JDP/Job Declarator Server).
    LeftToTheDeclaration,
    /// ext 0x0003: ext 0x0003/Negotiation requires the allocate's outputs to
    /// be empty, so there is no designated script; the job is judged by the
    /// ext 0x0003/Output Verification recompute instead.
    ///
    /// Still registered, as [`AllocationKind::JudgedByDistribution`], so the
    /// mining side knows the token and binds the miner address and chain tip.
    JudgedByTheDistribution,
    /// A base-protocol allocate that designated nothing. The pool built that
    /// blob, so this is a pool fault, and the client only ever sees
    /// `invalid-mining-job-token`.
    DesignatedNothing,
}

/// Which of the four an allocate token is. Pure and total so every combination
/// can be asserted without a connection.
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

/// Register declared jobs and allocate tokens in the bridge so the mining
/// server's `SetCustomMiningJob` handler can find them. Runs after
/// `dispatch_jdp_inbound`, when `state.declared_jobs` holds the fresh entry.
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
            // Coinbase-only mode never declares (SV2 JDP/Coinbase-only Mode),
            // so the allocate is the mining side's only record. The
            // negotiation flag is asked explicitly, not inferred from
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
            // Neither reaches the bridge. Spelled out rather than swallowed
            // by a wildcard so a new event has to be classified here.
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

    /// Minimal ext 0x0003/SetPayoutDistribution registry entry: one weight-9
    /// miner slot behind a weight-1 pool output.
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

    /// The no-op hook designates one payout output like production does, so
    /// the base-protocol path it stands in for stays testable.
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

    /// ext 0x0003/Negotiation: with ext 0x0003 negotiated the
    /// `SetPayoutDistribution` push replaces the base output semantics —
    /// `coinbase_tx_outputs` in `AllocateMiningJobToken.Success` MUST be
    /// empty.
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
                // SV2 JDP/AllocateMiningJobToken.Success: one designated
                // payout output, 0 sats.
                let outputs: Vec<bitcoin::TxOut> =
                    bitcoin::consensus::deserialize(coinbase_outputs).expect("outputs decode");
                assert_eq!(outputs.len(), 1);
                assert_eq!(outputs[0].value, bitcoin::Amount::ZERO);
            }
            _ => panic!("expected AllocateMiningJobTokenSuccess"),
        }
    }

    // ── SV2 JDP/Job Declarator Server node-side validation of declared jobs ───

    /// The marker the node gate stamps on its own rejections, to tell them
    /// apart from ordinary handler errors.
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

    /// Stands in for bitcoin-core: answers with whatever verdicts the test
    /// wants, one per call and `Accepted` once they run out, and records that
    /// it was actually consulted.
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

    /// Issue a real token to `ADDR` on this session; the dispatch spends it
    /// before anything else.
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

    /// A node rejection answers `DeclareMiningJob.Error` and registers
    /// nothing, so no shares are paid for a job the node calls invalid.
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

    /// Without a validator wired, declarations are taken on the JDC's word:
    /// the gate is opt-in.
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

    /// `NeedsTransactions` is not a rejection: the node simply cannot judge
    /// yet. The pool's own ProvideMissingTransactions round-trip has to run.
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

    /// An allocate token authorises ONE declaration. The second one on the
    /// same token is refused `invalid-mining-job-token` before the node is
    /// asked. A conformant JDC uses one token per `DeclareMiningJob` anyway.
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

    /// A `ProvideMissingTransactions.Success` answering a request the session
    /// never made does not reach the node: that leg carries no token, so the
    /// `request_id` is its only authorisation.
    ///
    /// Both directions: the matching `request_id` MUST reach the node, so the
    /// test cannot pass with the second-leg validation removed.
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

        // The declare leg: no template txs are wired, so the single declared
        // wtxid is missing and a round-trip goes out.
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

        // Wrong request_id, right position count: no node call, no frame,
        // and the round-trip is still in flight afterwards.
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

    /// On the second leg there is nothing left to fetch, so a node that still
    /// lacks transactions has not validated the declaration — it must be
    /// refused `missing-txs`, not accepted.
    ///
    /// The node resolves a supplied transaction only by the wtxid it hashes
    /// to, so bytes that do not match their declared position stay "missing";
    /// nothing else compares them to the wtxids.
    ///
    /// Both directions: the same round-trip with the node accepting on the
    /// second leg is NOT refused, so this cannot pass on a refusal that comes
    /// from somewhere else.
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

    /// A declaration the session's own shape refuses costs no token, so a
    /// misconfigured connection keeps reporting the same, real reason.
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

    /// ext 0x0003/SetPayoutDistribution makes `SetPayoutDistribution` the
    /// mandatory first push after the extensions exchange — so 0x0003 is only
    /// offered while a pool-wide distribution is actually publishable.
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

        // No distribution published yet → the extension is not offered.
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

        // With a publishable pool-wide distribution the offer stands.
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

    /// The declare's mode is looked up for the address of the TOKEN it names,
    /// not for whichever address allocated last on the connection.
    ///
    /// Nothing binds a JDP session to a single payout address, so judging by
    /// the session's latest address would refuse A's correct plan against B's
    /// mode with `stale-payout-distribution`, which a JDC treats as fatal.
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
        // SV2 JDP/AllocateMiningJobToken rate-limits token issuance to 1/s per
        // connection. B allocates LAST, so a session-scoped answer would name
        // B.
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

        // …and B's token resolves to B, so a constant or first-token answer
        // cannot pass.
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

        // And a token nobody was issued has no address to ask about — the
        // dispatch refuses it before it asks anything.
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

    /// The denial is readable without taking the write lock, since a session
    /// awaiting its mode asks once per frame.
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

    /// The ext 0x0003/SetPayoutDistribution wire form mirrors the registry
    /// entry: weights ride in the TxOut amount field, dust limits and
    /// additional outputs pass through unchanged.
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

    /// `register_bridge_entries` pulls the declared-job
    /// payload out of the session state and writes a
    /// `RegisteredDeclaredJob` into the cross-server bridge.
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

    /// Both Coinbase-only allocates reach the mining side, each saying which
    /// kind it is; a base-protocol allocate that designated nothing registers
    /// nothing.
    ///
    /// Two sessions on purpose: the 0x0003 case is decided by
    /// `state.negotiated_extensions`, not by the event, so it needs a
    /// negotiated session.
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
                // Base protocol with no designated output: the pool built a
                // blob it cannot hold a coinbase to. Still nothing to register.
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
                // ext 0x0003/Negotiation requires the outputs empty — this is
                // the conformant shape.
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
        // The ext 0x0003 allocate registers too, as its own kind, so the
        // mining side binds miner address and chain tip without the
        // SV2 JDP/AllocateMiningJobToken.Success output test standing in for
        // ext 0x0003/Output Verification.
        let ext = r
            .allocation_ref(&negotiated, 1_000)
            .expect("an ext 0x0003 allocate is still a token the pool issued");
        assert_eq!(ext.kind, AllocationKind::JudgedByDistribution);
        assert_eq!(ext.miner_address.as_str(), ADDR);
        assert_eq!(ext.jdp_session_id, 43);
    }

    /// All eight combinations; only one of them is a fault.
    ///
    /// Key row: `(script: None, Coinbase-only, negotiated)` is NOT a fault.
    /// ext 0x0003/Negotiation REQUIRES empty `coinbase_tx_outputs`, and those
    /// jobs are judged by the ext 0x0003/Output Verification recompute.
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
            // Coinbase-only + ext 0x0003: NOT a fault — ext 0x0003/Negotiation
            // empties the outputs and ext 0x0003/Output Verification does the
            // judging.
            (None, false, true, D::JudgedByTheDistribution),
            // A script present on a negotiated session is still the
            // distribution's to judge, not the weaker designated-output check.
            (Some(SCRIPT), false, true, D::JudgedByTheDistribution),
            // Full-Template: the declaration is the record. Registering would
            // let the JDC skip SV2 JDP/Job Declarator Server validation.
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
