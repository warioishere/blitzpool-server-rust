// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 mining-port server: translator tasks fan templates out, one task per
//! connection runs Noise-XK and calls the pure handlers in [`crate::mining::client`].
//! Shares are judged against the template pinned on the job at send-time, so a
//! block change cannot reclassify an in-flight share (pool rule, not a spec MUST).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bitcoin::Network;
use bp_common::{AddressId, StreamKind};
use bp_mining_job::{MiningJobCache, MiningJobError};
use bp_template_distribution::TemplateUpdate;
use bp_vardiff::{Clock, SystemClock};
use stratum_core::binary_sv2::GetSize;
use stratum_core::mining_sv2::MESSAGE_TYPE_SET_CUSTOM_MINING_JOB;
use stratum_core::parsers_sv2::{
    message_type_to_name, parse_message_frame_with_tlvs, IsSv2Message,
};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::bridge::JdpDeclaredJobRegistry;
use crate::codec_common::{write_message, WriteError};
use crate::extensions::SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS;
use crate::extranonce::{ConnectionExtranonce, SharedExtranonceAllocator};
use crate::hooks::MiningServerHooks;
use crate::mining::client::{
    apply_template_broadcast, apply_vardiff_check, handle_close_channel,
    handle_open_extended_mining_channel, handle_open_standard_mining_channel,
    handle_request_extensions, handle_set_custom_mining_job, handle_setup_connection,
    handle_submit_shares_extended, handle_submit_shares_standard, handle_update_channel,
    HandlerOutcome, MiningJobInputs, MiningSessionState, OutboundFrame, PortConfig, SessionEvent,
};
use bp_template_distribution::{ActiveTemplate, TemplateAssembler, TemplateChange};

use crate::mining::translator::TemplateBroadcast;
use crate::noise::{accept_pool_noise, NoiseConfig, NoiseTcpWriteHalf};
use crate::server_codec::{decode_mining_inbound, encode_mining_outbound, InboundMiningFrame};

// ── ServerConfig ────────────────────────────────────────────────────

/// Pool-wide config slice for the mining server. Per-port settings
/// live in [`PortConfig`] and are passed at `accept_connection` time.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Must match the bitcoin-core deployment the addresses are parsed for.
    pub network: Network,
    /// Appended to the coinbase scriptSig after the BIP-34 height push,
    /// dropped when the 100-byte limit would be exceeded.
    pub pool_identifier: String,
    /// How long [`StratumV2MiningServer::shutdown`] waits for a translator
    /// before detaching it.
    pub shutdown_drain_timeout: Duration,
    /// Log every wire frame at DEBUG. Heavy, staging only; per-share detail
    /// lives behind [`Self::share_logs`].
    pub debug_messages: bool,
    /// Log the pool-internal submit→ack latency at INFO, one line per share.
    pub log_submit_latency: bool,
    /// Per-share diagnostics at DEBUG, separate from [`Self::debug_messages`]
    /// so share difficulty can be tailed without the raw frame dumps.
    pub share_logs: bool,
}

impl ServerConfig {
    pub fn defaults_for(network: Network) -> Self {
        Self {
            network,
            pool_identifier: "/blitzpool-rust/".to_string(),
            shutdown_drain_timeout: Duration::from_secs(5),
            debug_messages: false,
            log_submit_latency: false,
            share_logs: false,
        }
    }
}

// ── Constants ───────────────────────────────────────────────────────

/// Broadcast-channel capacity for the translator → per-connection
/// fan-out. Lagged subscribers see `RecvError::Lagged` and recover
/// via the `current_template` snapshot on their next iteration.
const TEMPLATE_BROADCAST_CAPACITY: usize = 32;

// ── StratumV2MiningServer ───────────────────────────────────────────

/// Cheap-to-clone handle. [`Self::shutdown`] is the only clean way to stop
/// the translators.
#[derive(Clone)]
pub struct StratumV2MiningServer {
    inner: Arc<Inner>,
}

struct Inner {
    server_config: Arc<ServerConfig>,
    noise_config: NoiseConfig,
    hooks: MiningServerHooks,
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    // PPLNS stream (PPLNS-autoscaled) — every connection boots here before
    // its payout mode is resolved.
    template_tx: broadcast::Sender<TemplateBroadcast>,
    current_template: Arc<Mutex<Option<Arc<ActiveTemplate>>>>,
    // Fixed-reservation alt streams (Solo / GroupSolo / Blockparty) keyed by
    // StreamKind — a connection switches onto one when its OpenChannel address
    // resolves to that mode. Each fed by its own translator off its TDP handle.
    alt_streams: HashMap<StreamKind, AltStream>,
    // POOL-WIDE extranonce-prefix allocator, shared by every port. Standard
    // channels cannot roll their own extranonce, and ports share a coinbase,
    // so a second allocator would hand out the same prefixes and two miners
    // would mine byte-identical work.
    extranonce: SharedExtranonceAllocator,
    // Pool-wide cache of built MiningJobs, shared with every SV2 and SV1
    // server: one coinbase build per (template, payout set, slot size) for
    // the whole pool rather than per channel per broadcast.
    job_cache: Arc<MiningJobCache>,
    cancel: CancellationToken,
    translator_join: Mutex<Option<JoinHandle<()>>>,
    alt_translator_joins: Mutex<Vec<JoinHandle<()>>>,
}

/// One fixed-reservation alt template stream: the broadcast sender per-connection
/// tasks subscribe to + the current-template snapshot a freshly-routed connection
/// boots from. Mirrors the PPLNS stream's `template_tx` / `current_template`.
struct AltStream {
    template_tx: broadcast::Sender<TemplateBroadcast>,
    current_template: Arc<Mutex<Option<Arc<ActiveTemplate>>>>,
}

/// A single connection's claim on one alt stream — its own broadcast receiver
/// plus the snapshot to boot from. The per-connection task holds a
/// `HashMap<StreamKind, AltStreamHandle>` and `remove`s the matching entry when
/// it swaps onto that stream.
struct AltStreamHandle {
    rx: broadcast::Receiver<TemplateBroadcast>,
    initial: Option<Arc<ActiveTemplate>>,
}

impl StratumV2MiningServer {
    /// `initial_snapshot` must be taken alongside `updates_rx`: the translator
    /// applies it first, so the first OpenChannel sees a template even when the
    /// bootstrap pair was broadcast before this subscriber existed.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        server_config: ServerConfig,
        noise_config: NoiseConfig,
        updates_rx: broadcast::Receiver<TemplateUpdate>,
        initial_snapshot: bp_template_distribution::TemplateSnapshot,
        alt_streams: Vec<(
            StreamKind,
            broadcast::Receiver<TemplateUpdate>,
            bp_template_distribution::TemplateSnapshot,
        )>,
        hooks: MiningServerHooks,
        bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
        extranonce: SharedExtranonceAllocator,
        job_cache: Arc<MiningJobCache>,
    ) -> Self {
        let server_config = Arc::new(server_config);
        let (template_tx, _) = broadcast::channel(TEMPLATE_BROADCAST_CAPACITY);
        let current_template = Arc::new(Mutex::new(None::<Arc<ActiveTemplate>>));
        let cancel = CancellationToken::new();

        let translator_join = tokio::spawn(run_translator(
            updates_rx,
            initial_snapshot,
            template_tx.clone(),
            current_template.clone(),
            job_cache.clone(),
            cancel.clone(),
        ));
        // One translator per alt stream, each off its own TDP handle.
        let mut alt_map = HashMap::with_capacity(alt_streams.len());
        let mut alt_joins = Vec::with_capacity(alt_streams.len());
        for (kind, alt_updates_rx, alt_initial_snapshot) in alt_streams {
            let (alt_tx, _) = broadcast::channel(TEMPLATE_BROADCAST_CAPACITY);
            let alt_current = Arc::new(Mutex::new(None::<Arc<ActiveTemplate>>));
            alt_joins.push(tokio::spawn(run_translator(
                alt_updates_rx,
                alt_initial_snapshot,
                alt_tx.clone(),
                alt_current.clone(),
                job_cache.clone(),
                cancel.clone(),
            )));
            alt_map.insert(
                kind,
                AltStream {
                    template_tx: alt_tx,
                    current_template: alt_current,
                },
            );
        }

        Self {
            inner: Arc::new(Inner {
                server_config,
                noise_config,
                hooks,
                bridge,
                template_tx,
                current_template,
                alt_streams: alt_map,
                extranonce,
                job_cache,
                cancel,
                translator_join: Mutex::new(Some(translator_join)),
                alt_translator_joins: Mutex::new(alt_joins),
            }),
        }
    }

    /// Snapshot of the latest assembled template. `None` until the
    /// translator pairs its first `NewTemplate` + `SetNewPrevHash`.
    pub fn current_template(&self) -> Option<Arc<ActiveTemplate>> {
        self.inner
            .current_template
            .lock()
            .expect("current_template mutex poisoned")
            .clone()
    }

    /// Subscribe to template broadcasts. Each subscriber sees its own
    /// copy. Used by tests + the per-connection task; production
    /// `accept_connection` does this internally.
    pub fn subscribe_templates(&self) -> broadcast::Receiver<TemplateBroadcast> {
        self.inner.template_tx.subscribe()
    }

    /// Extranonce prefixes held across every server sharing the allocator.
    /// Tracks live SV2 channels; a count that only climbs means a release
    /// path is not firing.
    pub fn allocated_prefix_count(&self) -> usize {
        self.inner.extranonce.allocated_count()
    }

    /// Spawn a per-connection task for a socket classified as SV2 mining; it
    /// runs the Noise-XK handshake before the protocol loop.
    pub fn accept_connection(&self, socket: TcpStream, port_config: PortConfig) -> JoinHandle<()> {
        let server_config = self.inner.server_config.clone();
        let noise_config = self.inner.noise_config.clone();
        let hooks = self.inner.hooks.clone();
        let bridge = self.inner.bridge.clone();
        let template_rx = self.inner.template_tx.subscribe();
        let initial_template = self
            .inner
            .current_template
            .lock()
            .expect("current_template mutex poisoned")
            .clone();
        // Per-connection handle on every alt stream: a fresh broadcast
        // subscription + the current-template snapshot. The connection swaps
        // onto exactly one of these (if any) once its mode resolves.
        let alt_streams: HashMap<StreamKind, AltStreamHandle> = self
            .inner
            .alt_streams
            .iter()
            .map(|(kind, alt)| {
                let rx = alt.template_tx.subscribe();
                let initial = alt
                    .current_template
                    .lock()
                    .expect("alt current_template mutex poisoned")
                    .clone();
                (*kind, AltStreamHandle { rx, initial })
            })
            .collect();
        let cancel = self.inner.cancel.clone();
        let extranonce = ConnectionExtranonce::new(self.inner.extranonce.clone());
        let job_cache = self.inner.job_cache.clone();
        let session_id = self.alloc_session_id();

        tokio::spawn(async move {
            let result = run_mining_connection(
                session_id,
                server_config,
                noise_config,
                port_config,
                hooks,
                bridge,
                template_rx,
                initial_template,
                alt_streams,
                extranonce,
                job_cache,
                socket,
                cancel,
            )
            .await;
            if let Err(err) = result {
                debug!("sv2 mining connection ended: {err}");
            }
        })
    }

    /// Cancel the translator + every running connection. Idempotent.
    /// First call awaits the translator's clean teardown up to
    /// [`ServerConfig::shutdown_drain_timeout`].
    pub async fn shutdown(&self) {
        self.inner.cancel.cancel();
        let handle = self
            .inner
            .translator_join
            .lock()
            .expect("translator_join mutex poisoned")
            .take();
        if let Some(h) = handle {
            let drain_timeout = self.inner.server_config.shutdown_drain_timeout;
            match tokio::time::timeout(drain_timeout, h).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => warn!("sv2 translator task panicked during shutdown: {err}"),
                Err(_) => warn!(
                    "sv2 translator didn't drain within {:?}, detaching",
                    drain_timeout
                ),
            }
        }
        let alt_handles = std::mem::take(
            &mut *self
                .inner
                .alt_translator_joins
                .lock()
                .expect("alt_translator_joins mutex poisoned"),
        );
        for h in alt_handles {
            let drain_timeout = self.inner.server_config.shutdown_drain_timeout;
            match tokio::time::timeout(drain_timeout, h).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => warn!("sv2 alt translator panicked during shutdown: {err}"),
                Err(_) => warn!("sv2 alt translator didn't drain within {drain_timeout:?}"),
            }
        }
    }

    /// Generate a session id from 4 OS-CSPRNG bytes interpreted as a
    /// big-endian u32. Formatted as `{:08x}` on the wire so logs +
    /// `client_entity.sessionId` carry the same 8-char hex string.
    fn alloc_session_id(&self) -> u32 {
        let mut bytes = [0u8; 4];
        getrandom::getrandom(&mut bytes).unwrap_or_default();
        u32::from_be_bytes(bytes)
    }
}

// ── Translator task ─────────────────────────────────────────────────

/// Assemble TDP updates into templates and re-broadcast them, keeping
/// `current_template` so a fresh connection boots without waiting for the
/// next TDP message. Exits on `cancel` or when `updates_rx` closes.
async fn run_translator(
    mut updates_rx: broadcast::Receiver<TemplateUpdate>,
    initial_snapshot: bp_template_distribution::TemplateSnapshot,
    template_tx: broadcast::Sender<TemplateBroadcast>,
    current_template: Arc<Mutex<Option<Arc<ActiveTemplate>>>>,
    job_cache: Arc<MiningJobCache>,
    cancel: CancellationToken,
) {
    let mut assembler = TemplateAssembler::<ActiveTemplate>::new();

    // Bootstrap from the TdpHandle snapshot: the startup template pair can
    // be broadcast before this subscriber exists, and the snapshot holds it
    // for replay.
    if let Some((active, change)) = assembler.bootstrap_from_snapshot(initial_snapshot) {
        // Wrap once; the snapshot store and every broadcast subscriber
        // then share this allocation via Arc refcounting.
        let active = Arc::new(active);
        {
            let mut guard = current_template
                .lock()
                .expect("current_template mutex poisoned");
            *guard = Some(active.clone());
        }
        let _ = template_tx.send(TemplateBroadcast {
            template: active,
            change,
        });
    }

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                debug!("sv2 translator shutting down");
                return;
            }
            update = updates_rx.recv() => {
                let update = match update {
                    Ok(u) => u,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("sv2 translator lagged {n} TDP updates");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!("sv2 translator: TDP source closed");
                        return;
                    }
                };
                if let Some(change) = assembler.apply(&update) {
                    if let Some(active) = assembler.current().cloned() {
                        let active = Arc::new(active);
                        {
                            let mut guard = current_template
                                .lock()
                                .expect("current_template mutex poisoned");
                            *guard = Some(active.clone());
                        }
                        // Job-cache aging heartbeat: lookups prune too, but
                        // this also runs when no channel is open, so old
                        // entries do not wait for the next lookup.
                        job_cache.prune_expired();
                        // Broadcast::send errors only when there are no
                        // subscribers — freshly-accepted connections
                        // pick up via the snapshot.
                        let _ = template_tx.send(TemplateBroadcast {
                            template: active,
                            change,
                        });
                    }
                }
            }
        }
    }
}

// ── Per-connection task ─────────────────────────────────────────────

/// Drive a single SV2 mining connection from Noise-accept to close.
#[allow(clippy::too_many_arguments)]
async fn run_mining_connection(
    session_id: u32,
    server_config: Arc<ServerConfig>,
    noise_config: NoiseConfig,
    port_config: PortConfig,
    hooks: MiningServerHooks,
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    mut template_rx: broadcast::Receiver<TemplateBroadcast>,
    initial_template: Option<Arc<ActiveTemplate>>,
    mut alt_streams: HashMap<StreamKind, AltStreamHandle>,
    extranonce: ConnectionExtranonce,
    job_cache: Arc<MiningJobCache>,
    socket: TcpStream,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let session_id_hex = format!("{session_id:08x}");

    // Noise-XK handshake. On failure log and return; the accept loop keeps
    // the per-IP failure counter.
    let noise = match accept_pool_noise(socket, &noise_config).await {
        Ok(n) => n,
        Err(err) => {
            debug!("sv2 connection {session_id_hex} noise handshake failed: {err:?}");
            return Ok(());
        }
    };
    tracing::info!(
        session_id_hex = %session_id_hex,
        "sv2 noise handshake complete, transport encrypted"
    );
    let (mut reader, mut writer) = noise.into_split();

    let mut state = MiningSessionState::<SystemClock>::new(SystemClock, session_id, port_config);
    // Per-share diagnostic logging is a server-level flag; carry it on
    // the session so the submit validators can gate their per-share
    // traces (`🎯 Extended share difficulty`) on it.
    state.share_logs = server_config.share_logs;
    let mut current_template = initial_template;

    let mut vardiff_tick = tokio::time::interval(Duration::from_millis(state.vardiff_interval_ms));
    vardiff_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the first immediate tick: one full interval before the first
    // check, as on SV1.
    vardiff_tick.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            frame_recv = reader.read_frame() => {
                // Mark when the inbound frame became available — used to
                // measure pool-internal submit→ack latency (gated by
                // `log_submit_latency`, emitted after the response write).
                let recv_at = std::time::Instant::now();
                let frame = match frame_recv {
                    Ok(f) => f,
                    Err(err) => {
                        debug!("sv2 connection {session_id_hex} read_frame: {err:?}");
                        break;
                    }
                };
                let mut sv2_frame = frame;
                let header = sv2_frame.header();
                let payload_len = sv2_frame.payload().len();
                let header_msg_type = header.msg_type();
                // ext 0x0003/Negotiation: a 0x0003 reference from a session
                // that never negotiated it MUST be rejected, so the TLV is
                // parsed rather than filtered out; the handler enforces the gate.
                let mut tlv_extensions = state.negotiated_extensions.clone();
                if header_msg_type == MESSAGE_TYPE_SET_CUSTOM_MINING_JOB
                    && !tlv_extensions.contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
                {
                    tlv_extensions.push(SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS);
                }
                let (any_message, mut tlvs) = match parse_message_frame_with_tlvs(
                    header,
                    sv2_frame.payload(),
                    &tlv_extensions,
                ) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        warn!("sv2 connection {session_id_hex} parse: {err:?}");
                        continue;
                    }
                };
                if server_config.debug_messages {
                    let msg_name = message_type_to_name(header_msg_type);
                    debug!(
                        session_id_hex = %session_id_hex,
                        "📨 RX: {msg_name} (0x{header_msg_type:02x}) - {payload_len} bytes"
                    );
                }
                let mut inbound = match decode_mining_inbound(any_message) {
                    Ok(Some(f)) => f,
                    Ok(None) => {
                        debug!("sv2 connection {session_id_hex} non-mining frame, ignoring");
                        continue;
                    }
                    Err(err) => {
                        warn!("sv2 connection {session_id_hex} decode: {err}");
                        continue;
                    }
                };
                // ext 0x0002 Worker-ID: the validator resolves the worker
                // name from these TLVs, and ignores them when ext 0x0002 is
                // not negotiated (ext 0x0002/Behavior Based on Negotiation).
                if let InboundMiningFrame::SubmitSharesExtended(ref mut submit) = inbound {
                    submit.tlvs = tlvs.take().unwrap_or_default();
                }
                // ext 0x0003/distribution_id TLV Field.
                if let InboundMiningFrame::SetCustomMiningJob(ref mut custom) = inbound {
                    custom.distribution_id = tlvs
                        .as_deref()
                        .and_then(crate::extensions::parse_distribution_id_tlv);
                    // Re-resolve accounting per frame: a solo miner joining a
                    // group flips to Group-Solo without reconnecting. The
                    // template stream stays as routed at OpenChannel.
                    if let Some(address) = state.address.clone() {
                        state.accounting_stream =
                            hooks.payout_resolver.resolve_stream(&address);
                    }
                }
                // Per-share trace, gated by `share_logs`: it would flood at
                // production hashrate.
                if server_config.share_logs {
                    if let InboundMiningFrame::SubmitSharesExtended(ref submit) = inbound {
                        let mut ext_hex = String::with_capacity(submit.extranonce.len() * 2);
                        for b in submit.extranonce.iter() {
                            ext_hex.push_str(&format!("{b:02x}"));
                        }
                        debug!(
                            session_id_hex = %session_id_hex,
                            "📤 SubmitSharesExtended: channel={}, jobId={}, nonce=0x{:08x}, extranonce={}",
                            submit.channel_id, submit.job_id, submit.nonce, ext_hex
                        );
                    }
                }
                let is_submit =
                    matches!(inbound, InboundMiningFrame::SubmitSharesExtended(_));
                // The dispatch consumes the frame; the identity is kept for the
                // refusal log below.
                let open_identity = match &inbound {
                    InboundMiningFrame::OpenStandardMiningChannel(input, _) => {
                        Some(input.user_identity.clone())
                    }
                    InboundMiningFrame::OpenExtendedMiningChannel(input, _) => {
                        Some(input.user_identity.clone())
                    }
                    _ => None,
                };
                // The pool-wide extranonce allocator is locked INSIDE the
                // Open/Close dispatch arms only — the hot submit path never
                // touches it, so share validation across connections does
                // not serialize on one global mutex.
                let mut outcome = dispatch_inbound_frame(
                    &mut state,
                    inbound,
                    &extranonce,
                    &bridge,
                    SystemClock.now_ms(),
                );
                // SV2 Overview/SetupConnection.Error: the error is sent "prior
                // to closing the connection", so the disconnect is read here
                // and acted on only after the outbound write.
                let disconnect = outcome.events.iter().find_map(|e| match e {
                    SessionEvent::Disconnect { reason } => Some(reason.clone()),
                    _ => None,
                });
                if let (Some(user_identity), Some(error_code)) =
                    (&open_identity, open_channel_refusal(&outcome.outbound))
                {
                    warn!(
                        session_id_hex = %session_id_hex,
                        user_identity = %user_identity,
                        error_code,
                        "sv2 channel open refused"
                    );
                }
                let newly_opened_channel = outcome.events.iter().find_map(|e| match e {
                    SessionEvent::ChannelOpened {
                        channel_id, kind, ..
                    } => Some((*channel_id, *kind)),
                    _ => None,
                });
                // One-time stream routing at OpenChannel, before the initial
                // job is built. `state.stream` is set ONLY when the swap
                // succeeds, so submits never route to a stream whose
                // template_id the job does not carry.
                if newly_opened_channel.is_some() {
                    if let Some(addr) = state.address.as_ref() {
                        // Must precede the routing: `resolve_stream` reads the
                        // mode gate this publishes, and a miss defaults to Solo.
                        // The only call per channel, so the refcount is taken once.
                        let address = addr.clone();
                        let worker = state.worker_name.clone();
                        hooks
                            .session_persistence
                            .register_session(
                                &session_id_hex,
                                address.as_str(),
                                &worker,
                                Some(session_user_agent(state.user_agent.as_deref())),
                            )
                            .await;
                        if state.stream.is_pplns() {
                            let resolved = hooks.payout_resolver.resolve_stream(&address);
                            // The accounting follows the mode even when the
                            // swap below fails: a Group-Solo miner left on the
                            // PPLNS template is still Group-Solo and must not
                            // reference the pool-wide distribution.
                            state.accounting_stream = resolved;
                            if !resolved.is_pplns() {
                                if let Some(alt) = alt_streams.remove(&resolved) {
                                    template_rx = alt.rx;
                                    current_template = alt.initial;
                                    state.stream = resolved;
                                    debug!(
                                        "sv2 connection {session_id_hex}: routed to {} template stream",
                                        resolved.as_label()
                                    );
                                } else {
                                    warn!(
                                        "sv2 connection {session_id_hex}: address resolved to alt \
                                         stream {} that isn't wired; staying on the PPLNS stream",
                                        resolved.as_label()
                                    );
                                }
                            } else {
                                // PPLNS is the boot stream: no swap, logged so
                                // PPLNS routing is visible too.
                                debug!(
                                    "sv2 connection {session_id_hex}: routed to {} template stream",
                                    resolved.as_label()
                                );
                            }
                        }
                    }
                }
                // Decide the customer extranonce override after routing (it
                // is Solo-only and needs `state.stream`) and before the open
                // response is written: a miner without `SetExtranoncePrefix`
                // reads its prefix only from the OpenSuccess frame.
                if let Some((channel_id, _)) = newly_opened_channel {
                    if let Some(prefix) =
                        maybe_apply_custom_extranonce(&mut state, &hooks, channel_id)
                    {
                        for frame in outcome.outbound.iter_mut() {
                            if let OutboundFrame::OpenExtendedMiningChannelSuccess {
                                channel_id: cid,
                                extranonce_prefix,
                                ..
                            } = frame
                            {
                                if *cid == channel_id {
                                    *extranonce_prefix = prefix.to_vec();
                                }
                            }
                        }
                    }
                }
                let write_start = std::time::Instant::now();
                if let Err(err) = write_outbound_frames(
                    &mut writer,
                    outcome.outbound,
                    server_config.debug_messages,
                    &session_id_hex,
                )
                .await
                {
                    warn!("sv2 connection {session_id_hex} write: {err:?}");
                    break;
                }
                if let Some(reason) = disconnect {
                    debug!("sv2 connection {session_id_hex} closing after setup rejection: {reason}");
                    break;
                }
                let write_us = write_start.elapsed().as_micros();
                if server_config.log_submit_latency && is_submit {
                    info!(
                        session_id_hex = %session_id_hex,
                        latency_us = recv_at.elapsed().as_micros(),
                        write_us,
                        "sv2 submit→ack pool-internal latency"
                    );
                }
                // A newly opened channel gets a job + matching `SetNewPrevHash`
                // from the cached template right after OpenChannelSuccess.
                // Otherwise the miner waits for the next template, and a
                // mempool refresh carries no prev_hash.
                if let (Some((channel_id, _kind)), Some(template)) =
                    (newly_opened_channel, current_template.clone())
                {
                    match resolve_template_mining_job_inputs(
                        &state.address,
                        &server_config,
                        &template,
                        &hooks,
                        &job_cache,
                    )
                    .await
                    {
                        Ok(Some(mining_job_inputs)) => {
                            let synthetic_broadcast = TemplateBroadcast {
                                template: template.clone(),
                                change: TemplateChange::NewBlock,
                            };
                            let init_outcome = apply_template_broadcast(
                                &mut state,
                                &synthetic_broadcast,
                                &mining_job_inputs,
                                SystemClock.now_ms(),
                                Some(channel_id),
                            );
                            if let Err(err) = write_outbound_frames(
                                &mut writer,
                                init_outcome.outbound,
                                server_config.debug_messages,
                                &session_id_hex,
                            )
                            .await
                            {
                                warn!(
                                    "sv2 connection {session_id_hex} initial-job write: {err:?}"
                                );
                                break;
                            }
                        }
                        Ok(None) => {
                            // OpenChannel stores the address synchronously,
                            // so this is not expected; log it.
                            warn!(
                                "sv2 connection {session_id_hex}: no address after OpenChannel"
                            );
                        }
                        Err(err) => {
                            warn!(
                                "sv2 connection {session_id_hex}: initial mining_job build \
                                 failed: {err}"
                            );
                        }
                    }
                }
                let has_accepted_share = outcome.events.iter().any(|e| {
                    matches!(e, SessionEvent::ShareAccepted { .. })
                });
                let fanout_start = std::time::Instant::now();
                apply_session_events(outcome.events, &session_id_hex, &state, &hooks).await;
                let fanout_us = fanout_start.elapsed().as_micros();
                // Inline vardiff after an accepted share up-adjusts an active
                // miner without waiting for the timer tick. Gated like SV1's
                // inline check: never more often than the configured interval.
                if has_accepted_share
                    && state.vardiff_cooldown_elapsed()
                    && run_vardiff_check(
                        &mut state,
                        &mut writer,
                        server_config.debug_messages,
                        &session_id_hex,
                        &hooks,
                    )
                    .await
                    .is_err()
                {
                    break;
                }
                // Full frame-arm time. Event fan-out and job sends run after
                // the ack, so a large `iter_us` with a small `latency_us`
                // means post-ack work delayed the next share's read.
                if server_config.log_submit_latency {
                    let iter_us = recv_at.elapsed().as_micros();
                    if iter_us >= 50_000 {
                        warn!(
                            session_id_hex = %session_id_hex,
                            iter_us,
                            fanout_us,
                            is_submit,
                            "sv2 slow loop iteration — fanout_us splits event fan-out vs the rest"
                        );
                    }
                }
            }
            broadcast_recv = template_rx.recv() => {
                let payload = match broadcast_recv {
                    Ok(p) => p,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                current_template = Some(payload.template.clone());
                // Build a MiningJob only once the connection has an address;
                // before OpenChannel there is nothing to send.
                let mining_job_inputs = match resolve_template_mining_job_inputs(
                    &state.address,
                    &server_config,
                    &payload.template,
                    &hooks,
                    &job_cache,
                )
                .await
                {
                    Ok(Some(j)) => j,
                    Ok(None) => continue,
                    Err(err) => {
                        warn!(
                            "sv2 connection {session_id_hex}: resolve_template_mining_job_inputs failed: {err}"
                        );
                        continue;
                    }
                };
                // Runs BEFORE the job build so the new job pins a changed
                // custom extranonce prefix.
                let mut en_frames = custom_extranonce_broadcast_frames(&mut state, &hooks);
                let mut outcome = apply_template_broadcast(
                    &mut state,
                    &payload,
                    &mining_job_inputs,
                    SystemClock.now_ms(),
                    None,
                );
                // SV2 Mining/SetExtranoncePrefix must precede the job it
                // applies to: announce the switch, then the job built with it.
                if !en_frames.is_empty() {
                    en_frames.append(&mut outcome.outbound);
                    outcome.outbound = en_frames;
                }
                if let Err(err) = write_outbound_frames(
                    &mut writer,
                    outcome.outbound,
                    server_config.debug_messages,
                    &session_id_hex,
                )
                .await
                {
                    warn!("sv2 connection {session_id_hex} write: {err:?}");
                    break;
                }
                apply_session_events(outcome.events, &session_id_hex, &state, &hooks).await;
            }
            _ = vardiff_tick.tick() => {
                // Timer-driven vardiff: the only trigger that fires when no
                // shares arrive, so it's what down-adjusts a quiet miner.
                if run_vardiff_check(
                    &mut state,
                    &mut writer,
                    server_config.debug_messages,
                    &session_id_hex,
                    &hooks,
                )
                .await
                .is_err()
                {
                    break;
                }
            }
        }
    }

    // A dropped TCP connection never sends `CloseChannel`, so every held
    // prefix is released here. The loop arms only `break`, never `?`, so
    // every exit reaches this.
    for channel_id in state.channels.keys() {
        extranonce.release(*channel_id);
    }

    hooks
        .session_persistence
        .deregister_session(&session_id_hex)
        .await;
    let _ = writer.shutdown().await;
    Ok(())
}

/// The error code of the `OpenMiningChannel.Error` in `outbound`, if the
/// dispatch refused a channel open.
fn open_channel_refusal(outbound: &[OutboundFrame]) -> Option<&str> {
    outbound.iter().find_map(|frame| match frame {
        OutboundFrame::OpenMiningChannelError { error_code, .. } => Some(error_code.as_str()),
        _ => None,
    })
}

/// The session's user agent, with an empty vendor recorded as the
/// `jd-client/sv2` placeholder the downstream report later refines.
fn session_user_agent(user_agent: Option<&str>) -> &str {
    user_agent.unwrap_or("jd-client/sv2")
}

// ── Dispatch + Outbound write helpers ───────────────────────────────

/// Swap an Extended channel onto `prefix` and return the
/// [`OutboundFrame::SetExtranoncePrefix`] the caller must write before the
/// channel's next job (SV2 Mining/SetExtranoncePrefix).
fn swap_channel_prefix(
    channel: &mut crate::mining::channel::ChannelState,
    channel_id: u32,
    prefix: &[u8; 4],
) -> Option<OutboundFrame> {
    if channel.kind != crate::mining::channel::ChannelKind::Extended
        || channel.extranonce_prefix.as_slice() == prefix.as_slice()
    {
        return None;
    }
    channel.extranonce_prefix = prefix.to_vec();
    Some(OutboundFrame::SetExtranoncePrefix {
        channel_id,
        extranonce_prefix: prefix.to_vec(),
    })
}

/// Put the customer's extranonce prefix on a freshly-opened Extended channel
/// and return it for the not-yet-written OpenSuccess. Solo only: elsewhere the
/// prefix is the sole work-partitioner across a shared coinbase, so a picked
/// value could overlap another miner's search.
fn maybe_apply_custom_extranonce<C: bp_vardiff::Clock>(
    state: &mut MiningSessionState<C>,
    hooks: &MiningServerHooks,
    channel_id: u32,
) -> Option<[u8; 4]> {
    // Looked up BEFORE the Solo gate so a non-Solo connection carrying an
    // override is logged rather than silently dropped.
    let prefix = {
        let address = state.address.as_ref()?;
        hooks
            .custom_extranonce
            .lookup(address.as_str(), &state.worker_name)?
    };
    if state.stream != StreamKind::Solo {
        warn!(
            worker = %state.worker_name,
            stream = ?state.stream,
            "custom-extranonce override set for a non-Solo connection; ignoring \
             (the override applies only while mining Solo)"
        );
        return None;
    }
    // Extended-only (the per-job prefix pin exists only there), checked BEFORE
    // arming so a Standard channel neither arms the watch nor drops it silently.
    let kind = match state.channels.get(&channel_id) {
        Some(c) => c.kind,
        None => return None,
    };
    if kind != crate::mining::channel::ChannelKind::Extended {
        warn!(
            worker = %state.worker_name,
            channel_id,
            "custom-extranonce is Extended-channel only; the override for this Solo \
             worker does not apply to its Standard channel"
        );
        return None;
    }
    // Arms the per-template re-check, so a later change lands at the next
    // template without a reconnect.
    state.uses_custom_extranonce = true;
    // Primary channel only: every channel resolves to the same override, so a
    // second channel with it would duplicate the search space.
    if Some(channel_id) != state.primary_channel {
        warn!(
            worker = %state.worker_name,
            channel_id,
            "custom-extranonce applies to the primary channel only; this additional \
             channel keeps its pool-allocated prefix"
        );
        return None;
    }
    let channel = state.channels.get_mut(&channel_id)?;
    // No `SetExtranoncePrefix` at open: a miner that does not implement it
    // reads its prefix only from the OpenSuccess.
    if channel.extranonce_prefix.as_slice() == prefix {
        return None;
    }
    channel.extranonce_prefix = prefix.to_vec();
    Some(prefix)
}

/// Per-template re-check of the custom extranonce, so a change lands without a
/// reconnect; in-flight shares stay valid because each job pins its prefix.
/// A removed override keeps the last value until reconnect. Connections
/// without an override cost one bool test.
fn custom_extranonce_broadcast_frames<C: bp_vardiff::Clock>(
    state: &mut MiningSessionState<C>,
    hooks: &MiningServerHooks,
) -> Vec<OutboundFrame> {
    if !state.uses_custom_extranonce {
        return Vec::new();
    }
    // Armed only on the Solo stream; the gate is re-asserted here too.
    if state.stream != StreamKind::Solo {
        return Vec::new();
    }
    let prefix = {
        let Some(address) = state.address.as_ref() else {
            return Vec::new();
        };
        match hooks
            .custom_extranonce
            .lookup(address.as_str(), &state.worker_name)
        {
            Some(p) => p,
            None => return Vec::new(),
        }
    };
    // Only the primary channel carries the override, as at channel-open
    // (`maybe_apply_custom_extranonce`).
    let Some(primary) = state.primary_channel else {
        return Vec::new();
    };
    let mut frames = Vec::new();
    if let Some(channel) = state.channels.get_mut(&primary) {
        if let Some(frame) = swap_channel_prefix(channel, primary, &prefix) {
            frames.push(frame);
        }
    }
    frames
}

/// Route an [`InboundMiningFrame`] to its `handle_*` function. The pool-wide
/// extranonce allocator is locked only in the Open/Close arms, never on
/// submit, so share validation does not serialize behind channel churn. A
/// prefix allocated for a failed open stays held until connection close.
pub(crate) fn dispatch_inbound_frame<C: bp_vardiff::Clock + Clone>(
    state: &mut MiningSessionState<C>,
    inbound: InboundMiningFrame,
    extranonce: &ConnectionExtranonce,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    now_ms: u64,
) -> HandlerOutcome {
    match inbound {
        InboundMiningFrame::SetupConnection(input) => handle_setup_connection(state, &input),
        InboundMiningFrame::RequestExtensions(input) => handle_request_extensions(state, &input),
        InboundMiningFrame::OpenStandardMiningChannel(input, _placeholder_prefix) => {
            let prefix = extranonce.allocate(state.next_channel_id);
            handle_open_standard_mining_channel(state, &input, prefix)
        }
        InboundMiningFrame::OpenExtendedMiningChannel(input, _placeholder_prefix) => {
            let prefix = extranonce.allocate(state.next_channel_id);
            handle_open_extended_mining_channel(state, &input, prefix)
        }
        InboundMiningFrame::UpdateChannel(input) => handle_update_channel(state, &input),
        InboundMiningFrame::CloseChannel(input) => {
            let outcome = handle_close_channel(state, &input);
            // A group-channel close removes every member
            // (SV2 Mining/CloseChannel), so release per closed channel.
            for ev in &outcome.events {
                if let SessionEvent::ChannelClosed { channel_id, .. } = ev {
                    extranonce.release(*channel_id);
                }
            }
            outcome
        }
        InboundMiningFrame::SubmitSharesStandard(input) => {
            handle_submit_shares_standard(state, &input, now_ms)
        }
        InboundMiningFrame::SubmitSharesExtended(input) => {
            handle_submit_shares_extended(state, &input, now_ms)
        }
        InboundMiningFrame::SetCustomMiningJob(input) => {
            let (bridge_job, allocation, distribution) = {
                let guard = bridge.read().expect("bridge RwLock poisoned");
                // Projection precomputed at register time (address, declared
                // tip, binding, distribution reference), so the lock covers
                // only a map lookup and a clone.
                let bridge_job = guard.job_ref(&input.mining_job_token);
                // Coinbase-only mode never declares
                // (SV2 JDP/Coinbase-only Mode), so the allocate is the only
                // record of its token.
                let allocation = guard
                    .allocation_ref(&input.mining_job_token, now_ms)
                    .cloned();
                // ext 0x0003/Grace Window: a frame TLV (Coinbase-only) has no
                // declaration behind it and resolves by owner address; an
                // inherited one (Full-Template) must resolve under the JDP
                // session that accepted it.
                let distribution = crate::bridge::resolve_distribution_reference(
                    input.distribution_id,
                    bridge_job.as_ref(),
                    state
                        .negotiated_extensions
                        .contains(&crate::extensions::SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS),
                )
                .map(|reference| {
                    let scope = match reference {
                        crate::bridge::DistributionReference::FromFrame { .. } => {
                            match state.address.as_ref() {
                                Some(addr) => crate::bridge::DistributionScope::MinerAddress(addr),
                                None => crate::bridge::DistributionScope::JdpSession(0),
                            }
                        }
                        crate::bridge::DistributionReference::FromDeclaration {
                            jdp_session_id,
                            ..
                        } => crate::bridge::DistributionScope::JdpSession(jdp_session_id),
                    };
                    guard.distribution_acceptance(reference.distribution_id(), scope)
                });
                (bridge_job, allocation, distribution)
            };
            // Distributions are multi-use (ext 0x0003 push model) —
            // nothing to consume on acceptance.
            let outcome = handle_set_custom_mining_job(
                state,
                &input,
                bridge_job.as_ref(),
                allocation.as_ref(),
                distribution.as_ref(),
                now_ms,
            );
            // A token authorises exactly ONE custom job, consumed only on
            // SUCCESS so a stale-chain-tip retry still works. `classify_backing`
            // covers allocate-backed tokens too, which `bridge_job.is_some()`
            // misses. `declared_jobs` keeps the declaration for `PushSolution`.
            if matches!(
                outcome.outbound.first(),
                Some(OutboundFrame::SetCustomMiningJobSuccess { .. })
            ) {
                let mut guard = bridge.write().expect("bridge RwLock poisoned");
                match crate::bridge::classify_backing(bridge_job.as_ref(), allocation.as_ref()) {
                    Some(crate::bridge::TokenBacking::Declared(_)) => {
                        guard.consume_declared_job(&input.mining_job_token);
                    }
                    Some(crate::bridge::TokenBacking::BaseAllocation { .. })
                    | Some(crate::bridge::TokenBacking::DistributionAllocation(_)) => {
                        guard.consume_allocation(&input.mining_job_token);
                    }
                    // Unbacked tokens never reach a Success — the handler
                    // fails closed on them.
                    None => {}
                }
            }
            outcome
        }
    }
}

/// Encode and write every [`OutboundFrame`] through the Noise stream.
async fn write_outbound_frames(
    writer: &mut NoiseTcpWriteHalf,
    outbound: Vec<OutboundFrame>,
    debug_messages: bool,
    session_id_hex: &str,
) -> Result<(), WriteError> {
    for frame in outbound {
        let any_message = encode_mining_outbound(frame).map_err(WriteError::Codec)?;
        if debug_messages {
            let msg_type = any_message.message_type();
            let msg_name = message_type_to_name(msg_type);
            let payload_len = any_message.get_size();
            debug!(
                session_id_hex,
                "📤 TX: {msg_name} (0x{msg_type:02x}) - {payload_len} bytes"
            );
        }
        write_message(writer, any_message).await?;
    }
    Ok(())
}

/// Run a vardiff check and write the SetTarget; `Err` means drop the connection.
/// SetTarget alone is the complete SV2 difficulty change. No synthetic
/// `NewBlock` re-broadcast: its fake `SetNewPrevHash` retires all jobs and
/// makes firmware re-mine the identical header.
async fn run_vardiff_check(
    state: &mut MiningSessionState<SystemClock>,
    writer: &mut NoiseTcpWriteHalf,
    debug_messages: bool,
    session_id_hex: &str,
    hooks: &MiningServerHooks,
) -> Result<(), ()> {
    state.mark_vardiff_checked();
    let outcome = apply_vardiff_check(state);
    if let Err(err) =
        write_outbound_frames(writer, outcome.outbound, debug_messages, session_id_hex).await
    {
        warn!("sv2 connection {session_id_hex} vardiff write: {err:?}");
        return Err(());
    }
    apply_session_events(outcome.events, session_id_hex, state, hooks).await;
    Ok(())
}

/// Resolve payouts and pack the template's coinbase fields into
/// [`MiningJobInputs`]. `Ok(None)` before OpenChannel set an address, or when
/// no distribution could be built.
async fn resolve_template_mining_job_inputs(
    address: &Option<AddressId>,
    server_config: &ServerConfig,
    template: &ActiveTemplate,
    hooks: &MiningServerHooks,
    job_cache: &Arc<MiningJobCache>,
) -> Result<Option<MiningJobInputs>, MiningJobError> {
    let Some(addr) = address else {
        return Ok(None);
    };
    let resolved = hooks
        .payout_resolver
        .resolve_payouts(addr, template.coinbase_tx_value_remaining)
        .await;
    // No distribution means no job: a coinbase paying this one miner the whole
    // block is never the fallback. The channel keeps hashing what it holds,
    // as on SV1.
    if resolved.is_none() {
        return Ok(None);
    }
    Ok(Some(MiningJobInputs {
        network: server_config.network,
        payouts: resolved.entries,
        payouts_fingerprint: resolved.payouts_fingerprint,
        pool_identifier: server_config.pool_identifier.clone(),
        coinbase_prefix: template.coinbase_prefix.clone(),
        coinbase_tx_version: template.coinbase_tx_version,
        coinbase_tx_input_sequence: template.coinbase_tx_input_sequence,
        coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
        coinbase_tx_outputs: template.coinbase_tx_outputs.clone(),
        coinbase_tx_outputs_count: template.coinbase_tx_outputs_count,
        coinbase_tx_locktime: template.coinbase_tx_locktime,
        job_cache: job_cache.clone(),
    }))
}

/// Fan each [`SessionEvent`] out to its hook; no socket writes.
pub(crate) async fn apply_session_events(
    events: Vec<SessionEvent>,
    session_id_hex: &str,
    state: &MiningSessionState<SystemClock>,
    hooks: &MiningServerHooks,
) {
    apply_session_events_generic(events, session_id_hex, state, hooks).await;
}

/// Generic over the clock so unit tests can drive it with a `TestClock`.
pub(crate) async fn apply_session_events_generic<C: bp_vardiff::Clock>(
    events: Vec<SessionEvent>,
    session_id_hex: &str,
    state: &MiningSessionState<C>,
    hooks: &MiningServerHooks,
) {
    let address_str = state.address.as_ref().map(|a| a.as_str()).unwrap_or("");
    let worker_str = state.worker_name.as_str();

    for event in events {
        match event {
            SessionEvent::SetupComplete => {}
            // Acted on in the connection loop, which owns the socket —
            // it breaks once the rejection frame is written.
            SessionEvent::Disconnect { .. } => {}
            SessionEvent::ChannelOpened {
                channel_id,
                address,
                worker,
                kind,
            } => {
                let extranonce_size = state
                    .channels
                    .get(&channel_id)
                    .map(|c| c.extranonce_size)
                    .unwrap_or(0);
                let extranonce_prefix_len = state
                    .channels
                    .get(&channel_id)
                    .map(|c| c.extranonce_prefix.len())
                    .unwrap_or(0);
                let session_diff = state.session_difficulty.as_f64();
                tracing::info!(
                    session_id_hex,
                    channel_id,
                    address = %address.as_str(),
                    worker = %worker,
                    kind = ?kind,
                    extranonce_prefix_len,
                    extranonce_size,
                    session_diff,
                    "sv2 channel opened"
                );
                // Only the device-online event: `register_session` already
                // ran in the connection loop, before stream routing.
                hooks
                    .device_status_sink
                    .on_device_event(
                        address.as_str(),
                        &worker,
                        session_id_hex,
                        Some(session_user_agent(state.user_agent.as_deref())),
                        true,
                    )
                    .await;
            }
            SessionEvent::ChannelClosed { .. } => {
                if !address_str.is_empty() {
                    hooks
                        .device_status_sink
                        .on_device_event(
                            address_str,
                            worker_str,
                            session_id_hex,
                            Some(session_user_agent(state.user_agent.as_deref())),
                            false,
                        )
                        .await;
                }
            }
            SessionEvent::DifficultyChanged { .. } => {
                // Per channel, since SV2 difficulty is per channel.
                bp_metrics::record_stratum_difficulty_adjustment();
            }
            SessionEvent::ShareAccepted { channel_id, accept } => {
                // ext 0x0002 Worker-ID: a per-share worker name overrides the
                // channel default (ext 0x0002/Behavior Based on Negotiation).
                let effective_worker = accept
                    .effective_worker_name
                    .as_deref()
                    .unwrap_or(worker_str);
                let kind_label = match state.channels.get(&channel_id).map(|c| c.kind) {
                    Some(crate::mining::channel::ChannelKind::Standard) => "Standard",
                    Some(crate::mining::channel::ChannelKind::Extended) => "Extended",
                    None => "Unknown",
                };
                if accept.is_block_candidate {
                    tracing::info!(
                        session_id_hex,
                        channel_id,
                        address = %address_str,
                        worker = %effective_worker,
                        "🎉🎉🎉 BLOCK FOUND ({})!!! Difficulty: {:.2}",
                        kind_label,
                        accept.submission_difficulty.as_f64()
                    );
                } else if state.share_logs {
                    tracing::debug!(
                        session_id_hex,
                        channel_id,
                        address = %address_str,
                        worker = %effective_worker,
                        "✅ {} share accepted: seq={}, effective_diff={:.2}, submission_diff={:.2}",
                        kind_label,
                        0u32,
                        accept.effective_difficulty.as_f64(),
                        accept.submission_difficulty.as_f64()
                    );
                }
                hooks
                    .accepted_sink
                    .record_accepted(crate::shared_adapter::shared_accepted(
                        address_str,
                        effective_worker,
                        session_id_hex,
                        state.user_agent.as_deref(),
                        &accept,
                        // The per-session client row reports the whole
                        // connection's rate, a bundled rig's total included.
                        state.vardiff.values().map(|v| v.hash_rate()).sum::<f64>(),
                        state.channels.len() as u32,
                    ))
                    .await;
                if accept.is_block_candidate {
                    // `state.stream` was locked at OpenChannel, so it names
                    // the stream whose template the job used.
                    hooks
                        .block_sink
                        .submit_block(
                            &accept,
                            address_str,
                            effective_worker,
                            session_id_hex,
                            state.stream,
                        )
                        .await;
                }
            }
            SessionEvent::ShareRejected { channel_id, reject } => {
                let address_opt = state.address.as_ref().map(|a| a.as_str());
                let worker_opt = state.address.as_ref().map(|_| state.worker_name.as_str());
                let _ = channel_id;
                if let Some(share) = crate::shared_adapter::shared_rejected(
                    address_opt,
                    worker_opt,
                    session_id_hex,
                    reject.reason,
                    state.session_difficulty,
                ) {
                    hooks.rejected_sink.record_rejected(share).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::test_support::RecordingHooks;
    use crate::mining::client::SessionEvent;
    use crate::mining::submit::{RejectReason, ShareAccept, ShareReject};
    use bp_jobs_lifecycle::JobClassification;
    use bp_share::Difficulty;
    use bp_template_distribution::{NewTemplate, SetNewPrevHash};
    use bp_vardiff::TestClock;
    use std::sync::Arc;

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

    fn server_cfg() -> ServerConfig {
        ServerConfig::defaults_for(Network::Regtest)
    }

    fn _port_cfg() -> PortConfig {
        PortConfig {
            network: Network::Regtest,
            min_difficulty: Difficulty(0.00001),
            initial_difficulty: Difficulty(1024.0),
            target_shares_per_minute: 6.0,
            vardiff_interval_ms: 60_000,
            vardiff_silence_easing: false,
            job_lifecycle: bp_jobs_lifecycle::LifecycleConfig::DEFAULT,
        }
    }

    fn fresh_session_with_address() -> MiningSessionState<Arc<TestClock>> {
        let mut s = MiningSessionState::new(Arc::new(TestClock::new(0)), 1, _port_cfg());
        s.address = Some(AddressId::new(ADDR.to_string()).unwrap());
        s.worker_name = "wrk".to_string();
        s
    }

    // ── Custom extranonce apply (channel-open) ─────────────────────

    /// Test source returning a fixed prefix for exactly one (address, worker).
    struct FixedSource {
        address: String,
        worker: String,
        prefix: [u8; 4],
    }
    impl crate::hooks::CustomExtranonceSource for FixedSource {
        fn lookup(&self, address: &str, worker: &str) -> Option<[u8; 4]> {
            (address == self.address && worker == self.worker).then_some(self.prefix)
        }
    }

    fn hooks_with_override(address: &str, worker: &str, prefix: [u8; 4]) -> MiningServerHooks {
        let mut hooks = MiningServerHooks::no_op();
        hooks.custom_extranonce = Arc::new(FixedSource {
            address: address.to_string(),
            worker: worker.to_string(),
            prefix,
        });
        hooks
    }

    fn solo_session_with_extended_channel(
        channel_id: u32,
        prefix: Vec<u8>,
    ) -> MiningSessionState<Arc<TestClock>> {
        let mut s = fresh_session_with_address();
        s.stream = StreamKind::Solo;
        s.channels.insert(
            channel_id,
            crate::mining::channel::ChannelState::new_extended(
                channel_id,
                prefix,
                8,
                Difficulty(1024.0),
                [0xFF; 32],
                bp_jobs_lifecycle::LifecycleConfig::DEFAULT,
            ),
        );
        // First channel opened is the primary — the only one the override targets.
        s.primary_channel = Some(channel_id);
        s
    }

    /// Solo + Extended + override: the prefix is swapped and returned for the OpenSuccess.
    #[test]
    fn custom_extranonce_swaps_prefix_on_solo_extended() {
        const CUSTOM: [u8; 4] = [0xC0, 0xDE, 0xBA, 0xBE];
        let mut s = solo_session_with_extended_channel(7, vec![0x00, 0x00, 0x00, 0x05]);
        let hooks = hooks_with_override(ADDR, "wrk", CUSTOM);

        assert_eq!(
            maybe_apply_custom_extranonce(&mut s, &hooks, 7),
            Some(CUSTOM),
            "the applied prefix is handed back for the OpenSuccess"
        );
        // Channel now carries the custom prefix, so its next job pins it.
        assert_eq!(
            s.channels.get(&7).unwrap().extranonce_prefix,
            CUSTOM.to_vec()
        );
    }

    /// On a non-Solo stream the override is ignored and the prefix untouched.
    #[test]
    fn custom_extranonce_skips_non_solo_stream() {
        let mut s = solo_session_with_extended_channel(7, vec![0x00, 0x00, 0x00, 0x05]);
        s.stream = StreamKind::Pplns;
        let hooks = hooks_with_override(ADDR, "wrk", [0xC0, 0xDE, 0xBA, 0xBE]);
        assert!(maybe_apply_custom_extranonce(&mut s, &hooks, 7).is_none());
        assert_eq!(
            s.channels.get(&7).unwrap().extranonce_prefix,
            vec![0x00, 0x00, 0x00, 0x05]
        );
    }

    /// No override for this worker leaves the prefix untouched.
    #[test]
    fn custom_extranonce_skips_when_no_override() {
        let mut s = solo_session_with_extended_channel(7, vec![0x00, 0x00, 0x00, 0x05]);
        let hooks = hooks_with_override(ADDR, "different-worker", [0xC0, 0xDE, 0xBA, 0xBE]);
        assert!(maybe_apply_custom_extranonce(&mut s, &hooks, 7).is_none());
        assert_eq!(
            s.channels.get(&7).unwrap().extranonce_prefix,
            vec![0x00, 0x00, 0x00, 0x05]
        );
    }

    /// Already applied (channel holds the override) → no redundant frame.
    #[test]
    fn custom_extranonce_idempotent_when_already_applied() {
        const CUSTOM: [u8; 4] = [0xC0, 0xDE, 0xBA, 0xBE];
        let mut s = solo_session_with_extended_channel(7, CUSTOM.to_vec());
        let hooks = hooks_with_override(ADDR, "wrk", CUSTOM);
        assert!(maybe_apply_custom_extranonce(&mut s, &hooks, 7).is_none());
    }

    /// A Standard channel is skipped and must not arm the broadcast re-check.
    #[test]
    fn custom_extranonce_skips_standard_channel_without_arming() {
        let mut s = fresh_session_with_address();
        s.stream = StreamKind::Solo;
        s.channels.insert(
            7,
            crate::mining::channel::ChannelState::new_standard(
                7,
                vec![0x00, 0x00, 0x00, 0x05],
                Difficulty(1024.0),
                [0xFF; 32],
                bp_jobs_lifecycle::LifecycleConfig::DEFAULT,
            ),
        );
        let hooks = hooks_with_override(ADDR, "wrk", [0xC0, 0xDE, 0xBA, 0xBE]);
        assert!(maybe_apply_custom_extranonce(&mut s, &hooks, 7).is_none());
        assert!(
            !s.uses_custom_extranonce,
            "a Standard channel must not arm the broadcast re-check"
        );
    }

    // ── Custom extranonce arming + live change (broadcast path) ────

    /// An override at channel-open arms the broadcast re-check flag, so a later
    /// change lands live at the next template.
    #[test]
    fn channel_open_arms_broadcast_flag() {
        let mut s = solo_session_with_extended_channel(7, vec![0x00, 0x00, 0x00, 0x05]);
        assert!(!s.uses_custom_extranonce);
        let hooks = hooks_with_override(ADDR, "wrk", [0xC0, 0xDE, 0xBA, 0xBE]);
        let _ = maybe_apply_custom_extranonce(&mut s, &hooks, 7);
        assert!(
            s.uses_custom_extranonce,
            "an override at channel-open must arm the broadcast re-check"
        );
    }

    /// A connection without an override is never armed.
    #[test]
    fn channel_open_without_override_does_not_arm_flag() {
        let mut s = solo_session_with_extended_channel(7, vec![0x00, 0x00, 0x00, 0x05]);
        let hooks = hooks_with_override(ADDR, "different-worker", [0xC0, 0xDE, 0xBA, 0xBE]);
        let _ = maybe_apply_custom_extranonce(&mut s, &hooks, 7);
        assert!(
            !s.uses_custom_extranonce,
            "no override → flag stays false → broadcast path never touches this connection"
        );
    }

    /// An unarmed connection gets no frames even if an override exists.
    #[test]
    fn broadcast_frames_empty_when_not_armed() {
        let mut s = solo_session_with_extended_channel(7, vec![0x00, 0x00, 0x00, 0x05]);
        let hooks = hooks_with_override(ADDR, "wrk", [0xC0, 0xDE, 0xBA, 0xBE]);
        assert!(custom_extranonce_broadcast_frames(&mut s, &hooks).is_empty());
        assert_eq!(
            s.channels.get(&7).unwrap().extranonce_prefix,
            vec![0x00, 0x00, 0x00, 0x05]
        );
    }

    /// Armed + the override changed → swap the channel and emit the switch.
    #[test]
    fn broadcast_frames_switch_when_override_changed() {
        const NEW: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut s = solo_session_with_extended_channel(7, vec![0xC0, 0xDE, 0xBA, 0xBE]);
        s.uses_custom_extranonce = true;
        let hooks = hooks_with_override(ADDR, "wrk", NEW);
        let frames = custom_extranonce_broadcast_frames(&mut s, &hooks);
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            OutboundFrame::SetExtranoncePrefix {
                channel_id,
                extranonce_prefix,
            } => {
                assert_eq!(*channel_id, 7);
                assert_eq!(extranonce_prefix, &NEW.to_vec());
            }
            other => panic!("expected SetExtranoncePrefix, got {other:?}"),
        }
        assert_eq!(s.channels.get(&7).unwrap().extranonce_prefix, NEW.to_vec());
    }

    /// Armed but the override is unchanged → no redundant switch.
    #[test]
    fn broadcast_frames_empty_when_override_unchanged() {
        const CUSTOM: [u8; 4] = [0xC0, 0xDE, 0xBA, 0xBE];
        let mut s = solo_session_with_extended_channel(7, CUSTOM.to_vec());
        s.uses_custom_extranonce = true;
        let hooks = hooks_with_override(ADDR, "wrk", CUSTOM);
        assert!(custom_extranonce_broadcast_frames(&mut s, &hooks).is_empty());
    }

    /// Armed but the override was removed → the last value is kept.
    #[test]
    fn broadcast_frames_keep_last_value_when_override_removed() {
        let mut s = solo_session_with_extended_channel(7, vec![0xC0, 0xDE, 0xBA, 0xBE]);
        s.uses_custom_extranonce = true;
        let hooks = hooks_with_override(ADDR, "different-worker", [0x11, 0x22, 0x33, 0x44]);
        assert!(custom_extranonce_broadcast_frames(&mut s, &hooks).is_empty());
        assert_eq!(
            s.channels.get(&7).unwrap().extranonce_prefix,
            vec![0xC0, 0xDE, 0xBA, 0xBE]
        );
    }

    /// Armed but non-Solo → no switch, prefix untouched.
    #[test]
    fn broadcast_frames_empty_on_non_solo_even_if_armed() {
        let mut s = solo_session_with_extended_channel(7, vec![0xC0, 0xDE, 0xBA, 0xBE]);
        s.uses_custom_extranonce = true;
        s.stream = StreamKind::Pplns;
        let hooks = hooks_with_override(ADDR, "wrk", [0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(custom_extranonce_broadcast_frames(&mut s, &hooks).is_empty());
        assert_eq!(
            s.channels.get(&7).unwrap().extranonce_prefix,
            vec![0xC0, 0xDE, 0xBA, 0xBE]
        );
    }

    fn add_extended_channel(
        s: &mut MiningSessionState<Arc<TestClock>>,
        channel_id: u32,
        prefix: Vec<u8>,
    ) {
        s.channels.insert(
            channel_id,
            crate::mining::channel::ChannelState::new_extended(
                channel_id,
                prefix,
                8,
                Difficulty(1024.0),
                [0xFF; 32],
                bp_jobs_lifecycle::LifecycleConfig::DEFAULT,
            ),
        );
    }

    /// At open, the override applies to the primary channel only.
    #[test]
    fn custom_extranonce_applies_only_to_primary_channel_at_open() {
        const CUSTOM: [u8; 4] = [0xC0, 0xDE, 0xBA, 0xBE];
        let alloc2 = vec![0x00, 0x00, 0x00, 0x09];
        let mut s = solo_session_with_extended_channel(7, vec![0x00, 0x00, 0x00, 0x05]);
        add_extended_channel(&mut s, 8, alloc2.clone());
        let hooks = hooks_with_override(ADDR, "wrk", CUSTOM);

        // Primary (7) applies.
        assert_eq!(
            maybe_apply_custom_extranonce(&mut s, &hooks, 7),
            Some(CUSTOM)
        );
        assert_eq!(
            s.channels.get(&7).unwrap().extranonce_prefix,
            CUSTOM.to_vec()
        );

        // Non-primary (8) is skipped and keeps its distinct allocated prefix.
        assert!(maybe_apply_custom_extranonce(&mut s, &hooks, 8).is_none());
        assert_eq!(s.channels.get(&8).unwrap().extranonce_prefix, alloc2);
        assert_ne!(
            s.channels.get(&7).unwrap().extranonce_prefix,
            s.channels.get(&8).unwrap().extranonce_prefix,
            "the two channels must keep distinct prefixes — no collapse"
        );
    }

    /// On the broadcast path, a change switches only the primary channel.
    #[test]
    fn broadcast_frames_switch_only_the_primary_channel() {
        const NEW: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        let alloc2 = vec![0x00, 0x00, 0x00, 0x09];
        let mut s = solo_session_with_extended_channel(7, vec![0xC0, 0xDE, 0xBA, 0xBE]);
        s.uses_custom_extranonce = true;
        add_extended_channel(&mut s, 8, alloc2.clone());
        let hooks = hooks_with_override(ADDR, "wrk", NEW);

        let frames = custom_extranonce_broadcast_frames(&mut s, &hooks);
        assert_eq!(frames.len(), 1, "exactly one switch — the primary");
        assert!(matches!(
            &frames[0],
            OutboundFrame::SetExtranoncePrefix { channel_id: 7, .. }
        ));
        assert_eq!(s.channels.get(&7).unwrap().extranonce_prefix, NEW.to_vec());
        assert_eq!(
            s.channels.get(&8).unwrap().extranonce_prefix,
            alloc2,
            "non-primary channel must be untouched — no collapse"
        );
    }

    // ── Handle lifecycle ───────────────────────────────────────────

    #[tokio::test(flavor = "current_thread")]
    async fn server_spawn_and_shutdown_is_idempotent() {
        let (_tdp_tx, tdp_rx) = broadcast::channel::<TemplateUpdate>(8);
        let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
        let server = StratumV2MiningServer::spawn(
            server_cfg(),
            noise_cfg(),
            tdp_rx,
            bp_template_distribution::TemplateSnapshot::default(),
            Vec::new(),
            MiningServerHooks::no_op(),
            bridge,
            fresh_allocator(),
            Arc::new(MiningJobCache::new()),
        );
        server.shutdown().await;
        // Second call is a no-op (translator_join already taken).
        server.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_handle_is_cloneable_independently() {
        let (_tdp_tx, tdp_rx) = broadcast::channel::<TemplateUpdate>(8);
        let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
        let server = StratumV2MiningServer::spawn(
            server_cfg(),
            noise_cfg(),
            tdp_rx,
            bp_template_distribution::TemplateSnapshot::default(),
            Vec::new(),
            MiningServerHooks::no_op(),
            bridge,
            fresh_allocator(),
            Arc::new(MiningJobCache::new()),
        );
        let clone = server.clone();
        assert!(clone.current_template().is_none());
        server.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn allocated_session_ids_are_distinct_per_handle() {
        let (_tdp_tx, tdp_rx) = broadcast::channel::<TemplateUpdate>(8);
        let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
        let server = StratumV2MiningServer::spawn(
            server_cfg(),
            noise_cfg(),
            tdp_rx,
            bp_template_distribution::TemplateSnapshot::default(),
            Vec::new(),
            MiningServerHooks::no_op(),
            bridge,
            fresh_allocator(),
            Arc::new(MiningJobCache::new()),
        );
        let a = server.alloc_session_id();
        let b = server.alloc_session_id();
        let c = server.alloc_session_id();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
        for id in [a, b, c] {
            let hex = format!("{id:08x}");
            assert_eq!(hex.len(), 8);
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        }
        server.shutdown().await;
    }

    // ── Translator task ────────────────────────────────────────────

    fn nt(template_id: u64, future: bool) -> NewTemplate {
        NewTemplate {
            template_id,
            future_template: future,
            version: 0x2000_0000,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![0x03, 0xC8, 0x00, 0x00],
            coinbase_tx_input_sequence: 0xffff_ffff,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: vec![0xAA; 16],
            coinbase_tx_locktime: 0,
            merkle_path: vec![[0x11; 32]],
        }
    }

    fn snph(template_id: u64) -> SetNewPrevHash {
        SetNewPrevHash {
            template_id,
            prev_hash: [0xAB; 32],
            header_timestamp: 0x6500_0001,
            n_bits: 0x1d00_ffff,
            target: [0xFF; 32],
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn translator_broadcasts_active_template_after_pairing() {
        let (tdp_tx, tdp_rx) = broadcast::channel::<TemplateUpdate>(8);
        let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
        let server = StratumV2MiningServer::spawn(
            server_cfg(),
            noise_cfg(),
            tdp_rx,
            bp_template_distribution::TemplateSnapshot::default(),
            Vec::new(),
            MiningServerHooks::no_op(),
            bridge,
            fresh_allocator(),
            Arc::new(MiningJobCache::new()),
        );
        let mut rx = server.subscribe_templates();
        tdp_tx
            .send(TemplateUpdate::NewTemplate(nt(1, true)))
            .unwrap();
        tdp_tx
            .send(TemplateUpdate::SetNewPrevHash(snph(1)))
            .unwrap();
        let payload = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("translator must broadcast within 500ms")
            .expect("broadcast not closed");
        assert_eq!(payload.template.template_id, 1);
        assert_eq!(payload.template.prev_hash, [0xAB; 32]);
        assert!(server.current_template().is_some());
        server.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn translator_holds_current_template_snapshot() {
        let (tdp_tx, tdp_rx) = broadcast::channel::<TemplateUpdate>(8);
        let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
        let server = StratumV2MiningServer::spawn(
            server_cfg(),
            noise_cfg(),
            tdp_rx,
            bp_template_distribution::TemplateSnapshot::default(),
            Vec::new(),
            MiningServerHooks::no_op(),
            bridge,
            fresh_allocator(),
            Arc::new(MiningJobCache::new()),
        );
        assert!(server.current_template().is_none());
        tdp_tx
            .send(TemplateUpdate::NewTemplate(nt(7, true)))
            .unwrap();
        tdp_tx
            .send(TemplateUpdate::SetNewPrevHash(snph(7)))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let snap = server.current_template();
        assert!(snap.is_some());
        assert_eq!(snap.unwrap().template_id, 7);
        server.shutdown().await;
    }

    // ── apply_session_events fan-out ───────────────────────────────

    fn accept() -> ShareAccept {
        ShareAccept {
            payouts_fingerprint: [0u8; 32],
            classification: JobClassification::Active,
            effective_difficulty: Difficulty(1024.0),
            submission_difficulty: Difficulty(2048.0),
            header: [0u8; 80],
            hash: [0u8; 32],
            is_block_candidate: false,
            template_id: None,
            jdp_claims_the_block: false,
            witness_coinbase: Vec::new(),
            effective_worker_name: None,
            coinbase_tx_value_remaining: 5_000_000_000,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn share_accepted_event_fires_accepted_sink() {
        let recording = RecordingHooks::new();
        let hooks = recording.clone().into_server_hooks();
        let state = fresh_session_with_address();
        let events = vec![SessionEvent::ShareAccepted {
            channel_id: 1,
            accept: Box::new(accept()),
        }];
        apply_session_events_generic(events, "sess-1", &state, &hooks).await;
        let records = recording.accepted.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].address, ADDR);
        assert_eq!(records[0].worker, "wrk");
        assert_eq!(records[0].session_id_hex, "sess-1");
        assert!(recording.blocks_submitted.lock().unwrap().is_empty());
    }

    /// Each accepted share carries the live open-channel count of its connection.
    #[tokio::test(flavor = "current_thread")]
    async fn accepted_share_reports_open_channel_count() {
        use crate::mining::channel::ChannelState;

        let mk_channel = |cid: u32| {
            ChannelState::new_standard(
                cid,
                vec![0u8; 4],
                Difficulty(1024.0),
                [0xffu8; 32],
                bp_jobs_lifecycle::LifecycleConfig::DEFAULT,
            )
        };

        // One channel (direct miner) → count 1.
        let recording = RecordingHooks::new();
        let hooks = recording.clone().into_server_hooks();
        let mut state = fresh_session_with_address();
        state.channels.insert(1, mk_channel(1));
        apply_session_events_generic(
            vec![SessionEvent::ShareAccepted {
                channel_id: 1,
                accept: Box::new(accept()),
            }],
            "sess-1",
            &state,
            &hooks,
        )
        .await;
        assert_eq!(
            recording.accepted.lock().unwrap()[0].channel_count,
            1,
            "a single-channel connection reports 1"
        );

        // Three channels bundled on one connection → count 3.
        let recording = RecordingHooks::new();
        let hooks = recording.clone().into_server_hooks();
        let mut state = fresh_session_with_address();
        for cid in 1..=3u32 {
            state.channels.insert(cid, mk_channel(cid));
        }
        apply_session_events_generic(
            vec![SessionEvent::ShareAccepted {
                channel_id: 1,
                accept: Box::new(accept()),
            }],
            "sess-1",
            &state,
            &hooks,
        )
        .await;
        assert_eq!(
            recording.accepted.lock().unwrap()[0].channel_count,
            3,
            "a bundled rig reports its open-channel count"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn block_candidate_event_also_fires_block_sink() {
        let recording = RecordingHooks::new();
        let hooks = recording.clone().into_server_hooks();
        let state = fresh_session_with_address();
        let mut a = accept();
        a.is_block_candidate = true;
        let events = vec![SessionEvent::ShareAccepted {
            channel_id: 1,
            accept: Box::new(a),
        }];
        apply_session_events_generic(events, "sess-1", &state, &hooks).await;
        assert_eq!(recording.accepted.lock().unwrap().len(), 1);
        assert_eq!(recording.blocks_submitted.lock().unwrap().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn share_rejected_event_fires_rejected_sink() {
        let recording = RecordingHooks::new();
        let hooks = recording.clone().into_server_hooks();
        let state = fresh_session_with_address();
        let events = vec![SessionEvent::ShareRejected {
            channel_id: 1,
            reject: ShareReject::from(RejectReason::StaleShare),
        }];
        apply_session_events_generic(events, "sess-1", &state, &hooks).await;
        let records = recording.rejected.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].reason, bp_share_hook::RejectedReason::Stale);
        assert_eq!(records[0].address.as_deref(), Some(ADDR));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn channel_opened_event_fans_out_to_device_status() {
        let recording = RecordingHooks::new();
        let hooks = recording.clone().into_server_hooks();
        let state = fresh_session_with_address();
        let events = vec![SessionEvent::ChannelOpened {
            channel_id: 42,
            address: AddressId::new(ADDR.to_string()).unwrap(),
            worker: "worker-7".to_string(),
            kind: crate::mining::channel::ChannelKind::Standard,
        }];
        apply_session_events_generic(events, "sess-1", &state, &hooks).await;
        // No register from this layer.
        assert!(recording.registered.lock().unwrap().is_empty());
        // Device-online event fired (address is the session's locked one).
        let devices = recording.device_events.lock().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].1, "worker-7");
        assert!(devices[0].2, "online flag");
    }

    /// An empty event list makes no hook calls.
    #[tokio::test(flavor = "current_thread")]
    async fn empty_events_fan_out_no_op() {
        let recording = RecordingHooks::new();
        let hooks = recording.clone().into_server_hooks();
        let state = fresh_session_with_address();
        apply_session_events_generic(Vec::new(), "sess-1", &state, &hooks).await;
        assert!(recording.accepted.lock().unwrap().is_empty());
        assert!(recording.rejected.lock().unwrap().is_empty());
        assert!(recording.registered.lock().unwrap().is_empty());
    }

    // ── resolve_template_mining_job_inputs ────────────────────────

    fn active_template_fixture() -> ActiveTemplate {
        ActiveTemplate {
            template_id: 1,
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            n_bits: 0x1d00_ffff,
            header_timestamp: 0x6500_0001,
            coinbase_prefix: vec![0x03, 0xC8, 0x00, 0x00],
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xffff_ffff,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: vec![],
            coinbase_tx_outputs_count: 0,
            coinbase_tx_locktime: 0,
            merkle_path: vec![[0x11; 32]],
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolve_template_mining_job_inputs_returns_none_when_address_not_locked() {
        let cfg = server_cfg();
        let hooks = MiningServerHooks::no_op();
        let template = active_template_fixture();
        let out = resolve_template_mining_job_inputs(
            &None,
            &cfg,
            &template,
            &hooks,
            &Arc::new(MiningJobCache::new()),
        )
        .await
        .unwrap();
        assert!(out.is_none(), "no address → no MiningJobInputs");
    }

    /// MONEY: no distribution means no job, never a solo coinbase for this miner.
    #[tokio::test(flavor = "current_thread")]
    async fn resolve_template_mining_job_inputs_returns_none_when_the_resolver_serves_no_job() {
        struct NoJobResolver;
        #[async_trait::async_trait]
        impl crate::hooks::PayoutResolver for NoJobResolver {
            async fn resolve_payouts(
                &self,
                _: &AddressId,
                _: u64,
            ) -> bp_mining_job::ResolvedPayouts {
                bp_mining_job::ResolvedPayouts::none()
            }
            fn resolve_stream(&self, _: &AddressId) -> bp_common::StreamKind {
                bp_common::StreamKind::Pplns
            }
        }
        let cfg = server_cfg();
        let mut hooks = MiningServerHooks::no_op();
        hooks.payout_resolver = Arc::new(NoJobResolver);
        let template = active_template_fixture();
        let addr = Some(AddressId::new(ADDR.to_string()).unwrap());

        let out = resolve_template_mining_job_inputs(
            &addr,
            &cfg,
            &template,
            &hooks,
            &Arc::new(MiningJobCache::new()),
        )
        .await
        .unwrap();
        assert!(
            out.is_none(),
            "an empty payout list must produce NO job inputs — building one \
             would put an unpayable coinbase on the wire"
        );

        // Negative control: the same call with the default resolver does
        // produce inputs.
        let out = resolve_template_mining_job_inputs(
            &addr,
            &cfg,
            &template,
            &MiningServerHooks::no_op(),
            &Arc::new(MiningJobCache::new()),
        )
        .await
        .unwrap();
        assert!(
            out.is_some(),
            "precondition: a resolver that DOES return a list still yields job inputs"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolve_template_mining_job_inputs_runs_resolver_and_builds() {
        let cfg = server_cfg();
        let hooks = MiningServerHooks::no_op();
        let template = active_template_fixture();
        let addr = Some(AddressId::new(ADDR.to_string()).unwrap());
        let out = resolve_template_mining_job_inputs(
            &addr,
            &cfg,
            &template,
            &hooks,
            &Arc::new(MiningJobCache::new()),
        )
        .await
        .unwrap();
        assert!(out.is_some(), "address locked → MiningJobInputs populated");
        let inputs = out.unwrap();
        assert!(
            !inputs.payouts.is_empty(),
            "resolver returned at least one payout"
        );
        let job = inputs
            .build(bp_mining_job::EXTRANONCE_SLOT_LEN)
            .expect("MiningJobInputs.build for default slot");
        assert!(!job.coinbase_prefix().is_empty());
        assert!(!job.coinbase_suffix().is_empty());
    }

    // ── User agent ────────────────────────────────────────────────

    /// An empty vendor becomes the `jd-client/sv2` placeholder on the session row.
    #[test]
    fn user_agent_from_vendor() {
        use crate::mining::client::vendor_user_agent;
        assert_eq!(vendor_user_agent("bitaxe").as_deref(), Some("bitaxe/sv2"));
        assert_eq!(vendor_user_agent(""), None);
        assert_eq!(session_user_agent(Some("bitaxe/sv2")), "bitaxe/sv2");
        assert_eq!(session_user_agent(None), "jd-client/sv2");
    }

    /// The vendor is normalised like an SV1 user agent before `/sv2` is appended.
    #[test]
    fn user_agent_normalises_vendor_like_sv1() {
        use crate::mining::client::vendor_user_agent;
        assert_eq!(
            vendor_user_agent("cgminer/4.11.1").as_deref(),
            Some("cgminer/sv2")
        );
        assert_eq!(
            vendor_user_agent("bosminer-plus-tuner x").as_deref(),
            Some("Braiins OS/sv2")
        );
    }

    /// SetupConnection records the session's user agent from its vendor.
    #[test]
    fn setup_connection_records_the_vendor_user_agent() {
        let mut s = fresh_test_session();
        let setup = InboundMiningFrame::SetupConnection(SetupConnectionInput {
            protocol: PROTOCOL_MINING,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            vendor: "cgminer/4.11.1".to_string(),
        });
        let _ = dispatch_inbound_frame(&mut s, setup, &fresh_extranonce(), &fresh_bridge(), 0);
        assert_eq!(s.user_agent.as_deref(), Some("cgminer/sv2"));
    }

    // ── ServerConfig defaults ─────────────────────────────────────

    #[test]
    fn server_config_defaults_for_regtest() {
        let cfg = ServerConfig::defaults_for(Network::Regtest);
        assert_eq!(cfg.network, Network::Regtest);
        assert_eq!(cfg.pool_identifier, "/blitzpool-rust/");
        assert_eq!(cfg.shutdown_drain_timeout, Duration::from_secs(5));
    }

    // ── dispatch_inbound_frame ─────────────────────────────────────

    use crate::codec_common::SetupConnectionInput;
    use crate::extranonce::SV2_WORKER_ID;
    use crate::mining::client::{FLAG_REQUIRES_VERSION_ROLLING, PROTOCOL_MINING};
    use crate::mining::submit::SubmitSharesStandardInput;
    use crate::server_codec::InboundMiningFrame;

    fn fresh_test_session() -> MiningSessionState<Arc<TestClock>> {
        MiningSessionState::new(Arc::new(TestClock::new(0)), 1, _port_cfg())
    }

    fn fresh_allocator() -> SharedExtranonceAllocator {
        SharedExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID)
    }

    fn fresh_extranonce() -> ConnectionExtranonce {
        ConnectionExtranonce::new(fresh_allocator())
    }

    fn fresh_bridge() -> Arc<RwLock<JdpDeclaredJobRegistry>> {
        Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()))
    }

    /// `SetupConnection` dispatches to a success outcome.
    #[test]
    fn dispatch_setup_connection_emits_success() {
        let mut s = fresh_test_session();
        let alloc = fresh_extranonce();
        let bridge = fresh_bridge();
        let inbound = InboundMiningFrame::SetupConnection(SetupConnectionInput {
            protocol: PROTOCOL_MINING,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            vendor: "test".to_string(),
        });
        let outcome = dispatch_inbound_frame(&mut s, inbound, &alloc, &bridge, 0);
        assert!(matches!(
            outcome.outbound[0],
            crate::mining::client::OutboundFrame::SetupConnectionSuccess { .. }
        ));
        assert!(s.setup_complete);
    }

    /// `SubmitSharesStandard` on an unknown channel emits `invalid-channel-id`.
    #[test]
    fn dispatch_submit_standard_unknown_channel_emits_invalid_channel_id() {
        let mut s = fresh_test_session();
        let alloc = fresh_extranonce();
        let bridge = fresh_bridge();
        let inbound = InboundMiningFrame::SubmitSharesStandard(SubmitSharesStandardInput {
            channel_id: 99,
            sequence_number: 1,
            job_id: 1,
            nonce: 0,
            ntime: 0,
            version: 0,
        });
        let outcome = dispatch_inbound_frame(&mut s, inbound, &alloc, &bridge, 0);
        match &outcome.outbound[0] {
            crate::mining::client::OutboundFrame::SubmitSharesError { error_code, .. } => {
                assert_eq!(error_code, "invalid-channel-id");
            }
            _ => panic!("expected SubmitSharesError"),
        }
    }

    /// `CloseChannel` returns the closed channel's prefix to the allocator.
    #[test]
    fn dispatch_close_channel_releases_extranonce_prefix() {
        let mut s = fresh_test_session();
        let shared = fresh_allocator();
        let alloc = ConnectionExtranonce::new(shared.clone());
        let bridge = fresh_bridge();
        let setup = InboundMiningFrame::SetupConnection(SetupConnectionInput {
            protocol: PROTOCOL_MINING,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            vendor: "t".to_string(),
        });
        let _ = dispatch_inbound_frame(&mut s, setup, &alloc, &bridge, 0);
        let open = InboundMiningFrame::OpenStandardMiningChannel(
            crate::mining::client::OpenStandardMiningChannelInput {
                request_id: 1,
                user_identity: format!("{ADDR}.w"),
                nominal_hash_rate: 1_000.0,
                max_target: [0xFF; 32],
            },
            Vec::new(),
        );
        let _ = dispatch_inbound_frame(&mut s, open, &alloc, &bridge, 0);
        let cid = s.primary_channel.expect("channel opened");
        let before = shared.allocated_count();
        assert_eq!(before, 1, "one prefix allocated for the open channel");

        let inbound = InboundMiningFrame::CloseChannel(crate::mining::client::CloseChannelInput {
            channel_id: cid,
            reason_code: "user-quit".to_string(),
        });
        let _ = dispatch_inbound_frame(&mut s, inbound, &alloc, &bridge, 0);
        assert_eq!(
            shared.allocated_count(),
            before - 1,
            "close releases the channel's prefix"
        );
    }

    /// Only a refused open yields a refusal reason to log.
    #[test]
    fn open_channel_refusal_reports_the_reason_of_a_refused_open_only() {
        let mut s = fresh_test_session();
        let alloc = ConnectionExtranonce::new(fresh_allocator());
        let bridge = fresh_bridge();
        let setup = InboundMiningFrame::SetupConnection(SetupConnectionInput {
            protocol: PROTOCOL_MINING,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            vendor: "t".to_string(),
        });
        let _ = dispatch_inbound_frame(&mut s, setup, &alloc, &bridge, 0);
        let open = |request_id, user_identity: String| {
            InboundMiningFrame::OpenStandardMiningChannel(
                crate::mining::client::OpenStandardMiningChannelInput {
                    request_id,
                    user_identity,
                    nominal_hash_rate: 1_000.0,
                    max_target: [0xFF; 32],
                },
                Vec::new(),
            )
        };

        let refused = dispatch_inbound_frame(
            &mut s,
            open(1, "not-an-address.w".to_string()),
            &alloc,
            &bridge,
            0,
        );
        assert_eq!(
            open_channel_refusal(&refused.outbound),
            Some(crate::mining::client::ERR_UNKNOWN_USER)
        );

        let accepted =
            dispatch_inbound_frame(&mut s, open(2, format!("{ADDR}.w")), &alloc, &bridge, 0);
        assert!(
            s.primary_channel.is_some(),
            "precondition: the open succeeded"
        );
        assert_eq!(open_channel_refusal(&accepted.outbound), None);
    }

    /// A group close releases every member's prefix (SV2 Mining/CloseChannel).
    #[test]
    fn dispatch_group_close_releases_all_member_prefixes() {
        let mut s = fresh_test_session();
        let shared = fresh_allocator();
        let alloc = ConnectionExtranonce::new(shared.clone());
        let bridge = fresh_bridge();
        // non-RSJ setup → Extended channels are grouped.
        let setup = InboundMiningFrame::SetupConnection(SetupConnectionInput {
            protocol: PROTOCOL_MINING,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            vendor: "t".to_string(),
        });
        let _ = dispatch_inbound_frame(&mut s, setup, &alloc, &bridge, 0);
        for req in 1..=2u32 {
            let open = InboundMiningFrame::OpenExtendedMiningChannel(
                crate::mining::client::OpenExtendedMiningChannelInput {
                    request_id: req,
                    user_identity: format!("{ADDR}.w{req}"),
                    nominal_hash_rate: 1_000_000.0,
                    max_target: [0xFF; 32],
                    min_extranonce_size: 8,
                },
                Vec::new(),
            );
            let _ = dispatch_inbound_frame(&mut s, open, &alloc, &bridge, 0);
        }
        assert_eq!(shared.allocated_count(), 2, "two member prefixes allocated");
        let gid = s
            .groups
            .group_for_channel(s.primary_channel.unwrap())
            .expect("channels grouped");

        let inbound = InboundMiningFrame::CloseChannel(crate::mining::client::CloseChannelInput {
            channel_id: gid,
            reason_code: "bye".to_string(),
        });
        let _ = dispatch_inbound_frame(&mut s, inbound, &alloc, &bridge, 0);
        assert_eq!(
            shared.allocated_count(),
            0,
            "group close must release every member's prefix"
        );
        assert!(s.channels.is_empty());
    }

    /// Two connections with the same `session_id` still get distinct prefixes.
    #[test]
    fn same_session_id_on_two_connections_gets_distinct_prefixes() {
        let shared = fresh_allocator();
        let bridge = fresh_bridge();
        let mut prefixes = Vec::new();
        for _ in 0..2 {
            // `fresh_test_session` gives every session the same id.
            let mut s = fresh_test_session();
            let alloc = ConnectionExtranonce::new(shared.clone());
            let setup = InboundMiningFrame::SetupConnection(SetupConnectionInput {
                protocol: PROTOCOL_MINING,
                min_version: 2,
                max_version: 2,
                flags: FLAG_REQUIRES_VERSION_ROLLING,
                vendor: "t".to_string(),
            });
            let _ = dispatch_inbound_frame(&mut s, setup, &alloc, &bridge, 0);
            let open = InboundMiningFrame::OpenStandardMiningChannel(
                crate::mining::client::OpenStandardMiningChannelInput {
                    request_id: 1,
                    user_identity: format!("{ADDR}.w"),
                    nominal_hash_rate: 1_000.0,
                    max_target: [0xFF; 32],
                },
                Vec::new(),
            );
            let _ = dispatch_inbound_frame(&mut s, open, &alloc, &bridge, 0);
            let cid = s.primary_channel.expect("channel opened");
            prefixes.push(s.channels[&cid].extranonce_prefix.clone());
        }
        assert_eq!(
            prefixes[0].len(),
            4,
            "precondition: a real prefix was allocated"
        );
        assert_ne!(
            prefixes[0], prefixes[1],
            "two live connections must never share an extranonce prefix"
        );
    }

    /// A distribution is multi-use until settlement makes it stale, while each
    /// allocate token authorises one job (ext 0x0003/Implementation Notes).
    #[test]
    fn dispatch_set_custom_mining_job_resolves_distribution_multi_use() {
        use crate::jdp::payout_distribution::{compute_payout_vector, WeightedOutput};
        use crate::mining::client::SetCustomMiningJobInput;
        use crate::tokens::Token;

        let mut s = fresh_test_session();
        let alloc = fresh_extranonce();
        let bridge = fresh_bridge();
        let setup = InboundMiningFrame::SetupConnection(SetupConnectionInput {
            protocol: PROTOCOL_MINING,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            vendor: "t".to_string(),
        });
        let _ = dispatch_inbound_frame(&mut s, setup, &alloc, &bridge, 0);
        // ext 0x0003/Negotiation: the TLV is honoured only when 0x0003 is
        // negotiated on the mining connection.
        let negotiate =
            InboundMiningFrame::RequestExtensions(crate::extensions::RequestExtensions {
                request_id: 1,
                requested_extensions: vec![
                    crate::extensions::SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS,
                ],
            });
        let _ = dispatch_inbound_frame(&mut s, negotiate, &alloc, &bridge, 0);
        assert!(s
            .negotiated_extensions
            .contains(&crate::extensions::SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS));
        let open = InboundMiningFrame::OpenExtendedMiningChannel(
            crate::mining::client::OpenExtendedMiningChannelInput {
                request_id: 2,
                user_identity: format!("{ADDR}.w"),
                nominal_hash_rate: 1_000_000.0,
                max_target: [0xFF; 32],
                min_extranonce_size: 8,
            },
            Vec::new(),
        );
        let _ = dispatch_inbound_frame(&mut s, open, &alloc, &bridge, 0);
        let cid = s.primary_channel.expect("extended channel opened");
        {
            // Custom jobs need served work to pin a block-candidate threshold to.
            let ch = s.channels.get_mut(&cid).expect("channel just opened");
            ch.latest_extended_prev_hash = Some([0xAB; 32]);
            ch.latest_extended_n_bits = Some(0x1d00_ffff);
        }

        let entry = crate::bridge::PayoutDistributionEntry {
            distribution_id: 5,
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
            accounting: crate::bridge::DistributionAccounting::PoolWide,
            jdp_session_id: None,
            published_at_ms: 0,
        };
        // ext 0x0003/Payout Computation-conformant coinbase outputs for the
        // published weights.
        let conformant = bitcoin::consensus::serialize(
            &compute_payout_vector(
                &entry.built.pool_payout,
                &entry.built.payouts,
                &entry.built.dust_limits,
                &entry.built.additional_outputs,
                312_500_000,
            )
            .unwrap(),
        );
        bridge.write().unwrap().publish_pool_wide(entry);
        // One allocate token per job: a token authorises exactly one
        // `SetCustomMiningJob`; multi-use is the distribution's property.
        for req in 1..=3u8 {
            bridge.write().unwrap().register_allocation(
                Token([req; 16]),
                crate::bridge::AllocatedTokenRef {
                    miner_address: AddressId::new(ADDR.to_string()).unwrap(),
                    kind: crate::bridge::AllocationKind::JudgedByDistribution,
                    jdp_session_id: 1,
                    expires_at_ms: u64::MAX,
                },
                0,
            );
        }

        let make_input = |req: u32| SetCustomMiningJobInput {
            channel_id: cid,
            request_id: req,
            mining_job_token: Token([req as u8; 16]),
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            min_ntime: 0x6500_0001,
            n_bits: 0x1d00_ffff,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![0x03, 0xC8, 0x00],
            coinbase_tx_input_n_sequence: 0xFFFF_FFFF,
            coinbase_tx_outputs: conformant.clone(),
            coinbase_tx_locktime: 0,
            merkle_path: vec![[0x11; 32]],
            distribution_id: Some(5),
        };

        // Many jobs of one tip legitimately share one distribution.
        for req in 1..=2u32 {
            let out = dispatch_inbound_frame(
                &mut s,
                InboundMiningFrame::SetCustomMiningJob(make_input(req)),
                &alloc,
                &bridge,
                0,
            );
            assert!(
                matches!(
                    out.outbound[0],
                    crate::mining::client::OutboundFrame::SetCustomMiningJobSuccess { .. }
                ),
                "reference {req} must be accepted (multi-use)"
            );
        }

        // The tokens are spent; the distribution is still live, as the
        // settlement step below shows with a different code.
        let out = dispatch_inbound_frame(
            &mut s,
            InboundMiningFrame::SetCustomMiningJob(make_input(1)),
            &alloc,
            &bridge,
            0,
        );
        match &out.outbound[0] {
            crate::mining::client::OutboundFrame::SetCustomMiningJobError {
                error_code, ..
            } => assert_eq!(
                error_code,
                crate::mining::client::ERR_INVALID_MINING_JOB_TOKEN,
                "a token authorises one custom job"
            ),
            other => {
                panic!("a spent allocate token must not authorise a second job, got {other:?}")
            }
        }

        // ext 0x0003/Implementation Notes: a settlement invalidates every
        // published distribution.
        bridge.write().unwrap().invalidate_all_distributions();
        let out = dispatch_inbound_frame(
            &mut s,
            InboundMiningFrame::SetCustomMiningJob(make_input(3)),
            &alloc,
            &bridge,
            0,
        );
        match &out.outbound[0] {
            crate::mining::client::OutboundFrame::SetCustomMiningJobError {
                error_code, ..
            } => {
                assert_eq!(
                    error_code,
                    crate::mining::client::ERR_STALE_PAYOUT_DISTRIBUTION
                );
            }
            other => panic!("expected stale error, got {other:?}"),
        }
    }

    /// A declared token authorises one job, and a rejected job does not spend it.
    #[test]
    fn a_declared_token_authorises_one_custom_job_and_survives_a_rejection() {
        use crate::mining::client::tests::{
            bridge_entry_for, custom_job_matching, solo_session_with_extended_channel,
        };
        use crate::tokens::Token;

        // Solo: a declared job carries no distribution here, and the Solo gate
        // is what lets such a job be served at all.
        let mut s = solo_session_with_extended_channel();
        let cid = s.primary_channel.unwrap();
        let alloc = fresh_extranonce();
        let bridge = fresh_bridge();
        let token = Token([0x5Au8; 16]);
        let entry = bridge_entry_for(token, "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", 42);
        bridge.write().unwrap().register(
            token,
            crate::bridge::RegisteredDeclaredJob {
                declared_job: entry.declared_job.clone(),
                jdp_session_id: 42,
            },
        );

        // Rejected first: a tip the declaration was not accepted under.
        let mut stale = custom_job_matching(cid, &entry);
        stale.prev_hash = [0xCD; 32];
        let out = dispatch_inbound_frame(
            &mut s,
            InboundMiningFrame::SetCustomMiningJob(stale),
            &alloc,
            &bridge,
            0,
        );
        match &out.outbound[0] {
            crate::mining::client::OutboundFrame::SetCustomMiningJobError {
                error_code, ..
            } => {
                assert_eq!(error_code, crate::mining::client::ERR_STALE_CHAIN_TIP);
            }
            other => panic!("expected stale-chain-tip, got {other:?}"),
        }

        // The retry on the same token must still be served.
        let good = custom_job_matching(cid, &entry);
        let out = dispatch_inbound_frame(
            &mut s,
            InboundMiningFrame::SetCustomMiningJob(good.clone()),
            &alloc,
            &bridge,
            0,
        );
        assert!(
            matches!(
                out.outbound[0],
                crate::mining::client::OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "a rejection must not burn the token, got {:?}",
            out.outbound[0]
        );

        // And now it is spent.
        let out = dispatch_inbound_frame(
            &mut s,
            InboundMiningFrame::SetCustomMiningJob(good),
            &alloc,
            &bridge,
            0,
        );
        match &out.outbound[0] {
            crate::mining::client::OutboundFrame::SetCustomMiningJobError {
                error_code, ..
            } => {
                assert_eq!(
                    error_code,
                    crate::mining::client::ERR_INVALID_MINING_JOB_TOKEN
                );
            }
            other => panic!("a token must authorise one custom job, got {other:?}"),
        }
    }

    /// A Full-Template job's inherited distribution resolves in its declaring
    /// JDP session, not the address's newest slot, and is refused once settled.
    #[test]
    fn dispatch_resolves_an_inherited_distribution_in_its_declaring_session() {
        use crate::jdp::payout_distribution::{compute_payout_vector, WeightedOutput};
        use crate::mining::client::SetCustomMiningJobInput;
        use crate::tokens::Token;

        const OLD_SESSION: u32 = 11;
        const NEW_SESSION: u32 = 22;

        let mut s = fresh_test_session();
        let alloc = fresh_extranonce();
        let bridge = fresh_bridge();
        let _ = dispatch_inbound_frame(
            &mut s,
            InboundMiningFrame::SetupConnection(SetupConnectionInput {
                protocol: PROTOCOL_MINING,
                min_version: 2,
                max_version: 2,
                flags: FLAG_REQUIRES_VERSION_ROLLING,
                vendor: "t".to_string(),
            }),
            &alloc,
            &bridge,
            0,
        );
        let _ = dispatch_inbound_frame(
            &mut s,
            InboundMiningFrame::RequestExtensions(crate::extensions::RequestExtensions {
                request_id: 1,
                requested_extensions: vec![
                    crate::extensions::SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS,
                ],
            }),
            &alloc,
            &bridge,
            0,
        );
        let _ = dispatch_inbound_frame(
            &mut s,
            InboundMiningFrame::OpenExtendedMiningChannel(
                crate::mining::client::OpenExtendedMiningChannelInput {
                    request_id: 2,
                    user_identity: format!("{ADDR}.w"),
                    nominal_hash_rate: 1_000_000.0,
                    max_target: [0xFF; 32],
                    min_extranonce_size: 8,
                },
                Vec::new(),
            ),
            &alloc,
            &bridge,
            0,
        );
        let cid = s.primary_channel.expect("extended channel opened");
        {
            // Custom jobs need served work to pin a block-candidate threshold to.
            let ch = s.channels.get_mut(&cid).expect("channel just opened");
            ch.latest_extended_prev_hash = Some([0xAB; 32]);
            ch.latest_extended_n_bits = Some(0x1d00_ffff);
        }
        // Group-Solo: tailored entries exist only for Solo and Group-Solo,
        // and `resolve_distribution_reference` refuses to inherit on Solo.
        s.set_stream(bp_common::StreamKind::GroupSolo);
        let owner = bp_common::AddressId::new(ADDR.to_string()).unwrap();

        let tailored = |id: u64, published_at_ms: u64| crate::bridge::PayoutDistributionEntry {
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
                payouts_fingerprint: Some([0x5A; 32]),
                bookable: true,
            },
            accounting: crate::bridge::DistributionAccounting::GroupSolo(owner.clone()),
            jdp_session_id: Some(OLD_SESSION),
            published_at_ms,
        };
        let declared_against = tailored(5, 1_000);
        let conformant = bitcoin::consensus::serialize(
            &compute_payout_vector(
                &declared_against.built.pool_payout,
                &declared_against.built.payouts,
                &declared_against.built.dust_limits,
                &declared_against.built.additional_outputs,
                312_500_000,
            )
            .unwrap(),
        );

        // Built around the channel's OWN extranonce slot, or the binding would
        // refuse the job before the distribution is consulted.
        let slot = s
            .channels
            .get(&cid)
            .expect("channel opened")
            .full_extranonce_size();
        let script_sig_prefix = vec![0x03, 0xC8, 0x00];
        let mut coinbase_tx_prefix = Vec::new();
        coinbase_tx_prefix.extend_from_slice(&2u32.to_le_bytes());
        coinbase_tx_prefix.push(0x01);
        coinbase_tx_prefix.extend_from_slice(&[0u8; 32]);
        coinbase_tx_prefix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        coinbase_tx_prefix.push((script_sig_prefix.len() + slot) as u8);
        coinbase_tx_prefix.extend_from_slice(&script_sig_prefix);
        let mut coinbase_tx_suffix = Vec::new();
        coinbase_tx_suffix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        coinbase_tx_suffix.extend_from_slice(&conformant);
        coinbase_tx_suffix.extend_from_slice(&0u32.to_le_bytes());

        let token = Token([7u8; 16]);
        const SECOND_TOKEN: Token = Token([8u8; 16]);
        let declared_job = crate::jdp::declarations::DeclaredJob {
            new_token: token,
            miner_address: AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap(),
            version: 0x2000_0000,
            coinbase_tx_prefix,
            coinbase_tx_suffix,
            wtxid_list: vec![],
            raw_transactions: Default::default(),
            prev_hash: [0xAB; 32],
            declared_at_ms: 1_000,
            booking: None,
            distribution_id: Some(5),
        };
        let binding = crate::jdp::custom_job_binding::binding_from_declared_job(&declared_job)
            .expect("fixture declaration must project");
        {
            let mut guard = bridge.write().unwrap();
            guard.publish_tailored(OLD_SESSION, declared_against);
            // A NEWER slot for the same address; `MinerAddress` scope would
            // answer from this one.
            let mut newer = tailored(6, 9_000);
            newer.jdp_session_id = Some(NEW_SESSION);
            guard.publish_tailored(NEW_SESSION, newer);
            guard.register(
                token,
                crate::bridge::RegisteredDeclaredJob {
                    declared_job: declared_job.clone(),
                    jdp_session_id: OLD_SESSION,
                },
            );
            // Same declaration under its own token, since a token authorises
            // exactly one custom job.
            guard.register(
                SECOND_TOKEN,
                crate::bridge::RegisteredDeclaredJob {
                    declared_job: crate::jdp::declarations::DeclaredJob {
                        new_token: SECOND_TOKEN,
                        ..declared_job
                    },
                    jdp_session_id: OLD_SESSION,
                },
            );
        }

        // No TLV, as a Full-Template JDC sends; every bound field comes from
        // the declaration, so only the distribution scope decides.
        let make_input = |req: u32, tok: Token| SetCustomMiningJobInput {
            channel_id: cid,
            request_id: req,
            mining_job_token: tok,
            version: binding.version,
            prev_hash: [0xAB; 32],
            min_ntime: 0x6500_0001,
            n_bits: 0x1d00_ffff,
            coinbase_tx_version: binding.coinbase_tx_version,
            coinbase_prefix: binding.coinbase_script_sig_prefix.clone(),
            coinbase_tx_input_n_sequence: binding.coinbase_tx_input_n_sequence,
            coinbase_tx_outputs: binding.coinbase_tx_outputs.clone(),
            coinbase_tx_locktime: binding.coinbase_tx_locktime,
            merkle_path: binding.merkle_path.clone(),
            distribution_id: None,
        };

        let out = dispatch_inbound_frame(
            &mut s,
            InboundMiningFrame::SetCustomMiningJob(make_input(1, token)),
            &alloc,
            &bridge,
            0,
        );
        assert!(
            matches!(
                out.outbound[0],
                crate::mining::client::OutboundFrame::SetCustomMiningJobSuccess { .. }
            ),
            "the declaring session's distribution must resolve, got {:?}",
            out.outbound[0]
        );

        // ext 0x0003/Implementation Notes settlement: now it genuinely is
        // withdrawn and must be refused.
        bridge.write().unwrap().invalidate_all_distributions();
        let out = dispatch_inbound_frame(
            &mut s,
            InboundMiningFrame::SetCustomMiningJob(make_input(2, SECOND_TOKEN)),
            &alloc,
            &bridge,
            0,
        );
        match &out.outbound[0] {
            crate::mining::client::OutboundFrame::SetCustomMiningJobError {
                error_code, ..
            } => {
                assert_eq!(
                    error_code,
                    crate::mining::client::ERR_STALE_PAYOUT_DISTRIBUTION
                );
            }
            other => panic!("a settled distribution must not stay mineable, got {other:?}"),
        }
    }

    /// `dispatch_inbound_frame` stays synchronous; calling it from a sync
    /// test keeps a hidden await from creeping in.
    #[test]
    fn dispatch_is_synchronous_to_handlers() {
        let mut s = fresh_test_session();
        let alloc = fresh_extranonce();
        let bridge = fresh_bridge();
        let inbound =
            InboundMiningFrame::UpdateChannel(crate::mining::client::UpdateChannelInput {
                channel_id: 99,
                nominal_hash_rate: 1_000_000.0,
                maximum_target: [0xFF; 32],
            });
        let outcome = dispatch_inbound_frame(&mut s, inbound, &alloc, &bridge, 0);
        // Unknown channel → UpdateChannelError.
        assert!(matches!(
            outcome.outbound[0],
            crate::mining::client::OutboundFrame::UpdateChannelError { .. }
        ));
    }

    /// An `OutboundFrame` encodes into a valid `MessageFrame`.
    #[test]
    fn outbound_frame_encodes_and_wraps_to_sv2_frame() {
        let outbound = crate::mining::client::OutboundFrame::SubmitSharesSuccess {
            channel_id: 1,
            last_sequence_number: 42,
            new_submits_accepted_count: 1,
            new_shares_sum: 1024,
        };
        let any_msg = crate::server_codec::encode_mining_outbound(outbound).unwrap();
        let result: Result<
            stratum_core::codec_sv2::MessageFrame<stratum_core::parsers_sv2::AnyMessageOwned>,
            _,
        > = any_msg.try_into();
        assert!(
            result.is_ok(),
            "AnyMessageOwned must wrap into MessageFrame"
        );
    }
}
