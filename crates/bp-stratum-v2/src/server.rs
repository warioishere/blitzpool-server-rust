// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mining-port server: handle + translator task + per-connection task
//! topology.
//!
//! Mirrors [`bp_stratum_v1::server`]'s shape (clone-able handle wrapping
//! an `Arc<Inner>`, translator-task fanning TDP updates to per-connection
//! `broadcast::Receiver<TemplateBroadcast>`s, per-connection task driven
//! by `tokio::select!` over four sources). What's different:
//!
//! - **Noise wrap**: every accepted [`TcpStream`] passes through
//!   [`crate::noise::accept_pool_noise`] before the protocol-level
//!   handler runs. The per-connection task owns the resulting
//!   [`crate::noise::NoiseTcpStream`].
//! - **Pure-handler dispatch**: the SV2 handler layer lives in
//!   [`crate::mining::client`] (`handle_*` + `apply_*` functions); this
//!   module's per-connection task drives them.
//! - **Async payout-resolver**: the template-broadcast arm calls
//!   [`crate::hooks::PayoutResolver::resolve_payouts`] to produce a
//!   `Vec<PayoutEntry>` per template, then builds a `MiningJob` via
//!   [`bp_mining_job::build_mining_job_from_tdp`], then calls
//!   [`crate::mining::client::apply_template_broadcast`].
//! - **Bridge access**: the per-connection task carries an
//!   `Arc<RwLock<JdpDeclaredJobRegistry>>` and consults it on
//!   `SetCustomMiningJob` (Item E) for the security cross-check.
//!
//! ## What's wired
//!
//! - [`StratumV2MiningServer`] public handle with `spawn` /
//!   `accept_connection` / `shutdown` / `current_template` (mirrors SV1).
//! - Translator task: consumes
//!   [`bp_template_distribution::TemplateUpdate`] via the
//!   `broadcast::Receiver` returned by `TdpHandle::subscribe()`, drives
//!   an [`crate::mining::translator::SV2TemplateAssembler`], re-broadcasts
//!   `TemplateBroadcast` to per-connection tasks. Maintains
//!   `Arc<Mutex<Option<Arc<ActiveSV2Template>>>>` snapshot so freshly-accepted
//!   connections can boot from the current state without waiting for
//!   the next TDP update.
//! - Per-connection-task: Noise-XK handshake on accept, then a
//!   `tokio::select!` loop over `{cancel, noise-read,
//!   template-broadcast, vardiff-tick}`. Each arm calls into
//!   [`crate::mining::client`]'s pure handlers, then serialises the
//!   outcome's outbound frames via [`crate::server_codec::encode_mining_outbound`]
//!   and writes them through the Noise stream. Inbound frames flow
//!   `read_frame → parse_message_frame_with_tlvs → decode_mining_inbound
//!   → dispatch_inbound_frame → handle_*`.
//! - Hook fan-out for [`crate::mining::client::SessionEvent`] →
//!   [`crate::hooks::MiningServerHooks`] (block-submit / accepted /
//!   rejected / session-register / session-deregister).
//! - Per-connection [`crate::extranonce::ExtranonceAllocator`] feeds
//!   `OpenStandardMiningChannel` / `OpenExtendedMiningChannel` handler
//!   calls; `CloseChannel` releases back.
//! - Bridge cross-check on `SetCustomMiningJob`: `bridge.lookup(token)`'s
//!   `miner_address` (cloned alone, not the whole entry) is passed to the
//!   handler as `Option<&AddressId>`.
//!
//! ## Per-job template pinning (SV2 §5.3.14 strict — implemented)
//!
//! Both Standard and Extended share validation use the template the miner
//! actually hashed against, pinned on the job record at send-time — the
//! `StandardJobEntry`'s `template_snapshot` and the `ExtendedJob`'s
//! `network_difficulty` respectively. Neither consults the current template,
//! so a block-change between job-send and share-submit can't reclassify an
//! in-flight share's block-candidacy.
//!
//! ## Tests
//!
//! Real-TCP/Noise-handshake e2e tests live in `tests/regtest_*.rs`. Unit
//! tests in this module exercise `dispatch_inbound_frame` with synthetic
//! `InboundMiningFrame` inputs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::Network;
use bp_common::{AddressId, StreamKind};
use bp_mining_job::{MiningJobCache, MiningJobError};
use bp_template_distribution::TemplateUpdate;
use bp_vardiff::SystemClock;
use stratum_core::binary_sv2::GetSize;
use stratum_core::codec_sv2::StandardSv2Frame;
use stratum_core::framing_sv2::framing::Frame;
use stratum_core::parsers_sv2::{
    message_type_to_name, parse_message_frame_with_tlvs, AnyMessage, IsSv2Message,
};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::bridge::JdpDeclaredJobRegistry;
use crate::extranonce::ExtranonceAllocator;
use crate::hooks::MiningServerHooks;
use crate::mining::client::{
    apply_template_broadcast, apply_vardiff_check, handle_close_channel,
    handle_open_extended_mining_channel, handle_open_standard_mining_channel,
    handle_request_extensions, handle_set_custom_mining_job, handle_setup_connection,
    handle_submit_shares_extended, handle_submit_shares_standard, handle_update_channel,
    HandlerOutcome, MiningJobInputs, MiningSessionState, OutboundFrame, PortConfig, SessionEvent,
};
use crate::mining::translator::{
    ActiveSV2Template, SV2TemplateAssembler, TemplateBroadcast, TemplateChange,
};
use crate::noise::{accept_pool_noise, NoiseConfig, NoiseTcpWriteHalf};
use crate::server_codec::{decode_mining_inbound, encode_mining_outbound, InboundMiningFrame};

// ── ServerConfig ────────────────────────────────────────────────────

/// Pool-wide config slice for the mining server. Per-port settings
/// live in [`PortConfig`] and are passed at `accept_connection` time.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Network for `bitcoin::Address`-related operations. Caller
    /// matches this to the bitcoin-core deployment
    /// ([`Network::Bitcoin`] in production, [`Network::Regtest`] in
    /// e2e tests).
    pub network: Network,
    /// Pool identifier suffix appended to coinbase scriptSigs after
    /// the BIP-34 height push (until the 100-byte limit drops it).
    /// Typical value: `"/blitzpool/"`.
    pub pool_identifier: String,
    /// Drain timeout for [`StratumV2MiningServer::shutdown`]. The
    /// translator-task is awaited until this completes; after that it
    /// is detached and logged.
    pub shutdown_drain_timeout: Duration,
    /// When `true`, the per-connection task logs every inbound +
    /// outbound wire frame at DEBUG (`📨 RX:` / `📤 TX:` with the
    /// SV2 message name, msg_type byte, and payload length). Heavy —
    /// only enable in staging. Per-share detail lives behind
    /// [`Self::share_logs`].
    pub debug_messages: bool,
    /// When `true`, log the pool-internal submit→ack latency (µs from
    /// the inbound `SubmitSharesExtended` being read to its
    /// `SubmitShares*` response being written) at INFO, one line per
    /// share. Lightweight — isolates pool processing time.
    pub log_submit_latency: bool,
    /// When `true`, emit per-share diagnostic logs at DEBUG: the
    /// `📤 SubmitSharesExtended` detail line and the
    /// `🎯 Extended share difficulty` trace. Separate from
    /// [`Self::debug_messages`] (raw frame dumps) so operators can tail
    /// per-share difficulty without the full wire-frame firehose.
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

/// Public handle. Cheap to clone (internal `Arc`); the last
/// outstanding clone holds the translator task's `JoinHandle`.
/// Calling [`Self::shutdown`] is the only way to stop the translator
/// cleanly.
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
    current_template: Arc<Mutex<Option<Arc<ActiveSV2Template>>>>,
    // Fixed-reservation alt streams (Solo / GroupSolo / Blockparty) keyed by
    // StreamKind — a connection switches onto one when its OpenChannel address
    // resolves to that mode. Each fed by its own translator off its TDP handle.
    alt_streams: HashMap<StreamKind, AltStream>,
    // POOL-WIDE extranonce-prefix allocator, shared across every connection.
    // It MUST be global, not per-connection: Standard channels can't roll
    // their own extranonce, so two same-address Standard miners handed the
    // same prefix would mine byte-identical work (identical shares + a
    // shared best-difficulty). A per-connection allocator restarts at the
    // same base prefix on each connection, guaranteeing that collision; a
    // single shared allocator hands out a globally-unique prefix per channel.
    extranonce_allocator: Arc<Mutex<ExtranonceAllocator>>,
    // Pool-wide memoization of built MiningJobs — the binary creates
    // ONE cache and passes it into every per-port SV2 server (and the
    // SV1 servers): one PPLNS coinbase build per (template, payout
    // set, slot size) for the whole pool instead of one per channel
    // per broadcast.
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
    current_template: Arc<Mutex<Option<Arc<ActiveSV2Template>>>>,
}

/// A single connection's claim on one alt stream — its own broadcast receiver
/// plus the snapshot to boot from. The per-connection task holds a
/// `HashMap<StreamKind, AltStreamHandle>` and `remove`s the matching entry when
/// it swaps onto that stream.
struct AltStreamHandle {
    rx: broadcast::Receiver<TemplateBroadcast>,
    initial: Option<Arc<ActiveSV2Template>>,
}

impl StratumV2MiningServer {
    /// Spawn the mining server. `updates_rx` is typically
    /// `tdp_handle.subscribe()`. `initial_snapshot` is
    /// `tdp_handle.current_snapshot()` taken alongside the subscribe —
    /// the translator applies it to its assembler before entering the
    /// main loop so the very first OpenChannel sees a non-empty
    /// current_template even when the bitcoin-core bootstrap pair was
    /// broadcast before this subscriber existed (subscribe-after-send
    /// race; cross-ref `feedback-tdp-initial-template-drain`). Returns
    /// immediately — the translator runs on a tokio task tied to the
    /// shared cancel token.
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
        job_cache: Arc<MiningJobCache>,
    ) -> Self {
        let server_config = Arc::new(server_config);
        let (template_tx, _) = broadcast::channel(TEMPLATE_BROADCAST_CAPACITY);
        let current_template = Arc::new(Mutex::new(None::<Arc<ActiveSV2Template>>));
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
            let alt_current = Arc::new(Mutex::new(None::<Arc<ActiveSV2Template>>));
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
                extranonce_allocator: Arc::new(Mutex::new(ExtranonceAllocator::new_default())),
                job_cache,
                cancel,
                translator_join: Mutex::new(Some(translator_join)),
                alt_translator_joins: Mutex::new(alt_joins),
            }),
        }
    }

    pub fn server_config(&self) -> &Arc<ServerConfig> {
        &self.inner.server_config
    }

    /// Snapshot of the latest assembled template. `None` until the
    /// translator pairs its first `NewTemplate` + `SetNewPrevHash`.
    pub fn current_template(&self) -> Option<Arc<ActiveSV2Template>> {
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

    /// How many extranonce prefixes the pool-wide allocator currently holds.
    ///
    /// A prefix is taken at channel-open and returned on `CloseChannel` or
    /// connection teardown, so on a healthy server this tracks the number of
    /// live channels. A count that only ever climbs means prefixes are being
    /// stranded by a release path that isn't firing.
    pub fn allocated_prefix_count(&self) -> usize {
        match self.inner.extranonce_allocator.lock() {
            Ok(guard) => guard.allocated_count(),
            Err(poisoned) => poisoned.into_inner().allocated_count(),
        }
    }

    /// Spawn a per-connection task. The TCP-accept loop in
    /// `bin/blitzpool` calls this for each socket
    /// `bp_protocol_detect` identifies as SV2 mining.
    ///
    /// The first thing the task does is hand the `socket` to
    /// [`crate::noise::accept_pool_noise`] for the Noise-XK handshake.
    /// On handshake failure the task logs + returns; on success it
    /// enters the protocol loop.
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
        let extranonce_allocator = self.inner.extranonce_allocator.clone();
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
                extranonce_allocator,
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

/// Consume TDP updates, feed an `SV2TemplateAssembler`, re-broadcast
/// the resulting `(template, change)` pairs. Maintains
/// `current_template` so freshly-accepted connections boot from the
/// most recent state without waiting for the next TDP message.
///
/// Exits on `cancel` OR when `updates_rx` closes (upstream `TdpHandle`
/// dropped). Mirrors `bp_stratum_v1::server::run_translator`'s shape;
/// only the assembler type differs (SV2 vs SV1 — both consume the
/// same `TemplateUpdate` enum).
async fn run_translator(
    mut updates_rx: broadcast::Receiver<TemplateUpdate>,
    initial_snapshot: bp_template_distribution::TemplateSnapshot,
    template_tx: broadcast::Sender<TemplateBroadcast>,
    current_template: Arc<Mutex<Option<Arc<ActiveSV2Template>>>>,
    job_cache: Arc<MiningJobCache>,
    cancel: CancellationToken,
) {
    let mut assembler = SV2TemplateAssembler::new();

    // Bootstrap the assembler from the TdpHandle snapshot — same race
    // as SV1: the bitcoin-core startup pair is broadcast by bridge_out
    // BEFORE this per-server subscriber installs. The handle's internal
    // tap captures the pair into the snapshot so we can replay it here.
    if let Some((active, change)) = bp_template_distribution::bootstrap_assembler_from_snapshot(
        &mut assembler,
        initial_snapshot,
    ) {
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
                        // Job-cache aging heartbeat: prune piggybacks
                        // on lookups too, but the translator fires even
                        // when NO channel is open — without this, the
                        // last window's entries would sit in RAM until
                        // the next lookup.
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
    initial_template: Option<Arc<ActiveSV2Template>>,
    mut alt_streams: HashMap<StreamKind, AltStreamHandle>,
    extranonce_allocator: Arc<Mutex<ExtranonceAllocator>>,
    job_cache: Arc<MiningJobCache>,
    socket: TcpStream,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let session_id_hex = format!("{session_id:08x}");

    // Noise-XK handshake. On failure log + return; the IO-layer
    // accept loop already increments its per-IP failure counter
    // (fail-ban lives there).
    let noise = match accept_pool_noise::<AnyMessage<'static>>(socket, &noise_config).await {
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
    // `alt_streams` holds one receiver+snapshot per fixed-reservation stream;
    // at OpenChannel the connection `remove`s the entry for its resolved mode
    // (if any) and swaps `template_rx`/`current_template` onto it.
    // Extranonce-prefix allocation uses the POOL-WIDE shared allocator
    // (`extranonce_allocator`, passed in) — NOT a per-connection one.
    // Standard channels can't roll their own extranonce, so two
    // same-address Standard miners must never receive the same prefix;
    // only a global allocator guarantees that. Locked briefly per
    // channel open/close in `dispatch_inbound_frame` (never per-share).

    let mut vardiff_tick = tokio::time::interval(Duration::from_millis(state.vardiff_interval_ms));
    vardiff_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the first immediate tick — match the SV1 cadence (one full
    // interval before the first check).
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
                let mut sv2_frame = match frame {
                    Frame::Sv2(f) => f,
                    Frame::HandShake(_) => {
                        // Should never see a HandShake frame after the
                        // initial handshake completed. Defensive log.
                        warn!("sv2 connection {session_id_hex} unexpected HandShakeFrame post-setup");
                        continue;
                    }
                };
                let header = match sv2_frame.get_header() {
                    Some(h) => h,
                    None => {
                        warn!("sv2 connection {session_id_hex} frame missing header");
                        continue;
                    }
                };
                let payload_len = sv2_frame.payload().len();
                let header_msg_type = header.msg_type();
                let (any_message, tlvs) = match parse_message_frame_with_tlvs(
                    header,
                    sv2_frame.payload(),
                    &state.negotiated_extensions,
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
                // ext 0x0002 Worker-ID TLV wiring: when the frame is
                // a SubmitSharesExtended, re-serialise the parsed TLVs
                // into the wire-form tail bytes and attach to the
                // input. The validator + `resolve_share_worker_name_from_tlv`
                // consume the wire-form bytes (spec §1.1 / §2). When
                // ext 0x0002 isn't in `state.negotiated_extensions`,
                // the validator will silently ignore any TLV (spec §1.3).
                if let InboundMiningFrame::SubmitSharesExtended(ref mut submit) = inbound {
                    if let Some(tlv_list) = &tlvs {
                        let mut tail = Vec::new();
                        for tlv in tlv_list {
                            match tlv.encode() {
                                Ok(bytes) => tail.extend_from_slice(&bytes),
                                Err(err) => {
                                    warn!(
                                        ?err,
                                        "sv2 connection {session_id_hex} tlv encode (dropped)"
                                    );
                                }
                            }
                        }
                        submit.tail_tlvs = tail;
                    }
                }
                // Per-share SubmitSharesExtended trace, gated by
                // share_logs — would flood at production hashrate
                // without the gate.
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
                // The pool-wide extranonce allocator is locked INSIDE the
                // Open/Close dispatch arms only — the hot submit path never
                // touches it, so share validation across connections does
                // not serialize on one global mutex.
                let outcome = dispatch_inbound_frame(
                    &mut state,
                    inbound,
                    &extranonce_allocator,
                    &bridge,
                    now_ms(),
                );
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
                let write_us = write_start.elapsed().as_micros();
                // Pool-internal submit→ack latency: from the inbound
                // SubmitSharesExtended being read to its SubmitShares*
                // response being written (incl. validate + Noise encrypt).
                // Isolates pool processing from network / miner / measurement.
                if server_config.log_submit_latency && is_submit {
                    info!(
                        session_id_hex = %session_id_hex,
                        latency_us = recv_at.elapsed().as_micros(),
                        write_us,
                        "sv2 submit→ack pool-internal latency"
                    );
                }
                // If the dispatch opened a non-JDC mining channel, immediately
                // follow OpenChannelSuccess with a `NewExtendedMiningJob` /
                // `NewMiningJob` + matching `SetNewPrevHash` so the miner has
                // both halves of a workable job from the current cached
                // template. Without this the miner sits on "Waiting for jobs"
                // until the next mempool refresh (which only emits the job half
                // without a prev_hash, leaving the miner stuck — the BitAxe
                // symptom we hit).
                let newly_opened_channel = outcome.events.iter().find_map(|e| match e {
                    SessionEvent::ChannelOpened {
                        channel_id, kind, ..
                    } => Some((*channel_id, *kind)),
                    _ => None,
                });
                // One-time stream routing at OpenChannel: resolve the locked
                // address's mode → stream. A non-PPLNS connection swaps onto its
                // fixed-reservation template stream BEFORE the initial job is built
                // below, so its first job rides the right template. `state.stream`
                // is set ONLY when the swap succeeds, so the submit handle (driven
                // by `state.stream`) can never route to a stream whose template_id
                // the job doesn't carry.
                if let Some((channel_id, _)) = newly_opened_channel {
                    if let Some(addr) = state.address.as_ref() {
                        // Publish the address's mode into the mode-gate
                        // BEFORE the stream routing below. resolve_stream
                        // reads the gate, so the publish MUST precede it —
                        // otherwise the lookup misses and the connection
                        // defaults to the Solo stream regardless of port /
                        // group membership. (register_session was removed
                        // from the ChannelOpened event handler to avoid a
                        // double gate refcount; device-status still fires
                        // there.)
                        let address = addr.clone();
                        let worker = state.worker_name.clone();
                        let user_agent = if state.vendor.is_empty() {
                            "jd-client/sv2".to_string()
                        } else {
                            format!("{}/sv2", state.vendor)
                        };
                        hooks
                            .session_persistence
                            .register_session(
                                &session_id_hex,
                                address.as_str(),
                                &worker,
                                channel_id,
                                Some(user_agent.as_str()),
                            )
                            .await;
                        if state.stream.is_pplns() {
                            let resolved = hooks.payout_resolver.resolve_stream(&address);
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
                                // PPLNS resolves to the boot stream → no swap.
                                // Logged for symmetry with the alt-stream case
                                // so PPLNS routing is visible too.
                                debug!(
                                    "sv2 connection {session_id_hex}: routed to {} template stream",
                                    resolved.as_label()
                                );
                            }
                        }
                    }
                }
                if let (Some((channel_id, _kind)), Some(template)) =
                    (newly_opened_channel, current_template.clone())
                {
                    // Apply a customer extranonce override (if any) BEFORE the
                    // first job is built, so the job's pinned prefix carries it.
                    // `None` for every connection without an override — no
                    // behaviour change for anyone else.
                    let custom_en_frame =
                        maybe_apply_custom_extranonce(&mut state, &hooks, channel_id);
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
                            let mut init_outcome = apply_template_broadcast(
                                &mut state,
                                &synthetic_broadcast,
                                &mining_job_inputs,
                                now_ms(),
                                Some(channel_id),
                            );
                            // SetExtranoncePrefix must precede the job it applies
                            // to (§5.3.10): the miner switches prefix, then the
                            // first job — built with that prefix — arrives next.
                            if let Some(frame) = custom_en_frame {
                                init_outcome.outbound.insert(0, frame);
                            }
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
                            // Address not locked yet — shouldn't happen
                            // because OpenChannel resolved + stored the
                            // address synchronously. Defensive log.
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
                // Fire apply_vardiff_check after an accepted share — not
                // just on the 60s timer tick.
                let has_accepted_share = outcome.events.iter().any(|e| {
                    matches!(e, SessionEvent::ShareAccepted { .. })
                });
                let fanout_start = std::time::Instant::now();
                apply_session_events(outcome.events, &session_id_hex, &state, &hooks).await;
                let fanout_us = fanout_start.elapsed().as_micros();
                // Inline vardiff after an accepted share: up-adjusts an active
                // miner promptly instead of waiting for the next timer tick.
                // Same shared path as the timer arm — see run_vardiff_check.
                if has_accepted_share
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
                // diag: full frame-arm processing time. recv→ack
                // (`latency_us` above) is only the early part — the share
                // event fan-out (hooks / Redis) + any job send run AFTER
                // the ack. If `iter_us` is large while `latency_us` is
                // small, that post-ack work blocked the loop and delayed
                // the NEXT share's read — the send→ack spike the recv→ack
                // window can't see.
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
                // Resolve payouts + build MiningJob if the connection
                // has an address locked. Pre-OpenChannel connections
                // have nothing to broadcast to — skip cleanly.
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
                let outcome = apply_template_broadcast(
                    &mut state,
                    &payload,
                    &mining_job_inputs,
                    now_ms(),
                    None,
                );
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

    // Release every prefix this connection still holds. `CloseChannel`
    // already releases on a graceful close, but a miner that drops its TCP
    // connection (power-cut, crash, network blip) never sends one — without
    // this the prefix stays in the allocator's `used` set until the process
    // restarts. Every exit from the loop above lands here: the arms only
    // `break`, none of them `?`. Releasing a key with no allocation is a
    // no-op, so double-releasing an already-closed channel is harmless.
    {
        let mut alloc = match extranonce_allocator.lock() {
            Ok(guard) => guard,
            // A poisoned allocator mutex must not strand the prefixes — the
            // map itself is still consistent (no `.await` is ever held across
            // the lock), so recover rather than panic on the teardown path.
            Err(poisoned) => poisoned.into_inner(),
        };
        for channel_id in state.channels.keys() {
            alloc.release(channel_alloc_key(state.session_id, *channel_id));
        }
    }

    hooks
        .session_persistence
        .deregister_session(&session_id_hex)
        .await;
    let _ = writer.shutdown().await;
    Ok(())
}

// ── Dispatch + Outbound write helpers ───────────────────────────────

/// Globally-unique key for the pool-wide extranonce allocator. The wire
/// `channel_id` is only unique within a connection (every connection's
/// first channel is id 1), so it is combined with the per-connection
/// random `session_id` into one u64 — otherwise two connections' "channel
/// 1" would collide in the shared allocator and be handed the same prefix.
fn channel_alloc_key(session_id: u32, channel_id: u32) -> u64 {
    ((session_id as u64) << 32) | (channel_id as u64)
}

/// Swap the pool-allocated extranonce prefix for the customer's chosen one on a
/// freshly-opened Extended channel, returning the
/// [`OutboundFrame::SetExtranoncePrefix`] that announces it — or `None` when no
/// override applies (the case for every connection but the paying customer's).
///
/// Solo-gated: the override is only safe without collision handling when the
/// session hashes its own payout coinbase, i.e. the Solo stream. On any other
/// stream the prefix is the sole work-partitioner across miners sharing one
/// coinbase, so a customer-picked value could overlap another miner's search.
///
/// The caller writes the returned frame BEFORE the channel's first job: per SV2
/// §5.3.10 a new prefix takes effect from the next job, and that first job is
/// built (via the per-job prefix pin on [`crate::mining::jobs::ExtendedJob`])
/// with the value set here — so the miner never hashes a job under the old one.
fn maybe_apply_custom_extranonce<C: bp_vardiff::Clock>(
    state: &mut MiningSessionState<C>,
    hooks: &MiningServerHooks,
    channel_id: u32,
) -> Option<OutboundFrame> {
    if state.stream != StreamKind::Solo {
        return None;
    }
    // Scope the immutable borrow of address/worker so the `&mut channels`
    // below doesn't conflict; the prefix is `Copy`.
    let prefix = {
        let address = state.address.as_ref()?;
        hooks
            .custom_extranonce
            .lookup(address.as_str(), &state.worker_name)?
    };
    let channel = state.channels.get_mut(&channel_id)?;
    // Extended only: the per-job prefix pin + the miner's own coinbase splice
    // are Extended-channel mechanics. A Standard channel bakes the prefix into
    // the coinbase differently, so an override there wouldn't reconstruct.
    if channel.kind != crate::mining::channel::ChannelKind::Extended {
        return None;
    }
    if channel.extranonce_prefix.as_slice() == prefix.as_slice() {
        return None; // already applied — nothing to announce
    }
    channel.extranonce_prefix = prefix.to_vec();
    Some(OutboundFrame::SetExtranoncePrefix {
        channel_id,
        extranonce_prefix: prefix.to_vec(),
    })
}

/// Translate an [`InboundMiningFrame`] into a call to the matching
/// `handle_*` function. Returns the resulting [`HandlerOutcome`]
/// (sync handlers — currently no async hooks needed at dispatch time).
///
/// Per-handler context resolution:
///
/// - **OpenStandard/Extended-MiningChannel**: allocates a fresh
///   extranonce-prefix via [`ExtranonceAllocator`] using
///   `state.next_channel_id` (the about-to-be-allocated id). The
///   pool-wide allocator mutex is locked ONLY inside the Open/Close
///   arms — never across the submit arms — so per-share validation on
///   one connection can't serialize behind channel churn on another.
///   On handler error the prefix is leaked until connection close —
///   acceptable since channel-open errors are rare.
/// - **CloseChannel**: releases the extranonce-prefix of every channel the
///   handler actually closed — one for a normal close, ALL members for a
///   group-channel close (spec §5.3.9). Driven by the emitted
///   `ChannelClosed` events so both paths share one release point.
/// - **SubmitSharesStandard / SubmitSharesExtended**: both validate
///   against the **per-job template snapshot** pinned on the job record
///   at send-time (SV2 §5.3.14 strict) — the `StandardJobEntry`'s
///   `template_snapshot` and the `ExtendedJob`'s `network_difficulty`
///   respectively. Neither consults the current template, so a
///   block-change between job-send and share-submit can't reclassify an
///   in-flight share's block-candidacy.
/// - **SetCustomMiningJob**: queries the bridge for the
///   `mining_job_token` and passes the resolved miner address (or
///   `None`) plus the issued payout set to the handler; the
///   cross-check + payout validation happen inside the handler, and
///   the payout set is single-use-consumed here on success.
pub(crate) fn dispatch_inbound_frame<C: bp_vardiff::Clock + Clone>(
    state: &mut MiningSessionState<C>,
    inbound: InboundMiningFrame,
    extranonce_allocator: &Mutex<ExtranonceAllocator>,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    now_ms: u64,
) -> HandlerOutcome {
    match inbound {
        InboundMiningFrame::SetupConnection(input) => handle_setup_connection(state, &input),
        InboundMiningFrame::RequestExtensions(input) => handle_request_extensions(state, &input),
        InboundMiningFrame::OpenStandardMiningChannel(input, _placeholder_prefix) => {
            let key = channel_alloc_key(state.session_id, state.next_channel_id);
            let prefix = extranonce_allocator
                .lock()
                .expect("extranonce allocator mutex poisoned")
                .allocate(key)
                .unwrap_or_else(|_| Vec::new());
            handle_open_standard_mining_channel(state, &input, prefix)
        }
        InboundMiningFrame::OpenExtendedMiningChannel(input, _placeholder_prefix) => {
            let key = channel_alloc_key(state.session_id, state.next_channel_id);
            let prefix = extranonce_allocator
                .lock()
                .expect("extranonce allocator mutex poisoned")
                .allocate(key)
                .unwrap_or_else(|_| Vec::new());
            handle_open_extended_mining_channel(state, &input, prefix)
        }
        InboundMiningFrame::UpdateChannel(input) => handle_update_channel(state, &input),
        InboundMiningFrame::CloseChannel(input) => {
            let outcome = handle_close_channel(state, &input);
            // Release the extranonce prefix of every channel the close
            // actually removed — one for a normal close, all members for a
            // group-channel close (spec §5.3.9). Releasing an id with no
            // allocation is a harmless no-op.
            let mut alloc = extranonce_allocator
                .lock()
                .expect("extranonce allocator mutex poisoned");
            for ev in &outcome.events {
                if let SessionEvent::ChannelClosed { channel_id, .. } = ev {
                    alloc.release(channel_alloc_key(state.session_id, *channel_id));
                }
            }
            drop(alloc);
            outcome
        }
        InboundMiningFrame::SubmitSharesStandard(input) => {
            // SV2 §5.3.14 strict: the per-job snapshot is stored on
            // the StandardJobEntry at send-time. Handler reads it
            // out itself — no IO-layer template snapshot needed.
            handle_submit_shares_standard(state, &input, now_ms)
        }
        InboundMiningFrame::SubmitSharesExtended(input) => {
            // SV2 §5.3.14 strict: the per-job `network_difficulty` is pinned
            // on the ExtendedJob at send-time. Handler reads it from the job
            // record — no IO-layer current-template lookup needed.
            handle_submit_shares_extended(state, &input, now_ms)
        }
        InboundMiningFrame::SetCustomMiningJob(input) => {
            let (bridge_addr, payout_set) = {
                let guard = bridge.read().expect("bridge RwLock poisoned");
                (
                    // Clone only the miner address — the handler doesn't need
                    // the (potentially large) declared-job payload.
                    guard
                        .lookup(&input.mining_job_token)
                        .map(|e| e.miner_address.clone()),
                    guard.lookup_payout_set(&input.mining_job_token).cloned(),
                )
            };
            let outcome = handle_set_custom_mining_job(
                state,
                &input,
                bridge_addr.as_ref(),
                payout_set.as_ref(),
                now_ms,
            );
            // ext 0x0003 single-use (spec §4): once the custom job is
            // accepted, consume the payout set so it can't back a second job.
            if payout_set.is_some()
                && outcome
                    .outbound
                    .iter()
                    .any(|f| matches!(f, OutboundFrame::SetCustomMiningJobSuccess { .. }))
            {
                bridge
                    .write()
                    .expect("bridge RwLock poisoned")
                    .consume_payout_set(&input.mining_job_token);
            }
            outcome
        }
    }
}

/// Serialise every [`OutboundFrame`] in `outbound` via
/// [`encode_mining_outbound`] + `Sv2Frame::try_from(any_message)`
/// and write it through the Noise stream. When `debug_messages` is
/// `true`, each frame produces a `📤 TX:` DEBUG log line carrying the
/// SV2 message name, msg_type byte, and payload length.
async fn write_outbound_frames(
    writer: &mut NoiseTcpWriteHalf<AnyMessage<'static>>,
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
        {
            let sv2_frame: StandardSv2Frame<AnyMessage<'static>> =
                any_message
                    .try_into()
                    .map_err(|e: stratum_core::parsers_sv2::ParserError| {
                        WriteError::Codec(crate::server_codec::CodecError::Conversion(format!(
                            "{e:?}"
                        )))
                    })?;
            writer
                .write_frame(Frame::Sv2(sv2_frame))
                .await
                .map_err(WriteError::Io)?;
        }
    }
    Ok(())
}

/// Run a vardiff check and emit its result on the wire.
///
/// Shared by BOTH vardiff trigger points — the 60 s `vardiff_tick` timer
/// (down-adjusts a miner that went quiet, the only path that fires when no
/// shares arrive) and the inline check after an accepted share (promptly
/// up-adjusts an active miner without waiting for the next tick). Factoring
/// it here means the two arms can never diverge — in particular neither can
/// re-introduce a job re-broadcast on a difficulty change.
///
/// SetTarget alone is the complete SV2 difficulty-change mechanism — it
/// applies to future share submissions on the current job, no new job
/// required. A synthetic `TemplateChange::NewBlock` re-broadcast must NOT run
/// here: it emits a fake `SetNewPrevHash` (same prev_hash, frozen
/// header_timestamp from the cached template, new job_id) and retires all
/// jobs, making firmware reset and re-mine the identical header → session
/// best-difficulty freezes. Mirrors `StratumV2Client.checkDifficultyAllChannels`.
///
/// Returns `Err(())` if the wire write failed and the caller should drop the
/// connection (mirrors the `break`-on-write-error in the other loop arms).
async fn run_vardiff_check(
    state: &mut MiningSessionState<SystemClock>,
    writer: &mut NoiseTcpWriteHalf<AnyMessage<'static>>,
    debug_messages: bool,
    session_id_hex: &str,
    hooks: &MiningServerHooks,
) -> Result<(), ()> {
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

/// Outbound-write failure modes.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("codec: {0}")]
    Codec(#[from] crate::server_codec::CodecError),
    #[error("noise io: {0:?}")]
    Io(crate::noise::NoiseError),
}

/// Resolve payouts + pack the per-template coinbase fields into a
/// [`MiningJobInputs`] the per-connection broadcast handler can rebuild
/// per channel with the correct extranonce-slot size. Returns
/// `Ok(None)` when the connection hasn't locked an address yet (no
/// `OpenStandardMiningChannel` / `OpenExtendedMiningChannel`
/// processed).
///
/// Production wiring calls into the service-layer mode-resolver via
/// [`crate::hooks::PayoutResolver`]; tests use
/// [`crate::hooks::NoOpHooks`] (single 100%-to-self entry).
async fn resolve_template_mining_job_inputs(
    address: &Option<AddressId>,
    server_config: &ServerConfig,
    template: &ActiveSV2Template,
    hooks: &MiningServerHooks,
    job_cache: &Arc<MiningJobCache>,
) -> Result<Option<MiningJobInputs>, MiningJobError> {
    let Some(addr) = address else {
        return Ok(None);
    };
    let payouts = hooks
        .payout_resolver
        .resolve_payouts(addr, template.coinbase_tx_value_remaining)
        .await;
    Ok(Some(MiningJobInputs {
        network: server_config.network,
        payouts,
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

/// Translate each [`SessionEvent`] into the matching hook call. Pure
/// async fan-out — no socket writes.
///
/// `state` carries the channel's address + worker_name; the hook
/// trait surface accepts them as `&str` so this resolves them once
/// at the top.
pub(crate) async fn apply_session_events(
    events: Vec<SessionEvent>,
    session_id_hex: &str,
    state: &MiningSessionState<SystemClock>,
    hooks: &MiningServerHooks,
) {
    apply_session_events_generic(events, session_id_hex, state, hooks).await;
}

/// Generic variant — same body but generic over the clock type so
/// unit tests can drive it with `MiningSessionState<Arc<TestClock>>`.
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
                // BitAxe / NerdQAxe send their firmware string in the
                // SetupConnection `vendor` field; we lift it into
                // `client_entity.userAgent` with a `/sv2` suffix so the
                // /api/info userAgents histogram surfaces hardware as
                // e.g. `bitaxe/sv2`, `NerdQAxe++/sv2`. JDP clients
                // typically send no vendor → fall back to
                // `jd-client/sv2` so the downstream-report POST can
                // later refine it to the actual primary vendor.
                // `register_session` (mode-gate publish + client_entity
                // write) already ran in the connection loop's channel-open
                // block, BEFORE stream routing — doing it here would resolve
                // the stream too late and double the gate refcount. We only
                // emit the device-online event here. The register call lifted
                // the vendor-derived UA into client_entity.userAgent for the
                // /api/info histogram (`bitaxe/sv2`, etc.).
                let user_agent_owned = if state.vendor.is_empty() {
                    "jd-client/sv2".to_string()
                } else {
                    format!("{}/sv2", state.vendor)
                };
                hooks
                    .device_status_sink
                    .on_device_event(
                        address.as_str(),
                        &worker,
                        session_id_hex,
                        Some(user_agent_owned.as_str()),
                        true,
                    )
                    .await;
            }
            SessionEvent::ChannelClosed { .. } => {
                if !address_str.is_empty() {
                    // Same vendor-derived UA the online/register path uses.
                    let user_agent = if state.vendor.is_empty() {
                        "jd-client/sv2".to_string()
                    } else {
                        format!("{}/sv2", state.vendor)
                    };
                    hooks
                        .device_status_sink
                        .on_device_event(
                            address_str,
                            worker_str,
                            session_id_hex,
                            Some(user_agent.as_str()),
                            false,
                        )
                        .await;
                }
            }
            SessionEvent::DifficultyChanged { .. } => {}
            SessionEvent::ShareAccepted { channel_id, accept } => {
                // ext 0x0002 Worker-ID TLV: when the per-share TLV
                // resolves to a non-empty worker name, attribute the
                // share to that worker rather than the channel-default
                // (spec §1.3). When None, fall back to channel-default
                // (no TLV present, or ext 0x0002 not negotiated).
                let effective_worker = accept
                    .effective_worker_name
                    .as_deref()
                    .unwrap_or(worker_str);
                // Both Standard and Extended channels funnel through this
                // shared handler, so label the banner / trace with the
                // channel's actual kind instead of a fixed string.
                let kind_label = match state.channels.get(&channel_id).map(|c| c.kind) {
                    Some(crate::mining::channel::ChannelKind::Standard) => "Standard",
                    Some(crate::mining::channel::ChannelKind::Extended) => "Extended",
                    None => "Unknown",
                };
                // Block-found banner — always at INFO so block events
                // are visible without any debug flag. Height isn't on
                // the ShareAccept payload — block_sink logs it again
                // with template_id.
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
                    // Per-share accept trace — gated by `share_logs`
                    // (DEBUG); thousands per minute in production.
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
                // Same vendor-derived UA the register / device-status
                // path uses (empty vendor ⇒ no UA).
                let user_agent = if state.vendor.is_empty() {
                    None
                } else {
                    Some(format!("{}/sv2", state.vendor))
                };
                hooks
                    .accepted_sink
                    .record_accepted(
                        address_str,
                        effective_worker,
                        session_id_hex,
                        user_agent.as_deref(),
                        &accept,
                        // Sum every channel's vardiff hash-rate so the per-session
                        // client row reports the whole connection's rate. For a 1:1
                        // miner this is its single channel; for a bundled rig (one
                        // connection, several channels) it is the rig total.
                        state.vardiff.values().map(|v| v.hash_rate()).sum::<f64>(),
                        state.channels.len() as u32,
                    )
                    .await;
                if accept.is_block_candidate {
                    // Route the solution to the handle of the stream this
                    // connection mines (Solo → solo handle). `state.stream` was
                    // locked at OpenChannel, matching the template the job used.
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
                // validate_submit_extended already emits a
                // `❌ Extended share rejected: <reason>` line at WARN
                // for each rejection — no further log needed here.
                // Keep the rejected_sink fan-out for metrics.
                let address_opt = state.address.as_ref().map(|a| a.as_str());
                let worker_opt = state.address.as_ref().map(|_| state.worker_name.as_str());
                let _ = channel_id;
                hooks
                    .rejected_sink
                    .record_rejected(
                        address_opt,
                        worker_opt,
                        session_id_hex,
                        reject.reason,
                        state.session_difficulty,
                    )
                    .await;
            }
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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

    /// The pool-wide extranonce allocator must hand DISTINCT prefixes to the
    /// same wire `channel_id` (1) opened on two different connections —
    /// otherwise same-address Standard miners mine byte-identical work. The
    /// per-connection allocator this replaced gave both the same prefix.
    #[test]
    fn shared_allocator_distinct_prefix_per_session_same_channel_id() {
        let mut alloc = ExtranonceAllocator::new_default();
        let p_a = alloc.allocate(channel_alloc_key(0xAAAA_AAAA, 1)).unwrap();
        let p_b = alloc.allocate(channel_alloc_key(0xBBBB_BBBB, 1)).unwrap();
        assert_ne!(
            p_a, p_b,
            "channel_id=1 on two sessions must get distinct prefixes"
        );
        // Same (session, channel) re-allocation is idempotent.
        assert_eq!(
            p_a,
            alloc.allocate(channel_alloc_key(0xAAAA_AAAA, 1)).unwrap()
        );
        // Release frees it for reuse.
        alloc.release(channel_alloc_key(0xAAAA_AAAA, 1));
        assert!(alloc
            .get_prefix(channel_alloc_key(0xAAAA_AAAA, 1))
            .is_none());
    }

    const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    fn noise_cfg() -> NoiseConfig {
        NoiseConfig::parse_strings(
            "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72",
            "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n",
            crate::noise::DEFAULT_CERT_VALIDITY,
        )
        .unwrap()
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
            ),
        );
        s
    }

    /// Solo + Extended + a matching override: the channel's prefix is swapped
    /// and a SetExtranoncePrefix frame is returned to announce it.
    #[test]
    fn custom_extranonce_swaps_prefix_and_emits_frame_on_solo_extended() {
        const CUSTOM: [u8; 4] = [0xC0, 0xDE, 0xBA, 0xBE];
        let mut s = solo_session_with_extended_channel(7, vec![0x00, 0x00, 0x00, 0x05]);
        let hooks = hooks_with_override(ADDR, "wrk", CUSTOM);

        match maybe_apply_custom_extranonce(&mut s, &hooks, 7) {
            Some(OutboundFrame::SetExtranoncePrefix {
                channel_id,
                extranonce_prefix,
            }) => {
                assert_eq!(channel_id, 7);
                assert_eq!(extranonce_prefix, CUSTOM.to_vec());
            }
            other => panic!("expected SetExtranoncePrefix, got {other:?}"),
        }
        // Channel now carries the custom prefix, so its next job pins it.
        assert_eq!(
            s.channels.get(&7).unwrap().extranonce_prefix,
            CUSTOM.to_vec()
        );
    }

    /// The Solo gate: on any non-Solo stream the override is ignored and the
    /// prefix left untouched — the prefix is the sole partitioner across a
    /// shared coinbase there, so a customer value could overlap another miner.
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

    /// No override for this worker → no frame, prefix untouched. This is the
    /// path every non-customer connection takes.
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

    /// Already applied (channel holds the override) → no redundant frame. Lets
    /// the broadcast path (stage 2) call this every job without re-announcing.
    #[test]
    fn custom_extranonce_idempotent_when_already_applied() {
        const CUSTOM: [u8; 4] = [0xC0, 0xDE, 0xBA, 0xBE];
        let mut s = solo_session_with_extended_channel(7, CUSTOM.to_vec());
        let hooks = hooks_with_override(ADDR, "wrk", CUSTOM);
        assert!(maybe_apply_custom_extranonce(&mut s, &hooks, 7).is_none());
    }

    /// Standard channels are out of scope: the prefix is baked into the
    /// coinbase differently there, so an override wouldn't reconstruct.
    #[test]
    fn custom_extranonce_skips_standard_channel() {
        let mut s = fresh_session_with_address();
        s.stream = StreamKind::Solo;
        s.channels.insert(
            7,
            crate::mining::channel::ChannelState::new_standard(
                7,
                vec![0x00, 0x00, 0x00, 0x05],
                Difficulty(1024.0),
                [0xFF; 32],
            ),
        );
        let hooks = hooks_with_override(ADDR, "wrk", [0xC0, 0xDE, 0xBA, 0xBE]);
        assert!(maybe_apply_custom_extranonce(&mut s, &hooks, 7).is_none());
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
            Arc::new(MiningJobCache::new()),
        );
        // Random u32 IDs (4 OS-CSPRNG bytes → BE u32) — collision odds
        // across three draws are ~negligible. Test pins distinctness +
        // hex-format width.
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
            Arc::new(MiningJobCache::new()),
        );
        assert!(server.current_template().is_none());
        tdp_tx
            .send(TemplateUpdate::NewTemplate(nt(7, true)))
            .unwrap();
        tdp_tx
            .send(TemplateUpdate::SetNewPrevHash(snph(7)))
            .unwrap();
        // Give translator a tick to consume.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let snap = server.current_template();
        assert!(snap.is_some());
        assert_eq!(snap.unwrap().template_id, 7);
        server.shutdown().await;
    }

    // ── apply_session_events fan-out ───────────────────────────────

    fn accept() -> ShareAccept {
        ShareAccept {
            classification: JobClassification::Active,
            effective_difficulty: Difficulty(1024.0),
            submission_difficulty: Difficulty(2048.0),
            header: [0u8; 80],
            hash: [0u8; 32],
            is_block_candidate: false,
            template_id: None,
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

    /// Each accepted share carries the connection's open-channel count so the
    /// persistence layer can mark a bundled rig's difficulty as aggregated. A
    /// rental proxy bundles several same-rig devices onto ONE connection (N
    /// channels); a direct miner has 1. The count is the live channel total,
    /// not a constant.
    #[tokio::test(flavor = "current_thread")]
    async fn accepted_share_reports_open_channel_count() {
        use crate::mining::channel::ChannelState;

        let mk_channel = |cid: u32| {
            ChannelState::new_standard(cid, vec![0u8; 4], Difficulty(1024.0), [0xffu8; 32])
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
        assert_eq!(records[0].reason, RejectReason::StaleShare);
        assert_eq!(records[0].address.as_deref(), Some(ADDR));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn channel_opened_event_fans_out_to_device_status() {
        // `register_session` (mode-gate publish) moved to the connection
        // loop's channel-open block — it must run BEFORE stream routing,
        // so it is no longer fired from `apply_session_events`. The
        // ChannelOpened arm here now only emits the device-online event;
        // registration is covered end-to-end by the connection-loop /
        // regtest paths.
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
        // No register from this layer anymore.
        assert!(recording.registered.lock().unwrap().is_empty());
        // Device-online event fired (address is the session's locked one).
        let devices = recording.device_events.lock().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].1, "worker-7");
        assert!(devices[0].2, "online flag");
    }

    /// Empty event list is a no-op (no hook calls). Pins that the
    /// fan-out doesn't fire spurious blanks.
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

    fn active_template_fixture() -> ActiveSV2Template {
        ActiveSV2Template {
            template_id: 1,
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
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
        // The packed inputs build into a valid MiningJob for any
        // channel-negotiated slot size.
        let job = inputs
            .build(bp_mining_job::EXTRANONCE_SLOT_LEN)
            .expect("MiningJobInputs.build for default slot");
        assert!(!job.coinbase_prefix().is_empty());
        assert!(!job.coinbase_suffix().is_empty());
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

    use crate::extranonce::ExtranonceAllocator;
    use crate::mining::client::{
        SetupConnectionInput, FLAG_REQUIRES_VERSION_ROLLING, PROTOCOL_MINING,
    };
    use crate::mining::submit::SubmitSharesStandardInput;
    use crate::server_codec::InboundMiningFrame;

    fn fresh_test_session() -> MiningSessionState<Arc<TestClock>> {
        MiningSessionState::new(Arc::new(TestClock::new(0)), 1, _port_cfg())
    }

    fn fresh_bridge() -> Arc<RwLock<JdpDeclaredJobRegistry>> {
        Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()))
    }

    /// Dispatching a `SetupConnection` frame produces the matching
    /// success outcome from the pure handler.
    #[test]
    fn dispatch_setup_connection_emits_success() {
        let mut s = fresh_test_session();
        let alloc = Mutex::new(ExtranonceAllocator::new_default());
        let bridge = fresh_bridge();
        let inbound = InboundMiningFrame::SetupConnection(SetupConnectionInput {
            protocol: PROTOCOL_MINING,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            vendor: "test".to_string(),
            firmware: "0.1".to_string(),
            hardware_version: "rev1".to_string(),
            device_id: "dev-1".to_string(),
        });
        let outcome = dispatch_inbound_frame(&mut s, inbound, &alloc, &bridge, 0);
        assert!(matches!(
            outcome.outbound[0],
            crate::mining::client::OutboundFrame::SetupConnectionSuccess { .. }
        ));
        assert!(s.setup_complete);
    }

    /// Dispatching `SubmitSharesStandard` against an unknown channel
    /// emits `invalid-channel-id`. (With per-job template snapshots
    /// in `StandardJobMaps`, `current_template` no longer matters at
    /// dispatch — the snapshot lives on the JobEntry. The pre-channel
    /// race-defensive path now collapses into the standard channel-
    /// lookup error.)
    #[test]
    fn dispatch_submit_standard_unknown_channel_emits_invalid_channel_id() {
        let mut s = fresh_test_session();
        let alloc = Mutex::new(ExtranonceAllocator::new_default());
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

    /// Dispatching `CloseChannel` releases the closed channel's extranonce
    /// prefix back to the allocator — driven by the emitted `ChannelClosed`
    /// event. Open a real channel through dispatch (so the allocator + session
    /// agree on the id), then close it and pin via allocated_count.
    #[test]
    fn dispatch_close_channel_releases_extranonce_prefix() {
        let mut s = fresh_test_session();
        let alloc = Mutex::new(ExtranonceAllocator::new_default());
        let bridge = fresh_bridge();
        let setup = InboundMiningFrame::SetupConnection(SetupConnectionInput {
            protocol: PROTOCOL_MINING,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            vendor: "t".to_string(),
            firmware: "0.1".to_string(),
            hardware_version: "r".to_string(),
            device_id: "d".to_string(),
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
        let before = alloc.lock().unwrap().allocated_count();
        assert_eq!(before, 1, "one prefix allocated for the open channel");

        let inbound = InboundMiningFrame::CloseChannel(crate::mining::client::CloseChannelInput {
            channel_id: cid,
            reason_code: "user-quit".to_string(),
        });
        let _ = dispatch_inbound_frame(&mut s, inbound, &alloc, &bridge, 0);
        assert_eq!(
            alloc.lock().unwrap().allocated_count(),
            before - 1,
            "close releases the channel's prefix"
        );
    }

    /// A `CloseChannel` addressed to a group_channel_id releases the
    /// extranonce prefix of EVERY member (spec §5.3.9), driven by the per-
    /// member `ChannelClosed` events. Two grouped Extended channels → both
    /// prefixes freed on a single group close.
    #[test]
    fn dispatch_group_close_releases_all_member_prefixes() {
        let mut s = fresh_test_session();
        let alloc = Mutex::new(ExtranonceAllocator::new_default());
        let bridge = fresh_bridge();
        // non-RSJ setup → Extended channels are grouped.
        let setup = InboundMiningFrame::SetupConnection(SetupConnectionInput {
            protocol: PROTOCOL_MINING,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            vendor: "t".to_string(),
            firmware: "0.1".to_string(),
            hardware_version: "r".to_string(),
            device_id: "d".to_string(),
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
        assert_eq!(
            alloc.lock().unwrap().allocated_count(),
            2,
            "two member prefixes allocated"
        );
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
            alloc.lock().unwrap().allocated_count(),
            0,
            "group close must release every member's prefix"
        );
        assert!(s.channels.is_empty());
    }

    /// ext 0x0003 single-use end-to-end: dispatching a `SetCustomMiningJob`
    /// whose coinbase carries the bridge-registered payout set succeeds and
    /// the IO layer consumes the set; a second dispatch with the same token
    /// is rejected `stale-payout-outputs`.
    #[test]
    fn dispatch_set_custom_mining_job_consumes_payout_set_single_use() {
        use crate::jdp::dynamic_outputs::{encode_coinbase_outputs, DynamicOutput};
        use crate::mining::client::SetCustomMiningJobInput;
        use crate::tokens::Token;
        use bp_common::{AddressId, Sats};

        let mut s = fresh_test_session();
        let alloc = Mutex::new(ExtranonceAllocator::new_default());
        let bridge = fresh_bridge();
        let setup = InboundMiningFrame::SetupConnection(SetupConnectionInput {
            protocol: PROTOCOL_MINING,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            vendor: "t".to_string(),
            firmware: "0.1".to_string(),
            hardware_version: "r".to_string(),
            device_id: "d".to_string(),
        });
        let _ = dispatch_inbound_frame(&mut s, setup, &alloc, &bridge, 0);
        let open = InboundMiningFrame::OpenExtendedMiningChannel(
            crate::mining::client::OpenExtendedMiningChannelInput {
                request_id: 1,
                user_identity: format!("{ADDR}.w"),
                nominal_hash_rate: 1_000_000.0,
                max_target: [0xFF; 32],
                min_extranonce_size: 8,
            },
            Vec::new(),
        );
        let _ = dispatch_inbound_frame(&mut s, open, &alloc, &bridge, 0);
        let cid = s.primary_channel.expect("extended channel opened");

        // Pool commits a single payout output to the channel's miner.
        let committed = encode_coinbase_outputs(
            Network::Regtest,
            &[DynamicOutput {
                address: AddressId::new(ADDR.to_string()).unwrap(),
                sats: Sats(600),
            }],
        )
        .unwrap();
        let token = Token([7u8; 16]);
        bridge.write().unwrap().register_payout_set(
            token,
            crate::bridge::IssuedPayoutSet {
                outputs: committed.clone(),
                miner_address: AddressId::new(ADDR.to_string()).unwrap(),
                jdp_session_id: 1,
                registered_at_ms: 0,
                issued_prev_hash: Some([0xAB; 32]), // matches the job's prev_hash → fresh
                used: false,
            },
        );

        let make_input = |req: u32| SetCustomMiningJobInput {
            channel_id: cid,
            request_id: req,
            mining_job_token: token,
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            min_ntime: 0x6500_0001,
            n_bits: 0x1d00_ffff,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![0x03, 0xC8, 0x00],
            coinbase_tx_input_n_sequence: 0xFFFF_FFFF,
            coinbase_tx_outputs: committed.clone(),
            coinbase_tx_locktime: 0,
            merkle_path: vec![[0x11; 32]],
        };

        // First: carries the committed output → accept + consume.
        let out1 = dispatch_inbound_frame(
            &mut s,
            InboundMiningFrame::SetCustomMiningJob(make_input(1)),
            &alloc,
            &bridge,
            0,
        );
        assert!(matches!(
            out1.outbound[0],
            crate::mining::client::OutboundFrame::SetCustomMiningJobSuccess { .. }
        ));
        assert!(
            bridge
                .read()
                .unwrap()
                .lookup_payout_set(&token)
                .unwrap()
                .used,
            "payout set must be consumed after a successful custom job"
        );

        // Second: same token, now consumed → stale-payout-outputs.
        let out2 = dispatch_inbound_frame(
            &mut s,
            InboundMiningFrame::SetCustomMiningJob(make_input(2)),
            &alloc,
            &bridge,
            0,
        );
        match &out2.outbound[0] {
            crate::mining::client::OutboundFrame::SetCustomMiningJobError {
                error_code, ..
            } => {
                assert_eq!(error_code, crate::mining::client::ERR_STALE_PAYOUT_OUTPUTS);
            }
            other => panic!("expected stale error, got {other:?}"),
        }
    }

    /// dispatch_inbound_frame doesn't async-await anywhere internally
    /// — invoking it from sync test code is intentional + ensures the
    /// IO-layer doesn't accidentally introduce a hidden await.
    #[test]
    fn dispatch_is_synchronous_to_handlers() {
        let mut s = fresh_test_session();
        let alloc = Mutex::new(ExtranonceAllocator::new_default());
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

    /// Empty outbound vec is a no-op write — write_outbound_frames
    /// can short-circuit. Pin via building the call but with a
    /// dummy writer? Not testable without a real noise stream — but
    /// we can at least assert that encode_mining_outbound for an
    /// arbitrary OutboundFrame produces an AnyMessage that try_into
    /// converts cleanly to a StandardSv2Frame. That's the second
    /// half of write_outbound_frames; the first half (write_frame
    /// over noise) needs a regtest.
    #[test]
    fn outbound_frame_encodes_and_wraps_to_sv2_frame() {
        let outbound = crate::mining::client::OutboundFrame::SubmitSharesSuccess {
            channel_id: 1,
            last_sequence_number: 42,
            new_submits_accepted_count: 1,
            new_shares_sum: 1024,
        };
        let any_msg = crate::server_codec::encode_mining_outbound(outbound).unwrap();
        let result: Result<StandardSv2Frame<AnyMessage<'static>>, _> = any_msg.try_into();
        assert!(result.is_ok(), "AnyMessage must wrap into StandardSv2Frame");
    }
}
