// SPDX-License-Identifier: AGPL-3.0-or-later

//! Server handle, TDP translator task, per-connection driver.
//!
//! Three pieces wired together:
//!
//! 1. **`StratumV1Server`** — the public handle. Holds the shared
//!    [`ServerConfig`] + [`JobRegistry`] + [`ServerHooks`], owns the
//!    translator task, exposes `accept_connection(socket, port_config)`
//!    + `shutdown()`.
//!
//! 2. **Translator task** — consumes
//!    [`bp_template_distribution::TemplateUpdate`] from a
//!    `broadcast::Receiver` (= `TdpHandle::subscribe()` in production),
//!    feeds them to an [`SV1TemplateAssembler`], and re-broadcasts the
//!    resulting `(ActiveSV1Template, TemplateChange)` pairs to every
//!    per-connection task. Also maintains a `Mutex<Option<ActiveSV1Template>>`
//!    snapshot so freshly-accepted connections can boot from the current
//!    state without waiting for the next TDP update.
//!
//! 3. **Per-connection task** — owns the `TcpStream`, the
//!    [`SessionState`], and a `broadcast::Receiver<TemplateBroadcast>`.
//!    Drives the protocol via `tokio::select!` on four sources:
//!    inbound line, template broadcast, vardiff-check timer, cancel
//!    token. Each iteration translates the resulting [`HandlerOutcome`]
//!    into socket writes + hook calls.
//!
//! All three pieces share a single [`CancellationToken`] — `shutdown()`
//! cancels the token, the translator + all connections notice on their
//! next `select`, drop their writers (the FIN goes out on socket-close),
//! and exit.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bp_common::ExtranonceAllocator;
use bp_common::StreamKind;
use bp_template_distribution::TemplateUpdate;
use futures::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, LinesCodec, LinesCodecError};

/// Hard cap on a single Stratum-V1 line (newline-delimited JSON-RPC).
/// Real requests are well under 1 KiB (the largest is a `mining.configure`
/// with version-rolling); 16 KiB is ~66× headroom so no legitimate miner
/// is ever affected. Without a cap, a single connection sending bytes with
/// no newline grows the line buffer unboundedly → OOM from one peer. On
/// overflow we drop only that connection.
const MAX_STRATUM_LINE_BYTES: usize = 16 * 1024;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::client::{
    apply_new_template, apply_vardiff_check, dispatch, random_session_id_hex, HandlerOutcome,
    SessionEvent, SessionState,
};
use crate::config::{PortConfig, ServerConfig};
use crate::hooks::ServerHooks;
use crate::jobs::JobRegistry;
use crate::notify::{ActiveSV1Template, SV1TemplateAssembler, TemplateChange};
use bp_mining_job::PayoutEntry;
use bp_vardiff::SystemClock;

/// Pool-wide (across every SV1 port) collision-free extranonce1 allocator
/// plus its per-connection key counter. Constructed once by the binary
/// and shared into every [`StratumV1Server`] so two miners — even on
/// different ports — can never be handed the same extranonce1.
///
/// Cheap to clone (both fields are `Arc`). Each connection calls
/// [`allocate`](Self::allocate) exactly once at accept time; the returned
/// [`PrefixGuard`] releases the prefix back to the pool when the
/// connection task ends (any exit path — EOF, cancel, IO error).
#[derive(Clone)]
pub struct SharedExtranonce {
    allocator: Arc<Mutex<ExtranonceAllocator>>,
    /// Monotonic per-connection key. The allocator only needs the key to
    /// be unique within this (SV1) instance, so a plain counter suffices
    /// — SV2's separate instance never shares this map.
    next_key: Arc<AtomicU64>,
}

impl SharedExtranonce {
    /// Build a fresh SV1 allocator on [`bp_common::extranonce::SV1_WORKER_ID`]
    /// (disjoint from SV2's worker 0). Call once in the binary and clone
    /// into every port.
    pub fn new() -> Self {
        Self {
            allocator: Arc::new(Mutex::new(ExtranonceAllocator::new_default_on_worker(
                bp_common::extranonce::SV1_WORKER_ID,
            ))),
            next_key: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Allocate a pool-wide-unique 4-byte extranonce1. The returned guard
    /// releases the prefix on drop, covering every connection-exit path.
    /// [`PrefixGuard::prefix`] is `None` only when the (16.7M-slot) space
    /// is exhausted — the caller then keeps the session-id-derived
    /// extranonce1, i.e. the pre-unification random behaviour.
    pub fn allocate(&self) -> PrefixGuard {
        let key = self.next_key.fetch_add(1, Ordering::Relaxed);
        // Recover a poisoned lock rather than degrading silently: the
        // allocator is never left half-updated (its ops don't panic
        // mid-mutation), so a panic elsewhere must NOT permanently force
        // every future connection onto the non-unique session-id-derived
        // fallback. A `None` prefix below therefore means genuine
        // partition exhaustion, which the caller logs.
        let mut alloc = self
            .allocator
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let prefix = alloc
            .allocate(key)
            .ok()
            .and_then(|bytes| <[u8; 4]>::try_from(bytes.as_slice()).ok());
        drop(alloc);
        PrefixGuard {
            key,
            prefix,
            allocator: self.allocator.clone(),
        }
    }

    /// Number of extranonce1 prefixes currently checked out (one per live
    /// connection). Exposed for tests + potential metrics.
    pub fn allocated_count(&self) -> usize {
        self.allocator
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .allocated_count()
    }
}

impl Default for SharedExtranonce {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII claim on one extranonce1 prefix. Dropping it returns the prefix
/// to the shared allocator (idempotent for the exhausted/`None` case).
pub struct PrefixGuard {
    key: u64,
    prefix: Option<[u8; 4]>,
    allocator: Arc<Mutex<ExtranonceAllocator>>,
}

impl PrefixGuard {
    /// The allocated prefix, or `None` when the partition was exhausted
    /// (caller falls back to the session-id-derived extranonce1).
    pub fn prefix(&self) -> Option<[u8; 4]> {
        self.prefix
    }
}

impl Drop for PrefixGuard {
    fn drop(&mut self) {
        // Recover a poisoned lock so the prefix is always returned to the
        // pool — otherwise a single panic elsewhere would leak prefixes
        // toward exhaustion.
        self.allocator
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .release(self.key);
    }
}

/// Broadcast payload from translator → per-connection tasks. The clone
/// per subscriber is necessary because `apply_new_template` consumes the
/// template by reference; the production tracer/observability layer may
/// also tee these for metrics.
#[derive(Clone, Debug)]
pub struct TemplateBroadcast {
    /// `Arc` so the tokio broadcast channel hands each of the N connected
    /// sessions a refcount bump rather than a full deep copy of the
    /// template (merkle path + hex branches + coinbase buffers) on every
    /// NewBlock/Refresh. At ~600 sessions that's 600 deep clones per
    /// broadcast turned into 600 pointer bumps.
    pub template: Arc<ActiveSV1Template>,
    pub change: TemplateChange,
}

/// Capacity for the translator → connection broadcast channel. Lagged
/// subscribers receive `broadcast::error::RecvError::Lagged` and the
/// per-connection task treats it as "use the snapshot on next loop". The
/// default `32` is well above the expected drift between TDP arrival
/// and the per-connection select firing.
const TEMPLATE_BROADCAST_CAPACITY: usize = 32;

/// Public handle for the server. Cheap to clone (internal `Arc`); the
/// last clone holds the translator task's `JoinHandle`. Calling
/// [`shutdown`] is the only way to stop the translator cleanly.
#[derive(Clone)]
pub struct StratumV1Server {
    inner: Arc<Inner>,
}

struct Inner {
    server_config: Arc<ServerConfig>,
    registry: Arc<JobRegistry>,
    hooks: ServerHooks,
    // PPLNS stream (PPLNS-autoscaled reservation) — every connection boots
    // here before its payout mode is resolved.
    template_tx: broadcast::Sender<TemplateBroadcast>,
    current_template: Arc<Mutex<Option<Arc<ActiveSV1Template>>>>,
    // Fixed-reservation alt streams (Solo / GroupSolo / Blockparty) keyed by
    // StreamKind — a connection switches onto one at `mining.authorize` when
    // its address resolves to that mode. Each is fed by its own translator off
    // the matching TDP handle.
    alt_streams: HashMap<StreamKind, AltStream>,
    /// Pool-wide extranonce1 allocator, shared across every SV1 port so
    /// no two connections are ever handed the same prefix.
    extranonce: SharedExtranonce,
    cancel: CancellationToken,
    translator_join: Mutex<Option<JoinHandle<()>>>,
    alt_translator_joins: Mutex<Vec<JoinHandle<()>>>,
}

/// One fixed-reservation alt template stream: the broadcast sender per-connection
/// tasks subscribe to + the current-template snapshot a freshly-routed connection
/// boots from. Mirrors the PPLNS stream's `template_tx` / `current_template`.
struct AltStream {
    template_tx: broadcast::Sender<TemplateBroadcast>,
    current_template: Arc<Mutex<Option<Arc<ActiveSV1Template>>>>,
}

/// A single connection's claim on one alt stream — its own broadcast receiver
/// plus the snapshot to boot from. The per-connection task holds a
/// `HashMap<StreamKind, AltStreamHandle>` and `remove`s the matching entry when
/// it swaps onto that stream.
struct AltStreamHandle {
    rx: broadcast::Receiver<TemplateBroadcast>,
    initial: Option<Arc<ActiveSV1Template>>,
}

impl StratumV1Server {
    /// Spawn the server. `updates_rx` is typically
    /// `tdp_handle.subscribe()`; the translator drives an internal
    /// [`SV1TemplateAssembler`] and re-broadcasts pair-completed
    /// templates.
    ///
    /// `initial_snapshot` should be the result of
    /// `tdp_handle.current_snapshot()` taken right around the same time
    /// as `subscribe()`. The translator applies it to its assembler
    /// before entering the main loop so the very first connection sees
    /// a non-empty `current_template` even when the bitcoin-core
    /// bootstrap pair was sent before the broadcast subscription
    /// existed (subscribe-after-send race).
    ///
    /// Returns immediately — the translator runs on a Tokio task tied to
    /// the shared cancel token.
    pub fn spawn(
        server_config: ServerConfig,
        updates_rx: broadcast::Receiver<TemplateUpdate>,
        initial_snapshot: bp_template_distribution::TemplateSnapshot,
        alt_streams: Vec<(
            StreamKind,
            broadcast::Receiver<TemplateUpdate>,
            bp_template_distribution::TemplateSnapshot,
        )>,
        hooks: ServerHooks,
        extranonce: SharedExtranonce,
    ) -> Self {
        let server_config = Arc::new(server_config);
        let registry = Arc::new(JobRegistry::from_server_config(&server_config));
        let (template_tx, _) = broadcast::channel(TEMPLATE_BROADCAST_CAPACITY);
        let current_template = Arc::new(Mutex::new(None::<Arc<ActiveSV1Template>>));
        let cancel = CancellationToken::new();

        let translator_join = tokio::spawn(run_translator(
            updates_rx,
            initial_snapshot,
            template_tx.clone(),
            current_template.clone(),
            cancel.clone(),
        ));
        // One translator per alt stream, each off its own TDP handle.
        let mut alt_map = HashMap::with_capacity(alt_streams.len());
        let mut alt_joins = Vec::with_capacity(alt_streams.len());
        for (kind, alt_updates_rx, alt_initial_snapshot) in alt_streams {
            let (alt_tx, _) = broadcast::channel(TEMPLATE_BROADCAST_CAPACITY);
            let alt_current = Arc::new(Mutex::new(None::<Arc<ActiveSV1Template>>));
            alt_joins.push(tokio::spawn(run_translator(
                alt_updates_rx,
                alt_initial_snapshot,
                alt_tx.clone(),
                alt_current.clone(),
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
                registry,
                hooks,
                template_tx,
                current_template,
                alt_streams: alt_map,
                extranonce,
                cancel,
                translator_join: Mutex::new(Some(translator_join)),
                alt_translator_joins: Mutex::new(alt_joins),
            }),
        }
    }

    pub fn server_config(&self) -> &Arc<ServerConfig> {
        &self.inner.server_config
    }

    pub fn job_registry(&self) -> &Arc<JobRegistry> {
        &self.inner.registry
    }

    /// Snapshot of the latest assembled template, or `None` if the
    /// translator hasn't paired a `NewTemplate` + `SetNewPrevHash` yet.
    /// Useful for tests + the Phase-7 startup sequence (gate accepting
    /// connections on a non-empty snapshot if you want every new miner
    /// to receive a `mining.notify` immediately after handshake).
    pub fn current_template(&self) -> Option<Arc<ActiveSV1Template>> {
        self.inner
            .current_template
            .lock()
            .expect("current_template mutex poisoned")
            .clone()
    }

    /// Spawn a per-connection task. Returns once the task is scheduled;
    /// the connection runs until the socket closes, the cancel token
    /// fires, or the session signals `Disconnect`.
    ///
    /// The TCP-accept loop calls this for each socket the
    /// `bp_protocol_detect` router has identified as SV1.
    pub fn accept_connection(&self, socket: TcpStream, port_config: PortConfig) -> JoinHandle<()> {
        let server_config = self.inner.server_config.clone();
        let registry = self.inner.registry.clone();
        let hooks = self.inner.hooks.clone();
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
        let extranonce = self.inner.extranonce.clone();

        tokio::spawn(async move {
            let result = run_connection(
                server_config,
                port_config,
                registry,
                template_rx,
                initial_template,
                alt_streams,
                hooks,
                socket,
                cancel,
                extranonce,
            )
            .await;
            if let Err(err) = result {
                debug!("sv1 connection ended: {err}");
            }
        })
    }

    /// Cancel the translator + every running connection. Idempotent.
    /// Waits for the translator to finish on the first call; later
    /// calls are no-ops.
    ///
    /// Connections drop their writers on cancel — the FIN goes out via
    /// the normal `TcpStream::shutdown` path.
    pub async fn shutdown(&self) {
        self.inner.cancel.cancel();
        let handle = self
            .inner
            .translator_join
            .lock()
            .expect("translator_join mutex poisoned")
            .take();
        if let Some(h) = handle {
            if let Err(err) = h.await {
                warn!("sv1 translator task panicked during shutdown: {err}");
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
            if let Err(err) = h.await {
                warn!("sv1 alt translator task panicked during shutdown: {err}");
            }
        }
    }
}

// ── Translator task ──────────────────────────────────────────────────

/// Consume TDP updates, feed an `SV1TemplateAssembler`, and re-broadcast
/// the resulting `(template, change)` pairs. Maintains
/// `current_template` so freshly-accepted connections can boot from the
/// most recent state without waiting for the next TDP message.
///
/// Exits cleanly on `cancel` OR when `updates_rx` closes (= upstream
/// `TdpHandle` dropped).
async fn run_translator(
    mut updates_rx: broadcast::Receiver<TemplateUpdate>,
    initial_snapshot: bp_template_distribution::TemplateSnapshot,
    template_tx: broadcast::Sender<TemplateBroadcast>,
    current_template: Arc<Mutex<Option<Arc<ActiveSV1Template>>>>,
    cancel: CancellationToken,
) {
    let mut assembler = SV1TemplateAssembler::new();

    // Bootstrap the assembler from the TdpHandle snapshot. The handle's
    // internal tap subscribes BEFORE the worker thread starts so it
    // catches bitcoin-core's startup NewTemplate + SetNewPrevHash pair
    // — which the per-port broadcast subscriber here typically misses
    // because TdpHandle::spawn returns + Stratum-server construction
    // takes long enough that bridge_out emits the pair before this
    // subscribe gets installed. Without the bootstrap, current_template
    // stays None until the next on-chain block arrives.
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
                debug!("sv1 translator shutting down");
                return;
            }
            update = updates_rx.recv() => {
                let update = match update {
                    Ok(u) => u,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // The assembler is the only TDP consumer in this
                        // path; if we lag the upstream channel something
                        // upstream is malfunctioning. Logged + recovered:
                        // the next NewTemplate/SetNewPrevHash pair gets
                        // through.
                        warn!("sv1 translator lagged {n} TDP updates");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!("sv1 translator: TDP source closed");
                        return;
                    }
                };
                if let Some(change) = assembler.apply(&update) {
                    if let Some(active) = assembler.current().cloned() {
                        let active = Arc::new(active);
                        // Update the snapshot under the lock then drop
                        // it BEFORE the broadcast send so we never hold
                        // the mutex across an await point.
                        {
                            let mut guard = current_template
                                .lock()
                                .expect("current_template mutex poisoned");
                            *guard = Some(active.clone());
                        }
                        // Broadcast::send errors only when there are no
                        // subscribers — that's fine, freshly-accepted
                        // connections will pick up via the snapshot.
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

// ── Per-connection task ──────────────────────────────────────────────

/// Drive a single SV1 connection from accept-to-close. Uses
/// [`SystemClock`] in production; tests drive the pure handlers
/// directly via `client::dispatch`.
#[allow(clippy::too_many_arguments)]
async fn run_connection(
    server_config: Arc<ServerConfig>,
    port_config: PortConfig,
    registry: Arc<JobRegistry>,
    mut template_rx: broadcast::Receiver<TemplateBroadcast>,
    initial_template: Option<Arc<ActiveSV1Template>>,
    mut alt_streams: HashMap<StreamKind, AltStreamHandle>,
    hooks: ServerHooks,
    socket: TcpStream,
    cancel: CancellationToken,
    extranonce: SharedExtranonce,
) -> std::io::Result<()> {
    let (read_half, mut write_half) = socket.into_split();
    // Length-capped line framing: a peer that never sends a newline can no
    // longer grow the read buffer without bound (see MAX_STRATUM_LINE_BYTES).
    let mut lines = FramedRead::new(
        read_half,
        LinesCodec::new_with_max_length(MAX_STRATUM_LINE_BYTES),
    );

    let mut state = SessionState::<SystemClock>::new(
        SystemClock,
        &server_config,
        &port_config,
        random_session_id_hex(),
    );
    // Assign a pool-wide collision-free extranonce1 from the shared
    // allocator, decoupled from the (still-random) session id — the
    // session id keeps its old identity role for the UI / DB / device
    // notifications; only the coinbase extranonce becomes unique-by-
    // construction. The guard releases the prefix when this task ends
    // (every exit path: EOF, cancel, IO error, disconnect). If the
    // partition is ever exhausted `prefix()` is None and we keep the
    // session-id-derived extranonce1, i.e. the pre-unification behaviour.
    let extranonce_guard = extranonce.allocate();
    match extranonce_guard.prefix() {
        Some(prefix) => state.extranonce1 = prefix,
        None => warn!(
            session_id = %state.session_id_hex,
            "sv1: extranonce1 partition exhausted; falling back to the \
             session-id-derived (non-unique) prefix for this connection"
        ),
    }
    let mut current_template = initial_template;
    // `alt_streams` holds one receiver+snapshot per fixed-reservation stream;
    // at `mining.authorize` the connection `remove`s the entry for its resolved
    // mode (if any) and swaps `template_rx`/`current_template` onto it.

    let mut vardiff_tick = tokio::time::interval(std::time::Duration::from_millis(
        server_config.difficulty_check_interval_ms,
    ));
    vardiff_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the first immediate tick — wait a full interval before the
    // first vardiff check.
    vardiff_tick.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            frame = lines.next() => {
                // Map the codec item back to the `io::Result<Option<String>>`
                // shape the rest of the loop expects. An over-length line is
                // not an IO error — it's a misbehaving/garbage peer, so drop
                // just this connection rather than propagating.
                let line: std::io::Result<Option<String>> = match frame {
                    Some(Ok(l)) => Ok(Some(l)),
                    Some(Err(LinesCodecError::MaxLineLengthExceeded)) => {
                        warn!(
                            session_id = %state.session_id_hex,
                            max = MAX_STRATUM_LINE_BYTES,
                            "sv1: line exceeded max length; disconnecting"
                        );
                        break;
                    }
                    Some(Err(LinesCodecError::Io(e))) => Err(e),
                    None => Ok(None),
                };
                match line? {
                    None => break,                       // EOF
                    Some(line) => {
                        // Mark when the inbound line became available — used to
                        // measure pool-internal submit→ack latency (gated by
                        // `log_submit_latency`, emitted after the response write).
                        let recv_at = std::time::Instant::now();
                        if server_config.protocol_debug {
                            // Received JSON-RPC line dump, at DEBUG (not
                            // INFO) under the protocol_debug gate.
                            debug!(
                                session_id = %state.session_id_hex,
                                "📨 RX: {line}"
                            );
                        }
                        let now = now_ms();
                        let outcome = dispatch(
                            &mut state,
                            &server_config,
                            &port_config,
                            &registry,
                            current_template.as_deref(),
                            &line,
                            now,
                        );
                        // One-time stream routing at `mining.authorize`: resolve
                        // the address's payout mode → template stream. A non-PPLNS
                        // connection swaps onto its fixed-reservation stream BEFORE
                        // the first `mining.notify` is built in apply_outcome below,
                        // so its very first job already rides the right template.
                        // `state.stream` is set ONLY when the swap succeeds, so the
                        // block-submit handle (driven by `state.stream`) can never
                        // route to a stream whose template_id the job doesn't carry.
                        if outcome
                            .events
                            .iter()
                            .any(|e| matches!(e, SessionEvent::Authorized { .. }))
                        {
                            // Publish the address's mode into the mode-gate
                            // BEFORE the one-time stream routing below.
                            // `resolve_stream` reads the gate, so the publish
                            // must precede it — otherwise the lookup misses and
                            // the connection defaults to the Solo stream
                            // regardless of port / group membership. (The
                            // matching `register_session` in `apply_outcome`'s
                            // Authorized arm was removed to avoid a double
                            // refcount; device-status still fires there.)
                            let authd = state.authorization.as_ref().map(|auth| {
                                (
                                    auth.address.clone(),
                                    auth.worker.clone(),
                                    state.subscription.as_ref().map(|s| s.user_agent.clone()),
                                )
                            });
                            if let Some((address, worker, user_agent)) = authd {
                                hooks
                                    .session_persistence
                                    .register_session(
                                        &state.session_id_hex,
                                        &address,
                                        &worker,
                                        user_agent.as_deref(),
                                    )
                                    .await;
                                if state.stream.is_pplns() {
                                    let resolved =
                                        hooks.payout_resolver.resolve_stream(&address);
                                    if !resolved.is_pplns() {
                                        if let Some(alt) = alt_streams.remove(&resolved) {
                                            template_rx = alt.rx;
                                            current_template = alt.initial;
                                            state.stream = resolved;
                                            debug!(
                                                session_id = %state.session_id_hex,
                                                stream = resolved.as_label(),
                                                "sv1: connection routed to alt template stream"
                                            );
                                        } else {
                                            warn!(
                                                session_id = %state.session_id_hex,
                                                stream = resolved.as_label(),
                                                "sv1: address resolved to an alt stream that isn't \
                                                 wired; staying on the PPLNS stream"
                                            );
                                        }
                                    } else {
                                        // PPLNS resolves to the boot stream → no
                                        // swap. Logged for symmetry so PPLNS
                                        // routing is visible too.
                                        debug!(
                                            session_id = %state.session_id_hex,
                                            stream = resolved.as_label(),
                                            "sv1: connection routed to pplns template stream"
                                        );
                                    }
                                }
                            }
                        }
                        // Fire apply_vardiff_check immediately when an accepted
                        // share is at the current session difficulty and the
                        // cooldown has elapsed — not just on the 60s timer tick.
                        let run_inline_vardiff = outcome.events.iter().any(|e| {
                            matches!(e, SessionEvent::ShareAccepted(a)
                                if a.effective_difficulty == state.session_difficulty)
                        }) && now.saturating_sub(state.last_difficulty_check_ms)
                            >= server_config.difficulty_check_interval_ms;
                        // Did this line carry a share submit? (Yields an
                        // accept/reject event.) Decides whether to log latency.
                        let was_submit = outcome.events.iter().any(|e| {
                            matches!(
                                e,
                                SessionEvent::ShareAccepted(_) | SessionEvent::ShareRejected { .. }
                            )
                        });
                        if !apply_outcome(
                            outcome,
                            &mut state,
                            &server_config,
                            &port_config,
                            &registry,
                            current_template.as_ref(),
                            &hooks,
                            &mut write_half,
                        )
                        .await?
                        {
                            break;
                        }
                        // Pool-internal submit→ack latency: from the inbound
                        // mining.submit line being read to its response being
                        // written (incl. validate). Isolates pool processing
                        // from network / miner / measurement.
                        if server_config.log_submit_latency && was_submit {
                            info!(
                                session_id = %state.session_id_hex,
                                latency_us = recv_at.elapsed().as_micros(),
                                "sv1 submit→ack pool-internal latency"
                            );
                        }
                        if run_inline_vardiff {
                            let payouts = match current_template.as_deref() {
                                Some(t) => resolve_payouts_for_state(&state, &hooks, t).await,
                                None => vec![],
                            };
                            let outcome = apply_vardiff_check(
                                &mut state,
                                &server_config,
                                &port_config,
                                &registry,
                                current_template.as_ref(),
                                &payouts,
                                now,
                            );
                            if !apply_outcome(
                                outcome,
                                &mut state,
                                &server_config,
                                &port_config,
                                &registry,
                                current_template.as_ref(),
                                &hooks,
                                &mut write_half,
                            )
                            .await?
                            {
                                break;
                            }
                        }
                        // diag: full processing time of handling this line.
                        // `latency_us` above already covers recv→ack incl.
                        // the share fan-out; this also catches the inline
                        // vardiff retarget block. A large value blocked the
                        // loop and delays the next line's read — the
                        // send→ack spike the recv→ack window can't see.
                        if server_config.log_submit_latency && was_submit {
                            let iter_us = recv_at.elapsed().as_micros();
                            if iter_us >= 50_000 {
                                warn!(
                                    session_id = %state.session_id_hex,
                                    iter_us,
                                    "sv1 slow loop iteration — processing blocked the connection"
                                );
                            }
                        }
                    }
                }
            }
            broadcast = template_rx.recv() => {
                let payload = match broadcast {
                    Ok(p) => p,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Drained at next iteration via the snapshot
                        // (current_template is updated continuously by
                        // the translator).
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                current_template = Some(payload.template.clone());
                let clean_jobs = matches!(payload.change, TemplateChange::NewBlock);
                // Async-resolve payouts BEFORE calling apply_new_template
                // so the per-template MiningJob carries the correct
                // mode-aware coinbase distribution.
                let payouts = resolve_payouts_for_state(&state, &hooks, &payload.template).await;
                let outcome = apply_new_template(
                    &mut state,
                    &server_config,
                    &port_config,
                    &registry,
                    &payload.template,
                    &payouts,
                    clean_jobs,
                    now_ms(),
                );
                if !apply_outcome(
                    outcome,
                    &mut state,
                    &server_config,
                    &port_config,
                    &registry,
                    current_template.as_ref(),
                    &hooks,
                    &mut write_half,
                )
                .await?
                {
                    break;
                }
            }
            _ = vardiff_tick.tick() => {
                // Resolve payouts once for the tick — the handler only
                // builds a notify when the diff actually ratchets, but
                // the resolver is cheap and the alternative (resolving
                // inside the handler) requires async-handler refactor
                // we deliberately avoid (async-handler refactor would be needed).
                let payouts = match current_template.as_deref() {
                    Some(t) => resolve_payouts_for_state(&state, &hooks, t).await,
                    None => vec![],
                };
                let outcome = apply_vardiff_check(
                    &mut state,
                    &server_config,
                    &port_config,
                    &registry,
                    current_template.as_ref(),
                    &payouts,
                    now_ms(),
                );
                if !apply_outcome(
                    outcome,
                    &mut state,
                    &server_config,
                    &port_config,
                    &registry,
                    current_template.as_ref(),
                    &hooks,
                    &mut write_half,
                )
                .await?
                {
                    break;
                }
            }
        }
    }

    // Best-effort cleanup. `deregister_session` covers the device-offline
    // notification + the `client` row delete on teardown.
    hooks
        .session_persistence
        .deregister_session(&state.session_id_hex)
        .await;
    // Half-close the socket so the miner sees a FIN.
    let _ = write_half.shutdown().await;
    Ok(())
}

/// Flush outbound frames + process events. Returns `false` when the
/// session has signaled disconnect (caller breaks the loop).
///
/// On `SessionEvent::Authorized` this also async-resolves payouts
/// for the freshly-authorized address against the current template
/// and re-fires [`apply_new_template`] so the miner immediately
/// receives a `mining.notify` with the correct per-mode coinbase
/// distribution. Pre-Phase-7.4d this was a synchronous solo-only
/// fallback inside the handler; the new shape moves the async hook
/// call out of the pure-sync handler layer.
#[allow(clippy::too_many_arguments)]
async fn apply_outcome(
    outcome: HandlerOutcome,
    state: &mut SessionState<SystemClock>,
    server_config: &Arc<ServerConfig>,
    port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    current_template: Option<&Arc<ActiveSV1Template>>,
    hooks: &ServerHooks,
    write_half: &mut tokio::net::tcp::OwnedWriteHalf,
) -> std::io::Result<bool> {
    for frame in &outcome.outbound_frames {
        if server_config.protocol_debug {
            // Outbound JSON-RPC line dump (mining.notify,
            // mining.set_difficulty, share-accept/reject responses,
            // vardiff ratchet, etc.). The trailing `\n` is part of
            // the wire frame; trim it for a tidy log line.
            let pretty = trim_trailing_newline(frame);
            debug!(
                session_id = %state.session_id_hex,
                "📤 TX: {pretty}"
            );
        }
        write_half.write_all(frame).await?;
    }
    let mut keep_alive = true;
    for event in outcome.events {
        let is_authorized = matches!(&event, SessionEvent::Authorized { .. });
        if !process_event(event, state, hooks).await {
            keep_alive = false;
        }
        if is_authorized {
            // Post-authorize: deliver the first mining.notify with
            // the resolved payouts. The handler emits the Authorized
            // event but no longer builds notify inline (that is now
            // async-resolved in the main loop). When pre-template
            // (no `current_template` yet) the next template-broadcast
            // arm will fire the same path naturally.
            if let Some(template) = current_template {
                let payouts = resolve_payouts_for_state(state, hooks, template).await;
                let post = apply_new_template(
                    state,
                    server_config,
                    port_config,
                    registry,
                    template,
                    &payouts,
                    true,
                    now_ms(),
                );
                for frame in &post.outbound_frames {
                    if server_config.protocol_debug {
                        let pretty = trim_trailing_newline(frame);
                        debug!(
                            session_id = %state.session_id_hex,
                            "📤 TX: {pretty}"
                        );
                    }
                    write_half.write_all(frame).await?;
                }
                // `apply_new_template` doesn't currently emit session
                // events; if that changes, propagate them here.
                debug_assert!(post.events.is_empty());
            }
        }
    }
    Ok(keep_alive)
}

/// Async-resolve the coinbase payout list for the session's
/// authorized address. Returns an empty vec when the session is not
/// yet authorized; callers MUST treat empty as "no notify".
async fn resolve_payouts_for_state<C: bp_vardiff::Clock>(
    state: &SessionState<C>,
    hooks: &ServerHooks,
    template: &ActiveSV1Template,
) -> Vec<PayoutEntry> {
    let Some(auth) = state.authorization.as_ref() else {
        return vec![];
    };
    hooks
        .payout_resolver
        .resolve_payouts(&auth.address, template.coinbase_tx_value_remaining)
        .await
}

/// Translate a [`SessionEvent`] into the relevant hook calls. Returns
/// `false` on `Disconnect`.
///
/// Pulled out as a pub(crate) free function so unit tests can drive it
/// against a fake `SessionState` + recording hooks without ever
/// touching a `TcpStream`.
pub(crate) async fn process_event(
    event: SessionEvent,
    state: &SessionState<SystemClock>,
    hooks: &ServerHooks,
) -> bool {
    process_event_generic(event, state, hooks).await
}

/// Generic variant — exposed only to the test module so the recording
/// hooks can drive it with a `SessionState<Arc<TestClock>>`.
pub(crate) async fn process_event_generic<C: bp_vardiff::Clock>(
    event: SessionEvent,
    state: &SessionState<C>,
    hooks: &ServerHooks,
) -> bool {
    match event {
        SessionEvent::Subscribed => true,
        SessionEvent::DifficultyChanged { .. } => true,
        SessionEvent::Authorized { address, worker } => {
            // `register_session` (mode-gate publish + client_entity write)
            // already ran in the connection loop's authorize block, BEFORE
            // stream routing — moving it here would re-resolve the stream
            // too late and double the gate refcount. We only emit the
            // device-online event here. Subscribe carries the
            // firmware/vendor string in its user-agent field
            // (`cgminer/4.11.1` → `cgminer`); the register call lifted it
            // into client_entity.userAgent for the /api/info histogram.
            let user_agent = state.subscription.as_ref().map(|s| s.user_agent.as_str());
            hooks
                .device_status_sink
                .on_device_event(&address, &worker, &state.session_id_hex, user_agent, true)
                .await;
            true
        }
        SessionEvent::ShareAccepted(accept) => {
            let (address, worker) = state
                .authorization
                .as_ref()
                .map(|a| (a.address.as_str(), a.worker.as_str()))
                .unwrap_or(("", ""));
            hooks
                .accepted_sink
                .record_accepted(
                    address,
                    worker,
                    &state.session_id_hex,
                    state.subscription.as_ref().map(|s| s.user_agent.as_str()),
                    &accept,
                    state.hash_rate,
                )
                .await;
            if accept.is_block_candidate {
                hooks
                    .block_sink
                    .submit_block(
                        &accept,
                        address,
                        worker,
                        &state.session_id_hex,
                        state.stream,
                    )
                    .await;
            }
            true
        }
        SessionEvent::ShareRejected { reason, difficulty } => {
            let address = state.authorization.as_ref().map(|a| a.address.as_str());
            let worker = state.authorization.as_ref().map(|a| a.worker.as_str());
            hooks
                .rejected_sink
                .record_rejected(address, worker, &state.session_id_hex, reason, difficulty)
                .await;
            true
        }
        SessionEvent::Disconnect => {
            if let Some(auth) = state.authorization.as_ref() {
                hooks
                    .device_status_sink
                    .on_device_event(
                        auth.address.as_str(),
                        auth.worker.as_str(),
                        &state.session_id_hex,
                        state.subscription.as_ref().map(|s| s.user_agent.as_str()),
                        false,
                    )
                    .await;
            }
            false
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Strip the trailing `\n` (and stray `\r`) from a JSON-RPC wire
/// frame for log formatting. Falls back to lossy UTF-8 if the line
/// isn't valid UTF-8 (handlers always emit UTF-8, but defensive).
fn trim_trailing_newline(frame: &[u8]) -> std::borrow::Cow<'_, str> {
    let mut end = frame.len();
    while end > 0 && (frame[end - 1] == b'\n' || frame[end - 1] == b'\r') {
        end -= 1;
    }
    String::from_utf8_lossy(&frame[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line-length cap drops only the offending peer: a legitimate
    /// request decodes fine, while a peer that streams bytes without a
    /// newline past the cap yields `MaxLineLengthExceeded` (mapped to a
    /// disconnect in the connection loop) instead of growing the buffer
    /// without bound.
    #[tokio::test]
    async fn line_codec_caps_oversized_lines_but_passes_normal_ones() {
        // A normal subscribe line (well under the cap), then an over-length
        // line: MAX_STRATUM_LINE_BYTES+1 non-newline bytes.
        let normal = br#"{"id":1,"method":"mining.subscribe","params":[]}"#;
        let mut input = Vec::new();
        input.extend_from_slice(normal);
        input.push(b'\n');
        input.resize(input.len() + MAX_STRATUM_LINE_BYTES + 1, b'a');
        input.push(b'\n');

        let mut framed = FramedRead::new(
            &input[..],
            LinesCodec::new_with_max_length(MAX_STRATUM_LINE_BYTES),
        );

        // First line: the legitimate request, decoded verbatim (no newline).
        let first = framed.next().await.expect("an item").expect("ok line");
        assert_eq!(first.as_bytes(), normal);

        // Second line: over the cap → MaxLineLengthExceeded, not an OOM.
        match framed.next().await {
            Some(Err(LinesCodecError::MaxLineLengthExceeded)) => {}
            other => panic!("expected MaxLineLengthExceeded, got {other:?}"),
        }
    }

    use crate::client::SessionState;
    use crate::frame::{AuthorizeRequest, RpcId};
    use crate::hooks::test_support::RecordingHooks;
    use crate::notify::ActiveSV1Template;
    use bitcoin::Network;
    use bp_common::MiningMode;
    use bp_template_distribution::{NewTemplate, SetNewPrevHash};
    use bp_vardiff::TestClock;

    fn server_cfg() -> ServerConfig {
        ServerConfig::defaults_for(Network::Regtest)
    }

    fn port_cfg() -> PortConfig {
        PortConfig {
            payout_mode: MiningMode::Solo,
            ..PortConfig::new(3333, 16384.0)
        }
    }

    fn dummy_new_template(id: u64, future: bool) -> TemplateUpdate {
        TemplateUpdate::NewTemplate(NewTemplate {
            template_id: id,
            future_template: future,
            version: 0x2000_0000,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![0x03, 0x40, 0x0d, 0x03],
            coinbase_tx_input_sequence: 0xffff_ffff,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: {
                let mut v = vec![0u8; 8];
                v.push(0x26);
                v.extend_from_slice(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
                v.extend(std::iter::repeat_n(0xCC, 32));
                v
            },
            coinbase_tx_locktime: 0,
            merkle_path: vec![[0x11; 32]],
        })
    }

    fn dummy_prev_hash(template_id: u64) -> TemplateUpdate {
        TemplateUpdate::SetNewPrevHash(SetNewPrevHash {
            template_id,
            prev_hash: [0xAB; 32],
            header_timestamp: 0x65a1_b2c3,
            n_bits: 0x207f_ffff,
            target: [0xff; 32],
        })
    }

    fn fresh_state(port: &PortConfig) -> SessionState<Arc<TestClock>> {
        let clock = Arc::new(TestClock::new(1_000));
        SessionState::new(clock, &server_cfg(), port, "abcd1234".into())
    }

    // ── Translator task ───────────────────────────────────────────────

    #[tokio::test]
    async fn translator_paires_new_template_and_set_new_prev_hash() {
        let (updates_tx, updates_rx) = broadcast::channel(8);
        let (template_tx, mut template_rx) = broadcast::channel(8);
        let current = Arc::new(Mutex::new(None));
        let cancel = CancellationToken::new();
        let join = tokio::spawn(run_translator(
            updates_rx,
            bp_template_distribution::TemplateSnapshot::default(),
            template_tx,
            current.clone(),
            cancel.clone(),
        ));

        // NewTemplate(future) alone → no broadcast (cached).
        updates_tx.send(dummy_new_template(1, true)).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(template_rx.try_recv().is_err());

        // SetNewPrevHash → pair, broadcast NewBlock.
        updates_tx.send(dummy_prev_hash(1)).unwrap();
        let payload =
            tokio::time::timeout(std::time::Duration::from_millis(100), template_rx.recv())
                .await
                .expect("must broadcast")
                .expect("must succeed");
        assert_eq!(payload.change, TemplateChange::NewBlock);
        assert_eq!(payload.template.template_id, 1);
        // Snapshot updated.
        assert!(current.lock().unwrap().is_some());

        cancel.cancel();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn translator_emits_refresh_on_non_future_template() {
        let (updates_tx, updates_rx) = broadcast::channel(8);
        let (template_tx, mut template_rx) = broadcast::channel(8);
        let current = Arc::new(Mutex::new(None));
        let cancel = CancellationToken::new();
        let join = tokio::spawn(run_translator(
            updates_rx,
            bp_template_distribution::TemplateSnapshot::default(),
            template_tx,
            current.clone(),
            cancel.clone(),
        ));

        // Pair to activate.
        updates_tx.send(dummy_new_template(1, true)).unwrap();
        updates_tx.send(dummy_prev_hash(1)).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), template_rx.recv())
            .await
            .unwrap();

        // Now a non-future template → Refresh.
        updates_tx.send(dummy_new_template(2, false)).unwrap();
        let payload =
            tokio::time::timeout(std::time::Duration::from_millis(100), template_rx.recv())
                .await
                .expect("refresh must broadcast")
                .unwrap();
        assert_eq!(payload.change, TemplateChange::Refresh);
        assert_eq!(payload.template.template_id, 2);

        cancel.cancel();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn translator_exits_on_cancel() {
        let (_updates_tx, updates_rx) = broadcast::channel(8);
        let (template_tx, _template_rx) = broadcast::channel(8);
        let current = Arc::new(Mutex::new(None));
        let cancel = CancellationToken::new();
        let join = tokio::spawn(run_translator(
            updates_rx,
            bp_template_distribution::TemplateSnapshot::default(),
            template_tx,
            current,
            cancel.clone(),
        ));
        cancel.cancel();
        // Must exit promptly.
        tokio::time::timeout(std::time::Duration::from_millis(200), join)
            .await
            .expect("translator must exit on cancel")
            .unwrap();
    }

    // ── process_event hook fan-out ────────────────────────────────────

    fn dummy_share_accept(is_block_candidate: bool) -> Box<ShareAccept> {
        use crate::jobs::JobClassification;
        use bp_mining_job::{
            build_mining_job_from_tdp, PayoutEntry, TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
        };
        let active = ActiveSV1Template {
            template_id: 42,
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            n_bits: 0x1d00_ffff,
            header_timestamp: 0x65a1_b2c3,
            network_target: [0xff; 32],
            network_difficulty: 1.0,
            coinbase_prefix: vec![0x03, 0x40, 0x0d, 0x03],
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xffff_ffff,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: {
                let mut v = vec![0u8; 8];
                v.push(0x26);
                v.extend_from_slice(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
                v.extend(std::iter::repeat_n(0xCC, 32));
                v
            },
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
            merkle_path: vec![[0x11; 32]],
            merkle_branch_hex: vec![],
        };
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &active.coinbase_prefix,
            coinbase_tx_version: active.coinbase_tx_version,
            coinbase_tx_input_sequence: active.coinbase_tx_input_sequence,
            coinbase_tx_value_remaining: active.coinbase_tx_value_remaining,
            coinbase_tx_outputs: &active.coinbase_tx_outputs,
            coinbase_tx_outputs_count: active.coinbase_tx_outputs_count,
            coinbase_tx_locktime: active.coinbase_tx_locktime,
        };
        let payouts = vec![PayoutEntry {
            address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string(),
            sats: 5_000_000_000,
        }];
        let mining_job = build_mining_job_from_tdp(
            Network::Regtest,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();
        Box::new(ShareAccept {
            classification: JobClassification::Active,
            effective_difficulty: 1024.0,
            submission_difficulty: 2048.0,
            header: [0u8; 80],
            hash: [0u8; 32],
            is_block_candidate,
            mining_job: Arc::new(mining_job),
            template: Arc::new(active),
            enonce1: [0u8; 4],
            extranonce2: [0u8; 8],
        })
    }

    use crate::submit::ShareAccept;

    #[tokio::test]
    async fn authorize_event_fans_out_to_device_status() {
        // `register_session` (mode-gate publish) moved to the connection
        // loop's authorize block — it must run BEFORE stream routing, so
        // it is no longer fired from `apply_outcome`. The Authorized arm
        // here now only emits the device-online event; registration is
        // covered end-to-end by the connection-loop / regtest paths.
        let port = port_cfg();
        let state = fresh_state(&port);
        let rec = RecordingHooks::new();
        let hooks = rec.as_server_hooks();
        let keep = process_event_generic(
            SessionEvent::Authorized {
                address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".into(),
                worker: "w".into(),
            },
            &state,
            &hooks,
        )
        .await;
        assert!(keep);
        // No register from this layer anymore.
        assert!(rec.registered.lock().unwrap().is_empty());
        // Device-online event fired with the authorized address/worker.
        let devices = rec.device_events.lock().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(
            devices[0],
            (
                "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string(),
                "w".to_string(),
                true
            )
        );
    }

    #[tokio::test]
    async fn accepted_share_fans_out_to_accepted_sink_only_when_not_block() {
        let port = port_cfg();
        let mut state = fresh_state(&port);
        state.authorization = Some(AuthorizeRequest {
            id: RpcId::from(2),
            raw_username: "addr.w".into(),
            address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".into(),
            worker: "w".into(),
            password: None,
        });
        let rec = RecordingHooks::new();
        let hooks = rec.as_server_hooks();
        let keep = process_event_generic(
            SessionEvent::ShareAccepted(dummy_share_accept(false)),
            &state,
            &hooks,
        )
        .await;
        assert!(keep);
        let accepted = rec.accepted.lock().unwrap();
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].1, 1024.0); // effective_difficulty
                                           // No block submission for non-candidates.
        assert!(rec.blocks_submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn accepted_block_candidate_also_fires_block_sink() {
        let port = port_cfg();
        let mut state = fresh_state(&port);
        state.authorization = Some(AuthorizeRequest {
            id: RpcId::from(2),
            raw_username: "addr.w".into(),
            address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".into(),
            worker: "w".into(),
            password: None,
        });
        let rec = RecordingHooks::new();
        let hooks = rec.as_server_hooks();
        let _ = process_event_generic(
            SessionEvent::ShareAccepted(dummy_share_accept(true)),
            &state,
            &hooks,
        )
        .await;
        let accepted = rec.accepted.lock().unwrap();
        assert_eq!(accepted.len(), 1);
        let blocks = rec.blocks_submitted.lock().unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].2, 42); // template_id
    }

    #[tokio::test]
    async fn rejected_share_fans_out_to_rejected_sink() {
        let port = port_cfg();
        let mut state = fresh_state(&port);
        state.authorization = Some(AuthorizeRequest {
            id: RpcId::from(2),
            raw_username: "addr.w".into(),
            address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".into(),
            worker: "w".into(),
            password: None,
        });
        let rec = RecordingHooks::new();
        let hooks = rec.as_server_hooks();
        let _ = process_event_generic(
            SessionEvent::ShareRejected {
                reason: crate::submit::RejectReason::LowDifficulty,
                difficulty: 4096.0,
            },
            &state,
            &hooks,
        )
        .await;
        let rejected = rec.rejected.lock().unwrap();
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].3, 4096.0);
    }

    #[tokio::test]
    async fn disconnect_event_signals_caller_to_stop() {
        let port = port_cfg();
        let state = fresh_state(&port);
        let rec = RecordingHooks::new();
        let hooks = rec.as_server_hooks();
        let keep = process_event_generic(SessionEvent::Disconnect, &state, &hooks).await;
        assert!(!keep);
    }

    // ── Smoke test: spawn + shutdown ─────────────────────────────────

    #[tokio::test]
    async fn server_spawn_and_shutdown_is_clean() {
        let (_updates_tx, updates_rx) = broadcast::channel(8);
        // Two alt streams to exercise the multi-translator spawn + shutdown.
        let (_solo_tx, solo_rx) = broadcast::channel(8);
        let (_gs_tx, gs_rx) = broadcast::channel(8);
        let server = StratumV1Server::spawn(
            server_cfg(),
            updates_rx,
            bp_template_distribution::TemplateSnapshot::default(),
            vec![
                (
                    StreamKind::Solo,
                    solo_rx,
                    bp_template_distribution::TemplateSnapshot::default(),
                ),
                (
                    StreamKind::GroupSolo,
                    gs_rx,
                    bp_template_distribution::TemplateSnapshot::default(),
                ),
            ],
            ServerHooks::no_op(),
            SharedExtranonce::new(),
        );
        // Shutdown waits for every translator to exit.
        server.shutdown().await;
        // Second call is idempotent (no panic / hang).
        server.shutdown().await;
    }

    // ── SharedExtranonce ─────────────────────────────────────────────

    #[test]
    fn shared_extranonce_hands_distinct_worker1_prefixes() {
        let ex = SharedExtranonce::new();
        let g1 = ex.allocate();
        let g2 = ex.allocate();
        let p1 = g1.prefix().expect("first prefix allocated");
        let p2 = g2.prefix().expect("second prefix allocated");
        // Both live in SV1's worker-1 partition (top byte 0x01) — never the
        // SV2 worker-0 space — and are never equal to each other.
        assert_eq!(p1[0], 0x01, "SV1 prefix must start 0x01: {p1:?}");
        assert_eq!(p2[0], 0x01, "SV1 prefix must start 0x01: {p2:?}");
        assert_ne!(p1, p2, "two connections must never share extranonce1");
    }

    #[test]
    fn prefix_guard_releases_prefix_on_drop() {
        let ex = SharedExtranonce::new();
        assert_eq!(ex.allocated_count(), 0);
        let guard = ex.allocate();
        assert!(guard.prefix().is_some());
        assert_eq!(ex.allocated_count(), 1, "prefix is checked out while held");
        drop(guard);
        assert_eq!(
            ex.allocated_count(),
            0,
            "dropping the guard must return the prefix to the pool"
        );
    }

    /// Two SV1 connections on the same server (one shared allocator) must
    /// receive distinct extranonce1 values in their subscribe responses —
    /// the whole point of the unification. No bitcoin-core needed: the
    /// subscribe response is emitted immediately after the handshake.
    #[tokio::test]
    async fn two_connections_get_distinct_worker1_extranonce1() {
        use tokio::net::TcpListener;

        let (_updates_tx, updates_rx) = broadcast::channel(8);
        let server = StratumV1Server::spawn(
            server_cfg(),
            updates_rx,
            bp_template_distribution::TemplateSnapshot::default(),
            Vec::new(),
            ServerHooks::no_op(),
            SharedExtranonce::new(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept two connections, each served by the same server + allocator.
        let s1 = server.clone();
        let s2 = server.clone();
        let pc1 = port_cfg();
        let pc2 = port_cfg();
        let accept = tokio::spawn(async move {
            let (a, _) = listener.accept().await.unwrap();
            a.set_nodelay(true).ok();
            s1.accept_connection(a, pc1);
            let (b, _) = listener.accept().await.unwrap();
            b.set_nodelay(true).ok();
            s2.accept_connection(b, pc2);
        });

        let en1_a = subscribe_and_read_extranonce1(addr).await;
        let en1_b = subscribe_and_read_extranonce1(addr).await;
        accept.await.unwrap();

        assert_eq!(en1_a.len(), 8, "extranonce1 is 8 hex chars: {en1_a}");
        assert!(
            en1_a.starts_with("01") && en1_b.starts_with("01"),
            "both extranonce1 must be from worker 1: {en1_a} / {en1_b}"
        );
        assert_ne!(
            en1_a, en1_b,
            "two connections must never share extranonce1"
        );

        server.shutdown().await;
    }

    async fn subscribe_and_read_extranonce1(addr: std::net::SocketAddr) -> String {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpStream;

        let sock = TcpStream::connect(addr).await.unwrap();
        sock.set_nodelay(true).ok();
        let (read, mut write) = sock.into_split();
        let mut reader = BufReader::new(read);
        write
            .write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"t/1.0\"]}\n")
            .await
            .unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        v["result"][1]
            .as_str()
            .expect("extranonce1 in subscribe response")
            .to_string()
    }
}
