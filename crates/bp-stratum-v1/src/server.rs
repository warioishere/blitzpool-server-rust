// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV1 server: a translator task per template stream turns TDP updates into
//! [`ActiveSV1Template`] broadcasts plus a snapshot for new connections, and one
//! task per connection drives its [`SessionState`]. One [`CancellationToken`]
//! stops them all.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bp_common::SharedExtranonceAllocator;
use bp_common::StreamKind;
use bp_template_distribution::TemplateUpdate;
use futures::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, LinesCodec, LinesCodecError};

/// Bounds the per-connection read buffer; real requests stay well under 1 KiB.
/// On overflow only that connection is dropped.
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
use crate::notify::ActiveSV1Template;
use bp_mining_job::{MiningJobCache, ResolvedPayouts};
use bp_template_distribution::{TemplateAssembler, TemplateChange};
use bp_vardiff::{Clock, SystemClock};

/// Extranonce1 allocator shared by every SV1 port, so two miners, even on
/// different ports, never get the same extranonce1.
#[derive(Clone)]
pub struct SharedExtranonce {
    shared: SharedExtranonceAllocator,
}

impl SharedExtranonce {
    /// On [`bp_common::extranonce::SV1_WORKER_ID`], disjoint from SV2's partition.
    /// Build once and clone into every port.
    pub fn new() -> Self {
        Self {
            shared: SharedExtranonceAllocator::new_default_on_worker(
                bp_common::extranonce::SV1_WORKER_ID,
            ),
        }
    }

    /// The guard releases the prefix on drop, covering every connection-exit path.
    pub fn allocate(&self) -> PrefixGuard {
        let key = self.shared.next_key();
        let prefix = self.shared.allocate(key).ok();
        PrefixGuard {
            key,
            prefix,
            shared: self.shared.clone(),
        }
    }

    pub fn allocated_count(&self) -> usize {
        self.shared.allocated_count()
    }
}

impl Default for SharedExtranonce {
    fn default() -> Self {
        Self::new()
    }
}

/// Claim on one extranonce1 prefix, returned to the allocator on drop.
pub struct PrefixGuard {
    key: u64,
    prefix: Option<[u8; 4]>,
    shared: SharedExtranonceAllocator,
}

impl PrefixGuard {
    /// `None` when the partition is exhausted; the caller then keeps the
    /// session-id-derived extranonce1.
    pub fn prefix(&self) -> Option<[u8; 4]> {
        self.prefix
    }
}

impl Drop for PrefixGuard {
    fn drop(&mut self) {
        self.shared.release(self.key);
    }
}

/// Broadcast payload from translator → per-connection tasks.
#[derive(Clone, Debug)]
pub(crate) struct TemplateBroadcast {
    /// `Arc` so each connected session gets a refcount bump, not a deep copy.
    pub template: Arc<ActiveSV1Template>,
    pub change: TemplateChange,
}

/// A lagged connection skips the missed broadcasts and continues with the next one.
const TEMPLATE_BROADCAST_CAPACITY: usize = 32;

/// Cheap to clone. [`Self::shutdown`] is the only clean way to stop the translators.
#[derive(Clone)]
pub struct StratumV1Server {
    inner: Arc<Inner>,
}

struct Inner {
    server_config: Arc<ServerConfig>,
    registry: Arc<JobRegistry>,
    hooks: ServerHooks,
    // PPLNS stream: every connection boots here before its payout mode resolves.
    template_tx: broadcast::Sender<TemplateBroadcast>,
    current_template: Arc<Mutex<Option<Arc<ActiveSV1Template>>>>,
    // Fixed-reservation streams; a connection switches onto one at
    // `mining.authorize` when its address resolves to that mode.
    alt_streams: HashMap<StreamKind, AltStream>,
    extranonce: SharedExtranonce,
    /// Shared across ports: they ride the same TDP streams, so cache keys match
    /// and a coinbase is built once per template, not once per connection.
    job_cache: Arc<MiningJobCache>,
    cancel: CancellationToken,
    translator_join: Mutex<Option<JoinHandle<()>>>,
    alt_translator_joins: Mutex<Vec<JoinHandle<()>>>,
}

struct AltStream {
    template_tx: broadcast::Sender<TemplateBroadcast>,
    current_template: Arc<Mutex<Option<Arc<ActiveSV1Template>>>>,
}

/// One connection's receiver plus boot snapshot for an alt stream.
struct AltStreamHandle {
    rx: broadcast::Receiver<TemplateBroadcast>,
    initial: Option<Arc<ActiveSV1Template>>,
}

impl StratumV1Server {
    /// `initial_snapshot` is taken alongside `subscribe()` and seeds the assembler,
    /// because bitcoin-core's bootstrap pair may have gone out before the
    /// subscription existed.
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
        job_cache: Arc<MiningJobCache>,
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
            registry.clone(),
            job_cache.clone(),
            cancel.clone(),
        ));
        // All translators drive the same registry; safe because `cleanup_for_tip`
        // is keyed on prev-hash and thus order-independent across streams.
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
                registry.clone(),
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
                registry,
                hooks,
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

    pub fn job_registry(&self) -> &Arc<JobRegistry> {
        &self.inner.registry
    }

    /// Lets a caller gate accepting connections on a template being ready, so
    /// every new miner gets a `mining.notify` right after the handshake.
    pub fn current_template(&self) -> Option<Arc<ActiveSV1Template>> {
        self.inner
            .current_template
            .lock()
            .expect("current_template mutex poisoned")
            .clone()
    }

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
        let job_cache = self.inner.job_cache.clone();

        tokio::spawn(run_connection(
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
            job_cache,
        ))
    }

    /// Cancels translators and connections; idempotent.
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

async fn run_translator(
    mut updates_rx: broadcast::Receiver<TemplateUpdate>,
    initial_snapshot: bp_template_distribution::TemplateSnapshot,
    template_tx: broadcast::Sender<TemplateBroadcast>,
    current_template: Arc<Mutex<Option<Arc<ActiveSV1Template>>>>,
    registry: Arc<JobRegistry>,
    job_cache: Arc<MiningJobCache>,
    cancel: CancellationToken,
) {
    let mut assembler = TemplateAssembler::<ActiveSV1Template>::new();

    // Without this, current_template stays None until the next block: the
    // startup pair usually goes out before this subscriber exists.
    if let Some((active, change)) = assembler.bootstrap_from_snapshot(initial_snapshot) {
        let active = Arc::new(active);
        {
            let mut guard = current_template
                .lock()
                .expect("current_template mutex poisoned");
            *guard = Some(active.clone());
        }
        registry.cleanup_for_tip(&active.prev_hash, SystemClock.now_ms());
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
                        // Recovers with the next NewTemplate/SetNewPrevHash pair.
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
                        {
                            let mut guard = current_template
                                .lock()
                                .expect("current_template mutex poisoned");
                            *guard = Some(active.clone());
                        }
                        // Before the send, so a fast subscriber's new job is
                        // never raced by a trailing pass. This keeps the registry bounded.
                        registry.cleanup_for_tip(&active.prev_hash, SystemClock.now_ms());
                        // Runs even with no miner connected, so stale entries
                        // do not wait for the next lookup.
                        job_cache.prune_expired();
                        // Errors only without subscribers; new connections use the snapshot.
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

/// Returns nothing on purpose: every exit must reach the teardown, or the session
/// stays in the live-session set and the device is never reported offline. With
/// no error type, a `?` that would skip it does not compile.
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
    job_cache: Arc<MiningJobCache>,
) {
    let (read_half, mut write_half) = socket.into_split();
    // A peer that never sends a newline cannot grow the buffer without bound.
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
    // Extranonce1 is allocated separately from the random session id, which
    // stays the identity for UI, DB and device notifications.
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

    let mut vardiff_tick = tokio::time::interval(std::time::Duration::from_millis(
        server_config.difficulty_check_interval_ms,
    ));
    vardiff_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Wait a full interval before the first vardiff check.
    vardiff_tick.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            frame = lines.next() => {
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
                let line = match line {
                    Ok(line) => line,
                    // A vanished miner resets the connection instead of EOF;
                    // a normal end, which must still reach the teardown.
                    Err(err) => {
                        debug!(
                            session_id = %state.session_id_hex,
                            %err,
                            "sv1: read failed; closing the connection"
                        );
                        break;
                    }
                };
                match line {
                    None => break,                       // EOF
                    Some(line) => {
                        let recv_at = std::time::Instant::now();
                        if server_config.protocol_debug {
                            debug!(
                                session_id = %state.session_id_hex,
                                "📨 RX: {line}"
                            );
                        }
                        let now = SystemClock.now_ms();
                        let outcome = dispatch(
                            &mut state,
                            &server_config,
                            &port_config,
                            &registry,
                            current_template.as_deref(),
                            &line,
                            now,
                        );
                        // Stream routing happens before the first `mining.notify`, so the
                        // first job rides the right template. `state.stream` is set only
                        // on a successful swap, so block submit never targets a stream
                        // whose template_id the job does not carry.
                        if outcome
                            .events
                            .iter()
                            .any(|e| matches!(e, SessionEvent::Authorized { .. }))
                        {
                            // Register before routing: `resolve_stream` reads the
                            // mode-gate this publishes, and would otherwise default to
                            // Solo. `apply_outcome` must not register again (double
                            // gate refcount).
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
                                        debug!(
                                            session_id = %state.session_id_hex,
                                            stream = resolved.as_label(),
                                            "sv1: connection routed to pplns template stream"
                                        );
                                    }
                                }
                            }
                        }
                        // Retarget inline once the cooldown has elapsed, not only
                        // on the timer tick.
                        let run_inline_vardiff = outcome.events.iter().any(|e| {
                            matches!(e, SessionEvent::ShareAccepted(a)
                                if a.effective_difficulty == state.session_difficulty)
                        }) && now.saturating_sub(state.last_difficulty_check_ms)
                            >= server_config.difficulty_check_interval_ms;
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
                            &job_cache,
                            current_template.as_ref(),
                            &hooks,
                            &mut write_half,
                        )
                        .await
                        {
                            break;
                        }
                        // From line read to response written: pool processing only.
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
                                None => ResolvedPayouts::unsnapshotted(vec![]),
                            };
                            let outcome = apply_vardiff_check(
                                &mut state,
                                &server_config,
                                &port_config,
                                &registry,
                                &job_cache,
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
                                &job_cache,
                                current_template.as_ref(),
                                &hooks,
                                &mut write_half,
                            )
                            .await
                            {
                                break;
                            }
                        }
                        // Includes the inline retarget; a large value delays the
                        // next line's read.
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
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                current_template = Some(payload.template.clone());
                let clean_jobs = matches!(payload.change, TemplateChange::NewBlock);
                let payouts = resolve_payouts_for_state(&state, &hooks, &payload.template).await;
                let outcome = apply_new_template(
                    &mut state,
                    &server_config,
                    &port_config,
                    &registry,
                    &job_cache,
                    &payload.template,
                    &payouts,
                    clean_jobs,
                    SystemClock.now_ms(),
                );
                if !apply_outcome(
                    outcome,
                    &mut state,
                    &server_config,
                    &port_config,
                    &registry,
                    &job_cache,
                    current_template.as_ref(),
                    &hooks,
                    &mut write_half,
                )
                .await
                {
                    break;
                }
            }
            _ = vardiff_tick.tick() => {
                // Resolved even if no ratchet follows: cheap, and keeps the handler synchronous.
                let payouts = match current_template.as_deref() {
                    Some(t) => resolve_payouts_for_state(&state, &hooks, t).await,
                    None => ResolvedPayouts::unsnapshotted(vec![]),
                };
                let outcome = apply_vardiff_check(
                    &mut state,
                    &server_config,
                    &port_config,
                    &registry,
                    &job_cache,
                    current_template.as_ref(),
                    &payouts,
                    SystemClock.now_ms(),
                );
                if !apply_outcome(
                    outcome,
                    &mut state,
                    &server_config,
                    &port_config,
                    &registry,
                    &job_cache,
                    current_template.as_ref(),
                    &hooks,
                    &mut write_half,
                )
                .await
                {
                    break;
                }
            }
        }
    }

    hooks
        .session_persistence
        .deregister_session(&state.session_id_hex)
        .await;
    let _ = write_half.shutdown().await;
}

/// `false` when the session disconnected or the socket is gone. On `Authorized`
/// it resolves payouts and re-fires [`apply_new_template`] here, keeping the
/// async hook call out of the synchronous handler layer.
#[allow(clippy::too_many_arguments)]
async fn apply_outcome(
    outcome: HandlerOutcome,
    state: &mut SessionState<SystemClock>,
    server_config: &Arc<ServerConfig>,
    port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    job_cache: &Arc<MiningJobCache>,
    current_template: Option<&Arc<ActiveSV1Template>>,
    hooks: &ServerHooks,
    write_half: &mut tokio::net::tcp::OwnedWriteHalf,
) -> bool {
    for frame in &outcome.outbound_frames {
        if server_config.protocol_debug {
            let pretty = trim_trailing_newline(frame);
            debug!(
                session_id = %state.session_id_hex,
                "📤 TX: {pretty}"
            );
        }
        if write_failed(write_half, frame, &state.session_id_hex).await {
            return false;
        }
    }
    let mut keep_alive = true;
    for event in outcome.events {
        let is_authorized = matches!(&event, SessionEvent::Authorized { .. });
        if !process_event(event, state, hooks).await {
            keep_alive = false;
        }
        if is_authorized {
            // Without a template yet, the next broadcast delivers the first notify.
            if let Some(template) = current_template {
                let payouts = resolve_payouts_for_state(state, hooks, template).await;
                let post = apply_new_template(
                    state,
                    server_config,
                    port_config,
                    registry,
                    job_cache,
                    template,
                    &payouts,
                    true,
                    SystemClock.now_ms(),
                );
                for frame in &post.outbound_frames {
                    if server_config.protocol_debug {
                        let pretty = trim_trailing_newline(frame);
                        debug!(
                            session_id = %state.session_id_hex,
                            "📤 TX: {pretty}"
                        );
                    }
                    if write_failed(write_half, frame, &state.session_id_hex).await {
                        return false;
                    }
                }
                // If `apply_new_template` ever emits events, propagate them here.
                debug_assert!(post.events.is_empty());
            }
        }
    }
    keep_alive
}

/// `true` when the socket is gone. Folded into [`apply_outcome`]'s answer, not
/// propagated, so the connection loop still reaches its teardown.
async fn write_failed(
    write_half: &mut tokio::net::tcp::OwnedWriteHalf,
    frame: &[u8],
    session_id: &str,
) -> bool {
    match write_half.write_all(frame).await {
        Ok(()) => false,
        Err(err) => {
            debug!(session_id, %err, "sv1: write failed; closing the connection");
            true
        }
    }
}

/// Empty before authorize; callers MUST treat empty as "no notify".
async fn resolve_payouts_for_state<C: bp_vardiff::Clock>(
    state: &SessionState<C>,
    hooks: &ServerHooks,
    template: &ActiveSV1Template,
) -> ResolvedPayouts {
    let Some(auth) = state.authorization.as_ref() else {
        return ResolvedPayouts::unsnapshotted(vec![]);
    };
    hooks
        .payout_resolver
        .resolve_payouts(&auth.address, template.coinbase_tx_value_remaining)
        .await
}

/// Fans a [`SessionEvent`] out to the hooks; `false` on `Disconnect`.
pub(crate) async fn process_event<C: bp_vardiff::Clock>(
    event: SessionEvent,
    state: &SessionState<C>,
    hooks: &ServerHooks,
) -> bool {
    match event {
        SessionEvent::Subscribed => true,
        SessionEvent::DifficultyChanged => {
            // The only signal on either protocol that a difficulty moved.
            bp_metrics::record_stratum_difficulty_adjustment();
            true
        }
        SessionEvent::Authorized { address, worker } => {
            // `register_session` runs in the connection loop before stream
            // routing; here it would be too late and double the gate refcount.
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
                .record_accepted(crate::shared_adapter::shared_accepted(
                    address,
                    worker,
                    &state.session_id_hex,
                    state.subscription.as_ref().map(|s| s.user_agent.as_str()),
                    &accept,
                    state.hash_rate,
                ))
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
                .record_rejected(crate::shared_adapter::shared_rejected(
                    address,
                    worker,
                    &state.session_id_hex,
                    reason,
                    difficulty,
                ))
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

    /// Pins that an over-cap line errors while a normal one decodes.
    #[tokio::test]
    async fn line_codec_caps_oversized_lines_but_passes_normal_ones() {
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
        dummy_prev_hash_with(template_id, 0xAB)
    }

    fn dummy_prev_hash_with(template_id: u64, prev_byte: u8) -> TemplateUpdate {
        TemplateUpdate::SetNewPrevHash(SetNewPrevHash {
            template_id,
            prev_hash: [prev_byte; 32],
            header_timestamp: 0x65a1_b2c3,
            n_bits: 0x207f_ffff,
            target: [0xff; 32],
        })
    }

    /// Minimal valid MiningJob for registry entries in translator tests.
    fn dummy_mining_job() -> bp_mining_job::MiningJob {
        use bp_mining_job::{
            build_mining_job_from_tdp, PayoutEntry, TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
        };
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &[0x03, 0x40, 0x0d, 0x03],
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xffff_ffff,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &{
                let mut v = vec![0u8; 8];
                v.push(0x26);
                v.extend_from_slice(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
                v.extend(std::iter::repeat_n(0xCC, 32));
                v
            },
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        let payouts = vec![PayoutEntry {
            address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string(),
            sats: 5_000_000_000,
        }];
        build_mining_job_from_tdp(
            Network::Regtest,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .unwrap()
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
            Arc::new(JobRegistry::from_server_config(&server_cfg())),
            Arc::new(MiningJobCache::new()),
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
            Arc::new(JobRegistry::from_server_config(&server_cfg())),
            Arc::new(MiningJobCache::new()),
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
            Arc::new(JobRegistry::from_server_config(&server_cfg())),
            Arc::new(MiningJobCache::new()),
            cancel.clone(),
        ));
        cancel.cancel();
        // Must exit promptly.
        tokio::time::timeout(std::time::Duration::from_millis(200), join)
            .await
            .expect("translator must exit on cancel")
            .unwrap();
    }

    /// Pins that a block change retires old-tip jobs and a later same-tip pass spares new ones.
    #[tokio::test]
    async fn translator_retires_previous_tip_entries_on_new_block() {
        use crate::jobs::JobClassification;

        let (updates_tx, updates_rx) = broadcast::channel(8);
        let (template_tx, mut template_rx) = broadcast::channel(8);
        let current = Arc::new(Mutex::new(None));
        let registry = Arc::new(JobRegistry::from_server_config(&server_cfg()));
        let cancel = CancellationToken::new();
        let join = tokio::spawn(run_translator(
            updates_rx,
            bp_template_distribution::TemplateSnapshot::default(),
            template_tx,
            current,
            registry.clone(),
            Arc::new(MiningJobCache::new()),
            cancel.clone(),
        ));

        // Block 1 (prev 0xAB) → a connection registers a job on it.
        updates_tx.send(dummy_new_template(1, true)).unwrap();
        updates_tx.send(dummy_prev_hash_with(1, 0xAB)).unwrap();
        let payload1 =
            tokio::time::timeout(std::time::Duration::from_millis(200), template_rx.recv())
                .await
                .expect("first pair must broadcast")
                .unwrap();
        let tid1 = registry.add_template_shared(payload1.template.clone(), SystemClock.now_ms());
        let jid1 = registry.add_job(dummy_mining_job(), tid1, SystemClock.now_ms());
        assert_eq!(
            registry
                .classify(&jid1, SystemClock.now_ms())
                .unwrap()
                .classification,
            JobClassification::Active
        );

        // Block 2 (prev 0xCD) → the broadcast implies the retire already
        // ran (cleanup_for_tip fires before the send).
        updates_tx.send(dummy_new_template(2, true)).unwrap();
        updates_tx.send(dummy_prev_hash_with(2, 0xCD)).unwrap();
        let payload2 =
            tokio::time::timeout(std::time::Duration::from_millis(200), template_rx.recv())
                .await
                .expect("second pair must broadcast")
                .unwrap();
        assert_eq!(
            registry
                .classify(&jid1, SystemClock.now_ms())
                .unwrap()
                .classification,
            JobClassification::StaleCreditable,
            "previous-tip job must be retired by the block-change broadcast"
        );

        // A fresh new-tip job survives a later same-tip pass.
        let tid2 = registry.add_template_shared(payload2.template.clone(), SystemClock.now_ms());
        let jid2 = registry.add_job(dummy_mining_job(), tid2, SystemClock.now_ms());
        registry.cleanup_for_tip(&payload2.template.prev_hash, SystemClock.now_ms());
        assert_eq!(
            registry
                .classify(&jid2, SystemClock.now_ms())
                .unwrap()
                .classification,
            JobClassification::Active,
            "a later same-tip pass must not retire fresh new-tip jobs"
        );

        cancel.cancel();
        join.await.unwrap();
    }

    // ── process_event hook fan-out ────────────────────────────────────

    fn dummy_share_accept(is_block_candidate: bool) -> Box<ShareAccept> {
        use crate::jobs::JobClassification;
        use bp_mining_job::{
            build_mining_job_from_tdp, PayoutEntry, TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
        };
        let active = ActiveSV1Template::from_template(bp_template_distribution::ActiveTemplate {
            template_id: 42,
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            n_bits: 0x1d00_ffff,
            header_timestamp: 0x65a1_b2c3,
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
        });
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
            [0u8; 32],
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
        // Registration happens in the connection loop; this arm only emits
        // the device-online event.
        let port = port_cfg();
        let state = fresh_state(&port);
        let rec = RecordingHooks::new();
        let hooks = rec.as_server_hooks();
        let keep = process_event(
            SessionEvent::Authorized {
                address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".into(),
                worker: "w".into(),
            },
            &state,
            &hooks,
        )
        .await;
        assert!(keep);
        // No register from this layer.
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
        let keep = process_event(
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
        let _ = process_event(
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
        let _ = process_event(
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
        let keep = process_event(SessionEvent::Disconnect, &state, &hooks).await;
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
            Arc::new(MiningJobCache::new()),
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
        // Both in SV1's worker-1 partition, never SV2's, and distinct.
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

    /// Pins distinct extranonce1 values in two connections' subscribe responses.
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
            Arc::new(MiningJobCache::new()),
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
        assert_ne!(en1_a, en1_b, "two connections must never share extranonce1");

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
