// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection session state + pure SV1 handler functions.
//!
//! SV1 message handlers split by inbound method. State mutations are
//! confined to the [`SessionState`] struct; outbound frames are returned
//! as `Vec<u8>` so the I/O layer (Task #9 server) can decide how to flush them.
//!
//! Side-effects (DB row insert, address-settings cache update, notification
//! fan-out, PPLNS / group-solo `recordShare`, external-share submission,
//! push notifications) land on the **trait boundaries** in `hooks.rs` (Task #9).
//! This module returns a typed [`SessionEvent`] alongside the wire frame so the
//! server task can drive those hooks without re-deriving the state.
//!
//! Payout-mode dispatch in this module covers the **solo** path
//! (per-miner coinbase with optional dev-fee split). PPLNS and group-solo
//! paths depend on the service-layer adapters and land with the hooks.

use std::sync::Arc;

use bitcoin::Network;
use bp_mining_job::{
    address_to_script, normalize_btc_address, MiningJobCache, PayoutEntry, TdpCoinbaseTemplate,
    EXTRANONCE_SLOT_LEN,
};

use crate::config::{PortConfig, ServerConfig};
use crate::frame::{
    parse_request, write_authorize_response, write_configure_response, write_error,
    write_extranonce_subscribe_response, write_set_difficulty, write_submit_success,
    write_subscribe_response, AuthorizeRequest, ConfigureRequest, FrameParseError, RpcId,
    SV1Request, SubmitRequest, SubscribeRequest, SuggestDifficultyRequest, ERR_OTHER_UNKNOWN,
    ERR_UNAUTHORIZED_WORKER, REJECT_INVALID_ADDR, REJECT_NOT_SUBSCRIBED, REJECT_SUGGEST_DISABLED,
    REJECT_UNAUTHORIZED, VALIDATION_INVALID_AUTHORIZE,
};
use crate::jobs::JobRegistry;
use crate::notify::{build_notify_frame, ActiveSV1Template};
use crate::submit::{
    validate_submit, RejectReason, SessionContext, SessionShareCache, ShareAccept, ShareValidation,
};
use bp_vardiff::{Clock, VarDiffEngine};

// ── SessionState ─────────────────────────────────────────────────────

/// All per-session mutable state. Owned by the server task that drives
/// the connection; passed `&mut` into every handler so the state-machine
/// invariants stay local.
///
/// **No I/O fields** — this struct never owns a socket / channel.
/// Outbound frames produced by handlers are returned as `Vec<u8>` for
/// the caller to flush; inbound bytes are parsed and dispatched
/// upstream.
pub struct SessionState<C: Clock> {
    // Identity
    pub session_id_hex: String,
    pub extranonce1: [u8; 4],
    pub session_start_ms: u64,
    pub network: Network,

    // Handshake messages — populated as they arrive
    pub subscription: Option<SubscribeRequest>,
    pub configuration: Option<ConfigureRequest>,
    pub authorization: Option<AuthorizeRequest>,
    pub suggested_difficulty: Option<SuggestDifficultyRequest>,

    // Stratum lifecycle
    pub stratum_initialized: bool,
    pub used_suggested_difficulty: bool,

    // Difficulty + ckpool race clamp
    pub initial_difficulty: f64,
    pub session_difficulty: f64,
    pub old_session_difficulty: f64,
    pub diff_change_job_id: Option<u64>,
    pub pending_session_difficulty: Option<f64>,

    // VarDiff + dedup
    pub vardiff: VarDiffEngine<C>,
    pub last_difficulty_check_ms: u64,
    pub share_cache: SessionShareCache,
    pub accepted_share_count: u32,

    // Live caches mirrored back from vardiff
    pub hash_rate: f64,

    // Per-job dev-fee bookkeeping.
    pub no_fee: bool,

    /// Set once the client sends `mining.extranonce.subscribe`. Gates whether
    /// the server may push `mining.set_extranonce` to this session — a client
    /// that never opted in must not be sent extranonce updates, or it would
    /// keep mining on its original extranonce-1 and every share would mismatch.
    pub extranonce_subscribed: bool,

    /// Which TDP template stream this connection mines on. Resolved once from
    /// the authorized address (`StreamKind::for_mode`) and then fixed for the
    /// connection's lifetime, so the block-submit handle can never disagree
    /// with the template the job was built on. Defaults to `Default` until
    /// `mining.authorize` resolves it.
    pub stream: bp_common::StreamKind,

    /// Per-share diagnostic logging toggle (server-level
    /// `stratum_share_logs`). Copied from [`ServerConfig`] at
    /// construction; gates the `🎯 Share difficulty` + `✅ Share
    /// accepted` traces in [`validate_submit`].
    pub share_logs: bool,
}

impl<C: Clock> SessionState<C> {
    /// Construct a fresh session. `clock` drives the vardiff engine + the
    /// `session_start_ms` timestamp. `session_id_hex` is the 8-hex
    /// session identity (used for the UI / DB / device notifications) —
    /// pass a freshly-generated one via [`random_session_id_hex`] or a
    /// fixed value for deterministic tests.
    ///
    /// `extranonce1` is seeded from `session_id_hex` here as a fallback;
    /// in production the server overwrites it with a pool-wide
    /// collision-free prefix from `server::SharedExtranonce` right after
    /// construction (the two used to be the same value — they are now
    /// decoupled so two sessions can never mine identical coinbases).
    pub fn new(
        clock: C,
        server_config: &ServerConfig,
        port_config: &PortConfig,
        session_id_hex: String,
    ) -> Self {
        let session_start_ms = clock.now_ms();
        let extranonce1 = parse_session_id(&session_id_hex);
        let initial = port_config.effective_initial_difficulty();

        let vardiff = VarDiffEngine::new(
            clock,
            port_config.target_shares_per_minute,
            port_config.minimum_difficulty,
        );

        Self {
            session_id_hex,
            extranonce1,
            session_start_ms,
            network: server_config.network,

            subscription: None,
            configuration: None,
            authorization: None,
            suggested_difficulty: None,

            stratum_initialized: false,
            used_suggested_difficulty: false,

            initial_difficulty: initial,
            session_difficulty: initial,
            old_session_difficulty: initial,
            diff_change_job_id: None,
            pending_session_difficulty: Some(initial),

            vardiff,
            last_difficulty_check_ms: 0,
            share_cache: SessionShareCache::new(),
            accepted_share_count: 0,
            hash_rate: 0.0,
            no_fee: false,
            extranonce_subscribed: false,
            stream: bp_common::StreamKind::Pplns,
            share_logs: server_config.share_logs,
        }
    }

    /// True after `mining.authorize` has been accepted and the worker
    /// address recorded. PPLNS / group-solo path eligibility depends on
    /// this.
    pub fn is_authorized(&self) -> bool {
        self.authorization.is_some()
    }

    /// Convenience: build the read-only session context that
    /// [`validate_submit`] expects.
    pub fn submit_context(&self) -> SessionContext<'_> {
        SessionContext {
            extranonce1: &self.extranonce1,
            session_difficulty: self.session_difficulty,
            old_session_difficulty: self.old_session_difficulty,
            diff_change_job_id: self.diff_change_job_id,
            share_logs: self.share_logs,
        }
    }
}

fn parse_session_id(hex_id: &str) -> [u8; 4] {
    let bytes = hex::decode(hex_id).unwrap_or_default();
    let mut out = [0u8; 4];
    let len = bytes.len().min(4);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// Generate an 8-hex-char session id from the OS CSPRNG.
/// 4 random bytes → BE u32 → zero-padded hex string.
///
/// Returns `"00000000"` if `getrandom` fails — the OS RNG only fails in
/// pathological cases (e.g. closed FDs in a hardened seccomp sandbox),
/// and even then a fixed session id is preferable to crashing the
/// connection.
pub fn random_session_id_hex() -> String {
    let mut bytes = [0u8; 4];
    getrandom::getrandom(&mut bytes).unwrap_or_default();
    let n = u32::from_be_bytes(bytes);
    format!("{:08x}", n)
}

// ── Session-level outcomes ───────────────────────────────────────────

/// What a handler decided about the session beyond the wire frames it
/// returned. The server task uses this to drive the hooks layer
/// (DB writes, share-stats fan-out, disconnect) without re-deriving
/// state.
#[derive(Debug)]
pub enum SessionEvent {
    /// Subscribe completed (sessionId pinned, extranonce assigned). The
    /// server can log the user-agent etc. Carried for diagnostic logging
    /// only — no hooks fire on this.
    Subscribed,
    /// Authorize completed for `address` (already normalized). The
    /// server registers the client under this address for fan-out.
    Authorized { address: String, worker: String },
    /// VarDiff ratcheted. Caller wires `bp-stats` per-mode hashrate
    /// flush + `client_difficulty_statistics` persist.
    DifficultyChanged { old: f64, new: f64 },
    /// Accepted share — caller updates share-totals, runs PPLNS /
    /// group-solo `recordShare` (if applicable), invokes the block-found
    /// path when `is_block_candidate`.
    ShareAccepted(Box<ShareAccept>),
    /// Rejected share — caller fans out to per-mode reject counters.
    ShareRejected {
        reason: RejectReason,
        difficulty: f64,
    },
    /// Connection should be torn down (currently triggered only by
    /// invalid-bitcoin-address rejection during authorize).
    Disconnect,
}

/// Result of an inbound-request handler.
#[derive(Debug, Default)]
pub struct HandlerOutcome {
    /// Bytes to write to the socket, in order. Each entry is a fully
    /// line-terminated JSON-RPC frame.
    pub outbound_frames: Vec<Vec<u8>>,
    /// Side-effects the server task should drive.
    pub events: Vec<SessionEvent>,
}

impl HandlerOutcome {
    fn with_frame(frame: Vec<u8>) -> Self {
        Self {
            outbound_frames: vec![frame],
            events: vec![],
        }
    }
    fn push_frame(&mut self, frame: Vec<u8>) {
        self.outbound_frames.push(frame);
    }
    fn push_event(&mut self, event: SessionEvent) {
        self.events.push(event);
    }
}

// ── Dispatch ─────────────────────────────────────────────────────────

/// Parse a JSON-RPC line and dispatch to the appropriate handler.
/// Convenience wrapper that callers (the server task) use end-to-end:
///
/// - JSON parse failure → empty outcome (caller closes the socket).
/// - Validation failure → an error frame with the parsed id + error reason string.
/// - Recognized method → matching handler.
///
/// The pure handlers are also exposed individually so tests can drive
/// the state machine without re-encoding to JSON each time.
pub fn dispatch<C: Clock>(
    state: &mut SessionState<C>,
    server_config: &ServerConfig,
    port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    current_template: Option<&ActiveSV1Template>,
    line: &str,
    now_ms: u64,
) -> HandlerOutcome {
    let request = match parse_request(line) {
        Ok(req) => req,
        Err(FrameParseError::InvalidJson) => {
            // We surface this as a Disconnect event with no frames.
            let mut out = HandlerOutcome::default();
            out.push_event(SessionEvent::Disconnect);
            return out;
        }
        Err(FrameParseError::Validation { id, code, message }) => {
            return HandlerOutcome::with_frame(write_error(&id, code, message));
        }
    };
    match request {
        SV1Request::Subscribe(req) => handle_subscribe(
            state,
            server_config,
            port_config,
            registry,
            current_template,
            req,
            now_ms,
        ),
        SV1Request::Configure(req) => handle_configure(state, server_config, req),
        SV1Request::Authorize(req) => handle_authorize(
            state,
            server_config,
            port_config,
            registry,
            current_template,
            req,
            now_ms,
        ),
        SV1Request::SuggestDifficulty(req) => {
            handle_suggest_difficulty(state, port_config, registry, req, now_ms)
        }
        SV1Request::Submit(req) => handle_submit(state, port_config, registry, req, now_ms),
        SV1Request::ExtranonceSubscribe(id) => handle_extranonce_subscribe(state, id),
        SV1Request::Other { .. } => HandlerOutcome::default(),
    }
}

/// `mining.extranonce.subscribe` — opt-in to the dynamic-extranonce extension.
/// Records the opt-in on the session and acks with `{"result":true}`. The flag
/// gates any later `mining.set_extranonce` push (a session that never
/// subscribed must not be sent extranonce updates). We do NOT rotate the
/// extranonce here — extranonce-1 stays the pool-assigned prefix from
/// subscribe time until something explicitly changes it.
pub fn handle_extranonce_subscribe<C: Clock>(
    state: &mut SessionState<C>,
    id: RpcId,
) -> HandlerOutcome {
    state.extranonce_subscribed = true;
    HandlerOutcome::with_frame(write_extranonce_subscribe_response(&id))
}

// ── Subscribe ────────────────────────────────────────────────────────

pub fn handle_subscribe<C: Clock>(
    state: &mut SessionState<C>,
    server_config: &ServerConfig,
    port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    current_template: Option<&ActiveSV1Template>,
    request: SubscribeRequest,
    now_ms: u64,
) -> HandlerOutcome {
    let mut out = HandlerOutcome::default();

    // 1. Write subscribe response. We always echo the existing session_id
    // — repeated subscribes from a confused miner re-use the same id.
    // The subscription id (first field) stays the session id; the
    // extranonce1 (second field) is the pool-wide collision-free prefix
    // the server assigned to this connection (see
    // `server::SharedExtranonce`). The two used to be the same value;
    // decoupling them is why we send `state.extranonce1` here rather than
    // `session_id_hex`. On submit the coinbase is reconstructed from the
    // same `state.extranonce1`, so miner and pool always agree.
    let already_subscribed = state.subscription.is_some();
    state.subscription = Some(request);
    let subscription_id = state.subscription.as_ref().expect("just set").id.clone();
    let extranonce1_hex = hex::encode(state.extranonce1);
    out.push_frame(write_subscribe_response(
        &subscription_id,
        &state.session_id_hex,
        &extranonce1_hex,
        server_config.extranonce2_size,
    ));
    out.push_event(SessionEvent::Subscribed);

    // 2. ckpool-style immediate init — send mining.set_difficulty + first
    // mining.notify right after the subscribe response. No 15 ms timer,
    // no gating on mining.extranonce.subscribe. Idempotent: if a
    // re-subscribe arrives we skip re-init.
    if !state.stratum_initialized && !already_subscribed {
        flush_init(
            state,
            server_config,
            port_config,
            registry,
            current_template,
            now_ms,
            &mut out,
        );
    }
    out
}

/// Initialize the Stratum handshake. Factored out so test helpers can
/// drive it directly without the full subscribe round-trip.
fn flush_init<C: Clock>(
    state: &mut SessionState<C>,
    server_config: &ServerConfig,
    _port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    current_template: Option<&ActiveSV1Template>,
    _now_ms: u64,
    out: &mut HandlerOutcome,
) {
    state.stratum_initialized = true;

    // cpuminer fallback: any session whose userAgent identifies as
    // cpuminer AND whose initial difficulty is below the high-diff
    // threshold gets pinned to 0.1.
    if let Some(sub) = &state.subscription {
        if sub.user_agent == "cpuminer"
            && state.initial_difficulty < server_config.cpuminer_high_diff_threshold
        {
            let new_diff = server_config.cpuminer_fallback_difficulty;
            // Snapshot the boundary for the ckpool race-clamp.
            state.old_session_difficulty = state.session_difficulty;
            state.diff_change_job_id = Some(registry.peek_next_job_id());
            state.session_difficulty = new_diff;
            state.pending_session_difficulty = Some(new_diff);
            out.push_event(SessionEvent::DifficultyChanged {
                old: state.old_session_difficulty,
                new: new_diff,
            });
        }
    }

    // First set_difficulty — only if the client hadn't already supplied
    // a `suggest_difficulty`.
    if state.suggested_difficulty.is_none() {
        out.push_frame(write_set_difficulty(state.session_difficulty));
    }

    // The first mining.notify is built by the IO layer once it has
    // async-resolved payouts via the [`crate::hooks::PayoutResolver`]
    // hook. Pre-authorize there's no address to resolve against, so
    // we leave the frame out here regardless of whether a template
    // is available — the IO layer fires it after the first authorize
    // either way. (This uses async dispatch, unlike the old synchronous
    // fallback; safe because no real mining
    // can happen pre-authorize anyway.)
    let _ = current_template;
}

// ── Configure ────────────────────────────────────────────────────────

pub fn handle_configure<C: Clock>(
    state: &mut SessionState<C>,
    server_config: &ServerConfig,
    request: ConfigureRequest,
) -> HandlerOutcome {
    state.configuration = Some(request.clone());
    HandlerOutcome::with_frame(write_configure_response(
        &request.id,
        server_config.version_rolling_mask,
    ))
}

// ── Authorize ────────────────────────────────────────────────────────

pub fn handle_authorize<C: Clock>(
    state: &mut SessionState<C>,
    _server_config: &ServerConfig,
    _port_config: &PortConfig,
    _registry: &Arc<JobRegistry>,
    _current_template: Option<&ActiveSV1Template>,
    mut request: AuthorizeRequest,
    _now_ms: u64,
) -> HandlerOutcome {
    let mut out = HandlerOutcome::default();
    let id = request.id.clone();

    // Empty address parses out as e.g. "address.worker" with address="" —
    // We validate via the parse-
    // step here.
    if request.address.is_empty() {
        out.push_frame(write_error(
            &id,
            ERR_OTHER_UNKNOWN,
            VALIDATION_INVALID_AUTHORIZE,
        ));
        return out;
    }

    // Normalise (trim + bech32-lowercase). Critical for downstream cache
    // / PPLNS-window keys.
    request.address = normalize_btc_address(&request.address);

    // Validate via `address_to_script` — covers parse failure AND
    // network mismatch.
    // bitcoin-address-validation; our `Address::from_str` +
    // `require_network` covers the same shape.
    if address_to_script(state.network, &request.address).is_err() {
        out.push_frame(write_error(&id, ERR_OTHER_UNKNOWN, REJECT_INVALID_ADDR));
        out.push_event(SessionEvent::Disconnect);
        return out;
    }

    state.authorization = Some(request.clone());
    out.push_frame(write_authorize_response(&id));
    out.push_event(SessionEvent::Authorized {
        address: request.address.clone(),
        worker: request.worker.clone(),
    });

    // The post-authorize mining.notify is the IO layer's
    // responsibility: it observes the [`SessionEvent::Authorized`]
    // event, async-resolves payouts via
    // [`crate::hooks::PayoutResolver`], and calls
    // [`apply_new_template`] with the resolved payouts. This handler
    // stays pure-sync; cross-references at the IO layer in
    // `server.rs::process_event`.
    out
}

// ── Suggest difficulty ───────────────────────────────────────────────

pub fn handle_suggest_difficulty<C: Clock>(
    state: &mut SessionState<C>,
    port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    request: SuggestDifficultyRequest,
    _now_ms: u64,
) -> HandlerOutcome {
    let mut out = HandlerOutcome::default();
    let id = request.id.clone();

    if !port_config.allow_suggested_difficulty {
        out.push_frame(write_error(&id, ERR_OTHER_UNKNOWN, REJECT_SUGGEST_DISABLED));
        return out;
    }
    if state.used_suggested_difficulty {
        // Silent return — second suggest is ignored.
        return out;
    }
    state.suggested_difficulty = Some(request.clone());

    // Floor: a port with `minimum_difficulty > 0` must clamp UP.
    let new_diff = if port_config.minimum_difficulty > 0.0 {
        request
            .suggested_difficulty
            .max(port_config.minimum_difficulty)
    } else {
        request.suggested_difficulty
    };

    // Snapshot the ckpool race-clamp boundary on every diff-changing
    // event. Without this, pre-suggest in-flight
    // shares would be validated against the new diff with no fallback.
    if new_diff != state.session_difficulty {
        state.old_session_difficulty = state.session_difficulty;
        state.diff_change_job_id = Some(registry.peek_next_job_id());
        out.push_event(SessionEvent::DifficultyChanged {
            old: state.session_difficulty,
            new: new_diff,
        });
    }
    state.session_difficulty = new_diff;
    state.pending_session_difficulty = Some(new_diff);
    state.used_suggested_difficulty = true;
    out.push_frame(write_set_difficulty(new_diff));
    out
}

// ── Submit ───────────────────────────────────────────────────────────

pub fn handle_submit<C: Clock>(
    state: &mut SessionState<C>,
    port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    request: SubmitRequest,
    now_ms: u64,
) -> HandlerOutcome {
    let mut out = HandlerOutcome::default();
    let id = request.id.clone();

    // Pre-conditions match the RPC message handler branching.
    if state.authorization.is_none() {
        out.push_frame(write_error(
            &id,
            ERR_UNAUTHORIZED_WORKER,
            REJECT_UNAUTHORIZED,
        ));
        return out;
    }
    if !state.stratum_initialized {
        out.push_frame(write_error(
            &id,
            crate::frame::ERR_NOT_SUBSCRIBED,
            REJECT_NOT_SUBSCRIBED,
        ));
        return out;
    }

    // Snapshot the read-only inputs to release the borrow on `state`
    // before we hand `state.share_cache` out as `&mut`. Borrow-checker:
    // disjoint-field-borrow rules don't see through helper methods, so
    // we do the projection inline.
    let extranonce1 = state.extranonce1;
    let session_ctx = SessionContext {
        extranonce1: &extranonce1,
        session_difficulty: state.session_difficulty,
        old_session_difficulty: state.old_session_difficulty,
        diff_change_job_id: state.diff_change_job_id,
        share_logs: state.share_logs,
    };
    let validation = validate_submit(
        &request,
        &session_ctx,
        &mut state.share_cache,
        registry,
        now_ms,
    );

    match validation {
        ShareValidation::Accepted(accept) => {
            out.push_frame(write_submit_success(&id));
            state.accepted_share_count = state.accepted_share_count.saturating_add(1);
            // Feed vardiff. is_current_diff = (effective == session)
            // `effectiveDiff === sessionDifficulty`.
            let is_current = accept.effective_difficulty == state.session_difficulty;
            state
                .vardiff
                .update_hash_rate(accept.effective_difficulty, is_current);
            state.hash_rate = state.vardiff.hash_rate();
            // The caller drives per-mode share-stats + block-found fan-
            // out via the event; pass the full ShareAccept through.
            // (Borrow-checked: `port_config` is not held mutably across
            // this point.)
            let _ = port_config; // payout-mode routing lands with the hooks
            out.push_event(SessionEvent::ShareAccepted(accept));
        }
        ShareValidation::Rejected(reject) => {
            out.push_frame(write_error(&id, reject.wire_code, reject.wire_message));
            out.push_event(SessionEvent::ShareRejected {
                reason: reject.reason,
                difficulty: state.session_difficulty,
            });
        }
    }
    out
}

// ── Periodic vardiff check (60s timer poll) ──────────────────────────

/// Difficulty validation check. Polled on the difficulty-check
/// timer AND inline after every accepted current-diff share.
///
/// Returns:
///   - empty outcome if no retarget needed
///   - else: a `mining.set_difficulty` frame + a fresh `mining.notify`.
///     The new
///     notify carries `clean_jobs=false` — ckpool comment: "No forced
///     clean_jobs=true on diff change … the right cover for in-flight
///     stale-diff shares is the CK-style clamp, not a queue flush."
#[allow(clippy::too_many_arguments)]
pub fn apply_vardiff_check<C: Clock>(
    state: &mut SessionState<C>,
    server_config: &ServerConfig,
    port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    job_cache: &MiningJobCache,
    current_template: Option<&Arc<ActiveSV1Template>>,
    payouts: &[PayoutEntry],
    now_ms: u64,
) -> HandlerOutcome {
    let mut out = HandlerOutcome::default();
    state.last_difficulty_check_ms = now_ms;

    let Some(target) = state.vardiff.suggested_difficulty(state.session_difficulty) else {
        return out;
    };
    if !target.is_finite() || target == state.session_difficulty {
        return out;
    }

    // Snapshot the boundary BEFORE the ratchet. Any job
    // whose id is < the upcoming next-id was issued under the old diff.
    let previous = state.session_difficulty;
    state.old_session_difficulty = state.session_difficulty;
    state.diff_change_job_id = Some(registry.peek_next_job_id());
    state.session_difficulty = target;
    state.pending_session_difficulty = Some(target);
    out.push_event(SessionEvent::DifficultyChanged {
        old: previous,
        new: target,
    });

    out.push_frame(write_set_difficulty(target));

    // Fresh mining.notify with clean_jobs=false. The new notify carries
    // the new target implicitly; old jobs continue at old diff until
    // they age out (covered by the ckpool clamp).
    if let Some(template) = current_template {
        if let Some(frame) = build_and_register_notify(
            state,
            server_config,
            port_config,
            registry,
            job_cache,
            template,
            payouts,
            false,
            now_ms,
        ) {
            out.push_frame(frame);
        }
    }
    out
}

// ── New-template event (server-driven; see translator in notify.rs) ──

/// Push a fresh mining.notify when the assembler produces an
/// [`crate::notify::TemplateChange`]. `clean_jobs` boolean is true on
/// `SetNewPrevHash`, false on `NewTemplate(future=false)` refreshes.
///
/// Side-effects:
///   - allocates a new jobId in the registry,
///   - clears the dedup cache on `clean_jobs=true`.
#[allow(clippy::too_many_arguments)]
pub fn apply_new_template<C: Clock>(
    state: &mut SessionState<C>,
    server_config: &ServerConfig,
    port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    job_cache: &MiningJobCache,
    template: &Arc<ActiveSV1Template>,
    payouts: &[PayoutEntry],
    clean_jobs: bool,
    now_ms: u64,
) -> HandlerOutcome {
    let mut out = HandlerOutcome::default();
    if !state.stratum_initialized {
        return out;
    }
    if clean_jobs {
        state.share_cache.clear();
    }
    if let Some(frame) = build_and_register_notify(
        state,
        server_config,
        port_config,
        registry,
        job_cache,
        template,
        payouts,
        clean_jobs,
        now_ms,
    ) {
        out.push_frame(frame);
    }
    out
}

/// Build the per-miner [`bp_mining_job::MiningJob`] for `template` +
/// `payouts`, register it in the [`JobRegistry`], and produce the
/// wire bytes for the resulting `mining.notify`. Returns `None` when
/// `payouts` is empty (early return when no payout target is
/// resolvable).
///
/// `payouts` is supplied by the caller because resolution may be
/// async (PPLNS / Group-Solo distributions are read from the engine
/// crates). The IO-layer connection loop async-resolves payouts at
/// template-broadcast / authorize time via the
/// [`crate::hooks::PayoutResolver`] hook and threads them down here.
#[allow(clippy::too_many_arguments)]
fn build_and_register_notify<C: Clock>(
    state: &mut SessionState<C>,
    server_config: &ServerConfig,
    _port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    job_cache: &MiningJobCache,
    template: &Arc<ActiveSV1Template>,
    payouts: &[PayoutEntry],
    clean_jobs: bool,
    now_ms: u64,
) -> Option<Vec<u8>> {
    if payouts.is_empty() {
        return None;
    }

    state.no_fee = payouts.len() == 1
        && state
            .authorization
            .as_ref()
            .is_some_and(|a| payouts[0].address == a.address);

    let tdp_template = TdpCoinbaseTemplate {
        coinbase_prefix: &template.coinbase_prefix,
        coinbase_tx_version: template.coinbase_tx_version,
        coinbase_tx_input_sequence: template.coinbase_tx_input_sequence,
        coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
        coinbase_tx_outputs: &template.coinbase_tx_outputs,
        coinbase_tx_outputs_count: template.coinbase_tx_outputs_count,
        coinbase_tx_locktime: template.coinbase_tx_locktime,
    };
    // Pool-wide memoized build: SV1 always uses the fixed
    // EXTRANONCE_SLOT_LEN, so every connection with the same payout set
    // (all of PPLNS) shares literally ONE `MiningJob` per template.
    let mining_job = job_cache
        .get_or_build(
            state.network,
            payouts,
            &tdp_template,
            &server_config.pool_identifier,
            EXTRANONCE_SLOT_LEN,
        )
        .ok()?;

    // `template.clone()` is an Arc refcount bump — the registry shares
    // the one template allocation across every connection's registration.
    let template_id_hex = registry.add_template_shared(template.clone(), now_ms);
    let job_id_hex = registry.add_job_shared(mining_job.clone(), template_id_hex, now_ms);
    Some(build_notify_frame(
        template,
        &mining_job,
        &job_id_hex,
        clean_jobs,
    ))
}

// ── Destroy ──────────────────────────────────────────────────────────

/// Implements pure-state cleanup on disconnect — clears the
/// vardiff cache and the dedup set, signals a Disconnect for the hooks
/// layer to drive unregister/delete/notification. Idempotent.
pub fn apply_destroy<C: Clock>(state: &mut SessionState<C>) -> HandlerOutcome {
    state.share_cache.clear();
    let mut out = HandlerOutcome::default();
    out.push_event(SessionEvent::Disconnect);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::RpcId;
    use crate::notify::ActiveSV1Template;
    use bp_common::MiningMode;
    use bp_vardiff::TestClock;

    // ── Fixtures ──────────────────────────────────────────────────────

    fn server_config() -> ServerConfig {
        ServerConfig::defaults_for(Network::Regtest)
    }

    fn solo_port(initial_diff: f64) -> PortConfig {
        PortConfig {
            payout_mode: MiningMode::Solo,
            ..PortConfig::new(3333, initial_diff)
        }
    }

    fn empty_registry() -> Arc<JobRegistry> {
        Arc::new(JobRegistry::from_server_config(&server_config()))
    }

    fn fresh_state(clock: TestClock, port: &PortConfig) -> SessionState<Arc<TestClock>> {
        let clock = Arc::new(clock);
        SessionState::new(clock, &server_config(), port, "abcd1234".to_string())
    }

    fn template_for_regtest() -> ActiveSV1Template {
        ActiveSV1Template {
            template_id: 1,
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            n_bits: 0x207f_ffff, // regtest easy bits
            header_timestamp: 1_700_000_000,
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
            merkle_branch_hex: vec![
                "1111111111111111111111111111111111111111111111111111111111111111".into(),
            ],
        }
    }

    // Real regtest bech32 — accepted by `address_to_script(Network::Regtest, ...)`.
    const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    /// Test fixture: builds a `SubscribeRequest` with the **refined** UA
    /// (`refine_user_agent` strips `/version` and collapses known firmware
    /// tags). Pass the raw UA; the fixture mirrors the parser's behavior
    /// so the in-engine `== "cpuminer"` check fires as it would in prod.
    fn subscribe_req(raw_ua: Option<&str>) -> SubscribeRequest {
        let refined = raw_ua
            .map(crate::frame::refine_user_agent)
            .unwrap_or_else(|| "unknown".to_string());
        SubscribeRequest {
            id: RpcId::from(1),
            raw_user_agent: raw_ua.map(String::from),
            user_agent: refined,
        }
    }

    fn authorize_req(addr: &str) -> AuthorizeRequest {
        AuthorizeRequest {
            id: RpcId::from(2),
            raw_username: format!("{}.w", addr),
            address: addr.to_string(),
            worker: "w".to_string(),
            password: None,
        }
    }

    /// Solo-mode single-output payout fixture for the
    /// `apply_new_template` / `apply_vardiff_check` tests. Pre-7.4d
    /// the handlers built this internally; post-7.4d the caller
    /// supplies it (the IO-layer connection loop async-resolves via
    /// [`crate::hooks::PayoutResolver`]).
    fn solo_payouts_fixture(addr: &str) -> Vec<PayoutEntry> {
        vec![PayoutEntry {
            address: addr.to_string(),
            sats: 5_000_000_000,
        }]
    }

    // ── 3 destroy spec cases ────────────────────────────────────────

    #[test]
    fn destroy_before_subscribe_emits_disconnect_only() {
        let port = solo_port(1024.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        let out = apply_destroy(&mut state);
        assert!(out.outbound_frames.is_empty());
        assert!(matches!(out.events.as_slice(), [SessionEvent::Disconnect]));
    }

    #[test]
    fn destroy_with_subscription_only_still_just_disconnect() {
        let port = solo_port(1024.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        state.subscription = Some(subscribe_req(Some("cgminer/4.11.1")));
        let out = apply_destroy(&mut state);
        assert!(matches!(out.events.as_slice(), [SessionEvent::Disconnect]));
    }

    #[test]
    fn destroy_with_authorization_emits_disconnect() {
        let port = solo_port(1024.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        state.subscription = Some(subscribe_req(Some("cgminer")));
        state.authorization = Some(authorize_req(REGTEST_ADDR));
        let out = apply_destroy(&mut state);
        // The hooks layer in Task #9 will translate Disconnect into an
        // unregisterClient + DB delete; the pure layer just signals.
        assert!(matches!(out.events.as_slice(), [SessionEvent::Disconnect]));
    }

    // ── 2 cpuminer-fallback spec cases ──────────────────────────────

    #[test]
    fn cpuminer_fallback_pins_to_low_diff_below_threshold() {
        // initial_diff < cpuminer_high_diff_threshold (1_000_000) → pin to 0.1.
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        state.subscription = Some(subscribe_req(Some("cpuminer/2.5")));
        let reg = empty_registry();
        let mut out = HandlerOutcome::default();
        flush_init(&mut state, &server_config(), &port, &reg, None, 0, &mut out);

        // First out-frame is set_difficulty (no suggested-diff seen).
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        // 0.1 → integer-valued? No: 0.1.fract() != 0 → float.
        assert!(s.contains("\"params\":[0.1]"));
        assert_eq!(state.session_difficulty, 0.1);
    }

    #[test]
    fn cpuminer_fallback_kept_high_difficulty_handshake() {
        // initial_diff == high-threshold → fallback skipped, session keeps 1_000_000.
        let port = solo_port(1_000_000.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        state.subscription = Some(subscribe_req(Some("cpuminer/2.5")));
        let reg = empty_registry();
        let mut out = HandlerOutcome::default();
        flush_init(&mut state, &server_config(), &port, &reg, None, 0, &mut out);
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(s.contains("\"params\":[1000000]"));
        assert_eq!(state.session_difficulty, 1_000_000.0);
    }

    // ── 1 suggest-disabled spec case ─────────────────────────────────

    #[test]
    fn suggest_difficulty_rejects_when_port_disables_it() {
        let port = PortConfig {
            allow_suggested_difficulty: false,
            ..solo_port(1_000_000.0)
        };
        let mut state = fresh_state(TestClock::new(0), &port);
        let reg = empty_registry();
        let req = SuggestDifficultyRequest {
            id: RpcId::from(42),
            suggested_difficulty: 500_000.0,
        };
        let out = handle_suggest_difficulty(&mut state, &port, &reg, req, 0);
        assert_eq!(out.outbound_frames.len(), 1);
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(s.contains("Suggest difficulty is disabled for this connection"));
        // Session difficulty unchanged from its initial.
        assert_eq!(state.session_difficulty, 1_000_000.0);
        assert!(!state.used_suggested_difficulty);
    }

    // ── Subscribe + handshake basics ──────────────────────────────────

    #[test]
    fn subscribe_emits_response_with_session_extranonce_and_size() {
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        let reg = empty_registry();
        let out = handle_subscribe(
            &mut state,
            &server_config(),
            &port,
            &reg,
            None,
            subscribe_req(Some("cgminer/4.11.1")),
            0,
        );
        // First frame: subscribe response. Second frame: set_difficulty
        // (no clientSuggestedDifficulty + no template).
        assert!(out.outbound_frames.len() >= 2);
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        // Wire format: [[["mining.notify", sid]], ext1, 8].
        assert!(s.contains("\"mining.notify\""));
        assert!(s.contains("\"abcd1234\""));
        assert!(s.contains("8]"));
    }

    #[test]
    fn subscribe_response_carries_allocated_extranonce1_not_session_id() {
        // The server assigns a pool-wide collision-free extranonce1 that is
        // decoupled from the (random) session id. The subscribe response
        // must carry that allocated prefix as the extranonce1 field while
        // keeping the session id in the mining.notify subscription tuple.
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port); // session id "abcd1234"
                                                               // Simulate a worker-1 allocated prefix distinct from the session id.
        state.extranonce1 = [0x01, 0x00, 0x00, 0x2a];
        let reg = empty_registry();
        let out = handle_subscribe(
            &mut state,
            &server_config(),
            &port,
            &reg,
            None,
            subscribe_req(Some("cgminer/4.11.1")),
            0,
        );
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        // Session id stays as the subscription id (notify tuple)...
        assert!(
            s.contains("\"abcd1234\""),
            "session id must remain the subscription id: {s}"
        );
        // ...but the extranonce1 field is the allocated prefix, not the session id.
        assert!(
            s.contains("\"0100002a\""),
            "extranonce1 must be the allocated prefix 0100002a: {s}"
        );
    }

    #[test]
    fn subscribe_does_not_send_notify_inline_anymore() {
        // Pre-7.4d the handler built the first mining.notify inline
        // via an inline solo payout split whenever the connection was
        // already authorized (an unusual but legal ordering). Post-7.4d the
        // notify is built by the IO-layer connection loop after it
        // async-resolves payouts via the `PayoutResolver` hook. The
        // handler now emits only subscribe-response + set_difficulty.
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        state.authorization = Some(authorize_req(REGTEST_ADDR));
        let reg = empty_registry();
        let template = template_for_regtest();
        let out = handle_subscribe(
            &mut state,
            &server_config(),
            &port,
            &reg,
            Some(&template),
            subscribe_req(Some("cgminer/4.11.1")),
            0,
        );
        // Frames: subscribe response + set_difficulty. NO notify.
        assert_eq!(out.outbound_frames.len(), 2);
        let last = std::str::from_utf8(out.outbound_frames.last().unwrap()).unwrap();
        assert!(last.contains("\"mining.set_difficulty\""));
        // Registry untouched: notify-build (and its registry insert)
        // happens at the IO layer now.
        assert_eq!(reg.job_count(), 0);
        assert_eq!(reg.template_count(), 0);
    }

    // ── Configure ─────────────────────────────────────────────────────

    #[test]
    fn configure_writes_version_rolling_response() {
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        let out = handle_configure(
            &mut state,
            &server_config(),
            ConfigureRequest {
                id: RpcId::from(7),
                params: serde_json::json!([]),
            },
        );
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(s.contains("\"version-rolling\":true"));
        assert!(s.contains("\"version-rolling.mask\":\"1fffe000\""));
    }

    // ── Extranonce subscribe ──────────────────────────────────────────

    #[test]
    fn extranonce_subscribe_acks_and_sets_optin_flag() {
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        assert!(!state.extranonce_subscribed);
        let out = handle_extranonce_subscribe(&mut state, RpcId::from(7));
        // Opt-in recorded so a later mining.set_extranonce push is permitted.
        assert!(state.extranonce_subscribed);
        // Acked with {"result":true} carrying the request id.
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert_eq!(s, "{\"id\":7,\"error\":null,\"result\":true}\n");
    }

    // ── Authorize ─────────────────────────────────────────────────────

    #[test]
    fn authorize_accepts_valid_regtest_address() {
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        let reg = empty_registry();
        let out = handle_authorize(
            &mut state,
            &server_config(),
            &port,
            &reg,
            None,
            authorize_req(REGTEST_ADDR),
            0,
        );
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(s.contains("\"result\":true"));
        // Event signal for the hooks layer.
        assert!(out
            .events
            .iter()
            .any(|e| matches!(e, SessionEvent::Authorized { .. })));
        assert!(state.authorization.is_some());
    }

    #[test]
    fn authorize_rejects_invalid_address_and_signals_disconnect() {
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        let reg = empty_registry();
        let mut req = authorize_req("definitely-not-an-address");
        req.address = "definitely-not-an-address".into();
        let out = handle_authorize(&mut state, &server_config(), &port, &reg, None, req, 0);
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(s.contains("Invalid Bitcoin address"));
        assert!(out
            .events
            .iter()
            .any(|e| matches!(e, SessionEvent::Disconnect)));
    }

    #[test]
    fn authorize_rejects_wrong_network_address() {
        // Mainnet bech32 — `address_to_script(Network::Regtest, …)` rejects.
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        let reg = empty_registry();
        let req = authorize_req("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let out = handle_authorize(&mut state, &server_config(), &port, &reg, None, req, 0);
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(s.contains("Invalid Bitcoin address"));
    }

    // ── Suggest_difficulty: accept path ───────────────────────────────

    #[test]
    fn suggest_difficulty_updates_session_and_snapshots_ratchet_boundary() {
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        let reg = empty_registry();
        let req = SuggestDifficultyRequest {
            id: RpcId::from(3),
            suggested_difficulty: 2048.0,
        };
        let out = handle_suggest_difficulty(&mut state, &port, &reg, req, 0);
        assert_eq!(state.session_difficulty, 2048.0);
        assert_eq!(state.old_session_difficulty, 16384.0);
        assert!(state.diff_change_job_id.is_some());
        assert!(state.used_suggested_difficulty);
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(s.contains("\"params\":[2048]"));
    }

    #[test]
    fn suggest_difficulty_clamps_to_port_minimum_floor() {
        let port = PortConfig {
            minimum_difficulty: 1000.0,
            ..solo_port(16384.0)
        };
        let mut state = fresh_state(TestClock::new(0), &port);
        let reg = empty_registry();
        let req = SuggestDifficultyRequest {
            id: RpcId::from(3),
            suggested_difficulty: 64.0,
        };
        let out = handle_suggest_difficulty(&mut state, &port, &reg, req, 0);
        // Clamped UP to 1000.
        assert_eq!(state.session_difficulty, 1000.0);
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(s.contains("\"params\":[1000]"));
    }

    // ── Submit precondition rejects ───────────────────────────────────

    fn submit_req(job_id: &str) -> SubmitRequest<'_> {
        SubmitRequest {
            id: RpcId::from(9),
            worker: "w".into(),
            job_id,
            extranonce2_hex: "1122334455667788",
            ntime_hex: "65a1b2c3",
            nonce_hex: "deadbeef",
            version_mask_hex: "0",
        }
    }

    #[test]
    fn submit_before_authorize_rejects_with_unauthorized_worker() {
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        state.stratum_initialized = true;
        let reg = empty_registry();
        let out = handle_submit(&mut state, &port, &reg, submit_req("1"), 0);
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(s.contains("Unauthorized worker"));
    }

    #[test]
    fn submit_before_subscribe_init_rejects_with_not_subscribed() {
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        state.authorization = Some(authorize_req(REGTEST_ADDR));
        // stratum_initialized stays false.
        let reg = empty_registry();
        let out = handle_submit(&mut state, &port, &reg, submit_req("1"), 0);
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(s.contains("Not subscribed"));
    }

    // ── apply_vardiff_check ──────────────────────────────────────────

    #[test]
    fn vardiff_check_without_samples_is_a_noop() {
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        let reg = empty_registry();
        let out = apply_vardiff_check(
            &mut state,
            &server_config(),
            &port,
            &reg,
            &MiningJobCache::new(),
            None,
            &[],
            1_000,
        );
        assert!(out.outbound_frames.is_empty());
        // last_difficulty_check_ms is still updated.
        assert_eq!(state.last_difficulty_check_ms, 1_000);
    }

    // ── apply_new_template ────────────────────────────────────────────

    #[test]
    fn new_template_after_init_clears_dedup_on_clean_jobs() {
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        state.stratum_initialized = true;
        state.authorization = Some(authorize_req(REGTEST_ADDR));
        // Pretend we'd seen one share.
        state.share_cache.record(&submit_req("99"));
        assert!(!state.share_cache.is_empty());

        let reg = empty_registry();
        let template = Arc::new(template_for_regtest());
        let payouts = solo_payouts_fixture(REGTEST_ADDR);
        let out = apply_new_template(
            &mut state,
            &server_config(),
            &port,
            &reg,
            &MiningJobCache::new(),
            &template,
            &payouts,
            true,
            0,
        );
        assert!(
            state.share_cache.is_empty(),
            "clean_jobs=true must clear dedup"
        );
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(s.contains("\"mining.notify\""));
        assert!(s.ends_with("true]}\n"));
    }

    #[test]
    fn new_template_with_clean_jobs_false_does_not_clear_dedup() {
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        state.stratum_initialized = true;
        state.authorization = Some(authorize_req(REGTEST_ADDR));
        state.share_cache.record(&submit_req("99"));

        let reg = empty_registry();
        let template = Arc::new(template_for_regtest());
        let payouts = solo_payouts_fixture(REGTEST_ADDR);
        let out = apply_new_template(
            &mut state,
            &server_config(),
            &port,
            &reg,
            &MiningJobCache::new(),
            &template,
            &payouts,
            false,
            0,
        );
        assert!(
            !state.share_cache.is_empty(),
            "fee-refresh must NOT clear dedup"
        );
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(s.ends_with("false]}\n"));
    }

    #[test]
    fn new_template_skips_emit_when_stratum_not_initialized() {
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        // stratum_initialized stays false.
        let reg = empty_registry();
        let template = Arc::new(template_for_regtest());
        let payouts = solo_payouts_fixture(REGTEST_ADDR);
        let out = apply_new_template(
            &mut state,
            &server_config(),
            &port,
            &reg,
            &MiningJobCache::new(),
            &template,
            &payouts,
            true,
            0,
        );
        assert!(out.outbound_frames.is_empty());
    }

    // ── Random session id ─────────────────────────────────────────────

    #[test]
    fn random_session_id_is_eight_lowercase_hex_chars() {
        let id = random_session_id_hex();
        assert_eq!(id.len(), 8);
        assert!(id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
