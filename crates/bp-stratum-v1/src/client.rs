// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection SV1 session state and pure handlers. Handlers mutate only
//! [`SessionState`] and return wire frames plus [`SessionEvent`]s, so the
//! server task owns all I/O and drives the side-effect hooks from the events.

use std::sync::Arc;

use bitcoin::Network;
use bp_common::normalize_btc_address;
use bp_mining_job::{
    address_to_script, MiningJobCache, ResolvedPayouts, TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
};

use crate::config::{
    PortConfig, ServerConfig, CPUMINER_FALLBACK_DIFFICULTY, CPUMINER_HIGH_DIFF_THRESHOLD,
    EXTRANONCE2_SIZE, VERSION_ROLLING_MASK,
};
use crate::frame::{
    parse_request, write_authorize_response, write_configure_response, write_error,
    write_extranonce_subscribe_response, write_set_difficulty, write_submit_success,
    write_subscribe_response, AuthorizeRequest, ConfigureRequest, FrameParseError, RequestedMask,
    RpcId, SV1Request, SubmitRequest, SubscribeRequest, SuggestDifficultyRequest,
    ERR_OTHER_UNKNOWN, ERR_UNAUTHORIZED_WORKER, REJECT_INVALID_ADDR, REJECT_NOT_SUBSCRIBED,
    REJECT_SUGGEST_DISABLED, REJECT_UNAUTHORIZED, VALIDATION_INVALID_AUTHORIZE,
};
use crate::jobs::JobRegistry;
use crate::notify::{build_notify_frame, ActiveSV1Template};
use crate::submit::{
    validate_submit, RejectReason, SessionContext, SessionShareCache, ShareAccept, ShareValidation,
};
use bp_vardiff::{Clock, VarDiffEngine};

// ── SessionState ─────────────────────────────────────────────────────

/// All per-session mutable state, owned by the connection's server task.
/// Holds no socket or channel: handlers return frames for the caller to flush.
pub(crate) struct SessionState<C: Clock> {
    /// BIP-310 `last_mask`; each `mining.configure` replaces it with the mask
    /// just sent. ⚠️ Starts at the advertised mask, not zero: SV1 firmware is
    /// tested against ckpool, which accepts rolling without configure, so
    /// strictness applies only to a mask the pool actually answered.
    pub version_rolling_mask: u32,

    // Identity
    pub session_id_hex: String,
    pub extranonce1: [u8; 4],
    pub network: Network,

    // Handshake messages — populated as they arrive
    pub subscription: Option<SubscribeRequest>,
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

    // VarDiff + dedup
    pub vardiff: VarDiffEngine<C>,
    pub last_difficulty_check_ms: u64,
    pub share_cache: SessionShareCache,

    // Live caches mirrored back from vardiff
    pub hash_rate: f64,

    /// TDP template stream, resolved once at authorize and then fixed, so the
    /// block-submit handle can never disagree with the template a job was
    /// built on.
    pub stream: bp_common::StreamKind,

    /// Per-share diagnostic traces in [`validate_submit`], copied from
    /// [`ServerConfig`].
    pub share_logs: bool,
}

impl<C: Clock> SessionState<C> {
    /// `extranonce1` is seeded from `session_id_hex` only as a fallback; the
    /// server overwrites it with a pool-wide collision-free prefix
    /// (`server::SharedExtranonce`) so two sessions never mine identical
    /// coinbases.
    pub(crate) fn new(
        clock: C,
        server_config: &ServerConfig,
        port_config: &PortConfig,
        session_id_hex: String,
    ) -> Self {
        let extranonce1 = parse_session_id(&session_id_hex);
        let initial = port_config.effective_initial_difficulty();

        let vardiff = VarDiffEngine::new(
            clock,
            port_config.target_shares_per_minute,
            port_config.minimum_difficulty,
            initial,
        );

        Self {
            version_rolling_mask: VERSION_ROLLING_MASK,
            session_id_hex,
            extranonce1,
            network: server_config.network,

            subscription: None,
            authorization: None,
            suggested_difficulty: None,

            stratum_initialized: false,
            used_suggested_difficulty: false,

            initial_difficulty: initial,
            session_difficulty: initial,
            old_session_difficulty: initial,
            diff_change_job_id: None,

            vardiff,
            last_difficulty_check_ms: 0,
            share_cache: SessionShareCache::new(),
            hash_rate: 0.0,
            stream: bp_common::StreamKind::Pplns,
            share_logs: server_config.share_logs,
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

/// 8-hex-char session id from the OS CSPRNG. Falls back to `"00000000"` if
/// the RNG fails: a fixed id is better than dropping the connection.
pub(crate) fn random_session_id_hex() -> String {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).unwrap_or_default();
    let n = u32::from_be_bytes(bytes);
    format!("{:08x}", n)
}

// ── Session-level outcomes ───────────────────────────────────────────

/// What a handler decided beyond its wire frames; the server task drives the
/// hooks from these without re-deriving state.
#[derive(Debug)]
pub(crate) enum SessionEvent {
    /// Diagnostic only; no hooks fire on it.
    Subscribed,
    /// `address` is already normalized.
    Authorized {
        address: String,
        worker: String,
    },
    DifficultyChanged,
    ShareAccepted(Box<ShareAccept>),
    ShareRejected {
        reason: RejectReason,
        difficulty: f64,
    },
    Disconnect,
}

#[derive(Debug, Default)]
pub(crate) struct HandlerOutcome {
    /// Line-terminated JSON-RPC frames, in write order.
    pub outbound_frames: Vec<Vec<u8>>,
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

/// Parse a JSON-RPC line and dispatch it. Unparseable JSON disconnects; a
/// request that fails validation gets an error frame with its id.
pub(crate) fn dispatch<C: Clock>(
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
            let mut out = HandlerOutcome::default();
            out.push_event(SessionEvent::Disconnect);
            return out;
        }
        Err(FrameParseError::Validation { id, code, message }) => {
            return HandlerOutcome::with_frame(write_error(&id, code, message));
        }
    };
    match request {
        SV1Request::Subscribe(req) => {
            handle_subscribe(state, port_config, registry, current_template, req, now_ms)
        }
        SV1Request::Configure(req) => handle_configure(state, req),
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
        SV1Request::Submit(req) => handle_submit(state, registry, req, now_ms),
        SV1Request::ExtranonceSubscribe(id) => handle_extranonce_subscribe(id),
        SV1Request::Other { .. } => HandlerOutcome::default(),
    }
}

/// Acked and otherwise ignored: the pool never sends `mining.set_extranonce`,
/// so extranonce-1 stays fixed for the whole connection.
pub(crate) fn handle_extranonce_subscribe(id: RpcId) -> HandlerOutcome {
    HandlerOutcome::with_frame(write_extranonce_subscribe_response(&id))
}

// ── Subscribe ────────────────────────────────────────────────────────

pub(crate) fn handle_subscribe<C: Clock>(
    state: &mut SessionState<C>,
    port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    current_template: Option<&ActiveSV1Template>,
    request: SubscribeRequest,
    now_ms: u64,
) -> HandlerOutcome {
    let mut out = HandlerOutcome::default();

    // extranonce1 is the pool-wide prefix, not the session id: submit
    // rebuilds the coinbase from this same value.
    let already_subscribed = state.subscription.is_some();
    state.subscription = Some(request);
    let subscription_id = state.subscription.as_ref().expect("just set").id.clone();
    let extranonce1_hex = hex::encode(state.extranonce1);
    out.push_frame(write_subscribe_response(
        &subscription_id,
        &state.session_id_hex,
        &extranonce1_hex,
        EXTRANONCE2_SIZE,
    ));
    out.push_event(SessionEvent::Subscribed);

    // Init right after subscribe, as ckpool does, not gated on
    // mining.extranonce.subscribe. A re-subscribe skips it.
    if !state.stratum_initialized && !already_subscribed {
        flush_init(
            state,
            port_config,
            registry,
            current_template,
            now_ms,
            &mut out,
        );
    }
    out
}

fn flush_init<C: Clock>(
    state: &mut SessionState<C>,
    _port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    current_template: Option<&ActiveSV1Template>,
    _now_ms: u64,
    out: &mut HandlerOutcome,
) {
    state.stratum_initialized = true;

    if let Some(sub) = &state.subscription {
        if sub.user_agent == "cpuminer" && state.initial_difficulty < CPUMINER_HIGH_DIFF_THRESHOLD {
            let new_diff = CPUMINER_FALLBACK_DIFFICULTY;
            // Boundary for the ckpool race-clamp.
            state.old_session_difficulty = state.session_difficulty;
            state.diff_change_job_id = Some(registry.peek_next_job_id());
            state.session_difficulty = new_diff;
            state.vardiff.note_difficulty_assigned(new_diff);
            out.push_event(SessionEvent::DifficultyChanged);
        }
    }

    if state.suggested_difficulty.is_none() {
        out.push_frame(write_set_difficulty(state.session_difficulty));
    }

    // No notify here: the IO layer sends the first one after authorize,
    // since payouts cannot be resolved before there is an address.
    let _ = current_template;
}

// ── Configure ────────────────────────────────────────────────────────

pub(crate) fn handle_configure<C: Clock>(
    state: &mut SessionState<C>,
    request: ConfigureRequest,
) -> HandlerOutcome {
    // BIP-310: response = server_mask & miner_mask. An absent mask counts as
    // `ffffffff` per BIP-310; an unreadable one is treated the same (and
    // logged) rather than costing the miner version rolling entirely.
    let requested = match request.requested_version_rolling_mask() {
        RequestedMask::Requested(mask) => mask,
        RequestedMask::Absent => u32::MAX,
        RequestedMask::Malformed => {
            tracing::warn!(
                params = %request.params,
                "mining.configure carried an unreadable version-rolling.mask; \
                 falling back to the advertised mask"
            );
            u32::MAX
        }
    };
    let negotiated = VERSION_ROLLING_MASK & requested;

    // Assigned, not narrowed: a repeated configure is a fresh negotiation,
    // and the miner acts on the mask just sent.
    state.version_rolling_mask = negotiated;
    HandlerOutcome::with_frame(write_configure_response(&request.id, negotiated))
}

// ── Authorize ────────────────────────────────────────────────────────

pub(crate) fn handle_authorize<C: Clock>(
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

    // A username like ".worker" parses to an empty address.
    if request.address.is_empty() {
        tracing::warn!(
            session_id_hex = %state.session_id_hex,
            username = %request.raw_username,
            reason = VALIDATION_INVALID_AUTHORIZE,
            "sv1 authorize refused"
        );
        out.push_frame(write_error(
            &id,
            ERR_OTHER_UNKNOWN,
            VALIDATION_INVALID_AUTHORIZE,
        ));
        return out;
    }

    // Every cache and PPLNS-window key depends on the normalized form.
    request.address = normalize_btc_address(&request.address);

    // `address_to_script` covers parse failure AND network mismatch.
    if address_to_script(state.network, &request.address).is_err() {
        tracing::warn!(
            session_id_hex = %state.session_id_hex,
            username = %request.raw_username,
            reason = REJECT_INVALID_ADDR,
            "sv1 authorize refused"
        );
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

    // The IO layer sends the first notify on `Authorized` after resolving
    // payouts, so this handler stays synchronous.
    out
}

// ── Suggest difficulty ───────────────────────────────────────────────

pub(crate) fn handle_suggest_difficulty<C: Clock>(
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

    // Snapshot the ckpool race-clamp boundary on every difficulty change,
    // so shares in flight from before the suggest keep a fallback.
    if new_diff != state.session_difficulty {
        state.old_session_difficulty = state.session_difficulty;
        state.diff_change_job_id = Some(registry.peek_next_job_id());
        out.push_event(SessionEvent::DifficultyChanged);
    }
    state.session_difficulty = new_diff;
    state.vardiff.note_difficulty_assigned(new_diff);
    state.used_suggested_difficulty = true;
    out.push_frame(write_set_difficulty(new_diff));
    out
}

// ── Submit ───────────────────────────────────────────────────────────

pub(crate) fn handle_submit<C: Clock>(
    state: &mut SessionState<C>,
    registry: &Arc<JobRegistry>,
    request: SubmitRequest,
    now_ms: u64,
) -> HandlerOutcome {
    let mut out = HandlerOutcome::default();
    let id = request.id.clone();

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

    // Built inline so `state.share_cache` can be borrowed `&mut` alongside.
    let extranonce1 = state.extranonce1;
    let session_ctx = SessionContext {
        extranonce1: &extranonce1,
        session_difficulty: state.session_difficulty,
        old_session_difficulty: state.old_session_difficulty,
        diff_change_job_id: state.diff_change_job_id,
        share_logs: state.share_logs,
        version_rolling_mask: state.version_rolling_mask,
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
            state
                .vardiff
                .note_share_accepted(accept.effective_difficulty);
            state.hash_rate = state.vardiff.hash_rate();
            out.push_event(SessionEvent::ShareAccepted(accept));
        }
        ShareValidation::Rejected(reject) => {
            // Only a stale share counts as an arrival (see
            // `VarDiffEngine::note_stale_share`): an unknown job, a duplicate
            // and a below-target or malformed share say nothing about the rate,
            // and SV2 treats them the same way.
            let counts_as_arrival = match reject.reason {
                RejectReason::Stale => true,
                RejectReason::JobNotFound
                | RejectReason::DuplicateShare
                | RejectReason::LowDifficulty
                | RejectReason::VersionRollingNotAllowed => false,
            };
            if counts_as_arrival {
                state.vardiff.note_stale_share();
            }
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

/// Vardiff retarget, polled on the timer and after each accepted current-diff
/// share. A retarget sends `mining.set_difficulty` plus a notify with
/// `clean_jobs=false`: in-flight shares at the old difficulty are covered by
/// the ckpool-style clamp, not by a job flush.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_vardiff_check<C: Clock>(
    state: &mut SessionState<C>,
    server_config: &ServerConfig,
    port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    job_cache: &MiningJobCache,
    current_template: Option<&Arc<ActiveSV1Template>>,
    payouts: &ResolvedPayouts,
    now_ms: u64,
) -> HandlerOutcome {
    let mut out = HandlerOutcome::default();
    state.last_difficulty_check_ms = now_ms;

    // Silence counts as evidence, so only judge a session that could have
    // mined: without a handshake there is no miner, and without a template
    // an outage would walk every session down to the floor and make them
    // all flood on recovery.
    if !state.stratum_initialized || current_template.is_none() {
        return out;
    }

    let Some(target) = state.vardiff.suggested_difficulty(state.session_difficulty) else {
        return out;
    };
    if !target.is_finite() || target == state.session_difficulty {
        return out;
    }

    // Snapshot the boundary BEFORE the ratchet: any job id below the next
    // id was issued under the old diff.
    state.old_session_difficulty = state.session_difficulty;
    state.diff_change_job_id = Some(registry.peek_next_job_id());
    state.session_difficulty = target;
    state.vardiff.note_difficulty_assigned(target);
    out.push_event(SessionEvent::DifficultyChanged);

    out.push_frame(write_set_difficulty(target));

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

/// Push a notify for a [`bp_template_distribution::TemplateChange`].
/// `clean_jobs` is true on a new prevhash, which also clears the dedup cache.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_new_template<C: Clock>(
    state: &mut SessionState<C>,
    server_config: &ServerConfig,
    port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    job_cache: &MiningJobCache,
    template: &Arc<ActiveSV1Template>,
    payouts: &ResolvedPayouts,
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

/// Build and register the [`bp_mining_job::MiningJob`] and return its notify.
/// MONEY: `None` for an empty payout list, which means "serve no job"; a
/// coinbase for it would pay this one miner the whole block. `payouts` comes
/// from the caller because resolving it is async.
#[allow(clippy::too_many_arguments)]
fn build_and_register_notify<C: Clock>(
    state: &SessionState<C>,
    server_config: &ServerConfig,
    _port_config: &PortConfig,
    registry: &Arc<JobRegistry>,
    job_cache: &MiningJobCache,
    template: &Arc<ActiveSV1Template>,
    payouts: &ResolvedPayouts,
    clean_jobs: bool,
    now_ms: u64,
) -> Option<Vec<u8>> {
    if payouts.entries.is_empty() {
        return None;
    }

    let tdp_template = TdpCoinbaseTemplate {
        coinbase_prefix: &template.coinbase_prefix,
        coinbase_tx_version: template.coinbase_tx_version,
        coinbase_tx_input_sequence: template.coinbase_tx_input_sequence,
        coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
        coinbase_tx_outputs: &template.coinbase_tx_outputs,
        coinbase_tx_outputs_count: template.coinbase_tx_outputs_count,
        coinbase_tx_locktime: template.coinbase_tx_locktime,
    };
    // Memoized pool-wide: SV1 always uses EXTRANONCE_SLOT_LEN, so every
    // connection with the same payout set shares ONE `MiningJob` per template.
    let mining_job = job_cache
        .get_or_build(
            state.network,
            &payouts.entries,
            &tdp_template,
            &server_config.pool_identifier,
            EXTRANONCE_SLOT_LEN,
            payouts.payouts_fingerprint,
        )
        .inspect_err(|err| {
            tracing::warn!(
                ?err,
                session_id = %state.session_id_hex,
                "skipping mining.notify: mining-job build failed"
            );
        })
        .ok()?;

    let template_id_hex = registry.add_template_shared(template.clone(), now_ms);
    let job_id_hex = registry.add_job_shared(mining_job.clone(), template_id_hex, now_ms);
    Some(build_notify_frame(
        template,
        &mining_job,
        &job_id_hex,
        clean_jobs,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::RpcId;
    use crate::notify::ActiveSV1Template;
    use bp_common::MiningMode;
    use bp_mining_job::PayoutEntry;
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

    /// Vardiff only judges a session with a handshake and a template.
    fn mineable_template() -> Arc<ActiveSV1Template> {
        let t = ActiveSV1Template::from_template(bp_template_distribution::ActiveTemplate {
            template_id: 1,
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            n_bits: 0x1d00_ffff,
            header_timestamp: 0x65a1_b2c3,
            coinbase_prefix: vec![0x03, 0x40, 0x0d, 0x03],
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xffff_ffff,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: vec![0u8; 8],
            coinbase_tx_outputs_count: 0,
            coinbase_tx_locktime: 0,
            merkle_path: vec![],
        });
        Arc::new(t)
    }

    fn fresh_state(clock: TestClock, port: &PortConfig) -> SessionState<Arc<TestClock>> {
        let clock = Arc::new(clock);
        SessionState::new(clock, &server_config(), port, "abcd1234".to_string())
    }

    /// MONEY: an empty payout list ("serve no job") yields no notify, whichever
    /// layer enforces it, so a resolver fault never pays one miner the block.
    #[test]
    fn no_notify_is_built_when_the_resolver_serves_no_job() {
        let port = solo_port(1.0);
        let state = fresh_state(TestClock::new(0), &port);
        let template = mineable_template();
        let cache = MiningJobCache::new();

        let out = build_and_register_notify(
            &state,
            &server_config(),
            &port,
            &empty_registry(),
            &cache,
            &template,
            &ResolvedPayouts::none(),
            true,
            0,
        );
        assert!(
            out.is_none(),
            "an empty payout list must produce NO mining.notify"
        );

        // Control: a real list DOES produce one.
        let out = build_and_register_notify(
            &state,
            &server_config(),
            &port,
            &empty_registry(),
            &cache,
            &template,
            &ResolvedPayouts::unsnapshotted(vec![PayoutEntry {
                address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string(),
                sats: 5_000_000_000,
            }]),
            true,
            0,
        );
        assert!(
            out.is_some(),
            "precondition: a resolvable list still yields a mining.notify"
        );
    }

    fn template_for_regtest() -> ActiveSV1Template {
        ActiveSV1Template::from_template(bp_template_distribution::ActiveTemplate {
            template_id: 1,
            version: 0x2000_0000,
            prev_hash: [0xAB; 32],
            n_bits: 0x207f_ffff, // regtest easy bits
            header_timestamp: 1_700_000_000,
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
        })
    }

    // Real regtest bech32 — accepted by `address_to_script(Network::Regtest, ...)`.
    const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    /// Asserts the notify carries `template_for_regtest`'s real header values,
    /// not the `""` a desynced fixture would emit.
    fn assert_regtest_notify_header(frame: &[u8]) {
        let v: serde_json::Value =
            serde_json::from_slice(&frame[..frame.len() - 1]).expect("notify is JSON");
        let p = v["params"].as_array().expect("params array");
        // Word-swapping [0xAB; 32] is the identity.
        assert_eq!(p[1].as_str().unwrap(), "ab".repeat(32), "prevhash");
        assert_eq!(p[5].as_str().unwrap(), "20000000", "version");
        assert_eq!(p[6].as_str().unwrap(), "207fffff", "nbits");
        assert!(!p[7].as_str().unwrap().is_empty(), "ntime present");
    }

    /// Normalizes the raw UA as the parser does, so the `== "cpuminer"`
    /// check fires as it would in production.
    fn subscribe_req(raw_ua: Option<&str>) -> SubscribeRequest {
        let refined = raw_ua
            .map(bp_common::normalize_user_agent)
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

    fn solo_payouts_fixture(addr: &str) -> ResolvedPayouts {
        ResolvedPayouts::unsnapshotted(vec![PayoutEntry {
            address: addr.to_string(),
            sats: 5_000_000_000,
        }])
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
        flush_init(&mut state, &port, &reg, None, 0, &mut out);

        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
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
        flush_init(&mut state, &port, &reg, None, 0, &mut out);
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
            &port,
            &reg,
            None,
            subscribe_req(Some("cgminer/4.11.1")),
            0,
        );
        // Subscribe response, then set_difficulty.
        assert!(out.outbound_frames.len() >= 2);
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        // Wire format: [[["mining.notify", sid]], ext1, 8].
        assert!(s.contains("\"mining.notify\""));
        assert!(s.contains("\"abcd1234\""));
        assert!(s.contains("8]"));
    }

    #[test]
    fn subscribe_response_carries_allocated_extranonce1_not_session_id() {
        // Pins: extranonce1 field is the allocated prefix, the session id
        // stays in the mining.notify subscription tuple.
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port); // session id "abcd1234"
        state.extranonce1 = [0x01, 0x00, 0x00, 0x2a];
        let reg = empty_registry();
        let out = handle_subscribe(
            &mut state,
            &port,
            &reg,
            None,
            subscribe_req(Some("cgminer/4.11.1")),
            0,
        );
        let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(
            s.contains("\"abcd1234\""),
            "session id must remain the subscription id: {s}"
        );
        assert!(
            s.contains("\"0100002a\""),
            "extranonce1 must be the allocated prefix 0100002a: {s}"
        );
    }

    #[test]
    fn subscribe_does_not_send_notify_inline_anymore() {
        // Pins: even when already authorized, subscribe sends no notify and
        // touches no registry; the IO layer builds it after resolving payouts.
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        state.authorization = Some(authorize_req(REGTEST_ADDR));
        let reg = empty_registry();
        let template = template_for_regtest();
        let out = handle_subscribe(
            &mut state,
            &port,
            &reg,
            Some(&template),
            subscribe_req(Some("cgminer/4.11.1")),
            0,
        );
        assert_eq!(out.outbound_frames.len(), 2);
        let last = std::str::from_utf8(out.outbound_frames.last().unwrap()).unwrap();
        assert!(last.contains("\"mining.set_difficulty\""));
        assert_eq!(reg.job_count(), 0);
        assert_eq!(reg.template_count(), 0);
    }

    // ── Configure ─────────────────────────────────────────────────────

    /// Drive `handle_configure` and return `(response frame, negotiated mask)`.
    fn configure(params: serde_json::Value) -> (String, u32) {
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        let out = handle_configure(
            &mut state,
            ConfigureRequest {
                id: RpcId::from(7),
                params,
            },
        );
        (
            std::str::from_utf8(&out.outbound_frames[0])
                .unwrap()
                .to_string(),
            state.version_rolling_mask,
        )
    }

    /// The mask hex the pool answered with.
    fn negotiated_mask_hex(params: serde_json::Value) -> String {
        let (s, _) = configure(params);
        assert!(
            s.contains("\"version-rolling\":true"),
            "response must advertise the extension: {s}"
        );
        let marker = "\"version-rolling.mask\":\"";
        let start = s.find(marker).expect("mask field present") + marker.len();
        s[start..start + 8].to_string()
    }

    /// An unreadable `version-rolling.mask` gets the advertised mask: neither
    /// widened by a typo nor costing the miner its version rolling.
    #[test]
    fn an_unreadable_mask_falls_back_to_the_advertised_mask() {
        for bad in [
            serde_json::json!("1fffe0000"), // one digit too many
            serde_json::json!("zzzz"),      // not hex
            serde_json::json!(""),          // empty
            serde_json::json!(536862720),   // not a string
            serde_json::json!(" 1fffe000"), // stray whitespace
        ] {
            let (frame, stored) = configure(serde_json::json!([
                ["version-rolling"],
                {"version-rolling.mask": bad}
            ]));
            assert_eq!(
                stored, VERSION_ROLLING_MASK,
                "unreadable mask {bad} must not narrow the session"
            );
            assert!(
                frame.contains("\"version-rolling.mask\":\"1fffe000\""),
                "unreadable mask {bad} must still be answered with the advertised \
                 mask, got: {frame}"
            );
        }

        // Negative control: a readable mask is still honoured.
        assert_eq!(
            negotiated_mask_hex(serde_json::json!([
                ["version-rolling"],
                {"version-rolling.mask": "00c00000"}
            ])),
            "00c00000"
        );
    }

    /// A session without `mining.configure` starts at the advertised mask, not zero.
    #[test]
    fn a_fresh_session_starts_at_the_advertised_mask() {
        let port = solo_port(16384.0);
        let state = fresh_state(TestClock::new(0), &port);
        assert_eq!(state.version_rolling_mask, VERSION_ROLLING_MASK);
        assert_ne!(state.version_rolling_mask, 0);
    }

    #[test]
    fn configure_writes_version_rolling_response() {
        let (s, stored) = configure(serde_json::json!([]));
        assert!(s.contains("\"version-rolling\":true"));
        assert!(s.contains("\"version-rolling.mask\":\"1fffe000\""));
        assert_eq!(stored, 0x1fffe000);
    }

    /// BIP-310: `response = server_mask & miner_mask`.
    #[test]
    fn the_response_is_the_intersection_of_server_and_miner_mask() {
        assert_eq!(
            negotiated_mask_hex(serde_json::json!([
                ["version-rolling"],
                {"version-rolling.mask": "1fffe000"}
            ])),
            "1fffe000"
        );
        // A subset gets exactly that subset; BIP-310 forbids answering more.
        assert_eq!(
            negotiated_mask_hex(serde_json::json!([
                ["version-rolling"],
                {"version-rolling.mask": "00c00000"}
            ])),
            "00c00000"
        );
        // Bits the pool does not grant drop out.
        assert_eq!(
            negotiated_mask_hex(serde_json::json!([
                ["version-rolling"],
                {"version-rolling.mask": "ffffe000"}
            ])),
            "1fffe000"
        );
    }

    /// BIP-310: an absent mask defaults to `ffffffff`; reading it as zero
    /// would switch the miner's version rolling off.
    #[test]
    fn an_absent_mask_field_means_everything_not_nothing() {
        for params in [
            serde_json::json!([["version-rolling"], {}]),
            serde_json::json!([]),
        ] {
            assert_eq!(
                negotiated_mask_hex(params.clone()),
                "1fffe000",
                "absent mask must intersect to the full server mask for {params}"
            );
        }
        // Negative control: an *explicit* zero is honoured as zero.
        assert_eq!(
            negotiated_mask_hex(serde_json::json!([
                ["version-rolling"],
                {"version-rolling.mask": "00000000"}
            ])),
            "00000000"
        );
    }

    // ── Extranonce subscribe ──────────────────────────────────────────

    #[test]
    fn extranonce_subscribe_acks() {
        let out = handle_extranonce_subscribe(RpcId::from(7));
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
        let out = handle_submit(&mut state, &reg, submit_req("1"), 0);
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
        let out = handle_submit(&mut state, &reg, submit_req("1"), 0);
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
            &ResolvedPayouts::unsnapshotted(vec![]),
            1_000,
        );
        assert!(out.outbound_frames.is_empty());
        assert_eq!(state.last_difficulty_check_ms, 1_000);
    }

    // ── silence on the wire ──────────────────────────────────────────
    // `measured_session` sits at equilibrium (30 shares at 16384, 10 s
    // apart), so any retarget observed comes from what follows.

    fn measured_session(
        clock: &Arc<TestClock>,
    ) -> (SessionState<Arc<TestClock>>, ServerConfig, PortConfig) {
        let sc = server_config();
        let port = solo_port(16384.0);
        let mut state = SessionState::new(clock.clone(), &sc, &port, "abcd1234".to_string());
        state.stratum_initialized = true;
        for _ in 0..30 {
            state.vardiff.note_share_accepted(16384.0);
            clock.advance_ms(10_000);
        }
        (state, sc, port)
    }

    fn vardiff_check_now(
        state: &mut SessionState<Arc<TestClock>>,
        sc: &ServerConfig,
        port: &PortConfig,
        clock: &Arc<TestClock>,
    ) -> HandlerOutcome {
        apply_vardiff_check(
            state,
            sc,
            port,
            &empty_registry(),
            &MiningJobCache::new(),
            Some(&mineable_template()),
            &ResolvedPayouts::unsnapshotted(vec![]),
            clock.now_ms(),
        )
    }

    /// A session that never reaches its port's start difficulty is walked
    /// down on the wire.
    #[test]
    fn a_session_with_no_share_ever_is_eased_down_on_the_wire() {
        let clock = Arc::new(TestClock::new(0));
        let sc = server_config();
        let port = solo_port(1_000_000.0); // a high-diff port
        let mut state = SessionState::new(clock.clone(), &sc, &port, "abcd1234".to_string());
        state.stratum_initialized = true;
        clock.advance_ms(61_000);
        let out = vardiff_check_now(&mut state, &sc, &port, &clock);
        let frame = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(
            frame.contains("mining.set_difficulty"),
            "expected a set_difficulty frame, got {frame}"
        );
        assert!(
            state.session_difficulty < 1_000_000.0,
            "session stayed at {}",
            state.session_difficulty
        );
    }

    #[test]
    fn silence_eases_a_quiet_session_on_the_wire() {
        let clock = Arc::new(TestClock::new(0));
        let (mut state, sc, port) = measured_session(&clock);
        // 400 s of silence: 29 arrivals over 700 s → target ≈ 6787, below
        // half of 16384, rounds UP on the power-of-two ladder to 8192.
        clock.advance_ms(400_000);
        let out = vardiff_check_now(&mut state, &sc, &port, &clock);
        let frame = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
        assert!(
            frame.contains("mining.set_difficulty"),
            "expected a set_difficulty frame, got {frame}"
        );
        assert_eq!(state.session_difficulty, 8192.0, "one step down");
        assert!(out
            .events
            .iter()
            .any(|e| matches!(e, SessionEvent::DifficultyChanged)));
    }

    /// Stale rejects at the session's usual cadence are arrivals, so the same
    /// 400 s that ease a silent session hold this one.
    #[test]
    fn stale_rejects_at_the_usual_cadence_hold_the_session() {
        let clock = Arc::new(TestClock::new(0));
        let (mut state, sc, port) = measured_session(&clock);
        state.authorization = Some(authorize_req(REGTEST_ADDR));
        let reg = empty_registry();
        let _ = apply_new_template(
            &mut state,
            &sc,
            &port,
            &reg,
            &MiningJobCache::new(),
            &Arc::new(template_for_regtest()),
            &solo_payouts_fixture(REGTEST_ADDR),
            false,
            clock.now_ms(),
        );
        let job_id = format!("{:x}", reg.peek_next_job_id() - 1);
        reg.cleanup(true, clock.now_ms()); // the job retires: a new block
        let nonces: Vec<String> = (0..40u32).map(|i| format!("{i:08x}")).collect();
        for nonce in &nonces {
            clock.advance_ms(10_000);
            let request = SubmitRequest {
                nonce_hex: nonce,
                ..submit_req(&job_id)
            };
            let out = handle_submit(&mut state, &reg, request, clock.now_ms());
            let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
            assert!(s.contains("\"stale\""), "expected a stale reject, got {s}");
        }
        let out = vardiff_check_now(&mut state, &sc, &port, &clock);
        assert!(
            out.outbound_frames.is_empty(),
            "a session sending stale shares at its cadence must hold"
        );
        assert_eq!(state.session_difficulty, 16384.0);
    }

    /// An unknown-job share is no arrival: forty of them at the usual cadence
    /// do not hold a silent session up.
    #[test]
    fn unknown_job_rejects_do_not_count_as_arrivals() {
        let clock = Arc::new(TestClock::new(0));
        let (mut state, sc, port) = measured_session(&clock);
        state.authorization = Some(authorize_req(REGTEST_ADDR));
        let reg = empty_registry();
        let job_ids: Vec<String> = (0..40).map(|i| format!("{i:x}")).collect();
        for job_id in &job_ids {
            clock.advance_ms(10_000);
            let out = handle_submit(&mut state, &reg, submit_req(job_id), clock.now_ms());
            let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
            assert!(
                s.contains("Job not found"),
                "expected an unknown-job reject, got {s}"
            );
        }
        let _ = vardiff_check_now(&mut state, &sc, &port, &clock);
        assert!(
            state.session_difficulty < 16384.0,
            "unknown-job rejects held the session at {}",
            state.session_difficulty
        );
    }

    /// A duplicate repeats an arrival already counted: resending one at the
    /// usual cadence must not hold a silent session up.
    #[test]
    fn duplicate_rejects_do_not_count_as_arrivals() {
        let clock = Arc::new(TestClock::new(0));
        let (mut state, sc, port) = measured_session(&clock);
        state.authorization = Some(authorize_req(REGTEST_ADDR));
        let reg = empty_registry();
        for i in 0..40 {
            clock.advance_ms(10_000);
            let out = handle_submit(&mut state, &reg, submit_req("1"), clock.now_ms());
            let s = std::str::from_utf8(&out.outbound_frames[0]).unwrap();
            let expected = if i == 0 {
                "Job not found"
            } else {
                "Duplicate share"
            };
            assert!(
                s.contains(expected),
                "submit #{i}: expected {expected}, got {s}"
            );
        }
        let _ = vardiff_check_now(&mut state, &sc, &port, &clock);
        assert!(
            state.session_difficulty < 16384.0,
            "duplicates held the session at {}",
            state.session_difficulty
        );
    }

    // ── apply_new_template ────────────────────────────────────────────

    #[test]
    fn new_template_after_init_clears_dedup_on_clean_jobs() {
        let port = solo_port(16384.0);
        let mut state = fresh_state(TestClock::new(0), &port);
        state.stratum_initialized = true;
        state.authorization = Some(authorize_req(REGTEST_ADDR));
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
        assert_regtest_notify_header(&out.outbound_frames[0]);
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
        assert_regtest_notify_header(&out.outbound_frames[0]);
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
