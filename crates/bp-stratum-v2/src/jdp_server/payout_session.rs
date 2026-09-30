// SPDX-License-Identifier: AGPL-3.0-or-later

//! The ext 0x0003 side of one JDP connection: which payout distribution the
//! session is served, and when that is re-decided.
//!
//! The connection loop in the parent module handles the base protocol and
//! calls into [`PayoutSession`] at four points; everything that exists only
//! because of ext 0x0003 lives here.

use super::*;

/// What a session is being served, and why. Three outcomes rather than a
/// bool, because "served nothing" hides two states whose cures differ: a
/// build that failed and may fail again, and a mode that is not known YET and
/// resolves by itself the moment a mining session registers.
///
/// Collapsing them is what published a Solo distribution to every JDC that
/// allocated before its miner connected.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SessionDistribution {
    /// A plan is on file for this session, carrying the accounting it was
    /// BUILT for — which is what makes "is this still the right plan?"
    /// answerable later. `PoolWide` means the pool-wide push IS this miner's
    /// accounting (PPLNS); the tailored kinds carry their owner address, so
    /// nothing is lost by not holding one separately.
    ///
    /// One variant and not a tailored/pool-wide pair: they are the same
    /// concept — the accounting being served — and splitting them made every
    /// consumer re-join them, including one that had to synthesize a
    /// `DistributionAccounting::PoolWide` out of thin air to ask the shared
    /// question.
    Served(DistributionAccounting),
    /// The mode is not known YET. Nothing is published, and the caller retries
    /// on the next inbound frame — the check is a map lookup, so doing it per
    /// frame is free, and the answer normally arrives within milliseconds of
    /// the miner opening its channel.
    AwaitingMode,
    /// Nothing published because the build FAILED, or no distribution id was
    /// available. Retried on the session's own frames like `AwaitingMode`, but
    /// on a throttle ([`rebuild_due`]): unlike `AwaitingMode` this one runs the
    /// whole distribution build before it fails, and a JDC sends frames
    /// continuously, so retrying it unthrottled turns one failure into a
    /// rebuild per frame.
    ///
    /// Splitting this from `AwaitingMode` is the point of the type. They were
    /// briefly one variant, and that is precisely the collapse this enum was
    /// introduced to prevent — two states that look alike from outside and
    /// need different treatment.
    Denied,
}

impl SessionDistribution {
    /// The accounting this session is being served, or `None` while it is
    /// served nothing.
    ///
    /// The two "serving nothing" states are not merely the absence of a plan:
    /// a plan on file is REFERENCEABLE — `distribution_acceptance` answers
    /// with it, and ext 0x0003/Grace Window keeps the immediately-previous one
    /// answerable too. So when a plan stops being the right one it has to be
    /// dropped, not just superseded.
    fn accounting(&self) -> Option<&DistributionAccounting> {
        match self {
            Self::Served(accounting) => Some(accounting),
            Self::AwaitingMode | Self::Denied => None,
        }
    }
}

/// How long a session that was refused a distribution waits before the pool
/// tries to build it one again, on its own frames.
///
/// Below the publisher's 60 s default, because the publisher is the path this
/// backs up — and above anything a JDC's frame rate could turn into a rebuild
/// storm.
const DENIED_REBUILD_INTERVAL_MS: u64 = 30_000;

/// Whether an inbound frame should make the pool re-decide what this session
/// is served, given the accounting its address is on right now.
///
/// A `match`, and exhaustive, because the four states want four different
/// answers and a fifth added later must be classified rather than inherit
/// whichever one the `if` happened to be written around:
///
/// - `AwaitingMode` — every frame. The check is a mode lookup that returns
///   before anything is built, and the answer normally arrives within
///   milliseconds of the miner opening its channel.
/// - `Denied` — throttled, because this one runs the WHOLE distribution build
///   before it fails, and a JDC sends frames continuously. Retried at all
///   because the alternative was not retrying: the publisher's tick is the
///   only other path, and it skips a tick whose fingerprint is unchanged — on
///   a quiet window a session refused once stays refused with nothing left to
///   wake it.
/// - `Tailored` / `PoolWide` — only when the mode MOVED. These used to answer
///   `false` unconditionally, on the reasoning that a served session
///   re-decides when its slot is invalidated
///   (ext 0x0003/Implementation Notes). That holds for a settlement and for
///   nothing else:
///   `cache_sync::reconcile_gate_modes` flips a live address between Solo and
///   Group-Solo on a group join or leave, deliberately without a reconnect,
///   and until the pool next found a block the session kept being served the
///   plan for the mode it no longer had.
fn rebuild_due(
    served: &SessionDistribution,
    current_mode: Option<bp_common::StreamKind>,
    now_ms: u64,
    last_rebuild_ms: u64,
) -> bool {
    match served {
        SessionDistribution::AwaitingMode => true,
        SessionDistribution::Denied => {
            now_ms.saturating_sub(last_rebuild_ms) >= DENIED_REBUILD_INTERVAL_MS
        }
        // The one shared table, so a session is never served a plan the
        // mining side or the declare path would then refuse.
        SessionDistribution::Served(accounting) => {
            !crate::bridge::accounting_fits_mode(accounting, current_mode)
        }
    }
}

/// Makes "this session is still waiting for its mode" visible.
///
/// `AwaitingMode` is the NORMAL first answer for every JDC — it allocates ~8 s
/// before its mining channel opens, so warning on entry would fire once per
/// healthy start and mean nothing. What is not normal is STAYING there. An
/// address that never opens a mining session — a JDC pointed at the pool with
/// no miner behind it, or one whose miner mines somewhere else — waits
/// forever: it is denied the pool-wide distribution the whole time, publishes
/// nothing, and every trace of that is at `debug`. From outside it is
/// indistinguishable from a healthy session that happens not to be declaring,
/// which is the worst property a permanent refusal can have.
///
/// So the wait is timed and reported once, with the one thing an operator can
/// act on: the pool learns Solo from PPLNS from the PORT a miner connects on,
/// and until some miner opens a session for this address there is no answer to
/// be had. The recovery is reported too, so the log says how long it took
/// rather than trailing off.
struct AwaitingModeWatch {
    /// When the current wait started. `None` = not waiting.
    since_ms: Option<u64>,
    /// Whether THIS wait has already been reported. Reset with the wait, so a
    /// session that flaps gets one line per episode, not one per frame — the
    /// retry runs on every inbound frame.
    warned: bool,
}

impl AwaitingModeWatch {
    /// Comfortably past the ~8 s a healthy JDC needs, and under the
    /// publisher's 60 s tick so the per-frame retry is what trips it.
    const WARN_AFTER_MS: u64 = 30_000;

    fn new() -> Self {
        Self {
            since_ms: None,
            warned: false,
        }
    }

    /// Feed EVERY `served` transition through here, including the ones that
    /// resolve it.
    fn observe(
        &mut self,
        served: &SessionDistribution,
        session_id_hex: &str,
        miner: &AddressId,
        now: u64,
    ) {
        let SessionDistribution::AwaitingMode = served else {
            if self.warned {
                info!(
                    miner = miner.as_str(),
                    waited_ms = now.saturating_sub(self.since_ms.unwrap_or(now)),
                    "jdp {session_id_hex} payout mode known now — serving it again"
                );
            }
            self.since_ms = None;
            self.warned = false;
            return;
        };
        let since = *self.since_ms.get_or_insert(now);
        let waited_ms = now.saturating_sub(since);
        if !self.warned && waited_ms >= Self::WARN_AFTER_MS {
            self.warned = true;
            warn!(
                miner = miner.as_str(),
                waited_ms,
                "jdp {session_id_hex} has no known payout mode — it is served no payout \
                 distribution and cannot declare. The pool learns Solo from PPLNS off the port \
                 a miner connects on, so this clears only once a miner opens a mining session \
                 for this address"
            );
        }
    }
}

/// Everything a session's payout plan is tracked with.
///
/// A struct because three of the four move TOGETHER on every rebuild, and
/// nothing but a convention said so: each of the three call sites set
/// `served`, stamped `last_rebuild_ms` and fed [`AwaitingModeWatch::observe`]
/// by hand, at one of them with thirty lines in between. Forgetting the stamp
/// costs `Denied` its throttle — a whole distribution build per inbound frame;
/// forgetting the observe costs the stuck-session warning its state machine,
/// which is exactly what that type's doc demands ("Feed EVERY `served`
/// transition through here"). Neither would have failed to compile.
///
/// `last_pool_wide_written` rides along because it is the same session's plan
/// seen from the wire side, and [`republish_tailored`] already had to be
/// handed it.
struct SessionPlan {
    /// What this session is being served, and why.
    served: SessionDistribution,
    /// When the pool last TRIED to build this session a plan, whatever came
    /// of it — [`rebuild_due`]'s throttle for the refused case.
    last_rebuild_ms: u64,
    /// Makes a session stuck without a known payout mode visible.
    awaiting: AwaitingModeWatch,
    /// The pool-wide distribution id last written to this client, so a session
    /// arriving on that stream can be told whether it is behind. `None` while
    /// it holds something else (nothing yet, or a tailored push).
    last_pool_wide_written: Option<u64>,
}

impl SessionPlan {
    fn new() -> Self {
        Self {
            served: SessionDistribution::AwaitingMode,
            last_rebuild_ms: 0,
            awaiting: AwaitingModeWatch::new(),
            last_pool_wide_written: None,
        }
    }
}

/// Rebuild this session's plan and record it — the three post-conditions in
/// one place, so a fourth call site cannot half-apply them.
///
/// What it deliberately does NOT do is drop a plan the rebuild failed to
/// replace. Only the mode-moved caller does that, and only it can: the
/// condition is "was serving a plan, now serves none", which the other two
/// callers reach under circumstances where the old entry is either already
/// settlement-invalidated or still the right one.
async fn republish_tailored(
    hooks: &JdpServerHooks,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    writer: &mut NoiseTcpWriteHalf,
    session_id: u32,
    session_id_hex: &str,
    miner: &AddressId,
    plan: &mut SessionPlan,
) {
    plan.served = rebuild_tailored_plan(
        hooks,
        bridge,
        writer,
        session_id,
        session_id_hex,
        miner,
        &plan.served,
        &mut plan.last_pool_wide_written,
    )
    .await;
    let now = SystemClock.now_ms();
    plan.last_rebuild_ms = now;
    plan.awaiting
        .observe(&plan.served, session_id_hex, miner, now);
}

/// Build and push a fresh tailored distribution for `miner` on this session.
///
/// Reached only through [`republish_tailored`], whose three callers share
/// this one implementation: the first allocate; a
/// ext 0x0003/Implementation Notes settlement, which invalidates a tailored
/// slot exactly like the pool-wide one while the publisher only ever
/// republishes the latter; and the session's own frames, which retry an
/// undecided or refused build and answer a mode that moved.
///
/// It rebuilds from the mode gate every time, so it needs to be told nothing
/// about WHY it was called. What the mode-moved caller has to do on top is
/// drop the plan on file first — see [`SessionDistribution::accounting`].
#[allow(clippy::too_many_arguments)]
async fn rebuild_tailored_plan(
    hooks: &JdpServerHooks,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    writer: &mut NoiseTcpWriteHalf,
    session_id: u32,
    session_id_hex: &str,
    miner: &AddressId,
    // What this session is being served RIGHT NOW. Compared against what the
    // rebuild produces, so a plan that stops being the right one is dropped
    // rather than merely superseded — ext 0x0003/Grace Window keeps the
    // immediately-previous entry of a slot acceptable, which is exactly long
    // enough to declare against once more.
    //
    // The comparison lives here and not at a call site because there are
    // three call sites and only one of them ever knew a mode had moved. The
    // allocate path republishes unconditionally on every token request, and an
    // SRI jd-client allocates before nearly every declare — so a flip observed
    // on an allocate frame slid the old-mode plan into the grace slot with
    // nothing left to notice.
    serving: &SessionDistribution,
    // The pool-wide distribution id this session was last WRITTEN, or `None`
    // if what it is holding is not a pool-wide one (none was ever pushed, or a
    // tailored push has replaced it since — ext 0x0003/Payout Computation
    // gives the client ONE current distribution, not one per stream). Updated
    // in place, so the catch-up below can tell "already has it" from "is
    // holding something else".
    last_pool_wide_written: &mut Option<u64>,
) -> SessionDistribution {
    let (accounting, built) = match hooks.distribution_source.build_for_miner(miner).await {
        TailoredDistribution::Built { accounting, built } => (accounting, *built),
        // This miner rides the pool-wide distribution — either it always did
        // (its mode simply became known) or it changed under us and is PPLNS
        // now. Three things have to happen together, and leaving any one out
        // strands the session:
        //
        // 1. **Drop a tailored slot it may still hold.** `distribution_accep-
        //    tance` under `JdpSession` scope PREFERS that slot, so one left
        //    behind answers for every pool-wide id pushed afterwards — and
        //    every one of them resolves `Stale`.
        // 2. **Lift the denial**, or the acceptance answers `Unknown`.
        // 3. **Push the current distribution NOW**, unless the session
        //    demonstrably already holds it. Everything that reaches this arm
        //    from somewhere other than the pool-wide stream is holding
        //    something else: a session that was awaiting its mode was excluded
        //    from the pool-wide pushes and holds an id that has since fallen
        //    out of the ext 0x0003/Grace Window, and a tailored one
        //    holds its own plan, which ext 0x0003/Payout Computation makes
        //    authoritative for it. Only `stale-chain-tip` is a benign declare
        //    error for an SRI jd-client; `stale-payout-distribution` ends the
        //    session. Waiting for the next publish is not a recovery — the
        //    publisher skips a tick whose fingerprint is unchanged, so on a
        //    quiet window there is no next publish.
        TailoredDistribution::PoolWide => {
            let current = {
                let mut guard = bridge.write().expect("bridge RwLock poisoned");
                let had_tailored = guard.clear_tailored(session_id);
                guard.allow_pool_wide(session_id);
                if had_tailored {
                    debug!(
                        "jdp {session_id_hex} tailored slot dropped — this miner is on the \
                         pool-wide distribution now"
                    );
                }
                guard.current_pool_wide()
            };
            match current {
                // Already holding it — a session that has been on the
                // pool-wide stream all along receives its pushes like every
                // other, and re-sending the same id per frame would be
                // traffic for its own sake.
                Some(entry) if *last_pool_wide_written == Some(entry.distribution_id) => {}
                Some(entry) => {
                    let wire = wire_from_entry(&entry);
                    if let Err(err) = write_jdp_outbound_frames(
                        writer,
                        vec![JdpOutboundFrame::SetPayoutDistribution(wire)],
                    )
                    .await
                    {
                        warn!("jdp {session_id_hex} pool-wide catch-up write: {err:?}");
                    } else {
                        *last_pool_wide_written = Some(entry.distribution_id);
                        debug!(
                            distribution_id = entry.distribution_id,
                            "jdp {session_id_hex} pool-wide catch-up pushed"
                        );
                    }
                }
                // Nothing published yet at all. The session is allowed on the
                // pool-wide stream, so the publisher's first push reaches it.
                None => {
                    debug!("jdp {session_id_hex} on the pool-wide distribution, none published yet")
                }
            }
            return SessionDistribution::Served(DistributionAccounting::PoolWide);
        }
        // Not known YET. Publish nothing and keep pool-wide denied: both
        // guesses are a money error, in opposite directions. The caller
        // retries on the next inbound frame, by which time the miner has
        // usually opened its channel and the port has spoken.
        TailoredDistribution::ModeUnknown => {
            // Read first. This arm runs on EVERY inbound frame while the mode
            // is undecided, and after the first one there is nothing to write
            // — a write lock per frame would serialize the registry against
            // the mining side to re-insert an id that is already in the set.
            // Racing readers both deciding to write is harmless: the write is
            // an idempotent insert.
            let already_denied = bridge
                .read()
                .expect("bridge RwLock poisoned")
                .is_pool_wide_denied(session_id);
            if !already_denied {
                bridge
                    .write()
                    .expect("bridge RwLock poisoned")
                    .deny_pool_wide(session_id);
            }
            return SessionDistribution::AwaitingMode;
        }
        TailoredDistribution::Unavailable => {
            warn!(
                miner = miner.as_str(),
                "jdp {session_id_hex} tailored republish unavailable — \
                 refusing to fall back to the pool-wide distribution"
            );
            bridge
                .write()
                .expect("bridge RwLock poisoned")
                .deny_pool_wide(session_id);
            return SessionDistribution::Denied;
        }
    };
    let Some(distribution_id) = hooks.distribution_source.next_distribution_id().await else {
        warn!(
            "jdp {session_id_hex} tailored republish skipped — \
             distribution-id allocator unavailable"
        );
        bridge
            .write()
            .expect("bridge RwLock poisoned")
            .deny_pool_wide(session_id);
        return SessionDistribution::Denied;
    };
    let entry = PayoutDistributionEntry {
        distribution_id,
        built,
        accounting: accounting.clone(),
        jdp_session_id: Some(session_id),
        published_at_ms: SystemClock.now_ms(),
    };
    let wire = wire_from_entry(&entry);
    {
        let mut guard = bridge.write().expect("bridge RwLock poisoned");
        // Same lock as the publish, so there is no window in which the session
        // has neither plan. Only when the accounting actually changed: a
        // rebuild for the SAME accounting (an ext 0x0003/Implementation Notes
        // settlement, a fresh allocate) legitimately supersedes, and
        // ext 0x0003/Grace Window's grace entry is what a declaration already
        // in flight resolves against.
        if serving.accounting().is_some_and(|was| *was != accounting) {
            let dropped = guard.clear_tailored(session_id);
            info!(
                miner = miner.as_str(),
                was = ?serving.accounting(),
                now = ?accounting,
                dropped,
                "jdp {session_id_hex} payout mode moved — the plan built for the old one is \
                 dropped, not superseded"
            );
        }
        guard.publish_tailored(session_id, entry);
        guard.allow_pool_wide(session_id);
    }
    if let Err(err) =
        write_jdp_outbound_frames(writer, vec![JdpOutboundFrame::SetPayoutDistribution(wire)]).await
    {
        warn!("jdp {session_id_hex} tailored republish write: {err:?}");
    }
    // Whatever pool-wide id this session was holding, it is not holding it any
    // more — ext 0x0003/Payout Computation makes the LATEST push the one it
    // must use. If it ever comes back to the pool-wide distribution it has to
    // be pushed one again, even an id it has already seen.
    *last_pool_wide_written = None;
    debug!(distribution_id, "jdp {session_id_hex} tailored republished");
    SessionDistribution::Served(accounting)
}

/// A frame's ext 0x0003 context, read before the handler runs: the handler
/// may change the negotiated set, and the mode lookup is async.
pub(super) struct FrameProbe {
    negotiated_before: bool,
    requests_extensions: bool,
    current_mode: Option<bp_common::StreamKind>,
}

/// Per-connection ext 0x0003 state: the plan this session is served and the
/// miner it belongs to, learned from its first allocate.
pub(super) struct PayoutSession {
    session_id: u32,
    session_id_hex: String,
    plan: SessionPlan,
    identity: Option<AddressId>,
}

/// Whether this session negotiated ext 0x0003. The async entry points take
/// this instead of the session state, which is not `Sync`.
pub(super) fn negotiated(state: &JdpSessionState) -> bool {
    state
        .negotiated_extensions
        .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
}

impl PayoutSession {
    pub(super) fn new(session_id: u32, session_id_hex: &str) -> Self {
        Self {
            session_id,
            session_id_hex: session_id_hex.to_string(),
            plan: SessionPlan::new(),
            identity: None,
        }
    }

    /// Extensions whose TLVs an inbound frame may carry, or `None` for an
    /// ext 0x0003 frame, which only ever flows JDS to JDC and is dropped.
    ///
    /// A `DeclareMiningJob` is parsed with the 0x0003 TLV even when it was not
    /// negotiated, so the declare path can see and refuse it.
    pub(super) fn tlv_extensions(
        &self,
        state: &JdpSessionState,
        ext_type: u16,
        msg_type: u8,
    ) -> Option<Vec<u16>> {
        if ext_type == SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS {
            warn!(
                "jdp {} unexpected inbound ext-0x0003 frame — ignoring",
                self.session_id_hex
            );
            return None;
        }
        let mut extensions: Vec<u16> = state.negotiated_extensions.iter().copied().collect();
        if msg_type == MESSAGE_TYPE_DECLARE_MINING_JOB
            && !extensions.contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS)
        {
            extensions.push(SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS);
        }
        Some(extensions)
    }

    /// Copy the `distribution_id` TLV onto a `DeclareMiningJob`.
    pub(super) fn attach_distribution_id(
        inbound: &mut InboundJdpFrame,
        tlvs: Option<&[stratum_core::parsers_sv2::Tlv]>,
    ) {
        if let InboundJdpFrame::DeclareMiningJob(ref mut input) = inbound {
            input.distribution_id = tlvs.and_then(parse_distribution_id_tlv);
        }
    }

    pub(super) async fn probe(
        &self,
        negotiated_before: bool,
        inbound: &InboundJdpFrame,
        hooks: &JdpServerHooks,
    ) -> FrameProbe {
        // The mode of the miner this session's own plan belongs to. The
        // declare path looks up the mode of its token's address separately.
        let current_mode = match (&self.identity, negotiated_before) {
            (Some(miner), true) => hooks.distribution_source.current_mode(miner).await,
            _ => None,
        };
        FrameProbe {
            negotiated_before,
            requests_extensions: matches!(inbound, InboundJdpFrame::RequestExtensions(_)),
            current_mode,
        }
    }

    /// A new pool-wide distribution was published. Pushes it to a session on
    /// the pool-wide stream; a tailored session instead gets its own plan
    /// rebuilt if the publish invalidated it. `Err` means the write failed and
    /// the connection is done.
    pub(super) async fn on_publish(
        &mut self,
        negotiated: bool,
        hooks: &JdpServerHooks,
        bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
        writer: &mut NoiseTcpWriteHalf,
    ) -> Result<(), WriteError> {
        if !negotiated {
            return Ok(());
        }
        if self.identity.is_some()
            && !matches!(
                self.plan.served,
                SessionDistribution::Served(DistributionAccounting::PoolWide)
            )
        {
            let still_current = bridge
                .read()
                .expect("bridge RwLock poisoned")
                .current_tailored(self.session_id)
                .is_some();
            if still_current {
                return Ok(());
            }
            if let Some(miner) = self.identity.clone() {
                self.republish(hooks, bridge, writer, &miner).await;
            }
            return Ok(());
        }
        let current = bridge
            .read()
            .expect("bridge RwLock poisoned")
            .current_pool_wide();
        if let Some(entry) = current {
            let frame = JdpOutboundFrame::SetPayoutDistribution(wire_from_entry(&entry));
            if let Err(err) = write_jdp_outbound_frames(writer, vec![frame]).await {
                warn!(
                    "jdp {} distribution push write: {err:?}",
                    self.session_id_hex
                );
                return Err(err);
            }
            self.plan.last_pool_wide_written = Some(entry.distribution_id);
        }
        Ok(())
    }

    /// The frame just negotiated ext 0x0003: the current distribution goes out
    /// in the same write as `RequestExtensions.Success`, so it is the first
    /// message after it (ext 0x0003/SetPayoutDistribution).
    pub(super) fn append_first_push(
        &mut self,
        state: &JdpSessionState,
        bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
        probe: &FrameProbe,
        outcome: &mut JdpHandlerOutcome,
    ) {
        if !probe.requests_extensions || probe.negotiated_before || !negotiated(state) {
            return;
        }
        let current = bridge
            .read()
            .expect("bridge RwLock poisoned")
            .current_pool_wide();
        match current {
            Some(entry) => {
                self.plan.last_pool_wide_written = Some(entry.distribution_id);
                outcome
                    .outbound
                    .push(JdpOutboundFrame::SetPayoutDistribution(wire_from_entry(
                        &entry,
                    )));
            }
            None => warn!(
                "jdp {} 0x0003 negotiated but no pool-wide distribution available for the \
                 first push",
                self.session_id_hex
            ),
        }
    }

    /// After a frame's answer is written: learn the miner from an allocate,
    /// and re-decide the plan when it is undecided, refused, or built for a
    /// mode the miner is no longer on.
    pub(super) async fn after_frame(
        &mut self,
        negotiated: bool,
        hooks: &JdpServerHooks,
        bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
        writer: &mut NoiseTcpWriteHalf,
        events: &[JdpSessionEvent],
        probe: &FrameProbe,
    ) {
        if !negotiated {
            return;
        }
        for event in events {
            let JdpSessionEvent::TokenAllocated { miner_address, .. } = event else {
                continue;
            };
            self.identity = Some(miner_address.clone());
            self.republish(hooks, bridge, writer, miner_address).await;
        }

        let Some(miner) = self.identity.clone() else {
            return;
        };
        if !rebuild_due(
            &self.plan.served,
            probe.current_mode,
            SystemClock.now_ms(),
            self.plan.last_rebuild_ms,
        ) {
            return;
        }
        let was = self.plan.served.clone();
        self.republish(hooks, bridge, writer, &miner).await;
        // Due while serving a plan means the mode moved. If no plan could be
        // built for the new mode, the old one pays the wrong miners: drop it.
        if was.accounting().is_some() && self.plan.served.accounting().is_none() {
            let dropped = bridge
                .write()
                .expect("bridge RwLock poisoned")
                .clear_tailored(self.session_id);
            warn!(
                miner = miner.as_str(),
                was = ?was.accounting(),
                current_mode = ?probe.current_mode,
                dropped,
                "jdp {} payout mode moved but no plan could be built for the new one — \
                 dropping the old plan and serving nothing rather than a coinbase paying the \
                 wrong miners",
                self.session_id_hex
            );
        }
    }

    async fn republish(
        &mut self,
        hooks: &JdpServerHooks,
        bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
        writer: &mut NoiseTcpWriteHalf,
        miner: &AddressId,
    ) {
        republish_tailored(
            hooks,
            bridge,
            writer,
            self.session_id,
            &self.session_id_hex,
            miner,
            &mut self.plan,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    /// The four states get four answers, and the two that rebuild get them for
    /// different reasons. Without the `Denied` arm a session refused once has
    /// only the publisher's tick left — and that tick is skipped whenever the
    /// fingerprint is unchanged, so on a quiet window nothing wakes it at all.
    #[test]
    fn only_the_states_that_have_something_to_gain_rebuild_on_a_frame() {
        let miner = AddressId::new(ADDR.to_string()).unwrap();
        let solo = Some(bp_common::StreamKind::Solo);
        // Undecided: every frame, the check returns before anything is built.
        assert!(rebuild_due(&SessionDistribution::AwaitingMode, solo, 0, 0));
        assert!(rebuild_due(&SessionDistribution::AwaitingMode, solo, 1, 0));

        // Refused: not on the next frame, but not never either.
        assert!(!rebuild_due(
            &SessionDistribution::Denied,
            solo,
            1_000,
            1_000
        ));
        assert!(!rebuild_due(
            &SessionDistribution::Denied,
            solo,
            1_000 + DENIED_REBUILD_INTERVAL_MS - 1,
            1_000
        ));
        assert!(rebuild_due(
            &SessionDistribution::Denied,
            solo,
            1_000 + DENIED_REBUILD_INTERVAL_MS,
            1_000
        ));

        // Being served the plan its mode calls for: its own traffic decides
        // nothing, however long it keeps sending.
        for (served, mode) in [
            (
                SessionDistribution::Served(DistributionAccounting::Solo(miner.clone())),
                bp_common::StreamKind::Solo,
            ),
            (
                SessionDistribution::Served(DistributionAccounting::GroupSolo(miner.clone())),
                bp_common::StreamKind::GroupSolo,
            ),
            (
                SessionDistribution::Served(DistributionAccounting::PoolWide),
                bp_common::StreamKind::Pplns,
            ),
        ] {
            assert!(
                !rebuild_due(&served, Some(mode), u64::MAX, 0),
                "{served:?} on {mode:?}"
            );
        }
    }

    /// The mode moving under a served session is the ONE thing that re-opens
    /// it — every pair that is not the one it was built for, in both
    /// directions, so a fix that only caught the group-join direction fails
    /// here.
    #[test]
    fn a_served_session_rebuilds_exactly_when_its_mode_moved() {
        use bp_common::StreamKind as Sk;
        let miner = AddressId::new(ADDR.to_string()).unwrap();
        let served_for = |accounting: DistributionAccounting| match accounting {
            DistributionAccounting::PoolWide => {
                SessionDistribution::Served(DistributionAccounting::PoolWide)
            }
            tailored => SessionDistribution::Served(tailored),
        };
        for (accounting, built_for) in [
            (DistributionAccounting::Solo(miner.clone()), Sk::Solo),
            (
                DistributionAccounting::GroupSolo(miner.clone()),
                Sk::GroupSolo,
            ),
            (DistributionAccounting::PoolWide, Sk::Pplns),
        ] {
            let served = served_for(accounting);
            for now in [Sk::Solo, Sk::GroupSolo, Sk::Pplns, Sk::Blockparty] {
                assert_eq!(
                    rebuild_due(&served, Some(now), u64::MAX, 0),
                    now != built_for,
                    "{served:?} was built for {built_for:?}, gate now says {now:?}"
                );
            }
            // …and "the gate has never heard of this address" is not a move.
            // A miner behind a JDC that drops for a moment must not cost the
            // session the plan it is correctly being served.
            assert!(
                !rebuild_due(&served, None, u64::MAX, 0),
                "{served:?} must survive an unknown mode"
            );
        }
    }

    /// Only a served session has a plan on file to drop — and it is the
    /// dropping that matters: ext 0x0003/Grace Window keeps the
    /// immediately-previous entry acceptable, so a plan merely superseded is
    /// still declarable against.
    #[test]
    fn only_a_served_session_has_a_plan_to_drop() {
        let miner = AddressId::new(ADDR.to_string()).unwrap();
        for accounting in [
            DistributionAccounting::PoolWide,
            DistributionAccounting::Solo(miner.clone()),
            DistributionAccounting::GroupSolo(miner),
        ] {
            assert_eq!(
                SessionDistribution::Served(accounting.clone()).accounting(),
                Some(&accounting)
            );
        }
        assert_eq!(SessionDistribution::AwaitingMode.accounting(), None);
        assert_eq!(SessionDistribution::Denied.accounting(), None);
    }

    /// A healthy JDC start must not warn. It allocates ~8 s before its mining
    /// channel opens, so `AwaitingMode` on the first frames is the normal
    /// path — a line there would fire once per JDC and train the operator to
    /// ignore the one that matters.
    #[test]
    fn a_short_wait_for_the_mode_is_not_reported() {
        let mut w = AwaitingModeWatch::new();
        let miner = AddressId::new(ADDR.to_string()).unwrap();
        for t in [0, 3_000, 8_000] {
            w.observe(&SessionDistribution::AwaitingMode, "jdp-test", &miner, t);
        }
        assert!(!w.warned, "8 s is the measured normal, not an anomaly");
        w.observe(
            &SessionDistribution::Served(DistributionAccounting::Solo(miner.clone())),
            "jdp-test",
            &miner,
            8_100,
        );
        assert_eq!(w.since_ms, None, "a resolved wait must reset");
    }

    /// A wait that outlasts the threshold is reported exactly once, however
    /// many frames arrive — the retry runs on EVERY inbound frame, so a line
    /// per observation would be a line per frame.
    #[test]
    fn a_stuck_session_is_reported_once_and_its_recovery_too() {
        let mut w = AwaitingModeWatch::new();
        let miner = AddressId::new(ADDR.to_string()).unwrap();
        w.observe(
            &SessionDistribution::AwaitingMode,
            "jdp-test",
            &miner,
            1_000,
        );
        assert!(!w.warned);
        w.observe(
            &SessionDistribution::AwaitingMode,
            "jdp-test",
            &miner,
            1_000 + AwaitingModeWatch::WARN_AFTER_MS,
        );
        assert!(w.warned, "the threshold must trip it");
        assert_eq!(w.since_ms, Some(1_000), "the wait's start must not move");

        // Recovery clears BOTH, so a second episode on the same connection is
        // reported again instead of being swallowed by the first one's flag.
        w.observe(
            &SessionDistribution::Served(DistributionAccounting::PoolWide),
            "jdp-test",
            &miner,
            999_000,
        );
        assert!(!w.warned);
        assert_eq!(w.since_ms, None);
        w.observe(
            &SessionDistribution::AwaitingMode,
            "jdp-test",
            &miner,
            999_500,
        );
        assert_eq!(
            w.since_ms,
            Some(999_500),
            "a new episode starts its own clock"
        );
    }

    /// `Denied` is not `AwaitingMode`. It has its own warning at the point it
    /// happens (the build failed, and it says why); counting it as a wait for
    /// the mode would report the wrong cure — "no miner has connected for this
    /// address" — for a session whose mode is perfectly well known.
    #[test]
    fn a_denied_session_is_not_counted_as_awaiting_its_mode() {
        let mut w = AwaitingModeWatch::new();
        let miner = AddressId::new(ADDR.to_string()).unwrap();
        for t in [0, 60_000, 600_000] {
            w.observe(&SessionDistribution::Denied, "jdp-test", &miner, t);
        }
        assert!(!w.warned);
        assert_eq!(w.since_ms, None);
    }
}
