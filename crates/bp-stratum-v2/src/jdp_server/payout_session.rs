// SPDX-License-Identifier: AGPL-3.0-or-later

//! The ext 0x0003 side of one JDP connection: which payout distribution the
//! session is served, and when that is re-decided.
//!
//! The connection loop in the parent module handles the base protocol and
//! calls into [`PayoutSession`] at four points; everything that exists only
//! because of ext 0x0003 lives here.

use super::*;

/// What a session is being served, and why. Three outcomes rather than a
/// bool, because "served nothing" covers two states whose cures differ: a
/// build that failed and may fail again, and a mode that is not known YET and
/// resolves by itself once a mining session registers. Treating an unknown
/// mode as known would publish a wrong distribution.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SessionDistribution {
    /// A plan is on file, carrying the accounting it was BUILT for, so "is
    /// this still the right plan?" stays answerable. `PoolWide` means the
    /// pool-wide push is this miner's accounting (PPLNS); the tailored kinds
    /// carry their owner address.
    Served(DistributionAccounting),
    /// The mode is not known YET. Nothing is published, and the caller retries
    /// on the next inbound frame: the check is a map lookup, and the answer
    /// normally arrives right after the miner opens its channel.
    AwaitingMode,
    /// Nothing published because the build FAILED, or no distribution id was
    /// available. Retried on the session's own frames, but throttled
    /// ([`rebuild_due`]), because each retry runs the whole distribution build
    /// and a JDC sends frames continuously.
    Denied,
}

impl SessionDistribution {
    /// The accounting this session is being served, or `None` while it is
    /// served nothing.
    ///
    /// A plan on file is REFERENCEABLE: `distribution_acceptance` answers
    /// with it, and ext 0x0003/Grace Window keeps the immediately-previous one
    /// answerable too. So a plan that stops being right has to be dropped, not
    /// just superseded.
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
/// Below the publisher's 60 s default, which this backs up, and long enough
/// that a JDC's frame rate cannot turn it into a rebuild per frame.
const DENIED_REBUILD_INTERVAL_MS: u64 = 30_000;

/// Whether an inbound frame should make the pool re-decide what this session
/// is served, given the accounting its address is on right now.
///
/// An exhaustive `match`, so a state added later has to be classified:
///
/// - `AwaitingMode`: every frame. The mode lookup returns before anything is
///   built.
/// - `Denied`: throttled, because it runs the WHOLE distribution build. It
///   must retry at all because the publisher skips a tick whose fingerprint
///   is unchanged, so on a quiet window nothing else would wake the session.
/// - `Served`: only when the mode MOVED. A settlement re-decides through slot
///   invalidation (ext 0x0003/Implementation Notes), but
///   `cache_sync::reconcile_gate_modes` flips a live address between Solo and
///   Group-Solo on a group join or leave without a reconnect, and nothing
///   else would move the session off the plan for its old mode.
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
/// `AwaitingMode` is the NORMAL first answer for every JDC, which allocates
/// several seconds before its mining channel opens, so entering it is not
/// reported. STAYING there is: an address that never opens a mining session
/// is served nothing forever, which otherwise looks like a healthy session
/// that is not declaring.
///
/// The wait is timed and reported once, naming what an operator can act on:
/// the pool learns Solo from PPLNS from the PORT a miner connects on. The
/// recovery is reported too, with how long it took.
struct AwaitingModeWatch {
    /// When the current wait started. `None` = not waiting.
    since_ms: Option<u64>,
    /// Whether THIS wait has already been reported. Reset with the wait, so a
    /// session that flaps gets one line per episode, not one per frame.
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
/// `served`, `last_rebuild_ms` and `awaiting` move TOGETHER on every rebuild
/// (see [`republish_tailored`]): a missed stamp costs `Denied` its throttle,
/// a missed [`AwaitingModeWatch::observe`] costs the stuck-session warning its
/// state. `last_pool_wide_written` is the same plan seen from the wire side.
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

/// Rebuild this session's plan and record it, applying all three
/// post-conditions in one place.
///
/// It does NOT drop a plan the rebuild failed to replace. Only the
/// mode-moved caller does that: for the other callers the old entry is
/// either already settlement-invalidated or still the right one.
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
/// Reached only through [`republish_tailored`], from three callers: an
/// allocate; an ext 0x0003/Implementation Notes settlement, which invalidates
/// a tailored slot like the pool-wide one while the publisher only republishes
/// the latter; and the session's own frames, which retry an undecided or
/// refused build and answer a mode that moved.
///
/// It rebuilds from the mode gate every time, so it needs no reason for the
/// call.
#[allow(clippy::too_many_arguments)]
async fn rebuild_tailored_plan(
    hooks: &JdpServerHooks,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    writer: &mut NoiseTcpWriteHalf,
    session_id: u32,
    session_id_hex: &str,
    miner: &AddressId,
    // What this session is served RIGHT NOW. Compared against the rebuild, so
    // a plan that stops being right is dropped rather than superseded:
    // ext 0x0003/Grace Window keeps the immediately-previous entry of a slot
    // acceptable. The comparison lives here, not at a call site, because the
    // allocate path also republishes and clients allocate before nearly every
    // declare, so that is where a mode flip is usually observed.
    serving: &SessionDistribution,
    // The pool-wide distribution id this session was last WRITTEN, or `None`
    // if it holds something else (nothing yet, or a tailored push:
    // ext 0x0003/Payout Computation gives the client ONE current distribution).
    // Updated in place so the catch-up below knows whether to push.
    last_pool_wide_written: &mut Option<u64>,
) -> SessionDistribution {
    let (accounting, built) = match hooks.distribution_source.build_for_miner(miner).await {
        TailoredDistribution::Built { accounting, built } => (accounting, *built),
        // This miner rides the pool-wide distribution (PPLNS). Three things
        // have to happen together, or the session is stranded:
        //
        // 1. **Drop a tailored slot it may still hold.** `distribution_accep-
        //    tance` under `JdpSession` scope PREFERS that slot, so one left
        //    behind resolves every later pool-wide id as `Stale`.
        // 2. **Lift the denial**, or the acceptance answers `Unknown`.
        // 3. **Push the current distribution NOW**, unless the session already
        //    holds it. A session that was awaiting its mode may hold an id past
        //    the ext 0x0003/Grace Window, and a tailored one holds its own plan
        //    (ext 0x0003/Payout Computation). Only `stale-chain-tip` is a
        //    benign declare error; `stale-payout-distribution` ends the
        //    session. The publisher skips a tick whose fingerprint is
        //    unchanged, so waiting for it is not a recovery.
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
                // Already holding it: a session on the pool-wide stream gets
                // the publisher's pushes, so no re-send per frame.
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
        // Not known YET. Publish nothing and keep pool-wide denied: either
        // guess is a money error. The caller retries on the next inbound
        // frame, by which time the miner has usually opened its channel.
        TailoredDistribution::ModeUnknown => {
            // Read first: this arm runs on EVERY inbound frame while the mode
            // is undecided, and a write lock per frame would contend with the
            // mining side for nothing. Racing writers are harmless, the insert
            // is idempotent.
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
    // ext 0x0003/Payout Computation makes the LATEST push the one the client
    // uses, so a return to the pool-wide distribution needs a fresh push, even
    // of an id it has already seen.
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

    /// Each state gets its own answer: `AwaitingMode` rebuilds on every frame,
    /// `Denied` after the throttle, and a correctly served session never.
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
    /// it, checked for every pair in both directions.
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

    /// Only a served session has a plan on file to drop. Dropping matters
    /// because ext 0x0003/Grace Window keeps the immediately-previous entry
    /// acceptable, so a merely superseded plan is still declarable.
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

    /// A healthy JDC start must not warn: it allocates seconds before its
    /// mining channel opens, so `AwaitingMode` on the first frames is normal.
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
    /// many frames arrive, and so is its recovery.
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

    /// `Denied` is not counted as a wait for the mode: it has its own warning
    /// where the build fails, and "no miner has connected" would name the
    /// wrong cure for a session whose mode is known.
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
