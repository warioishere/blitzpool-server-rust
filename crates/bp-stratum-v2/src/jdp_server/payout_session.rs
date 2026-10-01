// SPDX-License-Identifier: AGPL-3.0-or-later

//! The ext 0x0003 side of one JDP connection: which payout distribution the
//! session is served, and when that is re-decided. The connection loop calls
//! into [`PayoutSession`].

use super::*;

/// What a session is being served. "Served nothing" is split in two because
/// the cures differ: a failed build is retried throttled, an unknown mode
/// resolves once a mining session registers.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SessionDistribution {
    /// A plan is on file, tagged with the accounting it was built for.
    Served(DistributionAccounting),
    /// The mode is not known yet; nothing published, retried on every frame.
    AwaitingMode,
    /// The build failed or no distribution id was available; retried
    /// throttled ([`rebuild_due`]).
    Denied,
}

impl SessionDistribution {
    /// The accounting served, or `None`. A plan that stops being right must be
    /// dropped, not superseded: ext 0x0003/Grace Window keeps the previous one
    /// acceptable.
    fn accounting(&self) -> Option<&DistributionAccounting> {
        match self {
            Self::Served(accounting) => Some(accounting),
            Self::AwaitingMode | Self::Denied => None,
        }
    }
}

/// Retry interval for a `Denied` session: below the publisher's 60 s tick, and
/// long enough that a JDC's frame rate cannot force a build per frame.
const DENIED_REBUILD_INTERVAL_MS: u64 = 30_000;

/// Whether an inbound frame should re-decide what this session is served.
/// `Denied` must retry here: the publisher skips a tick whose fingerprint is
/// unchanged. `Served` rebuilds only when the mode moved: a group join or
/// leave flips a live address between Solo and Group-Solo without a reconnect.
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
        // Shared table, so the mining side and declare path agree.
        SessionDistribution::Served(accounting) => {
            !crate::bridge::accounting_fits_mode(accounting, current_mode)
        }
    }
}

/// Reports a session stuck in `AwaitingMode` once per episode, and its
/// recovery. A short wait is normal: a JDC allocates before its mining
/// channel opens.
struct AwaitingModeWatch {
    /// When the current wait started. `None` = not waiting.
    since_ms: Option<u64>,
    /// Whether this wait has been reported; reset with the wait.
    warned: bool,
}

impl AwaitingModeWatch {
    /// Past the ~8 s a healthy JDC needs, under the publisher's 60 s tick.
    const WARN_AFTER_MS: u64 = 30_000;

    fn new() -> Self {
        Self {
            since_ms: None,
            warned: false,
        }
    }

    /// Feed every `served` transition through here, resolving ones included.
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

/// A session's payout plan. `served`, `last_rebuild_ms` and `awaiting` move
/// together on every rebuild, via [`republish_tailored`].
struct SessionPlan {
    served: SessionDistribution,
    /// When a build was last attempted; [`rebuild_due`]'s throttle.
    last_rebuild_ms: u64,
    awaiting: AwaitingModeWatch,
    /// The pool-wide distribution id last written to this client; `None` while
    /// it holds nothing or a tailored push.
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

/// Rebuild and record this session's plan. Does not drop a plan the rebuild
/// failed to replace; only the mode-moved caller needs that.
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

/// Build and push a fresh distribution for `miner` from the mode gate. Only
/// reached through [`republish_tailored`].
#[allow(clippy::too_many_arguments)]
async fn rebuild_tailored_plan(
    hooks: &JdpServerHooks,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    writer: &mut NoiseTcpWriteHalf,
    session_id: u32,
    session_id_hex: &str,
    miner: &AddressId,
    // Current plan; a changed accounting drops it (ext 0x0003/Grace Window).
    serving: &SessionDistribution,
    // Updated in place so the pool-wide catch-up knows whether to push.
    last_pool_wide_written: &mut Option<u64>,
) -> SessionDistribution {
    let (accounting, built) = match hooks.distribution_source.build_for_miner(miner).await {
        TailoredDistribution::Built { accounting, built } => (accounting, *built),
        // Pool-wide (PPLNS). All three or the session is stranded: drop a
        // leftover tailored slot (acceptance prefers it, so pool-wide ids
        // resolve `Stale`), lift the denial, and push the current distribution
        // now; `stale-payout-distribution` would end the session.
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
                // Already holding it; the publisher keeps it current.
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
                // The publisher's first push will reach it.
                None => {
                    debug!("jdp {session_id_hex} on the pool-wide distribution, none published yet")
                }
            }
            return SessionDistribution::Served(DistributionAccounting::PoolWide);
        }
        // Unknown mode: publish nothing and keep pool-wide denied; either
        // guess is a money error.
        TailoredDistribution::ModeUnknown => {
            // Read lock first: this runs on every frame while undecided.
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
        // Drop under the publish lock, and only on a changed accounting: a
        // same-accounting rebuild supersedes and keeps ext 0x0003/Grace Window.
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
    // The client uses the latest push (ext 0x0003/Payout Computation), so a
    // return to pool-wide needs a fresh push.
    *last_pool_wide_written = None;
    debug!(distribution_id, "jdp {session_id_hex} tailored republished");
    SessionDistribution::Served(accounting)
}

/// A frame's ext 0x0003 context, read before the handler can change it.
pub(super) struct FrameProbe {
    negotiated_before: bool,
    requests_extensions: bool,
    current_mode: Option<bp_common::StreamKind>,
}

/// Per-connection ext 0x0003 state; the miner is learned from the first allocate.
pub(super) struct PayoutSession {
    session_id: u32,
    session_id_hex: String,
    plan: SessionPlan,
    identity: Option<AddressId>,
}

/// Whether this session negotiated ext 0x0003 (the session state is not `Sync`).
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

    /// Extensions whose TLVs an inbound frame may carry; `None` drops an
    /// inbound ext 0x0003 frame. `DeclareMiningJob` always parses the 0x0003
    /// TLV so the declare path can refuse it when not negotiated.
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
        // The plan owner's mode; the declare path looks up its token's own.
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

    /// A pool-wide publish: push it, or rebuild an invalidated tailored plan.
    /// `Err` means the write failed and the connection is done.
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

    /// On negotiation, the current distribution is the first message after
    /// `RequestExtensions.Success` (ext 0x0003/SetPayoutDistribution).
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

    /// After a frame: learn the miner from an allocate and re-decide the plan
    /// when `rebuild_due`.
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
        // Mode moved and no new plan: the old one pays the wrong miners.
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
        assert!(rebuild_due(&SessionDistribution::AwaitingMode, solo, 0, 0));
        assert!(rebuild_due(&SessionDistribution::AwaitingMode, solo, 1, 0));

        // Denied: only after the throttle.
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

        // Served the right plan: never.
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

    /// A served session rebuilds exactly when its mode moved, for every pair.
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
            // An unknown mode (miner briefly gone) is not a move.
            assert!(
                !rebuild_due(&served, None, u64::MAX, 0),
                "{served:?} must survive an unknown mode"
            );
        }
    }

    /// Only a served session has a plan on file to drop.
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

    /// A healthy JDC start (`AwaitingMode` for a few seconds) does not warn.
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

    /// A stuck wait is reported once, its recovery too, and a new episode again.
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

        // Recovery clears both fields, so the next episode is reported again.
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

    /// `Denied` is not counted as awaiting the mode; it warns where the build fails.
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
