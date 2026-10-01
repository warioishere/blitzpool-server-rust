// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production coinbase payout resolver: gives SV1 and SV2 the per-mode coinbase
//! distribution at every template broadcast, so the on-chain coinbase pays what
//! the address's payout mode owes. Also the JDP ext 0x0003 distribution source.

use std::sync::Arc;

use async_trait::async_trait;
use bp_blockparty::CoinbaseDistributionEntry;
use bp_blockparty_engine::BlockpartyApi;
use bp_common::{AddressId, MiningMode, Sats};
use bp_group_solo_engine::engine::GroupSoloEngine;
// Re-exported so the wiring keeps one import path for the solo split.
pub(crate) use bp_mining_job::SoloFeeConfig;
use bp_mining_job::{solo_payouts, PayoutEntry, ResolvedPayouts};
use bp_pplns_engine::engine::PplnsEngine;
use bp_stratum_v2::bridge::DistributionAccounting;
use bp_stratum_v2::jdp_server::TailoredDistribution;
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::engines::BlitzpoolModeGate;

/// The production `PayoutResolver` for SV1 and SV2.
#[derive(Clone)]
pub(crate) struct ProductionPayoutResolver {
    mode_gate: Arc<BlitzpoolModeGate>,
    pplns: Option<PplnsEngine>,
    group_solo: GroupSoloEngine,
    solo_fee: SoloFeeConfig,
    /// When `None`, the Blockparty arm and the pending-fee guard fall back to Solo.
    blockparty: Option<Arc<dyn BlockpartyApi>>,
}

impl ProductionPayoutResolver {
    pub(crate) fn new(
        mode_gate: Arc<BlitzpoolModeGate>,
        pplns: Option<PplnsEngine>,
        group_solo: GroupSoloEngine,
        solo_fee: SoloFeeConfig,
        blockparty: Option<Arc<dyn BlockpartyApi>>,
    ) -> Self {
        Self {
            mode_gate,
            pplns,
            group_solo,
            solo_fee,
            blockparty,
        }
    }

    /// Resolution core for SV1 and SV2. The flag says whether a block found on
    /// this list could be booked (for snapshot modes: the list came from the
    /// engine AND its snapshot landed); one call yields both, so they agree.
    async fn resolve_internal(
        &self,
        miner_address: &str,
        reward_sats: u64,
    ) -> (ResolvedPayouts, bool) {
        let result = self.mode_gate.lookup_mode(miner_address);
        let vouchable = books_without_a_snapshot(result.mode);
        match result.mode {
            MiningMode::Solo => {
                // An admin of an unconfirmed Blockparty routes as Solo but
                // the coinbase pays the pool-fee address, so the admin cannot
                // take the whole reward before members confirm the splits.
                if let Some(route) = self
                    .blockparty_pending_fee_route(miner_address, reward_sats)
                    .await
                {
                    return (ResolvedPayouts::unsnapshotted(route), vouchable);
                }
                (
                    ResolvedPayouts::unsnapshotted(solo_payouts(
                        miner_address,
                        &self.solo_fee,
                        reward_sats,
                    )),
                    vouchable,
                )
            }
            MiningMode::Pplns => self.pplns_payouts(miner_address, reward_sats).await,
            MiningMode::Blockparty => (
                ResolvedPayouts::unsnapshotted(
                    self.blockparty_payouts(miner_address, reward_sats, result.group_id.as_deref())
                        .await,
                ),
                vouchable,
            ),
            MiningMode::GroupSolo => {
                let Some(gid_str) = result.group_id.as_deref() else {
                    error!(
                        miner_address,
                        "GroupSolo mode published WITHOUT a group_id; serving NO JOB"
                    );
                    return (ResolvedPayouts::none(), false);
                };
                let Ok(group_id) = Uuid::parse_str(gid_str) else {
                    error!(
                        miner_address,
                        gid_str, "GroupSolo group_id failed to parse as UUID; serving NO JOB"
                    );
                    return (ResolvedPayouts::none(), false);
                };
                self.group_solo_payouts(miner_address, reward_sats, group_id)
                    .await
            }
        }
    }
}

/// Can a block on this mode be booked without resolving a distribution snapshot?
/// Solo books no ledger row and Blockparty recomputes its splits, so yes. PPLNS
/// and Group-Solo book from the snapshot this exact list was stored under, and a
/// fallback list names one that was never written.
fn books_without_a_snapshot(mode: MiningMode) -> bool {
    match mode {
        MiningMode::Solo | MiningMode::Blockparty => true,
        MiningMode::Pplns | MiningMode::GroupSolo => false,
    }
}

/// Which of the two tailored (per-miner) builds a mode gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TailoredMode {
    Solo,
    GroupSolo,
}

/// What JDP serves a mode — the whole answer, not a yes/no.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JdpDistributionFor {
    /// The pool-wide PPLNS distribution IS this miner's accounting.
    PoolWide,
    /// A distribution built for this miner alone.
    Tailored(TailoredMode),
    /// Nothing at all — and deliberately not the pool-wide one either.
    Nothing,
    /// The address's mode is not known yet. Unlike `Nothing` this is not a
    /// decision; it resolves once a mining session registers.
    ModeUnknown,
}

/// What the pool serves a mode over JDP: the one, pure place that decides it,
/// so a new mode cannot reach a builder it was never classified for.
/// Blockparty (a rental) is deliberately refused, including the pool-wide
/// distribution, so it declares nothing the pool cannot account for.
fn jdp_distribution_for(mode: Option<MiningMode>) -> JdpDistributionFor {
    match mode {
        // No port has declared the mode yet; a JDC allocates before its
        // channel opens, so the gate's Solo default would be a guess.
        None => JdpDistributionFor::ModeUnknown,
        Some(MiningMode::Pplns) => JdpDistributionFor::PoolWide,
        Some(MiningMode::Solo) => JdpDistributionFor::Tailored(TailoredMode::Solo),
        Some(MiningMode::GroupSolo) => JdpDistributionFor::Tailored(TailoredMode::GroupSolo),
        Some(MiningMode::Blockparty) => JdpDistributionFor::Nothing,
    }
}

/// Which accounting a tailored build belongs to; it travels with the build
/// because the owner address alone cannot tell Solo from Group-Solo. A named
/// function so tests check it against `StreamKind::for_mode`, which the JDP
/// loop compares it with to detect a mode change.
fn accounting_for(tailored: TailoredMode, miner: &AddressId) -> DistributionAccounting {
    match tailored {
        TailoredMode::Solo => DistributionAccounting::Solo(miner.clone()),
        TailoredMode::GroupSolo => DistributionAccounting::GroupSolo(miner.clone()),
    }
}

/// Did the build fail because nothing in the window holds a share? The one
/// failure that must not become "no job": an empty window could never start.
/// Any other failure stays no-job, as an unreadable window may hide claims.
/// Group-Solo needs no equivalent: its builder always carries the finder.
fn is_empty_share_window(err: &bp_pplns_engine::engine::EngineError) -> bool {
    match err {
        bp_pplns_engine::engine::EngineError::Distribution(inner) => matches!(
            **inner,
            bp_pplns_engine::distribution::DistributionError::WeightBuild(
                bp_pplns::WeightBuildError::NoScoredMiners
            )
        ),
        _ => false,
    }
}

impl ProductionPayoutResolver {
    /// Returns the list and its bookable flag; see [`Self::resolve_internal`].
    async fn pplns_payouts(
        &self,
        miner_address: &str,
        reward_sats: u64,
    ) -> (ResolvedPayouts, bool) {
        let Some(pplns) = self.pplns.as_ref() else {
            error!(
                miner_address,
                "PPLNS mode in gate but `[pplns]` is absent from config; serving NO JOB"
            );
            return (ResolvedPayouts::none(), false);
        };
        // The pool-wide build is shared and cannot name a claimant; an empty
        // window (`NoScoredMiners`) is answered per-miner below.
        let built = match pplns.build_distribution(reward_sats).await {
            Ok(result) => Some(result),
            Err(err) if is_empty_share_window(&err) => {
                // Empty window: the weight model would pay the whole block to
                // the pool, and no job would deadlock it. This miner claims the
                // block; nobody else has a claim and the pool takes only its fee.
                match AddressId::new(miner_address.to_string()) {
                    Ok(claimant) => {
                        match pplns
                            .build_bootstrap_distribution(reward_sats, &claimant)
                            .await
                        {
                            Ok(result) => Some(result),
                            Err(err) => {
                                error!(
                                    %err,
                                    miner_address,
                                    reward_sats,
                                    "PPLNS window holds no scored miner and the bootstrap build \
                                     failed too; serving NO JOB"
                                );
                                None
                            }
                        }
                    }
                    Err(err) => {
                        error!(
                            %err,
                            miner_address,
                            "PPLNS window holds no scored miner and the asking address will not \
                             parse; serving NO JOB"
                        );
                        None
                    }
                }
            }
            Err(err) => {
                error!(
                    %err,
                    miner_address,
                    reward_sats,
                    "PPLNS distribution build failed; serving NO JOB until it succeeds"
                );
                None
            }
        };
        match built {
            // A build can succeed without its snapshot: the coinbase stands
            // (failing would hand this miner the whole block), but the
            // fingerprint names a missing key, so the block is not bookable.
            Some(result) => {
                if !result.snapshot_written {
                    warn!(
                        miner_address,
                        reward_sats,
                        "PPLNS distribution built but its snapshot did not land — the coinbase \
                         stands, a block found on it cannot be booked automatically"
                    );
                }
                // ext 0x0003/Payout Computation at this template's revenue,
                // the same formula a JDC runs with its own template value.
                match result.distribution.payout_entries_at(reward_sats) {
                    Ok(entries) => (
                        ResolvedPayouts {
                            entries: entries
                                .into_iter()
                                .map(|(address, sats)| PayoutEntry {
                                    address: address.into_inner(),
                                    sats,
                                })
                                .collect(),
                            payouts_fingerprint: result.payouts_fingerprint(),
                        },
                        result.snapshot_written,
                    ),
                    Err(err) => {
                        error!(
                            %err,
                            miner_address,
                            reward_sats,
                            "PPLNS ext 0x0003/Payout Computation evaluation failed; serving NO JOB"
                        );
                        (ResolvedPayouts::none(), false)
                    }
                }
            }
            None => (ResolvedPayouts::none(), false),
        }
    }

    /// The whole reward to the pool fee when the address administers an
    /// unconfirmed Blockparty; `None` falls through to the Solo coinbase.
    async fn blockparty_pending_fee_route(
        &self,
        miner_address: &str,
        reward_sats: u64,
    ) -> Option<Vec<PayoutEntry>> {
        let svc = self.blockparty.as_ref()?;
        let addr = AddressId::new(miner_address.to_string()).ok()?;
        let route = svc.pending_party_fee_route(&addr).await?;
        Some(pending_fee_route_payouts(route, reward_sats))
    }

    async fn blockparty_payouts(
        &self,
        miner_address: &str,
        reward_sats: u64,
        group_id_str: Option<&str>,
    ) -> Vec<PayoutEntry> {
        let Some(svc) = self.blockparty.as_ref() else {
            warn!(
                miner_address,
                "Blockparty mode in gate but service handle not wired; falling back to solo"
            );
            return solo_payouts(miner_address, &self.solo_fee, reward_sats);
        };
        let Some(gid_str) = group_id_str else {
            warn!(
                miner_address,
                "Blockparty mode published WITHOUT a group_id; falling back to solo"
            );
            return solo_payouts(miner_address, &self.solo_fee, reward_sats);
        };
        let Ok(group_id) = Uuid::parse_str(gid_str) else {
            warn!(
                miner_address,
                gid_str, "Blockparty group_id failed to parse as UUID; falling back to solo"
            );
            return solo_payouts(miner_address, &self.solo_fee, reward_sats);
        };
        match svc.build_payouts(group_id, Sats(reward_sats as i64)).await {
            Ok(Some(result)) => entries_to_payouts(&result.payouts),
            Ok(None) => {
                warn!(
                    miner_address,
                    %group_id,
                    "Blockparty group not found; falling back to solo"
                );
                solo_payouts(miner_address, &self.solo_fee, reward_sats)
            }
            Err(err) => {
                warn!(
                    %err,
                    miner_address,
                    %group_id,
                    "Blockparty distribution build failed; falling back to solo"
                );
                solo_payouts(miner_address, &self.solo_fee, reward_sats)
            }
        }
    }

    /// Returns the list and its bookable flag; see [`Self::resolve_internal`].
    async fn group_solo_payouts(
        &self,
        miner_address: &str,
        reward_sats: u64,
        group_id: Uuid,
    ) -> (ResolvedPayouts, bool) {
        // The connecting miner is the finder for the group's finder bonus.
        let finder = match AddressId::new(miner_address.to_string()) {
            Ok(a) => a,
            Err(_) => {
                error!(
                    miner_address,
                    "GroupSolo miner address failed AddressId parse; serving NO JOB"
                );
                return (ResolvedPayouts::none(), false);
            }
        };
        match self
            .group_solo
            .build_distribution(group_id, reward_sats, &finder)
            .await
        {
            Ok(result) => {
                if !result.snapshot_written {
                    warn!(
                        miner_address,
                        %group_id,
                        reward_sats,
                        "Group-Solo distribution built but its snapshot did not land — the \
                         coinbase stands, a block found on it cannot be booked automatically"
                    );
                }
                // ext 0x0003/Payout Computation at this template's revenue.
                match result.distribution.payout_entries_at(reward_sats) {
                    Ok(entries) => (
                        ResolvedPayouts {
                            entries: entries
                                .into_iter()
                                .map(|(address, sats)| PayoutEntry {
                                    address: address.into_inner(),
                                    sats,
                                })
                                .collect(),
                            payouts_fingerprint: result.payouts_fingerprint(),
                        },
                        result.snapshot_written,
                    ),
                    Err(err) => {
                        error!(
                            %err,
                            miner_address,
                            %group_id,
                            reward_sats,
                            "Group-Solo ext 0x0003/Payout Computation evaluation failed; serving NO JOB"
                        );
                        (ResolvedPayouts::none(), false)
                    }
                }
            }
            Err(err) => {
                error!(
                    %err,
                    miner_address,
                    %group_id,
                    reward_sats,
                    "Group-Solo distribution build failed; serving NO JOB until it succeeds"
                );
                (ResolvedPayouts::none(), false)
            }
        }
    }
}

// ─── Trait impls ──────────────────────────────────────────────────

#[async_trait]
impl bp_stratum_v1::PayoutResolver for ProductionPayoutResolver {
    async fn resolve_payouts(&self, miner_address: &str, reward_sats: u64) -> ResolvedPayouts {
        // Building a job needs the list, not the accounting promise.
        self.resolve_internal(miner_address, reward_sats).await.0
    }

    fn resolve_stream(&self, miner_address: &str) -> bp_common::StreamKind {
        // Same lookup as payout resolution, so a pending Blockparty admin
        // routes to the Solo stream.
        bp_common::StreamKind::for_mode(self.mode_gate.lookup_mode(miner_address).mode)
    }
}

#[async_trait]
impl bp_stratum_v2::hooks::PayoutResolver for ProductionPayoutResolver {
    async fn resolve_payouts(
        &self,
        miner_address: &AddressId,
        reward_sats: u64,
    ) -> ResolvedPayouts {
        self.resolve_internal(miner_address.as_str(), reward_sats)
            .await
            .0
    }

    fn resolve_stream(&self, miner_address: &AddressId) -> bp_common::StreamKind {
        bp_common::StreamKind::for_mode(self.mode_gate.lookup_mode(miner_address.as_str()).mode)
    }

    /// `None` (not Solo) for an address the gate has not learned yet: JDP
    /// allocates before the mining channel whose port decides the mode exists.
    fn resolve_stream_known(&self, miner_address: &AddressId) -> Option<bp_common::StreamKind> {
        self.mode_gate
            .lookup_known(miner_address.as_str())
            .map(|result| bp_common::StreamKind::for_mode(result.mode))
    }
}

// ─── Ext 0x0003 distribution source (push model) ──────────────────

/// Production [`bp_stratum_v2::jdp_server::PayoutDistributionSource`]: the
/// pool-wide PPLNS distribution, tailored ones per [`jdp_distribution_for`],
/// and the strictly increasing ext 0x0003/SetPayoutDistribution
/// `distribution_id` via Redis.
pub(crate) struct ProductionDistributionSource {
    pub(crate) resolver: Arc<ProductionPayoutResolver>,
    /// What the current template pays out; shared with the other JDP hooks so
    /// all resolve their reward against one implementation.
    pub(crate) chain: std::sync::Arc<dyn crate::jdp_hooks::ChainView>,
    pub(crate) redis: Option<redis::aio::ConnectionManager>,
    pub(crate) network: bitcoin::Network,
    /// Pool-output recipient for tailored distributions whose own
    /// allocator has no pool output (plain Solo without a dev fee).
    pub(crate) fee_address: Option<AddressId>,
}

impl ProductionDistributionSource {
    /// A payout address as its locking script on the pool's network. On `None`
    /// both lowering paths refuse the whole build: a skipped payout would shift
    /// every later position in the coinbase vector.
    fn script_of(&self, addr: &str) -> Option<Vec<u8>> {
        bp_mining_job::address_to_script(self.network, addr)
            .ok()
            .map(|s| s.to_bytes())
    }

    /// Lower a weight-native engine distribution into the wire shape.
    fn lower_weight_distribution(
        &self,
        d: &bp_pplns::WeightDistribution,
        fingerprint: Option<[u8; 32]>,
        bookable: bool,
    ) -> Option<bp_stratum_v2::bridge::BuiltPayoutDistribution> {
        let pool_script = self.script_of(d.fee_address.as_str())?;
        let mut payouts = Vec::new();
        let mut dust_limits = Vec::new();
        for entry in d.published() {
            let script = self.script_of(entry.address.as_str())?;
            payouts.push(bp_stratum_v2::jdp::payout_distribution::WeightedOutput {
                script_pubkey: script,
                weight: entry.wire_weight,
            });
            dust_limits.push(entry.dust_limit);
        }
        Some(bp_stratum_v2::bridge::BuiltPayoutDistribution {
            pool_payout: bp_stratum_v2::jdp::payout_distribution::WeightedOutput {
                script_pubkey: pool_script,
                weight: d.weight_p,
            },
            payouts,
            dust_limits,
            additional_outputs: Vec::new(),
            reference_reward_sats: d.reference_revenue_sats,
            payouts_fingerprint: fingerprint,
            bookable,
        })
    }

    /// Solo's exact sats-at-reference as weights (it settles by recompute, not
    /// from a snapshot). `entries` in ext 0x0003/Payout Computation order
    /// without the pool output, which comes from `pool_addr`.
    fn lower_exact_entries(
        &self,
        pool_addr: &str,
        pool_weight: u64,
        entries: &[(String, u64)],
        reference_reward_sats: u64,
    ) -> Option<bp_stratum_v2::bridge::BuiltPayoutDistribution> {
        let pool_script = self.script_of(pool_addr)?;
        let mut payouts = Vec::new();
        let mut dust_limits = Vec::new();
        for (addr, sats) in entries {
            if *sats == 0 {
                continue;
            }
            payouts.push(bp_stratum_v2::jdp::payout_distribution::WeightedOutput {
                script_pubkey: self.script_of(addr)?,
                weight: *sats,
            });
            dust_limits.push(bp_pplns::DUST_LIMIT_SATS as u32);
        }
        Some(bp_stratum_v2::bridge::BuiltPayoutDistribution {
            pool_payout: bp_stratum_v2::jdp::payout_distribution::WeightedOutput {
                script_pubkey: pool_script,
                weight: pool_weight.max(1),
            },
            payouts,
            dust_limits,
            additional_outputs: Vec::new(),
            reference_reward_sats,
            // Solo books nothing, so there is no snapshot to name.
            payouts_fingerprint: None,
            bookable: true,
        })
    }
}

#[async_trait]
impl bp_stratum_v2::jdp_server::PayoutDistributionSource for ProductionDistributionSource {
    async fn build_pool_wide(&self) -> Option<bp_stratum_v2::bridge::BuiltPayoutDistribution> {
        let t_ref = self.chain.reference_revenue()?;
        let pplns = self.resolver.pplns.as_ref()?;
        let result = match pplns.build_distribution(t_ref).await {
            Ok(r) => r,
            Err(err) => {
                warn!(%err, "jdp distribution source: PPLNS build failed — nothing to publish");
                return None;
            }
        };
        self.lower_weight_distribution(
            &result.distribution,
            Some(result.payouts_fingerprint()),
            result.snapshot_written,
        )
    }

    async fn build_for_miner(&self, miner_address: &AddressId) -> TailoredDistribution {
        // Failures return `Unavailable`, never `PoolWide`, which would pay a
        // non-PPLNS block to the PPLNS window. `lookup_known`, not
        // `lookup_mode`: this runs at allocate time, before a mining session
        // exists, and `lookup_mode` would guess Solo.
        let known = self.resolver.mode_gate.lookup_known(miner_address.as_str());
        let mode = known.as_ref().map(|r| r.mode);
        let tailored = match jdp_distribution_for(mode) {
            JdpDistributionFor::ModeUnknown => {
                debug!(
                    miner = miner_address.as_str(),
                    "jdp distribution source: no mining session for this address yet — \
                     publishing nothing until its mode is known (the port decides it, and no \
                     port has spoken)"
                );
                return TailoredDistribution::ModeUnknown;
            }
            JdpDistributionFor::PoolWide => return TailoredDistribution::PoolWide,
            JdpDistributionFor::Nothing => {
                warn!(
                    miner = miner_address.as_str(),
                    mode = ?mode,
                    "jdp distribution source: this mode is not served over JDP — serving NO \
                     distribution"
                );
                return TailoredDistribution::Unavailable;
            }
            JdpDistributionFor::Tailored(kind) => kind,
        };
        let Some(t_ref) = self.chain.reference_revenue() else {
            warn!(
                miner = miner_address.as_str(),
                "jdp distribution source: no reference revenue yet — no tailored distribution"
            );
            return TailoredDistribution::Unavailable;
        };
        let built = match tailored {
            TailoredMode::GroupSolo => {
                // `known` is Some here, but no `expect`: no panic on the money path.
                let Some(group_id) = known
                    .as_ref()
                    .and_then(|r| r.group_id.as_deref())
                    .and_then(|gid| Uuid::parse_str(gid).ok())
                else {
                    warn!(
                        miner = miner_address.as_str(),
                        "jdp distribution source: group-solo miner without a usable group id"
                    );
                    return TailoredDistribution::Unavailable;
                };
                match self
                    .resolver
                    .group_solo
                    .build_distribution(group_id, t_ref, miner_address)
                    .await
                {
                    Ok(result) => self.lower_weight_distribution(
                        &result.distribution,
                        Some(result.payouts_fingerprint()),
                        result.snapshot_written,
                    ),
                    Err(err) => {
                        warn!(%err, miner = miner_address.as_str(),
                            "jdp distribution source: group-solo build failed — no tailored distribution");
                        None
                    }
                }
            }
            TailoredMode::Solo => {
                let entries: Vec<(String, u64)> =
                    solo_payouts(miner_address.as_str(), &self.resolver.solo_fee, t_ref)
                        .into_iter()
                        .map(|p| (p.address, p.sats))
                        .collect();
                // The dev-fee output doubles as pool_payout; without one the
                // pool fee address anchors `weight_P` at weight 1 (it only
                // takes the ext 0x0003/Payout Computation residual).
                match self.resolver.solo_fee.dev_fee_address.clone() {
                    Some(dev) => {
                        let dev_weight = entries
                            .iter()
                            .find(|(a, _)| *a == dev)
                            .map(|(_, s)| *s)
                            .unwrap_or(1);
                        let miners: Vec<(String, u64)> =
                            entries.into_iter().filter(|(a, _)| *a != dev).collect();
                        self.lower_exact_entries(&dev, dev_weight, &miners, t_ref)
                    }
                    None => match self.fee_address.as_ref() {
                        Some(fee) => self.lower_exact_entries(fee.as_str(), 1, &entries, t_ref),
                        None => {
                            warn!(miner = miner_address.as_str(),
                                "jdp distribution source: solo miner but no pool fee address configured");
                            None
                        }
                    },
                }
            }
        };
        match built {
            Some(b) => TailoredDistribution::Built {
                accounting: accounting_for(tailored, miner_address),
                built: Box::new(b),
            },
            // `lower_*` failed (unusable address / weight overflow); still
            // never the pool-wide distribution.
            None => TailoredDistribution::Unavailable,
        }
    }

    async fn current_mode(&self, miner_address: &AddressId) -> Option<bp_common::StreamKind> {
        // The same `lookup_known` `build_for_miner` decides from, so the loop
        // never sees a mode change the builder disagrees with; no session is
        // undecided, not Solo, so a rig blip does not tear up a plan.
        bp_stratum_v2::hooks::PayoutResolver::resolve_stream_known(
            self.resolver.as_ref(),
            miner_address,
        )
    }

    async fn next_distribution_id(&self) -> Option<u64> {
        let mut conn = self.redis.clone()?;
        // Atomic floor-to-wallclock + INCR: strictly increasing across
        // restarts, Redis wipes and concurrent fronts
        // (ext 0x0003/SetPayoutDistribution).
        const LUA: &str = r#"
            local v = redis.call('GET', KEYS[1])
            if (not v) or (tonumber(v) < tonumber(ARGV[1])) then
                redis.call('SET', KEYS[1], ARGV[1])
            end
            return redis.call('INCR', KEYS[1])
        "#;
        let now_ms = chrono::Utc::now().timestamp_millis();
        match redis::Script::new(LUA)
            .key("jdp:distribution_id")
            .arg(now_ms)
            .invoke_async::<i64>(&mut conn)
            .await
        {
            Ok(id) => Some(id as u64),
            Err(err) => {
                warn!(%err, "jdp distribution source: distribution-id allocation failed");
                None
            }
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────

/// The pending-fee route's coinbase: one output, the whole reward to the
/// pool-fee address.
fn pending_fee_route_payouts(
    route: bp_blockparty_engine::PendingPartyFeeRoute,
    reward_sats: u64,
) -> Vec<PayoutEntry> {
    vec![PayoutEntry {
        address: route.fee_address.into_inner(),
        sats: reward_sats,
    }]
}

/// Engine entries as coinbase `PayoutEntry`s, carrying the exact sats the
/// distributor computed; the coinbase builder never re-derives them from a percentage.
fn entries_to_payouts(entries: &[CoinbaseDistributionEntry]) -> Vec<PayoutEntry> {
    entries
        .iter()
        .map(|e| PayoutEntry {
            address: e.address.as_str().to_string(),
            // Clamp so a negative `Sats` cannot wrap into a huge output.
            sats: e.sats.0.max(0) as u64,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_REWARD: u64 = 5_000_000_000;

    /// Solo and Blockparty are always bookable; the snapshot modes are not.
    /// The flag gates the whole block-found emission, not just a snapshot lookup.
    #[test]
    fn the_modes_that_resolve_no_snapshot_can_always_be_booked() {
        assert!(
            books_without_a_snapshot(MiningMode::Solo),
            "solo writes no engine ledger row — nothing a fallback could invalidate"
        );
        assert!(
            books_without_a_snapshot(MiningMode::Blockparty),
            "blockparty recomputes its splits and keys on the block hash"
        );
        assert!(!books_without_a_snapshot(MiningMode::Pplns));
        assert!(!books_without_a_snapshot(MiningMode::GroupSolo));
    }

    /// Pins the full mode → JDP distribution map, every mode named.
    #[test]
    fn jdp_answers_every_mode_with_exactly_one_distribution() {
        assert_eq!(
            jdp_distribution_for(Some(MiningMode::Pplns)),
            JdpDistributionFor::PoolWide,
            "PPLNS rides the shared window — that IS its accounting"
        );
        assert_eq!(
            jdp_distribution_for(Some(MiningMode::Solo)),
            JdpDistributionFor::Tailored(TailoredMode::Solo)
        );
        assert_eq!(
            jdp_distribution_for(Some(MiningMode::GroupSolo)),
            JdpDistributionFor::Tailored(TailoredMode::GroupSolo)
        );
        assert_eq!(
            jdp_distribution_for(Some(MiningMode::Blockparty)),
            JdpDistributionFor::Nothing,
            "a rental is not served over JDP, and must not fall back to pool-wide"
        );

        // No mining session yet (every JDC start): any answer would be a
        // guess, so it is "not yet" and the caller retries.
        assert_eq!(
            jdp_distribution_for(None),
            JdpDistributionFor::ModeUnknown,
            "an undecided mode must not resolve to any distribution — it used to \
             take the mode gate's Solo default and publish a Solo plan for it"
        );
        assert_ne!(
            jdp_distribution_for(None),
            jdp_distribution_for(Some(MiningMode::Solo)),
            "unknown and Solo must stay distinct answers — collapsing them IS the bug"
        );
    }

    /// For every mode, the built accounting matches the probed stream, or the
    /// JDP loop would see a mode change and rebuild the plan on every frame.
    #[test]
    fn what_a_mode_is_built_and_what_it_probes_as_are_the_same_answer() {
        use bp_stratum_v2::bridge::{accounting_matches_stream, DistributionAccounting as Acct};
        let miner = AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string())
            .expect("address");
        for mode in [
            MiningMode::Pplns,
            MiningMode::Solo,
            MiningMode::GroupSolo,
            MiningMode::Blockparty,
        ] {
            let probed = bp_common::StreamKind::for_mode(mode);
            // Via the same functions `build_for_miner` calls, so swapped arms
            // in `accounting_for` fail here.
            let built = match jdp_distribution_for(Some(mode)) {
                JdpDistributionFor::PoolWide => Some(Acct::PoolWide),
                JdpDistributionFor::Tailored(kind) => Some(accounting_for(kind, &miner)),
                // Nothing built, nothing to disagree with.
                JdpDistributionFor::Nothing => None,
                JdpDistributionFor::ModeUnknown => {
                    panic!("{mode:?} is a known mode; only `None` may answer ModeUnknown")
                }
            };
            let Some(built) = built else { continue };
            assert!(
                accounting_matches_stream(&built, probed),
                "{mode:?} is built as {built:?} but probes as {probed:?} — a session on this \
                 mode would rebuild its plan on every frame"
            );
        }
    }

    /// Solo and Group-Solo map to distinct tailored builds.
    #[test]
    fn the_two_tailored_modes_are_distinct() {
        assert_ne!(
            jdp_distribution_for(Some(MiningMode::Solo)),
            jdp_distribution_for(Some(MiningMode::GroupSolo))
        );
    }

    #[test]
    fn solo_payouts_empty_address_yields_empty() {
        let r = solo_payouts("", &SoloFeeConfig::default(), TEST_REWARD);
        assert!(r.is_empty());
    }

    #[test]
    fn solo_payouts_no_dev_fee_yields_single_100_pct() {
        let r = solo_payouts(
            "bc1qabc",
            &SoloFeeConfig {
                dev_fee_address: None,
                dev_fee_percent: 0.0,
            },
            TEST_REWARD,
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].address, "bc1qabc");
        assert_eq!(r[0].sats, TEST_REWARD);
    }

    #[test]
    fn solo_payouts_with_dev_fee_splits() {
        let r = solo_payouts(
            "bc1qminer",
            &SoloFeeConfig {
                dev_fee_address: Some("bc1qdev".into()),
                dev_fee_percent: 1.5,
            },
            TEST_REWARD,
        );
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].address, "bc1qdev");
        assert_eq!(r[0].sats, 75_000_000); // floor(1.5% × 5e9)
        assert_eq!(r[1].address, "bc1qminer");
        assert_eq!(r[1].sats, TEST_REWARD - 75_000_000); // miner takes the remainder
        assert_eq!(r[0].sats + r[1].sats, TEST_REWARD);
    }

    #[test]
    fn solo_payouts_with_dev_fee_empty_address_is_ignored() {
        // Trim treats whitespace-only as empty.
        let r = solo_payouts(
            "bc1qminer",
            &SoloFeeConfig {
                dev_fee_address: Some("   ".into()),
                dev_fee_percent: 1.5,
            },
            TEST_REWARD,
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].address, "bc1qminer");
        assert_eq!(r[0].sats, TEST_REWARD);
    }

    #[test]
    fn solo_payouts_rejects_out_of_range_fee_percent() {
        let r = solo_payouts(
            "bc1qminer",
            &SoloFeeConfig {
                dev_fee_address: Some("bc1qdev".into()),
                dev_fee_percent: 150.0,
            },
            TEST_REWARD,
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].address, "bc1qminer");
        assert_eq!(r[0].sats, TEST_REWARD);
    }

    #[test]
    fn solo_payouts_zero_percent_dev_fee_pays_miner_only() {
        // Dev address set but percent 0.0: no zero-value dev output.
        let r = solo_payouts(
            "bc1qminer",
            &SoloFeeConfig {
                dev_fee_address: Some("bc1qdev".into()),
                dev_fee_percent: 0.0,
            },
            TEST_REWARD,
        );
        assert_eq!(r.len(), 1, "no zero-value dev output");
        assert_eq!(r[0].address, "bc1qminer");
        assert_eq!(r[0].sats, TEST_REWARD);
    }

    /// The pending-fee route pays what the 100 % formula pays, for every
    /// subsidy era plus fees up to the whole money supply.
    #[test]
    fn pending_fee_route_pays_what_the_percent_formula_paid() {
        let fee = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let mut rewards = vec![0u64, 1, 546, 2_100_000_000_000_000];
        for era in 0..34u32 {
            let subsidy = 5_000_000_000u64 >> era;
            rewards.extend([subsidy, subsidy + 1, subsidy + 12_345_678]);
        }
        for reward in rewards {
            let route = bp_blockparty_engine::PendingPartyFeeRoute {
                fee_address: AddressId::new(fee.to_string()).unwrap(),
            };
            let paid = pending_fee_route_payouts(route, reward);
            assert_eq!(paid.len(), 1);
            assert_eq!(paid[0].address, fee);
            assert_eq!(
                paid[0].sats,
                PayoutEntry::from_percent(fee, 100.0, reward).sats,
                "reward {reward}"
            );
        }
    }

    #[test]
    fn entries_to_payouts_carries_exact_sats() {
        use bp_common::Sats;
        let entries = vec![
            CoinbaseDistributionEntry {
                address: AddressId::new("bc1qa".to_string()).unwrap(),
                percent: 60.0,
                sats: Sats(60_000_000),
            },
            CoinbaseDistributionEntry {
                address: AddressId::new("bc1qb".to_string()).unwrap(),
                percent: 40.0,
                sats: Sats(40_000_000),
            },
        ];
        let payouts = entries_to_payouts(&entries);
        assert_eq!(payouts.len(), 2);
        assert_eq!(payouts[0].address, "bc1qa");
        assert_eq!(payouts[0].sats, 60_000_000);
        assert_eq!(payouts[1].address, "bc1qb");
        assert_eq!(payouts[1].sats, 40_000_000);
    }
}
