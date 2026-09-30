// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production coinbase payout resolver.
//!
//! Gives BOTH SV1 + SV2 the per-mode coinbase output distribution at every
//! template broadcast, so the on-chain coinbase pays what the address's
//! payout mode owes.
//!
//! ## Resolution dispatch
//!
//! For each `(miner_address, reward_sats)` resolve request:
//!
//! 1. Consult [`BlitzpoolModeGate::lookup_mode`] for the address.
//! 2. **Solo** → [`solo_payouts`] (single 100%-to-miner OR split
//!    with `dev_fee_address`/`dev_fee_percent` when configured).
//! 3. **Pplns** → [`PplnsEngine::build_distribution`] → the weight
//!    distribution's payouts as `Vec<PayoutEntry>`.
//! 4. **GroupSolo** → [`GroupSoloEngine::build_distribution`] (need
//!    the group_id from the gate's `MiningModeResult.group_id` field
//!    plus the miner's own `AddressId` as the finder).
//!
//! ## Adapter strategy
//!
//! Both SV1 (`bp_stratum_v1::PayoutResolver`) + SV2
//! (`bp_stratum_v2::PayoutResolver`) traits are implemented directly on
//! [`ProductionPayoutResolver`]; the trait shapes differ only in the
//! address type (`&str` vs `&AddressId`).
//!
//! ## Performance notes
//!
//! `build_distribution` calls return `Arc<DistributionResult>` and the
//! engines collapse concurrent lookups for the same reward via an
//! `InflightResultCache`. The resolver runs at most once per
//! `(template-broadcast × connection)` event.

use std::sync::Arc;

use async_trait::async_trait;
use bp_blockparty::CoinbaseDistributionEntry;
use bp_blockparty_engine::BlockpartyApi;
use bp_common::{AddressId, MiningMode, Sats};
use bp_group_solo_engine::engine::GroupSoloEngine;
/// Re-exported so the wiring keeps one import path for the solo split.
pub(crate) use bp_mining_job::SoloFeeConfig;
use bp_mining_job::{solo_payouts, PayoutEntry, ResolvedPayouts};
use bp_pplns_engine::engine::PplnsEngine;
use bp_stratum_v2::bridge::DistributionAccounting;
use bp_stratum_v2::jdp_server::TailoredDistribution;
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::engines::BlitzpoolModeGate;

/// The single production `PayoutResolver` impl. Holds clones of the
/// engines + the mode gate; cheap to clone.
#[derive(Clone)]
pub(crate) struct ProductionPayoutResolver {
    mode_gate: Arc<BlitzpoolModeGate>,
    pplns: Option<PplnsEngine>,
    group_solo: GroupSoloEngine,
    solo_fee: SoloFeeConfig,
    /// Optional Blockparty service handle. When `None` the Blockparty arm
    /// and the Solo pending-fee guard fall back to standard Solo payouts.
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

    /// Resolution core — used by both the SV1 + SV2 trait impls.
    ///
    /// The second half of the pair says whether a block found on this list could
    /// be booked: for the two modes that resolve a snapshot, that means the list
    /// came from the engine AND the engine's snapshot landed. It comes from the
    /// same call that produced the list, so the flag and the list cannot
    /// disagree.
    async fn resolve_internal(
        &self,
        miner_address: &str,
        reward_sats: u64,
    ) -> (ResolvedPayouts, bool) {
        let result = self.mode_gate.lookup_mode(miner_address);
        let vouchable = books_without_a_snapshot(result.mode);
        match result.mode {
            MiningMode::Solo => {
                // Pending-fee guard: an admin whose Blockparty is still
                // DRAFT / CONFIRMING falls through to Solo for routing,
                // but the on-chain coinbase routes 100% to the pool-fee
                // address (BlockpartyService surfaces this as
                // `pending_party_fee_route`), so the admin cannot take the
                // full block reward before the members confirm the splits.
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

/// Can a block found on this mode's payout set be booked without resolving a
/// distribution snapshot?
///
/// Solo writes no engine ledger row at all — its coinbase is a single payout,
/// nothing to reconstruct. Blockparty recomputes the splits from the live engine
/// and writes its history row idempotently on the block hash, so it never reads
/// a fingerprint either. For both, whether the list came from an engine or from
/// a fallback changes nothing about what gets written, so the pool can book.
///
/// PPLNS and Group-Solo are the opposite: booking means resolving the snapshot
/// this exact list was stored under, and a fallback list names one that was
/// never written.
fn books_without_a_snapshot(mode: MiningMode) -> bool {
    match mode {
        MiningMode::Solo | MiningMode::Blockparty => true,
        MiningMode::Pplns | MiningMode::GroupSolo => false,
    }
}

/// Which of the two tailored builds a mode gets. Both need a reference
/// revenue and produce a per-miner distribution; they differ only in
/// where the weights come from.
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
    /// The pool does not know this address's mode yet, so it cannot know
    /// which of the above applies. Distinct from `Nothing`: that is a
    /// decision, this is the absence of one, and it resolves the moment a
    /// mining session registers.
    ModeUnknown,
}

/// What the pool serves a mode over JDP, decided before anything is built.
///
/// Pure and total on purpose: it is the one place the money question
/// "which distribution does this miner get?" is answered, so a new mode
/// cannot reach a builder it was never classified for, and the answer is
/// testable without engines, Redis or a template feed.
///
/// **Blockparty gets nothing.** A Blockparty group is a rental: the
/// hashrate is pointed straight at an address and the pool splits the
/// coinbase by fixed per-member percentages read from Postgres. A
/// job-declaring client exists so a miner can pick its own transaction
/// set, which a rental customer neither does nor wants, so JDP is not
/// offered. That is a deliberate REFUSAL: [`JdpDistributionFor::Nothing`]
/// denies the session the pool-wide distribution too (see
/// [`TailoredDistribution`]), so it declares nothing rather than something
/// the pool cannot account for.
fn jdp_distribution_for(mode: Option<MiningMode>) -> JdpDistributionFor {
    match mode {
        // No mining session for this address, so no port has declared its
        // mode. A JDC allocates before its channel opens, so the gate's Solo
        // default would be a guess at every JDC start.
        None => JdpDistributionFor::ModeUnknown,
        Some(MiningMode::Pplns) => JdpDistributionFor::PoolWide,
        Some(MiningMode::Solo) => JdpDistributionFor::Tailored(TailoredMode::Solo),
        Some(MiningMode::GroupSolo) => JdpDistributionFor::Tailored(TailoredMode::GroupSolo),
        Some(MiningMode::Blockparty) => JdpDistributionFor::Nothing,
    }
}

/// Which accounting a tailored build belongs to.
///
/// The kind travels with the build because the caller cannot re-derive it:
/// Solo and Group-Solo produce different payout vectors for the same one
/// address, so an owner address alone cannot tell the two apart later.
///
/// A named function, not an inline `match`: it is the second half of the
/// mode→answer table [`jdp_distribution_for`] starts, and the JDP loop
/// compares its result against `StreamKind::for_mode` to decide whether an
/// address's mode moved, so a test can call it rather than restate it.
fn accounting_for(tailored: TailoredMode, miner: &AddressId) -> DistributionAccounting {
    match tailored {
        TailoredMode::Solo => DistributionAccounting::Solo(miner.clone()),
        TailoredMode::GroupSolo => DistributionAccounting::GroupSolo(miner.clone()),
    }
}

/// Did the build fail because NOTHING in the window holds a share?
///
/// Matched as its own condition because it is the one build failure that
/// must not become "serve no job": the window fills only from accepted
/// shares and shares come only from jobs, so refusing would leave a fresh
/// window unable to ever start. Every OTHER failure keeps the no-job
/// answer: a window that cannot be read may be full of miners whose claims
/// are invisible right now, and handing the block to one connecting miner
/// would rob all of them.
///
/// Group-Solo needs no equivalent here: its builder always carries the
/// prospective finder as the claimant (its cache is keyed per-finder), so
/// this verdict never reaches its arm.
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
    /// Second half of the pair: could a block found on this list be booked? See
    /// [`Self::resolve_internal`].
    async fn pplns_payouts(
        &self,
        miner_address: &str,
        reward_sats: u64,
    ) -> (ResolvedPayouts, bool) {
        let Some(pplns) = self.pplns.as_ref() else {
            // PPLNS mode in the gate but no engine on this deployment: a
            // config inconsistency, so serve no job.
            error!(
                miner_address,
                "PPLNS mode in gate but `[pplns]` is absent from config; serving NO JOB"
            );
            return (ResolvedPayouts::none(), false);
        };
        // The pool-wide build first. It is shared by every PPLNS
        // connection, so it cannot name a claimant; an empty window comes
        // back as `NoScoredMiners` and is answered per-miner below.
        let built = match pplns.build_distribution(reward_sats).await {
            Ok(result) => Some(result),
            Err(err) if is_empty_share_window(&err) => {
                // Nobody in the window holds a share. The weight model would
                // pay the WHOLE block to the pool output, and serving no job
                // would deadlock a fresh window (it fills only from shares,
                // which come only from jobs). So this miner claims the block:
                // nobody else has a claim to lose, and the pool still takes
                // exactly its fee.
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
            // The build can succeed while its snapshot write does not: the
            // engine keeps the distribution, because failing it would hand
            // this miner the whole block. But the fingerprint then names a
            // key that does not exist, so there is nothing to vouch for.
            Some(result) => {
                if !result.snapshot_written {
                    warn!(
                        miner_address,
                        reward_sats,
                        "PPLNS distribution built but its snapshot did not land — the coinbase \
                         stands, a block found on it cannot be booked automatically"
                    );
                }
                // The ext 0x0003/Payout Computation evaluation at this
                // template's revenue — the same formula a JDC runs with its
                // own template value.
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

    /// Pending-party-fee guard. Returns `Some(vec![pool_fee → 100%])`
    /// when the connecting address is the admin of an unconfirmed
    /// Blockparty (DRAFT or CONFIRMING). Returns `None` otherwise so
    /// the caller falls through to the standard Solo coinbase.
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

    /// Second half of the pair: could a block found on this list be booked? See
    /// [`Self::resolve_internal`].
    async fn group_solo_payouts(
        &self,
        miner_address: &str,
        reward_sats: u64,
        group_id: Uuid,
    ) -> (ResolvedPayouts, bool) {
        // The finder is the miner connecting on this share path; the
        // Group-Solo engine applies the group's `finder_bonus_ppm` to it.
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
                // The ext 0x0003/Payout Computation evaluation at this
                // template's revenue.
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
        // The same mode lookup the payout resolution uses, mapped to a
        // stream. A Solo address (incl. a Blockparty admin whose party is
        // still DRAFT) routes to the Solo stream; everything else to Default.
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

    /// `lookup_known`, so an address the gate has never been told about comes
    /// back as `None` instead of as Solo. The gate learns an address from the
    /// port a mining session opens on; a JDP connection has no port to derive
    /// a mode from, and the allocate runs before the mining channel exists.
    fn resolve_stream_known(&self, miner_address: &AddressId) -> Option<bp_common::StreamKind> {
        self.mode_gate
            .lookup_known(miner_address.as_str())
            .map(|result| bp_common::StreamKind::for_mode(result.mode))
    }
}

// ─── Ext 0x0003 distribution source (push model) ──────────────────

/// Production [`bp_stratum_v2::jdp_server::PayoutDistributionSource`]: builds
/// the pool-wide PPLNS distribution for the publisher and tailored
/// distributions (Solo or Group-Solo — see [`jdp_distribution_for`]) once an
/// allocate reveals a session's identity, and allocates the
/// ext 0x0003/SetPayoutDistribution strictly-increasing `distribution_id` via
/// Redis.
pub(crate) struct ProductionDistributionSource {
    pub(crate) resolver: Arc<ProductionPayoutResolver>,
    /// What the pool's current template pays out. The same seam the other two
    /// production JDP hooks take (`ProductionJdpAllocateResolver`,
    /// `ProductionJdpBlockSink`), so all three resolve their reward against
    /// one implementation.
    pub(crate) chain: std::sync::Arc<dyn crate::jdp_hooks::ChainView>,
    pub(crate) redis: Option<redis::aio::ConnectionManager>,
    pub(crate) network: bitcoin::Network,
    /// Pool-output recipient for tailored distributions whose own
    /// allocator has no pool output (plain Solo without a dev fee).
    pub(crate) fee_address: Option<AddressId>,
}

impl ProductionDistributionSource {
    /// A payout address as its locking script on the pool's network.
    ///
    /// `None` for an address that does not parse or does not belong to this
    /// network. Both lowering paths refuse the whole build on that rather than
    /// skipping the entry: a dropped payout would shift every later position
    /// in the coinbase vector.
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
            // A published entry whose script fails to derive would shift every
            // ext 0x0003/Payout Computation position — fail the whole build
            // instead.
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

    /// Sats-at-reference as weights, for Solo — the one mode JDP serves that
    /// has its own exact allocator and settles by recompute rather than from a
    /// snapshot. `entries` in ext 0x0003/Payout Computation order WITHOUT a
    /// pool output; the pool output script comes from `pool_addr`.
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
        // Decided once, by mode, before anything is built (see
        // `jdp_distribution_for`). A non-PPLNS mode's shares do NOT enter the
        // PPLNS window, so every failure path below returns `Unavailable`,
        // never `PoolWide`, which would pay its block to the PPLNS window.
        // ⚠️ `lookup_known`, not `lookup_mode`: this runs at ALLOCATE time,
        // before the miner's mining session exists, and `lookup_mode` guesses
        // Solo for an address it has never seen.
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
                // `known` is Some here (`ModeUnknown` returned above), but an
                // `expect` would put a panic on the money path for an
                // invariant the compiler cannot see.
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
                // The dev-fee output doubles as pool_payout when set;
                // otherwise the configured pool fee address anchors `weight_P`
                // (weight 1 ≈ dust dilution, ext 0x0003/Payout Computation
                // residual).
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
            // The kind travels with the build: Solo and Group-Solo produce
            // different payout vectors for the same address, and the mining
            // side cannot tell them apart from the owner alone.
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
        // The same `lookup_known` `build_for_miner` decides from, so the JDP
        // loop cannot conclude "the mode moved" from a gate reading the
        // builder would disagree with. An address with no mining session is
        // undecided, not Solo, so a rig blip does not tear up a session's plan.
        bp_stratum_v2::hooks::PayoutResolver::resolve_stream_known(
            self.resolver.as_ref(),
            miner_address,
        )
    }

    async fn next_distribution_id(&self) -> Option<u64> {
        let mut conn = self.redis.clone()?;
        // Atomic floor-to-wallclock + INCR: strictly increasing across
        // restarts, Redis wipes and concurrent fronts
        // (ext 0x0003/SetPayoutDistribution). Two calls in the same
        // millisecond still differ (the INCR).
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

/// Translate the engine's `CoinbaseDistributionEntry` shape into the
/// `bp_mining_job::PayoutEntry` shape consumed by `build_mining_job_from_tdp`.
/// Carries the EXACT per-output sats the distributor computed (largest-remainder
/// residuum, fixed finder bonus, solvency cap) — the coinbase builder places
/// them verbatim, never re-deriving from a percentage.
fn entries_to_payouts(entries: &[CoinbaseDistributionEntry]) -> Vec<PayoutEntry> {
    entries
        .iter()
        .map(|e| PayoutEntry {
            address: e.address.as_str().to_string(),
            // `Sats` is a signed i64 and a coinbase output is non-negative;
            // clamp so a negative value cannot wrap via `as u64` into an
            // invalid coinbase amount.
            sats: e.sats.0.max(0) as u64,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_REWARD: u64 = 5_000_000_000;

    /// The promise this flag carries gates the whole block-found emission, not
    /// just a snapshot lookup: without it nothing is emitted, so the durable
    /// `blocks_entity` row, the notification and the Blockparty history row all
    /// go missing for a block the pool served. Solo and Blockparty resolve no
    /// snapshot at all, so they always get it. Only the mode→answer decision is
    /// pinned here, not the emission itself.
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
        // And the two that DO resolve one must keep needing an engine behind
        // the list, or booking would name a snapshot nobody wrote.
        assert!(!books_without_a_snapshot(MiningMode::Pplns));
        assert!(!books_without_a_snapshot(MiningMode::GroupSolo));
    }

    /// What JDP serves each mode, pinned as the full mode→answer map.
    ///
    /// Every mode is named individually, because the answers are not
    /// interchangeable and getting one wrong is a money bug:
    ///
    /// - `PoolWide` for a non-PPLNS mode would have its block pay the
    ///   PPLNS window and book under the PPLNS fingerprint.
    /// - `Tailored` for PPLNS would build a per-miner distribution for a
    ///   miner whose accounting is the shared window.
    /// - `Nothing` for a served mode silently stops JDP working for it.
    ///
    /// Blockparty is the deliberate refusal (see `jdp_distribution_for`).
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

        // No mining session for this address, so no port has said which mode
        // it is: the state at every JDC start, since a JDC allocates before it
        // opens its mining channel. Any answer would be a guess that costs
        // money either way, so the answer is "not yet" and the caller retries.
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

    /// What a mode gets BUILT and what the mode probe REPORTS have to agree,
    /// for every mode.
    ///
    /// Two mappings off the same `MiningMode` reach the JDP loop: the plan
    /// comes from [`jdp_distribution_for`], the probe answer from
    /// `StreamKind::for_mode` (via `resolve_stream_known`), and the loop
    /// compares them through `accounting_matches_stream` to decide whether the
    /// mode moved. If they disagree for any mode, a correctly served session
    /// concludes "moved" on every frame and rebuilds its plan, burning a
    /// distribution id and pushing a frame each time.
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
            // The accounting `build_for_miner` stamps onto the entry for this
            // mode, via the same two functions it calls rather than a
            // restated copy, so swapped arms in `accounting_for` fail here.
            let built = match jdp_distribution_for(Some(mode)) {
                JdpDistributionFor::PoolWide => Some(Acct::PoolWide),
                JdpDistributionFor::Tailored(kind) => Some(accounting_for(kind, &miner)),
                // Nothing is built, so there is nothing for the probe to
                // disagree with: the session lands in the refused state, whose
                // retry is time-throttled and never asks about the mode.
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

    /// The two tailored modes must not be swapped: each names the builder
    /// that reads ITS weights. A Group-Solo miner built as Solo would get a
    /// single-payout coinbase and its group members nothing.
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
                                                         // The two outputs sum to exactly the reward.
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
        // Dev address set but percent left at the default of 0.0: no
        // zero-value dev output, a single 100 %-to-miner payout.
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

    /// Paying the reward directly gives the same satoshis as the 100 %
    /// percent formula for every reward that occurs: every subsidy era plus
    /// fees, up to the whole money supply.
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
