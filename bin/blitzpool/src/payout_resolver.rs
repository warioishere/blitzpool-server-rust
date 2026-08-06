// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production coinbase payout resolver — Phase 7.4d.
//!
//! Cross-cutting wiring that gives BOTH SV1 + SV2 the correct
//! per-mode coinbase output distribution at every template-broadcast
//! moment. Pre-7.4d both protocols hardcoded "100% to authorized
//! miner" regardless of port mode (PPLNS / Group-Solo crediting was
//! still correct via the accept-hook fan-out — only the on-chain
//! coinbase shape was wrong, which means PPLNS members received
//! 0 sats when a block landed even though their shares were
//! windowed in PG).
//!
//! ## Resolution dispatch
//!
//! For each `(miner_address, reward_sats)` resolve request:
//!
//! 1. Consult [`BlitzpoolModeGate::lookup_mode`] for the address.
//! 2. **Solo** → [`solo_payouts`] (single 100%-to-miner OR split
//!    with `dev_fee_address`/`dev_fee_percent` when configured).
//! 3. **Pplns** → [`PplnsEngine::build_distribution`] →
//!    `Vec<CoinbaseDistributionEntry>` → `Vec<PayoutEntry>`.
//! 4. **GroupSolo** → [`GroupSoloEngine::build_distribution`] (need
//!    the group_id from the gate's `MiningModeResult.group_id` field
//!    plus the miner's own `AddressId` as the finder).
//!
//! ## Adapter strategy
//!
//! Both SV1 (`bp_stratum_v1::PayoutResolver`) + SV2
//! (`bp_stratum_v2::PayoutResolver`) traits land on
//! [`ProductionPayoutResolver`] directly — the trait shapes are
//! identical aside from the address-shape (`&str` vs `&AddressId`).
//! No adapter shim crate needed; we impl both traits on the same
//! struct.
//!
//! ## Performance notes
//!
//! `build_distribution` calls return `Arc<DistributionResult>` and
//! the engines short-circuit duplicate reward-sats lookups via an
//! `InflightResultCache`. The resolver is called at most once per
//! `(template-broadcast × connection)` event, so per-connection
//! per-template cadence is ~30 s. The cache compresses concurrent
//! lookups across connections so total throughput is bounded by the
//! cache's TTL.

use std::sync::Arc;

use async_trait::async_trait;
use bp_blockparty_engine::BlockpartyApi;
use bp_common::{AddressId, MiningMode, Sats};
use bp_group_solo_engine::engine::GroupSoloEngine;
/// Re-exported so the wiring keeps one import path for the solo split.
pub(crate) use bp_mining_job::SoloFeeConfig;
use bp_mining_job::{solo_payouts, PayoutEntry, ResolvedPayouts};
use bp_pplns::CoinbaseDistributionEntry;
use bp_pplns_engine::engine::PplnsEngine;
use bp_stratum_v2::jdp_server::TailoredDistribution;
use tracing::{error, warn};
use uuid::Uuid;

use crate::engines::BlitzpoolModeGate;

/// The single production [`PayoutResolver`] impl. Holds clones of the
/// engines + the mode gate; cheap to clone (each field is internally
/// `Arc` or already-clone-friendly).
#[derive(Clone)]
pub(crate) struct ProductionPayoutResolver {
    mode_gate: Arc<BlitzpoolModeGate>,
    pplns: Option<PplnsEngine>,
    group_solo: GroupSoloEngine,
    solo_fee: SoloFeeConfig,
    /// Optional Blockparty service handle. When `None` the Blockparty
    /// arm + the Solo pending-fee guard short-circuit to standard Solo
    /// payouts — i.e. a deployment without the Blockparty feature wired
    /// behaves exactly as before.
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
    /// came from the engine AND the engine's snapshot landed. It is returned
    /// from the same call that produced the list on purpose. Measuring it with a
    /// second, independent `build_distribution` let the two disagree — the probe
    /// could succeed and the real build then fall back to a solo split while the
    /// flag still said "engine-backed", promising a booking against a snapshot
    /// that names a 100 %-to-one-address list nobody stored.
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
                // `pending_party_fee_route`). Without the guard the
                // admin would pocket the full block reward before the
                // members confirm the splits.
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

/// Does the pool serve this mode a payout distribution over JDP at all?
///
/// **Blockparty does not get one.** A Blockparty group is a rental: the
/// hashrate is pointed straight at an address and the pool splits the
/// coinbase by fixed per-member percentages read from Postgres. A
/// job-declaring client exists so a miner can pick its own transaction
/// set, which a rental customer neither does nor wants — so there is
/// nothing for JDP to add, and the pool does not offer it.
///
/// This is a REFUSAL, not an omission. The Blockparty arm of
/// `build_for_miner` used to build a tailored distribution from the
/// Blockparty allocator, so the whole path existed and any Blockparty
/// admin pointing a JDC at the pool would have exercised it — untested
/// money surface for a feature that is not offered. Answering
/// `Unavailable` denies the session the pool-wide distribution too (see
/// [`TailoredDistribution`]), so it can declare nothing at all rather
/// than declare something the pool cannot account for.
///
/// A `match`, not an `if`: which modes JDP serves is exactly the kind of
/// per-mode decision a fourth mode must not be able to fall out of.
fn jdp_serves_a_distribution(mode: MiningMode) -> bool {
    match mode {
        MiningMode::Pplns | MiningMode::Solo | MiningMode::GroupSolo => true,
        MiningMode::Blockparty => false,
    }
}

/// Did the build fail because NOTHING in the window holds a share?
///
/// Matched as its own condition because it is the one build failure that
/// must not become "serve no job": the window fills only from accepted
/// shares and shares come only from jobs, so refusing would leave a fresh
/// window unable to ever start. Every OTHER failure keeps the no-job
/// answer — a window that cannot be read may be full of miners whose
/// claims are simply invisible right now, and handing the block to one
/// connecting miner would rob all of them.
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
            // PPLNS mode was published into the gate but the engine
            // is disabled at this deployment — config inconsistency.
            // Fall back to solo + warn.
            error!(
                miner_address,
                "PPLNS mode in gate but `[pplns]` is absent from config; serving NO JOB"
            );
            return (ResolvedPayouts::none(), false);
        };
        // The pool-wide build first. It is shared by every PPLNS
        // connection, so it cannot name a claimant — an empty window comes
        // back as `NoScoredMiners` and is answered per-miner below.
        let built = match pplns.build_distribution(reward_sats).await {
            Ok(result) => Some(result),
            Err(err) if is_empty_share_window(&err) => {
                // Nobody in the window holds a share. The distribution the
                // weight model would otherwise produce pays the WHOLE
                // block to the pool output, and serving no job at all
                // would deadlock a fresh window: the window only fills
                // from accepted shares, and shares only come from jobs.
                // So this miner claims the block — nobody else has a claim
                // to lose, and the pool still takes exactly its fee.
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
            // The build can succeed while its snapshot write does not — the
            // engine keeps the distribution on purpose, because failing it would
            // hand this miner the whole block. But the fingerprint then names a
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
                // The §4 evaluation at this template's revenue — the
                // same formula a JDC runs with its own template value.
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
                            "PPLNS §4 evaluation failed; serving NO JOB"
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
        // Single output at `route.percent` (100% for the pending-fee route) →
        // exact sats. The coinbase builder's remainder guard tops up any
        // sub-1-sat floor loss on this sole output.
        let sats = ((route.percent as f64 / 100.0) * reward_sats as f64).floor() as u64;
        Some(vec![PayoutEntry {
            address: route.fee_address.into_inner(),
            sats,
        }])
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
        // Group-Solo engine bumps the finder's payout via the
        // `finder_bonus_sats` config knob when emitting the
        // distribution.
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
                // The §4 evaluation at this template's revenue.
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
                            "Group-Solo §4 evaluation failed; serving NO JOB"
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
        // Single source of truth: same mode lookup the payout resolution uses,
        // mapped to a stream. A Solo address (incl. a Blockparty admin whose
        // party is still DRAFT and falls through to a 1-output fee coinbase)
        // routes to the Solo stream; everything else to Default.
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
}

// ─── Ext 0x0003 distribution source (push model) ──────────────────

/// Production [`bp_stratum_v2::jdp_server::PayoutDistributionSource`]:
/// builds the pool-wide PPLNS distribution for the publisher and
/// tailored distributions (Solo or Group-Solo — see
/// [`jdp_serves_a_distribution`]) once an allocate reveals a session's
/// identity, and allocates the §3.1 strictly-increasing
/// `distribution_id` via Redis.
pub(crate) struct ProductionDistributionSource {
    pub(crate) resolver: Arc<ProductionPayoutResolver>,
    pub(crate) tdp: bp_template_distribution::TdpHandle,
    pub(crate) redis: Option<redis::aio::ConnectionManager>,
    pub(crate) network: bitcoin::Network,
    /// Pool-output recipient for tailored distributions whose own
    /// allocator has no pool output (plain Solo without a dev fee).
    pub(crate) fee_address: Option<AddressId>,
}

impl ProductionDistributionSource {
    fn reference_revenue(&self) -> Option<u64> {
        self.tdp
            .current_snapshot()
            .new_template
            .as_ref()
            .map(|t| t.coinbase_tx_value_remaining)
    }

    /// Lower a weight-native engine distribution into the wire shape.
    fn lower_weight_distribution(
        &self,
        d: &bp_pplns::WeightDistribution,
        fingerprint: Option<[u8; 32]>,
        bookable: bool,
    ) -> Option<bp_stratum_v2::jdp_server::BuiltPayoutDistribution> {
        let script_of = |addr: &str| -> Option<Vec<u8>> {
            bp_mining_job::address_to_script(self.network, addr)
                .ok()
                .map(|s| s.to_bytes())
        };
        let pool_script = script_of(d.fee_address.as_str())?;
        let mut payouts = Vec::new();
        let mut dust_limits = Vec::new();
        for entry in d.published() {
            // A published entry whose script fails to derive would shift
            // every §4 position — fail the whole build instead.
            let script = script_of(entry.address.as_str())?;
            payouts.push(bp_stratum_v2::jdp::payout_distribution::WeightedOutput {
                script_pubkey: script,
                weight: entry.wire_weight,
            });
            dust_limits.push(entry.dust_limit);
        }
        Some(bp_stratum_v2::jdp_server::BuiltPayoutDistribution {
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

    /// Sats-at-reference as weights, for Solo — the one mode JDP serves
    /// that has its own exact allocator and settles by recompute rather
    /// than from a snapshot. `entries` in §4 order WITHOUT a pool output;
    /// the pool output script comes from `pool_addr`.
    fn lower_exact_entries(
        &self,
        pool_addr: &str,
        pool_weight: u64,
        entries: &[(String, u64)],
        reference_reward_sats: u64,
    ) -> Option<bp_stratum_v2::jdp_server::BuiltPayoutDistribution> {
        let script_of = |addr: &str| -> Option<Vec<u8>> {
            bp_mining_job::address_to_script(self.network, addr)
                .ok()
                .map(|s| s.to_bytes())
        };
        let pool_script = script_of(pool_addr)?;
        let mut payouts = Vec::new();
        let mut dust_limits = Vec::new();
        for (addr, sats) in entries {
            if *sats == 0 {
                continue;
            }
            payouts.push(bp_stratum_v2::jdp::payout_distribution::WeightedOutput {
                script_pubkey: script_of(addr)?,
                weight: *sats,
            });
            dust_limits.push(bp_pplns::DUST_LIMIT_SATS as u32);
        }
        Some(bp_stratum_v2::jdp_server::BuiltPayoutDistribution {
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
    async fn build_pool_wide(&self) -> Option<bp_stratum_v2::jdp_server::BuiltPayoutDistribution> {
        let t_ref = self.reference_revenue()?;
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
        // Everything below `Pplns` is a mode whose shares do NOT enter
        // the PPLNS window, so every failure path here returns
        // `Unavailable`, never `PoolWide`. Serving the pool-wide
        // distribution to such a miner pays its block to the PPLNS
        // window and books it under the PPLNS fingerprint.
        let lookup = self.resolver.mode_gate.lookup_mode(miner_address.as_str());
        if lookup.mode == MiningMode::Pplns {
            return TailoredDistribution::PoolWide;
        }
        // Decided by mode BEFORE anything is built, and by an exhaustive
        // `match` (see [`jdp_serves_a_distribution`]) so a mode cannot fall
        // out of it silently.
        if !jdp_serves_a_distribution(lookup.mode) {
            warn!(
                miner = miner_address.as_str(),
                mode = ?lookup.mode,
                "jdp distribution source: this mode is not served over JDP — serving NO \
                 distribution"
            );
            return TailoredDistribution::Unavailable;
        }
        let Some(t_ref) = self.reference_revenue() else {
            warn!(
                miner = miner_address.as_str(),
                "jdp distribution source: no reference revenue yet — no tailored distribution"
            );
            return TailoredDistribution::Unavailable;
        };
        let built = match lookup.mode {
            MiningMode::Pplns => unreachable!("handled above"),
            MiningMode::GroupSolo => {
                let Some(group_id) = lookup
                    .group_id
                    .as_deref()
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
            MiningMode::Solo => {
                let entries: Vec<(String, u64)> =
                    solo_payouts(miner_address.as_str(), &self.resolver.solo_fee, t_ref)
                        .into_iter()
                        .map(|p| (p.address, p.sats))
                        .collect();
                // The dev-fee output doubles as pool_payout when set;
                // otherwise the configured pool fee address anchors
                // `weight_P` (weight 1 ≈ dust dilution, §4 residual).
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
            MiningMode::Blockparty => {
                unreachable!("refused by jdp_serves_a_distribution above")
            }
        };
        match built {
            Some(b) => TailoredDistribution::Built(Box::new(b)),
            // `lower_*` failed (unusable address / weight overflow).
            // Still not the pool-wide distribution's problem.
            None => TailoredDistribution::Unavailable,
        }
    }

    async fn next_distribution_id(&self) -> Option<u64> {
        let mut conn = self.redis.clone()?;
        // Atomic floor-to-wallclock + INCR: strictly increasing across
        // restarts, Redis wipes and concurrent fronts (§3.1). Two calls
        // in the same millisecond still differ (the INCR).
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
            // `Sats` is a signed i64; a coinbase output can only ever be a
            // non-negative amount. Clamp defensively so a (should-be-impossible)
            // negative distributor value can't wrap to ~1.8e19 via `as u64` and
            // blow up the coinbase as bad-cb-amount.
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
    /// snapshot at all, so withholding it from them buys nothing and costs that.
    ///
    /// Only the mode→answer decision is pinned here. That the emission really
    /// follows from it is a property of the block-found fan-out and needs the
    /// full-stack regtest that is still missing.
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

    /// Which modes JDP serves, pinned as a mode→answer decision.
    ///
    /// Blockparty is the refusal: a rental points its hashrate at an address
    /// and the pool splits the coinbase from Postgres, so a job-declaring
    /// client adds nothing. Before this, `build_for_miner` built a tailored
    /// distribution for it out of the Blockparty allocator — a reachable,
    /// untested money path for a feature the pool does not offer.
    ///
    /// The other three must stay served, or JDP silently stops working for
    /// them: PPLNS rides the pool-wide distribution, Solo and Group-Solo get
    /// a tailored one.
    #[test]
    fn jdp_serves_every_mode_except_blockparty() {
        assert!(!jdp_serves_a_distribution(MiningMode::Blockparty));
        for served in [MiningMode::Pplns, MiningMode::Solo, MiningMode::GroupSolo] {
            assert!(
                jdp_serves_a_distribution(served),
                "{served:?} must keep its JDP distribution — refusing it serves no job at all"
            );
        }
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
        // Dev address set but percent left at the production default of 0.0
        // (operator forgot `dev_fee_percent`). Must NOT emit a zero-value dev
        // output — collapse to a single 100 %-to-miner payout.
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
