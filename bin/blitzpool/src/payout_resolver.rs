// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production coinbase payout resolver.
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
use bp_common::{AddressId, MiningMode, PayoutIdentity, Sats};
use bp_group_solo_engine::engine::GroupSoloEngine;
/// Re-exported so the wiring keeps one import path for the solo split.
pub(crate) use bp_mining_job::SoloFeeConfig;
use bp_mining_job::{is_payable_identity, solo_payouts, PayoutEntry, ResolvedPayouts};
use bp_pplns::CoinbaseDistributionEntry;
use bp_pplns_engine::engine::PplnsEngine;
use bp_stratum_v2::bridge::DistributionAccounting;
use bp_stratum_v2::jdp_server::TailoredDistribution;
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::engines::BlitzpoolModeGate;
use crate::payout_identities::PayoutIdentityDirectory;

/// The single production `PayoutResolver` impl. Holds clones of the
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
    /// `payout_id → PayoutIdentity` for the rotating identities of currently
    /// connected miners. See [`PayoutIdentityDirectory`] for why the descriptor
    /// arrives this way and not down the connection.
    identities: Arc<PayoutIdentityDirectory>,
    /// The network the coinbase renders against — carried so
    /// [`weight_entries_to_payouts`] can ask
    /// [`bp_mining_job::is_payable_identity`], which is the renderer's own
    /// question and therefore network-aware. Not `bp_config::Network`: the
    /// mapping belongs at the wiring edge (`network::config_network_to_bitcoin`),
    /// and one more copy of it in here is `CLAUDE.md`'s opening failure mode.
    network: bitcoin::Network,
}

impl ProductionPayoutResolver {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        mode_gate: Arc<BlitzpoolModeGate>,
        pplns: Option<PplnsEngine>,
        group_solo: GroupSoloEngine,
        solo_fee: SoloFeeConfig,
        blockparty: Option<Arc<dyn BlockpartyApi>>,
        identities: Arc<PayoutIdentityDirectory>,
        network: bitcoin::Network,
    ) -> Self {
        Self {
            mode_gate,
            pplns,
            group_solo,
            solo_fee,
            blockparty,
            identities,
            network,
        }
    }

    /// **How this pool pays a `payout_id`** — one lookup, one place.
    ///
    /// Every mode's payout builder goes through here for a miner-supplied
    /// identity, so "rotating miners are paid a derived script" is a property of
    /// one function rather than of four arms agreeing. Pool-side addresses (the
    /// Solo dev fee, the Blockparty pending-fee route, a group's operator-entered
    /// member addresses) deliberately do NOT: they are `Static` at their
    /// construction site, which is what keeps the pool-fee address unrotatable.
    fn identity_of(&self, payout_id: &str) -> PayoutIdentity {
        self.identities.identity_for(payout_id)
    }

    /// Solo's payout list for `miner_address`.
    ///
    /// Exists because the Solo split is reached from six places — the Solo arm
    /// and five Blockparty fallbacks — and every one of them has to resolve the
    /// identity the same way. Five of them spelling
    /// `solo_payouts(miner_address, …)` and one spelling
    /// `solo_payouts(&self.identity_of(miner_address), …)` is precisely how a
    /// rotating miner ends up paid a hash on the fallback path only, which is
    /// the shape of `CLAUDE.md`'s 2026-08-03 entry.
    fn solo_split(&self, miner_address: &str, reward_sats: u64) -> Vec<PayoutEntry> {
        solo_payouts(
            &self.identity_of(miner_address),
            &self.solo_fee,
            reward_sats,
        )
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
                    ResolvedPayouts::unsnapshotted(self.solo_split(miner_address, reward_sats)),
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
/// Pure and total on purpose. It is the one place the money question
/// "which distribution does this miner get?" is answered, so a mode added
/// later cannot reach a builder it was never classified for — and because
/// it takes only a [`MiningMode`], the answer is testable without engines,
/// Redis or a template feed.
///
/// **Blockparty gets nothing.** A Blockparty group is a rental: the
/// hashrate is pointed straight at an address and the pool splits the
/// coinbase by fixed per-member percentages read from Postgres. A
/// job-declaring client exists so a miner can pick its own transaction
/// set, which a rental customer neither does nor wants — so there is
/// nothing for JDP to add, and the pool does not offer it.
///
/// That is a REFUSAL, not an omission. `build_for_miner` used to build a
/// tailored distribution for it out of the Blockparty allocator, so the
/// whole path existed and any Blockparty admin pointing a JDC at the pool
/// would have exercised it — untested money surface for a feature that is
/// not offered. [`JdpDistributionFor::Nothing`] denies the session the
/// pool-wide distribution too (see [`TailoredDistribution`]), so it can
/// declare nothing at all rather than declare something the pool cannot
/// account for.
fn jdp_distribution_for(mode: Option<MiningMode>) -> JdpDistributionFor {
    match mode {
        // No mining session for this address, so no port has declared its
        // mode. Taking the gate's Solo default here published a Solo plan for
        // whoever allocated first — and a JDC allocates ~8 s before its
        // channel opens, so that was every JDC, every start.
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
/// A named function and not an inline `match`, because it is the second half
/// of the mode→answer table [`jdp_distribution_for`] starts, and the JDP loop
/// compares its result against `StreamKind::for_mode` to decide whether an
/// address's mode moved. A test that restates this mapping instead of calling
/// it proves nothing about the pair actually agreeing.
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
                // The ext 0x0003/Payout Computation evaluation at this
                // template's revenue — the same formula a JDC runs with its
                // own template value.
                match result.distribution.payout_entries_at(reward_sats) {
                    Ok(entries) => (
                        ResolvedPayouts {
                            entries: weight_entries_to_payouts(
                                entries,
                                &self.identities,
                                self.network,
                            ),
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
        // Single output at `route.percent` (100% for the pending-fee route) →
        // exact sats. The coinbase builder's remainder guard tops up any
        // sub-1-sat floor loss on this sole output.
        let sats = ((route.percent as f64 / 100.0) * reward_sats as f64).floor() as u64;
        Some(vec![PayoutEntry::static_address(
            route.fee_address.into_inner(),
            sats,
        )])
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
            return self.solo_split(miner_address, reward_sats);
        };
        let Some(gid_str) = group_id_str else {
            warn!(
                miner_address,
                "Blockparty mode published WITHOUT a group_id; falling back to solo"
            );
            return self.solo_split(miner_address, reward_sats);
        };
        let Ok(group_id) = Uuid::parse_str(gid_str) else {
            warn!(
                miner_address,
                gid_str, "Blockparty group_id failed to parse as UUID; falling back to solo"
            );
            return self.solo_split(miner_address, reward_sats);
        };
        match svc.build_payouts(group_id, Sats(reward_sats as i64)).await {
            Ok(Some(result)) => entries_to_payouts(&result.payouts, &self.identities),
            Ok(None) => {
                warn!(
                    miner_address,
                    %group_id,
                    "Blockparty group not found; falling back to solo"
                );
                self.solo_split(miner_address, reward_sats)
            }
            Err(err) => {
                warn!(
                    %err,
                    miner_address,
                    %group_id,
                    "Blockparty distribution build failed; falling back to solo"
                );
                self.solo_split(miner_address, reward_sats)
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
                // The ext 0x0003/Payout Computation evaluation at this
                // template's revenue.
                match result.distribution.payout_entries_at(reward_sats) {
                    Ok(entries) => (
                        ResolvedPayouts {
                            entries: weight_entries_to_payouts(
                                entries,
                                &self.identities,
                                self.network,
                            ),
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
    /// one implementation — this one used to re-derive it from a raw
    /// `TdpHandle`, and `ChainView::reference_revenue`'s own doc says the two
    /// must be the same number.
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
    ) -> Option<bp_stratum_v2::jdp_server::BuiltPayoutDistribution> {
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

/// Lower a weight-native engine distribution into the wire shape.
///
/// **A rotating entry makes the whole distribution unpublishable**, and this is
/// the same refusal the `TailoredMode::Solo` arm of
/// `ProductionDistributionSource::build_for_miner` writes for a rotating miner —
/// one reason, stated twice because the two reach it from different directions,
/// and the alternative is a fall-through that publishes the wrong thing.
///
/// A published ext 0x0003 distribution is a list of FIXED `script_pubkey` bytes
/// under a distribution id, which a JDC reuses across blocks. There is no height
/// here, so lowering a rotating identity would pin that miner to whichever
/// address this one build derived — for every block the JDC ever builds against
/// this distribution id. Rotation in name only, and the miner who configured an
/// xpub would never see its second address.
///
/// `None` costs the JDC its published distribution and pays every one of these
/// miners correctly through the mining path instead, where `payout_script` has
/// the height.
///
/// A free function taking the two things it reads, for the reason
/// [`weight_entries_to_payouts`] is one: the refusal is then provable without a
/// live `GroupSoloEngine` (hence a Postgres pool) behind `self.resolver`. As a
/// method it had no test at all, and one rotating miner in the window silences
/// ext 0x0003 for the entire pool — a regression in either direction was
/// unobservable.
fn lower_weight_distribution(
    d: &bp_pplns::WeightDistribution,
    identities: &PayoutIdentityDirectory,
    network: bitcoin::Network,
    fingerprint: Option<[u8; 32]>,
    bookable: bool,
) -> Option<bp_stratum_v2::jdp_server::BuiltPayoutDistribution> {
    let script_of = |addr: &str| -> Option<Vec<u8>> {
        bp_mining_job::address_to_script(network, addr)
            .ok()
            .map(|s| s.to_bytes())
    };
    let pool_script = script_of(d.fee_address.as_str())?;
    let mut payouts = Vec::new();
    let mut dust_limits = Vec::new();
    for entry in d.published() {
        // `match` and not `if identity.rotates()`: this arm chooses what to
        // *do* with an identity, which is the exhaustive question. The key is
        // a ledger key, so for a rotating miner `script_of` below would be
        // handed a 47-char `payout_id` and answer `None` — the right answer,
        // reached for the wrong reason and logged as if the miner had
        // configured a broken address. Say it explicitly instead.
        match identities.identity_for(entry.address.as_str()) {
            PayoutIdentity::Rotating { payout_id, .. } => {
                warn!(
                    payout_id = payout_id.as_str(),
                    entries = d.entries.len(),
                    "jdp distribution source: a distribution member's payout identity rotates \
                     per block, which a published distribution's fixed scripts cannot express \
                     — no published distribution"
                );
                return None;
            }
            PayoutIdentity::Static { .. } => {}
        }
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

#[async_trait]
impl bp_stratum_v2::jdp_server::PayoutDistributionSource for ProductionDistributionSource {
    async fn build_pool_wide(&self) -> Option<bp_stratum_v2::jdp_server::BuiltPayoutDistribution> {
        let t_ref = self.chain.reference_revenue()?;
        let pplns = self.resolver.pplns.as_ref()?;
        let result = match pplns.build_distribution(t_ref).await {
            Ok(r) => r,
            Err(err) => {
                warn!(%err, "jdp distribution source: PPLNS build failed — nothing to publish");
                return None;
            }
        };
        lower_weight_distribution(
            &result.distribution,
            &self.resolver.identities,
            self.network,
            Some(result.payouts_fingerprint()),
            result.snapshot_written,
        )
    }

    async fn build_for_miner(&self, miner_address: &AddressId) -> TailoredDistribution {
        // Once, by mode, before anything is built — see
        // [`jdp_distribution_for`]. Everything that is not PPLNS is a mode
        // whose shares do NOT enter the PPLNS window, so every failure
        // path below returns `Unavailable`, never `PoolWide`: serving the
        // pool-wide distribution to such a miner pays its block to the
        // PPLNS window and books it under the PPLNS fingerprint.
        // ⚠️ `lookup_known`, not `lookup_mode`: this runs at ALLOCATE time,
        // before the miner's mining session exists, and `lookup_mode` answers
        // Solo for an address it has never seen. Publishing off that guess is
        // how a PPLNS miner came to be handed a Solo distribution — and a
        // Group-Solo finder one that pays him instead of his group.
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
                // Total rather than an unwrap: `ModeUnknown` already
                // returned above, so `known` is Some here — but expressing
                // that with `expect` would put a panic on the money path for
                // an invariant the compiler cannot see.
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
                    Ok(result) => lower_weight_distribution(
                        &result.distribution,
                        &self.resolver.identities,
                        self.network,
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
                let identity = self.resolver.identity_of(miner_address.as_str());
                // **A REFUSAL, not a fallback** — the idiom `jdp_distribution_for`
                // established for Blockparty, and the same answer the
                // base-protocol allocate path gives (`jdp_hooks.rs`).
                //
                // A published ext 0x0003 distribution is a list of FIXED
                // `script_pubkey` bytes under a distribution id, and a JDC reuses
                // it across blocks. There is no height here and no way to change
                // it per block, so a rotating identity has no expressible form:
                // lowering one would pin every future block to a script derived
                // at whatever index this build happened to pick — rotation in
                // name only, and a miner who configured an xpub would never see
                // its second address.
                //
                // `Unavailable` costs this JDC its tailored distribution and pays
                // it correctly through the mining path instead. `match` and not
                // `if identity.rotates()`: this arm chooses what to *do* with an
                // identity, which is the exhaustive question.
                match &identity {
                    PayoutIdentity::Rotating { payout_id, .. } => {
                        warn!(
                            miner = miner_address.as_str(),
                            payout_id = payout_id.as_str(),
                            "jdp distribution source: this miner's payout identity rotates per \
                             block, which a published distribution's fixed scripts cannot \
                             express — no tailored distribution"
                        );
                        return TailoredDistribution::Unavailable;
                    }
                    PayoutIdentity::Static { .. } => {}
                }
                let entries: Vec<(String, u64)> =
                    solo_payouts(&identity, &self.resolver.solo_fee, t_ref)
                        .into_iter()
                        .map(|p| (p.payout_id().to_string(), p.sats))
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
            // `lower_*` failed (unusable address / weight overflow).
            // Still not the pool-wide distribution's problem.
            None => TailoredDistribution::Unavailable,
        }
    }

    async fn current_mode(&self, miner_address: &AddressId) -> Option<bp_common::StreamKind> {
        // The same `lookup_known` [`Self::build_for_miner`] decides from, so
        // the JDP loop cannot conclude "the mode moved" from a gate reading
        // the builder would disagree with. `lookup_known` and not
        // `lookup_mode`: an address with no mining session is undecided, not
        // Solo, and here that difference is the difference between leaving a
        // session's plan alone and tearing it up every time a rig blips.
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

/// Translate the engine's `CoinbaseDistributionEntry` shape into the
/// `bp_mining_job::PayoutEntry` shape consumed by `build_mining_job_from_tdp`.
/// Carries the EXACT per-output sats the distributor computed (largest-remainder
/// residuum, fixed finder bonus, solvency cap) — the coinbase builder places
/// them verbatim, never re-deriving from a percentage.
///
/// **Blockparty only, and it REFUSES a rotating identity.** Not an omission — a
/// decision, and the same one `jdp_distribution_for` writes as an explicit
/// `Nothing` arm rather than a fall-through. A Blockparty group is a rental: its
/// members are enrolled by an admin into `blockparty_member`, out of band, and
/// the hashing device never presents an identity for them. There is no
/// channel-open at which a member could supply a descriptor, so a `Rotating` here
/// means a member address collided with a published `payout_id` — a bug, not a
/// miner to pay.
///
/// The refusal is an empty list, which is `ResolvedPayouts::none()` — the pool's
/// existing "serve no job" answer. Deliberately NOT a fall-through to
/// `solo_split`: that pays this block's whole reward to the connecting miner and
/// nothing to the group, which is the wrong money rather than no money. And
/// deliberately not "skip that one entry": the remaining percentages would no
/// longer sum to the group's split, so the coinbase would silently pay a
/// distribution no admin ever configured.
fn entries_to_payouts(
    entries: &[CoinbaseDistributionEntry],
    identities: &PayoutIdentityDirectory,
) -> Vec<PayoutEntry> {
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        // `match`, not `is_some()` on a descriptor: the refusal has to be an arm
        // the compiler can see, per `CLAUDE.md`.
        match identities.identity_for(e.address.as_str()) {
            PayoutIdentity::Static { .. } => out.push(PayoutEntry::static_address(
                e.address.as_str(),
                // `Sats` is a signed i64; a coinbase output can only ever be a
                // non-negative amount. Clamp defensively so a
                // (should-be-impossible) negative distributor value can't wrap
                // to ~1.8e19 via `as u64` and blow up the coinbase as
                // bad-cb-amount.
                e.sats.0.max(0) as u64,
            )),
            PayoutIdentity::Rotating { .. } => {
                error!(
                    payout_id = e.address.as_str(),
                    entries = entries.len(),
                    "Blockparty distribution contains a ROTATING identity; Blockparty members are \
                     operator-entered addresses and this mode does not derive scripts — refusing \
                     the whole distribution and serving NO JOB"
                );
                return Vec::new();
            }
        }
    }
    out
}

/// Translate a §4 weight-model evaluation (`payout_entries_at`) into coinbase
/// payout entries.
///
/// **PPLNS and Group-Solo both resolve through here**, which is the point: this
/// was the same three-line closure written twice, once per mode, and
/// `CLAUDE.md`'s opening line is about exactly that shape. It is also where the
/// two modes stop paying a literal address once identities can rotate — one
/// edit, both modes, instead of the "fixed twice in two PRs a day apart" entry.
///
/// The entry keys are **ledger keys**, not addresses — for a rotating miner the
/// key is a 47-char `payout_id`, and the script it pays comes from the
/// descriptor at this block's height. Hence the directory lookup: handing the
/// key to `PayoutEntry::static_address` verbatim, which is what this did while
/// every identity was `Static`, would put a hash where a script has to go.
///
/// # Why an unpayable entry refuses the WHOLE list
///
/// The distribution that produced these entries already filtered its rows
/// through `is_payable_payout_key` against the *same* resolution
/// (`bp_coinbase_snapshot::resolve_derived_keys`, Amendment 2) — the filter and
/// this lowering are two reads of one answer, so an unpayable key arriving here
/// means they disagreed. There is no safe way to absorb that disagreement one
/// entry at a time:
///
/// - **Dropping the entry** hands its satoshis to the pool output, because the
///   pool output is the §4 residual of whatever the payout entries do not claim.
///   That is the pool taking more than its fee — the one thing `CLAUDE.md` says
///   it must never do — and under PPLNS the miner would *also* be credited at
///   settlement, since settlement books from the block's own coinbase.
/// - **Paying the key as an address** is what Amendment 2's gap actually is:
///   `address_to_script` refuses an `xpb…` hash, `build_payout_outputs`
///   propagates it with `?`, and `MiningJobCache::get_or_build(…).ok()?` in the
///   SV1 client turns that into no `mining.notify` for every connection sharing
///   this payout set — with no log line at all.
///
/// An empty list is `ResolvedPayouts::none()`, the pool's existing "serve no
/// job" answer: this template is lost for this payout set, loudly, and the next
/// build (≤ the 30 s inputs cache) re-resolves and drops the key at the filter
/// instead — where the weight model withholds its value correctly.
///
/// The exhaustive `match` lives inside `is_payable_identity`, which is the
/// point: it is the renderer's own predicate, three lines from `payout_script`,
/// and asking it here rather than re-deriving "can we pay this" is what stops a
/// third answer to that question from existing.
fn weight_entries_to_payouts(
    entries: Vec<(AddressId, u64)>,
    identities: &PayoutIdentityDirectory,
    network: bitcoin::Network,
) -> Vec<PayoutEntry> {
    let mut out = Vec::with_capacity(entries.len());
    let total = entries.len();
    for (key, sats) in entries {
        let identity = identities.identity_for(key.as_str());
        if !is_payable_identity(network, &identity) {
            error!(
                payout_id = key.as_str(),
                entries = total,
                %network,
                "a distribution entry's ledger key resolves to an identity this coinbase cannot \
                 pay — the build-time payability filter and this lowering disagreed (a rotating \
                 identity forgotten by the directory, or a wrong-network address); refusing the \
                 whole distribution and serving NO JOB rather than paying its satoshis to the pool"
            );
            return Vec::new();
        }
        out.push(PayoutEntry { identity, sats });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_REWARD: u64 = 5_000_000_000;

    /// The miner argument to [`solo_payouts`]. These cases are about the dev-fee
    /// split, which is the same arithmetic for either identity variant; the
    /// rotating side of the Solo path is covered where it is observable — the
    /// derived-script regtest gate — not here, where nothing renders a script.
    fn miner(address: &str) -> PayoutIdentity {
        PayoutIdentity::static_address_verbatim(address)
    }

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

    /// What JDP serves each mode, pinned as the full mode→answer map.
    ///
    /// Every mode is named individually rather than looped, because the
    /// three answers are not interchangeable and getting one wrong is a
    /// money bug, not a routing bug:
    ///
    /// - `PoolWide` for a non-PPLNS mode would have its block pay the
    ///   PPLNS window and book under the PPLNS fingerprint.
    /// - `Tailored` for PPLNS would build a per-miner distribution for a
    ///   miner whose accounting is the shared window.
    /// - `Nothing` for a served mode silently stops JDP working for it.
    ///
    /// Blockparty is the deliberate refusal: a rental points its hashrate
    /// at an address and the pool splits the coinbase from Postgres, so a
    /// job-declaring client adds nothing. `build_for_miner` used to build
    /// it one anyway, out of the Blockparty allocator — a reachable,
    /// untested money path for a feature the pool does not offer.
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

        // The fifth answer, and the one that used to be missing: no mining
        // session for this address, so no port has said which mode it is.
        //
        // This is not an edge case but the state at every JDC start — a JDC
        // allocates ~8 s before it opens its mining channel, and the gate only
        // learns an address when a session registers. Answering anything here
        // is a guess, and both guesses cost money in opposite directions: a
        // tailored plan pays one miner out of a shared window, the pool-wide
        // one pays a Solo miner's block into the PPLNS window. So the answer
        // is "not yet", and the caller retries.
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
    /// mode moved. Let those two disagree for any mode and a session correctly
    /// served would conclude "moved" on every single frame — rebuilding its
    /// plan, burning a distribution id and pushing a frame, per frame, forever.
    ///
    /// So it is pinned here rather than left to the fact that today they
    /// happen to line up.
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
            // mode, by calling the same two functions it calls — not by
            // restating them. Swap the arms inside `accounting_for` and this
            // test goes red; a restated copy would stay green while every
            // Group-Solo JDP session got a plan the mining side then refuses.
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
        let r = solo_payouts(&miner(""), &SoloFeeConfig::default(), TEST_REWARD);
        assert!(r.is_empty());
    }

    #[test]
    fn solo_payouts_no_dev_fee_yields_single_100_pct() {
        let r = solo_payouts(
            &miner("bc1qabc"),
            &SoloFeeConfig {
                dev_fee_address: None,
                dev_fee_percent: 0.0,
            },
            TEST_REWARD,
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].payout_id(), "bc1qabc");
        assert_eq!(r[0].sats, TEST_REWARD);
    }

    #[test]
    fn solo_payouts_with_dev_fee_splits() {
        let r = solo_payouts(
            &miner("bc1qminer"),
            &SoloFeeConfig {
                dev_fee_address: Some("bc1qdev".into()),
                dev_fee_percent: 1.5,
            },
            TEST_REWARD,
        );
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].payout_id(), "bc1qdev");
        assert_eq!(r[0].sats, 75_000_000); // floor(1.5% × 5e9)
        assert_eq!(r[1].payout_id(), "bc1qminer");
        assert_eq!(r[1].sats, TEST_REWARD - 75_000_000); // miner takes the remainder
                                                         // The two outputs sum to exactly the reward.
        assert_eq!(r[0].sats + r[1].sats, TEST_REWARD);
    }

    #[test]
    fn solo_payouts_with_dev_fee_empty_address_is_ignored() {
        // Trim treats whitespace-only as empty.
        let r = solo_payouts(
            &miner("bc1qminer"),
            &SoloFeeConfig {
                dev_fee_address: Some("   ".into()),
                dev_fee_percent: 1.5,
            },
            TEST_REWARD,
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].payout_id(), "bc1qminer");
        assert_eq!(r[0].sats, TEST_REWARD);
    }

    #[test]
    fn solo_payouts_rejects_out_of_range_fee_percent() {
        let r = solo_payouts(
            &miner("bc1qminer"),
            &SoloFeeConfig {
                dev_fee_address: Some("bc1qdev".into()),
                dev_fee_percent: 150.0,
            },
            TEST_REWARD,
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].payout_id(), "bc1qminer");
        assert_eq!(r[0].sats, TEST_REWARD);
    }

    #[test]
    fn solo_payouts_zero_percent_dev_fee_pays_miner_only() {
        // Dev address set but percent left at the production default of 0.0
        // (operator forgot `dev_fee_percent`). Must NOT emit a zero-value dev
        // output — collapse to a single 100 %-to-miner payout.
        let r = solo_payouts(
            &miner("bc1qminer"),
            &SoloFeeConfig {
                dev_fee_address: Some("bc1qdev".into()),
                dev_fee_percent: 0.0,
            },
            TEST_REWARD,
        );
        assert_eq!(r.len(), 1, "no zero-value dev output");
        assert_eq!(r[0].payout_id(), "bc1qminer");
        assert_eq!(r[0].sats, TEST_REWARD);
    }

    /// A BIP-32 test-vector xpub — a real key with a real checksum, because
    /// `RotatingPayout::from_xpub_str` refuses anything else and the refusal test
    /// below would then be asserting against an empty directory.
    const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    fn blockparty_entries(first: &str) -> Vec<CoinbaseDistributionEntry> {
        use bp_common::Sats;
        vec![
            CoinbaseDistributionEntry {
                address: AddressId::new(first.to_string()).unwrap(),
                percent: 60.0,
                sats: Sats(60_000_000),
            },
            CoinbaseDistributionEntry {
                address: AddressId::new("bc1qb".to_string()).unwrap(),
                percent: 40.0,
                sats: Sats(40_000_000),
            },
        ]
    }

    #[test]
    fn entries_to_payouts_carries_exact_sats() {
        let entries = blockparty_entries("bc1qa");
        let payouts = entries_to_payouts(&entries, &PayoutIdentityDirectory::new());
        assert_eq!(payouts.len(), 2);
        assert_eq!(payouts[0].payout_id(), "bc1qa");
        assert_eq!(payouts[0].sats, 60_000_000);
        assert_eq!(payouts[1].payout_id(), "bc1qb");
        assert_eq!(payouts[1].sats, 40_000_000);
    }

    /// **Blockparty's refusal, and its shape.** A rotating identity among the
    /// members is a bug — they are operator-entered addresses — so the whole
    /// distribution is refused rather than the entry skipped: skipping leaves the
    /// other members' percentages no longer summing to the group's split, which
    /// pays out a distribution no admin configured.
    ///
    /// The test above is this one's negative control, on the same entries: with an
    /// empty directory the identical list yields both outputs, so the emptiness
    /// here is the refusal and not a broken fixture.
    #[test]
    fn entries_to_payouts_refuses_a_rotating_member_entirely() {
        let identity = bp_payout_descriptor::RotatingPayout::from_xpub_str(XPUB)
            .expect("a BIP-32 vector is a valid xpub")
            .into_payout_identity();
        let payout_id = identity.payout_id().to_string();
        let directory = PayoutIdentityDirectory::new();
        directory.publish_for_test(identity);

        let entries = blockparty_entries(&payout_id);
        assert_eq!(
            entries.len(),
            2,
            "the precondition: one rotating member AND one static one"
        );

        let payouts = entries_to_payouts(&entries, &directory);
        assert!(
            payouts.is_empty(),
            "the static member must go down with it — a partial Blockparty split \
             is worse than no job: {payouts:?}"
        );
        assert!(
            ResolvedPayouts::unsnapshotted(payouts).is_none(),
            "and an empty list is exactly the pool's existing serve-no-job answer"
        );
    }

    // ── The weight path: PPLNS and Group-Solo ──────────────────────────────

    /// A real regtest address, because the payability question here is asked by
    /// the renderer's own network-aware parser: a `bc1q…` literal is *not* payable
    /// on regtest, so a fabricated one would make every test below pass for the
    /// wrong reason.
    const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    fn weight_entries(first: &str) -> Vec<(AddressId, u64)> {
        vec![
            (AddressId::new(first.to_string()).unwrap(), 60_000_000),
            (
                AddressId::new(REGTEST_ADDR.to_string()).unwrap(),
                40_000_000,
            ),
        ]
    }

    /// A rotating miner's ledger key must lower to a **rotating** payout entry —
    /// not to a static one carrying the key as its address, which is the shape
    /// that renders a 47-char `payout_id` into a coinbase and fails
    /// `build_payout_outputs`.
    #[test]
    fn weight_entries_lower_a_rotating_ledger_key_to_a_rotating_payout() {
        let identity = bp_payout_descriptor::RotatingPayout::from_xpub_str(XPUB)
            .expect("a BIP-32 vector is a valid xpub")
            .into_payout_identity();
        let payout_id = identity.payout_id().to_string();
        let directory = PayoutIdentityDirectory::new();
        directory.publish_for_test(identity);

        let payouts = weight_entries_to_payouts(
            weight_entries(&payout_id),
            &directory,
            bitcoin::Network::Regtest,
        );

        assert_eq!(payouts.len(), 2, "both miners are payable: {payouts:?}");
        assert!(
            payouts[0].identity.rotates(),
            "the rotating miner must arrive as a rotating identity, so the coinbase \
             derives a fresh script instead of being handed a payout_id"
        );
        assert_eq!(
            payouts[0].payout_id(),
            payout_id,
            "and the LEDGER key is unchanged by the lowering — settlement books \
             against this, not against the derived address"
        );
        assert_eq!(payouts[0].sats, 60_000_000, "sats carry through untouched");
        assert!(!payouts[1].identity.rotates());
        assert_eq!(payouts[1].sats, 40_000_000);
    }

    /// **The refusal, with its control in the same test.** A rotating ledger key
    /// the directory has forgotten resolves to `Static { address: payout_id }`,
    /// which no parser accepts. Dropping that one entry would hand its 60 M sats
    /// to the pool as the §4 residual *while settlement still credits the miner
    /// from the block's own coinbase* — the pool taking more than its fee, and a
    /// double credit. So the whole distribution goes.
    ///
    /// The control is the identical entry list against a directory that knows the
    /// key: it lowers to two payouts. The emptiness is therefore the guard, not a
    /// malformed fixture.
    #[test]
    fn a_forgotten_rotating_key_refuses_the_whole_weight_distribution() {
        let identity = bp_payout_descriptor::RotatingPayout::from_xpub_str(XPUB)
            .expect("a BIP-32 vector is a valid xpub")
            .into_payout_identity();
        let payout_id = identity.payout_id().to_string();

        let forgotten = PayoutIdentityDirectory::new();
        assert!(
            !forgotten.identity_for(&payout_id).rotates(),
            "the precondition: this directory has never heard of the key"
        );
        let refused = weight_entries_to_payouts(
            weight_entries(&payout_id),
            &forgotten,
            bitcoin::Network::Regtest,
        );
        assert!(
            refused.is_empty(),
            "an unpayable ledger key must take the whole distribution with it, \
             because the alternative is paying its share to the pool: {refused:?}"
        );
        assert!(
            ResolvedPayouts::unsnapshotted(refused).is_none(),
            "and that empties into the pool's existing serve-no-job answer, which \
             self-heals on the next build"
        );

        let known = PayoutIdentityDirectory::new();
        known.publish_for_test(identity);
        assert_eq!(
            weight_entries_to_payouts(
                weight_entries(&payout_id),
                &known,
                bitcoin::Network::Regtest
            )
            .len(),
            2,
            "control: the same entries lower fine once the identity is resolvable"
        );
    }

    /// The same refusal covers the other way a key becomes unrenderable, which has
    /// nothing to do with rotation: a literal address from the wrong network. The
    /// weight path's own filter parses against the pool's network, so a mainnet
    /// address in a regtest window is exactly as unpayable as a forgotten xpub —
    /// and `is_payable_identity` is asked the one question rather than each caller
    /// re-deriving what "payable" means.
    #[test]
    fn a_wrong_network_literal_refuses_the_whole_weight_distribution() {
        let directory = PayoutIdentityDirectory::new();
        let mainnet = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let entries = vec![
            (AddressId::new(mainnet.to_string()).unwrap(), 60_000_000),
            (
                AddressId::new(REGTEST_ADDR.to_string()).unwrap(),
                40_000_000,
            ),
        ];

        assert!(
            weight_entries_to_payouts(entries, &directory, bitcoin::Network::Regtest).is_empty(),
            "a mainnet address cannot be paid by a regtest coinbase"
        );
        assert_eq!(
            weight_entries_to_payouts(
                weight_entries(REGTEST_ADDR),
                &directory,
                bitcoin::Network::Regtest
            )
            .len(),
            2,
            "control: two regtest literals through the same call lower to two \
             payouts, so the emptiness above is the network check"
        );
    }

    // ── The ext 0x0003 lowering: PPLNS pool-wide and Group-Solo tailored ────

    /// Reference revenue for the fixture below: a quarter-era block subsidy, so
    /// both members' §4 amounts are ~150 M sats and `min_payout` withholds
    /// neither.
    const TEST_T_REF: u64 = 312_500_000;

    /// A real regtest P2WPKH for the pool output. `pay_P` is structural (§4), so
    /// [`bp_pplns::build_weight_distribution`] refuses outright on a fee address
    /// it cannot parse — a `format!`-ed one would make the fixture below an
    /// `Err`, not a distribution.
    fn pool_fee_address() -> AddressId {
        AddressId::new(bp_test_support::deterministic_p2wpkh_regtest([0x7f; 32]))
            .expect("a derived p2wpkh is a valid payout address")
    }

    /// The two-member distribution the lowering is handed, built by the real
    /// [`bp_pplns::build_weight_distribution`] rather than assembled field by
    /// field: the build is what decides which entries are `published()`, and a
    /// hand-written `WeightDistribution` could claim a published set the weight
    /// model would never produce.
    ///
    /// `first_key` is the member under test — a literal regtest address for the
    /// control, the rotating `payout_id` for the refusal. `derived` is how the
    /// build is told a key it cannot parse is nonetheless payable
    /// (`is_payable_payout_key`); without it the rotating row is dropped *above*
    /// the score total, leaving a one-member distribution with nothing to refuse.
    fn two_member_distribution(
        first_key: &str,
        derived: &std::collections::HashSet<String>,
    ) -> bp_pplns::WeightDistribution {
        let shares = std::collections::HashMap::from([
            (
                AddressId::new(first_key.to_string()).expect("payout key"),
                60.0,
            ),
            (
                AddressId::new(REGTEST_ADDR.to_string()).expect("regtest address"),
                40.0,
            ),
        ]);
        let balances = std::collections::HashMap::new();
        let fee = pool_fee_address();
        bp_pplns::build_weight_distribution(bp_pplns::WeightDistributionInput {
            address_shares: &shares,
            balances: &balances,
            fee_percent: 1.5,
            fee_address: &fee,
            coinbase_weight_budget: 50_000,
            min_payout_sats: Some(Sats(5_000)),
            finder_bonus_ppm: 0,
            finder_address: None,
            reference_revenue_sats: TEST_T_REF,
            withheld_value: bp_pplns::WithheldValue::ToOtherMiners,
            derived_payout_keys: derived,
        })
        .expect("two scored miners and a payable fee address")
    }

    /// **One rotating member costs the WHOLE pool its published distribution**,
    /// and that is the intended trade: a published distribution is a list of
    /// fixed `script_pubkey`s a JDC reuses across blocks, there is no height here
    /// to derive a rotating script at, and the two alternatives are both wrong —
    /// pinning the miner to one derived address forever, or dropping its entry
    /// and handing its satoshis to the pool as the §4 residual.
    ///
    /// The control is the same fixture with two static members: it lowers to two
    /// payouts. So the `None` below is the refusal and not a distribution that
    /// was empty, unparseable or never built — which is what a lone `is_none()`
    /// would have been worth here.
    ///
    /// **What the other modes do at this call.** This one function is the whole
    /// weight-native lowering: PPLNS reaches it from `build_pool_wide` and
    /// Group-Solo from the `TailoredMode::GroupSolo` arm of `build_for_miner`, so
    /// the refusal is one implementation for both — the difference is only blast
    /// radius (PPLNS: every JDC on the pool; Group-Solo: that group's JDC). Solo
    /// does not come through here at all: it lowers exact sats
    /// (`lower_exact_entries`) and refuses a rotating identity one level up, in
    /// `build_for_miner`. Blockparty is never published over JDP at all
    /// ([`JdpDistributionFor::Nothing`]).
    #[test]
    fn one_rotating_member_refuses_the_whole_published_distribution() {
        // Distinct from REGTEST_ADDR, or the fixture's share map would collapse
        // to a single member and the "whole distribution" would be one entry.
        let static_first = bp_test_support::deterministic_p2wpkh_regtest([0x11; 32]);
        let control = two_member_distribution(&static_first, &std::collections::HashSet::new());
        assert_eq!(
            control.published().count(),
            2,
            "the control's precondition: both members hold a §4 output, so the \
             lowering below has two entries to walk"
        );

        let lowered = lower_weight_distribution(
            &control,
            &PayoutIdentityDirectory::new(),
            bitcoin::Network::Regtest,
            Some([7u8; 32]),
            true,
        )
        .expect("two static regtest members are publishable");
        assert_eq!(
            lowered.payouts.len(),
            2,
            "control: every published member reaches the wire, in §4 order"
        );
        assert_eq!(
            lowered.payouts.iter().map(|p| p.weight).collect::<Vec<_>>(),
            control
                .published()
                .map(|e| e.wire_weight)
                .collect::<Vec<_>>(),
            "and carries the published wire weight untouched — §4 positions are \
             what a JDC pays against"
        );
        // The weights alone are not the control. §4 pays *weight against script*,
        // so a lowering that put the right weights beside the wrong scripts is
        // the failure with money in it, and the assertion above cannot see it:
        // building every `WeightedOutput` with `pool_script.clone()` sends the
        // entire miners' cut to the pool address and keeps the weight list
        // identical. Pairing them positionally is what closes that, and it also
        // catches the two vectors drifting out of step, which is the specific
        // hazard of building `payouts` and `dust_limits` in one loop.
        assert_eq!(
            lowered
                .payouts
                .iter()
                .map(|p| p.script_pubkey.clone())
                .collect::<Vec<_>>(),
            control
                .published()
                .map(|e| {
                    bp_mining_job::address_to_script(bitcoin::Network::Regtest, e.address.as_str())
                        .expect("the fixture's members are real regtest addresses")
                        .to_bytes()
                })
                .collect::<Vec<_>>(),
            "each §4 weight must sit against ITS OWN member's script"
        );
        assert_eq!(
            lowered.dust_limits,
            control
                .published()
                .map(|e| e.dust_limit)
                .collect::<Vec<_>>(),
            "and the dust limits stay in step with the payouts they bound — the \
             two vectors are filled in one loop, so nothing but position \
             relates them"
        );
        assert_eq!(lowered.pool_payout.weight, control.weight_p);
        assert_eq!(
            lowered.pool_payout.script_pubkey,
            bp_mining_job::address_to_script(
                bitcoin::Network::Regtest,
                control.fee_address.as_str()
            )
            .expect("the fixture's fee address is a real regtest address")
            .to_bytes(),
            "the pool's own output is the §4 residual's destination, so it is \
             worth pinning that it is the fee address and not a member's"
        );
        assert_eq!(lowered.reference_reward_sats, TEST_T_REF);

        // The same distribution with ONE member swapped to a rotating identity.
        let identity = bp_payout_descriptor::RotatingPayout::from_xpub_str(XPUB)
            .expect("a BIP-32 vector is a valid xpub")
            .into_payout_identity();
        let payout_id = identity.payout_id().to_string();
        let derived = std::collections::HashSet::from([payout_id.clone()]);
        let rotating = two_member_distribution(&payout_id, &derived);
        assert!(
            rotating
                .published()
                .any(|e| e.address.as_str() == payout_id),
            "the refusal's precondition: the rotating key really is in the \
             published set. Un-vouched it is dropped at the build's own filter, \
             and then this test would assert `None` about a distribution that \
             never contained a rotating miner"
        );
        assert_eq!(
            rotating.published().count(),
            2,
            "and the static member is published beside it — so what is refused \
             below is a distribution that would otherwise have paid somebody"
        );

        let directory = PayoutIdentityDirectory::new();
        directory.publish_for_test(identity);
        assert!(
            directory.identity_for(&payout_id).rotates(),
            "the directory must answer Rotating for this key, or the lowering is \
             being asked a different question"
        );

        assert!(
            lower_weight_distribution(
                &rotating,
                &directory,
                bitcoin::Network::Regtest,
                Some([7u8; 32]),
                true,
            )
            .is_none(),
            "a rotating member must take the whole published distribution with \
             it — publishing the rest would pay this miner's share to the pool \
             output as the §4 residual, and publishing a script derived here \
             would pin every future block a JDC builds to that one address"
        );

        // What the assertion above pins is the *scope* of the refusal: turn the
        // `Rotating` arm into a `continue` and the other member is published
        // alone, which fails here. It does not pin the arm's existence —
        // measured, not assumed: deleting the `return None` and falling through
        // still answers `None`, because the ledger key handed to
        // `address_to_script` is a hash. That is the second guard, and the
        // function's own comment is about reaching the right answer for the right
        // reason rather than by accident.
        //
        // Which makes this assertion the one that would notice the accident going
        // away: a `payout_id` that ever parsed as an address would leave the
        // `match` arm as the only thing refusing this distribution.
        assert!(
            bp_mining_job::address_to_script(bitcoin::Network::Regtest, &payout_id).is_err(),
            "a payout_id must stay unparseable as an address — if that changes, \
             the `None` above is no longer over-determined and the arm alone \
             carries it"
        );
    }
}
