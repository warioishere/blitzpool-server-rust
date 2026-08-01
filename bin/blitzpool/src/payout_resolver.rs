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
use bp_mining_job::{solo_payouts, PayoutEntry};
use bp_pplns::CoinbaseDistributionEntry;
use bp_pplns_engine::engine::PplnsEngine;
use tracing::warn;
use uuid::Uuid;

use crate::engines::BlitzpoolModeGate;

/// Server-wide solo dev-fee config (mirrors
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
    ) -> (Vec<PayoutEntry>, bool) {
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
                    return (route, vouchable);
                }
                (
                    solo_payouts(miner_address, &self.solo_fee, reward_sats),
                    vouchable,
                )
            }
            MiningMode::Pplns => self.pplns_payouts(miner_address, reward_sats).await,
            MiningMode::Blockparty => (
                self.blockparty_payouts(miner_address, reward_sats, result.group_id.as_deref())
                    .await,
                vouchable,
            ),
            MiningMode::GroupSolo => {
                let Some(gid_str) = result.group_id.as_deref() else {
                    warn!(
                        miner_address,
                        "GroupSolo mode published WITHOUT a group_id; falling back to solo \
                         payouts so the coinbase is at least spendable"
                    );
                    // A Group-Solo address on a solo list: the booking path would
                    // look for a snapshot this list never had.
                    return (
                        solo_payouts(miner_address, &self.solo_fee, reward_sats),
                        false,
                    );
                };
                let Ok(group_id) = Uuid::parse_str(gid_str) else {
                    warn!(
                        miner_address,
                        gid_str, "GroupSolo group_id failed to parse as UUID; falling back to solo"
                    );
                    return (
                        solo_payouts(miner_address, &self.solo_fee, reward_sats),
                        false,
                    );
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

impl ProductionPayoutResolver {
    /// Resolve payouts and say whether the pool could book a block found on
    /// them.
    ///
    /// The plain resolver hides its fallbacks by design: when an engine is
    /// unreachable it hands back a solo split so the miner still gets a
    /// spendable coinbase. That is right for building a job and wrong for
    /// accounting — a fallback list has no distribution snapshot behind it, so
    /// nothing could ever be booked against it. The ext-0x0003 path needs to
    /// tell the two apart before it promises a JD-client's block is bookable.
    ///
    /// The question is per mode, because only two modes resolve a snapshot at
    /// all. Answering it as "did an engine build this" would withhold the
    /// promise from the two modes that need no snapshot — and the promise gates
    /// far more than the snapshot lookup: without it no block-found is emitted
    /// at all, so the durable `blocks_entity` row, the notification and the
    /// Blockparty history row would all go missing for a block the pool served.
    pub(crate) async fn resolve_payouts_reporting_source(
        &self,
        miner_address: &AddressId,
        reward_sats: u64,
    ) -> (Vec<PayoutEntry>, bool) {
        // One build, both answers. Anything else lets the promise describe a
        // different outcome than the list it is attached to.
        self.resolve_internal(miner_address.as_str(), reward_sats)
            .await
    }

    /// Second half of the pair: could a block found on this list be booked? See
    /// [`Self::resolve_internal`].
    async fn pplns_payouts(
        &self,
        miner_address: &str,
        reward_sats: u64,
    ) -> (Vec<PayoutEntry>, bool) {
        let Some(pplns) = self.pplns.as_ref() else {
            // PPLNS mode was published into the gate but the engine
            // is disabled at this deployment — config inconsistency.
            // Fall back to solo + warn.
            warn!(
                miner_address,
                "PPLNS mode in gate but `[pplns]` is absent from config; falling back to solo"
            );
            return (
                solo_payouts(miner_address, &self.solo_fee, reward_sats),
                false,
            );
        };
        match pplns.build_distribution(reward_sats).await {
            // The build can succeed while its snapshot write does not — the
            // engine keeps the distribution on purpose, because failing it would
            // hand this miner the whole block. But the fingerprint then names a
            // key that does not exist, so there is nothing to vouch for.
            Ok(result) => {
                if !result.snapshot_written {
                    warn!(
                        miner_address,
                        reward_sats,
                        "PPLNS distribution built but its snapshot did not land — the coinbase \
                         stands, a block found on it cannot be booked automatically"
                    );
                }
                (entries_to_payouts(&result.payouts), result.snapshot_written)
            }
            Err(err) => {
                warn!(
                    %err,
                    miner_address,
                    reward_sats,
                    "PPLNS distribution build failed; falling back to solo coinbase"
                );
                (
                    solo_payouts(miner_address, &self.solo_fee, reward_sats),
                    false,
                )
            }
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
    ) -> (Vec<PayoutEntry>, bool) {
        // The finder is the miner connecting on this share path; the
        // Group-Solo engine bumps the finder's payout via the
        // `finder_bonus_sats` config knob when emitting the
        // distribution.
        let finder = match AddressId::new(miner_address.to_string()) {
            Ok(a) => a,
            Err(_) => {
                warn!(
                    miner_address,
                    "GroupSolo miner address failed AddressId parse; falling back to solo"
                );
                return (
                    solo_payouts(miner_address, &self.solo_fee, reward_sats),
                    false,
                );
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
                (entries_to_payouts(&result.payouts), result.snapshot_written)
            }
            Err(err) => {
                warn!(
                    %err,
                    miner_address,
                    %group_id,
                    reward_sats,
                    "Group-Solo distribution build failed; falling back to solo coinbase"
                );
                (
                    solo_payouts(miner_address, &self.solo_fee, reward_sats),
                    false,
                )
            }
        }
    }
}

// ─── Trait impls ──────────────────────────────────────────────────

#[async_trait]
impl bp_stratum_v1::PayoutResolver for ProductionPayoutResolver {
    async fn resolve_payouts(&self, miner_address: &str, reward_sats: u64) -> Vec<PayoutEntry> {
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
    ) -> Vec<PayoutEntry> {
        self.resolve_internal(miner_address.as_str(), reward_sats)
            .await
            .0
    }

    fn resolve_stream(&self, miner_address: &AddressId) -> bp_common::StreamKind {
        bp_common::StreamKind::for_mode(self.mode_gate.lookup_mode(miner_address.as_str()).mode)
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
