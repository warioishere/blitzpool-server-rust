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
use bp_mining_job::PayoutEntry;
use bp_pplns::CoinbaseDistributionEntry;
use bp_pplns_engine::engine::PplnsEngine;
use tracing::warn;
use uuid::Uuid;

use crate::engines::BlitzpoolModeGate;

/// Server-wide solo dev-fee config (mirrors
/// [`bp_stratum_v1::client::solo_payouts`]'s inputs).
#[derive(Clone, Debug)]
pub(crate) struct SoloFeeConfig {
    /// Bitcoin address that receives the dev fee on solo payouts.
    /// `None` disables dev fee — full reward to miner.
    pub(crate) dev_fee_address: Option<String>,
    /// Dev fee in `[0.0, 100.0]`. Ignored when `dev_fee_address` is `None`.
    pub(crate) dev_fee_percent: f64,
}

impl Default for SoloFeeConfig {
    fn default() -> Self {
        Self {
            dev_fee_address: None,
            dev_fee_percent: 0.0,
        }
    }
}

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
    async fn resolve_internal(&self, miner_address: &str, reward_sats: u64) -> Vec<PayoutEntry> {
        let result = self.mode_gate.lookup_mode(miner_address);
        match result.mode {
            MiningMode::Solo => {
                // Pending-fee guard: an admin whose Blockparty is still
                // DRAFT / CONFIRMING falls through to Solo for routing,
                // but the on-chain coinbase routes 100% to the pool-fee
                // address (BlockpartyService surfaces this as
                // `pending_party_fee_route`). Without the guard the
                // admin would pocket the full block reward before the
                // members confirm the splits.
                if let Some(route) = self.blockparty_pending_fee_route(miner_address).await {
                    return route;
                }
                solo_payouts(miner_address, &self.solo_fee)
            }
            MiningMode::Pplns => self.pplns_payouts(miner_address, reward_sats).await,
            MiningMode::Blockparty => {
                self.blockparty_payouts(miner_address, reward_sats, result.group_id.as_deref())
                    .await
            }
            MiningMode::GroupSolo => {
                let Some(gid_str) = result.group_id.as_deref() else {
                    warn!(
                        miner_address,
                        "GroupSolo mode published WITHOUT a group_id; falling back to solo \
                         payouts so the coinbase is at least spendable"
                    );
                    return solo_payouts(miner_address, &self.solo_fee);
                };
                let Ok(group_id) = Uuid::parse_str(gid_str) else {
                    warn!(
                        miner_address,
                        gid_str, "GroupSolo group_id failed to parse as UUID; falling back to solo"
                    );
                    return solo_payouts(miner_address, &self.solo_fee);
                };
                self.group_solo_payouts(miner_address, reward_sats, group_id)
                    .await
            }
        }
    }

    async fn pplns_payouts(&self, miner_address: &str, reward_sats: u64) -> Vec<PayoutEntry> {
        let Some(pplns) = self.pplns.as_ref() else {
            // PPLNS mode was published into the gate but the engine
            // is disabled at this deployment — config inconsistency.
            // Fall back to solo + warn.
            warn!(
                miner_address,
                "PPLNS mode in gate but `[pplns]` is absent from config; falling back to solo"
            );
            return solo_payouts(miner_address, &self.solo_fee);
        };
        match pplns.build_distribution(reward_sats).await {
            Ok(result) => entries_to_payouts(&result.payouts),
            Err(err) => {
                warn!(
                    %err,
                    miner_address,
                    reward_sats,
                    "PPLNS distribution build failed; falling back to solo coinbase"
                );
                solo_payouts(miner_address, &self.solo_fee)
            }
        }
    }

    /// Pending-party-fee guard. Returns `Some(vec![pool_fee → 100%])`
    /// when the connecting address is the admin of an unconfirmed
    /// Blockparty (DRAFT or CONFIRMING). Returns `None` otherwise so
    /// the caller falls through to the standard Solo coinbase.
    async fn blockparty_pending_fee_route(&self, miner_address: &str) -> Option<Vec<PayoutEntry>> {
        let svc = self.blockparty.as_ref()?;
        let addr = AddressId::new(miner_address.to_string()).ok()?;
        let route = svc.pending_party_fee_route(&addr).await?;
        Some(vec![PayoutEntry {
            address: route.fee_address.into_inner(),
            percent: route.percent as f64,
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
            return solo_payouts(miner_address, &self.solo_fee);
        };
        let Some(gid_str) = group_id_str else {
            warn!(
                miner_address,
                "Blockparty mode published WITHOUT a group_id; falling back to solo"
            );
            return solo_payouts(miner_address, &self.solo_fee);
        };
        let Ok(group_id) = Uuid::parse_str(gid_str) else {
            warn!(
                miner_address,
                gid_str, "Blockparty group_id failed to parse as UUID; falling back to solo"
            );
            return solo_payouts(miner_address, &self.solo_fee);
        };
        match svc.build_payouts(group_id, Sats(reward_sats as i64)).await {
            Ok(Some(result)) => entries_to_payouts(&result.payouts),
            Ok(None) => {
                warn!(
                    miner_address,
                    %group_id,
                    "Blockparty group not found; falling back to solo"
                );
                solo_payouts(miner_address, &self.solo_fee)
            }
            Err(err) => {
                warn!(
                    %err,
                    miner_address,
                    %group_id,
                    "Blockparty distribution build failed; falling back to solo"
                );
                solo_payouts(miner_address, &self.solo_fee)
            }
        }
    }

    async fn group_solo_payouts(
        &self,
        miner_address: &str,
        reward_sats: u64,
        group_id: Uuid,
    ) -> Vec<PayoutEntry> {
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
                return solo_payouts(miner_address, &self.solo_fee);
            }
        };
        match self
            .group_solo
            .build_distribution(group_id, reward_sats, &finder)
            .await
        {
            Ok(result) => entries_to_payouts(&result.payouts),
            Err(err) => {
                warn!(
                    %err,
                    miner_address,
                    %group_id,
                    reward_sats,
                    "Group-Solo distribution build failed; falling back to solo coinbase"
                );
                solo_payouts(miner_address, &self.solo_fee)
            }
        }
    }
}

// ─── Trait impls ──────────────────────────────────────────────────

#[async_trait]
impl bp_stratum_v1::PayoutResolver for ProductionPayoutResolver {
    async fn resolve_payouts(&self, miner_address: &str, reward_sats: u64) -> Vec<PayoutEntry> {
        self.resolve_internal(miner_address, reward_sats).await
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
    }

    fn resolve_stream(&self, miner_address: &AddressId) -> bp_common::StreamKind {
        bp_common::StreamKind::for_mode(self.mode_gate.lookup_mode(miner_address.as_str()).mode)
    }
}

// ─── Helpers ──────────────────────────────────────────────────────

/// Translate the engine's `CoinbaseDistributionEntry` shape into the
/// `bp_mining_job::PayoutEntry` shape consumed by
/// `build_mining_job_from_tdp`. Drops the absolute sats — the coinbase
/// is built from percentages, and `build_mining_job`
/// re-derives floor(percent/100 × reward) per entry (matching the
/// engine's math).
fn entries_to_payouts(entries: &[CoinbaseDistributionEntry]) -> Vec<PayoutEntry> {
    entries
        .iter()
        .map(|e| PayoutEntry {
            address: e.address.as_str().to_string(),
            percent: e.percent,
        })
        .collect()
}

/// Solo-mode coinbase split. Mirrors
/// [`bp_stratum_v1::client::solo_payouts`]:
/// 100%-to-miner, or `dev_fee_percent` to dev + remainder to miner.
fn solo_payouts(miner_address: &str, fee: &SoloFeeConfig) -> Vec<PayoutEntry> {
    let dev_addr = fee
        .dev_fee_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let percent = fee.dev_fee_percent;
    match (miner_address.is_empty(), dev_addr) {
        (true, _) => vec![],
        (false, None) => vec![PayoutEntry {
            address: miner_address.to_string(),
            percent: 100.0,
        }],
        (false, Some(_dev)) if !(0.0..=100.0).contains(&percent) => {
            // Defensive: out-of-range dev percent → ignore the fee, full to miner.
            warn!(
                percent,
                "solo dev_fee_percent out of [0,100]; ignoring fee + paying 100% to miner"
            );
            vec![PayoutEntry {
                address: miner_address.to_string(),
                percent: 100.0,
            }]
        }
        (false, Some(_dev)) if percent <= 0.0 => {
            // Dev address configured but a zero (or negative) percent — the
            // common "set dev_fee_address, forgot dev_fee_percent" misconfig,
            // since the production default is 0.0. Emitting a dev output at 0 %
            // would put a useless zero-value output in the coinbase; pay the
            // whole reward to the miner instead.
            vec![PayoutEntry {
                address: miner_address.to_string(),
                percent: 100.0,
            }]
        }
        (false, Some(dev)) => vec![
            PayoutEntry {
                address: dev.to_string(),
                percent,
            },
            PayoutEntry {
                address: miner_address.to_string(),
                percent: 100.0 - percent,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solo_payouts_empty_address_yields_empty() {
        let r = solo_payouts("", &SoloFeeConfig::default());
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
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].address, "bc1qabc");
        assert!((r[0].percent - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn solo_payouts_with_dev_fee_splits() {
        let r = solo_payouts(
            "bc1qminer",
            &SoloFeeConfig {
                dev_fee_address: Some("bc1qdev".into()),
                dev_fee_percent: 1.5,
            },
        );
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].address, "bc1qdev");
        assert!((r[0].percent - 1.5).abs() < f64::EPSILON);
        assert_eq!(r[1].address, "bc1qminer");
        assert!((r[1].percent - 98.5).abs() < f64::EPSILON);
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
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].address, "bc1qminer");
    }

    #[test]
    fn solo_payouts_rejects_out_of_range_fee_percent() {
        let r = solo_payouts(
            "bc1qminer",
            &SoloFeeConfig {
                dev_fee_address: Some("bc1qdev".into()),
                dev_fee_percent: 150.0,
            },
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].address, "bc1qminer");
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
        );
        assert_eq!(r.len(), 1, "no zero-value dev output");
        assert_eq!(r[0].address, "bc1qminer");
        assert!((r[0].percent - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn entries_to_payouts_translates_address_id_to_string() {
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
        assert!((payouts[0].percent - 60.0).abs() < f64::EPSILON);
        assert_eq!(payouts[1].address, "bc1qb");
        assert!((payouts[1].percent - 40.0).abs() < f64::EPSILON);
    }
}
