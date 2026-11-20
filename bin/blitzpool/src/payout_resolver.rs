// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production coinbase payout resolver: gives SV1 and SV2 the coinbase of the
//! address's payout mode at every template broadcast, and is the JDP ext 0x0003
//! distribution source. What each mode builds is `bp_mode_payouts`, shared
//! with the API block preview; this module adds the mode gate, the coinbase
//! tags and the ext 0x0003 wire shape.

use std::sync::Arc;

use async_trait::async_trait;
use bp_blockparty_engine::BlockpartyService;
use bp_common::{AddressId, MiningMode};
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_mining_job::ResolvedPayouts;
use bp_mining_job::SoloFeeConfig;
use bp_mining_mode::MiningModeResult;
use bp_mode_payouts::{ModeBuild, ModeEngines};
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
    group_solo: Option<GroupSoloEngine>,
    solo_fee: SoloFeeConfig,
    /// When `None`, the Blockparty arm serves no job.
    blockparty: Option<Arc<BlockpartyService>>,
    /// Team and Blockparty coinbase tags; `None` adds none.
    coinbase_tags: Option<Arc<crate::coinbase_tags::CoinbaseTagCache>>,
}

impl ProductionPayoutResolver {
    pub(crate) fn new(
        mode_gate: Arc<BlitzpoolModeGate>,
        pplns: Option<PplnsEngine>,
        group_solo: Option<GroupSoloEngine>,
        solo_fee: SoloFeeConfig,
        blockparty: Option<Arc<BlockpartyService>>,
        coinbase_tags: Option<Arc<crate::coinbase_tags::CoinbaseTagCache>>,
    ) -> Self {
        Self {
            mode_gate,
            pplns,
            group_solo,
            solo_fee,
            blockparty,
            coinbase_tags,
        }
    }

    /// The tag a Team or Blockparty set for its coinbase.
    fn coinbase_tag(&self, group_id: Uuid) -> Option<bp_common::CoinbaseTag> {
        self.coinbase_tags.as_ref()?.get(group_id)
    }

    /// The engines this process holds, for the shared per-mode build.
    fn engines(&self) -> ModeEngines<'_> {
        ModeEngines {
            pplns: self.pplns.as_ref(),
            group_solo: self.group_solo.as_ref(),
            blockparty: self.blockparty.as_deref().map(BlockpartyService::payouts),
            solo_fee: &self.solo_fee,
        }
    }

    /// Resolution core for SV1 and SV2: the gate's mode through the shared
    /// per-mode build. An admin of an unready Blockparty is refused at
    /// session start and kicked when it creates the party; until that kick
    /// lands, its connection mines Solo.
    async fn resolve_internal(&self, miner: &AddressId, reward_sats: u64) -> ResolvedPayouts {
        let mode = self.mode_gate.lookup_mode(miner.as_str());
        // A Team or Blockparty mines its own coinbase, so it may tag it;
        // Solo and the pool-wide PPLNS coinbase carry the pool's alone.
        let tag = match mode {
            MiningModeResult::GroupSolo(group_id) | MiningModeResult::Blockparty(group_id) => {
                self.coinbase_tag(group_id)
            }
            MiningModeResult::Solo | MiningModeResult::Pplns => None,
        };
        let resolved = self.engines().payouts_at(mode, miner, reward_sats).await;
        if resolved.is_none() {
            error!(
                miner = miner.as_str(),
                ?mode,
                "no payout list; serving NO JOB"
            );
        }
        resolved.with_coinbase_tag(tag)
    }
}

/// Which of the two tailored (per-miner) builds a mode gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TailoredMode {
    /// Built only while the Solo coinbase carries a fee output
    /// ([`solo_fee_output`]); without one the base protocol serves Solo.
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
}

/// What the pool serves a mode over JDP: the one, pure place that decides it,
/// so a new mode cannot reach a builder it was never classified for.
/// Blockparty (a rental) is deliberately refused, including the pool-wide
/// distribution, so it declares nothing the pool cannot account for.
fn jdp_distribution_for(mode: MiningMode) -> JdpDistributionFor {
    match mode {
        MiningMode::Pplns => JdpDistributionFor::PoolWide,
        MiningMode::Solo => JdpDistributionFor::Tailored(TailoredMode::Solo),
        MiningMode::GroupSolo => JdpDistributionFor::Tailored(TailoredMode::GroupSolo),
        MiningMode::Blockparty => JdpDistributionFor::Nothing,
    }
}

/// The fee output of a Solo coinbase, as `(address, sats)`: the one ext 0x0003
/// gives a Solo miner, as the distribution's pool output. `None` when the
/// coinbase pays only the miner, which the base protocol already expresses.
/// Read from `entries`, the payout list `solo_payouts` builds the real Solo
/// coinbase from, so the distribution and the coinbase cannot disagree.
fn solo_fee_output(entries: &[(String, u64)], fee: &SoloFeeConfig) -> Option<(String, u64)> {
    let fee_address = fee.fee_address()?;
    entries
        .iter()
        .find(|(address, _)| address == fee_address)
        .cloned()
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

// ─── Trait impls ──────────────────────────────────────────────────

#[async_trait]
impl bp_stratum_v1::PayoutResolver for ProductionPayoutResolver {
    async fn resolve_payouts(&self, miner_address: &str, reward_sats: u64) -> ResolvedPayouts {
        match AddressId::new(miner_address) {
            Ok(miner) => self.resolve_internal(&miner, reward_sats).await,
            Err(err) => {
                error!(%err, miner_address, "SV1 payout address will not parse; serving NO JOB");
                ResolvedPayouts::none()
            }
        }
    }

    fn resolve_stream(&self, miner_address: &str) -> bp_common::StreamKind {
        // Same gate lookup as payout resolution, so the template stream and
        // the payout always name one mode.
        bp_common::StreamKind::for_mode(self.mode_gate.lookup_mode(miner_address).mode())
    }
}

#[async_trait]
impl bp_stratum_v2::hooks::PayoutResolver for ProductionPayoutResolver {
    async fn resolve_payouts(
        &self,
        miner_address: &AddressId,
        reward_sats: u64,
    ) -> ResolvedPayouts {
        self.resolve_internal(miner_address, reward_sats).await
    }

    fn resolve_stream(&self, miner_address: &AddressId) -> bp_common::StreamKind {
        bp_common::StreamKind::for_mode(self.mode_gate.lookup_mode(miner_address.as_str()).mode())
    }

    /// `None` (not Solo) for an address the gate has not learned yet: JDP
    /// allocates before the mining channel whose port decides the mode exists.
    fn resolve_stream_known(&self, miner_address: &AddressId) -> Option<bp_common::StreamKind> {
        self.mode_gate
            .lookup_known(miner_address.as_str())
            .map(|result| bp_common::StreamKind::for_mode(result.mode()))
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
        for (address, weight, dust_limit) in d.wire_outputs() {
            payouts.push(bp_stratum_v2::jdp::payout_distribution::WeightedOutput {
                script_pubkey: self.script_of(address.as_str())?,
                weight,
            });
            dust_limits.push(dust_limit);
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
            result.bookable,
        )
    }

    async fn build_for_miner(&self, miner_address: &AddressId) -> TailoredDistribution {
        // Failures return `Unavailable`, never `PoolWide`, which would pay a
        // non-PPLNS block to the PPLNS window. `lookup_known`, not
        // `lookup_mode`: a JDC allocates before its channel opens, so no port
        // may have declared the mode yet, and `lookup_mode` would guess Solo.
        let Some(known) = self.resolver.mode_gate.lookup_known(miner_address.as_str()) else {
            debug!(
                miner = miner_address.as_str(),
                "jdp distribution source: no mining session for this address yet — \
                 publishing nothing until its mode is known (the port decides it, and no \
                 port has spoken)"
            );
            return TailoredDistribution::ModeUnknown;
        };
        let tailored = match jdp_distribution_for(known.mode()) {
            JdpDistributionFor::PoolWide => return TailoredDistribution::PoolWide,
            JdpDistributionFor::Nothing => {
                warn!(
                    miner = miner_address.as_str(),
                    mode = ?known,
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
        // `known` is Solo or Group-Solo here (`jdp_distribution_for`), so the
        // build is exact for Solo and weighted for Group-Solo.
        let built = match self
            .resolver
            .engines()
            .build(known, miner_address, t_ref)
            .await
        {
            ModeBuild::Weighted(built) => self.lower_weight_distribution(
                &built.distribution,
                Some(built.payouts_fingerprint()),
                built.bookable,
            ),
            ModeBuild::Exact(payouts) => {
                let entries: Vec<(String, u64)> =
                    payouts.into_iter().map(|p| (p.address, p.sats)).collect();
                let Some((fee_address, fee_weight)) =
                    solo_fee_output(&entries, &self.resolver.solo_fee)
                else {
                    warn!(
                        miner = miner_address.as_str(),
                        "jdp distribution source: Solo without a fee pays only the miner, which \
                         base-protocol Job Declaration serves; no ext 0x0003 distribution"
                    );
                    return TailoredDistribution::Unavailable;
                };
                let miners: Vec<(String, u64)> = entries
                    .into_iter()
                    .filter(|(a, _)| *a != fee_address)
                    .collect();
                self.lower_exact_entries(&fee_address, fee_weight, &miners, t_ref)
            }
            ModeBuild::NoJob => return TailoredDistribution::Unavailable,
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

#[cfg(test)]
mod tests {
    use super::*;
    use bp_mining_job::solo_payouts;

    const TEST_REWARD: u64 = 5_000_000_000;

    /// Only a Team's and a Blockparty's coinbase carries a group tag: the same
    /// address and the same cached tag give Solo and PPLNS none. Without the
    /// engines wired, the two group arms serve no job, which still carries
    /// the tag they added.
    #[tokio::test]
    async fn only_the_team_and_blockparty_arms_add_their_tag() {
        let address = AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap();
        let group = Uuid::new_v4();
        let tag = bp_common::CoinbaseTag::parse("Dezentralschweiz")
            .unwrap()
            .unwrap();
        let gate = Arc::new(BlitzpoolModeGate::new());
        let resolver = ProductionPayoutResolver::new(
            gate.clone(),
            None,
            None,
            SoloFeeConfig {
                dev_fee_address: None,
                dev_fee_percent: 0.0,
            },
            None,
            Some(Arc::new(crate::coinbase_tags::CoinbaseTagCache::from_tags(
                [(group, tag.clone())],
            ))),
        );
        for (mode, tagged) in [
            (MiningModeResult::Solo, false),
            (MiningModeResult::Pplns, false),
            (MiningModeResult::GroupSolo(group), true),
            (MiningModeResult::Blockparty(group), true),
        ] {
            gate.set_mode(address.as_str(), mode);
            let resolved = resolver.resolve_internal(&address, TEST_REWARD).await;
            assert_eq!(
                resolved.coinbase_tag,
                tagged.then(|| tag.clone()),
                "{mode:?}"
            );
        }
        assert!(
            ProductionPayoutResolver::new(
                gate,
                None,
                None,
                SoloFeeConfig {
                    dev_fee_address: None,
                    dev_fee_percent: 0.0,
                },
                None,
                None,
            )
            .resolve_internal(&address, TEST_REWARD)
            .await
            .coinbase_tag
            .is_none(),
            "control: no cache, no tag"
        );
    }

    /// Pins the full mode → JDP distribution map, every mode named.
    #[test]
    fn jdp_answers_every_mode_with_exactly_one_distribution() {
        assert_eq!(
            jdp_distribution_for(MiningMode::Pplns),
            JdpDistributionFor::PoolWide,
            "PPLNS rides the shared window — that IS its accounting"
        );
        assert_eq!(
            jdp_distribution_for(MiningMode::Solo),
            JdpDistributionFor::Tailored(TailoredMode::Solo)
        );
        assert_eq!(
            jdp_distribution_for(MiningMode::GroupSolo),
            JdpDistributionFor::Tailored(TailoredMode::GroupSolo)
        );
        assert_eq!(
            jdp_distribution_for(MiningMode::Blockparty),
            JdpDistributionFor::Nothing,
            "a rental is not served over JDP, and must not fall back to pool-wide"
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
            let built = match jdp_distribution_for(mode) {
                JdpDistributionFor::PoolWide => Some(Acct::PoolWide),
                JdpDistributionFor::Tailored(kind) => Some(accounting_for(kind, &miner)),
                // Nothing built, nothing to disagree with.
                JdpDistributionFor::Nothing => None,
            };
            let Some(built) = built else { continue };
            assert!(
                accounting_matches_stream(&built, probed),
                "{mode:?} is built as {built:?} but probes as {probed:?} — a session on this \
                 mode would rebuild its plan on every frame"
            );
        }
    }

    /// Revenue fixed; the allocate path never asks for chain demands.
    struct RevenueOnly;
    impl crate::jdp_hooks::ChainView for RevenueOnly {
        fn demands(&self) -> Option<crate::jdp_hooks::ChainDemands> {
            None
        }
        fn reference_revenue(&self) -> Option<u64> {
            Some(TEST_REWARD)
        }
    }

    /// An address with no mining session gets "not yet", never the gate's
    /// Solo default: a Solo plan published for it would be a guess.
    #[tokio::test]
    async fn an_address_without_a_session_gets_no_distribution_yet() {
        use bp_stratum_v2::jdp_server::PayoutDistributionSource;
        let gate = Arc::new(BlitzpoolModeGate::new());
        let source = ProductionDistributionSource {
            resolver: Arc::new(ProductionPayoutResolver::new(
                gate.clone(),
                None,
                None,
                SoloFeeConfig::default(),
                None,
                None,
            )),
            chain: Arc::new(RevenueOnly),
            redis: None,
            network: bitcoin::Network::Regtest,
        };
        let miner = AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap();
        assert!(matches!(
            source.build_for_miner(&miner).await,
            TailoredDistribution::ModeUnknown
        ));
        gate.set_mode(miner.as_str(), MiningModeResult::Solo);
        assert!(
            matches!(
                source.build_for_miner(&miner).await,
                TailoredDistribution::Unavailable
            ),
            "control: once its session registers Solo, it is answered (no fee: base protocol)"
        );
    }

    /// Solo and Group-Solo map to distinct tailored builds.
    #[test]
    fn the_two_tailored_modes_are_distinct() {
        assert_ne!(
            jdp_distribution_for(MiningMode::Solo),
            jdp_distribution_for(MiningMode::GroupSolo)
        );
    }

    /// A Solo coinbase gets an ext 0x0003 distribution only through its fee
    /// output; without one it pays the miner alone, which base-protocol Job
    /// Declaration serves.
    #[test]
    fn a_solo_fee_output_is_found_only_when_the_coinbase_pays_one() {
        const MINER: &str = "bc1qminer";
        const DEV: &str = "bc1qdev";
        let entries = |fee: &SoloFeeConfig| -> Vec<(String, u64)> {
            solo_payouts(MINER, fee, TEST_REWARD)
                .into_iter()
                .map(|p| (p.address, p.sats))
                .collect()
        };

        let no_fee = SoloFeeConfig::default();
        assert_eq!(entries(&no_fee).len(), 1, "precondition: the miner alone");
        assert_eq!(solo_fee_output(&entries(&no_fee), &no_fee), None);

        let zero_fee = SoloFeeConfig {
            dev_fee_address: Some(DEV.to_string()),
            dev_fee_percent: 0.0,
        };
        assert_eq!(
            entries(&zero_fee).len(),
            1,
            "precondition: a 0 % fee pays nobody"
        );
        assert_eq!(solo_fee_output(&entries(&zero_fee), &zero_fee), None);

        let with_fee = SoloFeeConfig {
            dev_fee_address: Some(DEV.to_string()),
            dev_fee_percent: 1.0,
        };
        let paid = entries(&with_fee);
        let (address, sats) = solo_fee_output(&paid, &with_fee).expect("the fee output");
        assert_eq!(address, DEV);
        assert!(sats > 0);
        assert!(
            paid.iter().any(|(a, s)| a == DEV && *s == sats),
            "the fee output is the one the coinbase pays"
        );
    }
}
