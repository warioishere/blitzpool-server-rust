// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a payout mode's coinbase pays for one address at one revenue: the one
//! per-mode build behind the Stratum payout resolver, the JDP ext 0x0003
//! tailored distribution and the API block preview, so the three cannot drift.
//! Each failure is logged here with its cause; the caller decides what an
//! empty answer means for it.

use std::sync::Arc;

use bp_blockparty::CoinbaseDistributionEntry;
use bp_blockparty_engine::BlockpartyPayouts;
use bp_coinbase_snapshot::BuiltDistribution;
use bp_common::{AddressId, Sats};
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_mining_job::{solo_payouts, PayoutEntry, ResolvedPayouts, SoloFeeConfig};
use bp_mining_mode::MiningModeResult;
use bp_pplns_engine::engine::PplnsEngine;
use tracing::{error, warn};
use uuid::Uuid;

/// The engines the modes build from, borrowed from whichever process holds
/// them. A mode whose engine is `None` gets no job.
#[derive(Clone, Copy)]
pub struct ModeEngines<'a> {
    pub pplns: Option<&'a PplnsEngine>,
    pub group_solo: Option<&'a GroupSoloEngine>,
    pub blockparty: Option<&'a BlockpartyPayouts>,
    pub solo_fee: &'a SoloFeeConfig,
}

/// One mode's build for one address.
#[derive(Debug)]
pub enum ModeBuild {
    /// Exact sats per output at the revenue it was built for: Solo and
    /// Blockparty.
    Exact(Vec<PayoutEntry>),
    /// A weight distribution, evaluated per template revenue with
    /// ext 0x0003/Payout Computation: PPLNS and Group-Solo.
    Weighted(Arc<BuiltDistribution>),
    /// Nothing can be built now; the cause is logged.
    NoJob,
}

impl ModeEngines<'_> {
    /// `miner` is the address the job is for: the Solo payee, the claimant of
    /// an empty PPLNS window, the Group-Solo finder, the Blockparty admin.
    pub async fn build(
        &self,
        mode: MiningModeResult,
        miner: &AddressId,
        reward_sats: u64,
    ) -> ModeBuild {
        match mode {
            MiningModeResult::Solo => {
                ModeBuild::Exact(solo_payouts(miner.as_str(), self.solo_fee, reward_sats))
            }
            MiningModeResult::Pplns => self.pplns(miner, reward_sats).await,
            MiningModeResult::GroupSolo(group_id) => {
                self.group_solo(group_id, miner, reward_sats).await
            }
            MiningModeResult::Blockparty(group_id) => {
                self.blockparty(group_id, miner, reward_sats).await
            }
        }
    }

    /// [`Self::build`] as the coinbase payout list at `reward_sats`.
    pub async fn payouts_at(
        &self,
        mode: MiningModeResult,
        miner: &AddressId,
        reward_sats: u64,
    ) -> ResolvedPayouts {
        match self.build(mode, miner, reward_sats).await {
            ModeBuild::Exact(entries) => ResolvedPayouts::unsnapshotted(entries),
            ModeBuild::Weighted(built) => lower_built(mode, &built, miner, reward_sats),
            ModeBuild::NoJob => ResolvedPayouts::none(),
        }
    }

    async fn pplns(&self, miner: &AddressId, reward_sats: u64) -> ModeBuild {
        let Some(pplns) = self.pplns else {
            error!(
                miner = miner.as_str(),
                "PPLNS mode but `[pplns]` is absent from config; no payout list"
            );
            return ModeBuild::NoJob;
        };
        // The pool-wide build is shared and cannot name a claimant; an empty
        // window (`NoScoredMiners`) is answered per miner below.
        let built = match pplns.build_distribution(reward_sats).await {
            Ok(built) => built,
            // Empty window: the weight model would pay the whole block to the
            // pool, and no job would deadlock it. This miner claims the block;
            // nobody else has a claim and the pool takes only its fee.
            Err(err) if is_empty_share_window(&err) => {
                match pplns.build_bootstrap_distribution(reward_sats, miner).await {
                    Ok(built) => built,
                    Err(err) => {
                        error!(
                            %err,
                            miner = miner.as_str(),
                            reward_sats,
                            "PPLNS window holds no scored miner and the bootstrap build \
                             failed too; no payout list"
                        );
                        return ModeBuild::NoJob;
                    }
                }
            }
            Err(err) => {
                error!(
                    %err,
                    miner = miner.as_str(),
                    reward_sats,
                    "PPLNS distribution build failed; no payout list until it succeeds"
                );
                return ModeBuild::NoJob;
            }
        };
        ModeBuild::Weighted(built)
    }

    async fn group_solo(&self, group_id: Uuid, finder: &AddressId, reward_sats: u64) -> ModeBuild {
        let Some(group_solo) = self.group_solo else {
            error!(
                miner = finder.as_str(),
                %group_id,
                "Group-Solo mode but `[group_solo]` is absent from config; no payout list"
            );
            return ModeBuild::NoJob;
        };
        match group_solo
            .build_distribution(group_id, reward_sats, finder)
            .await
        {
            Ok(built) => ModeBuild::Weighted(built),
            Err(err) => {
                error!(
                    %err,
                    miner = finder.as_str(),
                    %group_id,
                    reward_sats,
                    "Group-Solo distribution build failed; no payout list until it succeeds"
                );
                ModeBuild::NoJob
            }
        }
    }

    /// The members' split, or no job when it cannot be built: only the admin
    /// hashes, so a solo coinbase would pay the admin the whole block.
    async fn blockparty(&self, group_id: Uuid, admin: &AddressId, reward_sats: u64) -> ModeBuild {
        let Some(blockparty) = self.blockparty else {
            error!(
                miner = admin.as_str(),
                "Blockparty mode but its service is not wired; no payout list"
            );
            return ModeBuild::NoJob;
        };
        match blockparty
            .build_payouts(group_id, Sats(reward_sats as i64))
            .await
        {
            Ok(Some(result)) => ModeBuild::Exact(entries_to_payouts(&result.payouts)),
            Ok(None) => {
                warn!(
                    miner = admin.as_str(),
                    %group_id,
                    "Blockparty group not found; no payout list"
                );
                ModeBuild::NoJob
            }
            Err(err) => {
                warn!(
                    %err,
                    miner = admin.as_str(),
                    %group_id,
                    "Blockparty distribution build failed; no payout list until it succeeds"
                );
                ModeBuild::NoJob
            }
        }
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

/// A PPLNS or Group-Solo build as this template's coinbase list, evaluated with
/// ext 0x0003/Payout Computation at this template's revenue, the same formula a
/// JDC runs with its own. An unbookable build still stands: failing would hand
/// this miner the whole block.
fn lower_built(
    mode: MiningModeResult,
    built: &BuiltDistribution,
    miner: &AddressId,
    reward_sats: u64,
) -> ResolvedPayouts {
    if !built.bookable {
        warn!(
            ?mode,
            miner = miner.as_str(),
            reward_sats,
            "distribution built but not bookable; the coinbase stands, a block found on \
             it cannot be booked automatically"
        );
    }
    match built.distribution.payout_entries_at(reward_sats) {
        Ok(entries) => ResolvedPayouts {
            entries: entries
                .into_iter()
                .map(|(address, sats)| PayoutEntry {
                    address: address.into_inner(),
                    sats,
                })
                .collect(),
            payouts_fingerprint: built.payouts_fingerprint(),
            coinbase_tag: None,
        },
        Err(err) => {
            error!(
                %err,
                ?mode,
                miner = miner.as_str(),
                reward_sats,
                "ext 0x0003/Payout Computation evaluation failed; no payout list"
            );
            ResolvedPayouts::none()
        }
    }
}

/// Engine entries as coinbase `PayoutEntry`s, carrying the exact sats the
/// distributor computed; the coinbase builder never re-derives them from a
/// percentage.
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
    const MINER: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    fn no_fee() -> SoloFeeConfig {
        SoloFeeConfig {
            dev_fee_address: None,
            dev_fee_percent: 0.0,
        }
    }

    fn miner() -> AddressId {
        AddressId::new(MINER).unwrap()
    }

    /// Without its engine, every engine-backed mode serves no job; Solo needs
    /// none and pays the miner.
    #[tokio::test]
    async fn a_mode_without_its_engine_serves_no_job() {
        let fee = no_fee();
        let engines = ModeEngines {
            pplns: None,
            group_solo: None,
            blockparty: None,
            solo_fee: &fee,
        };
        let group = Uuid::new_v4();
        for mode in [
            MiningModeResult::Pplns,
            MiningModeResult::GroupSolo(group),
            MiningModeResult::Blockparty(group),
        ] {
            assert!(
                matches!(
                    engines.build(mode, &miner(), TEST_REWARD).await,
                    ModeBuild::NoJob
                ),
                "{mode:?}"
            );
        }
        let solo = engines
            .payouts_at(MiningModeResult::Solo, &miner(), TEST_REWARD)
            .await;
        assert_eq!(solo.entries.len(), 1);
        assert_eq!(solo.entries[0].address, MINER);
        assert_eq!(solo.entries[0].sats, TEST_REWARD);
    }

    /// An empty PPLNS window is built for the asking miner, not answered with
    /// no job: no job would deadlock a fresh pool, whose first share could then
    /// never land.
    #[tokio::test]
    async fn an_empty_pplns_window_is_built_for_the_asking_miner() {
        use bp_pplns_engine::config::PplnsEngineConfig;
        use bp_pplns_engine::window::NetworkDifficulty;
        // The index `bp_test_support::redis_db::PPLNS_ENGINE` lends this binary.
        let Some(redis) = bp_test_support::connect_redis_in_range_or_skip(
            bp_test_support::redis_db::PPLNS_ENGINE,
            31,
        )
        .await
        else {
            return;
        };
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        const ASKER: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let config = PplnsEngineConfig {
            dust_sweep_enabled: false,
            fee_address: Some(AddressId::new("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap()),
            ..PplnsEngineConfig::default()
        };
        let engine = PplnsEngine::spawn(config, redis, pool, NetworkDifficulty::new(1_000_000.0))
            .await
            .expect("the engine spawns on reachable services");
        assert!(
            engine.build_distribution(TEST_REWARD).await.is_err(),
            "precondition: the window is empty"
        );
        let fee = no_fee();
        let engines = ModeEngines {
            pplns: Some(&engine),
            group_solo: None,
            blockparty: None,
            solo_fee: &fee,
        };
        let resolved = engines
            .payouts_at(
                MiningModeResult::Pplns,
                &AddressId::new(ASKER).unwrap(),
                TEST_REWARD,
            )
            .await;
        assert!(
            resolved
                .entries
                .iter()
                .any(|p| p.address == ASKER && p.sats > 0),
            "the asking miner must be paid, got {:?}",
            resolved.entries
        );
    }

    fn blockparty_payouts_on(pool: sqlx::PgPool) -> BlockpartyPayouts {
        BlockpartyPayouts::new(
            pool,
            bp_blockparty_engine::BlockpartyPayoutConfig {
                fee_address: bp_common::AddressId::new(
                    "bcrt1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
                )
                .unwrap(),
                fee_percent: 2.0,
                min_payout_sats: bp_common::Sats(5_000),
            },
        )
    }

    /// The admin is the only one hashing, so a solo coinbase here would pay
    /// the whole block to the admin and nothing to the members.
    async fn assert_no_job(svc: &BlockpartyPayouts, group_id: Uuid, case: &str) {
        let fee = no_fee();
        let engines = ModeEngines {
            pplns: None,
            group_solo: None,
            blockparty: Some(svc),
            solo_fee: &fee,
        };
        let resolved = engines
            .payouts_at(
                MiningModeResult::Blockparty(group_id),
                &miner(),
                TEST_REWARD,
            )
            .await;
        assert!(
            resolved.is_none(),
            "{case}: must serve no job, got {:?}",
            resolved.entries
        );
    }

    #[tokio::test]
    async fn a_blockparty_whose_split_build_fails_serves_no_job() {
        let gid = Uuid::new_v4();
        let unreachable = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(300))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/nope")
            .expect("a lazily-connected pool parses its url");
        let svc = blockparty_payouts_on(unreachable);
        assert!(
            svc.build_payouts(gid, Sats(TEST_REWARD as i64))
                .await
                .is_err(),
            "precondition: the split build must fail on this pool"
        );
        assert_no_job(&svc, gid, "database error").await;
    }

    #[tokio::test]
    async fn a_blockparty_whose_group_is_gone_serves_no_job() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let svc = blockparty_payouts_on(pool);
        let gid = Uuid::new_v4();
        assert!(
            matches!(
                svc.build_payouts(gid, Sats(TEST_REWARD as i64)).await,
                Ok(None)
            ),
            "precondition: a fresh group id must resolve to no group"
        );
        assert_no_job(&svc, gid, "group not found").await;
    }

    /// Pins what PPLNS and Group-Solo hand the job builder: the §4 list at
    /// this revenue and the fingerprint, with or without the snapshot.
    #[test]
    fn a_built_distribution_lowers_to_its_payout_list() {
        use std::collections::HashMap;
        let a = AddressId::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string()).unwrap();
        let b = AddressId::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string()).unwrap();
        let fee = AddressId::new("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy".to_string()).unwrap();
        let shares = HashMap::from([(a.clone(), 60.0), (b.clone(), 40.0)]);
        let distribution = bp_pplns::build_weight_distribution(bp_pplns::WeightDistributionInput {
            address_shares: &shares,
            balances: &HashMap::new(),
            fee_percent: 1.5,
            fee_address: &fee,
            coinbase_weight_budget: 50_000,
            min_payout_sats: Sats(5_000),
            finder_bonus_ppm: 0,
            finder_address: None,
            reference_revenue_sats: TEST_REWARD,
            withheld_value: bp_pplns::WithheldValue::ToOtherMiners,
        })
        .unwrap();
        let reward = TEST_REWARD + 12_345;
        let expected: Vec<(String, u64)> = distribution
            .payout_entries_at(reward)
            .unwrap()
            .into_iter()
            .map(|(addr, sats)| (addr.into_inner(), sats))
            .collect();
        assert_eq!(
            expected.len(),
            3,
            "precondition: pool output plus both miners"
        );

        for promised in [true, false] {
            let built = BuiltDistribution {
                distribution: distribution.clone(),
                bookable: promised,
            };
            let resolved = lower_built(MiningModeResult::Pplns, &built, &miner(), reward);
            let got: Vec<(String, u64)> = resolved
                .entries
                .into_iter()
                .map(|p| (p.address, p.sats))
                .collect();
            assert_eq!(
                got, expected,
                "the coinbase stands with or without the snapshot"
            );
            assert_eq!(resolved.payouts_fingerprint, distribution.fingerprint);
        }
    }

    #[test]
    fn entries_to_payouts_carries_exact_sats() {
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
