// SPDX-License-Identifier: AGPL-3.0-or-later

//! Blockparty payout split. Members get `floor(minerCut * percentBp / 10000)`
//! of the reward minus the base fee; a share below the dust floor is trimmed
//! into the pool-fee output (no carry-forward), as is the rounding leftover,
//! so outputs sum to the reward exactly. `Σ percentBp == 10000` is trusted.

use bp_common::{AddressId, Sats};
use serde::{Deserialize, Serialize};

/// One coinbase output of a party's split.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CoinbaseDistributionEntry {
    pub address: AddressId,
    pub percent: f64,
    pub sats: Sats,
}

/// Persisted as-is into `blockparty_block_history.splits` (JSONB).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockpartySplitSnapshot {
    pub address: String,
    pub percent_bp: i32,
    pub sats: i64,
    /// The coinbase paid it nothing (its share fell below the dust floor);
    /// `sats` is 0.
    #[serde(default, skip_serializing_if = "is_false")]
    pub trimmed: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Copy, Clone, Debug)]
pub struct BlockpartyMemberInput<'a> {
    pub address: &'a AddressId,
    /// Basis points: 100 = 1%, 10_000 = 100%.
    pub percent_bp: i32,
}

pub struct BlockpartyDistributionInput<'a> {
    pub members: &'a [BlockpartyMemberInput<'a>],
    pub block_reward_sats: Sats,
    pub pool_fee_address: &'a AddressId,
    /// Decimal percent, e.g. `2.0` for 2 %.
    pub pool_fee_percent: f64,
    /// At least `DUST_LIMIT_SATS`: boot refuses a smaller
    /// `[blockparty].min_payout_sats`.
    pub min_payout_sats: Sats,
}

#[derive(Clone, Debug)]
pub struct BlockpartyDistributionResult {
    /// Coinbase outputs, pool fee first then non-trimmed members. The pool
    /// fee output carries the base fee plus trimmed amounts plus rounding.
    pub payouts: Vec<CoinbaseDistributionEntry>,
}

pub fn build_blockparty_distribution(
    input: BlockpartyDistributionInput<'_>,
) -> BlockpartyDistributionResult {
    let reward = input.block_reward_sats.0;
    if reward <= 0 {
        return BlockpartyDistributionResult {
            payouts: Vec::new(),
        };
    }

    if input.members.is_empty() {
        return BlockpartyDistributionResult {
            payouts: vec![CoinbaseDistributionEntry {
                address: input.pool_fee_address.clone(),
                percent: 100.0,
                sats: Sats(reward),
            }],
        };
    }

    let dust = input.min_payout_sats.0;

    // The f64 floor stays accurate: at real reward sizes the product fits
    // well inside f64's 53-bit integer range.
    let base_pool_fee = ((reward as f64 * input.pool_fee_percent) / 100.0).floor() as i64;
    let miner_cut = reward - base_pool_fee;

    // A share below the dust floor is trimmed to 0.
    let member_sats: Vec<i64> = input
        .members
        .iter()
        .map(|m| {
            let nominal = ((miner_cut as i128 * m.percent_bp as i128) / 10_000) as i64;
            if nominal < dust {
                0
            } else {
                nominal
            }
        })
        .collect();
    let pool_fee = reward - member_sats.iter().sum::<i64>();

    let mut payouts = Vec::with_capacity(input.members.len() + 1);
    if pool_fee > 0 {
        payouts.push(CoinbaseDistributionEntry {
            address: input.pool_fee_address.clone(),
            percent: (pool_fee as f64 / reward as f64) * 100.0,
            sats: Sats(pool_fee),
        });
    }
    for (m, &sats) in input.members.iter().zip(&member_sats) {
        if sats > 0 {
            payouts.push(CoinbaseDistributionEntry {
                address: m.address.clone(),
                percent: (sats as f64 / reward as f64) * 100.0,
                sats: Sats(sats),
            });
        }
    }

    BlockpartyDistributionResult { payouts }
}

/// The split a found block's coinbase actually paid, one entry per member in
/// roster order: its sats as `paid_to` reports them, marked trimmed when the
/// coinbase paid it nothing.
pub fn splits_paid(
    members: &[BlockpartyMemberInput<'_>],
    paid_to: impl Fn(&AddressId) -> u64,
) -> Vec<BlockpartySplitSnapshot> {
    members
        .iter()
        .map(|m| {
            let sats = paid_to(m.address);
            BlockpartySplitSnapshot {
                address: m.address.as_str().to_owned(),
                percent_bp: m.percent_bp,
                sats: sats as i64,
                trimmed: sats == 0,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::AddressId;

    fn addr(s: &str) -> AddressId {
        AddressId::new(s).expect("test address shape")
    }

    fn fee_addr() -> AddressId {
        addr("bc1qfeeaddress")
    }

    /// What the outputs pay `address`; 0 when no output pays it.
    fn paid(r: &BlockpartyDistributionResult, address: &AddressId) -> i64 {
        r.payouts
            .iter()
            .filter(|p| &p.address == address)
            .map(|p| p.sats.0)
            .sum()
    }

    fn input<'a>(
        members: &'a [BlockpartyMemberInput<'a>],
        fee: &'a AddressId,
        reward: i64,
        fee_percent: f64,
        min_payout: i64,
    ) -> BlockpartyDistributionInput<'a> {
        BlockpartyDistributionInput {
            members,
            block_reward_sats: Sats(reward),
            pool_fee_address: fee,
            pool_fee_percent: fee_percent,
            min_payout_sats: Sats(min_payout),
        }
    }

    #[test]
    fn returns_empty_when_reward_is_zero() {
        let a = addr("bc1qaaaaa");
        let members = [BlockpartyMemberInput {
            address: &a,
            percent_bp: 10_000,
        }];
        let fee = fee_addr();
        let r = build_blockparty_distribution(input(&members, &fee, 0, 2.0, 5_000));
        assert!(r.payouts.is_empty());
    }

    #[test]
    fn routes_full_reward_to_pool_fee_when_no_members() {
        let reward = 312_500_000;
        let fee = fee_addr();
        let r = build_blockparty_distribution(input(&[], &fee, reward, 2.0, 5_000));
        assert_eq!(r.payouts.len(), 1);
        assert_eq!(r.payouts[0].sats, Sats(reward));
        assert_eq!(r.payouts[0].address, fee);
    }

    #[test]
    fn splits_miner_cut_by_basis_points_and_balances_against_pool_fee() {
        let reward = 312_500_000i64;
        let a = addr("bc1qaaaaa");
        let b = addr("bc1qbbbbb");
        let c = addr("bc1qccccc");
        let members = [
            BlockpartyMemberInput {
                address: &a,
                percent_bp: 5_000,
            },
            BlockpartyMemberInput {
                address: &b,
                percent_bp: 3_000,
            },
            BlockpartyMemberInput {
                address: &c,
                percent_bp: 2_000,
            },
        ];
        let fee = fee_addr();
        let r = build_blockparty_distribution(input(&members, &fee, reward, 2.0, 5_000));

        let base_fee = (reward as f64 * 2.0 / 100.0).floor() as i64;
        let miner_cut = reward - base_fee;
        let expect_a = (miner_cut as i128 * 5_000 / 10_000) as i64;
        let expect_b = (miner_cut as i128 * 3_000 / 10_000) as i64;
        let expect_c = (miner_cut as i128 * 2_000 / 10_000) as i64;

        assert_eq!(paid(&r, &a), expect_a);
        assert_eq!(paid(&r, &b), expect_b);
        assert_eq!(paid(&r, &c), expect_c);

        let total_out: i64 = r.payouts.iter().map(|p| p.sats.0).sum();
        assert_eq!(total_out, reward, "outputs must sum exactly to reward");
        assert_eq!(paid(&r, &fee), reward - (expect_a + expect_b + expect_c));
    }

    #[test]
    fn rolls_sub_min_payout_members_into_pool_fee_with_trimmed_flag() {
        // 1% of 98000 miner-cut = 980 sats < 5000 minPayout → trimmed.
        let reward = 100_000i64;
        let a = addr("bc1qaaaaa");
        let b = addr("bc1qbbbbb");
        let members = [
            BlockpartyMemberInput {
                address: &a,
                percent_bp: 9_900,
            },
            BlockpartyMemberInput {
                address: &b,
                percent_bp: 100,
            },
        ];
        let fee = fee_addr();
        let r = build_blockparty_distribution(input(&members, &fee, reward, 2.0, 5_000));

        assert_eq!(paid(&r, &b), 0, "trimmed: no output");
        assert!(paid(&r, &a) > 0);

        let base_fee = (reward as f64 * 2.0 / 100.0).floor() as i64;
        assert!(paid(&r, &fee) > base_fee, "trimmed sats roll into pool fee");

        let total_out: i64 = r.payouts.iter().map(|p| p.sats.0).sum();
        assert_eq!(total_out, reward);
    }

    #[test]
    fn conserves_total_sats_across_assorted_cases() {
        let a = addr("bc1qaaaaa");
        let b = addr("bc1qbbbbb");
        let c = addr("bc1qccccc");
        let members = [
            BlockpartyMemberInput {
                address: &a,
                percent_bp: 3_333,
            },
            BlockpartyMemberInput {
                address: &b,
                percent_bp: 3_333,
            },
            BlockpartyMemberInput {
                address: &c,
                percent_bp: 3_334,
            },
        ];
        let fee = fee_addr();
        for (reward, pct) in [
            (312_500_000i64, 2.0f64),
            (156_250_000, 1.5),
            (78_125_000, 0.0),
            (1_000_000_000, 5.0),
        ] {
            let r = build_blockparty_distribution(input(&members, &fee, reward, pct, 5_000));
            let total: i64 = r.payouts.iter().map(|p| p.sats.0).sum();
            assert_eq!(
                total, reward,
                "conservation broken for reward={reward} pct={pct}"
            );
        }
    }

    #[test]
    fn ordering_is_pool_fee_then_members_in_input_order() {
        let a = addr("bc1qaaaaa");
        let b = addr("bc1qbbbbb");
        let members = [
            BlockpartyMemberInput {
                address: &a,
                percent_bp: 5_000,
            },
            BlockpartyMemberInput {
                address: &b,
                percent_bp: 5_000,
            },
        ];
        let fee = fee_addr();
        let r = build_blockparty_distribution(input(&members, &fee, 100_000_000, 2.0, 5_000));
        assert_eq!(r.payouts[0].address, fee);
        assert_eq!(r.payouts[1].address, a);
        assert_eq!(r.payouts[2].address, b);
    }
}
