// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-function payout split for Blockparty groups.
//!
//! Phases:
//!   1. `basePoolFee = floor(reward * poolFeePercent / 100)`
//!   2. `minerCut    = reward − basePoolFee`
//!   3. per member   `floor(minerCut * percentBp / 10000)`
//!   4. sub-threshold members (nominal < max(min_payout, DUST)) →
//!      `sats=0`, `trimmed=true`; their nominal share rolls into the
//!      pool-fee output (no carry-forward, no dust pending).
//!   5. rounding leftover (`reward − Σ paid`) → folded into the pool-
//!      fee output so total outputs == reward exactly.
//!
//! Inputs are trusted: the service layer enforces `Σ percentBp == 10000`.
//! A mis-summed input under/over-pays; the residual lands in pool-fee.

use bp_common::{AddressId, Sats};
use bp_pplns::{CoinbaseDistributionEntry, DUST_LIMIT_SATS};
use serde::{Deserialize, Serialize};

/// One member's split contribution to a block. Persisted as-is into
/// the `blockparty_block_history.splits` JSONB column.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockpartySplitSnapshot {
    pub address: String,
    pub percent_bp: i32,
    pub sats: i64,
    /// `true` when this member's nominal share fell below the dust
    /// floor and was rolled into pool-fee. `sats` is then 0.
    #[serde(default, skip_serializing_if = "is_false")]
    pub trimmed: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One member's input to the distribution. Borrowed `address` so the
/// caller's `BlockpartyMemberRow.address: AddressId` can be passed
/// without cloning.
#[derive(Copy, Clone, Debug)]
pub struct BlockpartyMemberInput<'a> {
    pub address: &'a AddressId,
    /// Basis points: 100 = 1%, 10_000 = 100%.
    pub percent_bp: i32,
}

pub struct BlockpartyDistributionInput<'a> {
    pub members: &'a [BlockpartyMemberInput<'a>],
    pub block_reward_sats: Sats,
    /// `None` = no pool-fee output emitted (caller absorbs the float).
    pub pool_fee_address: Option<&'a AddressId>,
    /// Decimal percent, e.g. `2.0` for 2 %.
    pub pool_fee_percent: f64,
    /// Operational dust floor. Clamped to ≥ `DUST_LIMIT_SATS` at runtime.
    pub min_payout_sats: Sats,
}

#[derive(Clone, Debug)]
pub struct BlockpartyDistributionResult {
    /// Per-member breakdown — one entry per input member, same order.
    pub splits: Vec<BlockpartySplitSnapshot>,
    /// Final pool-fee output sats (base fee + trimmed amounts + rounding).
    pub pool_fee_sats: Sats,
    /// Coinbase outputs, pool fee first then non-trimmed members.
    pub payouts: Vec<CoinbaseDistributionEntry>,
}

pub fn build_blockparty_distribution(
    input: BlockpartyDistributionInput<'_>,
) -> BlockpartyDistributionResult {
    let reward = input.block_reward_sats.0;
    if reward <= 0 {
        return BlockpartyDistributionResult {
            splits: Vec::new(),
            pool_fee_sats: Sats(0),
            payouts: Vec::new(),
        };
    }

    // Empty members → whole reward to pool fee. Skip output if no addr.
    if input.members.is_empty() {
        let payouts = match input.pool_fee_address {
            Some(addr) => vec![CoinbaseDistributionEntry {
                address: addr.clone(),
                percent: 100.0,
                sats: Sats(reward),
            }],
            None => Vec::new(),
        };
        return BlockpartyDistributionResult {
            splits: Vec::new(),
            pool_fee_sats: Sats(reward),
            payouts,
        };
    }

    let dust = input.min_payout_sats.0.max(DUST_LIMIT_SATS as i64);

    // Phase 1+2 — base fee + miner cut. f64 floor stays accurate at
    // canonical reward sizes (≤ 51.2 BTC = 5.12e9 sats) since the
    // product fits well within f64's 53-bit integer window.
    let base_pool_fee = ((reward as f64 * input.pool_fee_percent) / 100.0).floor() as i64;
    let miner_cut = reward - base_pool_fee;

    // Phase 3+4 — per-member floor. i128 multiply is integer-exact and
    // free since miner_cut * percent_bp ≤ 5.12e9 * 10_000 = 5.12e13.
    let mut splits = Vec::with_capacity(input.members.len());
    let mut paid_to_members: i64 = 0;
    for m in input.members {
        let nominal = ((miner_cut as i128 * m.percent_bp as i128) / 10_000) as i64;
        let (sats, trimmed) = if nominal < dust {
            (0, true)
        } else {
            paid_to_members += nominal;
            (nominal, false)
        };
        splits.push(BlockpartySplitSnapshot {
            address: m.address.as_str().to_owned(),
            percent_bp: m.percent_bp,
            sats,
            trimmed,
        });
    }

    let pool_fee = reward - paid_to_members;

    // Reserve worst-case: fee + every member non-trimmed.
    let mut payouts = Vec::with_capacity(input.members.len() + 1);
    if pool_fee > 0 {
        if let Some(addr) = input.pool_fee_address {
            payouts.push(CoinbaseDistributionEntry {
                address: addr.clone(),
                percent: (pool_fee as f64 / reward as f64) * 100.0,
                sats: Sats(pool_fee),
            });
        }
    }
    for (m, s) in input.members.iter().zip(splits.iter()) {
        if s.sats > 0 {
            payouts.push(CoinbaseDistributionEntry {
                address: m.address.clone(),
                percent: (s.sats as f64 / reward as f64) * 100.0,
                sats: Sats(s.sats),
            });
        }
    }

    BlockpartyDistributionResult {
        splits,
        pool_fee_sats: Sats(pool_fee),
        payouts,
    }
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

    fn input<'a>(
        members: &'a [BlockpartyMemberInput<'a>],
        fee: Option<&'a AddressId>,
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
        let r = build_blockparty_distribution(input(&members, Some(&fee), 0, 2.0, 5_000));
        assert!(r.splits.is_empty());
        assert_eq!(r.pool_fee_sats, Sats(0));
        assert!(r.payouts.is_empty());
    }

    #[test]
    fn routes_full_reward_to_pool_fee_when_no_members() {
        let reward = 312_500_000;
        let fee = fee_addr();
        let r = build_blockparty_distribution(input(&[], Some(&fee), reward, 2.0, 5_000));
        assert_eq!(r.pool_fee_sats, Sats(reward));
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
        let r = build_blockparty_distribution(input(&members, Some(&fee), reward, 2.0, 5_000));

        let base_fee = (reward as f64 * 2.0 / 100.0).floor() as i64;
        let miner_cut = reward - base_fee;
        let expect_a = (miner_cut as i128 * 5_000 / 10_000) as i64;
        let expect_b = (miner_cut as i128 * 3_000 / 10_000) as i64;
        let expect_c = (miner_cut as i128 * 2_000 / 10_000) as i64;

        assert_eq!(r.splits[0].sats, expect_a);
        assert_eq!(r.splits[1].sats, expect_b);
        assert_eq!(r.splits[2].sats, expect_c);
        assert!(!r.splits[0].trimmed);
        assert!(!r.splits[1].trimmed);
        assert!(!r.splits[2].trimmed);

        let total_out: i64 = r.payouts.iter().map(|p| p.sats.0).sum();
        assert_eq!(total_out, reward, "outputs must sum exactly to reward");
        assert_eq!(r.pool_fee_sats.0, reward - (expect_a + expect_b + expect_c));
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
        let r = build_blockparty_distribution(input(&members, Some(&fee), reward, 2.0, 5_000));

        assert!(r.splits[1].trimmed);
        assert_eq!(r.splits[1].sats, 0);
        assert!(!r.splits[0].trimmed);

        let base_fee = (reward as f64 * 2.0 / 100.0).floor() as i64;
        assert!(
            r.pool_fee_sats.0 > base_fee,
            "trimmed sats roll into pool fee"
        );

        let total_out: i64 = r.payouts.iter().map(|p| p.sats.0).sum();
        assert_eq!(total_out, reward);
    }

    #[test]
    fn uses_dust_limit_as_effective_floor_when_min_payout_is_lower() {
        // minPayout=100 but DUST=546. A 490-sat output must still trim
        // (Bitcoin relay policy floor). reward=50_000, fee=2% → miner_cut=49_000,
        // 1% of that = 490 < 546.
        let reward = 50_000i64;
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
        let r = build_blockparty_distribution(input(&members, Some(&fee), reward, 2.0, 100));
        assert!(r.splits[1].trimmed);
        assert_eq!(DUST_LIMIT_SATS, 546);
    }

    #[test]
    fn skips_pool_fee_output_when_address_is_none() {
        let reward = 312_500_000i64;
        let a = addr("bc1qaaaaa");
        let members = [BlockpartyMemberInput {
            address: &a,
            percent_bp: 10_000,
        }];
        let r = build_blockparty_distribution(input(&members, None, reward, 2.0, 5_000));
        // No fee output emitted; sum of payouts < reward (the 2% base
        // fee is silently absorbed by the caller).
        assert_eq!(r.payouts.len(), 1);
        assert_eq!(r.payouts[0].address, a);
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
            let r = build_blockparty_distribution(input(&members, Some(&fee), reward, pct, 5_000));
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
        let r = build_blockparty_distribution(input(&members, Some(&fee), 100_000_000, 2.0, 5_000));
        assert_eq!(r.payouts[0].address, fee);
        assert_eq!(r.payouts[1].address, a);
        assert_eq!(r.payouts[2].address, b);
    }
}
