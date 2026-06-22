// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-Solo coinbase distribution. Thin adapter on top of
//! [`bp_pplns::build_coinbase_distribution`] that sets the Group-Solo
//! invariants: `suppress_matching_debits = true` and the finder-bonus
//! parameters.
//!
//! Why a wrapper and not a direct call: this is the single call-site that
//! makes Group-Solo semantics explicit, prevents the next reader from
//! wondering whether `suppress_matching_debits` is supposed to be `true`
//! here, and gives stratum-/api-callers a typed Group-Solo input shape
//! instead of forcing them to remember which `bp-pplns` knobs to flip.

use std::collections::HashMap;

use bp_common::{AddressId, Sats};
use bp_pplns::{
    build_coinbase_distribution, CoinbaseDistributionInput, CoinbaseDistributionResult,
};

use crate::round::GroupRoundState;

/// Inputs to a single Group-Solo coinbase distribution build.
pub struct GroupSoloDistributionInput<'a> {
    /// Live per-round share state for this group.
    pub round: &'a GroupRoundState,
    /// Signed ledger balances at distribution time, keyed by miner
    /// address. Same shape as the PPLNS one; sign convention matches
    /// `bp-pplns`.
    pub balances: &'a HashMap<AddressId, Sats>,
    /// Full block reward (subsidy + mempool fees).
    pub block_reward_sats: Sats,
    /// Pool fee percent, e.g. `2.0` for 2 %.
    pub fee_percent: f64,
    /// Pool fee payout address. `None` → no fee output.
    pub fee_address: Option<&'a AddressId>,
    /// Max weight units for coinbase outputs. `0` falls back to the
    /// `bp-pplns` default.
    pub coinbase_weight_budget: u32,
    /// Operational minimum on-chain output. `None` falls back to the
    /// `bp-pplns` dust-limit default.
    pub min_payout_sats: Option<Sats>,
    /// Finder-bonus carve-out (paid as a dedicated coinbase output on top
    /// of the finder's proportional share). Requires both
    /// `finder_bonus_sats` AND `finder_address` to be set to take effect.
    pub finder_bonus_sats: Option<Sats>,
    pub finder_address: Option<&'a AddressId>,
}

/// Build a Group-Solo coinbase distribution. Pure function — the result
/// is suitable for either:
///
/// - Coinbase template assembly (caller persists the snapshot and
///   includes the payouts in the SV2 / SV1 coinbase).
/// - Ledger application after block-found (caller writes `balance_after`
///   as absolute values to `pplns_group_balance`).
pub fn build_group_solo_distribution(
    input: GroupSoloDistributionInput<'_>,
) -> CoinbaseDistributionResult {
    build_coinbase_distribution(CoinbaseDistributionInput {
        address_shares: input.round.address_shares(),
        balances: input.balances,
        block_reward_sats: input.block_reward_sats,
        fee_percent: input.fee_percent,
        fee_address: input.fee_address,
        coinbase_weight_budget: input.coinbase_weight_budget,
        // Group-Solo invariant: trims donate to fee instead of creating
        // matching debits on active miners.
        suppress_matching_debits: true,
        min_payout_sats: input.min_payout_sats,
        finder_bonus_sats: input.finder_bonus_sats,
        finder_address: input.finder_address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> AddressId {
        AddressId::new(s.to_string()).expect("valid test address")
    }

    #[test]
    fn empty_round_falls_back_to_fee_only() {
        let round = GroupRoundState::new();
        let balances = HashMap::new();
        let fee = addr("bc1qfee");
        let result = build_group_solo_distribution(GroupSoloDistributionInput {
            round: &round,
            balances: &balances,
            block_reward_sats: Sats(5_000_000_000),
            fee_percent: 2.0,
            fee_address: Some(&fee),
            coinbase_weight_budget: 0,
            min_payout_sats: None,
            finder_bonus_sats: None,
            finder_address: None,
        });
        // bp-pplns fallback: 100% to fee address.
        assert_eq!(result.payouts.len(), 1);
        assert_eq!(result.payouts[0].address, fee);
        assert_eq!(result.payouts[0].sats, Sats(5_000_000_000));
    }

    #[test]
    fn single_miner_gets_majority_share_after_fee() {
        let mut round = GroupRoundState::new();
        round.record_share(addr("bc1qalice"), 100.0, 1_000);
        let balances = HashMap::new();
        let fee = addr("bc1qfee");
        let result = build_group_solo_distribution(GroupSoloDistributionInput {
            round: &round,
            balances: &balances,
            block_reward_sats: Sats(5_000_000_000),
            fee_percent: 2.0,
            fee_address: Some(&fee),
            coinbase_weight_budget: 0,
            min_payout_sats: None,
            finder_bonus_sats: None,
            finder_address: None,
        });
        // 2% fee + 98% to alice.
        let fee_out = result
            .payouts
            .iter()
            .find(|p| p.address == fee)
            .expect("fee out");
        let alice_out = result
            .payouts
            .iter()
            .find(|p| p.address == addr("bc1qalice"))
            .expect("alice out");
        assert_eq!(fee_out.sats, Sats(100_000_000));
        // alice ≈ reward - fee = 4_900_000_000 (off by ≤1 sat rounding).
        let diff = (alice_out.sats.to_i64() - 4_900_000_000).abs();
        assert!(diff <= 1, "alice payout {}", alice_out.sats.to_i64());
    }

    #[test]
    fn proportional_split_two_miners() {
        let mut round = GroupRoundState::new();
        round.record_share(addr("bc1qalice"), 75.0, 1_000);
        round.record_share(addr("bc1qbob"), 25.0, 1_001);
        let balances = HashMap::new();
        let fee = addr("bc1qfee");
        let result = build_group_solo_distribution(GroupSoloDistributionInput {
            round: &round,
            balances: &balances,
            block_reward_sats: Sats(1_000_000_000),
            fee_percent: 0.0,
            fee_address: Some(&fee),
            coinbase_weight_budget: 0,
            min_payout_sats: None,
            finder_bonus_sats: None,
            finder_address: None,
        });
        let alice = result
            .payouts
            .iter()
            .find(|p| p.address == addr("bc1qalice"))
            .expect("alice out")
            .sats
            .to_i64();
        let bob = result
            .payouts
            .iter()
            .find(|p| p.address == addr("bc1qbob"))
            .expect("bob out")
            .sats
            .to_i64();
        // 75/25 split of 1B sats; allow ±1 sat for floor rounding.
        assert!((alice - 750_000_000).abs() <= 1);
        assert!((bob - 250_000_000).abs() <= 1);
    }

    #[test]
    fn finder_bonus_routes_extra_to_finder() {
        let mut round = GroupRoundState::new();
        round.record_share(addr("bc1qalice"), 50.0, 1_000);
        round.record_share(addr("bc1qbob"), 50.0, 1_001);
        let balances = HashMap::new();
        let fee = addr("bc1qfee");
        let alice = addr("bc1qalice");
        let result = build_group_solo_distribution(GroupSoloDistributionInput {
            round: &round,
            balances: &balances,
            block_reward_sats: Sats(1_000_000_000),
            fee_percent: 0.0,
            fee_address: Some(&fee),
            coinbase_weight_budget: 0,
            min_payout_sats: None,
            finder_bonus_sats: Some(Sats(100_000_000)), // 0.1 BTC bonus
            finder_address: Some(&alice),
        });
        let alice_total = result
            .payouts
            .iter()
            .filter(|p| p.address == alice)
            .map(|p| p.sats.to_i64())
            .sum::<i64>();
        let bob_total = result
            .payouts
            .iter()
            .filter(|p| p.address == addr("bc1qbob"))
            .map(|p| p.sats.to_i64())
            .sum::<i64>();
        // Alice gets the 100M bonus on top of her proportional cut.
        // Both miners share the residual (reward - bonus) 50/50, so each
        // gets ~450M, plus alice gets the 100M bonus → ~550M.
        assert!(
            alice_total > bob_total + 90_000_000,
            "alice {} bob {}",
            alice_total,
            bob_total
        );
    }

    #[test]
    fn suppress_matching_debits_keeps_group_solo_on_unsigned_pending() {
        // A miner with no current-round shares but a previously-credited
        // balance should NOT be debited in Group-Solo. In PPLNS-mode
        // (`suppress_matching_debits = false`) that miner would see a
        // matching debit; in Group-Solo we leave them alone (pending stays
        // intact until their next pending credit).
        let mut round = GroupRoundState::new();
        round.record_share(addr("bc1qalice"), 100.0, 1_000);
        let mut balances = HashMap::new();
        balances.insert(addr("bc1qhistorical"), Sats(50_000));
        let fee = addr("bc1qfee");
        let result = build_group_solo_distribution(GroupSoloDistributionInput {
            round: &round,
            balances: &balances,
            block_reward_sats: Sats(5_000_000_000),
            fee_percent: 0.0,
            fee_address: Some(&fee),
            coinbase_weight_budget: 0,
            min_payout_sats: None,
            finder_bonus_sats: None,
            finder_address: None,
        });
        // Historical miner's balance must not have been mutated.
        let historical_after = result.balance_after.get(&addr("bc1qhistorical"));
        // Either untouched (not present in balance_after) or unchanged.
        if let Some(b) = historical_after {
            assert_eq!(*b, Sats(50_000));
        }
    }
}
