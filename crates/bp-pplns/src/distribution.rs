// SPDX-License-Identifier: AGPL-3.0-or-later

//! 5-phase coinbase distribution with signed credit/debit ledger.
//!
//! Phases:
//!
//! 1. **rawFair** per miner: `floor(shares / totalShares × rewardForMiners)`.
//! 2. **target** per miner: `rawFair + balance_old` (signed).
//! 3. **Eligibility**: `target ≥ min_payout` → on-chain output; otherwise
//!    target stays in the ledger as the new balance.
//! 4. **Weight-budget trim**: greedy-keep largest-target-first up to the
//!    coinbase weight budget. Trimmed miners' target becomes their new
//!    balance.
//! 5. **Phase 5a**: redistribute trimmed sats (only the share-this-block
//!    portion) to kept active miners proportionally to shares, with
//!    matching per-miner debits.
//! 5. **Phase 5a.5**: solvency cap — if Σ(kept.onChain) > rewardForMiners,
//!    reduce credit-claimers' on-chain amounts proportionally to their
//!    `balance_old` and carry the uncovered portion forward.
//! 5. **Phase 5b**: residuum distribution — any positive remainder
//!    (floor-rounding, sub-dust accumulation) goes to kept active miners
//!    proportionally to shares, with matching debits so the ledger stays
//!    pool-neutral.
//! 6. **Build payouts + balanceAfter**.

use std::collections::{HashMap, HashSet};

use bp_common::{AddressId, Sats};

use crate::weight::{
    output_weight_for_address, BUDGET_SAFETY_MARGIN_WU, COINBASE_BASE_WEIGHT,
    COINBASE_OUTPUT_WEIGHT, COINBASE_WITNESS_COMMITMENT_WEIGHT, DEFAULT_COINBASE_WEIGHT_BUDGET,
    DUST_LIMIT_SATS,
};

/// Inputs to one block-found coinbase distribution.
pub struct CoinbaseDistributionInput<'a> {
    /// Diff-1-weighted share count per miner in this round.
    pub address_shares: &'a HashMap<AddressId, f64>,
    /// Signed ledger balances at distribution-build time. Positive = pool
    /// owes miner; negative = miner owes pool.
    pub balances: &'a HashMap<AddressId, Sats>,
    /// Full block reward in sats (subsidy + mempool fees).
    pub block_reward_sats: Sats,
    /// Pool fee percent, e.g. `2.0` for 2 %.
    pub fee_percent: f64,
    /// Pool fee payout address. `None` → no fee output emitted.
    pub fee_address: Option<&'a AddressId>,
    /// Max weight units for coinbase outputs. `0` falls back to
    /// `DEFAULT_COINBASE_WEIGHT_BUDGET`.
    pub coinbase_weight_budget: u32,
    /// Group-Solo flag: trim/residuum donations go to fee instead of
    /// creating matching debits on active miners. Keeps Group-Solo on
    /// the simpler unsigned-pending model.
    pub suppress_matching_debits: bool,
    /// Operational minimum on-chain output. `None` falls back to
    /// `DUST_LIMIT_SATS`. Always clamped ≥ `DUST_LIMIT_SATS` at runtime.
    pub min_payout_sats: Option<Sats>,
    /// Group-Solo finder bonus: paid as a dedicated coinbase output on top
    /// of the finder's proportional share. Capped at 95 % of the miner-cut
    /// and suppressed entirely if it would fall below `min_payout_sats`.
    /// Requires both `finder_bonus_sats` AND `finder_address` to be set.
    pub finder_bonus_sats: Option<Sats>,
    pub finder_address: Option<&'a AddressId>,
}

/// One coinbase output: address + on-chain sats + percent of block reward.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CoinbaseDistributionEntry {
    pub address: AddressId,
    pub percent: f64,
    pub sats: Sats,
}

#[derive(Clone, Debug)]
pub struct CoinbaseDistributionResult {
    pub payouts: Vec<CoinbaseDistributionEntry>,
    pub considered_addresses: HashSet<AddressId>,
    /// Resulting balance per miner whose ledger state changed. Apply as
    /// absolute writes inside the block-found DB transaction.
    pub balance_after: HashMap<AddressId, Sats>,
    /// Weight-budget pressure telemetry for the autoscaler. `None` on the
    /// degenerate no-shares / fee-100 fallback paths (those carry no useful
    /// pressure signal — the autoscaler skips them).
    pub budget_telemetry: Option<BudgetTelemetry>,
}

/// Per-distribution weight-budget pressure, consumed by the coinbase-budget
/// autoscaler. Utilization = `desired_weight / effective_budget`: at ≥ 1.0 the
/// trimmer dropped miners (`trimmed_count > 0`); below 1.0 it's the headroom
/// the budget still has before it would start trimming.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetTelemetry {
    /// Total coinbase weight all eligible miners would need with no trim
    /// (fixed overhead + every eligible payout output).
    pub desired_weight: u32,
    /// The trim threshold actually applied this block (`budget` minus the
    /// safety margin). Denominator for the utilization ratio.
    pub effective_budget: u32,
    /// How many eligible miners the budget forced off-chain into carry-forward.
    pub trimmed_count: u32,
}

impl BudgetTelemetry {
    /// Fraction of the trim threshold the (untrimmed) demand consumes.
    /// `< 1.0` = headroom; `>= 1.0` = trimming occurred. The autoscaler's
    /// control input. `effective_budget == 0` (degenerate) reports `0.0`.
    pub fn utilization(&self) -> f64 {
        if self.effective_budget == 0 {
            return 0.0;
        }
        self.desired_weight as f64 / self.effective_budget as f64
    }
}

#[derive(Clone, Debug)]
struct MinerComputation {
    address: AddressId,
    shares: f64,
    /// Kept for algorithm documentation — `target` is what's actually
    /// consulted downstream.
    #[allow(dead_code)]
    raw_fair: i64,
    balance_old: i64,
    target: i64,
    eligible: bool,
    on_chain: i64,
    balance_new: i64,
}

pub fn build_coinbase_distribution(
    input: CoinbaseDistributionInput<'_>,
) -> CoinbaseDistributionResult {
    let block_reward = input.block_reward_sats.to_i64();
    let budget = if input.coinbase_weight_budget > 0 {
        input.coinbase_weight_budget
    } else {
        DEFAULT_COINBASE_WEIGHT_BUDGET
    };
    let min_payout = input
        .min_payout_sats
        .map(|s| s.to_i64())
        .filter(|v| *v > 0)
        .unwrap_or(DUST_LIMIT_SATS as i64)
        .max(DUST_LIMIT_SATS as i64);

    let considered_addresses = collect_considered(input.address_shares, input.balances);

    // ── Early exit: no shares this block ──────────────────────────────
    let total_shares: f64 = input.address_shares.values().sum();
    if input.address_shares.is_empty() || total_shares <= 0.0 {
        return fee_100_fallback(
            input.fee_address,
            input.block_reward_sats,
            considered_addresses,
        );
    }

    // Fee + finder bonus carve-outs.
    let want_fee = ((input.fee_percent / 100.0) * block_reward as f64).floor() as i64;
    let fee_emitted = input.fee_address.is_some() && want_fee >= min_payout;
    let fee_sats = if fee_emitted { want_fee } else { 0 };
    let mut reward_for_miners = block_reward - fee_sats;

    let configured_bonus = input.finder_bonus_sats.map(|s| s.to_i64()).unwrap_or(0);
    let want_bonus = if configured_bonus > 0 && input.finder_address.is_some() {
        configured_bonus
    } else {
        0
    };
    let bonus_cap = ((reward_for_miners as f64) * 0.95).floor() as i64;
    let capped_bonus = want_bonus.min(bonus_cap);
    let bonus_emitted = capped_bonus >= min_payout;
    let bonus_sats = if bonus_emitted { capped_bonus } else { 0 };
    reward_for_miners -= bonus_sats;

    // ── Phase 1 + 2: rawFair + target per miner ───────────────────────
    let mut computations: HashMap<AddressId, MinerComputation> = HashMap::new();
    for (addr, shares) in input.address_shares {
        let ratio = shares / total_shares;
        let raw_fair = (ratio * reward_for_miners as f64).floor() as i64;
        let balance_old = input.balances.get(addr).map(|s| s.to_i64()).unwrap_or(0);
        let target = raw_fair + balance_old;
        computations.insert(
            addr.clone(),
            MinerComputation {
                address: addr.clone(),
                shares: *shares,
                raw_fair,
                balance_old,
                target,
                eligible: target >= min_payout,
                on_chain: 0,
                balance_new: target,
            },
        );
    }

    // Pending-only miners (non-zero balance, no current shares).
    for (addr, balance) in input.balances {
        if input.address_shares.contains_key(addr) {
            continue;
        }
        let balance_old = balance.to_i64();
        if balance_old == 0 {
            continue;
        }
        let target = balance_old;
        computations.insert(
            addr.clone(),
            MinerComputation {
                address: addr.clone(),
                shares: 0.0,
                raw_fair: 0,
                balance_old,
                target,
                eligible: target >= min_payout,
                on_chain: 0,
                balance_new: target,
            },
        );
    }

    // ── Phase 3 + 4: eligibility + adaptive weight-budget trim ───────
    let effective_budget = budget.saturating_sub(BUDGET_SAFETY_MARGIN_WU);
    let fee_output_weight = if fee_emitted {
        input
            .fee_address
            .map(|a| output_weight_for_address(a.as_str()))
            .unwrap_or(COINBASE_OUTPUT_WEIGHT)
    } else {
        0
    };
    let bonus_output_weight = if bonus_emitted {
        input
            .finder_address
            .map(|a| output_weight_for_address(a.as_str()))
            .unwrap_or(COINBASE_OUTPUT_WEIGHT)
    } else {
        0
    };
    let fixed_weight = COINBASE_BASE_WEIGHT
        + COINBASE_WITNESS_COMMITMENT_WEIGHT
        + fee_output_weight
        + bonus_output_weight;

    let mut eligible_list: Vec<MinerComputation> = computations
        .values()
        .filter(|c| c.eligible)
        .cloned()
        .collect();
    // Largest target first. NaN-safe via partial_cmp + unwrap_or(Equal).
    eligible_list.sort_by(|a, b| {
        b.target
            .cmp(&a.target)
            .then_with(|| a.address.as_str().cmp(b.address.as_str()))
    });

    let mut kept: Vec<AddressId> = Vec::new();
    let mut trimmed: Vec<AddressId> = Vec::new();
    let mut used_weight = fixed_weight;
    // Pre-trim demand: what keeping *every* eligible miner would weigh.
    // Drives the autoscaler's utilization ratio; not used for the trim
    // decision itself.
    let mut desired_weight = fixed_weight;
    for miner in &eligible_list {
        let out_weight = output_weight_for_address(miner.address.as_str());
        desired_weight = desired_weight.saturating_add(out_weight);
        if used_weight + out_weight <= effective_budget {
            kept.push(miner.address.clone());
            used_weight += out_weight;
        } else {
            trimmed.push(miner.address.clone());
        }
    }
    let budget_telemetry = Some(BudgetTelemetry {
        desired_weight,
        effective_budget,
        trimmed_count: trimmed.len() as u32,
    });

    // Kept miners: full target on-chain, balance clears to 0.
    for addr in &kept {
        if let Some(c) = computations.get_mut(addr) {
            c.on_chain = c.target;
            c.balance_new = 0;
        }
    }
    // Trimmed miners: balance stays at target (already set above).

    // ── Phase 5a: redistribute trimmed amount to kept active miners ──
    // Only the "this-block" portion of trimmed targets gets redistributed
    // (pending-only trimmed miners have past-block claims, not redistributable).
    let trimmed_total: i64 = trimmed
        .iter()
        .filter_map(|a| computations.get(a))
        .filter(|c| c.shares > 0.0)
        .map(|c| c.target)
        .sum();

    let mut fee_bonus_sats: i64 = 0;
    if trimmed_total > 0 {
        if input.suppress_matching_debits {
            fee_bonus_sats += trimmed_total;
        } else {
            let kept_active_shares: f64 = kept
                .iter()
                .filter_map(|a| computations.get(a))
                .filter(|c| c.shares > 0.0)
                .map(|c| c.shares)
                .sum();

            if kept_active_shares > 0.0 {
                let mut bonus_assigned: i64 = 0;
                // Compute and apply per-miner bonuses.
                let kept_active_addrs: Vec<AddressId> = kept
                    .iter()
                    .filter(|a| {
                        computations
                            .get(*a)
                            .map(|c| c.shares > 0.0)
                            .unwrap_or(false)
                    })
                    .cloned()
                    .collect();

                for addr in &kept_active_addrs {
                    if let Some(c) = computations.get_mut(addr) {
                        let bonus =
                            ((trimmed_total as f64) * c.shares / kept_active_shares).floor() as i64;
                        c.on_chain += bonus;
                        c.balance_new -= bonus;
                        bonus_assigned += bonus;
                    }
                }
                // Floor-rounding residual → largest-shares active miner.
                let bonus_residuum = trimmed_total - bonus_assigned;
                if bonus_residuum > 0 && !kept_active_addrs.is_empty() {
                    let biggest = kept_active_addrs
                        .iter()
                        .max_by(|a, b| {
                            let sa = computations.get(*a).map(|c| c.shares).unwrap_or(0.0);
                            let sb = computations.get(*b).map(|c| c.shares).unwrap_or(0.0);
                            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .cloned();
                    if let Some(biggest) = biggest {
                        if let Some(c) = computations.get_mut(&biggest) {
                            c.on_chain += bonus_residuum;
                            c.balance_new -= bonus_residuum;
                        }
                    }
                }
            }
            // If no kept active miners and trimmed > 0, the trim sats stay
            // in the trimmed miners' balances (target) — coinbase will
            // undershoot reward_for_miners.
        }
    }

    // ── Phase 5a.5: Solvency cap ─────────────────────────────────────
    let preliminary_on_chain: i64 = computations.values().map(|c| c.on_chain).sum();
    let overshoot = preliminary_on_chain - reward_for_miners;
    if overshoot > 0 {
        let mut credit_claimers: Vec<AddressId> = kept
            .iter()
            .filter(|a| {
                computations
                    .get(*a)
                    .map(|c| c.balance_old > 0)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        // Ascending by balance_old so the last (largest)
        // claimer absorbs the floor-rounding residual so no on_chain goes
        // negative.
        credit_claimers.sort_by(|a, b| {
            let ba = computations.get(a).map(|c| c.balance_old).unwrap_or(0);
            let bb = computations.get(b).map(|c| c.balance_old).unwrap_or(0);
            ba.cmp(&bb).then_with(|| a.as_str().cmp(b.as_str()))
        });

        let total_credit: i64 = credit_claimers
            .iter()
            .filter_map(|a| computations.get(a))
            .map(|c| c.balance_old)
            .sum();

        if total_credit >= overshoot && !credit_claimers.is_empty() {
            // Pass 1: proportional cut (floored), each clamped to the
            // claimer's own credit so on_chain never goes negative. Track
            // the per-claimer cut so pass 2 can top up any shortfall.
            let n = credit_claimers.len();
            let mut cuts: Vec<i64> = Vec::with_capacity(n);
            let mut applied: i64 = 0;
            for (i, addr) in credit_claimers.iter().enumerate() {
                let balance_old = computations.get(addr).map(|c| c.balance_old).unwrap_or(0);
                let mut cut = if i == n - 1 {
                    overshoot - applied
                } else {
                    ((overshoot as f64) * balance_old as f64 / total_credit as f64).floor() as i64
                };
                if cut < 0 {
                    cut = 0;
                }
                if cut > balance_old {
                    cut = balance_old;
                }
                applied += cut;
                cuts.push(cut);
            }
            // Pass 2: distribute any residual shortfall left by pass-1
            // floor-rounding. When `overshoot ≈ total_credit` (near-zero
            // slack — the normal shape when active miners with no prior
            // balance consume the whole reward and the pending credits
            // sum to almost exactly the overshoot), the per-claimer
            // floors lose up to `n - 1` sats in aggregate, more than the
            // last claimer can absorb on its own. Spread the leftover
            // across claimers that still have headroom. Total remaining
            // headroom = `total_credit - applied ≥ overshoot - applied`,
            // so this always closes the gap. The old code bailed to a
            // fee-100% fallback here — catastrophic: it handed the entire
            // block to the pool fee over a few sats of rounding.
            let mut remaining = overshoot - applied;
            for (i, addr) in credit_claimers.iter().enumerate() {
                if remaining <= 0 {
                    break;
                }
                let balance_old = computations.get(addr).map(|c| c.balance_old).unwrap_or(0);
                let headroom = balance_old - cuts[i];
                if headroom <= 0 {
                    continue;
                }
                let extra = headroom.min(remaining);
                cuts[i] += extra;
                applied += extra;
                remaining -= extra;
            }
            // Apply the final cuts: reduce on-chain, carry the unpaid
            // credit forward in the ledger.
            for (i, addr) in credit_claimers.iter().enumerate() {
                let cut = cuts[i];
                if cut == 0 {
                    continue;
                }
                if let Some(c) = computations.get_mut(addr) {
                    c.on_chain -= cut;
                    c.balance_new += cut;
                }
            }
            debug_assert_eq!(
                applied, overshoot,
                "solvency cap must fully absorb the overshoot when total_credit >= overshoot"
            );
        } else {
            // Mathematically impossible: overshoot > 0 ⇒ total_credit ≥ overshoot.
            return fee_100_fallback(
                input.fee_address,
                input.block_reward_sats,
                considered_addresses,
            );
        }
    }

    // ── Phase 5b: residuum distribution proportional to shares ───────
    let on_chain_total: i64 = computations.values().map(|c| c.on_chain).sum();
    let pending_fee_bonus_under_total = if input.suppress_matching_debits {
        fee_bonus_sats
    } else {
        0
    };
    let residuum = reward_for_miners - on_chain_total - pending_fee_bonus_under_total;
    if residuum > 0 {
        if input.suppress_matching_debits {
            fee_bonus_sats += residuum;
        } else {
            let kept_active_addrs: Vec<AddressId> = kept
                .iter()
                .filter(|a| {
                    computations
                        .get(*a)
                        .map(|c| c.shares > 0.0)
                        .unwrap_or(false)
                })
                .cloned()
                .collect();
            let kept_active_shares: f64 = kept_active_addrs
                .iter()
                .filter_map(|a| computations.get(a))
                .map(|c| c.shares)
                .sum();
            if kept_active_shares > 0.0 {
                let mut assigned: i64 = 0;
                for addr in &kept_active_addrs {
                    if let Some(c) = computations.get_mut(addr) {
                        let bonus =
                            ((residuum as f64) * c.shares / kept_active_shares).floor() as i64;
                        c.on_chain += bonus;
                        c.balance_new -= bonus;
                        assigned += bonus;
                    }
                }
                let residual = residuum - assigned;
                if residual > 0 {
                    let biggest = kept_active_addrs
                        .iter()
                        .max_by(|a, b| {
                            let sa = computations.get(*a).map(|c| c.shares).unwrap_or(0.0);
                            let sb = computations.get(*b).map(|c| c.shares).unwrap_or(0.0);
                            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .cloned();
                    if let Some(biggest) = biggest {
                        if let Some(c) = computations.get_mut(&biggest) {
                            c.on_chain += residual;
                            c.balance_new -= residual;
                        }
                    }
                }
            } else {
                // No kept active miner to absorb the residuum — route it to
                // the fee output (emitted in Phase 6) so the coinbase doesn't
                // undershoot the block reward. Mirrors the Group-Solo
                // donate-residuum-to-fee path. (If no fee output is emitted
                // either, Phase 5c handles it; only a no-fee + no-active-miner
                // config can still leave it unclaimed.)
                fee_bonus_sats += residuum;
            }
        }
    } else if residuum < 0 {
        // After the Phase 5a.5 solvency cap this can't happen; defense in depth.
        return fee_100_fallback(
            input.fee_address,
            input.block_reward_sats,
            considered_addresses,
        );
    }

    // ── Phase 5c: residuum fallback when no fee output emitted ───────
    //
    // In `suppress_matching_debits` mode (Group-Solo) the trim_total and
    // rounding residuum accumulate in `fee_bonus_sats`, which Phase 6
    // only emits via the fee output. If `fee_emitted == false` (no fee
    // address configured, or `want_fee` below `min_payout`) those sats
    // would be silently dropped and the coinbase would undershoot the
    // block reward by that many sats — money out the void.
    //
    // Roll the accumulated `fee_bonus_sats` into the largest-share kept
    // miner's on-chain payout (same residual-distribution pattern that
    // the non-suppress path uses for rounding leftovers).
    if fee_bonus_sats > 0 && !fee_emitted {
        let biggest_active = kept
            .iter()
            .filter(|a| {
                computations
                    .get(*a)
                    .map(|c| c.shares > 0.0)
                    .unwrap_or(false)
            })
            .max_by(|a, b| {
                let sa = computations.get(*a).map(|c| c.shares).unwrap_or(0.0);
                let sb = computations.get(*b).map(|c| c.shares).unwrap_or(0.0);
                sa.partial_cmp(&sb)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.as_str().cmp(a.as_str()))
            })
            .cloned();
        if let Some(addr) = biggest_active {
            if let Some(c) = computations.get_mut(&addr) {
                c.on_chain += fee_bonus_sats;
                fee_bonus_sats = 0;
            }
        }
        // If there's no kept-active miner (all trimmed) the residuum
        // stays unclaimed — degenerate config; the chain still accepts
        // the block, the operator loses the round's residual sats.
    }

    // ── Phase 6: build payouts + balanceAfter ────────────────────────
    let mut payouts: Vec<CoinbaseDistributionEntry> = Vec::new();

    let total_fee_sats = if fee_emitted {
        // fee_bonus_sats carries Group-Solo trim/residuum donations and (for
        // PPLNS) a residuum that had no kept-active miner to absorb it; both
        // are emitted via the fee output. It is 0 on the normal PPLNS path.
        fee_sats + fee_bonus_sats
    } else {
        fee_sats
    };
    if fee_emitted {
        if let Some(fee_addr) = input.fee_address {
            payouts.push(CoinbaseDistributionEntry {
                address: fee_addr.clone(),
                percent: (total_fee_sats as f64 / block_reward as f64) * 100.0,
                sats: Sats(total_fee_sats),
            });
        }
    }

    if bonus_emitted {
        if let Some(finder_addr) = input.finder_address {
            payouts.push(CoinbaseDistributionEntry {
                address: finder_addr.clone(),
                percent: (bonus_sats as f64 / block_reward as f64) * 100.0,
                sats: Sats(bonus_sats),
            });
        }
    }

    // Sort kept miners by on-chain descending (and address for ties → determinism).
    let mut sorted_kept: Vec<MinerComputation> = kept
        .iter()
        .filter_map(|a| computations.get(a).cloned())
        .collect();
    sorted_kept.sort_by(|a, b| {
        b.on_chain
            .cmp(&a.on_chain)
            .then_with(|| a.address.as_str().cmp(b.address.as_str()))
    });
    for c in sorted_kept {
        if c.on_chain <= 0 {
            continue;
        }
        payouts.push(CoinbaseDistributionEntry {
            address: c.address,
            percent: (c.on_chain as f64 / block_reward as f64) * 100.0,
            sats: Sats(c.on_chain),
        });
    }

    let mut balance_after: HashMap<AddressId, Sats> = HashMap::new();
    for c in computations.values() {
        if c.balance_old != 0 || c.balance_new != 0 {
            balance_after.insert(c.address.clone(), Sats(c.balance_new));
        }
    }

    if payouts.is_empty() {
        return fee_100_fallback(
            input.fee_address,
            input.block_reward_sats,
            considered_addresses,
        );
    }

    CoinbaseDistributionResult {
        payouts,
        considered_addresses,
        balance_after,
        budget_telemetry,
    }
}

fn collect_considered(
    shares: &HashMap<AddressId, f64>,
    balances: &HashMap<AddressId, Sats>,
) -> HashSet<AddressId> {
    let mut s: HashSet<AddressId> = HashSet::with_capacity(shares.len() + balances.len());
    s.extend(shares.keys().cloned());
    s.extend(balances.keys().cloned());
    s
}

fn fee_100_fallback(
    fee_address: Option<&AddressId>,
    block_reward: Sats,
    considered_addresses: HashSet<AddressId>,
) -> CoinbaseDistributionResult {
    let payouts = match fee_address {
        Some(addr) => vec![CoinbaseDistributionEntry {
            address: addr.clone(),
            percent: 100.0,
            sats: block_reward,
        }],
        None => Vec::new(),
    };
    CoinbaseDistributionResult {
        payouts,
        considered_addresses,
        balance_after: HashMap::new(),
        // No-shares / fee-100 path carries no weight-budget pressure signal.
        budget_telemetry: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- test helpers -----

    fn addr(s: &str) -> AddressId {
        AddressId::new(s).expect("test address must be shape-valid")
    }

    fn miner(s: &str) -> AddressId {
        addr(s)
    }

    fn make_input<'a>(
        shares: &'a HashMap<AddressId, f64>,
        balances: &'a HashMap<AddressId, Sats>,
        fee_addr: Option<&'a AddressId>,
        block_reward: i64,
    ) -> CoinbaseDistributionInput<'a> {
        CoinbaseDistributionInput {
            address_shares: shares,
            balances,
            block_reward_sats: Sats(block_reward),
            fee_percent: 2.0,
            fee_address: fee_addr,
            coinbase_weight_budget: DEFAULT_COINBASE_WEIGHT_BUDGET,
            suppress_matching_debits: false,
            min_payout_sats: Some(Sats(DUST_LIMIT_SATS as i64)),
            finder_bonus_sats: None,
            finder_address: None,
        }
    }

    fn miners_p2wpkh() -> [AddressId; 4] {
        [
            miner("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            miner("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
            miner("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"),
            miner("bc1q8m4u0aqf7p4lq97e6tsxqnxc6vkdrap5pjc8r8"),
        ]
    }

    fn fee_addr() -> AddressId {
        miner("bc1qfeevuwf65wq86q0nrjs0xpe89gej7z6e2vsj0u")
    }

    // ----- empty / fee-100% cases -----

    #[test]
    fn no_miners_no_fee_returns_empty() {
        let shares = HashMap::new();
        let balances = HashMap::new();
        let input = make_input(&shares, &balances, None, 5_000_000_000);
        let r = build_coinbase_distribution(input);
        assert!(r.payouts.is_empty());
        assert!(r.balance_after.is_empty());
    }

    #[test]
    fn no_miners_with_fee_address_returns_fee_100() {
        let shares = HashMap::new();
        let balances = HashMap::new();
        let fa = fee_addr();
        let input = make_input(&shares, &balances, Some(&fa), 5_000_000_000);
        let r = build_coinbase_distribution(input);
        assert_eq!(r.payouts.len(), 1);
        assert_eq!(r.payouts[0].address, fa);
        assert_eq!(r.payouts[0].sats, Sats(5_000_000_000));
        assert!((r.payouts[0].percent - 100.0).abs() < 1e-9);
    }

    /// Regression for the live test-server fee-100 bug. Two freshly
    /// mining addresses (no prior balance) consume the entire miner
    /// reward, so the overshoot to claw back ≈ the sum of the pending
    /// credits — with near-zero slack. The per-claimer floor-rounding
    /// across many claimers used to leave a residual the last claimer
    /// couldn't absorb, which tripped the catastrophic fee-100%
    /// fallback (whole block routed to the pool fee, every miner
    /// dropped). It must now spread the residual and pay the miners.
    #[test]
    fn solvency_cap_rounding_shortfall_pays_miners_not_fee_100() {
        let m1 = miner("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let m2 = miner("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
        let mut shares: HashMap<AddressId, f64> = HashMap::new();
        shares.insert(m1.clone(), 461_480.0);
        shares.insert(m2.clone(), 347_188.0);

        // 60 pending-only credit holders with distinct, non-round
        // balances ≥ min_payout (no current shares). Distinct values
        // force per-claimer floor loss; 60 of them lose far more in
        // aggregate than the ~1-sat slack between overshoot and
        // total_credit.
        let mut balances: HashMap<AddressId, Sats> = HashMap::new();
        for i in 0..60u32 {
            balances.insert(
                addr(&format!("pendingcredit{i:04}")),
                Sats(5_000 + i as i64 * 131),
            );
        }

        let fa = fee_addr();
        let block_reward = 313_577_703_i64;
        let input = CoinbaseDistributionInput {
            address_shares: &shares,
            balances: &balances,
            block_reward_sats: Sats(block_reward),
            fee_percent: 1.0,
            fee_address: Some(&fa),
            coinbase_weight_budget: DEFAULT_COINBASE_WEIGHT_BUDGET,
            suppress_matching_debits: false,
            min_payout_sats: Some(Sats(5_000)),
            finder_bonus_sats: None,
            finder_address: None,
        };
        let r = build_coinbase_distribution(input);

        // Not the fee-100 fallback: both active miners are paid.
        assert!(
            r.payouts.iter().any(|p| p.address == m1 && p.sats.0 > 0),
            "miner 1 must be paid, got payouts: {:?}",
            r.payouts
        );
        assert!(
            r.payouts.iter().any(|p| p.address == m2 && p.sats.0 > 0),
            "miner 2 must be paid"
        );
        assert!(
            r.payouts.iter().any(|p| p.address == fa),
            "fee output must be present"
        );
        // The two active miners should split ~the whole reward (they did
        // all the work this block); the pool fee is ~1%, not ~100%.
        let fee_sats = r.payouts.iter().find(|p| p.address == fa).unwrap().sats.0;
        assert!(
            fee_sats < block_reward / 50,
            "fee must be ~1%, not the whole block — got {fee_sats}"
        );
        // Coinbase fully spends the reward (no overspend → no
        // bad-cb-amount; no underspend → no sats to the void).
        let total: i64 = r.payouts.iter().map(|p| p.sats.0).sum();
        assert_eq!(
            total, block_reward,
            "coinbase must spend exactly the reward"
        );
    }

    // ----- budget telemetry (autoscaler signal) -----

    #[test]
    fn telemetry_none_on_no_shares_fallback() {
        // No-shares / fee-100 path carries no pressure signal.
        let shares = HashMap::new();
        let balances = HashMap::new();
        let fa = fee_addr();
        let input = make_input(&shares, &balances, Some(&fa), 5_000_000_000);
        let r = build_coinbase_distribution(input);
        assert!(r.budget_telemetry.is_none());
    }

    #[test]
    fn telemetry_reports_headroom_under_generous_budget() {
        // Four miners, default (large) budget → nobody trimmed, desired
        // demand sits below the trim threshold.
        let m = miners_p2wpkh();
        let mut shares = HashMap::new();
        for (i, a) in m.iter().enumerate() {
            shares.insert(a.clone(), (i + 1) as f64 * 10.0);
        }
        let balances = HashMap::new();
        let fa = fee_addr();
        let input = make_input(&shares, &balances, Some(&fa), 5_000_000_000);
        let r = build_coinbase_distribution(input);
        let t = r.budget_telemetry.expect("trim path must emit telemetry");
        assert_eq!(t.trimmed_count, 0, "generous budget must not trim");
        assert!(t.desired_weight > 0);
        assert!(
            t.desired_weight <= t.effective_budget,
            "no-trim run must sit at/under the threshold: {} <= {}",
            t.desired_weight,
            t.effective_budget
        );
    }

    #[test]
    fn telemetry_reports_overflow_under_tight_budget() {
        // Same miners, tight budget that can't fit them all → trimmer drops
        // some and desired demand exceeds the threshold (utilization > 1.0).
        let m = miners_p2wpkh();
        let mut shares = HashMap::new();
        for (i, a) in m.iter().enumerate() {
            shares.insert(a.clone(), (i + 1) as f64 * 10.0);
        }
        let balances = HashMap::new();
        let fa = fee_addr();
        let mut input = make_input(&shares, &balances, Some(&fa), 5_000_000_000);
        // Just above base+safety margin so only a couple of outputs fit.
        input.coinbase_weight_budget = BUDGET_SAFETY_MARGIN_WU + COINBASE_BASE_WEIGHT + 1;
        let r = build_coinbase_distribution(input);
        let t = r.budget_telemetry.expect("trim path must emit telemetry");
        assert!(t.trimmed_count > 0, "tight budget must trim someone");
        assert!(
            t.desired_weight > t.effective_budget,
            "overflow run must exceed the threshold: {} > {}",
            t.desired_weight,
            t.effective_budget
        );
    }

    // ----- single miner -----

    #[test]
    fn single_miner_full_block_minus_fee() {
        let m = miners_p2wpkh();
        let fa = fee_addr();
        let mut shares = HashMap::new();
        shares.insert(m[0].clone(), 100.0);
        let balances = HashMap::new();
        let input = make_input(&shares, &balances, Some(&fa), 5_000_000_000);
        let r = build_coinbase_distribution(input);

        // Fee output + 1 miner output.
        assert_eq!(r.payouts.len(), 2);
        assert_eq!(r.payouts[0].address, fa);
        assert_eq!(r.payouts[0].sats, Sats(100_000_000)); // 2% of 5 BTC subsidy
        assert_eq!(r.payouts[1].address, m[0]);
        assert_eq!(r.payouts[1].sats, Sats(4_900_000_000));
        // Sum equals block reward.
        let total: i64 = r.payouts.iter().map(|p| p.sats.to_i64()).sum();
        assert_eq!(total, 5_000_000_000);
    }

    // ----- floor remainder routing -----

    #[test]
    fn three_way_split_residuum_goes_to_largest_active_miner() {
        // 4_900_000_000 / 3 = 1_633_333_333 floor, residuum = 1.
        // Active miner with largest shares takes the residual.
        let m = miners_p2wpkh();
        let fa = fee_addr();
        let mut shares = HashMap::new();
        shares.insert(m[0].clone(), 3.0); // largest
        shares.insert(m[1].clone(), 1.0);
        shares.insert(m[2].clone(), 1.0);
        let balances = HashMap::new();
        let input = make_input(&shares, &balances, Some(&fa), 5_000_000_000);
        let r = build_coinbase_distribution(input);

        let total: i64 = r.payouts.iter().map(|p| p.sats.to_i64()).sum();
        assert_eq!(total, 5_000_000_000);
        // Ledger pool-neutral: total balance change = 0 (matching debits absorb residuum).
        let sum_balance_after: i64 = r.balance_after.values().map(|s| s.to_i64()).sum();
        // Floor remainder went on-chain to one miner with matching debit → sum < 0 by remainder.
        // In a steady-state pool starting at zero balances, after one block the sum should be
        // the negative of the residuum (= absorbed by the largest active miner's new debit).
        assert!(sum_balance_after <= 0);
    }

    // ----- sub-dust accumulates as credit -----

    #[test]
    fn sub_dust_target_stays_as_pending_credit() {
        // Tiny block reward, two miners — one shares-dominant, other gets sub-dust.
        // Set reward so smaller miner's rawFair < DUST_LIMIT_SATS (546).
        let m = miners_p2wpkh();
        let fa = fee_addr();
        let mut shares = HashMap::new();
        shares.insert(m[0].clone(), 1000.0);
        shares.insert(m[1].clone(), 1.0); // sub-dust at low rewards
        let balances = HashMap::new();
        let input = make_input(&shares, &balances, Some(&fa), 50_000);
        // 50_000 reward - 1000 fee = 49_000 for miners. m[1] gets ~48 sats → sub-dust.
        let r = build_coinbase_distribution(input);

        // m[1] must NOT appear in payouts.
        assert!(!r.payouts.iter().any(|p| p.address == m[1]));
        // m[1]'s balance_after must equal their rawFair (positive pending credit).
        let bal_m1 = r.balance_after.get(&m[1]).expect("m[1] balance_after");
        assert!(bal_m1.to_i64() > 0);
    }

    // ----- fee output suppressed when below min_payout -----

    #[test]
    fn fee_under_min_payout_is_suppressed() {
        // Tiny block reward where 2% fee is below DUST_LIMIT_SATS.
        // 5_000 sats × 2% = 100 sats < 546 dust → fee NOT emitted, miners get full reward.
        let m = miners_p2wpkh();
        let fa = fee_addr();
        let mut shares = HashMap::new();
        shares.insert(m[0].clone(), 1.0);
        let balances = HashMap::new();
        let input = make_input(&shares, &balances, Some(&fa), 5_000);
        let r = build_coinbase_distribution(input);

        // No fee output emitted.
        assert!(!r.payouts.iter().any(|p| p.address == fa));
        // Miner gets the full 5_000 (no fee carved off).
        assert_eq!(r.payouts[0].sats, Sats(5_000));
    }

    // ----- pending-only miner with prior credit gets paid this block -----

    #[test]
    fn pending_only_miner_gets_credit_payout() {
        // Miner had a 10_000 pending credit, no shares this round. Their
        // target = balance_old = 10_000 ≥ dust → on-chain output.
        let m = miners_p2wpkh();
        let fa = fee_addr();
        let mut shares = HashMap::new();
        shares.insert(m[0].clone(), 100.0); // active miner provides the credit "headroom"

        // Build an asymmetric balance state with matching debit so the
        // ledger starts at sum=0.
        let mut balances = HashMap::new();
        balances.insert(m[1].clone(), Sats(10_000)); // pending credit
        balances.insert(m[0].clone(), Sats(-10_000)); // matching debit on active miner

        let input = make_input(&shares, &balances, Some(&fa), 5_000_000_000);
        let r = build_coinbase_distribution(input);

        // Pending miner m[1] receives on-chain output equal to their credit.
        let m1_out = r
            .payouts
            .iter()
            .find(|p| p.address == m[1])
            .expect("pending-only miner should be paid");
        assert_eq!(m1_out.sats, Sats(10_000));
        // Their balance after = 0.
        assert_eq!(r.balance_after.get(&m[1]), Some(&Sats(0)));
    }

    // ----- solvency cap: abandoned-debtor overshoot triggers credit haircut -----

    #[test]
    fn solvency_cap_haircuts_credit_when_debtor_abandoned() {
        // m[1] has a 1_000_000 pending credit but the matching debit was
        // on m[2] who is now ABSENT (no entry in balances). When m[0]
        // works and m[1]'s credit gets paid, the on-chain total
        // overshoots reward_for_miners and the cap must kick in.
        let m = miners_p2wpkh();
        let fa = fee_addr();
        let mut shares = HashMap::new();
        shares.insert(m[0].clone(), 100.0); // active worker
        let mut balances = HashMap::new();
        balances.insert(m[1].clone(), Sats(5_000_000_000)); // huge stale credit (no matching debit)

        // Block reward 5 BTC subsidy. m[1]'s credit alone would exceed it.
        let input = make_input(&shares, &balances, Some(&fa), 5_000_000_000);
        let r = build_coinbase_distribution(input);

        let total_on_chain: i64 = r.payouts.iter().map(|p| p.sats.to_i64()).sum();
        // Total emitted must never exceed block_reward.
        assert!(
            total_on_chain <= 5_000_000_000,
            "overshoot: {total_on_chain}"
        );
        // m[1] balance_after must carry the uncovered remainder forward (positive).
        let m1_after = r.balance_after.get(&m[1]).expect("m[1] balance_after");
        assert!(m1_after.to_i64() > 0);
    }

    // ----- suppress_matching_debits (Group-Solo mode) -----

    #[test]
    fn suppress_matching_debits_donates_residuum_to_fee() {
        let m = miners_p2wpkh();
        let fa = fee_addr();
        let mut shares = HashMap::new();
        shares.insert(m[0].clone(), 3.0);
        shares.insert(m[1].clone(), 1.0);
        shares.insert(m[2].clone(), 1.0);
        let balances = HashMap::new();
        let input = CoinbaseDistributionInput {
            suppress_matching_debits: true,
            ..make_input(&shares, &balances, Some(&fa), 5_000_000_000)
        };
        let r = build_coinbase_distribution(input);

        // No miner balance changes in Group-Solo mode (all rounds reset elsewhere).
        let any_member_balance = r
            .balance_after
            .iter()
            .filter(|(a, _)| **a != fa)
            .any(|(_, s)| s.to_i64() != 0);
        assert!(
            !any_member_balance,
            "members must have zero balance change in Group-Solo"
        );
        // Coinbase total still equals block reward (no sats lost).
        let total: i64 = r.payouts.iter().map(|p| p.sats.to_i64()).sum();
        assert_eq!(total, 5_000_000_000);
    }

    #[test]
    fn suppress_matching_debits_without_fee_rolls_residuum_into_biggest_miner() {
        // Group-Solo with `fee_address = None`. Without the Phase 5c
        // fallback the trim+residuum sats accumulated in
        // `fee_bonus_sats` would be silently dropped (Phase 6 only
        // emits them via the fee output). The fix rolls the bucket
        // into the largest-share kept miner so the coinbase still
        // sums to the full block reward.
        let m = miners_p2wpkh();
        let mut shares = HashMap::new();
        // Asymmetric weights so the "largest share" is unambiguous.
        shares.insert(m[0].clone(), 100.0);
        shares.insert(m[1].clone(), 200.0);
        shares.insert(m[2].clone(), 300.0);
        let balances = HashMap::new();
        let input = CoinbaseDistributionInput {
            suppress_matching_debits: true,
            ..make_input(&shares, &balances, None, 5_000_000_000)
        };
        let r = build_coinbase_distribution(input);

        // Bit-exact: no sats burned, no fee output (no fee address).
        let total: i64 = r.payouts.iter().map(|p| p.sats.to_i64()).sum();
        assert_eq!(
            total, 5_000_000_000,
            "all sats must be claimed when there's no fee output to absorb residuum"
        );
        // No fee output emitted (fee_address was None). Exactly 3
        // outputs — one per kept miner — and the sum equals the
        // reward bit-exact.
        assert_eq!(r.payouts.len(), 3);
        // The 600-share total split by 1/2/3 leaves a few rounding
        // sats — they should land on the largest-share miner (m[2]).
        // Pure share split for m[2]: floor(5_000_000_000 * 300/600) = 2_500_000_000.
        // Anything above that proves the fallback rolled residuum in.
        let m2_sats = r
            .payouts
            .iter()
            .find(|p| p.address == m[2])
            .expect("largest-share miner must be in payouts")
            .sats
            .to_i64();
        assert!(
            m2_sats > 2_500_000_000,
            "largest-share miner must receive the residuum (got {m2_sats})"
        );
    }

    /// PPLNS (non-suppress) edge case: a budget so tight that *every*
    /// active miner is trimmed off-chain leaves no kept-active miner to
    /// absorb the Phase 5b residuum. Without the donate-to-fee fix the
    /// residuum (≈ the whole miner reward) would vanish and the coinbase
    /// would undershoot the block reward. The fix routes it to the fee
    /// output, mirroring the Group-Solo path, so the coinbase stays
    /// bit-exact. Trimmed miners' work is preserved as carry-forward
    /// balance (they get paid next round).
    #[test]
    fn pplns_all_active_trimmed_routes_residuum_to_fee() {
        let m = miners_p2wpkh();
        let fa = fee_addr();
        let mut shares = HashMap::new();
        shares.insert(m[0].clone(), 3.0);
        shares.insert(m[1].clone(), 2.0);
        shares.insert(m[2].clone(), 1.0);
        let balances = HashMap::new();
        let block_reward = 5_000_000_000_i64;
        let input = CoinbaseDistributionInput {
            // effective_budget saturates to 0 → no miner output fits →
            // all active miners trimmed, kept is empty.
            coinbase_weight_budget: 1,
            ..make_input(&shares, &balances, Some(&fa), block_reward)
        };
        let r = build_coinbase_distribution(input);

        // Conservation: coinbase outputs still sum to the full reward.
        let total: i64 = r.payouts.iter().map(|p| p.sats.to_i64()).sum();
        assert_eq!(
            total, block_reward,
            "coinbase must not undershoot when all active miners are trimmed"
        );
        // The whole reward lands on the fee output (fee_sats + routed
        // residuum == block_reward); no miner gets an on-chain payout
        // this round.
        assert_eq!(r.payouts.len(), 1, "only the fee output is emitted");
        assert_eq!(r.payouts[0].address, fa);
        assert_eq!(r.payouts[0].sats, Sats(block_reward));
        // Trimmed miners' work is preserved as carry-forward balance.
        let carried: i64 = r
            .balance_after
            .iter()
            .filter(|(a, _)| **a != fa)
            .map(|(_, s)| s.to_i64())
            .sum();
        assert!(
            carried > 0,
            "trimmed miners must carry their share forward, got {carried}"
        );
    }

    // ----- finder bonus -----

    #[test]
    fn finder_bonus_emitted_as_separate_output() {
        let m = miners_p2wpkh();
        let fa = fee_addr();
        let finder = m[0].clone();
        let mut shares = HashMap::new();
        shares.insert(m[0].clone(), 1.0);
        shares.insert(m[1].clone(), 1.0);
        let balances = HashMap::new();
        let input = CoinbaseDistributionInput {
            finder_bonus_sats: Some(Sats(100_000)),
            finder_address: Some(&finder),
            ..make_input(&shares, &balances, Some(&fa), 5_000_000_000)
        };
        let r = build_coinbase_distribution(input);

        // Three outputs: fee, finder bonus, m[1] proportional share.
        // Plus m[0]'s proportional share — so 4 outputs total.
        // (Finder is in addressShares too, so they appear twice: once as bonus, once as share.)
        assert_eq!(r.payouts.len(), 4);
        let total: i64 = r.payouts.iter().map(|p| p.sats.to_i64()).sum();
        assert_eq!(total, 5_000_000_000);
        // The bonus output is exactly 100_000 sats.
        assert!(r
            .payouts
            .iter()
            .any(|p| p.sats == Sats(100_000) && p.address == finder));
    }

    // ----- determinism: same input → same output -----

    #[test]
    fn deterministic_across_runs() {
        let m = miners_p2wpkh();
        let fa = fee_addr();
        let mut shares = HashMap::new();
        shares.insert(m[0].clone(), 3.0);
        shares.insert(m[1].clone(), 2.0);
        shares.insert(m[2].clone(), 5.0);
        let balances = HashMap::new();
        let r1 =
            build_coinbase_distribution(make_input(&shares, &balances, Some(&fa), 5_000_000_000));
        let r2 =
            build_coinbase_distribution(make_input(&shares, &balances, Some(&fa), 5_000_000_000));
        assert_eq!(r1.payouts, r2.payouts);
    }

    // ── PPLNS trim → ledger → next-round semantics ──────────────────────
    //
    // The three tests below cover the trim → ledger → next-round flow
    // incl. a 2-round verification: trimmed miners' pending balance
    // ACTUALLY pays out in the next distribution, and
    // bonus-receivers' matching-debit ACTUALLY reduces their next-round
    // target. This is the "carry-forward + deduction" question that
    // operators need answered: "trimmed miners get paid eventually, and
    // the matching-debit on bonus-receivers does what it says on the tin."

    /// Tight budget forces trim across 50 miners; verifies the two
    /// biggest active
    /// miners get a bonus (`balance_after` < 0) proportional to their
    /// shares.
    #[test]
    fn trim_bonus_distributed_proportional_to_shares_creates_matching_debits() {
        let fa = fee_addr();
        let alice = miner("bc1qalice0pplnstrimtest0000000000000000000aaa");
        let bob = miner("bc1qbob000pplnstrimtest00000000000000000000bbb");
        let mut shares: HashMap<AddressId, f64> = HashMap::new();
        shares.insert(alice.clone(), 1_000_000.0);
        shares.insert(bob.clone(), 500_000.0);
        for i in 2..50 {
            // Tiny tail miners — get trimmed because the budget can't
            // accommodate 50 outputs. Address strings need not be
            // bech32-valid; `output_weight_for_address` falls back to
            // 172 WU (the conservative upper bound) for unparseable
            // entries, which is fine for the trim math.
            shares.insert(miner(&format!("bc1qtinypplns{i:040x}")), 10_000.0);
        }
        let balances: HashMap<AddressId, Sats> = HashMap::new();
        let input = CoinbaseDistributionInput {
            coinbase_weight_budget: 1500, // tight → trim
            ..make_input(&shares, &balances, Some(&fa), 5_000_000_000)
        };
        let r = build_coinbase_distribution(input);

        // Both Alice + Bob kept (sorted by target = shares-weighted).
        assert!(r.payouts.iter().any(|p| p.address == alice));
        assert!(r.payouts.iter().any(|p| p.address == bob));

        // Both got bonus → balance_after is negative (matching debit).
        let alice_after = r.balance_after.get(&alice).copied().unwrap_or(Sats(0));
        let bob_after = r.balance_after.get(&bob).copied().unwrap_or(Sats(0));
        assert!(
            alice_after.to_i64() < 0,
            "Alice should have matching-debit (negative balance_after), got {alice_after:?}"
        );
        assert!(
            bob_after.to_i64() < 0,
            "Bob should have matching-debit, got {bob_after:?}"
        );
        // Alice's share-ratio ≈ 0.505, Bob's ≈ 0.253 → |Alice debit| > |Bob debit|.
        assert!(
            alice_after.to_i64().abs() > bob_after.to_i64().abs(),
            "Alice's debit must exceed Bob's (proportional to shares); got Alice={} Bob={}",
            alice_after.to_i64(),
            bob_after.to_i64(),
        );
    }

    /// Trimmed miners' target stays as positive `balance_after` (carry-forward
    /// credit for the next round).
    #[test]
    fn trimmed_miner_target_becomes_balance_after_carry_forward_credit() {
        let fa = fee_addr();
        let mut shares: HashMap<AddressId, f64> = HashMap::new();
        let addrs: Vec<AddressId> = (0..10)
            .map(|i| miner(&format!("bc1qpplnscf{i:040x}")))
            .collect();
        // Decreasing share counts (largest first will be kept under tight budget).
        for (i, a) in addrs.iter().enumerate() {
            shares.insert(a.clone(), (100_000 - i as i64 * 5_000) as f64);
        }
        let balances: HashMap<AddressId, Sats> = HashMap::new();
        let input = CoinbaseDistributionInput {
            coinbase_weight_budget: 1200, // ~3 outputs fit
            ..make_input(&shares, &balances, Some(&fa), 5_000_000_000)
        };
        let r = build_coinbase_distribution(input);

        let kept_addrs: std::collections::HashSet<AddressId> = r
            .payouts
            .iter()
            .filter(|p| p.address != fa)
            .map(|p| p.address.clone())
            .collect();
        let trimmed_addrs: Vec<AddressId> = addrs
            .iter()
            .filter(|a| !kept_addrs.contains(a))
            .cloned()
            .collect();

        assert!(
            !trimmed_addrs.is_empty(),
            "test setup must produce trimmed miners (kept={})",
            kept_addrs.len()
        );

        // At least one trimmed miner must have positive carry-forward credit.
        let trimmed_with_credit = trimmed_addrs
            .iter()
            .filter(|a| r.balance_after.get(a).copied().unwrap_or(Sats(0)).to_i64() > 0)
            .count();
        assert!(
            trimmed_with_credit > 0,
            "trimmed miners must carry-forward positive credit; \
             kept={} trimmed={} (none had balance_after > 0)",
            kept_addrs.len(),
            trimmed_addrs.len(),
        );
    }

    /// Two-round end-to-end verification of the user-asked question:
    /// "trimmed addresses go into the ledger, AND the next round those
    /// who got more in round 1 get deducted in round 2 (matching-debit)."
    ///
    /// The matching-debit shows up cleanly as a reduced **target** in
    /// round 2. Target isn't directly exposed, but with a LARGE r2
    /// budget (no trim → no r2 bonus re-allocation), `on_chain = target`
    /// for every kept miner. Then:
    /// - Bonus-receivers (balance_old < 0) → target = raw_fair + negative → on_chain < raw_fair.
    /// - Trimmed credit-holders (balance_old > 0) → target = raw_fair + positive → on_chain > raw_fair.
    /// - Ledger sum stays bounded (Σ-neutral across both rounds).
    #[test]
    fn two_round_trimmed_get_credited_bonus_receivers_get_deducted() {
        let fa = fee_addr();
        let alice = miner("bc1qaliceround2pplns000000000000000000000aaa");
        let charlie = miner("bc1qcharlieround2pplns0000000000000000000ccc");
        let mut shares: HashMap<AddressId, f64> = HashMap::new();
        shares.insert(alice.clone(), 1_000_000.0);
        shares.insert(
            miner("bc1qbob00round2pplns000000000000000000000bbb"),
            500_000.0,
        );
        shares.insert(charlie.clone(), 100_000.0);
        for i in 3..20 {
            shares.insert(miner(&format!("bc1qpplns2r{i:040x}")), 50_000.0);
        }
        let block_reward: i64 = 5_000_000_000;
        let huge_budget: u32 = 200_000; // fits all 20 miners — no r2 trim.

        // ── Round 1: tight budget → some kept, some trimmed ─────────────
        let balances_r1: HashMap<AddressId, Sats> = HashMap::new();
        let input_r1 = CoinbaseDistributionInput {
            coinbase_weight_budget: 1300,
            ..make_input(&shares, &balances_r1, Some(&fa), block_reward)
        };
        let r1 = build_coinbase_distribution(input_r1);

        let alice_bal_r1 = r1
            .balance_after
            .get(&alice)
            .copied()
            .unwrap_or(Sats(0))
            .to_i64();
        let charlie_bal_r1 = r1
            .balance_after
            .get(&charlie)
            .copied()
            .unwrap_or(Sats(0))
            .to_i64();
        let sum_after_r1: i64 = r1.balance_after.values().map(|s| s.to_i64()).sum();

        // Sanity: r1 trimmer produced the expected ledger shape.
        assert!(alice_bal_r1 < 0, "r1: Alice debit, got {alice_bal_r1}");
        assert!(
            charlie_bal_r1 > 0,
            "r1: Charlie credit, got {charlie_bal_r1}"
        );

        // ── Round 2: HUGE budget → no trim → no r2 bonus ────────────────
        //
        // With no trim, on_chain = target for every kept miner. target =
        // raw_fair + balance_old, so the matching-debit / carry-credit
        // shows up directly in on-chain payouts.
        let input_r2 = CoinbaseDistributionInput {
            coinbase_weight_budget: huge_budget,
            ..make_input(&shares, &r1.balance_after, Some(&fa), block_reward)
        };
        let r2 = build_coinbase_distribution(input_r2);

        // Baseline r2 with ZERO balances (same shares, same budget):
        // every kept miner gets exactly raw_fair on-chain. The DELTA
        // vs this baseline isolates the carry-forward effect.
        let baseline_balances: HashMap<AddressId, Sats> = HashMap::new();
        let baseline_input = CoinbaseDistributionInput {
            coinbase_weight_budget: huge_budget,
            ..make_input(&shares, &baseline_balances, Some(&fa), block_reward)
        };
        let baseline = build_coinbase_distribution(baseline_input);

        let payout = |r: &CoinbaseDistributionResult, a: &AddressId| -> i64 {
            r.payouts
                .iter()
                .find(|p| p.address == *a)
                .map(|p| p.sats.to_i64())
                .unwrap_or(0)
        };
        let alice_r2 = payout(&r2, &alice);
        let alice_baseline = payout(&baseline, &alice);
        let charlie_r2 = payout(&r2, &charlie);
        let charlie_baseline = payout(&baseline, &charlie);

        // **DEDUCTION INVARIANT**: Alice (matching-debit carried in)
        // gets LESS than baseline (her debt is paid back via reduced target).
        assert!(
            alice_r2 < alice_baseline,
            "r2 DEDUCTION FAILED: Alice {alice_r2} ≥ baseline {alice_baseline}; \
             r1 carried debit {alice_bal_r1}"
        );
        // The deduction must equal the carried debit (Solvency-Cap may
        // shave a few sats via the credit-haircut for large pre-existing
        // credits when on-chain overshoots reward — within 10 % tolerates
        // that 1-2-sat float).
        let deduction = alice_baseline - alice_r2;
        let expected = alice_bal_r1.abs();
        let tolerance = (expected / 10).max(100);
        assert!(
            (deduction - expected).abs() <= tolerance,
            "r2 deduction {deduction} should be ~equal to r1 debit {expected} (±{tolerance})"
        );

        // **CARRY-CREDIT INVARIANT**: Charlie (trimmed in r1, balance > 0
        // carried in) gets MORE than baseline (his pending credit is paid out).
        // Solvency-cap may shave it — verify just that he's net-better off.
        let charlie_total_r2 = charlie_r2
            + r2.balance_after
                .get(&charlie)
                .copied()
                .unwrap_or(Sats(0))
                .to_i64();
        assert!(
            charlie_total_r2 >= charlie_baseline + charlie_bal_r1 - (expected / 10).max(100),
            "r2 CARRY-CREDIT FAILED: Charlie's total (on-chain {charlie_r2} + ledger remainder) \
             should be >= baseline {charlie_baseline} + r1 credit {charlie_bal_r1}"
        );

        // **LEDGER-NEUTRALITY INVARIANT**: ledger sum across both rounds
        // stays bounded — the matching-debit accounting is Σ-conservative.
        let sum_after_r2: i64 = r2.balance_after.values().map(|s| s.to_i64()).sum();
        let drift = sum_after_r1 + sum_after_r2;
        assert!(
            drift.abs() <= 1_000,
            "ledger drift across 2 rounds {drift} > 1000 sats — accounting is not Σ-neutral"
        );
    }

    // ----- property: total on-chain ≤ block reward, always -----

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_total_never_exceeds_block_reward(
            seed_shares in proptest::collection::vec(1u32..1000u32, 1..6),
            reward in 1_000_000_000i64..10_000_000_000i64,
            fee_pct in 0.0f64..5.0f64,
        ) {
            let m = miners_p2wpkh();
            let fa = fee_addr();
            let mut shares = HashMap::new();
            for (i, s) in seed_shares.iter().enumerate() {
                shares.insert(m[i % m.len()].clone(), *s as f64);
            }
            let balances = HashMap::new();
            let input = CoinbaseDistributionInput {
                fee_percent: fee_pct,
                ..make_input(&shares, &balances, Some(&fa), reward)
            };
            let r = build_coinbase_distribution(input);
            let total: i64 = r.payouts.iter().map(|p| p.sats.to_i64()).sum();
            prop_assert!(total <= reward, "emitted {total} > reward {reward}");
        }

        #[test]
        fn prop_ledger_pool_neutral_under_normal_inputs(
            seed_shares in proptest::collection::vec(1u32..1000u32, 1..6),
            reward in 1_000_000_000i64..10_000_000_000i64,
        ) {
            // With zero starting balances and matching-debit accounting,
            // sum of balance_after equals minus the total on-chain bonus
            // (residuum/trim) applied — which is bounded and small.
            let m = miners_p2wpkh();
            let fa = fee_addr();
            let mut shares = HashMap::new();
            for (i, s) in seed_shares.iter().enumerate() {
                shares.insert(m[i % m.len()].clone(), *s as f64);
            }
            let balances = HashMap::new();
            let input = make_input(&shares, &balances, Some(&fa), reward);
            let r = build_coinbase_distribution(input);
            let sum_after: i64 = r.balance_after.values().map(|s| s.to_i64()).sum();
            // From zero start, the only net ledger movement is the residuum-bonus
            // chain, which is bounded by the number of miners × 1 sat per
            // floor-rounding step → far less than 100 sats per block in practice.
            prop_assert!(
                sum_after.abs() <= 1000,
                "ledger drift {sum_after} > 1000 sats for {} miners",
                shares.len()
            );
        }
    }
}
