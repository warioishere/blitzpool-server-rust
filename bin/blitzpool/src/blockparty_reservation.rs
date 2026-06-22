// SPDX-License-Identifier: AGPL-3.0-or-later

//! Blockparty coinbase-reservation sizer.
//!
//! Implements [`bp_blockparty_engine::CoinbaseReservation`] over the Blockparty
//! TDP stream. When a party reaches `Ready` (roster final, about to mine), the
//! engine calls [`TdpCoinbaseReservation::ensure_capacity_for_members`]; we
//! compute the coinbase weight the roster needs and, if it exceeds what's
//! currently reserved, raise bitcoin-core's reservation via
//! [`TdpHandle::set_coinbase_constraints`].
//!
//! **High-water-mark.** The reservation only ever grows (across all active
//! parties sharing the one Blockparty stream) and never drops below the
//! configured floor (`[blockparty].coinbase_weight_budget`). For any party that
//! fits the floor the call is a no-op — so the common case has zero
//! reservation churn and zero template lag. A raise only happens for a party
//! larger than the floor, and reaches templates within ~one TDP cycle; keeping
//! the floor ≥ the realistic max party means that lagging path is never the
//! validity guarantee, only headroom.
//!
//! Blockparty does NOT weight-trim (unlike Group-Solo / PPLNS), so this sizing
//! is how a larger-than-floor party stays valid. Beyond
//! [`BLOCKPARTY_MAX_RESERVATION_WU`] the reservation caps out (pathological
//! party guard); such a party is logged and would risk rejection — far past any
//! realistic size.

use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use bp_blockparty_engine::CoinbaseReservation;
use bp_pplns::{
    BUDGET_SAFETY_MARGIN_WU, COINBASE_BASE_WEIGHT, COINBASE_OUTPUT_WEIGHT,
    COINBASE_WITNESS_COMMITMENT_WEIGHT,
};
use bp_template_distribution::TdpHandle;
use tracing::{info, warn};

use crate::boot::tdp_constraint_for_budget;

/// Hard cap on the Blockparty coinbase reservation (weight units). Defends
/// block space against a pathologically large party — ~289 P2TR members, far
/// beyond any realistic party. A party past this caps out (no further raise).
const BLOCKPARTY_MAX_RESERVATION_WU: u32 = 50_000;

/// Sizes the Blockparty TDP stream's coinbase reservation to the largest party
/// that has reached `Ready` this process lifetime (never below the floor).
pub(crate) struct TdpCoinbaseReservation {
    tdp: TdpHandle,
    floor_budget_wu: u32,
    current_budget_wu: AtomicU32,
}

impl TdpCoinbaseReservation {
    /// `floor_budget_wu` is `[blockparty].coinbase_weight_budget` — the same
    /// budget boot advertised to bitcoin-core for the Blockparty stream, so the
    /// starting `current` matches the live reservation.
    pub(crate) fn new(tdp: TdpHandle, floor_budget_wu: u32) -> Self {
        Self {
            tdp,
            floor_budget_wu,
            current_budget_wu: AtomicU32::new(floor_budget_wu),
        }
    }
}

/// Total coinbase weight budget (WU) needed for `member_count` member outputs
/// plus one pool-fee output, using the worst-case P2TR output weight. Same WU
/// units as `[blockparty].coinbase_weight_budget` and the PPLNS budget, so it
/// feeds [`tdp_constraint_for_budget`] directly.
fn budget_for_members(member_count: usize) -> u32 {
    let outputs = (member_count as u32).saturating_add(1); // members + pool fee
    COINBASE_BASE_WEIGHT
        .saturating_add(COINBASE_WITNESS_COMMITMENT_WEIGHT)
        .saturating_add(outputs.saturating_mul(COINBASE_OUTPUT_WEIGHT))
        .saturating_add(BUDGET_SAFETY_MARGIN_WU)
}

/// Pure high-water decision: the target budget (WU) given the currently-applied
/// budget, the floor, and the party size — or `None` when no raise is needed.
/// Never below the floor, never above [`BLOCKPARTY_MAX_RESERVATION_WU`].
fn next_budget_wu(current: u32, floor: u32, member_count: usize) -> Option<u32> {
    let needed = budget_for_members(member_count)
        .max(floor)
        .min(BLOCKPARTY_MAX_RESERVATION_WU);
    (needed > current).then_some(needed)
}

#[async_trait]
impl CoinbaseReservation for TdpCoinbaseReservation {
    async fn ensure_capacity_for_members(&self, member_count: usize) {
        let current = self.current_budget_wu.load(Ordering::Acquire);
        let Some(target) = next_budget_wu(current, self.floor_budget_wu, member_count) else {
            // Floor already covers this party — no raise, no template lag.
            return;
        };
        let c = tdp_constraint_for_budget(target);
        match self
            .tdp
            .set_coinbase_constraints(c.max_additional_size, c.max_additional_sigops)
            .await
        {
            Ok(()) => {
                // Store unconditionally to `target`: concurrent callers may race,
                // but each only ever raises, so the reservation converges to the
                // largest requested and stays there (high-water).
                self.current_budget_wu.fetch_max(target, Ordering::AcqRel);
                info!(
                    member_count,
                    current_wu = current,
                    target_wu = target,
                    "blockparty: raised coinbase reservation for max-size party"
                );
            }
            Err(err) => warn!(
                %err,
                member_count,
                target_wu = target,
                "blockparty: raising coinbase reservation failed; reservation unchanged"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_grows_with_member_count() {
        let one = budget_for_members(1);
        let fifty = budget_for_members(50);
        assert!(fifty > one);
        // 50 members + 1 fee = 51 outputs × 172 WU + base + commitment + margin.
        let expected = COINBASE_BASE_WEIGHT
            + COINBASE_WITNESS_COMMITMENT_WEIGHT
            + 51 * COINBASE_OUTPUT_WEIGHT
            + BUDGET_SAFETY_MARGIN_WU;
        assert_eq!(fifty, expected);
    }

    #[test]
    fn no_raise_when_floor_covers_party() {
        // Floor 8000 WU (the default) comfortably holds a small party → no raise.
        assert_eq!(next_budget_wu(8_000, 8_000, 5), None);
        assert_eq!(next_budget_wu(8_000, 8_000, 10), None);
    }

    #[test]
    fn raises_above_floor_for_large_party() {
        // A party needing more than the floor triggers a raise to exactly its need.
        let big = budget_for_members(200);
        assert!(big > 8_000);
        assert_eq!(next_budget_wu(8_000, 8_000, 200), Some(big));
    }

    #[test]
    fn high_water_no_redundant_raise() {
        // Once raised for a big party, a smaller party never lowers it.
        let big = budget_for_members(200);
        assert_eq!(next_budget_wu(big, 8_000, 10), None);
        assert_eq!(next_budget_wu(big, 8_000, 199), None);
    }

    #[test]
    fn caps_at_max_reservation() {
        // A pathological party caps at the ceiling rather than reserving unbounded.
        let target = next_budget_wu(8_000, 8_000, 100_000);
        assert_eq!(target, Some(BLOCKPARTY_MAX_RESERVATION_WU));
        // And once at the cap, no further raise.
        assert_eq!(
            next_budget_wu(BLOCKPARTY_MAX_RESERVATION_WU, 8_000, 100_000),
            None
        );
    }

    #[test]
    fn never_below_floor() {
        // Even a 0-member party never drops the reservation below the floor.
        assert_eq!(next_budget_wu(5_000, 8_000, 0), Some(8_000));
    }
}
