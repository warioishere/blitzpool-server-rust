// SPDX-License-Identifier: AGPL-3.0-or-later

//! Distribution telemetry. The satoshi allocation itself is the ext 0x0003
//! §4 weight formula in [`crate::weights`].

/// Per-distribution weight-budget pressure, consumed by the coinbase-budget
/// autoscaler. Utilization = `desired_weight / effective_budget`: at ≥ 1.0 the
/// blockspace cut dropped miners (`trimmed_count > 0`); below 1.0 it's the
/// headroom the budget still has before it would start cutting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetTelemetry {
    /// Total coinbase weight all published miners would need with no cut
    /// (fixed overhead + every payout output).
    pub desired_weight: u32,
    /// The cut threshold actually applied this build (`budget` minus the
    /// safety margin). Denominator for the utilization ratio.
    pub effective_budget: u32,
    /// How many miners the blockspace cut dropped from the published set
    /// (settled via their balance instead of an own output).
    pub trimmed_count: u32,
}

impl BudgetTelemetry {
    /// Fraction of the cut threshold the (uncut) demand consumes.
    /// `< 1.0` = headroom; `>= 1.0` = the cut fired. The autoscaler's
    /// control input. `effective_budget == 0` (degenerate) reports `0.0`.
    pub fn utilization(&self) -> f64 {
        if self.effective_budget == 0 {
            return 0.0;
        }
        self.desired_weight as f64 / self.effective_budget as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utilization_is_demand_over_effective_budget() {
        let t = BudgetTelemetry {
            desired_weight: 45_000,
            effective_budget: 50_000,
            trimmed_count: 0,
        };
        assert!((t.utilization() - 0.9).abs() < 1e-9);
    }

    #[test]
    fn utilization_degenerate_zero_budget_reports_zero() {
        let t = BudgetTelemetry {
            desired_weight: 45_000,
            effective_budget: 0,
            trimmed_count: 3,
        };
        assert_eq!(t.utilization(), 0.0);
    }
}
