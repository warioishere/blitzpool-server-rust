// SPDX-License-Identifier: AGPL-3.0-or-later

//! PPLNS pure math, no I/O: the ext 0x0003 §4 weight distribution builder,
//! its telemetry and weight constants. A payout is `floor(weight · T / W)`
//! and the pool output takes the residual `pay_P = T − Σpay`, so the
//! outputs sum to `T` exactly.

mod distribution;
mod weight;
mod weights;

pub use distribution::BudgetTelemetry;
pub use weight::{
    is_valid_payout_address, max_coinbase_outputs, output_weight_for_address,
    validate_fee_payout_budget, FeePayoutBudgetError, BUDGET_SAFETY_MARGIN_WU,
    COINBASE_BASE_WEIGHT, COINBASE_OUTPUT_WEIGHT, COINBASE_WITNESS_COMMITMENT_WEIGHT,
    DEFAULT_COINBASE_WEIGHT_BUDGET, DEFAULT_MIN_PAYOUT_SATS, DUST_LIMIT_SATS, MAX_FINDER_BONUS_PPM,
    MIN_COINBASE_WEIGHT_BUDGET,
};
pub use weights::{
    build_weight_distribution, WeightBuildError, WeightDistribution, WeightDistributionInput,
    WeightEntry, WithheldValue, SCORE_PRECISION,
};
