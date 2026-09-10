// SPDX-License-Identifier: AGPL-3.0-or-later

//! PPLNS pure math — the weight-native distribution builder (SV2 ext
//! 0x0003 §4 model) plus the shared record types and weight constants.
//!
//! No I/O. Window aggregation, Redis snapshots, DB writes, and dust-sweep
//! cron belong to a higher-level service crate that consumes this one.
//!
//! **Sat tolerance:** a payout is `floor(weight · T / W)`, so an entry is at
//! most one satoshi under its exact share, and the pool output takes the §4
//! residual `pay_P = T − Σpay` — the outputs sum to `T` exactly. There is no
//! drift allowance beyond that flooring.

mod distribution;
mod weight;
mod weights;

pub use distribution::{BudgetTelemetry, CoinbaseDistributionEntry};
pub use weight::{
    is_payable_payout_key, is_valid_payout_address, max_coinbase_outputs,
    output_weight_for_address, output_weight_for_payout_key, resolve_min_payout_sats,
    validate_fee_payout_budget, FeePayoutBudgetError, BUDGET_SAFETY_MARGIN_WU,
    COINBASE_BASE_WEIGHT, COINBASE_OUTPUT_WEIGHT, COINBASE_WITNESS_COMMITMENT_WEIGHT,
    DEFAULT_COINBASE_WEIGHT_BUDGET, DEFAULT_MIN_PAYOUT_SATS, DUST_LIMIT_SATS, MAX_FINDER_BONUS_PPM,
    MIN_COINBASE_WEIGHT_BUDGET, P2WPKH_OUTPUT_WEIGHT,
};
pub use weights::{
    build_weight_distribution, WeightBuildError, WeightDistribution, WeightDistributionInput,
    WeightEntry, WithheldValue, SCORE_PRECISION,
};
