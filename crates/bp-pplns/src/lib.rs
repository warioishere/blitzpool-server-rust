// SPDX-License-Identifier: AGPL-3.0-or-later

//! PPLNS engine — pure math for the 5-phase coinbase distribution algorithm
//! with signed credit/debit ledger and abandoned-debtor solvency cap.
//!
//! No I/O. Window aggregation, Redis snapshots, DB writes, and dust-sweep
//! cron belong to a higher-level service crate that consumes this one.
//!
//! Sat-drift tolerance is recorded in `feedback-sat-parity-relaxed`.

mod distribution;
mod weight;

pub use distribution::{
    build_coinbase_distribution, BudgetTelemetry, CoinbaseDistributionEntry,
    CoinbaseDistributionInput, CoinbaseDistributionResult,
};
pub use weight::{
    is_valid_payout_address, max_coinbase_outputs, output_weight_for_address,
    resolve_min_payout_sats, validate_fee_payout_budget, FeePayoutBudgetError,
    BUDGET_SAFETY_MARGIN_WU, COINBASE_BASE_WEIGHT, COINBASE_OUTPUT_WEIGHT,
    COINBASE_WITNESS_COMMITMENT_WEIGHT, DEFAULT_COINBASE_WEIGHT_BUDGET, DEFAULT_MIN_PAYOUT_SATS,
    DUST_LIMIT_SATS,
};
