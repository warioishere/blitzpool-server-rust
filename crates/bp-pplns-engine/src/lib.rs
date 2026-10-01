// SPDX-License-Identifier: AGPL-3.0-or-later

//! PPLNS engine around the pure `bp-pplns` math: Redis window, Postgres ledger.
//! A miner entry is `floor(weight · T / W)`, at most one sat below its exact
//! share; the pool output is the §4 residual `T − Σpay`, so outputs sum to `T`
//! exactly. Solvency, ledger symmetry and idempotency are not negotiable.

pub mod autoscale;
pub mod config;
pub mod distribution;
pub mod engine;
pub mod hooks;
pub mod ledger;
pub mod reader;
pub mod sweep;
pub mod window;

// Re-exported so `bp-api` can render them without depending on `bp-pplns`.
pub use bp_pplns::{
    max_coinbase_outputs, COINBASE_BASE_WEIGHT, COINBASE_OUTPUT_WEIGHT,
    COINBASE_WITNESS_COMMITMENT_WEIGHT, DUST_LIMIT_SATS,
};
