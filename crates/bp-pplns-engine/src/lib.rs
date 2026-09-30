// SPDX-License-Identifier: AGPL-3.0-or-later

//! PPLNS engine — production-side orchestration around the pure
//! `bp-pplns` math crate.
//!
//! This crate plugs into both
//! `bp-stratum-v1` and `bp-stratum-v2` via the hook traits they define,
//! and into `bp-db` (PostgreSQL) + Redis for state persistence.
//!
//! **Output tolerance is one satoshi per entry, and nothing is destroyed.**
//! Under the weight model a payout is `floor(weight · T / W)`, so each miner
//! entry lands at most one satoshi below its exact share, and the pool output
//! is the §4 residual `pay_P = T − Σpay` — it absorbs every remainder, so the
//! outputs sum to `T` exactly. There is no drift budget to spend: solvency,
//! ledger symmetry and idempotency are not negotiable, and neither is the sum.
//!
//! # Module layout
//!
//! - [`config`] — `PplnsEngineConfig` typed knobs (fee, min-payout,
//!   coinbase weight budget, abandoned-balance days, …) with bounds-
//!   checked validation.
//! - [`error`] — narrow `thiserror` enum, no umbrella over PG/Redis.
//! - [`window`] — Redis-backed sliding window. `record_share` (atomic
//!   MULTI/EXEC), trim, drift recalc, snapshot persistence.
//! - [`ledger`] — Postgres-backed signed credit/debit ledger.
//!   Balance bulk-upsert + history bulk-insert in one TX, lastAcceptedShareAt
//!   60s flush buffer.
//! - [`distribution`] — `build_distribution` wrapper around the shared
//!   weight build + snapshot write, `bp_coinbase_snapshot::build_and_snapshot`.
//! - [`sweep`] — daily 03:00 UTC `tokio`-loop that pair-cancels
//!   abandoned credits ↔ debits.
//! - [`hooks`] — `bp_share_hook::SharedAcceptedShareSink` impl for SV1 and
//!   SV2. Mode-aware: only records shares stamped as PPLNS.
//! - [`reader`] — read-only views consumed by `bp-api` (ledger
//!   summary, per-miner status, window stats, …).
//! - [`engine`] — top-level `PplnsEngine` that wires window + ledger
//!   + sweep cron + inflight cache into a single `spawn`-able handle.

pub mod autoscale;
pub mod config;
pub mod distribution;
pub mod engine;
pub mod error;
pub mod hooks;
pub mod ledger;
pub mod reader;
pub mod sweep;
pub mod window;

// Re-export the coinbase-weight constants + dust floor so consumers
// (bp-api in particular) can render them on the /api/pplns/fees
// endpoint without taking a direct dep on the underlying bp-pplns
// crate.
pub use bp_pplns::{
    max_coinbase_outputs, COINBASE_BASE_WEIGHT, COINBASE_OUTPUT_WEIGHT,
    COINBASE_WITNESS_COMMITMENT_WEIGHT, DUST_LIMIT_SATS,
};
