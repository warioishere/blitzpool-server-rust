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
//! (This used to claim "a few thousand sats of drift is acceptable during the
//! migration". The migration is over and the weight model removed the slack.)
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
//! - [`distribution`] — `build_distribution` wrapper around
//!   `bp_pplns::build_coinbase_distribution` with snapshot-readback +
//!   recompute-fallback.
//! - [`sweep`] — daily 03:00 UTC `tokio`-loop that pair-cancels
//!   abandoned credits ↔ debits. Group-solo dust-absorption lives in
//!   the future `bp-group-solo-engine` crate.
//! - [`inflight`] — per-block-reward dedup of concurrent
//!   `build_distribution` calls (in-flight-future shared via
//!   `tokio::sync::watch` / `OnceCell`-based dedup with TTL).
//! - [`hooks`] — `bp_stratum_v1::hooks::{AcceptedShareSink,
//!   BlockSubmissionSink}` impls (and SV2 equivalents once that hook
//!   surface lands). Mode-aware: only records if the share's address
//!   resolves to PPLNS.
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

// `InflightResultCache` extracted to the shared `bp-inflight-cache`
// crate so `bp-group-solo-engine` (and future engines) can share the
// dedup-plus-TTL pattern without duplicating ~350 LoC. Re-export so
// existing call sites that imported `bp_pplns_engine::inflight::…`
// keep working.
pub use bp_inflight_cache as inflight;

// Re-export the coinbase-weight constants + dust floor so consumers
// (bp-api in particular) can render them on the /api/pplns/fees
// endpoint without taking a direct dep on the underlying bp-pplns
// crate.
pub use bp_pplns::{
    max_coinbase_outputs, COINBASE_BASE_WEIGHT, COINBASE_OUTPUT_WEIGHT,
    COINBASE_WITNESS_COMMITMENT_WEIGHT, DUST_LIMIT_SATS,
};
