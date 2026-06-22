// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-Solo service-engine — production-side orchestration around
//! the pure `bp-group-solo` math crate.
//!
//! Group-Solo is a PROP (proportional) mining mode running inside a
//! group: each block reward is split proportionally to in-round
//! shares, with an optional configurable finder bonus paid as a
//! dedicated coinbase output. After each block found, the round
//! resets (unlike PPLNS's sliding window) — this is the "block-found
//! reset" path. A scheduled reset path (cron, per-group preset) wipes
//! the round on a calendar tick instead.
//!
//!
//! # Differences vs `bp-pplns-engine`
//!
//! - **Unsigned ledger**: `pendingSats` is always `≥ 0`. No matching
//!   debits, no pair-cancel sweep. Sub-dust accumulates as positive
//!   pending; dust-sweep deletes single-sided when dormant.
//! - **Round-based, not windowed**: the share zset wipes on every
//!   block-found. The optional cron-driven scheduled reset wipes
//!   balances on top.
//! - **Per-group config**: `finderBonusSats`, `roundResetPreset`,
//!   `roundResetTimezone`, `roundResetIntervalDays` live in the DB
//!   row keyed by `groupId`, NOT in `GroupSoloEngineConfig`.
//! - **Per-(group, finder) snapshots**: each miner's
//!   `getPayoutDistribution` call writes a snapshot keyed by their
//!   own address; `on_block_found` reads the snapshot for the actual
//!   finder.

pub mod config;
pub mod distribution;
pub mod engine;
pub mod error;
pub mod hooks;
pub mod ledger;
pub mod reader;
pub mod reset;
pub mod round;
pub mod sweep;
