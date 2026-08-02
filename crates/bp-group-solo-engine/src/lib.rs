// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-Solo service-engine — production-side orchestration around
//! the pure `bp-group-solo` math crate.
//!
//! Group-Solo is a PROP (proportional) mining mode running inside a
//! group: each block reward is split proportionally to in-round
//! shares, with an optional finder bonus — a configurable SHARE of the
//! miner cut, folded into the finder's own weight rather than paid as
//! a dedicated output. After each block found, the round
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
//! - **Per-group config**: `finderBonusPpm`, `roundResetPreset`,
//!   `roundResetTimezone`, `roundResetIntervalDays` live in the DB
//!   row keyed by `groupId`, NOT in `GroupSoloEngineConfig`.
//! - **Per-(group, finder) snapshots**: each miner's
//!   `getPayoutDistribution` call writes a snapshot keyed by their
//!   own address; `on_block_found` reads the snapshot for the actual
//!   finder.

/// The finder-bonus ceiling lives as two literals in two crates that
/// cannot see each other: [`bp_group_mgmt::MAX_FINDER_BONUS_PPM`] is
/// what a settings PATCH is validated against, and
/// [`bp_pplns::MAX_FINDER_BONUS_PPM`] is what `build_weight_distribution`
/// silently CLAMPS to.
///
/// Raising only the validator — the natural edit when an operator asks
/// for a higher ceiling — compiles and passes every test, and the pool
/// then accepts and echoes back a bonus it never pays: the admin sees
/// 60 %, the chain pays 50 %, and nothing logs the gap.
///
/// This crate is the only one that depends on both, so it is where the
/// two get nailed together. A one-sided edit now fails the build.
const _: () = assert!(
    bp_group_mgmt::MAX_FINDER_BONUS_PPM as i64 == bp_pplns::MAX_FINDER_BONUS_PPM as i64,
    "bp_group_mgmt::MAX_FINDER_BONUS_PPM and bp_pplns::MAX_FINDER_BONUS_PPM must agree — \
     the API would otherwise accept a bonus the coinbase silently clamps"
);

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
