// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-Solo service-engine.
//!
//! Group-Solo is a mining mode running inside a group: each block reward
//! is split proportionally to the members' shares, with an optional
//! finder bonus (a configurable SHARE of the miner cut, folded into the
//! finder's own weight rather than paid as a dedicated output).
//!
//! # Differences vs `bp-pplns-engine`
//!
//! - **No ledger.** A member the coinbase cannot pay forfeits the block
//!   and their share falls to the pool output
//!   ([`bp_pplns::WithheldValue::ToPool`]). Nobody is over- or underpaid,
//!   so there are no balances, no dust sweep and no settlement at
//!   block-found: what the coinbase paid IS the record.
//!
//!   That only holds while every member fits in the coinbase, so the
//!   member cap is not a preference: `GroupService` refuses a join past
//!   what `bp_pplns::max_coinbase_outputs` says the Group-Solo weight
//!   budget can pay.
//! - **Two payout modes**: `Prop` keeps a round that a block-found
//!   (when `resetRoundOnBlock` is set) or a scheduled calendar reset
//!   wipes; `Window` keeps a time-bucketed sliding window instead.
//! - **Per-group config**: `finderBonusPpm`, `roundResetPreset`,
//!   `roundResetTimezone`, `roundResetIntervalDays` live in the DB
//!   row keyed by `groupId`, NOT in `GroupSoloEngineConfig`.
//! - **Per-job snapshots**: each build is stored under its payout list's
//!   fingerprint, and `on_block_found` resolves the one the winning
//!   job's coinbase was built from.

/// The finder-bonus ceiling lives as two literals in two crates that
/// cannot see each other: [`bp_group_mgmt::MAX_FINDER_BONUS_PPM`] is
/// what a settings PATCH is validated against, and
/// [`bp_pplns::MAX_FINDER_BONUS_PPM`] is what `build_weight_distribution`
/// silently CLAMPS to. Raising only the validator would make the pool
/// accept a bonus it never pays. This crate is the only one that depends
/// on both, so the build fails here on a one-sided edit.
const _: () = assert!(
    bp_group_mgmt::MAX_FINDER_BONUS_PPM as i64 == bp_pplns::MAX_FINDER_BONUS_PPM as i64,
    "bp_group_mgmt::MAX_FINDER_BONUS_PPM and bp_pplns::MAX_FINDER_BONUS_PPM must agree — \
     the API would otherwise accept a bonus the coinbase silently clamps"
);

pub mod config;
pub mod distribution;
pub mod engine;
pub mod error;
pub mod history;
pub mod hooks;
pub mod reader;
pub mod reset;
pub mod round;
