// SPDX-License-Identifier: AGPL-3.0-or-later

//! Periodic self-check crons.
//!
//! - [`network_difficulty`] — polls mempool.space every 10 min, upserts
//!   `network_difficulty_tracker_entity`, and emits a push to subscribers
//!   when the difficulty value changes.
//! - [`best_difficulty`] — every 60 s, scans `address_settings_entity`
//!   for every address with at least one push subscription and emits a
//!   push if the persisted best has advanced since the last cron tick
//!   for that address.

pub mod best_difficulty;
pub mod hourly_stats;
pub mod network_difficulty;
