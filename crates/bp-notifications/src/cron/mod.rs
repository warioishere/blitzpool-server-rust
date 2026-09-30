// SPDX-License-Identifier: AGPL-3.0-or-later

//! Periodic self-check crons.
//!
//! - [`network_difficulty`] — polls mempool.space every 10 min, upserts
//!   `network_difficulty_tracker_entity`, and emits a push to subscribers
//!   when the difficulty value changes.
//! - [`best_difficulty`] — every 60 s, reads the persisted best of every
//!   subscribed address and notifies when it has advanced past the
//!   tracked baseline.
//! - `hourly_stats` — hourly stats / workers digest for Telegram and
//!   ntfy subscribers that enabled it.

pub mod best_difficulty;
pub mod hourly_stats;
pub mod network_difficulty;
