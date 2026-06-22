// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-address mining-mode routing — solo / pplns / group-solo.
//!
//! Pure dependency-inverted logic: the crate does not talk to Redis, DB,
//! or any other I/O system. Production wiring (in higher-layer crates)
//! supplies impls of [`LiveMarkerReader`], [`GroupMembershipReader`], and
//! [`PplnsWindowReader`]; [`ModeResolver`] composes them and adds a tiny
//! in-process cache (30 s TTL) to soak repeated UI-dashboard polls.
//!
//! Companion piece: [`MarkDebouncer`], an in-memory rate-limiter for the
//! live-marker write path (≤1 Redis write/min/address for unchanged
//! mode, immediate write on mode change).
//!
//! Implements the `MiningModeService` / `MinerActiveModeService` pair.

mod debouncer;
mod reader;
mod resolver;
mod result;

pub use debouncer::{MarkDebouncer, DEFAULT_REFRESH_INTERVAL};
pub use reader::{
    BlockpartyMembershipReader, GroupMembershipReader, LiveMarkerReader, NoopBlockpartyReader,
    PplnsWindowReader,
};
pub use resolver::{ModeResolver, DEFAULT_CACHE_TTL};
pub use result::MiningModeResult;
