// SPDX-License-Identifier: AGPL-3.0-or-later

//! [`MiningModeResult`], what a mode resolution hands around, and
//! [`MarkDebouncer`] for the live-marker write. The resolution itself lives
//! with its I/O: the bin's session persistence and `bp-api`'s `mode` module.

mod debouncer;
mod result;

pub use debouncer::{MarkDebouncer, DEFAULT_REFRESH_INTERVAL};
pub use result::MiningModeResult;

/// Redis key of an address's live mode marker: the mode its last accepted
/// share was mined in, kept for a few minutes.
pub fn live_mode_marker_key(address: &str) -> String {
    format!("miner:{address}:mode")
}
