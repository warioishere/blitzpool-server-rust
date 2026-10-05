// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tunable pool-wide constants. Changing these here changes pool-wide behaviour.

use std::time::Duration;

/// Width of one time slot; a slot ending at `X` covers `[X - SLOT_DURATION_MS, X)`.
pub const SLOT_DURATION_MS: i64 = 10 * 60 * 1_000;

/// Delay after slot end before charts show the slot, so readers never see a
/// partial datapoint the flush has not committed yet.
pub const CHART_VISIBILITY_BUFFER_MS: i64 = 60_000;

/// Same buffer as a [`Duration`].
pub const CHART_VISIBILITY_BUFFER: Duration = Duration::from_millis(60_000);

/// Ceiling on a single share's difficulty. Anything above is implausible for a
/// real miner (a corrupted frame or a probe) and is dropped by the accumulator.
pub const MAX_REASONABLE_DIFFICULTY: f64 = 1.0e15;
