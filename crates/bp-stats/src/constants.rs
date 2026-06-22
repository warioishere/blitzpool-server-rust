// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tunable pool-wide constants. Changing these here changes pool-wide behaviour.

use std::time::Duration;

/// Width of one time slot. The pool buckets all per-slot stats by their
/// **end timestamp**: a slot ending at `X` contains every event in
/// `[X - SLOT_DURATION_MS, X)`.
pub const SLOT_DURATION_MS: i64 = 10 * 60 * 1_000;

/// Safety buffer between slot-end and chart visibility. A slot is not shown
/// on charts until `now > slot_end + CHART_VISIBILITY_BUFFER_MS`, so that
/// the flush has had a chance to commit the slot's data to PG before
/// downstream readers can see a partial datapoint.
pub const CHART_VISIBILITY_BUFFER_MS: i64 = 60_000;

/// Same buffer as a [`Duration`] for callers that prefer the typed form.
pub const CHART_VISIBILITY_BUFFER: Duration = Duration::from_millis(60_000);

/// Defense-in-depth ceiling on per-share difficulty values. PG columns
/// `pool_share_statistics.accepted` and `.rejected` are `real` (≈3.4e38),
/// so a single ingested diff above ~1e15 is implausible for real miners
/// and almost certainly a corrupted SV2 frame or a misconfigured probe.
/// Shares above this limit are silently discarded by the accumulator —
/// see `PoolSharesAccumulator::add_accepted_share`.
pub const MAX_REASONABLE_DIFFICULTY: f64 = 1.0e15;

/// Once a flusher reports this many consecutive failures, the health
/// monitor flips to "warning" so the caller can emit a single
/// `tracing::warn!`. Three minutes of sustained PG outage = enough slack
/// that one slow query doesn't spam the log, quick enough that a real
/// outage is visible before OOM.
pub const FLUSH_FAILURE_WARN_THRESHOLD: u32 = 3;
