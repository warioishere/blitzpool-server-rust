// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed recorder helpers wrapping the `metrics` macros, so emit-sites
//! share one set of metric + label names ([`crate::constants`]).
//!
//! All functions are zero-cost when the global recorder isn't
//! installed (the `metrics` facade no-ops). That makes tests safe even
//! without a [`crate::service::MetricsService::spawn`].

use metrics::{counter, gauge};

use crate::constants::*;

/// Update the Core→Satellite stream-consumer lag gauges for one consumer
/// group. `lag` is `None` when Redis can't compute it (the stream was trimmed
/// below the group's read offset, probable entry loss); the `_computable`
/// gauge then drops to `0` so alerting sees what a lag of "0" would hide.
/// `pending` (PEL size) is always known and always emitted.
pub fn set_stream_consumer_lag(stream: &str, group: &str, lag: Option<u64>, pending: u64) {
    let stream = stream.to_string();
    let group = group.to_string();
    gauge!(STREAM_CONSUMER_PENDING, LABEL_STREAM => stream.clone(), LABEL_GROUP => group.clone())
        .set(pending as f64);
    gauge!(
        STREAM_CONSUMER_LAG_COMPUTABLE,
        LABEL_STREAM => stream.clone(),
        LABEL_GROUP => group.clone(),
    )
    .set(if lag.is_some() { 1.0 } else { 0.0 });
    if let Some(lag) = lag {
        gauge!(STREAM_CONSUMER_LAG, LABEL_STREAM => stream, LABEL_GROUP => group).set(lag as f64);
    }
}

/// Tick the vardiff-adjustment counter.
pub fn record_stratum_difficulty_adjustment() {
    counter!(STRATUM_DIFFICULTY_ADJUSTMENTS_TOTAL).increment(1);
}

/// Publish the two block-parking depths from the confirmation watcher's
/// pass.
///
/// `unbookable` is the one to alert on: those blocks paid miners on-chain
/// and never reached a ledger. Nothing else in the pool reads that store,
/// so this gauge is the only standing signal that it is not empty.
pub fn set_parked_block_counts(pending_apply: u64, unbookable: u64) {
    gauge!(POOL_BLOCKS_PENDING_APPLY).set(pending_apply as f64);
    gauge!(POOL_BLOCKS_UNBOOKABLE).set(unbookable as f64);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The facade no-ops without a global recorder, so every helper must be
    /// safe to call before `MetricsService::spawn` (and in tests).
    #[test]
    fn recorder_helpers_no_panic_without_global_recorder() {
        set_stream_consumer_lag("shares:accepted", "money", Some(0), 0);
        set_stream_consumer_lag("shares:accepted", "money", Some(1234), 5);
        set_stream_consumer_lag("blocks:found", "notify", None, 2);
        record_stratum_difficulty_adjustment();
        set_parked_block_counts(1, 0);
    }
}
