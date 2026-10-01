// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed helpers over the `metrics` macros, so emit-sites share the names in
//! [`crate::constants`]. They no-op without an installed recorder, so tests
//! need no [`crate::service::MetricsService::spawn`].

use metrics::{counter, gauge};

use crate::constants::*;

/// Update the stream-consumer gauges for one group. `lag` is `None` when
/// Redis cannot compute it; the `_computable` gauge then drops to `0`, so
/// alerting sees what a lag of "0" would hide.
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

/// Publish the two block-parking depths. Alert on `unbookable`: those blocks
/// paid miners on-chain and never reached a ledger.
pub fn set_parked_block_counts(pending_apply: u64, unbookable: u64) {
    gauge!(POOL_BLOCKS_PENDING_APPLY).set(pending_apply as f64);
    gauge!(POOL_BLOCKS_UNBOOKABLE).set(unbookable as f64);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every helper is safe to call without a global recorder.
    #[test]
    fn recorder_helpers_no_panic_without_global_recorder() {
        set_stream_consumer_lag("shares:accepted", "money", Some(0), 0);
        set_stream_consumer_lag("shares:accepted", "money", Some(1234), 5);
        set_stream_consumer_lag("blocks:found", "notify", None, 2);
        record_stratum_difficulty_adjustment();
        set_parked_block_counts(1, 0);
    }
}
