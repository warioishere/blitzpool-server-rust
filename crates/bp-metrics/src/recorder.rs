// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed recorder helpers — the only place call-sites should reach
//! into the `metrics` crate. Centralizes label-string discipline +
//! unit conversion (e.g. `Duration` → seconds-as-f64) so emit-sites
//! stay terse.
//!
//! All functions are zero-cost when the global recorder isn't
//! installed (the `metrics` facade no-ops). That makes tests safe even
//! without a [`crate::service::MetricsService::spawn`].

use std::time::Duration;

use metrics::{counter, gauge, histogram};

use crate::constants::*;

/// Stratum share outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareStatus {
    Valid,
    Invalid,
    Stale,
}

impl ShareStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ShareStatus::Valid => "valid",
            ShareStatus::Invalid => "invalid",
            ShareStatus::Stale => "stale",
        }
    }
}

/// Aggregation job outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregationStatus {
    Success,
    Failure,
}

impl AggregationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AggregationStatus::Success => "success",
            AggregationStatus::Failure => "failure",
        }
    }
}

/// Record one accepted / rejected / stale share. The `validation_time`
/// is optional — pass `None` if the call-site doesn't measure it (e.g.
/// pre-share-validation rejects). `difficulty` feeds the
/// `pool_share_difficulty` histogram.
pub fn record_share_submission(
    status: ShareStatus,
    difficulty: f64,
    validation_time: Option<Duration>,
) {
    counter!(STRATUM_SHARES_TOTAL, LABEL_STATUS => status.as_str()).increment(1);
    histogram!(POOL_SHARE_DIFFICULTY).record(difficulty);
    if let Some(d) = validation_time {
        histogram!(STRATUM_SHARE_VALIDATION_DURATION_SECONDS).record(d.as_secs_f64());
    }
}

/// Update the per-protocol live-connection gauge.
pub fn set_stratum_clients_connected(protocol: &'static str, count: i64) {
    gauge!(STRATUM_CLIENTS_CONNECTED, LABEL_PROTOCOL => protocol).set(count as f64);
}

/// Tick the vardiff-adjustment counter.
pub fn record_stratum_difficulty_adjustment() {
    counter!(STRATUM_DIFFICULTY_ADJUSTMENTS_TOTAL).increment(1);
}

/// Tick the mining-job-sent counter (call once per `mining.notify` /
/// `NewMiningJob` emit).
pub fn record_stratum_job_sent() {
    counter!(STRATUM_JOBS_SENT_TOTAL).increment(1);
}

/// Record an API request — both the counter + the duration histogram
/// get the same label set so dashboards can join cleanly. `status` is
/// the integer HTTP status code stringified by the caller.
pub fn record_api_request(method: &str, endpoint: &str, status: u16, duration: Duration) {
    let status = status.to_string();
    let method = method.to_string();
    let endpoint = endpoint.to_string();
    counter!(
        API_REQUESTS_TOTAL,
        LABEL_METHOD => method.clone(),
        LABEL_ENDPOINT => endpoint.clone(),
        LABEL_STATUS => status.clone(),
    )
    .increment(1);
    histogram!(
        API_REQUEST_DURATION_SECONDS,
        LABEL_METHOD => method,
        LABEL_ENDPOINT => endpoint,
        LABEL_STATUS => status,
    )
    .record(duration.as_secs_f64());
}

/// Update pool-aggregate gauges. Called from the stats-sink's flush
/// cycle and from the block-found path.
pub fn record_pool_stats(hashrate_h_per_s: f64, active_miners: i64) {
    gauge!(POOL_HASHRATE_HASHES_PER_SECOND).set(hashrate_h_per_s);
    gauge!(POOL_MINERS_ACTIVE).set(active_miners as f64);
}

/// Tick the `pool_blocks_found_total` counter. Called from the
/// block-submission-confirmation path in `bin/blitzpool`.
pub fn record_pool_block_found() {
    counter!(POOL_BLOCKS_FOUND_TOTAL).increment(1);
}

/// Record one aggregation-job run. `job_name` should be a stable
/// string identifying the job (e.g. `"stats_sink_flush"`,
/// `"pplns_dust_sweep"`, `"group_solo_round_reset"`).
pub fn record_aggregation_job(
    job_name: &'static str,
    status: AggregationStatus,
    duration: Duration,
) {
    counter!(
        AGGREGATION_JOBS_TOTAL,
        LABEL_JOB_NAME => job_name,
        LABEL_STATUS => status.as_str(),
    )
    .increment(1);
    histogram!(
        AGGREGATION_JOB_DURATION_SECONDS,
        LABEL_JOB_NAME => job_name,
    )
    .record(duration.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests verify the API doesn't panic when called without a
    // global recorder (the `metrics` facade no-ops). Integration tests
    // in `service.rs` exercise the round-trip through the exporter.

    #[test]
    fn share_status_wire_strings_are_stable() {
        assert_eq!(ShareStatus::Valid.as_str(), "valid");
        assert_eq!(ShareStatus::Invalid.as_str(), "invalid");
        assert_eq!(ShareStatus::Stale.as_str(), "stale");
    }

    #[test]
    fn aggregation_status_wire_strings_are_stable() {
        assert_eq!(AggregationStatus::Success.as_str(), "success");
        assert_eq!(AggregationStatus::Failure.as_str(), "failure");
    }

    #[test]
    fn recorder_helpers_no_panic_without_global_recorder() {
        record_share_submission(ShareStatus::Valid, 1024.0, Some(Duration::from_millis(5)));
        record_share_submission(ShareStatus::Invalid, 0.5, None);
        record_share_submission(ShareStatus::Stale, 2048.0, None);
        set_stratum_clients_connected("sv1", 42);
        set_stratum_clients_connected("sv2", 7);
        record_stratum_difficulty_adjustment();
        record_stratum_job_sent();
        record_api_request("GET", "/api/pplns/window", 200, Duration::from_millis(15));
        record_api_request("POST", "/api/groups", 201, Duration::from_millis(80));
        record_pool_stats(1.234e15, 600);
        record_pool_block_found();
        record_aggregation_job(
            "stats_sink_flush",
            AggregationStatus::Success,
            Duration::from_millis(120),
        );
        record_aggregation_job(
            "pplns_dust_sweep",
            AggregationStatus::Failure,
            Duration::from_secs(45),
        );
    }
}
