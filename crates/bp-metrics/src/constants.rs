// SPDX-License-Identifier: AGPL-3.0-or-later

//! Metric names + label names + histogram bucket layouts.
//!
//! Single source of truth so emit-sites in [`crate::recorder`] and
//! Grafana dashboards both see byte-identical strings. The bucket
//! values are tuned for share-validation and API request latencies.

// ── Stratum ──────────────────────────────────────────────────────────

pub const STRATUM_SHARES_TOTAL: &str = "stratum_shares_total";
pub const STRATUM_CLIENTS_CONNECTED: &str = "stratum_clients_connected";
pub const STRATUM_DIFFICULTY_ADJUSTMENTS_TOTAL: &str = "stratum_difficulty_adjustments_total";
pub const STRATUM_JOBS_SENT_TOTAL: &str = "stratum_jobs_sent_total";
pub const STRATUM_SHARE_VALIDATION_DURATION_SECONDS: &str =
    "stratum_share_validation_duration_seconds";

/// Bucket layout for share-validation duration (seconds). Sub-millisecond
/// resolution at the fast end (hot-path validation) to 1 s at the slow
/// end (degraded-PG-roundtrip outliers).
pub const SHARE_VALIDATION_BUCKETS_SECONDS: &[f64] =
    &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0];

// ── API ──────────────────────────────────────────────────────────────

pub const API_REQUEST_DURATION_SECONDS: &str = "api_request_duration_seconds";
pub const API_REQUESTS_TOTAL: &str = "api_requests_total";

/// Bucket layout for API request duration (seconds).
/// 10 ms floor, 10 s ceiling.
pub const API_REQUEST_BUCKETS_SECONDS: &[f64] = &[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

// ── Pool aggregate ───────────────────────────────────────────────────

pub const POOL_HASHRATE_HASHES_PER_SECOND: &str = "pool_hashrate_hashes_per_second";
pub const POOL_MINERS_ACTIVE: &str = "pool_miners_active";
pub const POOL_BLOCKS_FOUND_TOTAL: &str = "pool_blocks_found_total";
pub const POOL_SHARE_DIFFICULTY: &str = "pool_share_difficulty";

/// Share-difficulty histogram buckets (raw difficulty, not seconds).
pub const POOL_SHARE_DIFFICULTY_BUCKETS: &[f64] =
    &[1.0, 10.0, 100.0, 1_000.0, 10_000.0, 100_000.0, 1_000_000.0];

// ── Aggregation jobs (share-stats-sink + pplns-sweep) ───────────────

pub const AGGREGATION_JOBS_TOTAL: &str = "aggregation_jobs_total";
pub const AGGREGATION_JOB_DURATION_SECONDS: &str = "aggregation_job_duration_seconds";

/// Aggregation duration buckets — 100 ms to 60 s. Tuned for the 60 s
/// flush cron of the stats-sink + the daily 03:00 UTC sweep cron.
pub const AGGREGATION_JOB_BUCKETS_SECONDS: &[f64] = &[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0];

// ── Core→Satellite stream consumers ─────────────────────────────────

/// Per-group consumer lag — entries added to the stream but not yet
/// delivered to this consumer group. A rising value means a satellite is
/// behind or down. Only emitted while Redis can compute it (see
/// [`STREAM_CONSUMER_LAG_COMPUTABLE`]).
pub const STREAM_CONSUMER_LAG: &str = "stream_consumer_lag";
/// Per-group pending (delivered-but-unacked) entries — the PEL size.
pub const STREAM_CONSUMER_PENDING: &str = "stream_consumer_pending";
/// `1` when Redis can compute the group's lag, `0` when it can't — which
/// happens exactly when the stream was trimmed below the group's last-read id
/// (probable entry loss). The plain lag gauge goes blind in that case, so
/// alert on `stream_consumer_lag_computable == 0`, not just on high lag.
pub const STREAM_CONSUMER_LAG_COMPUTABLE: &str = "stream_consumer_lag_computable";

// ── Label names ──────────────────────────────────────────────────────

pub const LABEL_STATUS: &str = "status";
pub const LABEL_PROTOCOL: &str = "protocol";
pub const LABEL_METHOD: &str = "method";
pub const LABEL_ENDPOINT: &str = "endpoint";
pub const LABEL_JOB_NAME: &str = "job_name";
pub const LABEL_STREAM: &str = "stream";
pub const LABEL_GROUP: &str = "group";
