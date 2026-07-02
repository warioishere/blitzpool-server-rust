// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prometheus metrics exporter for the pool.
//!
//! The metrics service uses `prom-client` with per-metric `Counter` / `Histogram` / `Gauge`
//! instances. Rust idiom is the `metrics` facade: emit values with
//! `metrics::counter!("name", "label" => "value").increment(1)` and
//! the global recorder (here: `metrics-exporter-prometheus`) collects
//! them. No need to pre-declare every metric — they materialize on
//! first emit.
//!
//! # Scope
//!
//! Portable to Rust + has an obvious consumer in the pool. Out-of-scope
//! Metrics deferred until a concrete consumer needs them:
//!
//! - Worker-thread metrics — Node-specific concurrency model.
//! - DB pool / query metrics — would require sqlx instrumentation
//!   layer; deferrable until a hot-path slowdown forces it.
//! - Redis operation metrics — same reasoning.
//! - API cache hits/misses — wired alongside `bp-api` later.
//!
//! # Modules
//!
//! - [`config`] — `PrometheusConfig` (bind addr, histogram buckets).
//! - [`constants`] — metric names + label names. Single source of truth
//!   to avoid typo-drift between emit-sites and Grafana queries.
//! - [`recorder`] — typed helpers (`record_share_submission`,
//!   `record_api_request`, etc.) wrapping the `metrics::*!` macros.
//! - [`service`] — `MetricsService::spawn(config)` installs the global
//!   recorder + spawns the HTTP `/metrics` listener.

pub mod config;
pub mod constants;
pub mod error;
pub mod recorder;
pub mod service;

pub use config::PrometheusConfig;
pub use error::MetricsError;
pub use recorder::{
    record_aggregation_job, record_api_request, record_pool_block_found, record_pool_stats,
    record_share_submission, record_stratum_difficulty_adjustment, record_stratum_job_sent,
    set_stratum_clients_connected, set_stream_consumer_lag, AggregationStatus, ShareStatus,
};
pub use service::{MetricsService, MetricsServiceHandle};
