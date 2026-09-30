// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prometheus metrics exporter for the pool.
//!
//! Emit-sites use the `metrics` facade (`metrics::counter!` /
//! `metrics::gauge!`); the global recorder (`metrics-exporter-prometheus`)
//! collects them. Metrics materialize on first emit, so `/metrics` shows only
//! what has actually been emitted: the stream-consumer lag, the parked-block
//! depths, vardiff adjustments and the lost-accepted-share counter.
//!
//! # Modules
//!
//! - [`config`] — `PrometheusConfig` (bind addr).
//! - [`constants`] — metric names + label names, shared by emit-sites and
//!   Grafana queries.
//! - [`recorder`] — typed helpers (`set_stream_consumer_lag`,
//!   `set_parked_block_counts`, …) wrapping the `metrics::*!` macros.
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
    record_stratum_difficulty_adjustment, set_parked_block_counts, set_stream_consumer_lag,
};
pub use service::{MetricsService, MetricsServiceHandle};
