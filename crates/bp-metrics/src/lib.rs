// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prometheus exporter for the pool. Metrics materialize on first emit, so
//! `/metrics` shows only what has actually been emitted.

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
