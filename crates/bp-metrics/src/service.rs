// SPDX-License-Identifier: AGPL-3.0-or-later

//! Spawn the Prometheus exporter HTTP listener + install the global
//! recorder.
//!
//! # Lifecycle
//!
//! Exactly **one** `MetricsService::spawn` per process — the `metrics`
//! crate uses a single global recorder, and the HTTP listener lives for
//! the rest of the process.

use metrics_exporter_prometheus::PrometheusBuilder;
use tracing::{info, warn};

use crate::config::PrometheusConfig;
use crate::error::MetricsError;

pub struct MetricsService;

impl MetricsService {
    /// Install the Prometheus recorder + spawn the HTTP listener.
    pub fn spawn(config: PrometheusConfig) -> Result<MetricsServiceHandle, MetricsError> {
        PrometheusBuilder::new()
            .with_http_listener(config.bind_addr)
            .install()
            .map_err(|e| MetricsError::Install(format!("install: {e}")))?;
        info!(
            bind_addr = %config.bind_addr,
            "Prometheus exporter started — /metrics endpoint live"
        );
        Ok(MetricsServiceHandle {
            bind_addr: config.bind_addr.to_string(),
        })
    }
}

/// Handle to the running exporter. The HTTP listener task is detached
/// and lives for the process lifetime (the global recorder is
/// install-once anyway), so nothing needs dropping manually.
#[derive(Clone, Debug)]
pub struct MetricsServiceHandle {
    pub bind_addr: String,
}

impl Drop for MetricsServiceHandle {
    fn drop(&mut self) {
        // The exporter has no shutdown handle in this mode, so the
        // listener outlives the handle; the log line makes that visible.
        warn!(
            bind_addr = %self.bind_addr,
            "MetricsServiceHandle dropped; Prometheus listener continues on global recorder"
        );
    }
}
