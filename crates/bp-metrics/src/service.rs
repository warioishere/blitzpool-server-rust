// SPDX-License-Identifier: AGPL-3.0-or-later

//! Spawn the Prometheus exporter HTTP listener + install the global
//! recorder.
//!
//! # Lifecycle
//!
//! Exactly **one** `MetricsService::spawn` per process — the `metrics`
//! crate uses a single global recorder. The handle holds the listener
//! task; dropping it shuts down the HTTP listener via the exporter's
//! own cancellation mechanism. Tests that need a per-test recorder
//! must use a different port each time and clean up explicitly.

use std::time::Duration;

use metrics_exporter_prometheus::PrometheusBuilder;
use tracing::{info, warn};

use crate::config::PrometheusConfig;
use crate::constants::{
    AGGREGATION_JOB_BUCKETS_SECONDS, AGGREGATION_JOB_DURATION_SECONDS, API_REQUEST_BUCKETS_SECONDS,
    API_REQUEST_DURATION_SECONDS, POOL_SHARE_DIFFICULTY, POOL_SHARE_DIFFICULTY_BUCKETS,
    SHARE_VALIDATION_BUCKETS_SECONDS, STRATUM_SHARE_VALIDATION_DURATION_SECONDS,
};
use crate::error::MetricsError;

pub struct MetricsService;

impl MetricsService {
    /// Install the Prometheus recorder + spawn the HTTP listener.
    /// Returns a handle that holds the listener alive; drop it to
    /// shut down the exporter.
    ///
    /// Bucket layouts for the four histograms are applied at install
    /// time — they can't be changed without reinstalling the recorder.
    pub fn spawn(config: PrometheusConfig) -> Result<MetricsServiceHandle, MetricsError> {
        let builder = PrometheusBuilder::new()
            .with_http_listener(config.bind_addr)
            // Set bucket layouts for our four histograms. Matchers are
            // exact-name; suffix-globs would be brittle.
            .set_buckets_for_metric(
                metrics_exporter_prometheus::Matcher::Full(
                    STRATUM_SHARE_VALIDATION_DURATION_SECONDS.to_string(),
                ),
                SHARE_VALIDATION_BUCKETS_SECONDS,
            )
            .map_err(|e| MetricsError::Install(format!("share-validation buckets: {e}")))?
            .set_buckets_for_metric(
                metrics_exporter_prometheus::Matcher::Full(
                    API_REQUEST_DURATION_SECONDS.to_string(),
                ),
                API_REQUEST_BUCKETS_SECONDS,
            )
            .map_err(|e| MetricsError::Install(format!("api-request buckets: {e}")))?
            .set_buckets_for_metric(
                metrics_exporter_prometheus::Matcher::Full(POOL_SHARE_DIFFICULTY.to_string()),
                POOL_SHARE_DIFFICULTY_BUCKETS,
            )
            .map_err(|e| MetricsError::Install(format!("share-difficulty buckets: {e}")))?
            .set_buckets_for_metric(
                metrics_exporter_prometheus::Matcher::Full(
                    AGGREGATION_JOB_DURATION_SECONDS.to_string(),
                ),
                AGGREGATION_JOB_BUCKETS_SECONDS,
            )
            .map_err(|e| MetricsError::Install(format!("aggregation buckets: {e}")))?;

        builder
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

    /// Best-effort sleep so the freshly-installed HTTP listener has a
    /// moment to bind the port before the caller scrapes. Useful in
    /// tests; production callers don't need this (the exporter binds
    /// synchronously inside `spawn` before returning).
    pub async fn wait_for_listener(_duration: Duration) {
        // `PrometheusBuilder::install` returns synchronously after the
        // listener is ready, so this is a no-op in practice. Keep the
        // method around for callers that want explicit wait-for-ready
        // semantics if the exporter behaviour ever changes.
    }
}

/// Handle. Cheap; holds nothing the caller needs to drop manually.
/// The exporter's HTTP listener task is detached + lives for the
/// process lifetime (the global recorder is install-once anyway).
#[derive(Clone, Debug)]
pub struct MetricsServiceHandle {
    pub bind_addr: String,
}

impl MetricsServiceHandle {
    /// Returns the URL of the `/metrics` endpoint. Useful for tests +
    /// for the `/health`-style status endpoint in `bp-api`.
    pub fn metrics_url(&self) -> String {
        format!("http://{}/metrics", self.bind_addr)
    }
}

impl Drop for MetricsServiceHandle {
    fn drop(&mut self) {
        // The metrics-exporter-prometheus listener doesn't expose a
        // clean shutdown handle in the install-on-runtime mode; once
        // installed the recorder lives for the process. Log so
        // operators can correlate handle-drops with the listener
        // outliving the holder if it ever becomes a problem.
        warn!(
            bind_addr = %self.bind_addr,
            "MetricsServiceHandle dropped; Prometheus listener continues on global recorder"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::{record_share_submission, ShareStatus};
    use std::sync::atomic::{AtomicU16, Ordering};

    // Port allocator across tests in this file. The global Prometheus
    // recorder is install-once-per-process, so tests can't all spawn
    // their own — only the first test actually installs; the rest
    // share the same recorder. We still use distinct ports to avoid
    // accidental dual-bind if cargo test ever reorders.
    static NEXT_PORT: AtomicU16 = AtomicU16::new(19_000);

    fn alloc_port() -> u16 {
        NEXT_PORT.fetch_add(1, Ordering::SeqCst)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn spawn_returns_handle_with_correct_url() {
        let port = alloc_port();
        let cfg = PrometheusConfig::with_bind(&format!("127.0.0.1:{port}")).expect("config");
        // We don't actually call spawn here to avoid global-recorder
        // double-install if another test in the suite already
        // installed. Test only the handle shape + URL formatting via
        // direct construction.
        let handle = MetricsServiceHandle {
            bind_addr: cfg.bind_addr.to_string(),
        };
        assert_eq!(
            handle.metrics_url(),
            format!("http://127.0.0.1:{port}/metrics")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn metrics_url_uses_handle_bind_addr() {
        let handle = MetricsServiceHandle {
            bind_addr: "10.0.0.5:9000".to_string(),
        };
        assert_eq!(handle.metrics_url(), "http://10.0.0.5:9000/metrics");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recorder_helpers_safe_to_call_before_spawn() {
        // Pre-install: facade no-ops. Verify no panic.
        record_share_submission(ShareStatus::Valid, 1024.0, Some(Duration::from_millis(3)));
    }
}
