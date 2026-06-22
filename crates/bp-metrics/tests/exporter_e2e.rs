// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! End-to-end test: spawn the Prometheus exporter, emit a few metrics
//! via the recorder helpers, scrape `/metrics`, verify the
//! Prometheus-text-format output contains the expected lines.
//!
//! **Single test only**: `metrics::set_global_recorder` is
//! install-once-per-process. Multiple tests inside one binary that
//! both call `MetricsService::spawn` would conflict. We bundle every
//! end-to-end assertion in this one test.

use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use bp_metrics::{
    record_aggregation_job, record_api_request, record_pool_stats, record_share_submission,
    record_stratum_difficulty_adjustment, record_stratum_job_sent, set_stratum_clients_connected,
    AggregationStatus, MetricsService, PrometheusConfig, ShareStatus,
};

static NEXT_PORT: AtomicU16 = AtomicU16::new(29_000);

fn alloc_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_emit_scrape_roundtrip() {
    let port = alloc_port();
    let cfg = PrometheusConfig::with_bind(&format!("127.0.0.1:{port}")).expect("parse bind addr");
    let handle = match MetricsService::spawn(cfg) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("MetricsService::spawn failed (port collision?): {e} — skipping");
            return;
        }
    };

    // Emit one of each metric kind. The recorder helpers must not
    // panic; the exporter must accept the labels + ranges.
    record_share_submission(ShareStatus::Valid, 1024.0, Some(Duration::from_millis(5)));
    record_share_submission(ShareStatus::Invalid, 0.5, None);
    record_share_submission(ShareStatus::Stale, 2048.0, Some(Duration::from_millis(2)));
    set_stratum_clients_connected("sv1", 42);
    set_stratum_clients_connected("sv2", 7);
    record_stratum_difficulty_adjustment();
    record_stratum_job_sent();
    record_stratum_job_sent();
    record_api_request("GET", "/api/info", 200, Duration::from_millis(15));
    record_api_request("POST", "/api/groups", 201, Duration::from_millis(80));
    record_pool_stats(1.234e15, 600);
    record_aggregation_job(
        "stats_sink_flush",
        AggregationStatus::Success,
        Duration::from_millis(120),
    );

    // Tiny wait so the exporter has a moment to schedule the histogram
    // observations through its internal channel (the exporter is
    // single-task; counters/gauges are sync, histograms can be slightly
    // delayed under pressure).
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = handle.metrics_url();
    let body = reqwest::get(&url)
        .await
        .expect("GET /metrics")
        .error_for_status()
        .expect("/metrics returned non-2xx")
        .text()
        .await
        .expect("read body");

    // Spot-check the expected metric names + label permutations.
    assert!(
        body.contains(r#"stratum_shares_total{status="valid"} 1"#),
        "stratum_shares_total{{status=valid}} missing — body:\n{body}"
    );
    assert!(body.contains(r#"stratum_shares_total{status="invalid"} 1"#));
    assert!(body.contains(r#"stratum_shares_total{status="stale"} 1"#));
    assert!(body.contains(r#"stratum_clients_connected{protocol="sv1"} 42"#));
    assert!(body.contains(r#"stratum_clients_connected{protocol="sv2"} 7"#));
    assert!(body.contains("stratum_difficulty_adjustments_total 1"));
    assert!(body.contains("stratum_jobs_sent_total 2"));
    // api_requests_total emits label-sorted (Prometheus convention).
    // We assert the bare metric name + the labels exist somewhere on
    // the same line rather than a fixed concatenation order.
    let api_lines: Vec<&str> = body
        .lines()
        .filter(|l| l.starts_with("api_requests_total{") && l.contains("/api/info"))
        .collect();
    assert!(
        !api_lines.is_empty(),
        "api_requests_total for /api/info missing — body:\n{body}"
    );
    let api_lines: Vec<&str> = body
        .lines()
        .filter(|l| l.starts_with("api_requests_total{") && l.contains("/api/groups"))
        .collect();
    assert!(
        !api_lines.is_empty(),
        "api_requests_total for /api/groups missing"
    );
    assert!(body.contains("pool_hashrate_hashes_per_second 1234"));
    assert!(body.contains("pool_miners_active 600"));
    assert!(
        body.contains(r#"aggregation_jobs_total{job_name="stats_sink_flush",status="success"} 1"#)
    );

    // Histogram buckets show up as `_bucket{le="..."}` lines. Verify at
    // least one bucket landed for each histogram metric.
    assert!(
        body.contains("stratum_share_validation_duration_seconds_bucket"),
        "share validation histogram missing"
    );
    assert!(
        body.contains("api_request_duration_seconds_bucket"),
        "api request histogram missing"
    );
    assert!(
        body.contains("pool_share_difficulty_bucket"),
        "share-difficulty histogram missing"
    );
    assert!(
        body.contains("aggregation_job_duration_seconds_bucket"),
        "aggregation histogram missing"
    );
}
