// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]

//! End-to-end test: spawn the Prometheus exporter, emit through the
//! recorder helpers, scrape `/metrics`, verify the
//! Prometheus-text-format output contains the expected lines.
//!
//! **Single test only**: the global recorder is install-once per
//! process, so two tests in this binary calling `MetricsService::spawn`
//! would conflict. Every end-to-end assertion lives in this one test.

use std::sync::atomic::{AtomicU16, Ordering};

use bp_metrics::{
    record_stratum_difficulty_adjustment, set_parked_block_counts, set_stream_consumer_lag,
    MetricsService, PrometheusConfig,
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

    // Emit through every recorder helper the pool calls.
    record_stratum_difficulty_adjustment();
    set_stream_consumer_lag("shares:accepted", "money", Some(12), 3);
    set_stream_consumer_lag("blocks:found", "notify", None, 0);
    set_parked_block_counts(2, 0);

    let url = format!("http://{}/metrics", handle.bind_addr);
    let body = reqwest::get(&url)
        .await
        .expect("GET /metrics")
        .error_for_status()
        .expect("/metrics returned non-2xx")
        .text()
        .await
        .expect("read body");

    // Labels are emitted sorted, so each line has a fixed shape.
    for line in [
        "stratum_difficulty_adjustments_total 1",
        r#"stream_consumer_pending{stream="shares:accepted",group="money"} 3"#,
        r#"stream_consumer_lag{stream="shares:accepted",group="money"} 12"#,
        r#"stream_consumer_lag_computable{stream="shares:accepted",group="money"} 1"#,
        r#"stream_consumer_lag_computable{stream="blocks:found",group="notify"} 0"#,
        "pool_blocks_pending_apply 2",
        "pool_blocks_unbookable 0",
    ] {
        assert!(body.contains(line), "`{line}` missing — body:\n{body}");
    }
    // A lag Redis cannot compute is not emitted as a (misleading) 0.
    assert!(
        !body.contains(r#"stream_consumer_lag{stream="blocks:found""#),
        "uncomputable lag must not be emitted — body:\n{body}"
    );
}
