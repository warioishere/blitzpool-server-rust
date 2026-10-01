// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core-side consumer-lag monitor for the Core→Satellite streams.
//!
//! Runs on the producing front, because a Satellite that is behind or down
//! cannot monitor itself; it warns before `MAXLEN` trims unconsumed entries.

use std::time::Duration;

use redis::aio::ConnectionManager;
use redis::streams::StreamInfoGroupsReply;
use redis::AsyncCommands;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Enough to catch a sustained backlog without polling churn.
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Per-group lag for one stream. `lag` is `None` when the stream was trimmed
/// below the group's last-read id (probable entry loss), so it is alarming,
/// never `0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LagReport {
    pub(crate) stream: String,
    pub(crate) group: String,
    pub(crate) lag: Option<usize>,
    pub(crate) pending: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LagStatus {
    Ok,
    /// The satellite is behind or down.
    OverBudget,
    /// Stream trimmed below the group offset: entries were almost certainly
    /// lost, while a plain lag number would read `0`.
    Unknown,
}

pub(crate) fn classify(lag: Option<usize>, budget: usize) -> LagStatus {
    match lag {
        None => LagStatus::Unknown,
        Some(l) if l > budget => LagStatus::OverBudget,
        Some(_) => LagStatus::Ok,
    }
}

pub(crate) struct StreamMonitorHandle {
    task: JoinHandle<()>,
    cancel: CancellationToken,
}

impl StreamMonitorHandle {
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        if let Err(err) = self.task.await {
            warn!(%err, "stream-monitor: task join failed");
        }
    }
}

pub(crate) fn spawn(
    redis: ConnectionManager,
    keys: Vec<&'static str>,
    lag_budget: usize,
) -> StreamMonitorHandle {
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        info!(?keys, lag_budget, "stream-monitor: watching consumer lag");
        loop {
            tokio::select! {
                biased;
                _ = task_cancel.cancelled() => break,
                _ = tick.tick() => {
                    for report in collect_lag(&redis, &keys).await {
                        // Every sample is exported: `lag = None` drops the
                        // `_computable` gauge to 0, which is what alerts fire on.
                        bp_metrics::set_stream_consumer_lag(
                            &report.stream,
                            &report.group,
                            report.lag.map(|l| l as u64),
                            report.pending as u64,
                        );
                        match classify(report.lag, lag_budget) {
                            LagStatus::OverBudget => warn!(
                                stream = %report.stream,
                                group = %report.group,
                                lag = ?report.lag,
                                pending = report.pending,
                                lag_budget,
                                "stream-monitor: consumer lag over budget — Satellite is behind or down"
                            ),
                            LagStatus::Unknown => warn!(
                                stream = %report.stream,
                                group = %report.group,
                                pending = report.pending,
                                "stream-monitor: consumer lag UNAVAILABLE — stream likely trimmed below the group offset (probable entry loss); investigate"
                            ),
                            LagStatus::Ok => debug!(
                                stream = %report.stream,
                                group = %report.group,
                                lag = ?report.lag,
                                "stream-monitor: lag ok"
                            ),
                        }
                    }
                }
            }
        }
        info!("stream-monitor: stopped");
    });
    StreamMonitorHandle { task, cancel }
}

/// A stream with no entries or no groups yet contributes nothing.
pub(crate) async fn collect_lag(redis: &ConnectionManager, keys: &[&str]) -> Vec<LagReport> {
    let mut out = Vec::new();
    for key in keys {
        let mut conn = redis.clone();
        let reply: Result<StreamInfoGroupsReply, _> = conn.xinfo_groups(*key).await;
        let groups = match reply {
            Ok(r) => r.groups,
            // No such key (no shares produced yet) or transient error — skip.
            Err(_) => continue,
        };
        for g in groups {
            out.push(LagReport {
                stream: (*key).to_string(),
                group: g.name,
                // Not coerced to 0: `None` is the entry-loss signal.
                lag: g.lag,
                pending: g.pending,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_test_support::{connect_redis_in_range_or_skip, redis_db};

    #[tokio::test]
    async fn collect_lag_reports_undelivered_entries() {
        let Some(conn) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 5).await else {
            return;
        };
        let key = "bp:test:monitor:stream";

        // Missing stream → no reports (no-such-key handled).
        assert!(collect_lag(&conn, &[key]).await.is_empty());

        // Create a group at the start, then add 4 entries nobody consumes.
        let _: () = conn
            .clone()
            .xgroup_create_mkstream(key, "g1", "0")
            .await
            .expect("mkstream");
        for i in 0..4 {
            let _: String = conn
                .clone()
                .xadd(key, "*", &[("d", &format!("v{i}"))])
                .await
                .expect("xadd");
        }

        let reports = collect_lag(&conn, &[key]).await;
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].group, "g1");
        assert_eq!(reports[0].lag, Some(4), "all 4 entries are undelivered");
    }

    /// `lag = None` classifies as `Unknown`, never as ok.
    #[test]
    fn classify_treats_none_as_unknown_not_ok() {
        assert_eq!(classify(None, 100), LagStatus::Unknown);
        assert_eq!(classify(Some(101), 100), LagStatus::OverBudget);
        assert_eq!(classify(Some(100), 100), LagStatus::Ok, "at budget is ok");
        assert_eq!(classify(Some(0), 100), LagStatus::Ok);
    }
}
