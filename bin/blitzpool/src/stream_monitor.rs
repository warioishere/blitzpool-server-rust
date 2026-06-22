// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core-side consumer-lag monitor for the Core→Satellite streams.
//!
//! The Core is always-on, so it's the right place to notice the
//! restartable Satellite falling behind (or being down): the Core keeps
//! producing, the stream grows, and each consumer group's `lag` (entries
//! added but not yet delivered to that group) climbs. When the lag crosses
//! a budget we warn — an operator's cue to act before the stream's `MAXLEN`
//! trims oldest entries (a fairness delle). Runs only in `core` mode; the
//! monolith has no streams and the satellite can't reliably self-monitor
//! when it's the thing falling behind.

use std::time::Duration;

use redis::aio::ConnectionManager;
use redis::streams::StreamInfoGroupsReply;
use redis::AsyncCommands;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// How often to sample the streams. New entries arrive at the share rate;
/// a 30s sample is plenty to catch a sustained backlog without polling churn.
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Per-group lag (undelivered entries) for one stream at one sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LagReport {
    pub(crate) stream: String,
    pub(crate) group: String,
    pub(crate) lag: usize,
    pub(crate) pending: usize,
}

/// Live monitor task + its cancel token.
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

/// Spawn the lag monitor over the given stream keys, warning when any
/// group's lag exceeds `lag_budget`.
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
                        if report.lag > lag_budget {
                            warn!(
                                stream = %report.stream,
                                group = %report.group,
                                lag = report.lag,
                                pending = report.pending,
                                lag_budget,
                                "stream-monitor: consumer lag over budget — Satellite is behind or down"
                            );
                        } else {
                            debug!(
                                stream = %report.stream,
                                group = %report.group,
                                lag = report.lag,
                                "stream-monitor: lag ok"
                            );
                        }
                    }
                }
            }
        }
        info!("stream-monitor: stopped");
    });
    StreamMonitorHandle { task, cancel }
}

/// Sample every consumer group's lag across the given streams. A stream
/// with no entries / no groups yet (`XINFO GROUPS` errors with no-such-key,
/// or returns no groups) simply contributes nothing this round.
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
                // `lag` is `None` if Redis can't compute it (e.g. the stream
                // was XADD-trimmed below the group's last-read id); treat that
                // as 0 here — the monitor is best-effort observability.
                lag: g.lag.unwrap_or(0),
                pending: g.pending,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REDIS_URL: &str = "redis://127.0.0.1:16379";

    async fn connect_redis_or_skip(db: u8) -> Option<ConnectionManager> {
        let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_URL.to_string());
        let client = redis::Client::open(format!("{base}/{db}")).ok()?;
        let mut conn = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            ConnectionManager::new(client),
        )
        .await
        {
            Ok(Ok(c)) => c,
            _ => {
                eprintln!("redis unreachable — skipping stream-monitor test");
                return None;
            }
        };
        if redis::cmd("FLUSHDB")
            .query_async::<()>(&mut conn)
            .await
            .is_err()
        {
            return None;
        }
        Some(conn)
    }

    #[tokio::test]
    async fn collect_lag_reports_undelivered_entries() {
        let Some(conn) = connect_redis_or_skip(5).await else {
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
        assert_eq!(reports[0].lag, 4, "all 4 entries are undelivered");
    }
}
