// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core-side consumer-lag monitor for the Core→Satellite streams.
//!
//! The Core is always-on, so it's the right place to notice the
//! restartable Satellite falling behind (or being down): the Core keeps
//! producing, the stream grows, and each consumer group's `lag` (entries
//! added but not yet delivered to that group) climbs. When the lag crosses
//! a budget we warn — an operator's cue to act before the stream's `MAXLEN`
//! trims oldest entries (a fairness delle). Runs only on the producing front;
//! the satellite can't reliably self-monitor when it's the thing falling
//! behind.

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

/// Per-group lag (undelivered entries) for one stream at one sample. `lag` is
/// `None` when Redis can't compute it — which happens exactly when the stream
/// was trimmed below the group's last-read id (the probable-entry-loss case),
/// so `None` is treated as alarming, not as `0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LagReport {
    pub(crate) stream: String,
    pub(crate) group: String,
    pub(crate) lag: Option<usize>,
    pub(crate) pending: usize,
}

/// Classification of one lag sample against the budget. Split out as a pure
/// function so the "is this alarming?" decision is unit-testable without Redis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LagStatus {
    /// Lag known and within budget.
    Ok,
    /// Lag known and over budget — the satellite is behind or down.
    OverBudget,
    /// Lag unavailable — the stream was trimmed below the group offset, which
    /// means entries were almost certainly lost. Alarming precisely because the
    /// plain lag number would read `0` here.
    Unknown,
}

/// Classify a lag sample. `None` → [`LagStatus::Unknown`] (never silently `0`).
pub(crate) fn classify(lag: Option<usize>, budget: usize) -> LagStatus {
    match lag {
        None => LagStatus::Unknown,
        Some(l) if l > budget => LagStatus::OverBudget,
        Some(_) => LagStatus::Ok,
    }
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
                        // Export before classifying: the gauges must reflect
                        // every sample, and `lag = None` drops the
                        // `_computable` gauge to 0 (the alertable blind spot).
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
                // `lag` is `None` if Redis can't compute it (the stream was
                // XADD-trimmed below the group's last-read id). Kept as-is
                // (NOT coerced to 0) so the monitor can flag it as the
                // entry-loss signal it is — see [`classify`].
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
        assert_eq!(reports[0].lag, Some(4), "all 4 entries are undelivered");
    }

    /// The alarming case is `lag = None` (Redis can't compute lag → stream
    /// trimmed below the group offset → probable entry loss). It must NOT be
    /// treated as `0`/ok — the whole point of the ② hardening.
    #[test]
    fn classify_treats_none_as_unknown_not_ok() {
        assert_eq!(classify(None, 100), LagStatus::Unknown);
        assert_eq!(classify(Some(101), 100), LagStatus::OverBudget);
        assert_eq!(classify(Some(100), 100), LagStatus::Ok, "at budget is ok");
        assert_eq!(classify(Some(0), 100), LagStatus::Ok);
    }
}
