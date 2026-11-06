// SPDX-License-Identifier: AGPL-3.0-or-later

//! Removes stream entries every consumer group has acknowledged, so Redis
//! keeps only what a consumer still needs plus the `MAXLEN` cap as the
//! outage buffer (see [`bp_share_stream::trim_consumed`]).

use std::time::Duration;

use redis::aio::ConnectionManager;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

pub(crate) const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// The streams large enough to matter: per share, per rejected share, per
/// device change.
pub(crate) const STREAMS: [&str; 3] = [
    bp_share_stream::ACCEPTED_STREAM_KEY,
    bp_share_stream::REJECTED_STREAM_KEY,
    bp_share_stream::DEVICE_STATUS_STREAM_KEY,
];

pub(crate) fn spawn_trim_task(redis: ConnectionManager, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        // The first trim waits one interval, which gives the consumer groups
        // created at boot time to exist before anything is removed.
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        info!(
            interval_secs = interval.as_secs(),
            streams = ?STREAMS,
            "stream-trim: task live (removes entries every group acknowledged)"
        );
        loop {
            tick.tick().await;
            for key in STREAMS {
                // One call removes at most Redis's default limit (10000
                // entries), so repeat until a call finds nothing left.
                let mut total = 0;
                loop {
                    match bp_share_stream::trim_consumed(&redis, key).await {
                        Ok(0) => break,
                        Ok(removed) => total += removed,
                        Err(err) => {
                            warn!(stream = key, %err, "stream-trim: failed; retry next tick");
                            break;
                        }
                    }
                }
                debug!(stream = key, removed = total, "stream-trim: trimmed");
            }
        }
    })
}
