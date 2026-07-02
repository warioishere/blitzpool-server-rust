// SPDX-License-Identifier: AGPL-3.0-or-later

//! Satellite-side rejected-share stream consumer.
//!
//! In `satellite` mode the Core publishes each rejected share (group_id already
//! stamped from the mode gate) onto the rejected stream. This consumer drains it
//! and runs the **same** [`SharedRejectedShareSink`] impls the engines expose —
//! the Group-Solo + stats reject counters. The share is fully Core-stamped, so
//! the sinks need no mode gate.
//!
//! Reject counters are pool-fairness/observability stats, not money; the
//! transport is at-least-once and the counters tolerate the rare double-count a
//! crash-before-ack redelivery would cause. The loop skeleton (ensure → pending
//! backlog → drain new + ack) lives in [`bp_share_stream::StreamConsumer::run`];
//! this file only supplies the per-entry sink fan-out.

use std::sync::Arc;

use async_trait::async_trait;
use bp_share_hook::{SharedRejectedShareOwned, SharedRejectedShareSink};
use bp_share_stream::{
    ConsumerLoopConfig, EnsureMode, StreamConsumer, StreamConsumerHandle, StreamEntryHandler,
    REJECTED_STREAM_KEY,
};
use redis::aio::ConnectionManager;

const BATCH: usize = 256;
const GROUP: &str = "satellite";
const CONSUMER: &str = "c1";

/// Fans each rejected share out to every reject sink.
struct RejectedHandler {
    sinks: Vec<Arc<dyn SharedRejectedShareSink>>,
}

#[async_trait]
impl StreamEntryHandler<SharedRejectedShareOwned> for RejectedHandler {
    async fn handle(&self, value: SharedRejectedShareOwned) {
        let view = value.as_view();
        for sink in &self.sinks {
            sink.record_rejected(view).await;
        }
    }
}

/// Spawn the rejected-share stream consumer. Owns the reject sinks + a Redis
/// handle. `0`-start: the counters tolerate a replayed history entry.
pub(crate) fn spawn(
    redis: ConnectionManager,
    sinks: Vec<Arc<dyn SharedRejectedShareSink>>,
) -> StreamConsumerHandle {
    let consumer: StreamConsumer<SharedRejectedShareOwned> =
        StreamConsumer::new(redis, REJECTED_STREAM_KEY, GROUP, CONSUMER);
    consumer.spawn(
        EnsureMode::FromZero,
        ConsumerLoopConfig::new(BATCH, "rejected"),
        RejectedHandler { sinks },
    )
}
