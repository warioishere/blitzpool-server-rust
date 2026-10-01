// SPDX-License-Identifier: AGPL-3.0-or-later

//! Satellite-side rejected-share stream consumer, running the same
//! [`SharedRejectedShareSink`] impls the engines expose; the share arrives
//! Core-stamped, so no mode gate is needed. Reject counters are not money, so
//! the rare at-least-once double-count is tolerated.

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

/// `0`-start: the counters tolerate a replayed history entry.
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
