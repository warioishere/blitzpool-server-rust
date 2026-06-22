// SPDX-License-Identifier: AGPL-3.0-or-later

//! Satellite-side rejected-share stream consumer.
//!
//! In `satellite` mode the Core publishes each rejected share (group_id
//! already stamped from the mode gate) onto the rejected stream. This task
//! drains it and runs the **same** [`SharedRejectedShareSink`] impls the
//! monolith runs in-process — the Group-Solo + stats reject counters. The
//! share is fully Core-stamped, so the sinks need no mode gate.
//!
//! Reject counters are pool-fairness/observability stats, not money; the
//! transport is at-least-once and the counters tolerate the rare double-
//! count a crash-before-ack redelivery would cause, so a single consumer is
//! enough.

use std::sync::Arc;
use std::time::Duration;

use bp_share_hook::{SharedRejectedShareOwned, SharedRejectedShareSink};
use bp_share_stream::{Consumed, StreamConsumer, REJECTED_STREAM_KEY};
use redis::aio::ConnectionManager;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

const BATCH: usize = 256;
const BLOCK_MS: usize = 1000;
const ERROR_BACKOFF: Duration = Duration::from_millis(500);
const GROUP: &str = "satellite";
const CONSUMER: &str = "c1";

/// Live consumer task + its cancel token.
pub(crate) struct RejectedConsumerHandle {
    task: JoinHandle<()>,
    cancel: CancellationToken,
}

impl RejectedConsumerHandle {
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        if let Err(err) = self.task.await {
            warn!(%err, "rejected-consumer: task join failed");
        }
    }
}

/// Spawn the rejected-share stream consumer. Owns the reject sinks + a Redis
/// handle.
pub(crate) fn spawn(
    redis: ConnectionManager,
    sinks: Vec<Arc<dyn SharedRejectedShareSink>>,
) -> RejectedConsumerHandle {
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        let consumer: StreamConsumer<SharedRejectedShareOwned> =
            StreamConsumer::new(redis, REJECTED_STREAM_KEY, GROUP, CONSUMER);
        if let Err(err) = consumer.ensure_group().await {
            warn!(%err, "rejected-consumer: ensure_group failed; task not started");
            return;
        }

        // Resume: replay the delivered-but-unacked backlog before new entries.
        loop {
            match consumer.read_pending(BATCH).await {
                Ok(batch) if batch.is_empty() => break,
                Ok(batch) => dispatch_and_ack(&consumer, &sinks, batch, "pending").await,
                Err(err) => {
                    warn!(%err, "rejected-consumer: read_pending failed; continuing");
                    break;
                }
            }
        }

        info!("rejected-consumer: live");
        loop {
            tokio::select! {
                biased;
                _ = task_cancel.cancelled() => break,
                result = consumer.read_new(BATCH, BLOCK_MS) => match result {
                    Ok(batch) => dispatch_and_ack(&consumer, &sinks, batch, "new").await,
                    Err(err) => {
                        warn!(%err, "rejected-consumer: read_new failed; backing off");
                        tokio::time::sleep(ERROR_BACKOFF).await;
                    }
                },
            }
        }
        info!("rejected-consumer: stopped");
    });
    RejectedConsumerHandle { task, cancel }
}

/// Fan each rejected share out to every sink, then `XACK` the batch.
async fn dispatch_and_ack(
    consumer: &StreamConsumer<SharedRejectedShareOwned>,
    sinks: &[Arc<dyn SharedRejectedShareSink>],
    batch: Vec<Consumed<SharedRejectedShareOwned>>,
    kind: &str,
) {
    if batch.is_empty() {
        return;
    }
    let mut ids = Vec::with_capacity(batch.len());
    for entry in &batch {
        let view = entry.value.as_view();
        for sink in sinks {
            sink.record_rejected(view).await;
        }
        ids.push(entry.id.clone());
    }
    match consumer.ack(&ids).await {
        Ok(n) => info!(n, kind, "rejected-consumer: applied + acked"),
        Err(err) => warn!(%err, kind, "rejected-consumer: ack failed (will redeliver)"),
    }
}
