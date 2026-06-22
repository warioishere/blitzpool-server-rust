// SPDX-License-Identifier: AGPL-3.0-or-later

//! Satellite-side device-status stream consumer.
//!
//! Device-status events (miner online/offline) originate on the Stratum
//! **front**, but the `NotificationDispatcher` lives on the Satellite. A split
//! front therefore publishes each event to the `device:status` stream (see
//! [`crate::device_status::ProducingDeviceStatusSink`]); this task drains that
//! stream and calls [`NotificationDispatcher::notify_device_status`] — the same
//! fan-out the monolith runs in-process.
//!
//! Notify-only (no ledger), so at-least-once delivery is harmless: a redelivery
//! after a crash-before-`XACK` just re-sends one online/offline push, which is
//! cosmetic. Mirrors [`crate::block_found_consumer`].

use std::sync::Arc;
use std::time::Duration;

use bp_notifications::dispatcher::NotificationDispatcher;
use bp_share_stream::{StreamConsumer, DEVICE_STATUS_STREAM_KEY};
use redis::aio::ConnectionManager;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::device_status::DeviceStatusStreamEvent;

const BATCH: usize = 64;
const BLOCK_MS: usize = 1000;
const ERROR_BACKOFF: Duration = Duration::from_millis(500);
const GROUP: &str = "device-status";
const CONSUMER: &str = "c1";

/// Live consumer task + its cancel token.
pub(crate) struct DeviceStatusConsumerHandle {
    task: JoinHandle<()>,
    cancel: CancellationToken,
}

impl DeviceStatusConsumerHandle {
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        if let Err(err) = self.task.await {
            warn!(%err, "device-status-consumer: task join failed");
        }
    }
}

/// Spawn the device-status stream consumer. Owns the dispatcher + a Redis
/// handle.
pub(crate) fn spawn(
    redis: ConnectionManager,
    dispatcher: Arc<NotificationDispatcher>,
) -> DeviceStatusConsumerHandle {
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        let consumer: StreamConsumer<DeviceStatusStreamEvent> =
            StreamConsumer::new(redis, DEVICE_STATUS_STREAM_KEY, GROUP, CONSUMER);
        // Tail-start ($): notifications aren't idempotent, so a freshly-created
        // group must not replay history (it would re-fire every buffered
        // online/offline event). Existing groups keep their offset.
        if let Err(err) = consumer.ensure_group_at_tail().await {
            warn!(%err, "device-status-consumer: ensure_group failed; task not started");
            return;
        }

        // Resume: replay the delivered-but-unacked backlog before new events.
        loop {
            match consumer.read_pending(BATCH).await {
                Ok(batch) if batch.is_empty() => break,
                Ok(batch) => {
                    fire_and_ack(&consumer, &dispatcher, batch, "pending").await;
                }
                Err(err) => {
                    warn!(%err, "device-status-consumer: read_pending failed; continuing");
                    break;
                }
            }
        }

        info!("device-status-consumer: live");
        loop {
            tokio::select! {
                biased;
                _ = task_cancel.cancelled() => break,
                result = consumer.read_new(BATCH, BLOCK_MS) => match result {
                    Ok(batch) => {
                        fire_and_ack(&consumer, &dispatcher, batch, "new").await;
                    }
                    Err(err) => {
                        warn!(%err, "device-status-consumer: read_new failed; backing off");
                        tokio::time::sleep(ERROR_BACKOFF).await;
                    }
                },
            }
        }
        info!("device-status-consumer: stopped");
    });
    DeviceStatusConsumerHandle { task, cancel }
}

/// Fan each event out via the dispatcher, then `XACK` the batch. Acking after
/// the notify is safe: a redelivery (crash before ack) just re-sends a push.
async fn fire_and_ack(
    consumer: &StreamConsumer<DeviceStatusStreamEvent>,
    dispatcher: &Arc<NotificationDispatcher>,
    batch: Vec<bp_share_stream::Consumed<DeviceStatusStreamEvent>>,
    kind: &str,
) {
    if batch.is_empty() {
        return;
    }
    let mut ids = Vec::with_capacity(batch.len());
    for entry in batch {
        if let Some(event) = entry.value.into_event() {
            dispatcher.notify_device_status(&event).await;
        }
        ids.push(entry.id);
    }
    match consumer.ack(&ids).await {
        Ok(n) => info!(n, kind, "device-status-consumer: fired + acked"),
        Err(err) => warn!(%err, kind, "device-status-consumer: ack failed (will redeliver)"),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bp_share_stream::{StreamConsumer, DEVICE_STATUS_STREAM_KEY};
    use bp_stratum_v1::DeviceStatusSink;
    use redis::aio::ConnectionManager;
    use sqlx::postgres::PgPoolOptions;
    use sqlx::PgPool;

    use crate::device_status::{DeviceStatusStreamEvent, ProducingDeviceStatusSink};

    const REDIS_URL: &str = "redis://127.0.0.1:16379";
    const PG_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";
    const ADDR: &str = "bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

    async fn connect_redis_or_skip(db: u8) -> Option<ConnectionManager> {
        let client = redis::Client::open(format!("{REDIS_URL}/{db}")).ok()?;
        let mut conn = tokio::time::timeout(Duration::from_secs(2), ConnectionManager::new(client))
            .await
            .ok()?
            .ok()?;
        let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await.ok()?;
        Some(conn)
    }

    async fn connect_pg_or_skip() -> Option<PgPool> {
        tokio::time::timeout(
            Duration::from_secs(2),
            PgPoolOptions::new().max_connections(2).connect(PG_URL),
        )
        .await
        .ok()?
        .ok()
    }

    /// End-to-end over real Redis + PG: the split front's producing sink
    /// publishes online + offline events, and a consumer drains them back with
    /// the wire format intact and acks them. This exercises the exact produce →
    /// XREADGROUP → reconstruct → XACK path that [`spawn`] runs (its loop
    /// mirrors `block_found_consumer`, covered by `regtest_split_e2e`).
    #[tokio::test]
    async fn producing_sink_events_round_trip_and_ack() {
        let Some(redis) = connect_redis_or_skip(9).await else {
            eprintln!("redis unreachable — skipping device-status round-trip test");
            return;
        };
        let Some(pg) = connect_pg_or_skip().await else {
            eprintln!("pg unreachable — skipping device-status round-trip test");
            return;
        };

        // Split front (no dispatcher) → publishes to DEVICE_STATUS_STREAM_KEY.
        let sink = ProducingDeviceStatusSink::new(redis.clone(), pg);
        sink.on_device_event(ADDR, "rig1", "sid-online", Some("cpuminer/2.5"), true)
            .await;
        sink.on_device_event(ADDR, "rig1", "sid-offline", None, false)
            .await;

        let consumer: StreamConsumer<DeviceStatusStreamEvent> =
            StreamConsumer::new(redis, DEVICE_STATUS_STREAM_KEY, "device-status", "c1");
        consumer.ensure_group().await.expect("ensure_group");

        let mut got = Vec::new();
        for _ in 0..5 {
            let batch = consumer.read_new(16, 500).await.expect("read_new");
            got.extend(batch);
            if got.len() >= 2 {
                break;
            }
        }
        assert_eq!(got.len(), 2, "both device-status events delivered");

        let online = got[0]
            .value
            .clone()
            .into_event()
            .expect("online event reconstructs");
        assert_eq!(online.address.as_str(), ADDR);
        assert_eq!(online.worker_name.as_deref(), Some("rig1"));
        assert_eq!(online.user_agent.as_deref(), Some("cpuminer/2.5"));
        assert!(online.is_online);

        let offline = got[1]
            .value
            .clone()
            .into_event()
            .expect("offline event reconstructs");
        assert!(!offline.is_online);
        assert!(!offline.is_returning, "offline never marks returning");
        assert_eq!(offline.user_agent, None);

        let ids: Vec<String> = got.iter().map(|e| e.id.clone()).collect();
        let acked = consumer.ack(&ids).await.expect("ack");
        assert_eq!(acked, 2, "both entries acked");
    }
}
