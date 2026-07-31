// SPDX-License-Identifier: AGPL-3.0-or-later

//! Satellite-side device-status stream consumer.
//!
//! Device-status events (miner online/offline) originate on the Stratum
//! **front**, but the `NotificationDispatcher` lives on the Satellite. A split
//! front therefore publishes each event to the `device:status` stream (see
//! [`crate::device_status::ProducingDeviceStatusSink`]); this task drains that
//! stream and feeds each event into the same
//! [`Gate`](crate::device_status_gate::Gate) a dispatcher-holding process
//! feeds directly. The gate's sweeper — not this task — is what sends.
//!
//! Notify-only (no ledger), so at-least-once delivery is harmless: a redelivery
//! after a crash-before-`XACK` just re-sends one online/offline push, which is
//! cosmetic. Tail-start ($) so a first run doesn't re-fire buffered history. The
//! loop skeleton lives in [`bp_share_stream::StreamConsumer::run`]; this file
//! only supplies the per-event dispatcher fan-out.

use std::sync::Arc;

use async_trait::async_trait;
use bp_share_stream::{
    ConsumerLoopConfig, EnsureMode, StreamConsumer, StreamConsumerHandle, StreamEntryHandler,
    DEVICE_STATUS_STREAM_KEY,
};
use redis::aio::ConnectionManager;

use crate::device_status::DeviceStatusStreamEvent;

const BATCH: usize = 64;
const GROUP: &str = "device-status";
const CONSUMER: &str = "c1";

/// Feeds each device-status event into the gate. Events that don't
/// reconstruct into a notify payload (`into_event` → `None`) are dropped.
struct DeviceStatusHandler {
    gate: Arc<crate::device_status_gate::Gate>,
    /// Same subscriber filter the in-process sink applies — a split
    /// front cannot know who is subscribed, so the drop happens here.
    subscribers: crate::device_status_gate::SubscribedAddresses,
}

#[async_trait]
impl StreamEntryHandler<DeviceStatusStreamEvent> for DeviceStatusHandler {
    async fn handle(&self, value: DeviceStatusStreamEvent) {
        if let Some(event) = value.into_event() {
            if !self.subscribers.contains(event.address.as_str()) {
                return;
            }
            self.gate.observe(&event);
        }
    }
}

/// Spawn the device-status stream consumer. Owns the gate + a Redis
/// handle. Tail-start ($): a freshly-created group must not replay history (it
/// would re-fire every buffered online/offline push); existing groups keep
/// their offset.
pub(crate) fn spawn(
    redis: ConnectionManager,
    gate: Arc<crate::device_status_gate::Gate>,
    subscribers: crate::device_status_gate::SubscribedAddresses,
) -> StreamConsumerHandle {
    let consumer: StreamConsumer<DeviceStatusStreamEvent> =
        StreamConsumer::new(redis, DEVICE_STATUS_STREAM_KEY, GROUP, CONSUMER);
    consumer.spawn(
        EnsureMode::FromTail,
        ConsumerLoopConfig::new(BATCH, "device-status"),
        DeviceStatusHandler { gate, subscribers },
    )
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
        // DB 11: every test target in this binary runs as a thread in one
        // process and FLUSHDBs its index on entry, so two sharing an index
        // wipe each other's stream. `redis_backup` already owns 9.
        let Some(redis) = connect_redis_or_skip(11).await else {
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
