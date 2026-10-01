// SPDX-License-Identifier: AGPL-3.0-or-later

//! Satellite-side device-status stream consumer: device events originate on
//! the Stratum front, the dispatcher lives here, so this feeds the stream into
//! the same [`Gate`](crate::device_status_gate::Gate). Notify-only, so an
//! at-least-once redelivery costs at most one duplicate push.

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

struct DeviceStatusHandler {
    gate: Arc<crate::device_status_gate::Gate>,
    /// A split front cannot know who is subscribed, so the filter runs here.
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

/// Tail-start: a fresh group must not replay buffered online/offline pushes.
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
    use bp_test_support::{connect_redis_in_range_or_skip, redis_db};

    use bp_share_hook::DeviceStatusSink;
    use bp_share_stream::{StreamConsumer, DEVICE_STATUS_STREAM_KEY};

    use crate::device_status::{DeviceStatusStreamEvent, ProducingDeviceStatusSink};

    const ADDR: &str = "bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

    /// Producer-sink events round-trip through XREADGROUP intact and are acked.
    #[tokio::test]
    async fn producing_sink_events_round_trip_and_ack() {
        let Some(redis) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 11).await else {
            eprintln!("redis unreachable — skipping device-status round-trip test");
            return;
        };
        let sink = ProducingDeviceStatusSink::new(redis.clone());
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
