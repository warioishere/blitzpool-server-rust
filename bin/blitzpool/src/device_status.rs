// SPDX-License-Identifier: AGPL-3.0-or-later

//! [`bp_share_hook::DeviceStatusSink`] implementations, fired by SV1 and SV2:
//!
//! - [`DispatcherDeviceStatusSink`] — feeds the in-process
//!   [`crate::device_status_gate::Gate`], which debounces and hands the
//!   confirmed message to the `NotificationDispatcher`. For a process that
//!   holds the dispatcher (a front co-located with the `notify` role).
//! - [`ProducingDeviceStatusSink`] — `XADD`s the event to the Core→Satellite
//!   `device:status` stream for a split front without a dispatcher; the
//!   Satellite drains it into its gate. It publishes unfiltered: the front
//!   holds no subscription state, and device events fire per
//!   connect/disconnect, not per share.
//!
//! `is_returning` is NOT resolved here: only the gate knows whether the
//! subscriber was told the device was gone, and it sets the flag on the
//! online path, the only one that reads it.

use std::sync::Arc;

use async_trait::async_trait;
use bp_common::AddressId;
use bp_notifications::dispatcher::DeviceStatusEvent;
use bp_share_hook::DeviceStatusSink;
use bp_share_stream::{StreamProducer, DEVICE_STATUS_STREAM_KEY};
use chrono::{TimeZone, Utc};
use redis::aio::ConnectionManager;
use tracing::warn;

/// Wire form of a [`DeviceStatusEvent`] for the Core→Satellite `device:status`
/// stream. Plain serde types; the bin owns the wire format, like
/// `BlockFoundEvent`. `is_returning` is part of the wire shape but always
/// `false`: the receiving gate sets it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct DeviceStatusStreamEvent {
    pub address: String,
    pub worker_name: Option<String>,
    pub user_agent: Option<String>,
    pub is_online: bool,
    pub is_returning: bool,
    pub timestamp_ms: i64,
}

impl From<&DeviceStatusEvent> for DeviceStatusStreamEvent {
    fn from(e: &DeviceStatusEvent) -> Self {
        Self {
            address: e.address.as_str().to_string(),
            worker_name: e.worker_name.clone(),
            user_agent: e.user_agent.clone(),
            is_online: e.is_online,
            is_returning: e.is_returning,
            timestamp_ms: e.timestamp.timestamp_millis(),
        }
    }
}

impl DeviceStatusStreamEvent {
    /// Reconstruct the dispatcher event on the Satellite. `None` if the
    /// address does not parse; the Core validated it, but the consumer must
    /// not panic on bad data.
    pub(crate) fn into_event(self) -> Option<DeviceStatusEvent> {
        let address = match AddressId::new(self.address.clone()) {
            Ok(a) => a,
            Err(err) => {
                warn!(%err, address = self.address, "device-status: stream event has unparseable address — dropping");
                return None;
            }
        };
        let timestamp = match Utc.timestamp_millis_opt(self.timestamp_ms).single() {
            Some(t) => t,
            None => Utc::now(),
        };
        Some(DeviceStatusEvent {
            address,
            worker_name: self.worker_name,
            user_agent: self.user_agent,
            is_online: self.is_online,
            is_returning: self.is_returning,
            timestamp,
        })
    }
}

/// Build the [`DeviceStatusEvent`] from the raw Stratum hook fields, for
/// both sinks. `None` (event dropped) on an invalid address.
/// `is_returning` is left `false`; the gate answers it (see module docs).
fn build_event(
    address: &str,
    worker: &str,
    user_agent: Option<&str>,
    is_online: bool,
) -> Option<DeviceStatusEvent> {
    let address_id = match AddressId::new(address.to_string()) {
        Ok(a) => a,
        Err(err) => {
            warn!(
                %err,
                address,
                is_online,
                "device-status: invalid AddressId shape — dropping event"
            );
            return None;
        }
    };
    Some(DeviceStatusEvent {
        address: address_id,
        worker_name: (!worker.is_empty()).then(|| worker.to_string()),
        user_agent: user_agent
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        is_online,
        is_returning: false,
        timestamp: Utc::now(),
    })
}

/// The device-status sink for both protocols. With an in-process dispatcher
/// events go straight to its gate; without one they go to the
/// `device:status` stream for the Satellite. No `gate` means "no co-located
/// dispatcher", not "notifications off". One instance serves both
/// protocols, so they cannot be wired to different destinations.
pub(crate) fn stratum_sinks(
    gate: Option<(
        Arc<crate::device_status_gate::Gate>,
        crate::device_status_gate::SubscribedAddresses,
    )>,
    redis: ConnectionManager,
) -> Arc<dyn DeviceStatusSink> {
    match gate {
        Some((gate, subscribers)) => Arc::new(DispatcherDeviceStatusSink::new(gate, subscribers)),
        None => Arc::new(ProducingDeviceStatusSink::new(redis)),
    }
}

/// Feeds both SV1 + SV2 device-status events into the shared
/// [`Gate`](crate::device_status_gate::Gate). Cheap to clone
/// (`Arc`-internal).
///
/// Nothing is sent here: the gate's sweeper decides when a transition is
/// real, so a flapping connection does not produce one push per TCP event.
#[derive(Clone)]
pub(crate) struct DispatcherDeviceStatusSink {
    gate: Arc<crate::device_status_gate::Gate>,
    /// Addresses with a device-status subscriber; other events are dropped
    /// before the gate allocates any state.
    subscribers: crate::device_status_gate::SubscribedAddresses,
}

impl DispatcherDeviceStatusSink {
    pub(crate) fn new(
        gate: Arc<crate::device_status_gate::Gate>,
        subscribers: crate::device_status_gate::SubscribedAddresses,
    ) -> Self {
        Self { gate, subscribers }
    }

    fn forward(&self, address: &str, worker: &str, user_agent: Option<&str>, is_online: bool) {
        if !self.subscribers.contains(address) {
            return;
        }
        if let Some(event) = build_event(address, worker, user_agent, is_online) {
            self.gate.observe(&event);
        }
    }
}

#[async_trait]
impl DeviceStatusSink for DispatcherDeviceStatusSink {
    async fn on_device_event(
        &self,
        address: &str,
        worker: &str,
        _session_id: &str,
        user_agent: Option<&str>,
        is_online: bool,
    ) {
        self.forward(address, worker, user_agent, is_online);
    }
}

/// Publishes SV1 + SV2 device-status events to the Core→Satellite
/// `device:status` stream for a front without a dispatcher; the Satellite's
/// [`crate::device_status_consumer`] drains it.
#[derive(Clone)]
pub(crate) struct ProducingDeviceStatusSink {
    producer: StreamProducer<DeviceStatusStreamEvent>,
}

impl ProducingDeviceStatusSink {
    pub(crate) fn new(redis: ConnectionManager) -> Self {
        Self {
            producer: StreamProducer::new(redis, DEVICE_STATUS_STREAM_KEY),
        }
    }

    async fn forward(
        &self,
        address: &str,
        worker: &str,
        user_agent: Option<&str>,
        is_online: bool,
    ) {
        let Some(event) = build_event(address, worker, user_agent, is_online) else {
            return;
        };
        let wire = DeviceStatusStreamEvent::from(&event);
        if let Err(err) = self.producer.publish(&wire).await {
            // Best-effort: a failure costs one push, not money, and must never
            // fail the Stratum connection.
            warn!(%err, address, is_online, "device-status: stream publish failed — event dropped");
        }
    }
}

#[async_trait]
impl DeviceStatusSink for ProducingDeviceStatusSink {
    async fn on_device_event(
        &self,
        address: &str,
        worker: &str,
        _session_id: &str,
        user_agent: Option<&str>,
        is_online: bool,
    ) {
        self.forward(address, worker, user_agent, is_online).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> DeviceStatusEvent {
        DeviceStatusEvent {
            address: AddressId::new("bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l").unwrap(),
            worker_name: Some("rig1".to_string()),
            user_agent: Some("cpuminer/2.5".to_string()),
            is_online: true,
            is_returning: true,
            timestamp: Utc
                .timestamp_millis_opt(1_700_000_000_123)
                .single()
                .unwrap(),
        }
    }

    /// The DTO is what crosses the Core→Satellite boundary, so its serde
    /// round-trip + reconstruction must preserve every rendered field.
    #[test]
    fn wire_round_trip_preserves_fields() {
        let ev = sample_event();
        let wire = DeviceStatusStreamEvent::from(&ev);
        let json = serde_json::to_string(&wire).expect("serialize");
        let back: DeviceStatusStreamEvent = serde_json::from_str(&json).expect("deserialize");
        let rebuilt = back.into_event().expect("valid address reconstructs");
        assert_eq!(rebuilt.address.as_str(), ev.address.as_str());
        assert_eq!(rebuilt.worker_name, ev.worker_name);
        assert_eq!(rebuilt.user_agent, ev.user_agent);
        assert_eq!(rebuilt.is_online, ev.is_online);
        assert_eq!(rebuilt.is_returning, ev.is_returning);
        assert_eq!(
            rebuilt.timestamp.timestamp_millis(),
            ev.timestamp.timestamp_millis()
        );
    }

    /// A corrupt/empty address on the wire must drop the event, not panic the
    /// consumer task.
    #[test]
    fn into_event_rejects_unparseable_address() {
        let wire = DeviceStatusStreamEvent {
            address: String::new(),
            worker_name: None,
            user_agent: None,
            is_online: false,
            is_returning: false,
            timestamp_ms: 0,
        };
        assert!(wire.into_event().is_none());
    }
}
