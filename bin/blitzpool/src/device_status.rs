// SPDX-License-Identifier: AGPL-3.0-or-later

//! `DeviceStatusSink` implementations — Phase 7.7.
//!
//! Both SV1 (`bp_stratum_v1::DeviceStatusSink`) and SV2
//! (`bp_stratum_v2::hooks::DeviceStatusSink`) define a small fire-on-
//! online/offline trait. The bin builds one of two concrete impls:
//!
//! - [`DispatcherDeviceStatusSink`] — forwards directly to the in-process
//!   `NotificationDispatcher`. Used by any process that holds the dispatcher
//!   (e.g. a front co-located with the `notify` role).
//! - [`ProducingDeviceStatusSink`] — `XADD`s the event to the Core→Satellite
//!   `device:status` stream. Used by a split **front** (Core), which has no
//!   dispatcher; the Satellite drains the stream and fans the event out. This
//!   is the cross-process route, mirroring the block-found stream — without it
//!   a split front would silently drop device-status notifications.
//!
//! The bin-side adapter fills the metadata fields the rendered message uses:
//! `user_agent` (threaded through `on_device_event` from the SV1 subscribe UA /
//! SV2 vendor) and `is_returning` (a `client_entity` lookup — a device that
//! comes back online within the window renders "back online").

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bp_common::AddressId;
use bp_notifications::dispatcher::{DeviceStatusEvent, NotificationDispatcher};
use bp_share_stream::{StreamProducer, DEVICE_STATUS_STREAM_KEY};
use bp_stratum_v1::DeviceStatusSink as Sv1DeviceStatusSink;
use bp_stratum_v2::hooks::DeviceStatusSink as Sv2DeviceStatusSink;
use chrono::{TimeZone, Utc};
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tracing::warn;

/// Sliding window during which a re-connecting device is considered
/// "returning" rather than "first time". Survives pool restarts (the
/// in-memory variant didn't, which made every device read as fresh
/// after a restart).
const RETURNING_WINDOW: Duration = Duration::from_secs(30 * 60);

/// Wire form of a [`DeviceStatusEvent`] for the Core→Satellite `device:status`
/// stream. Plain serde types — the bin owns the wire format, same as
/// `BlockFoundEvent`. The Core stamps `is_returning` (it holds the DB) so the
/// Satellite renders without re-deriving it.
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
    /// Reconstruct the dispatcher event on the Satellite. Returns `None` if the
    /// address no longer parses (shouldn't happen — the Core validated it
    /// before publishing — but the consumer must not panic on bad data).
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

/// Build the [`DeviceStatusEvent`] from the raw Stratum hook fields: parse the
/// address, resolve the `is_returning` flag via a `client_entity` lookup, and
/// assemble the event. Shared by both sink impls. Returns `None` when the
/// address shape is invalid (the event is dropped — nothing to notify).
async fn build_event(
    pool: &PgPool,
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
    // "Returning" = the most-recent client_entity row for this
    // (address, worker) was active within RETURNING_WINDOW. Only
    // meaningful on the online event; offline template ignores it.
    let is_returning = if is_online {
        let cutoff_ms = Utc::now().timestamp_millis()
            - i64::try_from(RETURNING_WINDOW.as_millis()).unwrap_or(i64::MAX);
        match bp_db::find_client_recent_first_seen(pool, address, worker, cutoff_ms).await {
            Ok(seen) => seen.is_some(),
            Err(err) => {
                warn!(
                    %err,
                    address,
                    worker,
                    "device-status: returning-window lookup failed; \
                     defaulting to is_returning=false"
                );
                false
            }
        }
    } else {
        false
    };
    Some(DeviceStatusEvent {
        address: address_id,
        worker_name: (!worker.is_empty()).then(|| worker.to_string()),
        user_agent: user_agent
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        is_online,
        is_returning,
        timestamp: Utc::now(),
    })
}

/// Forwards both SV1 + SV2 device-status events to the shared
/// [`NotificationDispatcher`]. Cheap to clone (`Arc`-internal).
#[derive(Clone)]
pub(crate) struct DispatcherDeviceStatusSink {
    dispatcher: Arc<NotificationDispatcher>,
    /// Pool handle for the `client_entity` `firstSeen`/`updatedAt` lookup
    /// that drives the `is_returning` flag. Best-effort: a DB error logs
    /// at WARN and the event still fires with `is_returning = false`.
    pool: PgPool,
}

impl DispatcherDeviceStatusSink {
    pub(crate) fn new(dispatcher: Arc<NotificationDispatcher>, pool: PgPool) -> Self {
        Self { dispatcher, pool }
    }

    async fn forward(
        &self,
        address: &str,
        worker: &str,
        user_agent: Option<&str>,
        is_online: bool,
    ) {
        if let Some(event) = build_event(&self.pool, address, worker, user_agent, is_online).await {
            self.dispatcher.notify_device_status(&event).await;
        }
    }
}

#[async_trait]
impl Sv1DeviceStatusSink for DispatcherDeviceStatusSink {
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

#[async_trait]
impl Sv2DeviceStatusSink for DispatcherDeviceStatusSink {
    async fn on_device_event(
        &self,
        address: &str,
        worker: &str,
        _session_id_hex: &str,
        user_agent: Option<&str>,
        is_online: bool,
    ) {
        self.forward(address, worker, user_agent, is_online).await;
    }
}

/// Publishes both SV1 + SV2 device-status events to the Core→Satellite
/// `device:status` stream. Used by a split front (Core) that has no in-process
/// dispatcher; the Satellite's [`crate::device_status_consumer`] drains the
/// stream and fans the event out. Cheap to clone (`StreamProducer` + `PgPool`
/// are both `Arc`-internal).
#[derive(Clone)]
pub(crate) struct ProducingDeviceStatusSink {
    producer: StreamProducer<DeviceStatusStreamEvent>,
    /// Same `is_returning` lookup as the dispatcher sink — the Core stamps the
    /// flag so the Satellite needn't re-derive it.
    pool: PgPool,
}

impl ProducingDeviceStatusSink {
    pub(crate) fn new(redis: ConnectionManager, pool: PgPool) -> Self {
        Self {
            producer: StreamProducer::new(redis, DEVICE_STATUS_STREAM_KEY),
            pool,
        }
    }

    async fn forward(
        &self,
        address: &str,
        worker: &str,
        user_agent: Option<&str>,
        is_online: bool,
    ) {
        let Some(event) = build_event(&self.pool, address, worker, user_agent, is_online).await
        else {
            return;
        };
        let wire = DeviceStatusStreamEvent::from(&event);
        if let Err(err) = self.producer.publish(&wire).await {
            // Best-effort like the dispatcher path: a publish failure costs one
            // online/offline push, not money. Log so the operator sees Redis
            // trouble, but never fail the Stratum connection over it.
            warn!(%err, address, is_online, "device-status: stream publish failed — event dropped");
        }
    }
}

#[async_trait]
impl Sv1DeviceStatusSink for ProducingDeviceStatusSink {
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

#[async_trait]
impl Sv2DeviceStatusSink for ProducingDeviceStatusSink {
    async fn on_device_event(
        &self,
        address: &str,
        worker: &str,
        _session_id_hex: &str,
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
