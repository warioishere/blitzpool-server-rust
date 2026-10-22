// SPDX-License-Identifier: AGPL-3.0-or-later

//! A Team's admin hears of a new join request: the API stores the request and
//! publishes it to `group:join-request` ([`StreamJoinRequestNotifier`]), the
//! notify process hands it to the dispatcher ([`spawn`]). Notify-only, so an
//! at-least-once redelivery costs at most one duplicate notice.

use std::sync::Arc;

use async_trait::async_trait;
use bp_common::AddressId;
use bp_group_mgmt_engine::{JoinRequestCreated, JoinRequestNotifier};
use bp_notifications::dispatcher::{JoinRequestNotice, NotificationDispatcher};
use bp_share_stream::{
    ConsumerLoopConfig, EnsureMode, StreamConsumer, StreamConsumerHandle, StreamEntryHandler,
    StreamProducer, GROUP_JOIN_REQUEST_STREAM_KEY,
};
use redis::aio::ConnectionManager;
use tracing::warn;

const BATCH: usize = 16;
const GROUP: &str = "group-join-request";
const CONSUMER: &str = "c1";

/// Wire shape on `group:join-request`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct JoinRequestStreamEvent {
    pub group_name: String,
    pub admin_address: String,
    pub requester_address: String,
}

impl From<&JoinRequestCreated> for JoinRequestStreamEvent {
    fn from(e: &JoinRequestCreated) -> Self {
        Self {
            group_name: e.group_name.clone(),
            admin_address: e.admin_address.as_str().to_string(),
            requester_address: e.requester_address.as_str().to_string(),
        }
    }
}

impl JoinRequestStreamEvent {
    /// `None` if an address does not parse; the API validated both, but the
    /// consumer must not panic on bad data.
    pub(crate) fn into_notice(self) -> Option<JoinRequestNotice> {
        match (
            AddressId::new(self.admin_address.clone()),
            AddressId::new(self.requester_address.clone()),
        ) {
            (Ok(admin_address), Ok(requester_address)) => Some(JoinRequestNotice {
                admin_address,
                requester_address,
                group_name: self.group_name,
            }),
            _ => {
                warn!(
                    admin = self.admin_address,
                    requester = self.requester_address,
                    "join-request: stream event has an unparseable address — dropping"
                );
                None
            }
        }
    }
}

/// Publishes each stored join request onto `group:join-request`. Wired into
/// the join-request service on the API process.
pub(crate) struct StreamJoinRequestNotifier {
    producer: StreamProducer<JoinRequestStreamEvent>,
}

impl StreamJoinRequestNotifier {
    pub(crate) fn new(redis: ConnectionManager) -> Self {
        Self {
            producer: StreamProducer::new(redis, GROUP_JOIN_REQUEST_STREAM_KEY),
        }
    }
}

#[async_trait]
impl JoinRequestNotifier for StreamJoinRequestNotifier {
    async fn join_request_created(&self, event: JoinRequestCreated) {
        // The request is stored either way; a lost publish only costs the
        // admin the notice, who still sees the request in the admin panel.
        if let Err(err) = self
            .producer
            .publish(&JoinRequestStreamEvent::from(&event))
            .await
        {
            warn!(%err, group_id = %event.group_id, "join-request: publish failed");
        }
    }
}

struct JoinRequestHandler {
    dispatcher: Arc<NotificationDispatcher>,
}

#[async_trait]
impl StreamEntryHandler<JoinRequestStreamEvent> for JoinRequestHandler {
    async fn handle(&self, value: JoinRequestStreamEvent) {
        if let Some(notice) = value.into_notice() {
            self.dispatcher.notify_join_request(&notice).await;
        }
    }
}

/// Tail-start: a fresh group must not replay requests that are already old.
pub(crate) fn spawn(
    redis: ConnectionManager,
    dispatcher: Arc<NotificationDispatcher>,
) -> StreamConsumerHandle {
    let consumer: StreamConsumer<JoinRequestStreamEvent> =
        StreamConsumer::new(redis, GROUP_JOIN_REQUEST_STREAM_KEY, GROUP, CONSUMER);
    consumer.spawn(
        EnsureMode::FromTail,
        ConsumerLoopConfig::new(BATCH, "group-join-request"),
        JoinRequestHandler { dispatcher },
    )
}

#[cfg(test)]
mod tests {
    use bp_test_support::{connect_redis_in_range_or_skip, redis_db};
    use uuid::Uuid;

    use super::*;

    const ADMIN: &str = "bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
    const REQUESTER: &str = "bcrt1qmodeunittestaddressxxxxxxxxxxxxxxxxxx";

    /// What the API publishes reaches the notify side as the same notice.
    #[tokio::test]
    async fn a_published_join_request_reaches_the_consumer_as_a_notice() {
        let Some(redis) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 31).await else {
            eprintln!("redis unreachable — skipping join-request round-trip test");
            return;
        };
        let consumer: StreamConsumer<JoinRequestStreamEvent> = StreamConsumer::new(
            redis.clone(),
            GROUP_JOIN_REQUEST_STREAM_KEY,
            GROUP,
            CONSUMER,
        );
        consumer.ensure_group().await.expect("ensure_group");

        StreamJoinRequestNotifier::new(redis)
            .join_request_created(JoinRequestCreated {
                group_id: Uuid::new_v4(),
                group_name: "PoolPals".to_string(),
                admin_address: AddressId::new(ADMIN).unwrap(),
                requester_address: AddressId::new(REQUESTER).unwrap(),
            })
            .await;

        let mut got = Vec::new();
        for _ in 0..5 {
            got.extend(consumer.read_new(16, 500).await.expect("read_new"));
            if !got.is_empty() {
                break;
            }
        }
        assert_eq!(got.len(), 1, "the published request is delivered");
        let notice = got[0]
            .value
            .clone()
            .into_notice()
            .expect("the notice reconstructs");
        assert_eq!(notice.admin_address.as_str(), ADMIN);
        assert_eq!(notice.requester_address.as_str(), REQUESTER);
        assert_eq!(notice.group_name, "PoolPals");
    }
}
