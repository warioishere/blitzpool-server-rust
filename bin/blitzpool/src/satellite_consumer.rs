// SPDX-License-Identifier: AGPL-3.0-or-later

//! Satellite-side accepted-share consumer: drains the Core's stream into the
//! engines' sinks (shares arrive mode-stamped). Two groups so a stall in one
//! never blocks the other's acks: **money** is single-consumer because window
//! order = consume order; delivery is at-least-once, money dedups on `share_id`.

use std::sync::Arc;

use bp_share_hook::SharedAcceptedShareSink;
use bp_share_stream::{
    AcceptedShareFanOut, ConsumerLoopConfig, EnsureMode, StreamConsumer, StreamConsumerHandle,
    ACCEPTED_STREAM_KEY,
};
use redis::aio::ConnectionManager;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::engines::AcceptedSinkSet;

/// Max entries pulled per read.
const BATCH: usize = 256;

const MONEY_GROUP: &str = "money";
const STATS_SESSION_GROUP: &str = "stats-session";
/// Single consumer name per group (the money group MUST stay single-consumer
/// for window ordering; the stats group keeps one for simplicity).
const CONSUMER: &str = "c1";

/// Spawn one consumer task per durability class against the shared accepted
/// stream. Owns clones of every handle it needs (all `Arc`-backed). Returns the
/// shared [`StreamConsumerHandle`] holding both tasks under one cancel token.
pub(crate) fn spawn(
    money_redis: ConnectionManager,
    stats_redis: ConnectionManager,
    sinks: AcceptedSinkSet,
) -> StreamConsumerHandle {
    let cancel = CancellationToken::new();
    // Each group gets its OWN connection: a blocking `XREAD BLOCK` would
    // head-of-line-block the other group on a shared multiplexed connection.
    let money = spawn_group(
        money_redis,
        MONEY_GROUP,
        "accepted-money",
        sinks.money,
        cancel.clone(),
    );
    let stats_session = spawn_group(
        stats_redis,
        STATS_SESSION_GROUP,
        "accepted-stats-session",
        sinks.aux,
        cancel.clone(),
    );
    StreamConsumerHandle::new(vec![money, stats_session], cancel, "accepted")
}

fn spawn_group(
    redis: ConnectionManager,
    group: &'static str,
    label: &'static str,
    sinks: Vec<Arc<dyn SharedAcceptedShareSink>>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    let consumer = StreamConsumer::accepted(redis, ACCEPTED_STREAM_KEY, group, CONSUMER);
    tokio::spawn(consumer.run(
        EnsureMode::FromZero,
        ConsumerLoopConfig::new(BATCH, label),
        cancel,
        AcceptedShareFanOut::new(sinks),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bp_common::MiningMode;
    use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareOwned};
    use bp_share_stream::StreamProducer;
    use bp_test_support::{connect_redis_in_range_or_skip, redis_db};
    use std::time::Duration;
    use tokio::sync::Mutex as AsyncMutex;

    /// Records the `share_id` of every share it receives, in arrival order.
    struct RecordingSink {
        seen: Arc<AsyncMutex<Vec<String>>>,
    }

    #[async_trait]
    impl SharedAcceptedShareSink for RecordingSink {
        async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
            self.seen.lock().await.push(share.share_id.to_string());
        }
    }

    fn sample(share_id: &str) -> SharedAcceptedShareOwned {
        SharedAcceptedShareOwned {
            address: "bc1qfoo".into(),
            worker: "rig1".into(),
            session_id: "sess1".into(),
            effective_difficulty: 1024.0,
            submission_difficulty: 2048.0,
            user_agent: None,
            is_block_candidate: false,
            hash_rate: 1.0,
            channel_count: 1,
            ts_ms: 1_700_000_000_000,
            share_id: share_id.into(),
            mode: MiningMode::Pplns,
            group_id: None,
        }
    }

    async fn wait_until_len(seen: &Arc<AsyncMutex<Vec<String>>>, target: usize) -> bool {
        for _ in 0..50 {
            if seen.lock().await.len() >= target {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    /// Both groups consume every share in order and shut down on cancel.
    #[tokio::test]
    async fn both_groups_consume_all_shares_in_order() {
        let Some(conn) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 7).await else {
            return;
        };

        // Publish three shares before the consumer starts.
        let producer = StreamProducer::new(conn.clone(), ACCEPTED_STREAM_KEY);
        for i in 0..3 {
            producer
                .publish(&sample(&format!("1:{i}")))
                .await
                .expect("publish");
        }

        let money_seen = Arc::new(AsyncMutex::new(Vec::new()));
        let aux_seen = Arc::new(AsyncMutex::new(Vec::new()));
        let sinks = AcceptedSinkSet {
            money: vec![Arc::new(RecordingSink {
                seen: money_seen.clone(),
            })],
            aux: vec![Arc::new(RecordingSink {
                seen: aux_seen.clone(),
            })],
        };

        let handle = spawn(conn.clone(), conn, sinks);

        assert!(
            wait_until_len(&money_seen, 3).await,
            "money group consumed all 3"
        );
        assert!(
            wait_until_len(&aux_seen, 3).await,
            "stats-session group consumed all 3"
        );

        handle.shutdown().await;

        let expected = vec!["1:0".to_string(), "1:1".to_string(), "1:2".to_string()];
        assert_eq!(*money_seen.lock().await, expected, "money order preserved");
        assert_eq!(*aux_seen.lock().await, expected, "aux order preserved");
    }

    /// A delivered-but-unacked backlog is replayed on restart.
    #[tokio::test]
    async fn pending_backlog_is_replayed_on_restart() {
        let Some(conn) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 8).await else {
            return;
        };

        let producer = StreamProducer::new(conn.clone(), ACCEPTED_STREAM_KEY);
        for i in 0..2 {
            producer
                .publish(&sample(&format!("1:{i}")))
                .await
                .expect("publish");
        }

        // Simulate a prior run that read the entries into the money group's
        // PEL but crashed before acking: ensure_group + read_new, no ack.
        let prior =
            StreamConsumer::accepted(conn.clone(), ACCEPTED_STREAM_KEY, MONEY_GROUP, CONSUMER);
        prior.ensure_group().await.expect("ensure_group");
        let delivered = prior.read_new(16, 500).await.expect("read_new");
        assert_eq!(delivered.len(), 2, "two entries delivered, left unacked");

        // Restart: the consumer with the same group+name must replay the
        // pending backlog through its sink before going live.
        let money_seen = Arc::new(AsyncMutex::new(Vec::new()));
        let sinks = AcceptedSinkSet {
            money: vec![Arc::new(RecordingSink {
                seen: money_seen.clone(),
            })],
            aux: Vec::new(),
        };
        let handle = spawn(conn.clone(), conn, sinks);

        assert!(
            wait_until_len(&money_seen, 2).await,
            "pending backlog replayed on restart"
        );
        handle.shutdown().await;
        assert_eq!(
            *money_seen.lock().await,
            vec!["1:0".to_string(), "1:1".to_string()],
        );
    }
}
