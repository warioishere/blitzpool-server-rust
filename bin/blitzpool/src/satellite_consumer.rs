// SPDX-License-Identifier: AGPL-3.0-or-later

//! Satellite-side accepted-share stream consumer.
//!
//! In `satellite` mode the process holds no Stratum listeners; accepted
//! shares arrive over the Redis stream the Core's [`ProducingSink`] writes
//! to. This task drains that stream into the **same**
//! [`SharedAcceptedShareSink`] impls the engines expose — the shares are
//! already `share_id`-/mode-stamped by the Core, so the consumer never
//! touches a mode gate.
//!
//! ## Two consumer groups, by durability class
//!
//! The accepted sinks split into two [`crate::engines::AcceptedSinkSet`]
//! classes, each consumed by its own group so a stall in one never blocks
//! the other's acks:
//!
//! - **money** (`PPLNS` + `Group-Solo` window mutations) — order-sensitive
//!   (window order = consume order) and exactly-once via the per-`share_id`
//!   dedup marker, so a single ordered consumer.
//! - **stats-session** (stats accumulators + session-persistence +
//!   live-mode marker) — order-insensitive.
//!
//! ## Delivery
//!
//! Each group `ensure_group`s, drains any **pending** (delivered-but-unacked)
//! backlog left by a previous run, then loops on **new** entries. The
//! transport is at-least-once: a crash between sink-apply and `XACK`
//! redelivers, and the money sinks dedup on `share_id` so the re-apply is a
//! no-op. See [`bp_share_stream`].

use std::sync::Arc;
use std::time::Duration;

use bp_share_hook::SharedAcceptedShareSink;
use bp_share_stream::{AcceptedShareConsumer, StreamConsumerHandle, ACCEPTED_STREAM_KEY};
use redis::aio::ConnectionManager;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::engines::AcceptedSinkSet;

/// Max entries pulled per `drain_*` call.
const BATCH: usize = 256;
/// How long a `drain_new` blocks waiting for at least one entry before
/// looping back to re-check the cancel signal.
const BLOCK_MS: usize = 1000;
/// Back-off after a transient stream error before retrying.
const ERROR_BACKOFF: Duration = Duration::from_millis(500);

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
    // Each consumer group gets its OWN connection. A group's blocking
    // `XREAD BLOCK` would otherwise head-of-line-block the other group's
    // reads (and any command queued behind it) on a shared multiplexed
    // connection.
    let money = spawn_group(money_redis, MONEY_GROUP, sinks.money, cancel.clone());
    let stats_session = spawn_group(stats_redis, STATS_SESSION_GROUP, sinks.aux, cancel.clone());
    StreamConsumerHandle::new(vec![money, stats_session], cancel, "accepted")
}

fn spawn_group(
    redis: ConnectionManager,
    group: &'static str,
    sinks: Vec<Arc<dyn SharedAcceptedShareSink>>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    let consumer = AcceptedShareConsumer::new(redis, ACCEPTED_STREAM_KEY, group, CONSUMER);
    tokio::spawn(async move {
        if let Err(err) = consumer.ensure_group().await {
            warn!(%err, group, "satellite-consumer: ensure_group failed; task not started");
            return;
        }

        // Resume: drain the delivered-but-unacked backlog from a previous
        // run before taking new entries. `drain_pending` re-reads from `0`
        // each call, so loop until it reports an empty batch.
        loop {
            match consumer.drain_pending(&sinks, BATCH).await {
                Ok(0) => break,
                Ok(n) => info!(n, group, "satellite-consumer: drained pending backlog"),
                Err(err) => {
                    warn!(%err, group, "satellite-consumer: drain_pending failed; continuing");
                    break;
                }
            }
        }

        info!(group, "satellite-consumer: live");
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = consumer.drain_new(&sinks, BATCH, BLOCK_MS) => {
                    match result {
                        Ok(_) => {}
                        Err(err) => {
                            warn!(%err, group, "satellite-consumer: drain_new failed; backing off");
                            tokio::time::sleep(ERROR_BACKOFF).await;
                        }
                    }
                }
            }
        }
        info!(group, "satellite-consumer: stopped");
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bp_common::MiningMode;
    use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareOwned};
    use bp_share_stream::AcceptedShareProducer;
    use tokio::sync::Mutex as AsyncMutex;

    const REDIS_URL: &str = "redis://127.0.0.1:16379";

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

    async fn connect_redis_or_skip(db: u8) -> Option<ConnectionManager> {
        let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_URL.to_string());
        let client = redis::Client::open(format!("{base}/{db}")).ok()?;
        let mut conn = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            ConnectionManager::new(client),
        )
        .await
        {
            Ok(Ok(c)) => c,
            _ => {
                eprintln!("redis unreachable — skipping satellite-consumer test");
                return None;
            }
        };
        if redis::cmd("FLUSHDB")
            .query_async::<()>(&mut conn)
            .await
            .is_err()
        {
            return None;
        }
        Some(conn)
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

    /// Both durability-class groups independently consume every published
    /// share, in order, and shut down cleanly on cancel.
    #[tokio::test]
    async fn both_groups_consume_all_shares_in_order() {
        let Some(conn) = connect_redis_or_skip(7).await else {
            return;
        };

        // Publish three shares before the consumer starts.
        let producer = AcceptedShareProducer::new(conn.clone(), ACCEPTED_STREAM_KEY);
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

    /// A delivered-but-unacked backlog (a consumer that read but never
    /// acked, e.g. crashed mid-apply) is replayed on restart via
    /// `drain_pending`.
    #[tokio::test]
    async fn pending_backlog_is_replayed_on_restart() {
        let Some(conn) = connect_redis_or_skip(8).await else {
            return;
        };

        let producer = AcceptedShareProducer::new(conn.clone(), ACCEPTED_STREAM_KEY);
        for i in 0..2 {
            producer
                .publish(&sample(&format!("1:{i}")))
                .await
                .expect("publish");
        }

        // Simulate a prior run that read the entries into the money group's
        // PEL but crashed before acking: ensure_group + read_new, no ack.
        let prior =
            AcceptedShareConsumer::new(conn.clone(), ACCEPTED_STREAM_KEY, MONEY_GROUP, CONSUMER);
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
