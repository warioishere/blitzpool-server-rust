// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared consume-loop driver for the generic [`StreamConsumer`].
//!
//! The Core→back event consumers (block-found, device-status, rejected) all run
//! the same skeleton: ensure the consumer group, replay the delivered-but-
//! unacked backlog, then drain new entries until cancelled — acking each batch
//! after dispatch. This module factors that skeleton out so each consumer only
//! supplies its per-entry action ([`StreamEntryHandler`]) plus a little config,
//! instead of hand-rolling the loop + a `*_and_ack` helper + a `Handle` struct.
//!
//! The accepted-share path keeps [`AcceptedShareConsumer`](crate::AcceptedShareConsumer),
//! whose `drain_*` helpers bake the sink fan-out in and which runs two groups on
//! two connections; it reuses the shared [`StreamConsumerHandle`] but keeps its
//! own loop.

use std::time::Duration;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{Consumed, StreamConsumer};

/// Where a freshly-created consumer group starts reading. Existing groups keep
/// their offset either way (`ensure_*` is idempotent on `BUSYGROUP`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureMode {
    /// From id `0` — replay the whole stream history on first creation. For
    /// **idempotent** consumers (ledger apply guarded by PG `UNIQUE`; reject
    /// counters that tolerate a rare double-count).
    FromZero,
    /// From the tail (`$`) — only entries added after group creation. For
    /// **non-idempotent** consumers (notifications) so a first start doesn't
    /// re-fire a push for every historical event.
    FromTail,
}

/// Tuning + labelling for the consume loop. `block_ms` (read-block) and
/// `error_backoff` are the same across every event consumer; only `batch` +
/// `label` differ, so [`Self::new`] fills the shared cadence.
#[derive(Debug, Clone, Copy)]
pub struct ConsumerLoopConfig {
    /// Max entries pulled per read.
    pub batch: usize,
    /// How long `read_new` blocks for at least one entry before looping back to
    /// re-check the cancel signal.
    pub block_ms: usize,
    /// Back-off after a transient stream error before retrying.
    pub error_backoff: Duration,
    /// Log label identifying this consumer (e.g. `"rejected"`).
    pub label: &'static str,
}

impl ConsumerLoopConfig {
    /// Shared cadence: 1s read-block, 500ms error back-off. Only `batch` +
    /// `label` are per-consumer.
    pub fn new(batch: usize, label: &'static str) -> Self {
        Self {
            batch,
            block_ms: 1000,
            error_backoff: Duration::from_millis(500),
            label,
        }
    }
}

/// Per-entry action a consumer runs against each reconstructed value. The driver
/// owns the batch read, id collection, `XACK`, and logging; a handler only
/// decides what one entry *does* (fan out to sinks, apply the ledger, fire a
/// notification). `&self` so it can hold shared deps (sinks / applier /
/// dispatcher) without cloning them per entry.
#[async_trait]
pub trait StreamEntryHandler<T>: Send + Sync {
    async fn handle(&self, value: T);
}

impl<T: DeserializeOwned + Send + 'static> StreamConsumer<T> {
    /// Spawn the standard consume loop and return its handle. Ensures the group
    /// at `ensure`, replays the pending backlog, then drains new entries until
    /// the handle is shut down.
    pub fn spawn<H>(
        self,
        ensure: EnsureMode,
        config: ConsumerLoopConfig,
        handler: H,
    ) -> StreamConsumerHandle
    where
        H: StreamEntryHandler<T> + 'static,
    {
        let cancel = CancellationToken::new();
        let task = tokio::spawn(self.run(ensure, config, cancel.clone(), handler));
        StreamConsumerHandle::new(vec![task], cancel, config.label)
    }

    /// The consume loop itself (spawned by [`Self::spawn`]; `pub` so tests can
    /// drive it directly). Returns when `cancel` fires.
    pub async fn run<H>(
        self,
        ensure: EnsureMode,
        config: ConsumerLoopConfig,
        cancel: CancellationToken,
        handler: H,
    ) where
        H: StreamEntryHandler<T>,
    {
        let ensured = match ensure {
            EnsureMode::FromZero => self.ensure_group().await,
            EnsureMode::FromTail => self.ensure_group_at_tail().await,
        };
        if let Err(err) = ensured {
            warn!(%err, label = config.label, "stream-consumer: ensure_group failed; task not started");
            return;
        }

        // Resume: replay the delivered-but-unacked backlog before new entries.
        // `read_pending` re-reads from `0` each call, so loop until it's empty.
        loop {
            match self.read_pending(config.batch).await {
                Ok(batch) if batch.is_empty() => break,
                Ok(batch) => self.drain_batch(&handler, batch, &config, "pending").await,
                Err(err) => {
                    warn!(%err, label = config.label, "stream-consumer: read_pending failed; continuing");
                    break;
                }
            }
        }

        info!(label = config.label, "stream-consumer: live");
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = self.read_new(config.batch, config.block_ms) => match result {
                    Ok(batch) => self.drain_batch(&handler, batch, &config, "new").await,
                    Err(err) => {
                        warn!(%err, label = config.label, "stream-consumer: read_new failed; backing off");
                        tokio::time::sleep(config.error_backoff).await;
                    }
                },
            }
        }
        info!(label = config.label, "stream-consumer: stopped");
    }

    /// Dispatch each entry to the handler in stream order, then `XACK` the whole
    /// batch. Acking *after* dispatch is safe across a crash: every event
    /// consumer is idempotent (ledger via PG `UNIQUE`, counters tolerate a dup,
    /// a re-sent notification is cosmetic), so a redelivery is harmless.
    async fn drain_batch<H>(
        &self,
        handler: &H,
        batch: Vec<Consumed<T>>,
        config: &ConsumerLoopConfig,
        kind: &'static str,
    ) where
        H: StreamEntryHandler<T>,
    {
        if batch.is_empty() {
            return;
        }
        let mut ids = Vec::with_capacity(batch.len());
        for entry in batch {
            handler.handle(entry.value).await;
            ids.push(entry.id);
        }
        match self.ack(&ids).await {
            Ok(n) => info!(n, kind, label = config.label, "stream-consumer: processed + acked"),
            Err(err) => {
                warn!(%err, kind, label = config.label, "stream-consumer: ack failed (will redeliver)")
            }
        }
    }
}

/// Live consumer task(s) + their shared cancel token. One shape for both the
/// single-task event consumers ([`StreamConsumer::spawn`]) and the accepted-share
/// consumer's two durability-class groups (built via [`Self::new`] with two
/// tasks). [`Self::shutdown`] cancels and joins them as part of graceful
/// shutdown.
pub struct StreamConsumerHandle {
    tasks: Vec<JoinHandle<()>>,
    cancel: CancellationToken,
    label: &'static str,
}

impl StreamConsumerHandle {
    /// Bundle already-spawned task(s) sharing `cancel`. Used by
    /// [`StreamConsumer::spawn`] (one task) and the accepted-share consumer
    /// (two tasks, one per consumer group).
    pub fn new(tasks: Vec<JoinHandle<()>>, cancel: CancellationToken, label: &'static str) -> Self {
        Self {
            tasks,
            cancel,
            label,
        }
    }

    /// Cancel the loop(s) and join the task(s).
    pub async fn shutdown(self) {
        self.cancel.cancel();
        for task in self.tasks {
            if let Err(err) = task.await {
                warn!(%err, label = self.label, "stream-consumer: task join failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Integration tests against a local docker-Redis at
    //! `redis://127.0.0.1:16379` (override with `BP_REDIS_URL`). Each test uses
    //! a distinct logical DB + stream key and skips cleanly if Redis isn't
    //! reachable. These secure the extracted consume-loop skeleton itself
    //! (ordering, pending-backlog replay, tail-start, clean cancel).
    #![allow(clippy::print_stderr)]

    use std::sync::Arc;

    use redis::aio::ConnectionManager;
    use redis::Client;
    use tokio::sync::Mutex as AsyncMutex;

    use super::*;
    use crate::StreamProducer;

    const DEFAULT_URL: &str = "redis://127.0.0.1:16379";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Evt {
        n: u32,
    }

    /// Records every value it handles, in arrival order.
    struct RecordingHandler {
        seen: Arc<AsyncMutex<Vec<u32>>>,
    }

    #[async_trait]
    impl StreamEntryHandler<Evt> for RecordingHandler {
        async fn handle(&self, value: Evt) {
            self.seen.lock().await.push(value.n);
        }
    }

    async fn connect_or_skip(db: u8) -> Option<ConnectionManager> {
        let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
        let client = Client::open(format!("{base}/{db}")).ok()?;
        let mut conn = match tokio::time::timeout(
            Duration::from_secs(2),
            ConnectionManager::new(client),
        )
        .await
        {
            Ok(Ok(c)) => c,
            _ => {
                eprintln!("redis unreachable — skipping runner integration test");
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

    async fn wait_until_len(seen: &Arc<AsyncMutex<Vec<u32>>>, target: usize) -> bool {
        for _ in 0..50 {
            if seen.lock().await.len() >= target {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    fn producer(conn: ConnectionManager, key: &str) -> StreamProducer<Evt> {
        StreamProducer::new(conn, key)
    }

    /// The driver ensures its group, drains entries in stream order through the
    /// handler, acks them (nothing left pending), and stops cleanly on cancel.
    #[tokio::test]
    async fn run_consumes_in_order_acks_and_stops_on_cancel() {
        let Some(conn) = connect_or_skip(6).await else {
            return;
        };
        let key = "bp:test:runner:order";
        let prod = producer(conn.clone(), key);
        for n in 0..3 {
            prod.publish(&Evt { n }).await.expect("publish");
        }

        let seen = Arc::new(AsyncMutex::new(Vec::new()));
        let consumer: StreamConsumer<Evt> = StreamConsumer::new(conn.clone(), key, "g", "c1");
        let cancel = CancellationToken::new();
        let task = tokio::spawn(consumer.run(
            EnsureMode::FromZero,
            ConsumerLoopConfig::new(16, "test"),
            cancel.clone(),
            RecordingHandler { seen: seen.clone() },
        ));

        assert!(wait_until_len(&seen, 3).await, "all three handled");
        assert_eq!(*seen.lock().await, vec![0, 1, 2], "stream order preserved");

        // Acked → nothing pending for this consumer.
        let checker: StreamConsumer<Evt> = StreamConsumer::new(conn, key, "g", "c1");
        assert!(
            checker.read_pending(16).await.expect("read_pending").is_empty(),
            "driver acked the batch"
        );

        cancel.cancel();
        task.await.expect("loop task joins after cancel");
    }

    /// A delivered-but-unacked backlog (a prior consumer that read but never
    /// acked — e.g. crashed mid-apply) is replayed through the handler on
    /// restart, before new entries.
    #[tokio::test]
    async fn run_replays_pending_backlog_on_restart() {
        let Some(conn) = connect_or_skip(7).await else {
            return;
        };
        let key = "bp:test:runner:pending";
        let prod = producer(conn.clone(), key);
        for n in 0..2 {
            prod.publish(&Evt { n }).await.expect("publish");
        }

        // Prior run: read into the PEL, never ack (simulated crash).
        let prior: StreamConsumer<Evt> = StreamConsumer::new(conn.clone(), key, "g", "c1");
        prior.ensure_group().await.expect("ensure");
        assert_eq!(prior.read_new(16, 500).await.expect("read_new").len(), 2);

        // Restart: same group+consumer must replay the pending backlog.
        let seen = Arc::new(AsyncMutex::new(Vec::new()));
        let consumer: StreamConsumer<Evt> = StreamConsumer::new(conn, key, "g", "c1");
        let cancel = CancellationToken::new();
        let task = tokio::spawn(consumer.run(
            EnsureMode::FromZero,
            ConsumerLoopConfig::new(16, "test"),
            cancel.clone(),
            RecordingHandler { seen: seen.clone() },
        ));

        assert!(wait_until_len(&seen, 2).await, "pending backlog replayed");
        assert_eq!(*seen.lock().await, vec![0, 1]);
        cancel.cancel();
        task.await.expect("join");
    }

    /// `FromTail` on a stream with pre-existing history must NOT replay it — a
    /// first start of a non-idempotent (notify) consumer only sees entries added
    /// after the group was created.
    #[tokio::test]
    async fn run_from_tail_skips_history() {
        let Some(conn) = connect_or_skip(8).await else {
            return;
        };
        let key = "bp:test:runner:tail";
        let prod = producer(conn.clone(), key);
        // History BEFORE the group exists.
        prod.publish(&Evt { n: 100 }).await.expect("publish old");

        let seen = Arc::new(AsyncMutex::new(Vec::new()));
        let consumer: StreamConsumer<Evt> = StreamConsumer::new(conn.clone(), key, "g", "c1");
        let cancel = CancellationToken::new();
        let task = tokio::spawn(consumer.run(
            EnsureMode::FromTail,
            ConsumerLoopConfig::new(16, "test"),
            cancel.clone(),
            RecordingHandler { seen: seen.clone() },
        ));

        // Give the loop a moment to create the group at the tail, then publish a
        // fresh entry that SHOULD be seen.
        tokio::time::sleep(Duration::from_millis(300)).await;
        prod.publish(&Evt { n: 200 }).await.expect("publish new");

        assert!(wait_until_len(&seen, 1).await, "the post-creation entry handled");
        assert_eq!(
            *seen.lock().await,
            vec![200],
            "the pre-creation entry was skipped"
        );
        cancel.cancel();
        task.await.expect("join");
    }
}
