// SPDX-License-Identifier: AGPL-3.0-or-later

//! Redis-stream transport (Core → Satellite) feeding the same share sinks
//! the engines expose in-process. Delivery is at-least-once; exactly-once
//! for the money sinks comes from the per-`share_id` dedup marker in the
//! PPLNS / Group-Solo `record_share` Lua, so a separate `XACK` is safe.

mod runner;
pub use runner::{ConsumerLoopConfig, EnsureMode, StreamConsumerHandle, StreamEntryHandler};

use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bp_share_hook::{
    SharedAcceptedShare, SharedAcceptedShareOwned, SharedAcceptedShareSink, SharedRejectedShare,
    SharedRejectedShareOwned, SharedRejectedShareSink,
};
use redis::aio::ConnectionManager;
use redis::streams::{StreamMaxlen, StreamReadOptions, StreamReadReply};
use redis::{AsyncCommands, RedisError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::mpsc;

/// Field name carrying the JSON-encoded share in each stream entry.
const FIELD: &str = "d";

/// The settings every pool connection uses: no response and no connect
/// timeout. A consumer's `XREAD … BLOCK` holds the reply for up to its block
/// time, longer than the client's 500 ms default, which would fail every idle
/// read.
pub fn connection_manager_config() -> redis::aio::ConnectionManagerConfig {
    redis::aio::ConnectionManagerConfig::new()
        .set_response_timeout(None)
        .set_connection_timeout(None)
}

/// Approximate `MAXLEN ~` cap: hours of buffer for a Satellite outage before
/// the oldest entries are trimmed. A breach costs fairness, not funds (the
/// coinbase already paid the window).
pub const DEFAULT_STREAM_MAXLEN: usize = 1_000_000;

/// Accepted-share stream (Core → Satellite).
pub const ACCEPTED_STREAM_KEY: &str = "shares:accepted";

/// Block-found events (Core → Satellite); at-least-once is fine because the
/// apply is PG-idempotent.
pub const BLOCK_FOUND_STREAM_KEY: &str = "blocks:found";

/// Rejected-share stream (Core → Satellite). The Core stamps `group_id`, so
/// the consumer needs no mode gate.
pub const REJECTED_STREAM_KEY: &str = "shares:rejected";

/// Miner online/offline events (Front → Satellite). Notify-only, so a
/// duplicate from at-least-once delivery is cosmetic.
pub const DEVICE_STATUS_STREAM_KEY: &str = "device:status";

/// Tells the Front to rebuild its in-memory routing caches when membership
/// changes in another process, which would otherwise only route after a
/// Front restart. Consumed from the tail: the Front warms from the DB at boot.
pub const CACHE_INVALIDATION_STREAM_KEY: &str = "cache:invalidate";

/// Which routing cache a [`CACHE_INVALIDATION_STREAM_KEY`] event targets.
/// A plain string so the set can grow; the consumer ignores unknown kinds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CacheInvalidation {
    /// `"group"` (Group-Solo address cache) or `"blockparty"` (party routing
    /// cache). See [`cache_kind`] for the canonical values.
    pub kind: String,
}

/// Canonical [`CacheInvalidation::kind`] values.
pub mod cache_kind {
    pub const GROUP: &str = "group";
    pub const BLOCKPARTY: &str = "blockparty";
    /// A block was booked: every published ext 0x0003 distribution is stale
    /// (ext 0x0003/Implementation Notes) and must be invalidated, since its
    /// weights encode pre-settlement balances that a job-declaring client
    /// would pay a second time.
    pub const SETTLEMENT: &str = "settlement";
}

#[derive(Debug, Error)]
pub enum StreamError {
    #[error("redis: {0}")]
    Redis(#[from] RedisError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("stream entry {id} is missing the `d` field")]
    MissingField { id: String },
}

/// Fills only when Redis publishing stalls; overflow drops the share rather
/// than blocking the stratum read loop (the miner already got its accept).
const PUBLISH_BUFFER: usize = 8192;

/// Values per pipelined drain round trip, so throughput is not one Redis
/// round trip per share.
const PUBLISH_BATCH: usize = 256;

/// Bounded channel plus a drain task owning the `XADD`s, so the stratum read
/// loop never blocks on Redis. Overflow drops are logged on power-of-two
/// counts to surface a sustained stall without flooding.
struct BufferedPublisher<T> {
    tx: mpsc::Sender<T>,
    dropped: Arc<AtomicU64>,
    what: &'static str,
}

impl<T: Serialize + Send + Sync + 'static> BufferedPublisher<T> {
    fn new(producer: StreamProducer<T>, what: &'static str) -> Self {
        let (tx, mut rx) = mpsc::channel::<T>(PUBLISH_BUFFER);
        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(PUBLISH_BATCH);
            while rx.recv_many(&mut batch, PUBLISH_BATCH).await > 0 {
                if let Err(e) = producer.publish_batch(&batch).await {
                    tracing::warn!(
                        error = %e,
                        what,
                        count = batch.len(),
                        "share-stream: stream publish failed (accounting deferred)"
                    );
                }
                batch.clear();
            }
        });
        Self {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
            what,
        }
    }

    /// Non-blocking hand-off; drops if the buffer is full or the drain task
    /// is gone.
    fn offer(&self, item: T) {
        if self.tx.try_send(item).is_err() {
            let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_power_of_two() {
                tracing::warn!(
                    dropped_total = n,
                    what = self.what,
                    "share-stream: publish buffer full — dropping (stream publish lagging)"
                );
            }
        }
    }
}

/// Publishes accepted shares onto the stream. Being a sink, it sits behind
/// the Core's in-process composite, so shares arrive already stamped with
/// `share_id`, `mode` and `group_id`.
pub struct ProducingSink {
    inner: BufferedPublisher<SharedAcceptedShareOwned>,
}

impl ProducingSink {
    pub fn new(producer: StreamProducer<SharedAcceptedShareOwned>) -> Self {
        Self {
            inner: BufferedPublisher::new(producer, "accepted"),
        }
    }
}

#[async_trait]
impl SharedAcceptedShareSink for ProducingSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        self.inner.offer(share.to_owned_record());
    }
}

/// [`ProducingSink`] for rejected shares; the Core's rejected composite
/// stamps `group_id` first.
pub struct ProducingRejectedSink {
    inner: BufferedPublisher<SharedRejectedShareOwned>,
}

impl ProducingRejectedSink {
    pub fn new(producer: StreamProducer<SharedRejectedShareOwned>) -> Self {
        Self {
            inner: BufferedPublisher::new(producer, "rejected"),
        }
    }
}

#[async_trait]
impl SharedRejectedShareSink for ProducingRejectedSink {
    async fn record_rejected(&self, share: SharedRejectedShare<'_>) {
        self.inner.offer(share.to_owned_record());
    }
}

/// Hands each consumed share to every sink in order; the sinks are the same
/// [`SharedAcceptedShareSink`] impls used in-process, so the transport
/// changes nothing about what a share does.
pub struct AcceptedShareFanOut {
    sinks: Vec<Arc<dyn SharedAcceptedShareSink>>,
}

impl AcceptedShareFanOut {
    pub fn new(sinks: Vec<Arc<dyn SharedAcceptedShareSink>>) -> Self {
        Self { sinks }
    }
}

#[async_trait]
impl StreamEntryHandler<SharedAcceptedShareOwned> for AcceptedShareFanOut {
    async fn handle(&self, value: SharedAcceptedShareOwned) {
        let view = value.as_view();
        for sink in &self.sinks {
            sink.record_accepted(view).await;
        }
    }
}

// ── Typed transport ─────────────────────────────────────────────────

/// Each increment is an accepted share that could not be decoded, i.e. a
/// miner underpaid; operators alert on it.
const ACCEPTED_UNDECODABLE_COUNTER: &str = "accepted_share_undecodable_dropped_total";

/// Publishes JSON-encoded `T` values onto a Redis stream. Cheap to clone.
#[derive(Clone)]
pub struct StreamProducer<T> {
    conn: ConnectionManager,
    stream_key: String,
    maxlen: usize,
    _marker: PhantomData<fn() -> T>,
}

impl<T: Serialize> StreamProducer<T> {
    pub fn new(conn: ConnectionManager, stream_key: impl Into<String>) -> Self {
        Self {
            conn,
            stream_key: stream_key.into(),
            maxlen: DEFAULT_STREAM_MAXLEN,
            _marker: PhantomData,
        }
    }

    /// Override the stream-length cap (approximate `MAXLEN ~`).
    pub fn with_maxlen(mut self, maxlen: usize) -> Self {
        self.maxlen = maxlen;
        self
    }

    /// `XADD … MAXLEN ~ cap` one value with an auto-generated id (`*`).
    /// Returns the entry id.
    pub async fn publish(&self, value: &T) -> Result<String, StreamError> {
        let json = serde_json::to_string(value)?;
        let mut conn = self.conn.clone();
        let id: String = conn
            .xadd_maxlen(
                &self.stream_key,
                StreamMaxlen::Approx(self.maxlen),
                "*",
                &[(FIELD, json.as_str())],
            )
            .await?;
        Ok(id)
    }

    /// [`Self::publish`] for several values in one round trip: one pipeline
    /// of `XADD`s, applied in order.
    pub async fn publish_batch(&self, values: &[T]) -> Result<(), StreamError> {
        let mut pipe = redis::pipe();
        for value in values {
            let json = serde_json::to_string(value)?;
            pipe.xadd_maxlen(
                &self.stream_key,
                StreamMaxlen::Approx(self.maxlen),
                "*",
                &[(FIELD, json.as_str())],
            )
            .ignore();
        }
        let mut conn = self.conn.clone();
        pipe.query_async::<()>(&mut conn).await?;
        Ok(())
    }
}

/// One consumed entry: its stream id + the reconstructed value.
#[derive(Debug, Clone, PartialEq)]
pub struct Consumed<T> {
    pub id: String,
    pub value: T,
}

/// Reads `T` values from a Redis stream via a consumer group. A given
/// `(group, consumer)` pair is one logical reader; on restart it reuses the
/// same names and reclaims its pending entries via [`Self::read_pending`].
#[derive(Clone)]
pub struct StreamConsumer<T> {
    conn: ConnectionManager,
    stream_key: String,
    group: String,
    consumer: String,
    /// `Some(counter)` when a dropped entry is lost money: the drop is then
    /// logged at `error` and counted instead of a `warn`.
    undecodable_counter: Option<&'static str>,
    _marker: PhantomData<fn() -> T>,
}

impl StreamConsumer<SharedAcceptedShareOwned> {
    /// Consumer for the accepted-share stream. An undecodable entry here is a
    /// share that can never be credited, so its drop is logged at `error` and
    /// counted, making a non-additive schema skew or corrupt write alertable.
    pub fn accepted(
        conn: ConnectionManager,
        stream_key: impl Into<String>,
        group: impl Into<String>,
        consumer: impl Into<String>,
    ) -> Self {
        Self {
            undecodable_counter: Some(ACCEPTED_UNDECODABLE_COUNTER),
            ..Self::new(conn, stream_key, group, consumer)
        }
    }
}

impl<T: DeserializeOwned> StreamConsumer<T> {
    pub fn new(
        conn: ConnectionManager,
        stream_key: impl Into<String>,
        group: impl Into<String>,
        consumer: impl Into<String>,
    ) -> Self {
        Self {
            conn,
            stream_key: stream_key.into(),
            group: group.into(),
            consumer: consumer.into(),
            undecodable_counter: None,
            _marker: PhantomData,
        }
    }

    /// Creates the group from id `0` if absent, replaying the whole history:
    /// only for idempotent consumers. Non-idempotent ones (notifications) use
    /// [`Self::ensure_group_at_tail`].
    pub async fn ensure_group(&self) -> Result<(), StreamError> {
        self.ensure_group_from("0").await
    }

    /// Creates the group at the tail (`$`) if absent, so a new notify group
    /// does not re-fire a push for every historical event. An existing group
    /// keeps its offset.
    pub async fn ensure_group_at_tail(&self) -> Result<(), StreamError> {
        self.ensure_group_from("$").await
    }

    async fn ensure_group_from(&self, start_id: &str) -> Result<(), StreamError> {
        let mut conn = self.conn.clone();
        let res: Result<(), RedisError> = conn
            .xgroup_create_mkstream(&self.stream_key, &self.group, start_id)
            .await;
        match res {
            Ok(()) => Ok(()),
            Err(e) if e.code() == Some("BUSYGROUP") => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Read up to `count` never-delivered entries (`>`), blocking up to
    /// `block_ms` for at least one. Returns `[]` on timeout.
    pub async fn read_new(
        &self,
        count: usize,
        block_ms: usize,
    ) -> Result<Vec<Consumed<T>>, StreamError> {
        let opts = StreamReadOptions::default()
            .group(&self.group, &self.consumer)
            .count(count)
            .block(block_ms);
        let mut conn = self.conn.clone();
        let reply: StreamReadReply = conn
            .xread_options(&[&self.stream_key], &[">"], &opts)
            .await?;
        Ok(self.partition(reply).await.0)
    }

    /// Re-read this consumer's pending (delivered-but-unacked) entries from
    /// the start (`0`) — the restart-resume path.
    pub async fn read_pending(&self, count: usize) -> Result<Vec<Consumed<T>>, StreamError> {
        Ok(self.read_pending_counted(count).await?.0)
    }

    /// Also returns the raw entry count (good + dead-lettered), so the resume
    /// loop can tell an empty PEL from an all-poison batch.
    pub(crate) async fn read_pending_counted(
        &self,
        count: usize,
    ) -> Result<(Vec<Consumed<T>>, usize), StreamError> {
        let opts = StreamReadOptions::default()
            .group(&self.group, &self.consumer)
            .count(count);
        let mut conn = self.conn.clone();
        let reply: StreamReadReply = conn
            .xread_options(&[&self.stream_key], &["0"], &opts)
            .await?;
        Ok(self.partition(reply).await)
    }

    /// `XACK` the given entry ids. Returns the number acknowledged.
    pub async fn ack(&self, ids: &[String]) -> Result<usize, StreamError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn.clone();
        let n: usize = conn.xack(&self.stream_key, &self.group, ids).await?;
        Ok(n)
    }

    fn decode_entry(entry: &redis::streams::StreamId) -> Result<T, StreamError> {
        let raw = entry
            .map
            .get(FIELD)
            .ok_or_else(|| StreamError::MissingField {
                id: entry.id.clone(),
            })?;
        let json: String = redis::from_redis_value_ref(raw).map_err(RedisError::from)?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Returns `(decodable entries, raw count)`. Undecodable entries are
    /// logged and `XACK`ed here: a decode failure is deterministic, and an
    /// un-acked one would sit in the PEL masking the consumer-lag monitor.
    /// See [`StreamConsumer::accepted`] for the money stream's handling.
    async fn partition(&self, reply: StreamReadReply) -> (Vec<Consumed<T>>, usize) {
        let mut good = Vec::new();
        let mut poison = Vec::new();
        for key in reply.keys {
            for entry in key.ids {
                match Self::decode_entry(&entry) {
                    Ok(value) => good.push(Consumed {
                        id: entry.id,
                        value,
                    }),
                    Err(err) => {
                        match self.undecodable_counter {
                            Some(counter) => {
                                tracing::error!(
                                    id = %entry.id,
                                    %err,
                                    stream = %self.stream_key,
                                    group = %self.group,
                                    "stream-consumer: LOST an undecodable accepted (money) share — \
                                     miner underpaid for this window; investigate share-schema skew / \
                                     corrupt write"
                                );
                                metrics::counter!(counter).increment(1);
                            }
                            None => tracing::warn!(
                                id = %entry.id,
                                %err,
                                stream = %self.stream_key,
                                group = %self.group,
                                "stream-consumer: dropping undecodable entry (dead-letter)"
                            ),
                        }
                        poison.push(entry.id);
                    }
                }
            }
        }
        let raw = good.len() + poison.len();
        if !poison.is_empty() {
            if let Err(err) = self.ack(&poison).await {
                tracing::warn!(
                    %err,
                    n = poison.len(),
                    stream = %self.stream_key,
                    group = %self.group,
                    "stream-consumer: dead-letter ack failed (entries stay pending, retried next read)"
                );
            }
        }
        (good, raw)
    }
}

#[cfg(test)]
mod tests {
    //! Integration tests against Redis (`BP_REDIS_URL`); each test uses its
    //! own logical DB and skips if Redis is unreachable.
    #![allow(clippy::print_stderr)]

    use super::*;
    use bp_share_hook::MiningMode;
    use redis::Client;

    const DEFAULT_URL: &str = "redis://127.0.0.1:16379";

    async fn connect_or_skip(db: u8) -> Option<ConnectionManager> {
        // This binary's own DB range, so other test binaries do not flush it.
        let db =
            bp_test_support::redis_db_in_range(bp_test_support::redis_db::SHARE_STREAM, db).await;
        let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
        let url = format!("{base}/{db}");
        let client = Client::open(url).ok()?;
        let mut conn = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            ConnectionManager::new_with_config(client, crate::connection_manager_config()),
        )
        .await
        {
            Ok(Ok(c)) => c,
            _ => {
                eprintln!("redis unreachable — skipping bp-share-stream integration test");
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

    /// An idle `XREADGROUP … BLOCK 1000` returns empty on a connection built
    /// with [`connection_manager_config`]; on the client's default config the
    /// same read fails at its 500 ms response timeout (negative control).
    #[tokio::test]
    async fn an_idle_blocking_read_outlasts_the_default_response_timeout() {
        let Some(_flushed) = connect_or_skip(16).await else {
            return;
        };
        let db =
            bp_test_support::redis_db_in_range(bp_test_support::redis_db::SHARE_STREAM, 16).await;
        let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
        let client = Client::open(format!("{base}/{db}")).expect("client");

        let ours = ConnectionManager::new_with_config(client.clone(), connection_manager_config())
            .await
            .expect("pool-config connection");
        let consumer: StreamConsumer<SharedAcceptedShareOwned> =
            StreamConsumer::new(ours, "test:idle-block", "g", "c");
        consumer.ensure_group_at_tail().await.expect("group");
        let idle = consumer.read_new(10, 1000).await.expect("idle read");
        assert!(idle.is_empty());

        let default =
            ConnectionManager::new_with_config(client, redis::aio::ConnectionManagerConfig::new())
                .await
                .expect("default connection");
        let consumer: StreamConsumer<SharedAcceptedShareOwned> =
            StreamConsumer::new(default, "test:idle-block", "g", "c");
        assert!(
            consumer.read_new(10, 1000).await.is_err(),
            "precondition: the default config must time the idle read out"
        );
    }

    /// Second, non-flushing connection to the same DB: a blocking
    /// `XREADGROUP … BLOCK` would otherwise head-of-line-block an `XADD` on
    /// the shared multiplexed connection.
    async fn connect_peer(db: u8) -> Option<ConnectionManager> {
        // Must fold like `connect_or_skip`, or producer and consumer never meet.
        let db =
            bp_test_support::redis_db_in_range(bp_test_support::redis_db::SHARE_STREAM, db).await;
        let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
        let url = format!("{base}/{db}");
        let client = Client::open(url).ok()?;
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            ConnectionManager::new_with_config(client, crate::connection_manager_config()),
        )
        .await
        {
            Ok(Ok(c)) => Some(c),
            _ => None,
        }
    }

    fn sample(
        share_id: &str,
        mode: MiningMode,
        group_id: Option<&str>,
    ) -> SharedAcceptedShareOwned {
        SharedAcceptedShareOwned {
            address: "bc1qfoo".into(),
            worker: "rig1".into(),
            session_id: "sess1".into(),
            effective_difficulty: 1024.0,
            submission_difficulty: 2048.0,
            user_agent: Some("bitaxe/1.0".into()),
            is_block_candidate: false,
            hash_rate: 12345.6,
            channel_count: 1,
            ts_ms: 1_700_000_000_000,
            share_id: share_id.into(),
            mode,
            group_id: group_id.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn ensure_group_is_idempotent() {
        let Some(conn) = connect_or_skip(14).await else {
            return;
        };
        let key = "bp:test:shares:accepted3";
        let consumer = StreamConsumer::accepted(conn.clone(), key, "money", "c1");
        consumer.ensure_group().await.expect("first ensure_group");
        // Second call must not error on the existing group (BUSYGROUP).
        consumer.ensure_group().await.expect("second ensure_group");
    }

    /// Recording sink — captures each share's id in dispatch order.
    struct RecordingSink {
        ids: Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl SharedAcceptedShareSink for RecordingSink {
        async fn record_accepted(&self, share: bp_share_hook::SharedAcceptedShare<'_>) {
            self.ids
                .lock()
                .expect("recording sink poisoned")
                .push(share.share_id.to_string());
        }
    }

    fn recording_fan_out() -> (AcceptedShareFanOut, Arc<std::sync::Mutex<Vec<String>>>) {
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let fan_out = AcceptedShareFanOut::new(vec![Arc::new(RecordingSink {
            ids: recorded.clone(),
        })]);
        (fan_out, recorded)
    }

    async fn xadd_poison(conn: &ConnectionManager, key: &str) {
        // Raw entry whose `d` field isn't a valid share record.
        let _: String = redis::cmd("XADD")
            .arg(key)
            .arg("*")
            .arg("d")
            .arg("{ not a share")
            .query_async(&mut conn.clone())
            .await
            .expect("xadd poison");
    }

    #[tokio::test]
    async fn drain_new_fans_out_to_sinks_in_order_and_acks() {
        let Some(conn) = connect_or_skip(15).await else {
            return;
        };
        let key = "bp:test:shares:accepted4";
        let producer = StreamProducer::new(conn.clone(), key);
        let consumer = StreamConsumer::accepted(conn.clone(), key, "money", "c1");
        consumer.ensure_group().await.expect("ensure_group");

        producer
            .publish(&sample("ep1:0", MiningMode::Pplns, None))
            .await
            .expect("publish");
        producer
            .publish(&sample("ep1:1", MiningMode::GroupSolo, Some("g")))
            .await
            .expect("publish");

        let (fan_out, recorded) = recording_fan_out();
        let n = consumer
            .drain_new(&fan_out, 10, 1000)
            .await
            .expect("drain_new");
        assert_eq!(n, 2, "both shares processed");
        assert_eq!(
            *recorded.lock().unwrap(),
            vec!["ep1:0".to_string(), "ep1:1".to_string()],
            "sinks see shares in produce order"
        );

        // drain_new acks → nothing left pending.
        assert!(
            consumer
                .read_pending(10)
                .await
                .expect("read_pending")
                .is_empty(),
            "drain_new must ack the batch"
        );
    }

    /// A poison entry between two good shares is dead-lettered while the good
    /// ones still reach the sinks in order.
    #[tokio::test]
    async fn drain_new_dead_letters_poison_share_and_keeps_good() {
        let Some(conn) = connect_or_skip(5).await else {
            return;
        };
        let key = "bp:test:shares:poison";
        let producer = StreamProducer::new(conn.clone(), key);
        let consumer = StreamConsumer::accepted(conn.clone(), key, "money", "c1");
        consumer.ensure_group().await.expect("ensure_group");

        producer
            .publish(&sample("ep1:0", MiningMode::Pplns, None))
            .await
            .expect("publish good1");
        xadd_poison(&conn, key).await;
        producer
            .publish(&sample("ep1:1", MiningMode::GroupSolo, Some("g")))
            .await
            .expect("publish good2");

        let (fan_out, recorded) = recording_fan_out();
        let n = consumer
            .drain_new(&fan_out, 10, 1000)
            .await
            .expect("drain_new");
        assert_eq!(n, 2, "both good shares processed, poison skipped");
        assert_eq!(
            *recorded.lock().unwrap(),
            vec!["ep1:0".to_string(), "ep1:1".to_string()],
            "sinks see only the good shares, in order"
        );

        // Good acked by drain_new, poison dead-lettered by the read → PEL empty.
        assert!(
            consumer
                .read_pending(10)
                .await
                .expect("read_pending")
                .is_empty(),
            "poison entry dead-lettered (acked), not left pending"
        );
    }

    /// Minimal recorder counting counter increments by name.
    #[derive(Default)]
    struct CountingRecorder {
        counts: Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
    }

    struct NamedCounter {
        name: String,
        counts: Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
    }

    impl metrics::CounterFn for NamedCounter {
        fn increment(&self, value: u64) {
            *self
                .counts
                .lock()
                .unwrap()
                .entry(self.name.clone())
                .or_default() += value;
        }
        fn absolute(&self, _value: u64) {}
    }

    impl metrics::Recorder for CountingRecorder {
        fn describe_counter(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_gauge(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_histogram(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn register_counter(
            &self,
            key: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            metrics::Counter::from_arc(Arc::new(NamedCounter {
                name: key.name().to_string(),
                counts: self.counts.clone(),
            }))
        }
        fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
            metrics::Gauge::noop()
        }
        fn register_histogram(
            &self,
            _: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            metrics::Histogram::noop()
        }
    }

    /// The accepted consumer counts an undecodable drop; a plain consumer on
    /// the same entry does not (negative control).
    #[test]
    fn an_undecodable_accepted_share_is_counted_as_lost() {
        let recorder = CountingRecorder::default();
        let counts = recorder.counts.clone();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        // `with_local_recorder` is per-thread; the current-thread runtime
        // polls the consumer on this very thread.
        let ran = metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let Some(conn) = connect_or_skip(12).await else {
                    return false;
                };
                let key = "bp:test:shares:lost";
                xadd_poison(&conn, key).await;

                let plain: StreamConsumer<SharedAcceptedShareOwned> =
                    StreamConsumer::new(conn.clone(), key, "plain", "c1");
                plain.ensure_group().await.expect("ensure plain");
                assert!(plain
                    .read_new(10, 500)
                    .await
                    .expect("read plain")
                    .is_empty());
                assert_eq!(
                    counts.lock().unwrap().get(ACCEPTED_UNDECODABLE_COUNTER),
                    None,
                    "a plain consumer drops without counting"
                );

                let money = StreamConsumer::accepted(conn, key, "money", "c1");
                money.ensure_group().await.expect("ensure money");
                assert!(money
                    .read_new(10, 500)
                    .await
                    .expect("read money")
                    .is_empty());
                true
            })
        });
        if !ran {
            return;
        }
        assert_eq!(
            counts.lock().unwrap().get(ACCEPTED_UNDECODABLE_COUNTER),
            Some(&1),
            "the accepted consumer counts the dropped share as lost"
        );
    }

    /// An all-poison batch at the front of the PEL does not end the resume
    /// drain before the good shares behind it.
    #[tokio::test]
    async fn resume_loop_drains_good_share_stranded_behind_front_poison() {
        let Some(conn) = connect_or_skip(2).await else {
            return;
        };
        let key = "bp:test:shares:strand";
        let group = "money";
        let consumer_name = "c1";
        let producer = StreamProducer::new(conn.clone(), key);
        let consumer = StreamConsumer::accepted(conn.clone(), key, group, consumer_name);
        consumer.ensure_group().await.expect("ensure_group");

        // Poison FIRST (lowest id → front of the PEL), good share behind it.
        xadd_poison(&conn, key).await;
        producer
            .publish(&sample("ep1:0", MiningMode::Pplns, None))
            .await
            .expect("publish good");

        // Post-crash state: a raw `>` read puts both in the PEL without
        // `partition` dead-lettering the poison.
        let _: redis::Value = redis::cmd("XREADGROUP")
            .arg("GROUP")
            .arg(group)
            .arg(consumer_name)
            .arg("COUNT")
            .arg(10)
            .arg("STREAMS")
            .arg(key)
            .arg(">")
            .query_async(&mut conn.clone())
            .await
            .expect("raw deliver to PEL");

        // Batch 1 forces an all-poison first batch; only the resume drain can
        // reach the good share.
        let (fan_out, recorded) = recording_fan_out();
        let cancel = tokio_util::sync::CancellationToken::new();
        let task = tokio::spawn(consumer.clone().run(
            EnsureMode::FromZero,
            ConsumerLoopConfig::new(1, "test"),
            cancel.clone(),
            fan_out,
        ));
        for _ in 0..50 {
            if !recorded.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        cancel.cancel();
        task.await.expect("join");

        assert_eq!(
            *recorded.lock().unwrap(),
            vec!["ep1:0".to_string()],
            "good share behind the front poison must not be stranded"
        );
        assert!(
            consumer
                .read_pending(10)
                .await
                .expect("read_pending")
                .is_empty(),
            "resume loop must drain the whole PEL (good dispatched, poison dead-lettered)"
        );
    }

    #[tokio::test]
    async fn producing_sink_publishes_each_accepted_share() {
        let Some(consumer_conn) = connect_or_skip(11).await else {
            return;
        };
        // The deferred XADD must not share the socket the consumer blocks on.
        let Some(producer_conn) = connect_peer(11).await else {
            return;
        };
        let key = "bp:test:shares:accepted5";
        let consumer = StreamConsumer::accepted(consumer_conn, key, "money", "c1");
        consumer.ensure_group().await.expect("ensure_group");

        let sink = ProducingSink::new(StreamProducer::new(producer_conn, key));
        let s1 = sample("ep1:0", MiningMode::Pplns, None);
        let s2 = sample("ep1:1", MiningMode::GroupSolo, Some("group-xyz"));
        // Drive the sink with stamped views, exactly as the composite would.
        sink.record_accepted(s1.as_view()).await;
        sink.record_accepted(s2.as_view()).await;

        let mut got = Vec::new();
        for _ in 0..10 {
            got.extend(consumer.read_new(10, 1000).await.expect("read_new"));
            if got.len() >= 2 {
                break;
            }
        }
        assert_eq!(got.len(), 2);
        // Reconstructed records are identical, in produce order.
        assert_eq!(got[0].value, s1, "the produced record round-trips intact");
        assert_eq!(got[1].value, s2, "mode + group_id round-trip intact");
    }

    /// A burst larger than one drain batch arrives complete and in order.
    #[tokio::test]
    async fn producing_sink_keeps_order_across_batches() {
        let Some(consumer_conn) = connect_or_skip(13).await else {
            return;
        };
        let Some(producer_conn) = connect_peer(13).await else {
            return;
        };
        let key = "bp:test:shares:accepted-batched";
        let consumer = StreamConsumer::accepted(consumer_conn, key, "money", "c1");
        consumer.ensure_group().await.expect("ensure_group");

        let sink = ProducingSink::new(StreamProducer::new(producer_conn, key));
        let n = PUBLISH_BATCH * 3 + 7;
        // No yield, so the drain finds more than one batch queued.
        for i in 0..n {
            sink.record_accepted(sample(&format!("ep1:{i}"), MiningMode::Pplns, None).as_view())
                .await;
        }

        let mut got = Vec::new();
        for _ in 0..50 {
            got.extend(consumer.read_new(1000, 1000).await.expect("read_new"));
            if got.len() >= n {
                break;
            }
        }
        let ids: Vec<String> = got.into_iter().map(|c| c.value.share_id).collect();
        let want: Vec<String> = (0..n).map(|i| format!("ep1:{i}")).collect();
        assert_eq!(ids, want);
    }

    /// A group-stamped rejected share round-trips the rejected stream intact.
    #[tokio::test]
    async fn producing_rejected_sink_publishes_each_rejected_share() {
        let Some(consumer_conn) = connect_or_skip(9).await else {
            return;
        };
        // Separate producer connection — see `producing_sink_publishes_each_accepted_share`.
        let Some(producer_conn) = connect_peer(9).await else {
            return;
        };
        let key = "bp:test:shares:rejected";
        let consumer: StreamConsumer<SharedRejectedShareOwned> =
            StreamConsumer::new(consumer_conn, key, "satellite", "c1");
        consumer.ensure_group().await.expect("ensure_group");

        let sink = ProducingRejectedSink::new(StreamProducer::new(producer_conn, key));
        let owned = SharedRejectedShareOwned {
            address: Some("bc1qfoo".into()),
            worker: Some("rig1".into()),
            session_id: "sess1".into(),
            reason: bp_share_hook::RejectedReason::LowDifficulty,
            difficulty: 512.0,
            group_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
        };
        sink.record_rejected(owned.as_view()).await;

        let got = consumer.read_new(10, 1000).await.expect("read_new");
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].value, owned,
            "the rejected record (incl. group_id) round-trips intact"
        );
    }

    // ── Generic transport ────────────────────────────────────────────

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Evt {
        n: u32,
        label: String,
    }

    /// Typed values round-trip, and an unacked entry is replayed by
    /// `read_pending` (the redelivery the block-found apply relies on).
    #[tokio::test]
    async fn generic_stream_round_trips_and_redelivers_pending() {
        let Some(conn) = connect_or_skip(10).await else {
            return;
        };
        let key = "bp:test:blocks:found";
        let producer: StreamProducer<Evt> = StreamProducer::new(conn.clone(), key);
        let consumer: StreamConsumer<Evt> = StreamConsumer::new(conn.clone(), key, "bf", "c1");
        consumer.ensure_group().await.expect("ensure_group");

        for n in 0..3 {
            producer
                .publish(&Evt {
                    n,
                    label: format!("e{n}"),
                })
                .await
                .expect("publish");
        }

        // Read new (delivers to the PEL) but do NOT ack.
        let batch = consumer.read_new(10, 1000).await.expect("read_new");
        assert_eq!(batch.len(), 3);
        assert_eq!(
            batch[0].value,
            Evt {
                n: 0,
                label: "e0".into()
            }
        );
        assert_eq!(batch[2].value.n, 2);

        // Unacked → still pending; a restart-resume read replays them.
        let pending = consumer.read_pending(10).await.expect("read_pending");
        assert_eq!(pending.len(), 3, "unacked entries replay as pending");

        // Ack them → pending drains.
        let ids: Vec<String> = pending.iter().map(|c| c.id.clone()).collect();
        let acked = consumer.ack(&ids).await.expect("ack");
        assert_eq!(acked, 3);
        assert!(consumer
            .read_pending(10)
            .await
            .expect("read_pending")
            .is_empty());
    }

    /// A tail-started group skips existing history; a `0`-started group on
    /// the same stream replays it.
    #[tokio::test]
    async fn ensure_group_at_tail_skips_history() {
        // Own DB: `connect_or_skip` flushes it.
        let Some(conn) = connect_or_skip(1).await else {
            return;
        };
        let key = "bp:test:tail";
        let _: () = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut conn.clone())
            .await
            .unwrap();
        let producer: StreamProducer<Evt> = StreamProducer::new(conn.clone(), key);

        // History added BEFORE the group exists.
        producer
            .publish(&Evt {
                n: 1,
                label: "old".into(),
            })
            .await
            .expect("publish old");

        // A tail-started group ignores it.
        let tail: StreamConsumer<Evt> = StreamConsumer::new(conn.clone(), key, "tail", "c1");
        tail.ensure_group_at_tail().await.expect("ensure tail");

        // An entry added AFTER creation is delivered.
        producer
            .publish(&Evt {
                n: 2,
                label: "new".into(),
            })
            .await
            .expect("publish new");
        let batch = tail.read_new(10, 1000).await.expect("read_new");
        assert_eq!(batch.len(), 1, "tail group skips the pre-creation entry");
        assert_eq!(
            batch[0].value,
            Evt {
                n: 2,
                label: "new".into()
            }
        );

        // Contrast: a `0`-started group on the SAME stream replays both.
        let zero: StreamConsumer<Evt> = StreamConsumer::new(conn, key, "zero", "c1");
        zero.ensure_group().await.expect("ensure zero");
        let all = zero.read_new(10, 1000).await.expect("read_new zero");
        assert_eq!(all.len(), 2, "a 0-started group replays the full history");
    }

    /// The producer caps stream length; approximate trimming may keep a
    /// macro-node extra, so the assertion is "well below produced".
    #[tokio::test]
    async fn producer_caps_stream_length() {
        let Some(conn) = connect_or_skip(8).await else {
            return;
        };
        let key = "bp:test:maxlen";
        let _: () = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut conn.clone())
            .await
            .unwrap();
        let producer: StreamProducer<Evt> = StreamProducer::new(conn.clone(), key).with_maxlen(100);
        for n in 0..1000u32 {
            producer
                .publish(&Evt {
                    n,
                    label: String::new(),
                })
                .await
                .expect("publish");
        }
        let len: usize = redis::cmd("XLEN")
            .arg(key)
            .query_async(&mut conn.clone())
            .await
            .unwrap();
        assert!(len >= 100, "keeps at least the cap, got {len}");
        assert!(
            len < 1000,
            "trimmed well below the produced count, got {len}"
        );
    }
}
