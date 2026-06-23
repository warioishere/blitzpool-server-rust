// SPDX-License-Identifier: AGPL-3.0-or-later

//! Redis-stream transport for accepted shares (Core → Satellite).
//!
//! The Core's share producer `XADD`s each accepted share (as a
//! [`bp_share_hook::SharedAcceptedShareOwned`] record) onto one Redis
//! stream; the Satellite consumes it through a **consumer group** and
//! reconstructs the owned record, then borrows a view back to drive the
//! per-engine accounting sinks (the same sink impls regardless of transport).
//!
//! # Delivery + exactly-once
//!
//! This layer is **at-least-once**: a consumer group delivers each entry,
//! and the consumer `XACK`s once it has handed the share to the sinks.
//! Exactly-once for the non-idempotent money sinks comes from a layer
//! above — the per-`share_id` dedup marker inside the PPLNS / Group-Solo
//! `record_share` Lua. A crash between sink-apply and `XACK` redelivers the
//! entry; the dedup marker makes the re-apply a no-op, so a *separate*
//! `XACK` is safe and the transport stays simple (it never needs to fold
//! the ack into the engine's mutation).
//!
//! Each entry stores the share as a single JSON field (`d`) — compact
//! enough at pool share-rates, and human-inspectable via `XRANGE`.

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

/// Default cap on a stream's length (approximate `MAXLEN ~`). Generous —
/// at pool share-rates this is hours of buffer for a Satellite outage — and
/// the producer trims oldest beyond it rather than letting Redis grow
/// unbounded. A breach is a fairness delle (the coinbase already paid the
/// window), not fund loss; the consumer-lag monitor alerts before then.
pub const DEFAULT_STREAM_MAXLEN: usize = 1_000_000;

/// Redis key of the accepted-share stream. Shared by the Core's producer
/// and the Satellite's consumer so the two stay in sync from one source.
pub const ACCEPTED_STREAM_KEY: &str = "shares:accepted";

/// Redis key of the block-found event stream (Core → Satellite). Rare,
/// low-volume traffic; the Satellite runs the block-found accounting +
/// notifications off it. At-least-once is fine — the apply is PG-idempotent.
pub const BLOCK_FOUND_STREAM_KEY: &str = "blocks:found";

/// Redis key of the rejected-share stream (Core → Satellite). The Satellite
/// runs the Group-Solo + stats reject counters off it. The share is
/// group_id-stamped by the Core, so the consumer needs no mode gate.
pub const REJECTED_STREAM_KEY: &str = "shares:rejected";

/// Redis key of the device-status event stream (Core → Satellite). Carries
/// miner online/offline events from the Stratum front so the Satellite (which
/// owns the notification dispatcher) can fan them out. Front-originated like
/// block-found, but notify-only — no ledger, so at-least-once is harmless
/// (a duplicated online/offline push is cosmetic).
pub const DEVICE_STATUS_STREAM_KEY: &str = "device:status";

/// Redis key of the cache-invalidation stream (Api/back → Front). Group-Solo +
/// Blockparty membership lives in per-process in-memory routing caches that the
/// Stratum mode-gate reads. When a membership change lands on a process other
/// than the Front (e.g. the `api` process in a split), it publishes here so the
/// Front rebuilds its routing cache — otherwise the change wouldn't route until
/// the Front restarts. Consumed tail-start (the Front warms from the DB at
/// boot, then only needs *new* invalidations).
pub const CACHE_INVALIDATION_STREAM_KEY: &str = "cache:invalidate";

/// Which routing cache a [`CACHE_INVALIDATION_STREAM_KEY`] event asks the Front
/// to rebuild. Plain string on the wire so the set can grow without a breaking
/// change (an unknown kind is ignored by the consumer).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CacheInvalidation {
    /// `"group"` (Group-Solo address cache) or `"blockparty"` (party routing
    /// cache). See [`CacheKind`] for the canonical values.
    pub kind: String,
}

/// Canonical [`CacheInvalidation::kind`] values, kept as constants so the
/// publisher and consumer agree without a shared enum across crates.
pub mod cache_kind {
    pub const GROUP: &str = "group";
    pub const BLOCKPARTY: &str = "blockparty";
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

/// Publishes accepted shares to a Redis stream. Cheap to clone
/// (`ConnectionManager` is `Arc`-backed + multiplexed).
#[derive(Clone)]
pub struct AcceptedShareProducer {
    conn: ConnectionManager,
    stream_key: String,
    maxlen: usize,
}

impl AcceptedShareProducer {
    pub fn new(conn: ConnectionManager, stream_key: impl Into<String>) -> Self {
        Self {
            conn,
            stream_key: stream_key.into(),
            maxlen: DEFAULT_STREAM_MAXLEN,
        }
    }

    /// Override the stream-length cap (approximate `MAXLEN ~`).
    pub fn with_maxlen(mut self, maxlen: usize) -> Self {
        self.maxlen = maxlen;
        self
    }

    /// `XADD … MAXLEN ~ cap` one share with an auto-generated id (`*`).
    /// Returns the entry id. Approximate trimming keeps the hot path cheap.
    pub async fn publish(&self, share: &SharedAcceptedShareOwned) -> Result<String, StreamError> {
        let json = serde_json::to_string(share)?;
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
}

/// A [`SharedAcceptedShareSink`] that publishes each accepted share onto the
/// Redis stream — the Core's fan-out target in `core` mode.
///
/// Because it *is* a sink, the Core reuses the unchanged in-process composite
/// (which stamps `share_id` + `mode` + `group_id`) and simply fans out to
/// this one sink instead of the engine sinks. The share it receives is
/// already stamped, so the published owned record carries everything the
/// Satellite's sinks need.
/// Off-loop publish buffer. An `XADD` is sub-millisecond at realistic
/// share rates, so this only fills if Redis publishing stalls. On overflow
/// we drop (best-effort — the miner already got its accept) rather than
/// block the stratum read loop. ~32 s of headroom at 250 shares/s.
const PUBLISH_BUFFER: usize = 8192;

pub struct ProducingSink {
    tx: mpsc::Sender<SharedAcceptedShareOwned>,
    dropped: Arc<AtomicU64>,
}

impl ProducingSink {
    pub fn new(producer: AcceptedShareProducer) -> Self {
        let (tx, mut rx) = mpsc::channel::<SharedAcceptedShareOwned>(PUBLISH_BUFFER);
        // Drain task: the `XADD` round-trip lives HERE, off the stratum read
        // loop, so a slow / head-of-line-blocked Redis connection can never
        // add share-ack latency (the loop already acked the share in ~40µs).
        tokio::spawn(async move {
            while let Some(owned) = rx.recv().await {
                if let Err(e) = producer.publish(&owned).await {
                    tracing::warn!(
                        error = %e,
                        share_id = %owned.share_id,
                        "share-stream: publish failed (share's accounting deferred)"
                    );
                }
            }
        });
        Self {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }
}

#[async_trait]
impl SharedAcceptedShareSink for ProducingSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        // Non-blocking hand-off to the drain task. The owned conversion is
        // the same allocation the publish path always made; `try_send` is a
        // few atomics + a move. No `.await` on a network round-trip here.
        let owned = share.to_owned_record();
        if self.tx.try_send(owned).is_err() {
            // Buffer full (publish lagging) or drain task gone — drop the
            // share's stream publish + count. Log on power-of-two crossings
            // to surface a sustained stall without flooding.
            let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_power_of_two() {
                tracing::warn!(
                    dropped_total = n,
                    "share-stream: publish buffer full — dropping accepted share (stream publish lagging)"
                );
            }
        }
    }
}

/// A [`SharedRejectedShareSink`] that publishes each rejected share onto the
/// Redis stream — the Core's rejected fan-out target in `core` mode. Mirrors
/// [`ProducingSink`]: the Core's rejected composite stamps the `group_id`
/// first, so the published owned record carries everything the Satellite's
/// reject sinks need.
pub struct ProducingRejectedSink {
    tx: mpsc::Sender<SharedRejectedShareOwned>,
    dropped: Arc<AtomicU64>,
}

impl ProducingRejectedSink {
    pub fn new(producer: StreamProducer<SharedRejectedShareOwned>) -> Self {
        let (tx, mut rx) = mpsc::channel::<SharedRejectedShareOwned>(PUBLISH_BUFFER);
        // Drain task — same off-loop pattern as `ProducingSink`: the XADD
        // never runs in the stratum read loop.
        tokio::spawn(async move {
            while let Some(owned) = rx.recv().await {
                if let Err(e) = producer.publish(&owned).await {
                    tracing::warn!(
                        error = %e,
                        "rejected-share-stream: publish failed (reject counter deferred)"
                    );
                }
            }
        });
        Self {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }
}

#[async_trait]
impl SharedRejectedShareSink for ProducingRejectedSink {
    async fn record_rejected(&self, share: SharedRejectedShare<'_>) {
        let owned = share.to_owned_record();
        if self.tx.try_send(owned).is_err() {
            let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_power_of_two() {
                tracing::warn!(
                    dropped_total = n,
                    "rejected-share-stream: publish buffer full — dropping rejected share (publish lagging)"
                );
            }
        }
    }
}

/// One consumed entry: its stream id + the reconstructed owned share.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsumedShare {
    pub id: String,
    pub share: SharedAcceptedShareOwned,
}

/// Reads accepted shares from a Redis stream via a consumer group. A given
/// `(group, consumer)` pair is one logical reader; on restart the Satellite
/// reuses the same names and reclaims its pending entries via
/// [`Self::read_pending`].
#[derive(Clone)]
pub struct AcceptedShareConsumer {
    conn: ConnectionManager,
    stream_key: String,
    group: String,
    consumer: String,
}

impl AcceptedShareConsumer {
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
        }
    }

    /// Create the consumer group if absent (`MKSTREAM`, starting at id `0` so
    /// nothing already in the stream is skipped). Idempotent: a `BUSYGROUP`
    /// error (group already exists) is treated as success.
    pub async fn ensure_group(&self) -> Result<(), StreamError> {
        let mut conn = self.conn.clone();
        let res: Result<(), RedisError> = conn
            .xgroup_create_mkstream(&self.stream_key, &self.group, "0")
            .await;
        match res {
            Ok(()) => Ok(()),
            // Group already exists — fine.
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
    ) -> Result<Vec<ConsumedShare>, StreamError> {
        let opts = StreamReadOptions::default()
            .group(&self.group, &self.consumer)
            .count(count)
            .block(block_ms);
        let mut conn = self.conn.clone();
        let reply: StreamReadReply = conn
            .xread_options(&[&self.stream_key], &[">"], &opts)
            .await?;
        self.parse(reply)
    }

    /// Re-read this consumer's pending (delivered-but-unacked) entries from
    /// the start (`0`) — the resume path after a restart, so an entry whose
    /// apply crashed before `XACK` is redelivered (and the dedup marker
    /// makes the re-apply a no-op).
    pub async fn read_pending(&self, count: usize) -> Result<Vec<ConsumedShare>, StreamError> {
        let opts = StreamReadOptions::default()
            .group(&self.group, &self.consumer)
            .count(count);
        let mut conn = self.conn.clone();
        let reply: StreamReadReply = conn
            .xread_options(&[&self.stream_key], &["0"], &opts)
            .await?;
        self.parse(reply)
    }

    /// Drain one batch of **new** entries: read up to `count` (blocking up
    /// to `block_ms`), dispatch each — in entry order — to every sink, then
    /// `XACK`. Returns the number processed (`0` on timeout).
    ///
    /// The dispatch drives the *same* [`SharedAcceptedShareSink`] impls the
    /// engines expose — one sink entrypoint regardless of transport (the
    /// equivalence seam). Acking *after* dispatch is safe across a crash
    /// because the money sinks dedup on `share_id`: a redelivered,
    /// already-applied share is a no-op.
    pub async fn drain_new(
        &self,
        sinks: &[Arc<dyn SharedAcceptedShareSink>],
        count: usize,
        block_ms: usize,
    ) -> Result<usize, StreamError> {
        let batch = self.read_new(count, block_ms).await?;
        self.dispatch_and_ack(&batch, sinks).await?;
        Ok(batch.len())
    }

    /// Drain this consumer's **pending** (delivered-but-unacked) entries —
    /// the restart-resume path. Same dispatch + ack as [`Self::drain_new`].
    pub async fn drain_pending(
        &self,
        sinks: &[Arc<dyn SharedAcceptedShareSink>],
        count: usize,
    ) -> Result<usize, StreamError> {
        let batch = self.read_pending(count).await?;
        self.dispatch_and_ack(&batch, sinks).await?;
        Ok(batch.len())
    }

    async fn dispatch_and_ack(
        &self,
        batch: &[ConsumedShare],
        sinks: &[Arc<dyn SharedAcceptedShareSink>],
    ) -> Result<(), StreamError> {
        if batch.is_empty() {
            return Ok(());
        }
        for cs in batch {
            let view = cs.share.as_view();
            for sink in sinks {
                sink.record_accepted(view).await;
            }
        }
        let ids: Vec<String> = batch.iter().map(|c| c.id.clone()).collect();
        self.ack(&ids).await?;
        Ok(())
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

    fn parse(&self, reply: StreamReadReply) -> Result<Vec<ConsumedShare>, StreamError> {
        let mut out = Vec::new();
        for key in reply.keys {
            for entry in key.ids {
                let raw = entry
                    .map
                    .get(FIELD)
                    .ok_or_else(|| StreamError::MissingField {
                        id: entry.id.clone(),
                    })?;
                let json: String = redis::from_redis_value(raw)?;
                let share: SharedAcceptedShareOwned = serde_json::from_str(&json)?;
                out.push(ConsumedShare {
                    id: entry.id,
                    share,
                });
            }
        }
        Ok(out)
    }
}

// ── Generic typed transport ─────────────────────────────────────────
//
// A minimal reusable Redis-stream producer/consumer over any serde type —
// the transport for low-volume Core→Satellite event streams (e.g.
// block-found). The accepted-share path keeps its own specialised types
// above (the consumer there fans out to `SharedAcceptedShareSink`s); this
// generic pair just moves typed values + leaves dispatch to the caller.

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
}

/// One consumed entry: its stream id + the reconstructed value.
#[derive(Debug, Clone, PartialEq)]
pub struct Consumed<T> {
    pub id: String,
    pub value: T,
}

/// Reads `T` values from a Redis stream via a consumer group. Mirrors
/// [`AcceptedShareConsumer`]'s raw read/ack surface but returns typed values
/// and leaves dispatch to the caller (block-found has a single handler, not a
/// sink fan-out).
#[derive(Clone)]
pub struct StreamConsumer<T> {
    conn: ConnectionManager,
    stream_key: String,
    group: String,
    consumer: String,
    _marker: PhantomData<fn() -> T>,
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
            _marker: PhantomData,
        }
    }

    /// Create the consumer group if absent (`MKSTREAM`, from id `0` — replays
    /// the whole stream history on first creation). Idempotent: a `BUSYGROUP`
    /// error is treated as success. Use for **idempotent** consumers (e.g. the
    /// ledger apply, guarded by PG `UNIQUE`), where replaying history is a safe
    /// no-op. For non-idempotent consumers (notifications) use
    /// [`Self::ensure_group_at_tail`] so a first start doesn't re-fire history.
    pub async fn ensure_group(&self) -> Result<(), StreamError> {
        self.ensure_group_from("0").await
    }

    /// Create the consumer group if absent starting at the tail (`$` — only
    /// entries added *after* creation). Idempotent (`BUSYGROUP` = success), so
    /// an existing group keeps its offset and isn't reset. Use for
    /// non-idempotent consumers (the notify fan-out): a freshly-added group on
    /// a stream that already has history must NOT replay it — that would re-fire
    /// a push for every historical block / device event.
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
        self.parse(reply)
    }

    /// Re-read this consumer's pending (delivered-but-unacked) entries from
    /// the start (`0`) — the restart-resume path.
    pub async fn read_pending(&self, count: usize) -> Result<Vec<Consumed<T>>, StreamError> {
        let opts = StreamReadOptions::default()
            .group(&self.group, &self.consumer)
            .count(count);
        let mut conn = self.conn.clone();
        let reply: StreamReadReply = conn
            .xread_options(&[&self.stream_key], &["0"], &opts)
            .await?;
        self.parse(reply)
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

    fn parse(&self, reply: StreamReadReply) -> Result<Vec<Consumed<T>>, StreamError> {
        let mut out = Vec::new();
        for key in reply.keys {
            for entry in key.ids {
                let raw = entry
                    .map
                    .get(FIELD)
                    .ok_or_else(|| StreamError::MissingField {
                        id: entry.id.clone(),
                    })?;
                let json: String = redis::from_redis_value(raw)?;
                let value: T = serde_json::from_str(&json)?;
                out.push(Consumed {
                    id: entry.id,
                    value,
                });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    //! Integration tests against a local docker-Redis at
    //! `redis://127.0.0.1:16379` (override with `BP_REDIS_URL`). Each test
    //! uses a distinct logical DB + stream key and skips cleanly if Redis
    //! isn't reachable.
    #![allow(clippy::print_stderr)]

    use super::*;
    use bp_share_hook::MiningMode;
    use redis::Client;

    const DEFAULT_URL: &str = "redis://127.0.0.1:16379";

    async fn connect_or_skip(db: u8) -> Option<ConnectionManager> {
        let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
        let url = format!("{base}/{db}");
        let client = Client::open(url).ok()?;
        let mut conn = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            ConnectionManager::new(client),
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

    /// Open a SECOND connection to a DB already prepared by
    /// [`connect_or_skip`] — does NOT flush (the first connection owns
    /// setup). Production runs the producer (Core) and the blocking
    /// consumer (Satellite) as separate processes on separate
    /// connections; a blocking `XREADGROUP … BLOCK` would otherwise
    /// head-of-line-block a deferred `XADD` sharing the same multiplexed
    /// connection.
    async fn connect_peer(db: u8) -> Option<ConnectionManager> {
        let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
        let url = format!("{base}/{db}");
        let client = Client::open(url).ok()?;
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            ConnectionManager::new(client),
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
            ts_ms: 1_700_000_000_000,
            share_id: share_id.into(),
            mode,
            group_id: group_id.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn round_trip_produce_consume_ack() {
        let Some(conn) = connect_or_skip(12).await else {
            return;
        };
        let key = "bp:test:shares:accepted";
        let producer = AcceptedShareProducer::new(conn.clone(), key);
        let consumer = AcceptedShareConsumer::new(conn.clone(), key, "money", "c1");
        consumer.ensure_group().await.expect("ensure_group");

        let s1 = sample("ep1:0", MiningMode::Pplns, None);
        let s2 = sample("ep1:1", MiningMode::GroupSolo, Some("group-xyz"));
        producer.publish(&s1).await.expect("publish s1");
        producer.publish(&s2).await.expect("publish s2");

        let got = consumer.read_new(10, 1000).await.expect("read_new");
        assert_eq!(got.len(), 2, "both shares delivered");
        // Reconstructed records are byte-identical, in produce order.
        assert_eq!(got[0].share, s1);
        assert_eq!(got[1].share, s2);

        // Ack both → no longer pending.
        let ids: Vec<String> = got.iter().map(|c| c.id.clone()).collect();
        assert_eq!(consumer.ack(&ids).await.expect("ack"), 2);
        let pending = consumer.read_pending(10).await.expect("read_pending");
        assert!(pending.is_empty(), "acked entries must not remain pending");
    }

    #[tokio::test]
    async fn unacked_entry_redelivers_via_pending() {
        // Simulates a consumer crash: deliver (marks pending), do NOT ack,
        // then re-read the pending entry list (the restart-resume path).
        let Some(conn) = connect_or_skip(13).await else {
            return;
        };
        let key = "bp:test:shares:accepted2";
        let producer = AcceptedShareProducer::new(conn.clone(), key);
        let consumer = AcceptedShareConsumer::new(conn.clone(), key, "money", "c1");
        consumer.ensure_group().await.expect("ensure_group");

        producer
            .publish(&sample("ep1:0", MiningMode::Pplns, None))
            .await
            .expect("publish");

        let first = consumer.read_new(10, 1000).await.expect("read_new");
        assert_eq!(first.len(), 1);

        // No ack → still pending. The resume path re-reads it.
        let pending = consumer.read_pending(10).await.expect("read_pending");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].share.share_id, "ep1:0");
    }

    #[tokio::test]
    async fn ensure_group_is_idempotent() {
        let Some(conn) = connect_or_skip(14).await else {
            return;
        };
        let key = "bp:test:shares:accepted3";
        let consumer = AcceptedShareConsumer::new(conn.clone(), key, "money", "c1");
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

    #[tokio::test]
    async fn drain_new_dispatches_to_sinks_in_order_and_acks() {
        let Some(conn) = connect_or_skip(15).await else {
            return;
        };
        let key = "bp:test:shares:accepted4";
        let producer = AcceptedShareProducer::new(conn.clone(), key);
        let consumer = AcceptedShareConsumer::new(conn.clone(), key, "money", "c1");
        consumer.ensure_group().await.expect("ensure_group");

        producer
            .publish(&sample("ep1:0", MiningMode::Pplns, None))
            .await
            .expect("publish");
        producer
            .publish(&sample("ep1:1", MiningMode::GroupSolo, Some("g")))
            .await
            .expect("publish");

        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sinks: Vec<Arc<dyn SharedAcceptedShareSink>> = vec![Arc::new(RecordingSink {
            ids: recorded.clone(),
        })];

        let n = consumer
            .drain_new(&sinks, 10, 1000)
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

    #[tokio::test]
    async fn producing_sink_publishes_each_accepted_share() {
        // DBs 0–15 only (valkey default `databases 16`); keep ≤ 15.
        let Some(consumer_conn) = connect_or_skip(11).await else {
            return;
        };
        // Producer holds its own connection — the sink's XADD is deferred
        // to a drain task, so it must not share the multiplexed socket the
        // consumer blocks on (mirrors the Core/Satellite process split).
        let Some(producer_conn) = connect_peer(11).await else {
            return;
        };
        let key = "bp:test:shares:accepted5";
        let consumer = AcceptedShareConsumer::new(consumer_conn, key, "money", "c1");
        consumer.ensure_group().await.expect("ensure_group");

        let sink = ProducingSink::new(AcceptedShareProducer::new(producer_conn, key));
        let owned = sample("ep1:0", MiningMode::Pplns, None);
        // Drive the sink with a stamped view, exactly as the composite would.
        sink.record_accepted(owned.as_view()).await;

        let got = consumer.read_new(10, 1000).await.expect("read_new");
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].share, owned,
            "the produced record round-trips intact"
        );
    }

    /// The rejected producing sink publishes a (group_id-stamped) rejected
    /// share onto the rejected stream; the Satellite reads the owned record
    /// back intact via the generic consumer.
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

    /// The generic `StreamProducer<T>`/`StreamConsumer<T>` move typed values
    /// through a consumer group: round-trip new entries, then prove a
    /// delivered-but-unacked entry is replayed via `read_pending` (the
    /// at-least-once redelivery the block-found apply relies on).
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

    /// `ensure_group_at_tail` (`$`) on a stream that already has history must
    /// NOT replay it — the notify consumers (block-found notify + device-status)
    /// rely on this so a first start doesn't re-fire a push for every historical
    /// block / event. Contrasted against the `0`-started group, which does.
    #[tokio::test]
    async fn ensure_group_at_tail_skips_history() {
        let Some(conn) = connect_or_skip(11).await else {
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

    /// The producer caps stream length (`MAXLEN ~`) so a stuck consumer can't
    /// grow Redis without bound. Approximate trimming keeps at least the cap
    /// but may keep up to a macro-node more — so we assert it trimmed well
    /// below the produced count, not an exact length.
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
