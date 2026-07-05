// SPDX-License-Identifier: AGPL-3.0-or-later

//! Buffered share-touch flusher.
//!
//! On the share hot path we collect per-session updates (best-diff sample,
//! current vardiff target, channel count, `updatedAt`) in a shared
//! [`TouchBuffer`] and flush them every [`flush_interval`](super::config)
//! via a single bulk `UPDATE ... FROM unnest(...)` statement, instead of
//! N synchronous DB hits per second on a busy pool.
//!
//! Buffer collapses duplicates per `(address, clientName, sessionId)` —
//! the latest sample wins for `currentDifficulty`/`channelCount`/`updatedAt`,
//! the maximum wins for `bestDifficulty`. On flush failure, the snapshot
//! is folded back into the live buffer for retry on the next tick.
//!
//! `hashRate` is **not** handled here — it's owned by the
//! [`crate::hashrate_sampler`], which writes a self-zeroing 2-min moving
//! average on its own cadence. Writing it from both paths would let the
//! 30s touch flush clobber the sampler's value every other tick.

use std::sync::Mutex;

use bp_db::bulk_touch_clients_for_share;
use hashbrown::{Equivalent, HashMap};
use sqlx::PgPool;
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};
use tracing::{debug, warn};

/// Buffer key. Matches the natural PK of the per-share UPDATE
/// (address + clientName + sessionId).
#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct TouchKey {
    pub address: String,
    pub client_name: String,
    pub session_id: String,
}

/// Borrowed view of a [`TouchKey`] for allocation-free map lookups. The
/// share hot path builds one of these (three `&str`, no heap) and passes
/// it to both the touch buffer and the hashrate sampler; an owned
/// `TouchKey` is materialised only when a session is first inserted.
///
/// Relies on `hashbrown`'s [`Equivalent`] lookup (std's `Borrow`-based
/// lookup can't express a borrowed composite key without allocating).
#[derive(Clone, Copy)]
pub(crate) struct TouchKeyRef<'a> {
    pub address: &'a str,
    pub client_name: &'a str,
    pub session_id: &'a str,
}

impl TouchKeyRef<'_> {
    /// Materialise the owned key — called only on the cold insert path.
    pub(crate) fn to_key(self) -> TouchKey {
        TouchKey {
            address: self.address.to_string(),
            client_name: self.client_name.to_string(),
            session_id: self.session_id.to_string(),
        }
    }
}

// `Hash` must feed the hasher the same bytes as `TouchKey`'s derived
// `Hash` so a `TouchKeyRef` lookup lands on a `TouchKey`-inserted entry:
// derive(Hash) on the struct hashes address, client_name, session_id in
// declaration order, and `str`/`String` hash identically — so we hash the
// same three in the same order. The `hashbrown_lookup_matches_owned_key`
// test pins this invariant.
impl std::hash::Hash for TouchKeyRef<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address.hash(state);
        self.client_name.hash(state);
        self.session_id.hash(state);
    }
}

impl Equivalent<TouchKey> for TouchKeyRef<'_> {
    fn equivalent(&self, key: &TouchKey) -> bool {
        self.address == key.address.as_str()
            && self.client_name == key.client_name.as_str()
            && self.session_id == key.session_id.as_str()
    }
}

/// One coalesced sample for a `TouchKey`. `share_diff` is the running
/// maximum across all shares seen since the last flush; the other
/// fields hold the latest observed value.
#[derive(Clone)]
pub(crate) struct TouchEntry {
    pub share_diff: f32,
    pub current_diff: Option<f32>,
    pub channel_count: i32,
    pub updated_at_ms: i64,
}

/// Shared buffer. Cloning the `Arc<TouchBuffer>` is the standard pattern
/// — the sink writes into it on every share, the flusher drains it on
/// every tick.
///
/// Locking is a plain `std::sync::Mutex`: no critical section here spans an
/// `.await` (record merges into the map; the flusher drains before the DB
/// round-trip), so an async mutex would be pure overhead on the hot path.
pub(crate) struct TouchBuffer {
    inner: Mutex<HashMap<TouchKey, TouchEntry>>,
}

impl Default for TouchBuffer {
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl TouchBuffer {
    /// Lock the map, recovering the guard if a previous holder panicked
    /// (poisoning). The critical sections here can't panic, but recovering
    /// instead of `.expect()`-panicking keeps a stray poison from turning
    /// every subsequent accepted share into a panic — same posture as the
    /// engine's shutdown path.
    fn guard(&self) -> std::sync::MutexGuard<'_, HashMap<TouchKey, TouchEntry>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Insert or merge a sample. `share_diff` takes the running max,
    /// the optionals overwrite only when `Some`, `updated_at_ms` takes
    /// the max (out-of-order shares mustn't roll the timestamp back).
    ///
    /// Takes a borrowed [`TouchKeyRef`] and allocates an owned key only on
    /// the first insert: after a session's first share in a flush window,
    /// every subsequent share is a zero-allocation `get_mut` lookup.
    pub(crate) fn record(
        &self,
        key: TouchKeyRef<'_>,
        share_diff: f32,
        current_diff: Option<f32>,
        channel_count: i32,
        updated_at_ms: i64,
    ) {
        let mut guard = self.guard();
        if let Some(e) = guard.get_mut(&key) {
            if share_diff > e.share_diff {
                e.share_diff = share_diff;
            }
            if current_diff.is_some() {
                e.current_diff = current_diff;
            }
            // Latest sample wins: a rejoin/leave changes the channel
            // count, the freshest share reflects the current bundle size.
            e.channel_count = channel_count;
            if updated_at_ms > e.updated_at_ms {
                e.updated_at_ms = updated_at_ms;
            }
        } else {
            guard.insert(
                key.to_key(),
                TouchEntry {
                    share_diff,
                    current_diff,
                    channel_count,
                    updated_at_ms,
                },
            );
        }
    }

    /// Drain everything currently buffered. Empties the buffer in one
    /// lock-pass. Returns the owned snapshot.
    fn drain(&self) -> HashMap<TouchKey, TouchEntry> {
        let mut guard = self.guard();
        std::mem::take(&mut *guard)
    }

    /// Fold a previously-drained snapshot back into the live buffer
    /// after a failed flush. Live writes (concurrent shares that landed
    /// after the drain) are newer than the snapshot, so for the
    /// "latest-wins" fields they win unconditionally — the snapshot
    /// only fills `None` slots. For `share_diff` we still take the
    /// running max (kommutativ).
    fn rebuffer(&self, snap: HashMap<TouchKey, TouchEntry>) {
        let mut guard = self.guard();
        for (k, v) in snap {
            guard
                .entry(k)
                .and_modify(|e| {
                    if v.share_diff > e.share_diff {
                        e.share_diff = v.share_diff;
                    }
                    if e.current_diff.is_none() {
                        e.current_diff = v.current_diff;
                    }
                    if v.updated_at_ms > e.updated_at_ms {
                        e.updated_at_ms = v.updated_at_ms;
                    }
                })
                .or_insert(v);
        }
    }

    /// Snapshot size — used by tests + lib metrics surface.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.guard().len()
    }
}

/// One flush pass. Drains the buffer, executes the bulk UPDATE, and
/// rebuffers the snapshot if the UPDATE fails. Returns the number of
/// rows the DB reported affected.
async fn flush_once(buffer: &TouchBuffer, pool: &PgPool) -> u64 {
    let snapshot = buffer.drain();
    if snapshot.is_empty() {
        return 0;
    }

    let n = snapshot.len();
    let mut addresses = Vec::with_capacity(n);
    let mut client_names = Vec::with_capacity(n);
    let mut session_ids = Vec::with_capacity(n);
    let mut share_diffs = Vec::with_capacity(n);
    let mut current_diffs = Vec::with_capacity(n);
    let mut channel_counts = Vec::with_capacity(n);
    let mut updated_ats = Vec::with_capacity(n);

    for (k, v) in &snapshot {
        addresses.push(k.address.clone());
        client_names.push(k.client_name.clone());
        session_ids.push(k.session_id.clone());
        share_diffs.push(v.share_diff);
        current_diffs.push(v.current_diff);
        channel_counts.push(v.channel_count);
        updated_ats.push(v.updated_at_ms);
    }

    match bulk_touch_clients_for_share(
        pool,
        &addresses,
        &client_names,
        &session_ids,
        &share_diffs,
        &current_diffs,
        &channel_counts,
        &updated_ats,
    )
    .await
    {
        Ok(rows) => {
            debug!(buffered = n, affected = rows, "client touch buffer flushed");
            rows
        }
        Err(e) => {
            warn!(
                error = %e,
                buffered = n,
                "client touch buffer flush failed; rebuffering for retry"
            );
            buffer.rebuffer(snapshot);
            0
        }
    }
}

/// Spawned 30s flush loop. Returns when `shutdown_rx` resolves; before
/// returning it executes a final flush so a graceful shutdown drains
/// the residual buffer.
pub(crate) async fn run_flush_loop(
    buffer: std::sync::Arc<TouchBuffer>,
    pool: PgPool,
    flush_interval: Duration,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let start = Instant::now() + flush_interval;
    let mut ticker = tokio::time::interval_at(start, flush_interval);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                flush_once(&buffer, &pool).await;
            }
            _ = &mut shutdown_rx => {
                debug!("client touch flush loop received shutdown");
                break;
            }
        }
    }
    let drained = flush_once(&buffer, &pool).await;
    debug!(final_drained = drained, "client touch flush loop exited");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Borrow an owned key as the ref the record path takes.
    fn kref(k: &TouchKey) -> TouchKeyRef<'_> {
        TouchKeyRef {
            address: &k.address,
            client_name: &k.client_name,
            session_id: &k.session_id,
        }
    }

    #[test]
    fn record_merges_running_max_and_latest() {
        let buf = TouchBuffer::default();
        let key = TouchKey {
            address: "addr".into(),
            client_name: "wkr".into(),
            session_id: "sess".into(),
        };
        buf.record(kref(&key), 100.0, Some(8.0), 1, 1000);
        buf.record(kref(&key), 50.0, Some(16.0), 1, 2000);
        buf.record(kref(&key), 200.0, None, 3, 1500);

        let snap = buf.drain();
        assert_eq!(snap.len(), 1);
        let entry = snap.get(&key).unwrap();
        assert_eq!(entry.share_diff, 200.0, "running max");
        assert_eq!(entry.current_diff, Some(16.0), "latest non-None");
        assert_eq!(entry.channel_count, 3, "latest sample wins");
        assert_eq!(
            entry.updated_at_ms, 2000,
            "max timestamp (out-of-order safe)"
        );
    }

    #[test]
    fn rebuffer_merges_with_live_writes() {
        let buf = TouchBuffer::default();
        let key = TouchKey {
            address: "addr".into(),
            client_name: "wkr".into(),
            session_id: "sess".into(),
        };
        // Simulate "drained" snapshot.
        let mut snap = HashMap::new();
        snap.insert(
            key.clone(),
            TouchEntry {
                share_diff: 100.0,
                current_diff: Some(8.0),
                channel_count: 1,
                updated_at_ms: 1000,
            },
        );
        // Meanwhile a new share landed.
        buf.record(kref(&key), 50.0, Some(16.0), 1, 2000);
        // DB failed → rebuffer the snapshot.
        buf.rebuffer(snap);

        let merged = buf.drain();
        let entry = merged.get(&key).unwrap();
        assert_eq!(entry.share_diff, 100.0, "max of rebuffered+live");
        assert_eq!(
            entry.current_diff,
            Some(16.0),
            "live write keeps its value (rebuffer doesn't clobber non-None with older value)"
        );
        assert_eq!(entry.updated_at_ms, 2000);
    }

    #[test]
    fn drain_empties_buffer() {
        let buf = TouchBuffer::default();
        let key = TouchKey {
            address: "a".into(),
            client_name: "c".into(),
            session_id: "s".into(),
        };
        buf.record(kref(&key), 1.0, None, 1, 1);
        assert_eq!(buf.len(), 1);
        let snap = buf.drain();
        assert_eq!(snap.len(), 1);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn hashbrown_lookup_matches_owned_key() {
        let buf = TouchBuffer::default();
        let r = |sid| TouchKeyRef {
            address: "bc1qxyz",
            client_name: "rig1",
            session_id: sid,
        };
        // Two shares, same identity: the second must find the entry the
        // first inserted (borrowed-ref lookup lands on the owned key) and
        // coalesce, not duplicate.
        buf.record(r("abc123"), 42.0, Some(8.0), 1, 1000);
        buf.record(r("abc123"), 99.0, None, 1, 2000);
        assert_eq!(buf.len(), 1, "same identity must coalesce, not duplicate");
        // A different session_id must be a distinct entry (no false hit).
        buf.record(r("zzz999"), 1.0, None, 1, 3000);
        assert_eq!(buf.len(), 2, "distinct identity is a separate entry");

        // The coalesced entry is retrievable by the equivalent OWNED key —
        // proves TouchKeyRef and TouchKey hash + compare identically.
        let snap = buf.drain();
        let owned = TouchKey {
            address: "bc1qxyz".into(),
            client_name: "rig1".into(),
            session_id: "abc123".into(),
        };
        let e = snap
            .get(&owned)
            .expect("owned-key lookup finds the ref-inserted entry");
        assert_eq!(e.share_diff, 99.0, "running max across both records");
    }
}
