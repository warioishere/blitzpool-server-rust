// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coalesces per-session share updates in a [`TouchBuffer`] and flushes them
//! periodically: the session's best onto its Postgres row, the rest into the
//! `client:live:*` Redis hashes ([`crate::live_store`]), instead of a write
//! per share. `hash_rate` is vardiff's session rate; once
//! the shares stop, [`crate::hashrate_watchdog`] zeroes it.

use std::sync::Mutex;

use hashbrown::{Equivalent, HashMap};
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};
use tracing::{debug, warn};

use sqlx::PgPool;

use crate::live_store::LiveSessionStore;

/// The session's natural key (address + clientName + sessionId).
#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct TouchKey {
    pub address: String,
    pub client_name: String,
    pub session_id: String,
}

/// Borrowed [`TouchKey`] for allocation-free lookups on the share hot path;
/// an owned key is built only on first insert. Needs `hashbrown`'s
/// [`Equivalent`]: std's `Borrow` cannot express a borrowed composite key.
#[derive(Clone, Copy)]
pub(crate) struct TouchKeyRef<'a> {
    pub address: &'a str,
    pub client_name: &'a str,
    pub session_id: &'a str,
}

impl TouchKeyRef<'_> {
    pub(crate) fn to_key(self) -> TouchKey {
        TouchKey {
            address: self.address.to_string(),
            client_name: self.client_name.to_string(),
            session_id: self.session_id.to_string(),
        }
    }
}

// Must hash exactly like `TouchKey`'s derived `Hash` (same fields, same
// order) or a ref lookup misses the owned entry; pinned by
// `hashbrown_lookup_matches_owned_key`.
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
    pub share_diff: f64,
    pub current_diff: Option<f32>,
    pub hash_rate: Option<f64>,
    pub channel_count: i32,
    pub updated_at_ms: i64,
}

/// Shared between the share sink and the flusher. A plain `std::sync::Mutex`
/// because no critical section spans an `.await`.
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
    /// Recovers from poisoning so one panic cannot make every later share panic.
    fn guard(&self) -> std::sync::MutexGuard<'_, HashMap<TouchKey, TouchEntry>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Insert or merge a sample: `share_diff` and `updated_at_ms` take the
    /// max (out-of-order shares must not roll the timestamp back), the
    /// optionals overwrite only when `Some`. A `hash_rate` of 0 is vardiff
    /// before its first estimate and keeps the stored rate.
    pub(crate) fn record(
        &self,
        key: TouchKeyRef<'_>,
        share_diff: f64,
        current_diff: Option<f32>,
        hash_rate: f64,
        channel_count: i32,
        updated_at_ms: i64,
    ) {
        // Postgres sorts NaN above every number, so one would pin the
        // session's best for good; non-finite live fields poison readers' sums.
        if !share_diff.is_finite() {
            return;
        }
        let current_diff = current_diff.filter(|d| d.is_finite());
        let hash_rate = Some(hash_rate).filter(|r| r.is_finite() && *r > 0.0);
        let mut guard = self.guard();
        if let Some(e) = guard.get_mut(&key) {
            if share_diff > e.share_diff {
                e.share_diff = share_diff;
            }
            if current_diff.is_some() {
                e.current_diff = current_diff;
            }
            if hash_rate.is_some() {
                e.hash_rate = hash_rate;
            }
            // Latest wins: the freshest share reflects the current channel count.
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
                    hash_rate,
                    channel_count,
                    updated_at_ms,
                },
            );
        }
    }

    /// Take the whole buffer in one lock pass.
    fn drain(&self) -> HashMap<TouchKey, TouchEntry> {
        let mut guard = self.guard();
        std::mem::take(&mut *guard)
    }

    /// Fold a drained snapshot back after a failed flush. Live writes are
    /// newer, so for latest-wins fields the snapshot only fills `None` slots.
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
                    if e.hash_rate.is_none() {
                        e.hash_rate = v.hash_rate;
                    }
                    if v.updated_at_ms > e.updated_at_ms {
                        e.updated_at_ms = v.updated_at_ms;
                    }
                })
                .or_insert(v);
        }
    }

    /// Number of buffered sessions.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.guard().len()
    }
}

/// One flush pass; rebuffers on a failed write and returns sessions written.
/// Both writes are idempotent, so a retry after a half-failed pass is safe.
/// Without a live store the live half is dropped, not rebuffered, or the
/// buffer would grow without bound.
pub(crate) async fn flush_once(
    buffer: &TouchBuffer,
    pool: &PgPool,
    live: Option<&LiveSessionStore>,
) -> u64 {
    let snapshot = buffer.drain();
    if snapshot.is_empty() {
        return 0;
    }
    let n = snapshot.len();
    if let Err(e) = raise_bests(pool, &snapshot).await {
        warn!(
            error = %e,
            buffered = n,
            "session best write failed; rebuffering for retry"
        );
        buffer.rebuffer(snapshot);
        return 0;
    }
    let Some(store) = live else {
        warn!(
            dropped = n,
            "no live store configured; session touch samples dropped"
        );
        return 0;
    };
    match store.write_touch_batch(&snapshot).await {
        Ok(()) => {
            debug!(buffered = n, "client touch buffer flushed to live hashes");
            n as u64
        }
        Err(e) => {
            warn!(
                error = %e,
                buffered = n,
                "live-session touch write failed; rebuffering for retry"
            );
            buffer.rebuffer(snapshot);
            0
        }
    }
}

/// Write each session's flushed best onto its row where it is a new record.
async fn raise_bests(
    pool: &PgPool,
    snapshot: &HashMap<TouchKey, TouchEntry>,
) -> Result<u64, bp_db::DbError> {
    let mut addresses = Vec::with_capacity(snapshot.len());
    let mut client_names = Vec::with_capacity(snapshot.len());
    let mut session_ids = Vec::with_capacity(snapshot.len());
    let mut bests = Vec::with_capacity(snapshot.len());
    for (k, v) in snapshot.iter().filter(|(_, v)| v.share_diff > 0.0) {
        addresses.push(k.address.clone());
        client_names.push(k.client_name.clone());
        session_ids.push(k.session_id.clone());
        bests.push(v.share_diff);
    }
    bp_db::raise_client_best_difficulties(pool, &addresses, &client_names, &session_ids, &bests)
        .await
}

/// Flush loop; flushes once more on shutdown to drain the residual buffer.
pub(crate) async fn run_flush_loop(
    buffer: std::sync::Arc<TouchBuffer>,
    pool: PgPool,
    live: Option<std::sync::Arc<LiveSessionStore>>,
    flush_interval: Duration,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let start = Instant::now() + flush_interval;
    let mut ticker = tokio::time::interval_at(start, flush_interval);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                flush_once(&buffer, &pool, live.as_deref()).await;
            }
            _ = &mut shutdown_rx => {
                debug!("client touch flush loop received shutdown");
                break;
            }
        }
    }
    // The shutdown drain is the last TTL refresh those sessions get;
    // afterwards they age out on the TTL like any silent session.
    let drained = flush_once(&buffer, &pool, live.as_deref()).await;
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
        buf.record(kref(&key), 100.0, Some(8.0), 1.0e12, 1, 1000);
        buf.record(kref(&key), 50.0, Some(16.0), 2.0e12, 1, 2000);
        buf.record(kref(&key), 200.0, None, 0.0, 3, 1500);

        let snap = buf.drain();
        assert_eq!(snap.len(), 1);
        let entry = snap.get(&key).unwrap();
        assert_eq!(entry.share_diff, 200.0, "running max");
        assert_eq!(entry.current_diff, Some(16.0), "latest non-None");
        assert_eq!(
            entry.hash_rate,
            Some(2.0e12),
            "latest positive rate; vardiff's 0 does not clobber it"
        );
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
                hash_rate: Some(1.0e12),
                channel_count: 1,
                updated_at_ms: 1000,
            },
        );
        // Meanwhile a new share landed.
        buf.record(kref(&key), 50.0, Some(16.0), 2.0e12, 1, 2000);
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
        assert_eq!(entry.hash_rate, Some(2.0e12), "same for the live rate");
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
        buf.record(kref(&key), 1.0, None, 0.0, 1, 1);
        assert_eq!(buf.len(), 1);
        let snap = buf.drain();
        assert_eq!(snap.len(), 1);
        assert_eq!(buf.len(), 0);
    }

    /// Pins that non-finite samples never enter the buffer.
    #[test]
    fn non_finite_samples_are_dropped_at_the_door() {
        let b = TouchBuffer::default();
        let k = TouchKey {
            address: "addr".into(),
            client_name: "wkr".into(),
            session_id: "sess".into(),
        };
        b.record(kref(&k), f64::INFINITY, None, 0.0, 1, 1);
        b.record(kref(&k), f64::NAN, None, 0.0, 1, 1);
        assert_eq!(b.len(), 0, "an unusable share_diff creates no entry");

        // A finite share with a non-finite vardiff target and rate keeps
        // the entry but drops the unusable fields.
        b.record(kref(&k), 5.0, Some(f32::INFINITY), f64::NAN, 1, 1);
        assert_eq!(b.len(), 1);
        let snap = b.drain();
        let e = snap.values().next().expect("entry");
        assert_eq!(e.share_diff, 5.0);
        assert_eq!(e.current_diff, None, "non-finite current_diff is dropped");
        assert_eq!(e.hash_rate, None, "non-finite hash_rate is dropped");
    }

    #[test]
    fn hashbrown_lookup_matches_owned_key() {
        let buf = TouchBuffer::default();
        let r = |sid| TouchKeyRef {
            address: "bc1qxyz",
            client_name: "rig1",
            session_id: sid,
        };
        // The second share must find the first's entry via the borrowed ref.
        buf.record(r("abc123"), 42.0, Some(8.0), 0.0, 1, 1000);
        buf.record(r("abc123"), 99.0, None, 0.0, 1, 2000);
        assert_eq!(buf.len(), 1, "same identity must coalesce, not duplicate");
        // A different session_id must be a distinct entry (no false hit).
        buf.record(r("zzz999"), 1.0, None, 0.0, 1, 3000);
        assert_eq!(buf.len(), 2, "distinct identity is a separate entry");

        // Retrievable by the owned key: both hash and compare identically.
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
