// SPDX-License-Identifier: AGPL-3.0-or-later

//! Buffered share-touch flusher.
//!
//! On the share hot path we collect per-session updates (best-diff sample,
//! current vardiff target, hashrate estimate, `updatedAt`) in a shared
//! [`TouchBuffer`] and flush them every [`flush_interval`](super::config)
//! via a single bulk `UPDATE ... FROM unnest(...)` statement, instead of
//! N synchronous DB hits per second on a busy pool.
//!
//! Buffer collapses duplicates per `(address, clientName, sessionId)` —
//! the latest sample wins for `currentDifficulty`/`hashRate`/`updatedAt`,
//! the maximum wins for `bestDifficulty`. On flush failure, the snapshot
//! is folded back into the live buffer for retry on the next tick.

use std::collections::HashMap;

use bp_db::bulk_touch_clients_for_share;
use sqlx::PgPool;
use tokio::sync::{oneshot, Mutex};
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

/// One coalesced sample for a `TouchKey`. `share_diff` is the running
/// maximum across all shares seen since the last flush; the other
/// fields hold the latest observed value.
#[derive(Clone)]
pub(crate) struct TouchEntry {
    pub share_diff: f32,
    pub current_diff: Option<f32>,
    pub hash_rate: Option<f64>,
    pub updated_at_ms: i64,
}

/// Shared buffer. Cloning the `Arc<TouchBuffer>` is the standard pattern
/// — the sink writes into it on every share, the flusher drains it on
/// every tick.
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
    /// Insert or merge a sample. `share_diff` takes the running max,
    /// the optionals overwrite only when `Some`, `updated_at_ms` takes
    /// the max (out-of-order shares mustn't roll the timestamp back).
    pub(crate) async fn record(
        &self,
        key: TouchKey,
        share_diff: f32,
        current_diff: Option<f32>,
        hash_rate: Option<f64>,
        updated_at_ms: i64,
    ) {
        let mut guard = self.inner.lock().await;
        guard
            .entry(key)
            .and_modify(|e| {
                if share_diff > e.share_diff {
                    e.share_diff = share_diff;
                }
                if current_diff.is_some() {
                    e.current_diff = current_diff;
                }
                if hash_rate.is_some() {
                    e.hash_rate = hash_rate;
                }
                if updated_at_ms > e.updated_at_ms {
                    e.updated_at_ms = updated_at_ms;
                }
            })
            .or_insert(TouchEntry {
                share_diff,
                current_diff,
                hash_rate,
                updated_at_ms,
            });
    }

    /// Drain everything currently buffered. Empties the buffer in one
    /// lock-pass. Returns the owned snapshot.
    async fn drain(&self) -> HashMap<TouchKey, TouchEntry> {
        let mut guard = self.inner.lock().await;
        std::mem::take(&mut *guard)
    }

    /// Fold a previously-drained snapshot back into the live buffer
    /// after a failed flush. Live writes (concurrent shares that landed
    /// after the drain) are newer than the snapshot, so for the
    /// "latest-wins" fields they win unconditionally — the snapshot
    /// only fills `None` slots. For `share_diff` we still take the
    /// running max (kommutativ).
    async fn rebuffer(&self, snap: HashMap<TouchKey, TouchEntry>) {
        let mut guard = self.inner.lock().await;
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

    /// Snapshot size — used by tests + lib metrics surface.
    #[cfg(test)]
    pub(crate) async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }
}

/// One flush pass. Drains the buffer, executes the bulk UPDATE, and
/// rebuffers the snapshot if the UPDATE fails. Returns the number of
/// rows the DB reported affected.
async fn flush_once(buffer: &TouchBuffer, pool: &PgPool) -> u64 {
    let snapshot = buffer.drain().await;
    if snapshot.is_empty() {
        return 0;
    }

    let n = snapshot.len();
    let mut addresses = Vec::with_capacity(n);
    let mut client_names = Vec::with_capacity(n);
    let mut session_ids = Vec::with_capacity(n);
    let mut share_diffs = Vec::with_capacity(n);
    let mut current_diffs = Vec::with_capacity(n);
    let mut hash_rates = Vec::with_capacity(n);
    let mut updated_ats = Vec::with_capacity(n);

    for (k, v) in &snapshot {
        addresses.push(k.address.clone());
        client_names.push(k.client_name.clone());
        session_ids.push(k.session_id.clone());
        share_diffs.push(v.share_diff);
        current_diffs.push(v.current_diff);
        hash_rates.push(v.hash_rate);
        updated_ats.push(v.updated_at_ms);
    }

    match bulk_touch_clients_for_share(
        pool,
        &addresses,
        &client_names,
        &session_ids,
        &share_diffs,
        &current_diffs,
        &hash_rates,
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
            buffer.rebuffer(snapshot).await;
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

    #[tokio::test]
    async fn record_merges_running_max_and_latest() {
        let buf = TouchBuffer::default();
        let key = TouchKey {
            address: "addr".into(),
            client_name: "wkr".into(),
            session_id: "sess".into(),
        };
        buf.record(key.clone(), 100.0, Some(8.0), Some(1.0e9), 1000)
            .await;
        buf.record(key.clone(), 50.0, Some(16.0), None, 2000).await;
        buf.record(key.clone(), 200.0, None, Some(2.0e9), 1500)
            .await;

        let snap = buf.drain().await;
        assert_eq!(snap.len(), 1);
        let entry = snap.get(&key).unwrap();
        assert_eq!(entry.share_diff, 200.0, "running max");
        assert_eq!(entry.current_diff, Some(16.0), "latest non-None");
        assert_eq!(entry.hash_rate, Some(2.0e9), "latest non-None");
        assert_eq!(
            entry.updated_at_ms, 2000,
            "max timestamp (out-of-order safe)"
        );
    }

    #[tokio::test]
    async fn rebuffer_merges_with_live_writes() {
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
                hash_rate: Some(1.0e9),
                updated_at_ms: 1000,
            },
        );
        // Meanwhile a new share landed.
        buf.record(key.clone(), 50.0, Some(16.0), None, 2000).await;
        // DB failed → rebuffer the snapshot.
        buf.rebuffer(snap).await;

        let merged = buf.drain().await;
        let entry = merged.get(&key).unwrap();
        assert_eq!(entry.share_diff, 100.0, "max of rebuffered+live");
        assert_eq!(
            entry.current_diff,
            Some(16.0),
            "live write keeps its value (rebuffer doesn't clobber non-None with older value)"
        );
        assert_eq!(
            entry.hash_rate,
            Some(1.0e9),
            "rebuffer fills None from live"
        );
        assert_eq!(entry.updated_at_ms, 2000);
    }

    #[tokio::test]
    async fn drain_empties_buffer() {
        let buf = TouchBuffer::default();
        let key = TouchKey {
            address: "a".into(),
            client_name: "c".into(),
            session_id: "s".into(),
        };
        buf.record(key, 1.0, None, None, 1).await;
        assert_eq!(buf.len().await, 1);
        let snap = buf.drain().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(buf.len().await, 0);
    }
}
