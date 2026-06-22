// SPDX-License-Identifier: AGPL-3.0-or-later

//! 60-second `lastAcceptedShareAt` flush buffer.
//!
//! Per-share PG-write is too expensive on the hot path (a busy pool
//! sees thousands of shares per minute, but the abandoned-balance
//! sweep tolerates 60-second drift trivially). Instead the hot path
//! calls [`TouchBuffer::mark`] (lock + insert, ~100ns), and a
//! background tokio task drains the buffer every 60 seconds and
//! issues one bulk `UPDATE pplns_balance` per drain.
//!
//! On flush failure the snapshot is `rebuffer`-ed back into the
//! buffer (newer-wins policy: if the hot path recorded a fresher
//! timestamp for an address during the failed flush, that fresher
//! value survives the merge). Next tick retries.
//!
//! Atomicity is achieved via `std::sync::Mutex` + `mem::take`.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::Duration;

use bp_db::{bulk_update_pplns_last_accepted_share_at, DbError, TouchUpdate};
use sqlx::PgPool;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Default flush cadence — 60 seconds.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// Lock-around-HashMap buffer for `(address → latest timestamp ms)`.
///
/// `mark` is sync + non-throwing for the hot path. `drain` snapshots
/// the buffer and resets it for the next window. `rebuffer` re-merges
/// a drained snapshot back on flush failure.
///
/// `mark` and `drain`/`rebuffer` are serialized by a `Mutex`; for a
/// typical pool (≲10k shares/s) the contention is negligible (each
/// `mark` is a HashMap-insert in nanoseconds). Reach for `parking_lot`
/// or a sharded shape only if profiling later shows contention.
#[derive(Debug, Default)]
pub struct TouchBuffer {
    inner: Mutex<HashMap<String, i64>>,
}

impl TouchBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hot-path entry. Coalesces multiple marks for the same address
    /// within one flush window via "newest-wins" — the buffer holds
    /// the most-recent `ts_ms` per address.
    pub fn mark(&self, address: &str, ts_ms: i64) {
        if address.is_empty() {
            return;
        }
        let mut buf = self.inner.lock();
        // Avoid allocating a `String` key on the hot path when the address
        // is already buffered (the common case: a miner submits many shares
        // per flush window). Only the first mark per (address, window) owns
        // the key.
        if let Some(entry) = buf.get_mut(address) {
            if ts_ms > *entry {
                *entry = ts_ms;
            }
        } else {
            buf.insert(address.to_string(), ts_ms);
        }
    }

    /// Drain the current buffer into a `Vec<TouchUpdate>` and reset
    /// the in-memory map. Idempotent: called multiple times in
    /// succession the second call returns an empty Vec.
    pub fn drain(&self) -> Vec<TouchUpdate> {
        let snapshot = {
            let mut buf = self.inner.lock();
            std::mem::take(&mut *buf)
        };
        snapshot
            .into_iter()
            .map(|(address, ts)| TouchUpdate {
                address,
                last_accepted_share_at_ms: ts,
            })
            .collect()
    }

    /// Re-merge a previously-drained snapshot back into the buffer
    /// (flush retry path). Existing entries that are newer than the
    /// snapshot value are preserved — newest-wins.
    pub fn rebuffer(&self, drained: Vec<TouchUpdate>) {
        let mut buf = self.inner.lock();
        for tu in drained {
            buf.entry(tu.address)
                .and_modify(|cur| {
                    if tu.last_accepted_share_at_ms > *cur {
                        *cur = tu.last_accepted_share_at_ms;
                    }
                })
                .or_insert(tu.last_accepted_share_at_ms);
        }
    }

    /// Snapshot the current buffer size (lock-bounded).
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── Background flush task ───────────────────────────────────────────

/// One-shot flush attempt. Returns `Ok(n)` with the number of rows
/// actually updated, or `Err((rebuffered, err))` after rebuffering
/// the snapshot on failure.
///
/// Exposed so [`crate::engine::PplnsEngine::shutdown`] can do a final
/// drain before exit.
pub async fn flush_once(pool: &PgPool, buffer: &TouchBuffer) -> Result<u64, DbError> {
    let snapshot = buffer.drain();
    if snapshot.is_empty() {
        return Ok(0);
    }
    match bulk_update_pplns_last_accepted_share_at(pool, &snapshot).await {
        Ok(n) => Ok(n),
        Err(e) => {
            // On failure: re-merge the drained snapshot so next tick
            // retries. Newer-wins policy preserves any hot-path touch
            // that landed during the failed flush.
            buffer.rebuffer(snapshot);
            Err(e)
        }
    }
}

/// Spawn the periodic-flush background task. Returns the
/// `JoinHandle` so the engine can `await` it during shutdown.
///
/// `cancel_rx` lets the engine signal a graceful exit: on cancel the
/// task drains one final time before returning.
pub fn spawn_flush_task(
    pool: PgPool,
    buffer: std::sync::Arc<TouchBuffer>,
    interval: Duration,
    mut cancel_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        // Skip the first immediate tick — `tokio::time::interval`
        // fires at t=0 by default which would race the first share.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await; // consume the initial t=0 tick

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    match flush_once(&pool, &buffer).await {
                        Ok(0) => {}
                        Ok(n) => debug!(rows_updated = n, "pplns touch-buffer flush ok"),
                        Err(e) => warn!(error = %e, "pplns touch-buffer flush failed; rebuffered"),
                    }
                }
                changed = cancel_rx.changed() => {
                    if changed.is_err() || *cancel_rx.borrow() {
                        // Final drain before exit.
                        if !buffer.is_empty() {
                            if let Err(e) = flush_once(&pool, &buffer).await {
                                warn!(error = %e, "pplns touch-buffer final flush failed");
                            }
                        }
                        break;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_inserts_new_address() {
        let buf = TouchBuffer::new();
        buf.mark("bc1qfoo", 1_700_000_000_000);
        assert_eq!(buf.len(), 1);
        let drained = buf.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].address, "bc1qfoo");
        assert_eq!(drained[0].last_accepted_share_at_ms, 1_700_000_000_000);
    }

    #[test]
    fn mark_newer_wins_for_same_address() {
        let buf = TouchBuffer::new();
        buf.mark("bc1qfoo", 1_700_000_000_000);
        buf.mark("bc1qfoo", 1_700_000_999_000);
        buf.mark("bc1qfoo", 1_700_000_500_000); // older — should not overwrite
        let drained = buf.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].last_accepted_share_at_ms, 1_700_000_999_000);
    }

    #[test]
    fn mark_empty_address_is_noop() {
        let buf = TouchBuffer::new();
        buf.mark("", 1_700_000_000_000);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn drain_resets_buffer() {
        let buf = TouchBuffer::new();
        buf.mark("bc1qa", 1);
        buf.mark("bc1qb", 2);
        let _ = buf.drain();
        assert!(buf.is_empty());
        // Second drain on empty buffer returns empty Vec.
        assert!(buf.drain().is_empty());
    }

    #[test]
    fn rebuffer_merges_newer_wins() {
        let buf = TouchBuffer::new();
        // Pretend the buffer has fresher touches arriving during a
        // failed flush.
        buf.mark("bc1qfoo", 1_700_000_999_000);
        buf.mark("bc1qbar", 1_700_000_500_000);

        // Rebuffer a snapshot with older values for foo + a new addr.
        let drained = vec![
            TouchUpdate {
                address: "bc1qfoo".to_string(),
                last_accepted_share_at_ms: 1_700_000_100_000,
            },
            TouchUpdate {
                address: "bc1qnew".to_string(),
                last_accepted_share_at_ms: 1_700_000_700_000,
            },
        ];
        buf.rebuffer(drained);

        let mut all: HashMap<String, i64> = buf
            .drain()
            .into_iter()
            .map(|tu| (tu.address, tu.last_accepted_share_at_ms))
            .collect();
        assert_eq!(all.len(), 3);
        // foo: hot-path value preserved (newer than rebuffer)
        assert_eq!(all.remove("bc1qfoo").unwrap(), 1_700_000_999_000);
        // bar: untouched
        assert_eq!(all.remove("bc1qbar").unwrap(), 1_700_000_500_000);
        // new: inserted from rebuffer
        assert_eq!(all.remove("bc1qnew").unwrap(), 1_700_000_700_000);
    }

    #[test]
    fn many_addresses_drain_in_one_shot() {
        let buf = TouchBuffer::new();
        for i in 0..1000 {
            buf.mark(&format!("bc1q{i}"), 1_700_000_000_000 + i as i64);
        }
        let drained = buf.drain();
        assert_eq!(drained.len(), 1000);
        assert!(buf.is_empty());
    }
}
