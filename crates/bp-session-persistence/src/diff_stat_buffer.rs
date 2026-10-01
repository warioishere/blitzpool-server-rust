// SPDX-License-Identifier: AGPL-3.0-or-later

//! Buffered per-`(address, worker, hour-slot)` max-difficulty writes: an
//! inline upsert per new max would burst after a restart and at every hour
//! rollover. A failed flush is rebuffered, so a slot's max is never lost.

use std::sync::Mutex;
use std::time::Duration;

use bp_db::bulk_upsert_client_difficulty_statistics;
use hashbrown::{Equivalent, HashMap};
use sqlx::PgPool;
use tokio::sync::oneshot;
use tracing::{debug, warn};

/// The table's conflict target, so a batch cannot hold a duplicate: a
/// multi-row `ON CONFLICT DO UPDATE` touching one row twice is a hard error.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct DiffStatKey {
    pub(crate) address: String,
    pub(crate) worker: String,
    pub(crate) slot_ms: i64,
}

/// Borrowed key for allocation-free hot-path lookups via `hashbrown`'s
/// [`Equivalent`]; std's `Borrow` cannot express a borrowed composite key.
#[derive(Clone, Copy)]
pub(crate) struct DiffStatKeyRef<'a> {
    pub(crate) address: &'a str,
    pub(crate) worker: &'a str,
    pub(crate) slot_ms: i64,
}

impl DiffStatKeyRef<'_> {
    fn to_key(self) -> DiffStatKey {
        DiffStatKey {
            address: self.address.to_string(),
            worker: self.worker.to_string(),
            slot_ms: self.slot_ms,
        }
    }
}

// Must hash exactly like `DiffStatKey`'s derived `Hash` (fields in declaration
// order), or a ref lookup never lands on an owned-key entry.
impl std::hash::Hash for DiffStatKeyRef<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address.hash(state);
        self.worker.hash(state);
        self.slot_ms.hash(state);
    }
}

impl Equivalent<DiffStatKey> for DiffStatKeyRef<'_> {
    fn equivalent(&self, key: &DiffStatKey) -> bool {
        self.address == key.address.as_str()
            && self.worker == key.worker.as_str()
            && self.slot_ms == key.slot_ms
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DiffStatEntry {
    pub(crate) max_difficulty: f32,
    pub(crate) updated_at_ms: i64,
}

/// Shared buffer: the sink records per share, the flusher drains per tick.
/// A `std::sync::Mutex` suffices because no critical section spans an `.await`.
#[derive(Default)]
pub(crate) struct DiffStatBuffer {
    inner: Mutex<HashMap<DiffStatKey, DiffStatEntry>>,
}

impl DiffStatBuffer {
    /// Recovers from poison so one panic does not turn every later share
    /// into a panic.
    fn guard(&self) -> std::sync::MutexGuard<'_, HashMap<DiffStatKey, DiffStatEntry>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Merge one sample; both fields take the max, so an out-of-order share
    /// cannot roll the timestamp back and [`Self::rebuffer`] is order-free.
    pub(crate) fn record(
        &self,
        key: DiffStatKeyRef<'_>,
        max_difficulty: f32,
        updated_at_ms: i64,
    ) -> bool {
        let mut guard = self.guard();
        if let Some(e) = guard.get_mut(&key) {
            let raised = max_difficulty > e.max_difficulty;
            if raised {
                e.max_difficulty = max_difficulty;
            }
            if updated_at_ms > e.updated_at_ms {
                e.updated_at_ms = updated_at_ms;
            }
            return raised;
        }
        guard.insert(
            key.to_key(),
            DiffStatEntry {
                max_difficulty,
                updated_at_ms,
            },
        );
        true
    }

    fn drain(&self) -> HashMap<DiffStatKey, DiffStatEntry> {
        let mut guard = self.guard();
        std::mem::take(&mut *guard)
    }

    /// Fold a drained snapshot back after a failed flush; taking the max means
    /// a live write that landed after the drain is never lowered.
    fn rebuffer(&self, snap: HashMap<DiffStatKey, DiffStatEntry>) {
        let mut guard = self.guard();
        for (k, v) in snap {
            guard
                .entry(k)
                .and_modify(|e| {
                    if v.max_difficulty > e.max_difficulty {
                        e.max_difficulty = v.max_difficulty;
                    }
                    if v.updated_at_ms > e.updated_at_ms {
                        e.updated_at_ms = v.updated_at_ms;
                    }
                })
                .or_insert(v);
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.guard().len()
    }
}

/// One flush pass: drain, bulk-upsert, rebuffer on failure.
async fn flush_once(buffer: &DiffStatBuffer, pool: &PgPool) -> u64 {
    let snapshot = buffer.drain();
    if snapshot.is_empty() {
        return 0;
    }
    let n = snapshot.len();
    let mut addresses = Vec::with_capacity(n);
    let mut client_names = Vec::with_capacity(n);
    let mut slot_times = Vec::with_capacity(n);
    let mut max_difficulties = Vec::with_capacity(n);
    let mut updated_ats = Vec::with_capacity(n);
    for (k, v) in &snapshot {
        addresses.push(k.address.clone());
        client_names.push(k.worker.clone());
        slot_times.push(k.slot_ms);
        max_difficulties.push(v.max_difficulty);
        updated_ats.push(v.updated_at_ms);
    }

    match bulk_upsert_client_difficulty_statistics(
        pool,
        &addresses,
        &client_names,
        &slot_times,
        &max_difficulties,
        &updated_ats,
    )
    .await
    {
        Ok(rows) => {
            debug!(buffered = n, rows, "diff-stat buffer: flushed");
            rows
        }
        Err(e) => {
            // A per-slot max is not ephemeral: dropped, the slot would
            // under-report for good.
            warn!(error = %e, buffered = n, "diff-stat buffer: flush failed; rebuffering");
            buffer.rebuffer(snapshot);
            0
        }
    }
}

/// Flush loop; drains once more on shutdown so a graceful stop keeps the window.
pub(crate) async fn run_flush_loop(
    buffer: std::sync::Arc<DiffStatBuffer>,
    pool: PgPool,
    interval: Duration,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    // `interval_at`: `interval` would fire its first tick immediately.
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                flush_once(&buffer, &pool).await;
            }
            _ = &mut shutdown_rx => {
                flush_once(&buffer, &pool).await;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key<'a>(addr: &'a str, worker: &'a str, slot: i64) -> DiffStatKeyRef<'a> {
        DiffStatKeyRef {
            address: addr,
            worker,
            slot_ms: slot,
        }
    }

    /// N shares of one slot collapse to one row carrying the highest difficulty.
    #[test]
    fn record_keeps_the_max_and_collapses_to_one_entry() {
        let b = DiffStatBuffer::default();
        assert!(b.record(key("a1", "w", 3_600_000), 100.0, 10));
        assert!(b.record(key("a1", "w", 3_600_000), 900.0, 11));
        assert!(!b.record(key("a1", "w", 3_600_000), 50.0, 12));
        assert_eq!(b.len(), 1, "one slot, one buffered row");

        let snap = b.drain();
        let e = snap.values().next().expect("one entry");
        assert_eq!(e.max_difficulty, 900.0);
        assert_eq!(
            e.updated_at_ms, 12,
            "timestamp still advances on a lower share"
        );
    }

    /// The borrowed key's manual `Hash` matches the owned key's derived one.
    #[test]
    fn a_borrowed_lookup_finds_the_owned_key() {
        let mut map: HashMap<DiffStatKey, u8> = HashMap::new();
        map.insert(
            DiffStatKey {
                address: "bc1qexample".to_string(),
                worker: "rig1".to_string(),
                slot_ms: 3_600_000,
            },
            7,
        );
        assert_eq!(
            map.get(&key("bc1qexample", "rig1", 3_600_000)),
            Some(&7),
            "borrowed lookup must land on the owned entry"
        );
        // And it must not match a neighbour that differs in only one field.
        assert!(map.get(&key("bc1qexample", "rig2", 3_600_000)).is_none());
        assert!(map.get(&key("bc1qexample", "rig1", 7_200_000)).is_none());
    }

    /// An hour rollover is a new row, not an overwrite of the previous hour.
    #[test]
    fn a_slot_rollover_is_a_separate_row() {
        let b = DiffStatBuffer::default();
        b.record(key("a1", "w", 3_600_000), 500.0, 10);
        b.record(key("a1", "w", 7_200_000), 20.0, 20);
        assert_eq!(b.len(), 2);
    }

    /// A rebuffered snapshot never lowers a value raised after the drain.
    #[test]
    fn rebuffer_never_lowers_a_live_write() {
        let b = DiffStatBuffer::default();
        b.record(key("a1", "w", 3_600_000), 100.0, 10);
        let snap = b.drain();
        assert_eq!(b.len(), 0, "drain empties");

        // A share lands after the drain, higher than the snapshot.
        b.record(key("a1", "w", 3_600_000), 700.0, 20);
        b.rebuffer(snap);

        let after = b.drain();
        let e = after.values().next().expect("one entry");
        assert_eq!(
            e.max_difficulty, 700.0,
            "the live 700 survives the older 100"
        );
        assert_eq!(e.updated_at_ms, 20);
    }
}
