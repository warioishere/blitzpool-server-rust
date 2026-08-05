// SPDX-License-Identifier: AGPL-3.0-or-later

//! Buffered per-slot max-difficulty writes.
//!
//! `client_difficulty_statistics_entity` holds one row per `(address, worker,
//! hour-slot)` with the highest share difficulty seen in that slot. The sink
//! used to upsert **inline** whenever a share set a new max, which is cheap in
//! the middle of a slot and a burst at its edges: after a process restart, and
//! at every hour rollover, every miner's first share is a new max and the next
//! ones keep raising it. Measured on prod 2026-08-05: 2.5 minutes after a
//! payout restart, one of those single-row upserts took **4.88 s**.
//!
//! So it batches now, like the session-row touch path next door: shares merge
//! into an in-memory map, one bulk upsert per tick drains it. Same shape on
//! purpose — [`crate::touch_buffer`] is the reference for record/drain/rebuffer.
//!
//! Two things this fixes beyond the burst:
//!
//! - The old inline path kept a `(address, worker) -> (slot, max)` cache to
//!   decide whether a share was a new max. On an upsert FAILURE the cache
//!   already said "persisted", so that slot's max was lost until a higher share
//!   arrived. This buffer rebuffers instead, so a failed flush is retried.
//! - The cache and the buffer coalesce the same thing, so keeping both would
//!   be two maps and two hot-path locks for one concept. The cache is gone.

use std::sync::Mutex;
use std::time::Duration;

use bp_db::bulk_upsert_client_difficulty_statistics;
use hashbrown::{Equivalent, HashMap};
use sqlx::PgPool;
use tokio::sync::oneshot;
use tracing::{debug, warn};

/// Buffer key — the table's conflict target, so a duplicate is impossible by
/// construction. That matters: a multi-row `ON CONFLICT DO UPDATE` that would
/// touch the same row twice is a hard Postgres error, not a merge.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct DiffStatKey {
    pub(crate) address: String,
    pub(crate) worker: String,
    pub(crate) slot_ms: i64,
}

/// Borrowed key for allocation-free lookups — the share hot path builds one of
/// these (two `&str` + an `i64`, no heap) and only the cold insert path
/// materialises an owned [`DiffStatKey`]. Relies on `hashbrown`'s
/// [`Equivalent`]; std's `Borrow`-based lookup cannot express a borrowed
/// composite key without allocating.
#[derive(Clone, Copy)]
pub(crate) struct DiffStatKeyRef<'a> {
    pub(crate) address: &'a str,
    pub(crate) worker: &'a str,
    pub(crate) slot_ms: i64,
}

impl DiffStatKeyRef<'_> {
    /// Materialise the owned key — cold insert path only.
    fn to_key(self) -> DiffStatKey {
        DiffStatKey {
            address: self.address.to_string(),
            worker: self.worker.to_string(),
            slot_ms: self.slot_ms,
        }
    }
}

// Must feed the hasher exactly what `DiffStatKey`'s derived `Hash` feeds it, or
// a ref lookup would never land on an owned-key entry: derive(Hash) hashes the
// fields in declaration order, and `str`/`String` hash identically. The
// `a_borrowed_lookup_finds_the_owned_key` test pins this.
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

/// Shared buffer. The sink writes into it per accepted share, the flusher
/// drains it per tick.
///
/// Plain `std::sync::Mutex`: no critical section spans an `.await` — record
/// merges into the map, the flusher drains before the DB round-trip.
#[derive(Default)]
pub(crate) struct DiffStatBuffer {
    inner: Mutex<HashMap<DiffStatKey, DiffStatEntry>>,
}

impl DiffStatBuffer {
    /// Lock, recovering the guard if a previous holder panicked. A stray
    /// poison must not turn every subsequent accepted share into a panic.
    fn guard(&self) -> std::sync::MutexGuard<'_, HashMap<DiffStatKey, DiffStatEntry>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Merge one sample: `max_difficulty` takes the running max, `updated_at_ms`
    /// the max (an out-of-order share must not roll the timestamp back).
    ///
    /// Both merges are commutative and idempotent, which is what makes
    /// [`Self::rebuffer`] trivially correct.
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

    /// Drain everything buffered, in one lock pass.
    fn drain(&self) -> HashMap<DiffStatKey, DiffStatEntry> {
        let mut guard = self.guard();
        std::mem::take(&mut *guard)
    }

    /// Fold a drained snapshot back after a failed flush. Both fields take the
    /// max, so merge order does not matter and a live write that landed after
    /// the drain cannot be lowered by the older snapshot.
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

/// One flush pass: drain, bulk-upsert, rebuffer on failure. Returns the rows
/// the DB reported affected.
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
            // Unlike a hashrate sample, a per-slot max is NOT ephemeral: drop
            // it and the slot under-reports until a higher share happens to
            // arrive. So it goes back into the buffer.
            warn!(error = %e, buffered = n, "diff-stat buffer: flush failed; rebuffering");
            buffer.rebuffer(snapshot);
            0
        }
    }
}

/// Spawned flush loop. Ticks every `interval`, and drains once more on
/// shutdown so a graceful stop does not discard the current window.
pub(crate) async fn run_flush_loop(
    buffer: std::sync::Arc<DiffStatBuffer>,
    pool: PgPool,
    interval: Duration,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    // `interval_at`, not `interval`: the latter fires its FIRST tick
    // immediately, which flushes an empty buffer at startup for nothing — and
    // makes "the share path never writes, the loop does" untestable, because
    // that first tick lands on whatever the caller buffered before the spawned
    // task was first polled. Same choice as `touch_buffer::run_flush_loop`.
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    // Skip missed ticks rather than burst-firing them: after a stall, catching
    // up would just drain an already-empty buffer several times over.
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

    /// The whole point of the buffer: N shares of one slot collapse to ONE
    /// row, carrying the highest difficulty — not the last one seen.
    #[test]
    fn record_keeps_the_max_and_collapses_to_one_entry() {
        let b = DiffStatBuffer::default();
        assert!(b.record(key("a1", "w", 3_600_000), 100.0, 10));
        assert!(b.record(key("a1", "w", 3_600_000), 900.0, 11));
        // A LOWER share must not lower the stored max, and must report that
        // it raised nothing.
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

    /// The manual `Hash` for the borrowed key must produce the same bytes as
    /// the derived one for the owned key, or every hot-path lookup would miss
    /// and each share would insert a fresh entry — silently turning the
    /// coalescing buffer into an unbounded append log with duplicate conflict
    /// keys, which the bulk upsert then rejects outright.
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

    /// The slot is part of the key, so an hour rollover is a NEW row rather
    /// than an overwrite — otherwise the previous hour's max would be lost
    /// before it was ever flushed.
    #[test]
    fn a_slot_rollover_is_a_separate_row() {
        let b = DiffStatBuffer::default();
        b.record(key("a1", "w", 3_600_000), 500.0, 10);
        b.record(key("a1", "w", 7_200_000), 20.0, 20);
        assert_eq!(b.len(), 2);
    }

    /// A failed flush must not lose the window, and must not lower a value a
    /// concurrent share raised in the meantime.
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
