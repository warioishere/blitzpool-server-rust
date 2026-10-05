// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hot-path write buffers that a periodic flush empties in bulk: `take`
//! removes what is due, and a failed write hands it back with `restore`,
//! which merges into whatever arrived meanwhile. Locking is the caller's
//! job (each accumulator holds a `Mutex`).

use std::collections::HashMap;
use std::hash::Hash;

// ─── BufferRecord trait ─────────────────────────────────────────────────────

/// A record of numeric fields used as the value in [`RecordDeltaBuffer`].
pub trait BufferRecord: Default + Clone {
    /// True iff every field is zero (or negative); such buckets are left out
    /// of `take`.
    fn is_zero(&self) -> bool;

    /// Merge `rhs` in: sums add, maxima take the larger value.
    fn add_assign(&mut self, rhs: &Self);
}

// ─── NumberDeltaBuffer ──────────────────────────────────────────────────────

/// Additive `f64` deltas keyed by `K`. `take` returns only positive values
/// so the flusher never writes no-op rows.
pub struct NumberDeltaBuffer<K> {
    map: HashMap<K, f64>,
}

impl<K> Default for NumberDeltaBuffer<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K> NumberDeltaBuffer<K> {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl<K> NumberDeltaBuffer<K>
where
    K: Eq + Hash,
{
    /// Zero and non-finite deltas are ignored so one NaN cannot poison a key.
    pub fn add(&mut self, key: K, delta: f64) {
        if delta == 0.0 || !delta.is_finite() {
            return;
        }
        *self.map.entry(key).or_insert(0.0) += delta;
    }

    /// Empty the buffer, returning its positive entries.
    pub fn take(&mut self) -> HashMap<K, f64> {
        let mut out = std::mem::take(&mut self.map);
        out.retain(|_, v| *v > 0.0);
        out
    }

    /// Hand back an unwritten [`Self::take`].
    pub fn restore(&mut self, snapshot: HashMap<K, f64>) {
        for (k, v) in snapshot {
            self.add(k, v);
        }
    }
}

// ─── NestedDeltaBuffer ──────────────────────────────────────────────────────

/// Additive nested map `outer → inner → f64`, e.g. `slot → mode → diff`.
pub struct NestedDeltaBuffer<O, I> {
    map: HashMap<O, HashMap<I, f64>>,
}

impl<O, I> Default for NestedDeltaBuffer<O, I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<O, I> NestedDeltaBuffer<O, I> {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl<O, I> NestedDeltaBuffer<O, I>
where
    O: Eq + Hash,
    I: Eq + Hash,
{
    pub fn add(&mut self, outer: O, inner: I, delta: f64) {
        if delta == 0.0 || !delta.is_finite() {
            return;
        }
        let entry = self.map.entry(outer).or_default();
        *entry.entry(inner).or_insert(0.0) += delta;
    }

    /// Empty the buffer, returning its positive entries.
    pub fn take(&mut self) -> HashMap<O, HashMap<I, f64>> {
        let mut out = std::mem::take(&mut self.map);
        out.retain(|_, inner| {
            inner.retain(|_, v| *v > 0.0);
            !inner.is_empty()
        });
        out
    }

    /// Hand back an unwritten [`Self::take`].
    pub fn restore(&mut self, snapshot: HashMap<O, HashMap<I, f64>>) {
        for (o, inner) in snapshot {
            let entry = self.map.entry(o).or_default();
            for (i, v) in inner {
                *entry.entry(i).or_insert(0.0) += v;
            }
        }
    }
}

// ─── RecordDeltaBuffer ──────────────────────────────────────────────────────

/// Map of key → multi-field record, merged per field.
pub struct RecordDeltaBuffer<K, R: BufferRecord> {
    map: HashMap<K, R>,
}

impl<K, R: BufferRecord> Default for RecordDeltaBuffer<K, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, R: BufferRecord> RecordDeltaBuffer<K, R> {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl<K, R> RecordDeltaBuffer<K, R>
where
    K: Eq + Hash,
    R: BufferRecord,
{
    pub fn add(&mut self, key: K, delta: &R) {
        if delta.is_zero() {
            return;
        }
        self.map.entry(key).or_default().add_assign(delta);
    }

    /// Empty the buffer, returning every non-zero bucket.
    pub fn take(&mut self) -> HashMap<K, R> {
        self.take_where(|_| true)
    }

    /// Remove and return the non-zero buckets whose key matches; the rest
    /// stay buffered.
    pub fn take_where(&mut self, mut due: impl FnMut(&K) -> bool) -> HashMap<K, R> {
        let mut out = HashMap::new();
        for (k, r) in std::mem::take(&mut self.map) {
            if !due(&k) {
                self.map.insert(k, r);
            } else if !r.is_zero() {
                out.insert(k, r);
            }
        }
        out
    }

    /// Hand back an unwritten part of a [`Self::take`].
    pub fn restore(&mut self, snapshot: impl IntoIterator<Item = (K, R)>) {
        for (k, r) in snapshot {
            self.map.entry(k).or_default().add_assign(&r);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── NumberDeltaBuffer ───────────────────────────────────────────────

    #[test]
    fn number_buffer_takes_positive_entries_only() {
        let mut buf: NumberDeltaBuffer<&'static str> = NumberDeltaBuffer::new();
        buf.add("a", 5.0);
        buf.add("b", -3.0); // counted internally but filtered by take
        buf.add("c", 0.0); // no-op
        let snap = buf.take();
        assert_eq!(snap.get("a"), Some(&5.0));
        assert!(!snap.contains_key("b"));
        assert!(!snap.contains_key("c"));
        assert!(buf.is_empty(), "take empties the buffer");
    }

    #[test]
    fn number_buffer_restore_adds_onto_writes_made_during_the_flush() {
        let mut buf: NumberDeltaBuffer<&'static str> = NumberDeltaBuffer::new();
        buf.add("a", 10.0);
        let snap = buf.take();
        // Concurrent write during the flush, which then fails.
        buf.add("a", 3.0);
        buf.restore(snap);
        assert_eq!(buf.take().get("a"), Some(&13.0));
    }

    #[test]
    fn number_buffer_ignores_non_finite() {
        let mut buf: NumberDeltaBuffer<&'static str> = NumberDeltaBuffer::new();
        buf.add("a", f64::NAN);
        buf.add("a", f64::INFINITY);
        buf.add("a", f64::NEG_INFINITY);
        assert!(buf.is_empty());
    }

    // ─── NestedDeltaBuffer ───────────────────────────────────────────────

    #[test]
    fn nested_buffer_add_and_take() {
        let mut buf: NestedDeltaBuffer<i64, &'static str> = NestedDeltaBuffer::new();
        buf.add(1_000, "solo", 100.0);
        buf.add(1_000, "pplns", 50.0);
        buf.add(2_000, "solo", 25.0);
        let snap = buf.take();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.get(&1_000).unwrap().get("solo"), Some(&100.0));
        assert_eq!(snap.get(&1_000).unwrap().get("pplns"), Some(&50.0));
        assert_eq!(snap.get(&2_000).unwrap().get("solo"), Some(&25.0));
        assert!(buf.is_empty());
    }

    #[test]
    fn nested_buffer_restore_adds_onto_writes_made_during_the_flush() {
        let mut buf: NestedDeltaBuffer<i64, &'static str> = NestedDeltaBuffer::new();
        buf.add(1_000, "solo", 100.0);
        let snap = buf.take();
        buf.add(1_000, "solo", 30.0);
        buf.add(1_000, "pplns", 7.0);
        buf.restore(snap);
        let merged = buf.take();
        assert_eq!(merged.get(&1_000).unwrap().get("solo"), Some(&130.0));
        assert_eq!(merged.get(&1_000).unwrap().get("pplns"), Some(&7.0));
    }

    // ─── RecordDeltaBuffer ───────────────────────────────────────────────

    #[derive(Default, Clone, Debug, PartialEq)]
    struct SumAndMax {
        sum: f64,
        max: f64,
    }

    impl BufferRecord for SumAndMax {
        fn is_zero(&self) -> bool {
            self.sum == 0.0 && self.max == 0.0
        }
        fn add_assign(&mut self, rhs: &Self) {
            self.sum += rhs.sum;
            self.max = self.max.max(rhs.max);
        }
    }

    #[test]
    fn record_buffer_zero_input_is_a_no_op() {
        let mut buf: RecordDeltaBuffer<&'static str, SumAndMax> = RecordDeltaBuffer::new();
        buf.add("k", &SumAndMax { sum: 0.0, max: 0.0 });
        assert!(buf.is_empty());
    }

    #[test]
    fn record_buffer_take_skips_all_zero_buckets() {
        // A write and its negation leave an allocated all-zero bucket.
        let mut buf: RecordDeltaBuffer<&'static str, SumAndMax> = RecordDeltaBuffer::new();
        buf.add("k", &SumAndMax { sum: 5.0, max: 0.0 });
        buf.add(
            "k",
            &SumAndMax {
                sum: -5.0,
                max: 0.0,
            },
        );
        assert!(!buf.take().contains_key("k"));
    }

    #[test]
    fn record_buffer_take_where_leaves_the_rest_buffered() {
        let mut buf: RecordDeltaBuffer<i64, SumAndMax> = RecordDeltaBuffer::new();
        buf.add(1, &SumAndMax { sum: 1.0, max: 1.0 });
        buf.add(2, &SumAndMax { sum: 2.0, max: 2.0 });
        let due = buf.take_where(|k| *k < 2);
        assert_eq!(due.keys().copied().collect::<Vec<_>>(), vec![1]);
        assert_eq!(buf.take().keys().copied().collect::<Vec<_>>(), vec![2]);
    }

    #[test]
    fn record_buffer_restore_sums_and_keeps_the_larger_max() {
        let mut buf: RecordDeltaBuffer<&'static str, SumAndMax> = RecordDeltaBuffer::new();
        buf.add(
            "k",
            &SumAndMax {
                sum: 10.0,
                max: 700.0,
            },
        );
        let snap = buf.take();
        // A write during the flush, which then fails.
        buf.add(
            "k",
            &SumAndMax {
                sum: 2.0,
                max: 50.0,
            },
        );
        buf.restore(snap);
        assert_eq!(
            buf.take().get("k"),
            Some(&SumAndMax {
                sum: 12.0,
                max: 700.0
            })
        );
    }
}
