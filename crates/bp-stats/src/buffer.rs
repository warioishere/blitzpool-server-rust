// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hot-path write buffers that a periodic flush drains in bulk. The delta
//! buffers only snapshot on `drain` and subtract on `confirm`, so writes made
//! during a flush survive it. Locking is the caller's job (each accumulator
//! holds a `Mutex`).

use std::collections::HashMap;
use std::hash::Hash;

// ─── BufferRecord trait ─────────────────────────────────────────────────────

/// A record of numeric fields used as the value in [`RecordDeltaBuffer`].
pub trait BufferRecord: Default + Clone {
    /// True iff every field is zero (or negative); such buckets are left out
    /// of `drain` snapshots.
    fn is_zero(&self) -> bool;

    fn add_assign(&mut self, rhs: &Self);

    /// Subtract field-wise, clamping at zero so a residual never turns
    /// negative. Returns `true` when the bucket is empty and can be removed.
    fn sub_assign_clamped(&mut self, rhs: &Self) -> bool;
}

// ─── NumberDeltaBuffer ──────────────────────────────────────────────────────

/// Additive `f64` deltas keyed by `K`. `drain` returns only positive values
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
    K: Clone + Eq + Hash,
{
    /// Zero and non-finite deltas are ignored so one NaN cannot poison a key.
    pub fn add(&mut self, key: K, delta: f64) {
        if delta == 0.0 || !delta.is_finite() {
            return;
        }
        *self.map.entry(key).or_insert(0.0) += delta;
    }

    pub fn get(&self, key: &K) -> Option<f64> {
        self.map.get(key).copied()
    }

    /// Snapshot positive entries. Does **not** clear the buffer.
    pub fn drain(&self) -> HashMap<K, f64> {
        let mut out = HashMap::with_capacity(self.map.len());
        for (k, v) in &self.map {
            if *v > 0.0 {
                out.insert(k.clone(), *v);
            }
        }
        out
    }

    /// Subtract a drained snapshot; keys left at ≤ 0 are removed.
    pub fn confirm(&mut self, snapshot: &HashMap<K, f64>) {
        for (k, flushed) in snapshot {
            if let Some(current) = self.map.get_mut(k) {
                *current -= flushed;
                if *current <= 0.0 {
                    self.map.remove(k);
                }
            }
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
    O: Clone + Eq + Hash,
    I: Clone + Eq + Hash,
{
    pub fn add(&mut self, outer: O, inner: I, delta: f64) {
        if delta == 0.0 || !delta.is_finite() {
            return;
        }
        let entry = self.map.entry(outer).or_default();
        *entry.entry(inner).or_insert(0.0) += delta;
    }

    /// Deep snapshot of positive entries; does not clear the buffer.
    pub fn drain(&self) -> HashMap<O, HashMap<I, f64>> {
        let mut out = HashMap::with_capacity(self.map.len());
        for (o, inner) in &self.map {
            let mut copy = HashMap::with_capacity(inner.len());
            for (k, v) in inner {
                if *v > 0.0 {
                    copy.insert(k.clone(), *v);
                }
            }
            if !copy.is_empty() {
                out.insert(o.clone(), copy);
            }
        }
        out
    }

    /// Subtract a drained snapshot; emptied keys are removed.
    pub fn confirm(&mut self, snapshot: &HashMap<O, HashMap<I, f64>>) {
        for (o, inner_snap) in snapshot {
            let Some(current_inner) = self.map.get_mut(o) else {
                continue;
            };
            for (k, flushed) in inner_snap {
                if let Some(have) = current_inner.get_mut(k) {
                    *have -= flushed;
                    if *have <= 0.0 {
                        current_inner.remove(k);
                    }
                }
            }
            if current_inner.is_empty() {
                self.map.remove(o);
            }
        }
    }
}

// ─── RecordDeltaBuffer ──────────────────────────────────────────────────────

/// Map of key → multi-field record, additive per field.
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
    K: Clone + Eq + Hash,
    R: BufferRecord,
{
    pub fn add(&mut self, key: K, delta: &R) {
        if delta.is_zero() {
            return;
        }
        self.map.entry(key).or_default().add_assign(delta);
    }

    /// Snapshot every non-zero bucket. Does **not** clear the buffer.
    pub fn drain(&self) -> HashMap<K, R> {
        let mut out = HashMap::with_capacity(self.map.len());
        for (k, r) in &self.map {
            if !r.is_zero() {
                out.insert(k.clone(), r.clone());
            }
        }
        out
    }

    /// Subtract a drained snapshot; emptied buckets are removed.
    pub fn confirm(&mut self, snapshot: &HashMap<K, R>) {
        for (k, snap) in snapshot {
            let Some(current) = self.map.get_mut(k) else {
                continue;
            };
            let all_zero = current.sub_assign_clamped(snap);
            if all_zero {
                self.map.remove(k);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── NumberDeltaBuffer ───────────────────────────────────────────────

    #[test]
    fn number_buffer_drains_positive_entries_only() {
        let mut buf: NumberDeltaBuffer<&'static str> = NumberDeltaBuffer::new();
        buf.add("a", 5.0);
        buf.add("b", -3.0); // counted internally but filtered by drain
        buf.add("c", 0.0); // no-op
        let snap = buf.drain();
        assert_eq!(snap.get("a"), Some(&5.0));
        assert!(!snap.contains_key("b"));
        assert!(!snap.contains_key("c"));
    }

    #[test]
    fn number_buffer_drain_is_non_clearing() {
        let mut buf: NumberDeltaBuffer<&'static str> = NumberDeltaBuffer::new();
        buf.add("a", 10.0);
        let _ = buf.drain();
        // Still in the buffer until confirm() runs.
        assert_eq!(buf.get(&"a"), Some(10.0));
    }

    #[test]
    fn number_buffer_confirm_subtracts_snapshot() {
        let mut buf: NumberDeltaBuffer<&'static str> = NumberDeltaBuffer::new();
        buf.add("a", 10.0);
        let snap = buf.drain();
        // Concurrent write during the flush.
        buf.add("a", 3.0);
        buf.confirm(&snap);
        // Residual = 10 + 3 - 10 = 3.
        assert_eq!(buf.get(&"a"), Some(3.0));
    }

    #[test]
    fn number_buffer_confirm_removes_zero_residual() {
        let mut buf: NumberDeltaBuffer<&'static str> = NumberDeltaBuffer::new();
        buf.add("a", 10.0);
        let snap = buf.drain();
        buf.confirm(&snap);
        assert_eq!(buf.get(&"a"), None);
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
    fn nested_buffer_add_and_drain() {
        let mut buf: NestedDeltaBuffer<i64, &'static str> = NestedDeltaBuffer::new();
        buf.add(1_000, "solo", 100.0);
        buf.add(1_000, "pplns", 50.0);
        buf.add(2_000, "solo", 25.0);
        let snap = buf.drain();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.get(&1_000).unwrap().get("solo"), Some(&100.0));
        assert_eq!(snap.get(&1_000).unwrap().get("pplns"), Some(&50.0));
        assert_eq!(snap.get(&2_000).unwrap().get("solo"), Some(&25.0));
    }

    #[test]
    fn nested_buffer_confirm_drops_empty_outer_keys() {
        let mut buf: NestedDeltaBuffer<i64, &'static str> = NestedDeltaBuffer::new();
        buf.add(1_000, "solo", 100.0);
        let snap = buf.drain();
        buf.confirm(&snap);
        assert!(buf.is_empty());
    }

    #[test]
    fn nested_buffer_concurrent_writes_survive_confirm() {
        let mut buf: NestedDeltaBuffer<i64, &'static str> = NestedDeltaBuffer::new();
        buf.add(1_000, "solo", 100.0);
        let snap = buf.drain();
        // Concurrent writes during the flush.
        buf.add(1_000, "solo", 30.0);
        buf.add(1_000, "pplns", 7.0);
        buf.confirm(&snap);
        let residual = buf.drain();
        assert_eq!(residual.get(&1_000).unwrap().get("solo"), Some(&30.0));
        assert_eq!(residual.get(&1_000).unwrap().get("pplns"), Some(&7.0));
    }

    // ─── RecordDeltaBuffer ───────────────────────────────────────────────

    #[derive(Default, Clone, Debug, PartialEq)]
    struct TwoField {
        a: f64,
        b: f64,
    }

    impl BufferRecord for TwoField {
        fn is_zero(&self) -> bool {
            self.a == 0.0 && self.b == 0.0
        }
        fn add_assign(&mut self, rhs: &Self) {
            self.a += rhs.a;
            self.b += rhs.b;
        }
        fn sub_assign_clamped(&mut self, rhs: &Self) -> bool {
            self.a -= rhs.a;
            self.b -= rhs.b;
            self.a <= 0.0 && self.b <= 0.0
        }
    }

    #[test]
    fn record_buffer_zero_input_is_a_no_op() {
        let mut buf: RecordDeltaBuffer<&'static str, TwoField> = RecordDeltaBuffer::new();
        buf.add("k", &TwoField { a: 0.0, b: 0.0 });
        assert!(buf.is_empty());
    }

    #[test]
    fn record_buffer_drain_skips_all_zero_buckets() {
        // A write and its negation leave an allocated all-zero bucket.
        let mut buf: RecordDeltaBuffer<&'static str, TwoField> = RecordDeltaBuffer::new();
        buf.add("k", &TwoField { a: 5.0, b: 3.0 });
        buf.add("k", &TwoField { a: -5.0, b: -3.0 });
        let snap = buf.drain();
        assert!(!snap.contains_key("k"));
    }

    #[test]
    fn record_buffer_confirm_subtracts_and_drops_zero() {
        let mut buf: RecordDeltaBuffer<&'static str, TwoField> = RecordDeltaBuffer::new();
        buf.add("k", &TwoField { a: 10.0, b: 7.0 });
        let snap = buf.drain();
        // Concurrent partial-overlap write.
        buf.add("k", &TwoField { a: 2.0, b: 0.0 });
        buf.confirm(&snap);
        let residual = buf.drain();
        assert_eq!(residual.get("k"), Some(&TwoField { a: 2.0, b: 0.0 }));
    }
}
