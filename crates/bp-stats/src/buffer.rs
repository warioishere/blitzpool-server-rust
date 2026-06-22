// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generic "hot-path writes, periodic bulk-flush" primitives.
//!
//! Three buffer flavours, each with the same conceptual API:
//!
//! ```text
//! buf.add*  /  buf.set  — hot path, synchronous, non-throwing
//! buf.len()             — count of unflushed keys
//! buf.drain()           — start a flush; returns a snapshot
//! buf.confirm(snap)     — flush succeeded; subtract / clear the snapshot
//! ```
//!
//! Two semantic models, depending on the data shape:
//!
//! - [`SwapBuffer`] — latest-wins-by-key. `drain` clears the buffer and
//!   returns the previous contents.
//! - [`NumberDeltaBuffer`] / [`NestedDeltaBuffer`] / [`RecordDeltaBuffer`] —
//!   additive numeric deltas. `drain` snapshots without clearing; `confirm`
//!   subtracts the flushed amounts so concurrent writes during the flush
//!   are preserved.
//!
//! Locking is the caller's responsibility — each accumulator wraps the
//! appropriate buffer in a `Mutex` so the hot-path lock is held only for
//! the HashMap mutation itself.

use std::collections::HashMap;
use std::hash::Hash;

// ─── BufferRecord trait ─────────────────────────────────────────────────────

/// A record of named numeric fields suitable for use as the value in
/// [`RecordDeltaBuffer`]. The trait drives the drain/confirm machinery:
/// `is_zero` filters out empty buckets from snapshots, `add_assign` is the
/// hot-path increment, `sub_assign_clamped` is the confirm-time
/// subtraction that clamps each field at zero so under-flow from
/// concurrent residuals can't surface as negative numbers.
///
/// All consumers of `RecordDeltaBuffer` derive this trait with a small
/// hand-written impl — there is no proc-macro because the shapes are
/// few and tailored.
pub trait BufferRecord: Default + Clone {
    /// True iff every field is zero (or negative). Used to skip empty
    /// buckets in `drain` snapshots.
    fn is_zero(&self) -> bool;

    /// Add every field of `rhs` to `self`.
    fn add_assign(&mut self, rhs: &Self);

    /// Subtract every field of `rhs` from `self`, clamping each field at
    /// zero. Returns `true` if every field is ≤ 0 after the subtraction
    /// (so the bucket can be removed from the buffer's map).
    fn sub_assign_clamped(&mut self, rhs: &Self) -> bool;
}

// ─── SwapBuffer ─────────────────────────────────────────────────────────────

/// Latest-wins-by-key buffer. `drain` swaps in a fresh empty map and
/// returns the previous one. Concurrent writes after `drain` go to the
/// new map and survive the flush automatically.
pub struct SwapBuffer<K, V> {
    map: HashMap<K, V>,
}

impl<K, V> Default for SwapBuffer<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> SwapBuffer<K, V> {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl<K, V> SwapBuffer<K, V>
where
    K: Eq + Hash,
{
    pub fn set(&mut self, key: K, value: V) {
        self.map.insert(key, value);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Snapshot the buffer and replace with a fresh empty one. New writes
    /// go to the new buffer.
    pub fn drain(&mut self) -> HashMap<K, V> {
        std::mem::take(&mut self.map)
    }

    /// Merge a previously-drained snapshot back into the live buffer after
    /// a flush failure. **Existing entries win** — anything written during
    /// the flush is preserved.
    pub fn rebuffer(&mut self, snapshot: HashMap<K, V>) {
        for (k, v) in snapshot {
            self.map.entry(k).or_insert(v);
        }
    }
}

// ─── NumberDeltaBuffer ──────────────────────────────────────────────────────

/// Additive numeric deltas keyed by `K`. Internally an `f64` accumulator;
/// use [`NumberDeltaBuffer::add`] to increment.
///
/// `drain` returns a snapshot of all keys with **positive** values. Zero
/// or negative entries are filtered out so the flusher never emits no-op
/// rows.
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
    /// Add `delta` to the value for `key`. Treats `0.0` and non-finite
    /// inputs (NaN, ±Inf) as no-ops.
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

    /// Subtract a previously-drained snapshot. Keys whose residual is ≤ 0
    /// are removed.
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

    /// Drop a key — used when an upstream account is deleted.
    pub fn forget(&mut self, key: &K) {
        self.map.remove(key);
    }
}

// ─── NestedDeltaBuffer ──────────────────────────────────────────────────────

/// Nested map `outer → inner → f64` with additive semantics. Used for
/// `slot → mode → diff` (pool-mode-hashrate) and `slot → reason → count`
/// (pool-rejected).
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

    /// Deep snapshot: each inner map is cloned, filtering positive entries.
    /// Outer keys with empty inner maps after filtering are skipped.
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

    /// Subtract a previously-drained snapshot. Outer keys whose inner map
    /// becomes empty are removed.
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

/// Map of key → multi-field record, additive per field. Used for
/// pool-share (2 fields), client-statistics (10 fields), client-rejected
/// (2 fields).
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
    /// Merge `delta` into the bucket for `key`. Creates a zero-initialised
    /// bucket on miss; never panics.
    pub fn add(&mut self, key: K, delta: &R) {
        // If the incoming record is all-zero, skip the allocation entirely.
        if delta.is_zero() {
            return;
        }
        self.map.entry(key).or_default().add_assign(delta);
    }

    /// Snapshot every non-zero bucket. Cloning by value (`R: Clone` is
    /// implied via `BufferRecord: Default + Clone`).
    pub fn drain(&self) -> HashMap<K, R> {
        let mut out = HashMap::with_capacity(self.map.len());
        for (k, r) in &self.map {
            if !r.is_zero() {
                out.insert(k.clone(), r.clone());
            }
        }
        out
    }

    /// Subtract a previously-drained snapshot. Buckets that go all-zero
    /// after subtraction are removed from the map.
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

    // ─── SwapBuffer ──────────────────────────────────────────────────────

    #[test]
    fn swap_buffer_drain_clears_and_returns_previous_contents() {
        let mut buf: SwapBuffer<&'static str, u32> = SwapBuffer::new();
        buf.set("a", 1);
        buf.set("b", 2);
        let snap = buf.drain();
        assert_eq!(snap.len(), 2);
        assert!(buf.is_empty());
    }

    #[test]
    fn swap_buffer_rebuffer_prefers_existing() {
        let mut buf: SwapBuffer<&'static str, u32> = SwapBuffer::new();
        buf.set("a", 1);
        let snap = buf.drain();
        // Concurrent write during the (failed) flush.
        buf.set("a", 99);
        buf.rebuffer(snap);
        // Existing wins.
        assert_eq!(buf.map.get("a"), Some(&99));
    }

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
        // Two-step: write something, then write its negation. End state
        // has the bucket allocated but all-zero. drain must skip it.
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
