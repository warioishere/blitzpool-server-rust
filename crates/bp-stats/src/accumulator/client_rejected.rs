// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-client per-slot per-reason rejected counts + diff sums, backing
//! the `client_rejected_statistics` PG table.

use parking_lot::Mutex;
use std::collections::HashMap;

use bp_common::AddressId;

use crate::accumulator::RejectedReason;
use crate::buffer::{BufferRecord, RecordDeltaBuffer};
use crate::slot::TimeSlot;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientRejectedKey {
    pub address: AddressId,
    pub slot: TimeSlot,
    pub reason: RejectedReason,
}

#[derive(Default, Clone, Debug, PartialEq)]
struct CountAndShares {
    count: f64,
    shares: f64,
}

impl BufferRecord for CountAndShares {
    fn is_zero(&self) -> bool {
        self.count == 0.0 && self.shares == 0.0
    }
    fn add_assign(&mut self, rhs: &Self) {
        self.count += rhs.count;
        self.shares += rhs.shares;
    }
    fn sub_assign_clamped(&mut self, rhs: &Self) -> bool {
        self.count -= rhs.count;
        self.shares -= rhs.shares;
        self.count <= 0.0 && self.shares <= 0.0
    }
}

/// Public snapshot shape: per-key `(count, shares)` pair.
pub type ClientRejectedSnapshot = HashMap<ClientRejectedKey, ClientRejectedRecord>;

#[derive(Debug, Clone, PartialEq)]
pub struct ClientRejectedRecord {
    pub count: f64,
    pub shares: f64,
}

pub struct ClientRejectedAccumulator {
    inner: Mutex<RecordDeltaBuffer<ClientRejectedKey, CountAndShares>>,
}

impl Default for ClientRejectedAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientRejectedAccumulator {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RecordDeltaBuffer::new()),
        }
    }

    /// Hot-path: record a rejected share. `count` defaults to 1.0 per
    /// share; `diff` is the diff-1 weight that's also written to
    /// `client_statistics` via [`ClientStatisticsAccumulator`].
    pub fn add(&self, key: ClientRejectedKey, count: f64, diff: f64) {
        if !count.is_finite() || !diff.is_finite() {
            return;
        }
        self.inner.lock().add(
            key,
            &CountAndShares {
                count,
                shares: diff,
            },
        );
    }

    pub fn drain(&self) -> ClientRejectedSnapshot {
        let raw = self.inner.lock().drain();
        raw.into_iter()
            .map(|(k, v)| {
                (
                    k,
                    ClientRejectedRecord {
                        count: v.count,
                        shares: v.shares,
                    },
                )
            })
            .collect()
    }

    pub fn confirm(&self, snapshot: &ClientRejectedSnapshot) {
        // Convert back into the internal record shape for the buffer's
        // sub-assign-clamped contract.
        let internal: HashMap<_, _> = snapshot
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    CountAndShares {
                        count: v.count,
                        shares: v.shares,
                    },
                )
            })
            .collect();
        self.inner.lock().confirm(&internal);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(addr: &str, slot_ms: i64, reason: RejectedReason) -> ClientRejectedKey {
        ClientRejectedKey {
            address: AddressId::new(addr.to_string()).expect("valid test address"),
            slot: TimeSlot::from_millis(slot_ms),
            reason,
        }
    }

    #[test]
    fn add_and_drain() {
        let acc = ClientRejectedAccumulator::new();
        acc.add(
            k("bc1qalice", 1_000, RejectedReason::JobNotFound),
            1.0,
            100.0,
        );
        acc.add(
            k("bc1qalice", 1_000, RejectedReason::JobNotFound),
            1.0,
            50.0,
        );
        acc.add(
            k("bc1qbob", 1_000, RejectedReason::LowDifficulty),
            1.0,
            25.0,
        );
        let snap = acc.drain();
        let alice = snap
            .get(&k("bc1qalice", 1_000, RejectedReason::JobNotFound))
            .expect("alice JNF bucket");
        assert_eq!(alice.count, 2.0);
        assert_eq!(alice.shares, 150.0);
        let bob = snap
            .get(&k("bc1qbob", 1_000, RejectedReason::LowDifficulty))
            .expect("bob LOW bucket");
        assert_eq!(bob.count, 1.0);
        assert_eq!(bob.shares, 25.0);
    }

    #[test]
    fn confirm_drops_zero_buckets() {
        let acc = ClientRejectedAccumulator::new();
        let key = k("bc1qalice", 1_000, RejectedReason::JobNotFound);
        acc.add(key.clone(), 1.0, 100.0);
        let snap = acc.drain();
        acc.confirm(&snap);
        assert!(acc.is_empty());
    }
}
