// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lifetime share totals — per address (lands in `address_settings`) and
//! per worker (lands in `worker_shares_entity`).
//!
//! Two independent buffers because the flush destinations are different
//! tables.

use parking_lot::Mutex;
use std::collections::HashMap;

use bp_common::AddressId;

use crate::buffer::NumberDeltaBuffer;

/// Composite key on `worker_shares_entity`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkerKey {
    pub address: AddressId,
    pub client_name: String,
}

pub type WorkerTotalsSnapshot = HashMap<WorkerKey, f64>;
pub type AddressTotalsSnapshot = HashMap<AddressId, f64>;

pub struct ShareTotalsAccumulator {
    address: Mutex<NumberDeltaBuffer<AddressId>>,
    worker: Mutex<NumberDeltaBuffer<WorkerKey>>,
}

impl Default for ShareTotalsAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl ShareTotalsAccumulator {
    pub fn new() -> Self {
        Self {
            address: Mutex::new(NumberDeltaBuffer::new()),
            worker: Mutex::new(NumberDeltaBuffer::new()),
        }
    }

    // ─── Hot path ────────────────────────────────────────────────────

    /// Increment the per-address lifetime share-diff total.
    pub fn add_address(&self, address: AddressId, diff: f64) {
        self.address.lock().add(address, diff);
    }

    /// Increment the per-worker lifetime share-diff total.
    pub fn add_worker(&self, key: WorkerKey, diff: f64) {
        self.worker.lock().add(key, diff);
    }

    /// Convenience: increment both totals from a single share.
    pub fn add(&self, address: AddressId, client_name: String, diff: f64) {
        self.add_address(address.clone(), diff);
        self.add_worker(
            WorkerKey {
                address,
                client_name,
            },
            diff,
        );
    }

    // ─── Coordinator drain / confirm ────────────────────────────────

    pub fn drain_addresses(&self) -> AddressTotalsSnapshot {
        self.address.lock().drain()
    }

    pub fn confirm_addresses(&self, snapshot: &AddressTotalsSnapshot) {
        self.address.lock().confirm(snapshot);
    }

    pub fn drain_workers(&self) -> WorkerTotalsSnapshot {
        self.worker.lock().drain()
    }

    pub fn confirm_workers(&self, snapshot: &WorkerTotalsSnapshot) {
        self.worker.lock().confirm(snapshot);
    }

    // ─── Maintenance ────────────────────────────────────────────────

    /// Drop an address (and all its workers) — used on account deletion.
    pub fn forget_address(&self, address: &AddressId) {
        let mut addr = self.address.lock();
        addr.forget(address);
        // Worker keys aren't directly forget-able by prefix; the next flush
        // will naturally clear residuals as they reach zero, but actively
        // dropping them here avoids stale buckets sticking in memory if
        // the address never sees another share. Cost is a single iteration
        // of the worker map.
        drop(addr);
        let mut workers = self.worker.lock();
        let to_remove: Vec<WorkerKey> = workers
            .drain()
            .keys()
            .filter(|k| &k.address == address)
            .cloned()
            .collect();
        // drain() above is a *snapshot* — it didn't clear the live map.
        // Use the keys to forget them individually.
        for key in to_remove {
            workers.forget(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> AddressId {
        AddressId::new(s.to_string()).expect("valid test address")
    }

    fn worker_key(addr: &str, client: &str) -> WorkerKey {
        WorkerKey {
            address: a(addr),
            client_name: client.to_string(),
        }
    }

    #[test]
    fn convenience_add_fans_to_both_buffers() {
        let acc = ShareTotalsAccumulator::new();
        acc.add(a("bc1qalice"), "w1".into(), 100.0);
        let addrs = acc.drain_addresses();
        let workers = acc.drain_workers();
        assert_eq!(addrs.get(&a("bc1qalice")), Some(&100.0));
        assert_eq!(workers.get(&worker_key("bc1qalice", "w1")), Some(&100.0));
    }

    #[test]
    fn distinct_workers_under_same_address_stay_separate() {
        let acc = ShareTotalsAccumulator::new();
        acc.add(a("bc1qalice"), "w1".into(), 100.0);
        acc.add(a("bc1qalice"), "w2".into(), 50.0);
        let workers = acc.drain_workers();
        assert_eq!(workers.len(), 2);
        let addrs = acc.drain_addresses();
        // Address total sums across workers.
        assert_eq!(addrs.get(&a("bc1qalice")), Some(&150.0));
    }

    #[test]
    fn drain_is_non_clearing_until_confirm() {
        let acc = ShareTotalsAccumulator::new();
        acc.add(a("bc1qalice"), "w1".into(), 100.0);
        let _ = acc.drain_addresses();
        let _ = acc.drain_workers();
        let again = acc.drain_addresses();
        assert_eq!(again.get(&a("bc1qalice")), Some(&100.0));
    }

    #[test]
    fn confirm_subtracts_and_preserves_concurrent_adds() {
        let acc = ShareTotalsAccumulator::new();
        acc.add(a("bc1qalice"), "w1".into(), 100.0);
        let addr_snap = acc.drain_addresses();
        let worker_snap = acc.drain_workers();
        // Concurrent write during the flush.
        acc.add(a("bc1qalice"), "w1".into(), 10.0);
        acc.confirm_addresses(&addr_snap);
        acc.confirm_workers(&worker_snap);
        assert_eq!(acc.drain_addresses().get(&a("bc1qalice")), Some(&10.0));
        assert_eq!(
            acc.drain_workers().get(&worker_key("bc1qalice", "w1")),
            Some(&10.0)
        );
    }

    #[test]
    fn forget_address_clears_address_and_workers() {
        let acc = ShareTotalsAccumulator::new();
        acc.add(a("bc1qalice"), "w1".into(), 100.0);
        acc.add(a("bc1qalice"), "w2".into(), 50.0);
        acc.add(a("bc1qbob"), "w1".into(), 25.0);
        acc.forget_address(&a("bc1qalice"));
        let addrs = acc.drain_addresses();
        let workers = acc.drain_workers();
        assert_eq!(addrs.get(&a("bc1qalice")), None);
        assert_eq!(addrs.get(&a("bc1qbob")), Some(&25.0));
        assert!(workers.keys().all(|k| k.address == a("bc1qbob")));
    }
}
