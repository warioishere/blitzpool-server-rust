// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lifetime share totals per address and per worker, plus the rejected
//! difficulty per worker. The address total flushes to its own table.

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
    worker_rejected: Mutex<NumberDeltaBuffer<WorkerKey>>,
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
            worker_rejected: Mutex::new(NumberDeltaBuffer::new()),
        }
    }

    // ─── Hot path ────────────────────────────────────────────────────

    pub fn add_address(&self, address: AddressId, diff: f64) {
        self.address.lock().add(address, diff);
    }

    pub fn add_worker(&self, key: WorkerKey, diff: f64) {
        self.worker.lock().add(key, diff);
    }

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

    /// Rejected difficulty of one share, added to the worker's lifetime total.
    pub fn add_worker_rejected(&self, key: WorkerKey, diff: f64) {
        self.worker_rejected.lock().add(key, diff);
    }

    // ─── Coordinator take / restore ─────────────────────────────────

    pub fn take_addresses(&self) -> AddressTotalsSnapshot {
        self.address.lock().take()
    }

    pub fn restore_addresses(&self, snapshot: AddressTotalsSnapshot) {
        self.address.lock().restore(snapshot);
    }

    pub fn take_workers(&self) -> WorkerTotalsSnapshot {
        self.worker.lock().take()
    }

    pub fn restore_workers(&self, snapshot: WorkerTotalsSnapshot) {
        self.worker.lock().restore(snapshot);
    }

    pub fn take_workers_rejected(&self) -> WorkerTotalsSnapshot {
        self.worker_rejected.lock().take()
    }

    pub fn restore_workers_rejected(&self, snapshot: WorkerTotalsSnapshot) {
        self.worker_rejected.lock().restore(snapshot);
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
        let addrs = acc.take_addresses();
        let workers = acc.take_workers();
        assert_eq!(addrs.get(&a("bc1qalice")), Some(&100.0));
        assert_eq!(workers.get(&worker_key("bc1qalice", "w1")), Some(&100.0));
    }

    #[test]
    fn distinct_workers_under_same_address_stay_separate() {
        let acc = ShareTotalsAccumulator::new();
        acc.add(a("bc1qalice"), "w1".into(), 100.0);
        acc.add(a("bc1qalice"), "w2".into(), 50.0);
        let workers = acc.take_workers();
        assert_eq!(workers.len(), 2);
        let addrs = acc.take_addresses();
        // Address total sums across workers.
        assert_eq!(addrs.get(&a("bc1qalice")), Some(&150.0));
    }

    #[test]
    fn take_empties_and_restore_adds_onto_writes_made_during_the_flush() {
        let acc = ShareTotalsAccumulator::new();
        acc.add(a("bc1qalice"), "w1".into(), 100.0);
        let addr_snap = acc.take_addresses();
        let worker_snap = acc.take_workers();
        assert!(acc.take_addresses().is_empty(), "take empties");
        // A write during the flush, which then fails.
        acc.add(a("bc1qalice"), "w1".into(), 10.0);
        acc.restore_addresses(addr_snap);
        acc.restore_workers(worker_snap);
        assert_eq!(acc.take_addresses().get(&a("bc1qalice")), Some(&110.0));
        assert_eq!(
            acc.take_workers().get(&worker_key("bc1qalice", "w1")),
            Some(&110.0)
        );
    }
}
