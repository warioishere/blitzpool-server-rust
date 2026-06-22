// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-client per-slot share statistics — the big 10-field-per-bucket
//! accumulator that backs the `client_statistics` PG table.

use parking_lot::Mutex;
use std::collections::HashMap;

use bp_common::AddressId;

use crate::buffer::{BufferRecord, RecordDeltaBuffer};
use crate::slot::TimeSlot;

/// Composite key on the client-statistics table: per address, per worker
/// (client) name, per session, per slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientStatisticsKey {
    pub address: AddressId,
    pub client_name: String,
    pub session_id: String,
    pub slot: TimeSlot,
}

/// The 10-field bucket. `shares` is the **diff sum**; the `*_count`
/// fields are share counts (integer-valued floats); the `*_diff1` fields
/// are diff sums broken down by rejection reason.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct ClientStatisticsRecord {
    pub shares: f64,
    pub accepted_count: f64,
    pub rejected_count: f64,
    pub rejected_job_not_found_count: f64,
    pub rejected_job_not_found_diff1: f64,
    pub rejected_duplicate_share_count: f64,
    pub rejected_duplicate_share_diff1: f64,
    pub rejected_low_difficulty_share_count: f64,
    pub rejected_low_difficulty_share_diff1: f64,
}

impl ClientStatisticsRecord {
    /// Sum of all three `*_diff1` fields. Used by the coordinator to
    /// fan rejected-diff totals into `worker_shares_entity`.
    pub fn rejected_diff_total(&self) -> f64 {
        self.rejected_job_not_found_diff1
            + self.rejected_duplicate_share_diff1
            + self.rejected_low_difficulty_share_diff1
    }
}

impl BufferRecord for ClientStatisticsRecord {
    fn is_zero(&self) -> bool {
        self.shares == 0.0
            && self.accepted_count == 0.0
            && self.rejected_count == 0.0
            && self.rejected_job_not_found_count == 0.0
            && self.rejected_job_not_found_diff1 == 0.0
            && self.rejected_duplicate_share_count == 0.0
            && self.rejected_duplicate_share_diff1 == 0.0
            && self.rejected_low_difficulty_share_count == 0.0
            && self.rejected_low_difficulty_share_diff1 == 0.0
    }

    fn add_assign(&mut self, rhs: &Self) {
        self.shares += rhs.shares;
        self.accepted_count += rhs.accepted_count;
        self.rejected_count += rhs.rejected_count;
        self.rejected_job_not_found_count += rhs.rejected_job_not_found_count;
        self.rejected_job_not_found_diff1 += rhs.rejected_job_not_found_diff1;
        self.rejected_duplicate_share_count += rhs.rejected_duplicate_share_count;
        self.rejected_duplicate_share_diff1 += rhs.rejected_duplicate_share_diff1;
        self.rejected_low_difficulty_share_count += rhs.rejected_low_difficulty_share_count;
        self.rejected_low_difficulty_share_diff1 += rhs.rejected_low_difficulty_share_diff1;
    }

    fn sub_assign_clamped(&mut self, rhs: &Self) -> bool {
        self.shares -= rhs.shares;
        self.accepted_count -= rhs.accepted_count;
        self.rejected_count -= rhs.rejected_count;
        self.rejected_job_not_found_count -= rhs.rejected_job_not_found_count;
        self.rejected_job_not_found_diff1 -= rhs.rejected_job_not_found_diff1;
        self.rejected_duplicate_share_count -= rhs.rejected_duplicate_share_count;
        self.rejected_duplicate_share_diff1 -= rhs.rejected_duplicate_share_diff1;
        self.rejected_low_difficulty_share_count -= rhs.rejected_low_difficulty_share_count;
        self.rejected_low_difficulty_share_diff1 -= rhs.rejected_low_difficulty_share_diff1;
        self.shares <= 0.0
            && self.accepted_count <= 0.0
            && self.rejected_count <= 0.0
            && self.rejected_job_not_found_count <= 0.0
            && self.rejected_job_not_found_diff1 <= 0.0
            && self.rejected_duplicate_share_count <= 0.0
            && self.rejected_duplicate_share_diff1 <= 0.0
            && self.rejected_low_difficulty_share_count <= 0.0
            && self.rejected_low_difficulty_share_diff1 <= 0.0
    }
}

pub type ClientStatisticsSnapshot = HashMap<ClientStatisticsKey, ClientStatisticsRecord>;

pub struct ClientStatisticsAccumulator {
    inner: Mutex<RecordDeltaBuffer<ClientStatisticsKey, ClientStatisticsRecord>>,
}

impl Default for ClientStatisticsAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientStatisticsAccumulator {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RecordDeltaBuffer::new()),
        }
    }

    /// Merge `delta` into the bucket for `key`. The caller batches whatever
    /// fields are relevant for a single share into one `Record` and
    /// hands it in.
    pub fn add(&self, key: ClientStatisticsKey, delta: &ClientStatisticsRecord) {
        self.inner.lock().add(key, delta);
    }

    pub fn drain(&self) -> ClientStatisticsSnapshot {
        self.inner.lock().drain()
    }

    pub fn confirm(&self, snapshot: &ClientStatisticsSnapshot) {
        self.inner.lock().confirm(snapshot);
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

    fn key(addr: &str, client: &str, session: &str, slot_ms: i64) -> ClientStatisticsKey {
        ClientStatisticsKey {
            address: AddressId::new(addr.to_string()).expect("valid test address"),
            client_name: client.to_string(),
            session_id: session.to_string(),
            slot: TimeSlot::from_millis(slot_ms),
        }
    }

    fn accepted_record(diff: f64) -> ClientStatisticsRecord {
        ClientStatisticsRecord {
            shares: diff,
            accepted_count: 1.0,
            ..Default::default()
        }
    }

    fn rejected_jnf_record(diff: f64) -> ClientStatisticsRecord {
        ClientStatisticsRecord {
            rejected_count: 1.0,
            rejected_job_not_found_count: 1.0,
            rejected_job_not_found_diff1: diff,
            ..Default::default()
        }
    }

    #[test]
    fn distinct_keys_stay_separate() {
        let acc = ClientStatisticsAccumulator::new();
        acc.add(key("bc1qalice", "w1", "s1", 1_000), &accepted_record(100.0));
        acc.add(key("bc1qalice", "w2", "s1", 1_000), &accepted_record(50.0));
        let snap = acc.drain();
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn same_key_sums_fields() {
        let acc = ClientStatisticsAccumulator::new();
        let k = key("bc1qalice", "w1", "s1", 1_000);
        acc.add(k.clone(), &accepted_record(100.0));
        acc.add(k.clone(), &accepted_record(50.0));
        acc.add(k.clone(), &rejected_jnf_record(7.0));
        let snap = acc.drain();
        let r = snap.get(&k).expect("merged bucket");
        assert_eq!(r.shares, 150.0);
        assert_eq!(r.accepted_count, 2.0);
        assert_eq!(r.rejected_count, 1.0);
        assert_eq!(r.rejected_job_not_found_count, 1.0);
        assert_eq!(r.rejected_job_not_found_diff1, 7.0);
        assert_eq!(r.rejected_diff_total(), 7.0);
    }

    #[test]
    fn confirm_drops_zero_buckets() {
        let acc = ClientStatisticsAccumulator::new();
        let k = key("bc1qalice", "w1", "s1", 1_000);
        acc.add(k.clone(), &accepted_record(100.0));
        let snap = acc.drain();
        acc.confirm(&snap);
        assert!(acc.is_empty());
    }

    #[test]
    fn concurrent_adds_survive_confirm() {
        let acc = ClientStatisticsAccumulator::new();
        let k = key("bc1qalice", "w1", "s1", 1_000);
        acc.add(k.clone(), &accepted_record(100.0));
        let snap = acc.drain();
        acc.add(k.clone(), &accepted_record(20.0));
        acc.confirm(&snap);
        let residual = acc.drain();
        assert_eq!(residual.get(&k).map(|r| r.shares), Some(20.0));
    }

    #[test]
    fn rejected_diff_total_is_sum_of_three_diff1_fields() {
        let r = ClientStatisticsRecord {
            rejected_job_not_found_diff1: 100.0,
            rejected_duplicate_share_diff1: 50.0,
            rejected_low_difficulty_share_diff1: 25.0,
            ..Default::default()
        };
        assert_eq!(r.rejected_diff_total(), 175.0);
    }
}
