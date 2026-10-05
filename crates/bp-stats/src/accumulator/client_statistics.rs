// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-client per-slot share statistics: the multi-field accumulator that
//! backs the `client_statistics` PG table.

use parking_lot::Mutex;
use std::collections::HashMap;

use bp_common::AddressId;

use super::flushed_max;
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

/// One bucket. `shares` is the **diff sum**, `*_count` are share counts and
/// `*_diff1` are diff sums per rejection reason.
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
    /// Version bits rolled outside the negotiated BIP-310 mask. Not folded into
    /// low-difficulty: such a share's proof-of-work may be perfectly good.
    pub rejected_version_rolling_count: f64,
    pub rejected_version_rolling_diff1: f64,
    /// Job retired past the grace window. Not folded into job-not-found: this
    /// is the normal tail of a block transition, not work the pool never had.
    pub rejected_stale_count: f64,
    pub rejected_stale_diff1: f64,
    /// Highest single accepted share difficulty of the slot. A maximum, not
    /// a sum: merged with `max`, and with `GREATEST` in the database.
    pub max_difficulty: f64,
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
            && self.rejected_version_rolling_count == 0.0
            && self.rejected_version_rolling_diff1 == 0.0
            && self.rejected_stale_count == 0.0
            && self.rejected_stale_diff1 == 0.0
            && self.max_difficulty == 0.0
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
        self.rejected_version_rolling_count += rhs.rejected_version_rolling_count;
        self.rejected_version_rolling_diff1 += rhs.rejected_version_rolling_diff1;
        self.rejected_stale_count += rhs.rejected_stale_count;
        self.rejected_stale_diff1 += rhs.rejected_stale_diff1;
        self.max_difficulty = self.max_difficulty.max(rhs.max_difficulty);
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
        self.rejected_version_rolling_count -= rhs.rejected_version_rolling_count;
        self.rejected_version_rolling_diff1 -= rhs.rejected_version_rolling_diff1;
        self.rejected_stale_count -= rhs.rejected_stale_count;
        self.rejected_stale_diff1 -= rhs.rejected_stale_diff1;
        self.max_difficulty = flushed_max(self.max_difficulty, rhs.max_difficulty);
        self.shares <= 0.0
            && self.accepted_count <= 0.0
            && self.rejected_count <= 0.0
            && self.rejected_job_not_found_count <= 0.0
            && self.rejected_job_not_found_diff1 <= 0.0
            && self.rejected_duplicate_share_count <= 0.0
            && self.rejected_duplicate_share_diff1 <= 0.0
            && self.rejected_low_difficulty_share_count <= 0.0
            && self.rejected_low_difficulty_share_diff1 <= 0.0
            && self.rejected_version_rolling_count <= 0.0
            && self.rejected_version_rolling_diff1 <= 0.0
            && self.rejected_stale_count <= 0.0
            && self.rejected_stale_diff1 <= 0.0
            && self.max_difficulty <= 0.0
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

    /// Two shares in one row: the sums add, the maximum keeps the higher.
    #[test]
    fn slot_max_is_a_maximum_not_a_sum() {
        let acc = ClientStatisticsAccumulator::new();
        let k = key("bc1qalice", "w1", "s1", 1_000);
        for (credited, solved) in [(10.0, 500.0), (10.0, 300.0)] {
            acc.add(
                k.clone(),
                &ClientStatisticsRecord {
                    max_difficulty: solved,
                    ..accepted_record(credited)
                },
            );
        }
        let snap = acc.drain();
        let rec = snap.get(&k).expect("row");
        assert_eq!((rec.shares, rec.max_difficulty), (20.0, 500.0));
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
}
