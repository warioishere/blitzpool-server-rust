// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-client per-slot share statistics: the multi-field accumulator that
//! backs the `client_statistics` PG table.

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

/// One bucket. `shares` is the **diff sum**, `*_count` are share counts and
/// `*_diff1` are diff sums per rejection reason.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct ClientStatisticsRecord {
    pub shares: f64,
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

    /// Empty the accumulator for a flush.
    pub fn take(&self) -> ClientStatisticsSnapshot {
        self.inner.lock().take()
    }

    /// Empty only the slots that ended before `current`; the slot in
    /// progress stays buffered.
    pub fn take_before(&self, current: TimeSlot) -> ClientStatisticsSnapshot {
        self.inner.lock().take_where(|key| key.slot < current)
    }

    /// Hand back an unwritten part of a take.
    pub fn restore(
        &self,
        snapshot: impl IntoIterator<Item = (ClientStatisticsKey, ClientStatisticsRecord)>,
    ) {
        self.inner.lock().restore(snapshot);
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
            ..Default::default()
        }
    }

    fn rejected_jnf_record(diff: f64) -> ClientStatisticsRecord {
        ClientStatisticsRecord {
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
        let snap = acc.take();
        let rec = snap.get(&k).expect("row");
        assert_eq!((rec.shares, rec.max_difficulty), (20.0, 500.0));
    }

    #[test]
    fn distinct_keys_stay_separate() {
        let acc = ClientStatisticsAccumulator::new();
        acc.add(key("bc1qalice", "w1", "s1", 1_000), &accepted_record(100.0));
        acc.add(key("bc1qalice", "w2", "s1", 1_000), &accepted_record(50.0));
        let snap = acc.take();
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn same_key_sums_fields() {
        let acc = ClientStatisticsAccumulator::new();
        let k = key("bc1qalice", "w1", "s1", 1_000);
        acc.add(k.clone(), &accepted_record(100.0));
        acc.add(k.clone(), &accepted_record(50.0));
        acc.add(k.clone(), &rejected_jnf_record(7.0));
        let snap = acc.take();
        let r = snap.get(&k).expect("merged bucket");
        assert_eq!(r.shares, 150.0);
        assert_eq!(r.rejected_job_not_found_count, 1.0);
        assert_eq!(r.rejected_job_not_found_diff1, 7.0);
    }

    #[test]
    fn take_before_leaves_the_open_slot_buffered() {
        let acc = ClientStatisticsAccumulator::new();
        let ended = key("bc1qalice", "w1", "s1", 1_000);
        let open = key("bc1qalice", "w1", "s1", 2_000);
        acc.add(ended.clone(), &accepted_record(100.0));
        acc.add(open.clone(), &accepted_record(5.0));
        let due = acc.take_before(TimeSlot::from_millis(2_000));
        assert_eq!(due.keys().cloned().collect::<Vec<_>>(), vec![ended]);
        assert_eq!(acc.take().keys().cloned().collect::<Vec<_>>(), vec![open]);
    }

    #[test]
    fn restore_adds_onto_writes_made_during_the_flush() {
        let acc = ClientStatisticsAccumulator::new();
        let k = key("bc1qalice", "w1", "s1", 1_000);
        acc.add(k.clone(), &accepted_record(100.0));
        let snap = acc.take(); // the flush fails
        acc.add(k.clone(), &accepted_record(20.0));
        acc.restore(snap);
        assert_eq!(acc.take().get(&k).map(|r| r.shares), Some(120.0));
    }
}
