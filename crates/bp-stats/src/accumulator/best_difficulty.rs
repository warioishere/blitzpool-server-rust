// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-address best difficulty of the current flush window, plus the user
//! agent that set it. The flush merges it with `GREATEST`, so the stored
//! all-time best is the only source of truth and no in-process cache can
//! diverge from it after the row is reset out of band.

use std::collections::HashMap;

use bp_common::AddressId;
use parking_lot::Mutex;

/// One address's best-difficulty candidate for the current window.
#[derive(Clone, Debug, PartialEq)]
pub struct BestDifficultyEntry {
    pub best_difficulty: f64,
    pub user_agent: Option<String>,
}

/// Snapshot handed to the flusher.
pub type BestDifficultySnapshot = HashMap<AddressId, BestDifficultyEntry>;

/// MAX-semantic per-address accumulator. Infallible on the hot path.
#[derive(Default)]
pub struct BestDifficultyAccumulator {
    inner: Mutex<HashMap<AddressId, BestDifficultyEntry>>,
}

impl BestDifficultyAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Keep the running max per address. Non-finite or non-positive values are
    /// dropped. The address is cloned only on insert, so the steady-state hot
    /// path allocates nothing.
    pub fn add(&self, address: &AddressId, candidate: f64, user_agent: Option<&str>) {
        if !candidate.is_finite() || candidate <= 0.0 {
            return;
        }
        let mut guard = self.inner.lock();
        match guard.get_mut(address) {
            Some(entry) if candidate > entry.best_difficulty => {
                entry.best_difficulty = candidate;
                entry.user_agent = user_agent.map(str::to_string);
            }
            Some(_) => {} // existing max is higher — leave it
            None => {
                guard.insert(
                    address.clone(),
                    BestDifficultyEntry {
                        best_difficulty: candidate,
                        user_agent: user_agent.map(str::to_string),
                    },
                );
            }
        }
    }

    /// Empty the accumulator for a flush.
    pub fn take(&self) -> BestDifficultySnapshot {
        std::mem::take(&mut *self.inner.lock())
    }

    /// Hand back an unwritten [`Self::take`]: per address the higher best
    /// wins, with the user agent that set it.
    pub fn restore(&self, snapshot: BestDifficultySnapshot) {
        let mut guard = self.inner.lock();
        for (address, entry) in snapshot {
            match guard.get_mut(&address) {
                Some(live) if live.best_difficulty >= entry.best_difficulty => {}
                Some(live) => *live = entry,
                None => {
                    guard.insert(address, entry);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> AddressId {
        AddressId::new(s.to_string()).expect("valid test address")
    }

    #[test]
    fn keeps_running_max_and_its_user_agent() {
        let acc = BestDifficultyAccumulator::new();
        acc.add(&a("bc1qalice"), 100.0, Some("bitaxe"));
        acc.add(&a("bc1qalice"), 250.0, Some("nerdqaxe"));
        acc.add(&a("bc1qalice"), 40.0, Some("worker")); // lower — ignored
        let snap = acc.take();
        let e = snap.get(&a("bc1qalice")).unwrap();
        assert_eq!(e.best_difficulty, 250.0);
        assert_eq!(e.user_agent.as_deref(), Some("nerdqaxe"));
    }

    #[test]
    fn discards_non_finite_and_non_positive() {
        let acc = BestDifficultyAccumulator::new();
        acc.add(&a("bc1qbob"), f64::NAN, None);
        acc.add(&a("bc1qbob"), 0.0, None);
        acc.add(&a("bc1qbob"), -5.0, None);
        assert!(acc.take().is_empty());
    }

    #[test]
    fn take_empties_the_accumulator() {
        let acc = BestDifficultyAccumulator::new();
        acc.add(&a("bc1qalice"), 100.0, Some("x"));
        assert_eq!(
            acc.take().get(&a("bc1qalice")).unwrap().best_difficulty,
            100.0
        );
        assert!(acc.take().is_empty());
    }

    #[test]
    fn restore_keeps_the_higher_of_snapshot_and_mid_flush_value() {
        let acc = BestDifficultyAccumulator::new();
        acc.add(&a("bc1qalice"), 100.0, Some("x"));
        acc.add(&a("bc1qbob"), 900.0, Some("b"));
        let snap = acc.take(); // the flush fails
        acc.add(&a("bc1qalice"), 300.0, Some("y")); // higher, mid-flush
        acc.add(&a("bc1qbob"), 50.0, Some("c")); // lower, mid-flush
        acc.restore(snap);
        let after = acc.take();
        assert_eq!(after[&a("bc1qalice")].best_difficulty, 300.0);
        assert_eq!(after[&a("bc1qalice")].user_agent.as_deref(), Some("y"));
        assert_eq!(after[&a("bc1qbob")].best_difficulty, 900.0);
        assert_eq!(after[&a("bc1qbob")].user_agent.as_deref(), Some("b"));
    }
}
