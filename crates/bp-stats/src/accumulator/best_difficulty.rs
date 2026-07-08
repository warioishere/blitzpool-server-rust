// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-address all-time best-difficulty accumulator.
//!
//! MAX-semantic (not delta): tracks the highest `submission_difficulty`
//! seen per address in the current flush window, plus the firmware/vendor
//! string of the share that set it. The flush folds it into
//! `address_settings_entity."bestDifficulty"` via `GREATEST`, so the
//! persisted all-time best self-corrects every tick — there is no
//! long-lived write-through cache to diverge after an out-of-band reset
//! (the reset zeroes the row; the next flush's window max is `GREATEST`ed
//! straight back in).

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

    /// Record a candidate. Keeps the running max per address (+ the
    /// user-agent that set it). Non-finite / non-positive candidates are
    /// silently discarded — the share path must not throw.
    pub fn add(&self, address: AddressId, candidate: f64, user_agent: Option<&str>) {
        if !candidate.is_finite() || candidate <= 0.0 {
            return;
        }
        let mut guard = self.inner.lock();
        let entry = guard.entry(address).or_insert(BestDifficultyEntry {
            best_difficulty: 0.0,
            user_agent: None,
        });
        if candidate > entry.best_difficulty {
            entry.best_difficulty = candidate;
            entry.user_agent = user_agent.map(str::to_string);
        }
    }

    /// Snapshot the current per-address maxima WITHOUT clearing — mirrors
    /// the drain/confirm contract of the sibling accumulators: an entry is
    /// only dropped once [`Self::confirm`] has seen it persisted.
    pub fn drain(&self) -> BestDifficultySnapshot {
        self.inner.lock().clone()
    }

    /// Drop the entries the flush persisted. An address whose live max
    /// grew past the confirmed snapshot (a higher share arrived mid-flush)
    /// is KEPT so the next tick folds the higher value in. `GREATEST` makes
    /// re-persisting a confirmed value a no-op, so this stays idempotent.
    pub fn confirm(&self, snapshot: &BestDifficultySnapshot) {
        let mut guard = self.inner.lock();
        for (address, confirmed) in snapshot {
            if let Some(live) = guard.get(address) {
                if live.best_difficulty <= confirmed.best_difficulty {
                    guard.remove(address);
                }
            }
        }
    }

    /// Drop an address — used on account deletion.
    pub fn forget_address(&self, address: &AddressId) {
        self.inner.lock().remove(address);
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
        acc.add(a("bc1qalice"), 100.0, Some("bitaxe"));
        acc.add(a("bc1qalice"), 250.0, Some("nerdqaxe"));
        acc.add(a("bc1qalice"), 40.0, Some("worker")); // lower — ignored
        let snap = acc.drain();
        let e = snap.get(&a("bc1qalice")).unwrap();
        assert_eq!(e.best_difficulty, 250.0);
        assert_eq!(e.user_agent.as_deref(), Some("nerdqaxe"));
    }

    #[test]
    fn discards_non_finite_and_non_positive() {
        let acc = BestDifficultyAccumulator::new();
        acc.add(a("bc1qbob"), f64::NAN, None);
        acc.add(a("bc1qbob"), 0.0, None);
        acc.add(a("bc1qbob"), -5.0, None);
        assert!(acc.drain().is_empty());
    }

    #[test]
    fn drain_does_not_clear_confirm_drops_persisted() {
        let acc = BestDifficultyAccumulator::new();
        acc.add(a("bc1qalice"), 100.0, Some("x"));
        let snap = acc.drain();
        assert_eq!(acc.drain().get(&a("bc1qalice")).unwrap().best_difficulty, 100.0);
        acc.confirm(&snap);
        assert!(acc.drain().is_empty(), "confirmed entry dropped");
    }

    #[test]
    fn confirm_keeps_a_higher_value_that_arrived_mid_flush() {
        let acc = BestDifficultyAccumulator::new();
        acc.add(a("bc1qalice"), 100.0, Some("x"));
        let snap = acc.drain(); // 100 persisted by the flush
        acc.add(a("bc1qalice"), 300.0, Some("y")); // new high arrives mid-flush
        acc.confirm(&snap);
        let e = acc.drain().get(&a("bc1qalice")).cloned().unwrap();
        assert_eq!(e.best_difficulty, 300.0, "higher mid-flush value survives confirm");
        assert_eq!(e.user_agent.as_deref(), Some("y"));
    }
}
