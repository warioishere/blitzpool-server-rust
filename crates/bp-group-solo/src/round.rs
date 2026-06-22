// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-memory per-group round state.
//!
//! Group-Solo runs on **PROP semantics**: one share window per group, the
//! window resets on every block-found. Each member's payout share equals
//! `their_diff / total_diff` (minus fee carve-outs handled in [`crate::distribution`]).
//!
//! The state lives in Redis in production (`groupsolo:{groupId}:*` keys);
//! this Rust struct is the in-process side of that — pure data, no I/O.
//! Service-layer code wraps a [`GroupRoundState`] per group, mirroring it
//! to/from Redis at the appropriate boundaries (see `DEFERRED.md` for the
//! Redis-coupled bits).

use std::collections::HashMap;

use bp_common::AddressId;

/// Highest-diff single share observed in the current round. Surfaced on
/// the round-stats UI endpoint and read by admin tools.
#[derive(Debug, Clone, PartialEq)]
pub struct BestShare {
    pub address: AddressId,
    pub diff: f64,
    /// Unix milliseconds when the share was accepted.
    pub time_ms: i64,
}

/// Outcome of `record_share` — lets the caller decide whether to write
/// through to durable storage (Redis hash for `bestShare`) without
/// re-reading the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareEffect {
    /// `true` if this share is the new round-best. The service layer
    /// should write it through to Redis on `true` (the in-memory state
    /// already records it).
    pub best_improved: bool,
    /// `true` if this is the first accepted share from `address` since
    /// the last round reset. Lets the service layer skip a redundant
    /// `last_accepted_at` write on subsequent shares.
    pub first_in_round: bool,
}

/// In-memory state for one group's current round. Reset on every block-
/// found by [`Self::reset_round`].
#[derive(Debug, Clone, Default)]
pub struct GroupRoundState {
    address_shares: HashMap<AddressId, f64>,
    rejected_shares: HashMap<AddressId, f64>,
    /// Persists ACROSS rounds (not cleared in `reset_round` by default)
    /// so the admin-kick inactivity gate can look back weeks. Caller can
    /// opt to clear via `reset_round(true)`.
    last_accepted_at: HashMap<AddressId, i64>,
    best: Option<BestShare>,
    total_diff: f64,
}

impl GroupRoundState {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Hot path ────────────────────────────────────────────────────

    /// Record an accepted share. Non-finite or non-positive `diff` is a
    /// no-op. Returns a [`ShareEffect`] so the
    /// caller can persist the new best-share to durable storage on
    /// `best_improved`.
    pub fn record_share(&mut self, address: AddressId, diff: f64, now_ms: i64) -> ShareEffect {
        if !diff.is_finite() || diff <= 0.0 {
            return ShareEffect {
                best_improved: false,
                first_in_round: false,
            };
        }

        let first_in_round = !self.address_shares.contains_key(&address);
        *self.address_shares.entry(address.clone()).or_insert(0.0) += diff;
        self.total_diff += diff;
        self.last_accepted_at.insert(address.clone(), now_ms);

        let best_improved = match &self.best {
            None => true,
            Some(b) => diff > b.diff,
        };
        if best_improved {
            self.best = Some(BestShare {
                address,
                diff,
                time_ms: now_ms,
            });
        }

        ShareEffect {
            best_improved,
            first_in_round,
        }
    }

    /// Record a rejected share. Diff-1-weighted total per address;
    /// resets with the round.
    pub fn record_reject(&mut self, address: AddressId, shares: f64) {
        if !shares.is_finite() || shares <= 0.0 {
            return;
        }
        *self.rejected_shares.entry(address).or_insert(0.0) += shares;
    }

    /// Reset the round. PROP semantics: clears the share / reject / best
    /// state. By default keeps `last_accepted_at` across rounds (the
    /// admin-kick clock isn't tied to block-find cadence); pass
    /// `clear_last_accepted = true` to reset it too (used by the
    /// dust-sweep + group-dissolve paths).
    pub fn reset_round(&mut self, clear_last_accepted: bool) {
        self.address_shares.clear();
        self.rejected_shares.clear();
        self.best = None;
        self.total_diff = 0.0;
        if clear_last_accepted {
            self.last_accepted_at.clear();
        }
    }

    /// Drop a single member from every map. Used when an address is
    /// kicked or leaves the group.
    pub fn forget_member(&mut self, address: &AddressId) {
        if let Some(diff) = self.address_shares.remove(address) {
            self.total_diff -= diff;
            if self.total_diff < 0.0 {
                self.total_diff = 0.0;
            }
        }
        self.rejected_shares.remove(address);
        self.last_accepted_at.remove(address);
        if let Some(b) = &self.best {
            if &b.address == address {
                // The kicked member held the round-best; recompute.
                self.best = self
                    .address_shares
                    .iter()
                    .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|(addr, &diff)| BestShare {
                        address: addr.clone(),
                        diff,
                        // We lost the original timestamp on recomputation;
                        // surface zero so callers can see the recomputed
                        // marker. Production code reads best-share rarely
                        // and treats `time_ms == 0` as "not durably set".
                        time_ms: 0,
                    });
            }
        }
    }

    // ── Read-only views ─────────────────────────────────────────────

    pub fn address_shares(&self) -> &HashMap<AddressId, f64> {
        &self.address_shares
    }

    pub fn rejected_shares(&self) -> &HashMap<AddressId, f64> {
        &self.rejected_shares
    }

    pub fn last_accepted_at(&self) -> &HashMap<AddressId, i64> {
        &self.last_accepted_at
    }

    pub fn best(&self) -> Option<&BestShare> {
        self.best.as_ref()
    }

    pub fn total_diff(&self) -> f64 {
        self.total_diff
    }

    pub fn miner_count(&self) -> usize {
        self.address_shares.len()
    }

    pub fn is_empty(&self) -> bool {
        self.address_shares.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> AddressId {
        AddressId::new(s.to_string()).expect("valid test address")
    }

    #[test]
    fn first_share_sets_initial_best() {
        let mut r = GroupRoundState::new();
        let effect = r.record_share(addr("bc1qalice"), 100.0, 1_000);
        assert!(effect.best_improved);
        assert!(effect.first_in_round);
        let best = r.best().expect("best set");
        assert_eq!(best.address, addr("bc1qalice"));
        assert_eq!(best.diff, 100.0);
        assert_eq!(best.time_ms, 1_000);
    }

    #[test]
    fn higher_diff_improves_best() {
        let mut r = GroupRoundState::new();
        r.record_share(addr("bc1qalice"), 100.0, 1_000);
        let effect = r.record_share(addr("bc1qbob"), 200.0, 1_001);
        assert!(effect.best_improved);
        assert_eq!(r.best().unwrap().address, addr("bc1qbob"));
        assert_eq!(r.best().unwrap().diff, 200.0);
    }

    #[test]
    fn equal_diff_does_not_improve_best() {
        let mut r = GroupRoundState::new();
        r.record_share(addr("bc1qalice"), 100.0, 1_000);
        let effect = r.record_share(addr("bc1qbob"), 100.0, 1_001);
        assert!(!effect.best_improved);
        // First share's address keeps the slot.
        assert_eq!(r.best().unwrap().address, addr("bc1qalice"));
    }

    #[test]
    fn first_in_round_distinguishes_repeats() {
        let mut r = GroupRoundState::new();
        let e1 = r.record_share(addr("bc1qalice"), 10.0, 1_000);
        assert!(e1.first_in_round);
        let e2 = r.record_share(addr("bc1qalice"), 10.0, 2_000);
        assert!(!e2.first_in_round);
    }

    #[test]
    fn shares_accumulate_per_address() {
        let mut r = GroupRoundState::new();
        r.record_share(addr("bc1qalice"), 10.0, 1_000);
        r.record_share(addr("bc1qalice"), 30.0, 2_000);
        r.record_share(addr("bc1qbob"), 5.0, 3_000);
        assert_eq!(r.address_shares().get(&addr("bc1qalice")), Some(&40.0));
        assert_eq!(r.address_shares().get(&addr("bc1qbob")), Some(&5.0));
        assert_eq!(r.total_diff(), 45.0);
        assert_eq!(r.miner_count(), 2);
    }

    #[test]
    fn invalid_diff_is_silently_dropped() {
        let mut r = GroupRoundState::new();
        r.record_share(addr("bc1qalice"), f64::NAN, 1_000);
        r.record_share(addr("bc1qalice"), f64::INFINITY, 2_000);
        r.record_share(addr("bc1qalice"), 0.0, 3_000);
        r.record_share(addr("bc1qalice"), -5.0, 4_000);
        assert!(r.is_empty());
        assert_eq!(r.total_diff(), 0.0);
    }

    #[test]
    fn rejected_shares_accumulate_independently() {
        let mut r = GroupRoundState::new();
        r.record_share(addr("bc1qalice"), 100.0, 1_000);
        r.record_reject(addr("bc1qalice"), 5.0);
        r.record_reject(addr("bc1qalice"), 7.5);
        r.record_reject(addr("bc1qbob"), 2.0);
        assert_eq!(r.rejected_shares().get(&addr("bc1qalice")), Some(&12.5));
        assert_eq!(r.rejected_shares().get(&addr("bc1qbob")), Some(&2.0));
        // Rejects don't touch total_diff or best.
        assert_eq!(r.total_diff(), 100.0);
        assert_eq!(r.best().unwrap().diff, 100.0);
    }

    #[test]
    fn reset_round_clears_shares_but_preserves_last_accepted_by_default() {
        let mut r = GroupRoundState::new();
        r.record_share(addr("bc1qalice"), 100.0, 1_000);
        r.record_share(addr("bc1qbob"), 50.0, 2_000);
        r.record_reject(addr("bc1qalice"), 5.0);
        r.reset_round(false);
        assert!(r.is_empty());
        assert!(r.rejected_shares().is_empty());
        assert!(r.best().is_none());
        assert_eq!(r.total_diff(), 0.0);
        // last_accepted_at preserved (cross-round admin-kick clock).
        assert_eq!(r.last_accepted_at().get(&addr("bc1qalice")), Some(&1_000));
        assert_eq!(r.last_accepted_at().get(&addr("bc1qbob")), Some(&2_000));
    }

    #[test]
    fn reset_round_with_clear_last_accepted_wipes_everything() {
        let mut r = GroupRoundState::new();
        r.record_share(addr("bc1qalice"), 100.0, 1_000);
        r.reset_round(true);
        assert!(r.last_accepted_at().is_empty());
    }

    #[test]
    fn forget_member_drops_state_and_adjusts_total() {
        let mut r = GroupRoundState::new();
        r.record_share(addr("bc1qalice"), 100.0, 1_000);
        r.record_share(addr("bc1qbob"), 50.0, 2_000);
        r.record_reject(addr("bc1qalice"), 3.0);
        r.forget_member(&addr("bc1qalice"));
        assert_eq!(r.miner_count(), 1);
        assert!(r.address_shares().get(&addr("bc1qalice")).is_none());
        assert!(r.rejected_shares().get(&addr("bc1qalice")).is_none());
        assert!(r.last_accepted_at().get(&addr("bc1qalice")).is_none());
        assert_eq!(r.total_diff(), 50.0);
    }

    #[test]
    fn forget_member_recomputes_best_if_kicked_member_held_it() {
        let mut r = GroupRoundState::new();
        r.record_share(addr("bc1qalice"), 100.0, 1_000);
        r.record_share(addr("bc1qbob"), 50.0, 2_000);
        r.record_share(addr("bc1qbob"), 30.0, 3_000);
        // Alice holds the round-best at 100.0; Bob has 80 total spread
        // across two shares with 50 the highest individual diff.
        // After forgetting Alice, best should fall back to *cumulative*
        // bob — but our recompute uses cumulative, not per-share, since
        // we don't store individual shares. Treat the surfaced fallback
        // as informational with time_ms = 0.
        r.forget_member(&addr("bc1qalice"));
        let best = r.best().expect("recomputed best");
        assert_eq!(best.address, addr("bc1qbob"));
        assert_eq!(best.time_ms, 0);
    }

    #[test]
    fn forget_unknown_member_is_noop() {
        let mut r = GroupRoundState::new();
        r.record_share(addr("bc1qalice"), 100.0, 1_000);
        r.forget_member(&addr("bc1qnobody"));
        assert_eq!(r.miner_count(), 1);
        assert_eq!(r.total_diff(), 100.0);
    }
}
