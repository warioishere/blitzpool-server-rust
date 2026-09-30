// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection storage for JDP-declared mining jobs, FIFO-bounded at
//! [`MAX_DECLARED_JOBS`] entries (each job holds ~1–2 MB of raw tx data).
//!
//! An accepted `DeclareMiningJob` is stored under the fresh
//! `new_mining_job_token` together with the current template's `prev_hash`.
//! A later `PushSolution` finds its job via `match_for_solution(prev_hash)`.
//!
//! The prev_hash-first order is stricter than the spec: SV2 JDP/PushSolution
//! says the JDS "MUST attempt to reconstruct and propagate the block using the
//! template data associated with its most recently sent
//! `DeclareMiningJob.Success`". Preferring a `prev_hash` match and falling back
//! to most-recent never picks a job the spec would reject.
//!
//! `HashMap` does not keep insertion order, so a parallel `VecDeque<Token>`
//! does the FIFO bookkeeping.

use std::collections::{HashMap, VecDeque};

use bp_common::AddressId;

use super::dynamic_outputs::PayoutBooking;
use crate::tokens::Token;

/// FIFO cap on stored declarations.
pub const MAX_DECLARED_JOBS: usize = 3;

// ── DeclaredJob ──────────────────────────────────────────────────────

/// One declared job's payload, keyed in [`DeclaredJobStore`] by
/// `new_token`. Holds everything `PushSolution` will need to
/// reconstruct the block: the coinbase prefix/suffix (the JDC's
/// declared coinbase minus the extranonce slot), the wtxid list, and
/// the raw transactions covering each wtxid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredJob {
    /// Token the JDS issued in `DeclareMiningJobSuccess`; the JDC's
    /// reference for `PushSolution` and (via the bridge) `SetCustomMiningJob`.
    pub new_token: Token,
    /// Whose declaration this is, resolved when the token was allocated.
    ///
    /// Stamped here rather than looked up again at `PushSolution` time: the
    /// block-found path books against this address, and a later lookup (the
    /// allocate token is already consumed) could miss or answer differently.
    pub miner_address: AddressId,
    /// Block-header `version` field the JDC declared.
    pub version: u32,
    /// Coinbase prefix as the JDC declared it (everything before the
    /// extranonce slot).
    pub coinbase_tx_prefix: Vec<u8>,
    /// Coinbase suffix (everything after the extranonce slot).
    pub coinbase_tx_suffix: Vec<u8>,
    /// wtxid list the JDC declared. Position = order in the block's
    /// merkle leaves (excluding the coinbase, which is recomputed
    /// from prefix + extranonce + suffix).
    pub wtxid_list: Vec<[u8; 32]>,
    /// Raw witness-serialised transactions, keyed by position in
    /// `wtxid_list`. Resolved by the JDS from its template-tx cache plus
    /// the `ProvideMissingTransactions` round-trip.
    pub raw_transactions: HashMap<u32, Vec<u8>>,
    /// `prev_hash` of the pool's current template at declaration time — the
    /// tip every `SetCustomMiningJob` on this declaration is held to, and the
    /// preferred-match key of `match_for_solution`. Always known: a
    /// declaration that arrives before the pool has a tip is refused.
    pub prev_hash: [u8; 32],
    /// Wall-clock ms when this declaration was stored.
    pub declared_at_ms: u64,
    /// How a block found on this job is booked, carried from the ext 0x0003
    /// declare-time check that proved this coinbase pays the pool's issued
    /// payout set. `None` when nothing proved it (base-protocol declaration,
    /// or 0x0003 not negotiated): a found block is then reported, not booked.
    pub booking: Option<PayoutBooking>,
    /// ext 0x0003/distribution_id TLV Field: the `distribution_id` this
    /// declaration was accepted against, whether or not a block found on it
    /// can be booked.
    ///
    /// Not derived from [`Self::booking`], which additionally requires the
    /// distribution's settlement snapshot: a declaration against a
    /// non-bookable distribution is still valid and served, and must not hit
    /// the mining side's `custom-jobs-require-solo` refusal.
    ///
    /// `None` for a base-protocol declaration, which is what that Solo gate
    /// catches.
    pub distribution_id: Option<u64>,
}

// ── DeclaredJobStore ─────────────────────────────────────────────────

/// Per-connection FIFO-bounded store of declared jobs. Owned `&mut`
/// by the JDP connection task — no internal locking.
#[derive(Debug)]
pub struct DeclaredJobStore {
    jobs: HashMap<Token, DeclaredJob>,
    /// Insertion order, oldest at the front. `pop_front()` gives the
    /// next eviction candidate.
    order: VecDeque<Token>,
}

impl Default for DeclaredJobStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DeclaredJobStore {
    pub fn new() -> Self {
        Self {
            jobs: HashMap::with_capacity(MAX_DECLARED_JOBS),
            order: VecDeque::with_capacity(MAX_DECLARED_JOBS),
        }
    }

    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    /// Insert a declared job. If the store holds [`MAX_DECLARED_JOBS`]
    /// already, the oldest entry is evicted.
    ///
    /// A `new_token` already in the store replaces the existing entry and
    /// keeps its FIFO position (tokens are random, so this only keeps the
    /// API total).
    pub fn insert(&mut self, job: DeclaredJob) {
        let token = job.new_token;
        if self.jobs.insert(token, job).is_some() {
            // Replace: don't touch insertion order, don't evict.
            return;
        }
        self.order.push_back(token);
        if self.jobs.len() > MAX_DECLARED_JOBS {
            if let Some(oldest_token) = self.order.pop_front() {
                self.jobs.remove(&oldest_token);
            }
        }
    }

    /// Look up a job by `new_token`.
    pub fn get(&self, new_token: &Token) -> Option<&DeclaredJob> {
        self.jobs.get(new_token)
    }

    /// Find the job a `PushSolution` belongs to.
    ///
    /// 1. Prefer a job whose stored `prev_hash` matches the
    ///    solution's `prev_hash`. Among matches, pick the most
    ///    recently declared.
    /// 2. Fall back to the most-recently-declared job overall when
    ///    no `prev_hash` match exists. This fallback is the spec's rule
    ///    (SV2 JDP/PushSolution); step 1 narrows it.
    ///
    /// Returns `None` only when the store is empty.
    pub fn match_for_solution(&self, solution_prev_hash: &[u8; 32]) -> Option<&DeclaredJob> {
        let mut prev_hash_match: Option<&DeclaredJob> = None;
        let mut overall_recent: Option<&DeclaredJob> = None;

        for job in self.jobs.values() {
            if &job.prev_hash == solution_prev_hash {
                match prev_hash_match {
                    Some(current) if current.declared_at_ms >= job.declared_at_ms => {}
                    _ => prev_hash_match = Some(job),
                }
            }
            match overall_recent {
                Some(current) if current.declared_at_ms >= job.declared_at_ms => {}
                _ => overall_recent = Some(job),
            }
        }
        prev_hash_match.or(overall_recent)
    }

    /// Iterate stored jobs in **insertion order** (oldest first).
    ///
    /// For handler tests: `accept_declaration` keys a job under a token the
    /// JDS mints itself, so a test has no key to `get` by.
    pub fn iter(&self) -> impl Iterator<Item = &DeclaredJob> {
        self.order.iter().filter_map(|t| self.jobs.get(t))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(prefix: u8) -> Token {
        let mut b = [0u8; 16];
        b[0] = prefix;
        Token(b)
    }

    fn job(token_seed: u8, declared_at: u64, prev_hash: [u8; 32]) -> DeclaredJob {
        DeclaredJob {
            new_token: tok(token_seed),
            miner_address: AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap(),
            version: 0x2000_0000,
            coinbase_tx_prefix: vec![0xAA; 8],
            coinbase_tx_suffix: vec![0xBB; 8],
            wtxid_list: vec![[0u8; 32]; 3],
            raw_transactions: HashMap::new(),
            prev_hash,
            declared_at_ms: declared_at,
            booking: None,
            distribution_id: None,
        }
    }

    // ── basic insert/get ───────────────────────────────────────────

    #[test]
    fn empty_store_starts_at_len_zero() {
        let s = DeclaredJobStore::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn insert_then_get_returns_same_job() {
        let mut s = DeclaredJobStore::new();
        let j = job(0x01, 1_000, ph(0x00));
        s.insert(j.clone());
        let stored = s.get(&tok(0x01)).expect("must be found");
        assert_eq!(stored, &j);
    }

    #[test]
    fn get_unknown_token_returns_none() {
        let s = DeclaredJobStore::new();
        assert!(s.get(&tok(0xFF)).is_none());
    }

    // ── FIFO cap ───────────────────────────────────────────────────

    #[test]
    fn cap_of_three_evicts_oldest_on_fourth_insert() {
        let mut s = DeclaredJobStore::new();
        s.insert(job(0x01, 1_000, ph(0x00)));
        s.insert(job(0x02, 2_000, ph(0x00)));
        s.insert(job(0x03, 3_000, ph(0x00)));
        assert_eq!(s.len(), 3);
        s.insert(job(0x04, 4_000, ph(0x00)));
        assert_eq!(s.len(), 3);
        // The oldest, 0x01, is gone; 0x02/0x03/0x04 remain.
        assert!(s.get(&tok(0x01)).is_none(), "oldest is evicted");
        assert!(s.get(&tok(0x02)).is_some());
        assert!(s.get(&tok(0x03)).is_some());
        assert!(s.get(&tok(0x04)).is_some());
    }

    /// Replacing an existing token neither rotates the FIFO nor evicts.
    #[test]
    fn replace_existing_token_preserves_fifo_position() {
        let mut s = DeclaredJobStore::new();
        s.insert(job(0x01, 1_000, ph(0x00)));
        s.insert(job(0x02, 2_000, ph(0x00)));
        s.insert(job(0x03, 3_000, ph(0x00)));
        s.insert(job(0x01, 9_999, ph(0x00)));
        assert_eq!(s.len(), 3, "a replace does not evict");
        assert_eq!(s.get(&tok(0x01)).unwrap().declared_at_ms, 9_999);
        // Next insert evicts 0x01 (still at the front), not 0x02.
        s.insert(job(0x04, 4_000, ph(0x00)));
        assert!(s.get(&tok(0x01)).is_none());
        assert!(s.get(&tok(0x02)).is_some());
    }

    // ── match_for_solution ─────────────────────────────────────────

    fn ph(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// No declared jobs → no match.
    #[test]
    fn match_for_solution_empty_store_returns_none() {
        let s = DeclaredJobStore::new();
        assert!(s.match_for_solution(&ph(0x11)).is_none());
    }

    /// Single prev-hash-matching job wins.
    #[test]
    fn match_for_solution_picks_prev_hash_match() {
        let mut s = DeclaredJobStore::new();
        s.insert(job(0x01, 1_000, ph(0xAA)));
        s.insert(job(0x02, 2_000, ph(0xBB)));
        let matched = s.match_for_solution(&ph(0xAA)).unwrap();
        assert_eq!(matched.new_token, tok(0x01));
    }

    /// When multiple jobs match the prev_hash, pick the most-recently
    /// declared one.
    #[test]
    fn match_for_solution_prefers_most_recent_prev_hash_match() {
        let mut s = DeclaredJobStore::new();
        s.insert(job(0x01, 1_000, ph(0xAA)));
        s.insert(job(0x02, 5_000, ph(0xAA))); // newer same prev_hash
        s.insert(job(0x03, 3_000, ph(0xAA))); // older same prev_hash
        let matched = s.match_for_solution(&ph(0xAA)).unwrap();
        assert_eq!(matched.new_token, tok(0x02));
    }

    /// No prev_hash match → fall back to most-recently-declared overall.
    #[test]
    fn match_for_solution_falls_back_to_most_recent_when_no_prev_hash_match() {
        let mut s = DeclaredJobStore::new();
        s.insert(job(0x01, 1_000, ph(0xAA)));
        s.insert(job(0x02, 5_000, ph(0xBB)));
        s.insert(job(0x03, 3_000, ph(0xCC)));
        // Solution carries 0xFF — none stored.
        let matched = s.match_for_solution(&ph(0xFF)).unwrap();
        assert_eq!(matched.new_token, tok(0x02), "0x02 declared last");
    }

    // ── iter ───────────────────────────────────────────────────────

    /// `iter` yields jobs in insertion order (oldest first).
    #[test]
    fn iter_yields_jobs_in_insertion_order() {
        let mut s = DeclaredJobStore::new();
        s.insert(job(0x01, 1_000, ph(0x00)));
        s.insert(job(0x02, 2_000, ph(0x00)));
        s.insert(job(0x03, 3_000, ph(0x00)));
        let tokens: Vec<Token> = s.iter().map(|j| j.new_token).collect();
        assert_eq!(tokens, vec![tok(0x01), tok(0x02), tok(0x03)]);
    }
}
