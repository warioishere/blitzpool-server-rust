// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection storage for JDP-declared mining jobs. FIFO-bounded
//! store with automatic eviction after 3 entries.
//!
//! When a JDC calls `DeclareMiningJob` and the JDS validates it
//! successfully, the JDS:
//!
//! 1. Issues a fresh token in `DeclareMiningJobSuccess.new_mining_job_token`.
//! 2. Stores the declared job + raw-tx map + the current template's
//!    `prev_hash` keyed by the new token.
//! 3. Caps the store at 3 entries (~5 s of declarations; each job is
//!    ~1–2 MB of raw tx data — bounded memory).
//!
//! Later, when the JDC submits a `PushSolution`, the JDS uses
//! `match_for_solution(prev_hash)` to find which declared job the
//! solution belongs to. Spec §6.4.9 says to match by `prev_hash`; we
//! prefer `prev_hash` matches and fall back to "most recent"
//! when no match (defensive: declarations that pre-date the JDS
//! observing the current prev_hash store `prev_hash = None`).
//!
//! ## FIFO eviction
//!
//! Rust `HashMap` doesn't preserve insertion order, so we keep a parallel
//! `VecDeque<Token>` for FIFO bookkeeping. Cost: a 16-byte Token push
//! / pop per declaration — negligible vs the MB-sized raw-tx-map
//! moves.

use std::collections::{HashMap, VecDeque};

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
    /// Token the JDS issued in `DeclareMiningJobSuccess`. Becomes
    /// the JDC's reference for `PushSolution` and (via the SV2
    /// mining-protocol bridge) `SetCustomMiningJob`.
    pub new_token: Token,
    /// Token the JDC presented in `DeclareMiningJob` (an earlier
    /// `AllocateMiningJobToken` token). Kept for audit / debug.
    pub original_token: Token,
    /// The JDC's `DeclareMiningJob.request_id` — echoed in the
    /// `Success` frame.
    pub request_id: u32,
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
    /// `wtxid_list`. Resolved by the JDS from its template-tx cache
    /// plus the `ProvideMissingTransactions` round-trip (see
    /// `jdp::tx_validation` — landing in a follow-up commit).
    pub raw_transactions: HashMap<u32, Vec<u8>>,
    /// `prev_hash` of the JDS's current template at declaration
    /// time. `None` if the JDS hadn't yet received its first
    /// `SetNewPrevHash` — defensive, the field is used as a
    /// preferred-match key by `match_for_solution` but solutions
    /// without a hit fall back to the most-recent declaration.
    pub prev_hash: Option<[u8; 32]>,
    /// Wall-clock ms when this declaration was stored.
    pub declared_at_ms: u64,
}

// ── DeclaredJobStore ─────────────────────────────────────────────────

/// Per-connection FIFO-bounded store of declared jobs. Owned `&mut`
/// by the JDP connection task — no internal locking.
#[derive(Debug)]
pub struct DeclaredJobStore {
    capacity: usize,
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
        Self::with_capacity(MAX_DECLARED_JOBS)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            jobs: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Insert a declared job. If the store is at capacity, the
    /// oldest entry is evicted and returned. Returns `None` when
    /// the insert didn't push anything out.
    ///
    /// Inserting a job with a `new_token` that's already in the
    /// store replaces the existing entry (its FIFO position is
    /// preserved). This is defensive — JDS-generated tokens are
    /// random 16-byte values so collisions are astronomically
    /// unlikely; the replace path keeps the API total.
    pub fn insert(&mut self, job: DeclaredJob) -> Option<DeclaredJob> {
        let token = job.new_token;
        if let Some(existing) = self.jobs.insert(token, job) {
            // Replace: don't touch insertion order, don't evict.
            return Some(existing);
        }
        self.order.push_back(token);
        if self.jobs.len() > self.capacity {
            // Evict oldest.
            if let Some(oldest_token) = self.order.pop_front() {
                if let Some(evicted) = self.jobs.remove(&oldest_token) {
                    return Some(evicted);
                }
            }
        }
        None
    }

    /// Look up a job by `new_token`.
    pub fn get(&self, new_token: &Token) -> Option<&DeclaredJob> {
        self.jobs.get(new_token)
    }

    /// Remove a job. Idempotent for unknown tokens.
    pub fn remove(&mut self, new_token: &Token) -> Option<DeclaredJob> {
        let removed = self.jobs.remove(new_token)?;
        // Drop the matching entry from the FIFO. Linear scan over at
        // most `capacity` entries → trivial for `MAX_DECLARED_JOBS=3`.
        if let Some(pos) = self.order.iter().position(|t| t == new_token) {
            self.order.remove(pos);
        }
        Some(removed)
    }

    /// Find the job a `PushSolution` belongs to.
    ///
    /// 1. Prefer a job whose stored `prev_hash` matches the
    ///    solution's `prev_hash`. Among matches, pick the most
    ///    recently declared.
    /// 2. Fall back to the most-recently-declared job overall when
    ///    no `prev_hash` match exists — defensive for declarations
    ///    that pre-date the JDS observing a current prev_hash.
    ///
    /// Returns `None` only when the store is empty.
    pub fn match_for_solution(&self, solution_prev_hash: &[u8; 32]) -> Option<&DeclaredJob> {
        let mut prev_hash_match: Option<&DeclaredJob> = None;
        let mut overall_recent: Option<&DeclaredJob> = None;

        for job in self.jobs.values() {
            if let Some(stored) = job.prev_hash {
                if &stored == solution_prev_hash {
                    match prev_hash_match {
                        Some(current) if current.declared_at_ms >= job.declared_at_ms => {}
                        _ => prev_hash_match = Some(job),
                    }
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
    /// Exposed for diagnostics + the JDP-server's per-connection
    /// teardown path (drop all declared-job state on disconnect).
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

    fn job(token_seed: u8, declared_at: u64, prev_hash: Option<[u8; 32]>) -> DeclaredJob {
        DeclaredJob {
            new_token: tok(token_seed),
            original_token: tok(token_seed.wrapping_add(0x80)),
            request_id: token_seed as u32,
            version: 0x2000_0000,
            coinbase_tx_prefix: vec![0xAA; 8],
            coinbase_tx_suffix: vec![0xBB; 8],
            wtxid_list: vec![[0u8; 32]; 3],
            raw_transactions: HashMap::new(),
            prev_hash,
            declared_at_ms: declared_at,
        }
    }

    // ── basic insert/get ───────────────────────────────────────────

    #[test]
    fn empty_store_starts_at_len_zero() {
        let s = DeclaredJobStore::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.capacity(), MAX_DECLARED_JOBS);
    }

    #[test]
    fn insert_then_get_returns_same_job() {
        let mut s = DeclaredJobStore::new();
        let j = job(0x01, 1_000, None);
        assert!(s.insert(j.clone()).is_none(), "no eviction under cap");
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
        s.insert(job(0x01, 1_000, None));
        s.insert(job(0x02, 2_000, None));
        s.insert(job(0x03, 3_000, None));
        assert_eq!(s.len(), 3);
        let evicted = s.insert(job(0x04, 4_000, None));
        assert_eq!(s.len(), 3);
        let evicted = evicted.expect("4th insert evicts");
        assert_eq!(evicted.new_token, tok(0x01), "oldest is evicted");
        // 0x01 is gone, 0x02/0x03/0x04 remain.
        assert!(s.get(&tok(0x01)).is_none());
        assert!(s.get(&tok(0x02)).is_some());
        assert!(s.get(&tok(0x03)).is_some());
        assert!(s.get(&tok(0x04)).is_some());
    }

    #[test]
    fn custom_capacity_honoured() {
        let mut s = DeclaredJobStore::with_capacity(2);
        s.insert(job(0x01, 1_000, None));
        s.insert(job(0x02, 2_000, None));
        let evicted = s.insert(job(0x03, 3_000, None));
        assert_eq!(s.len(), 2);
        assert_eq!(evicted.unwrap().new_token, tok(0x01));
    }

    /// Replacing an existing token (same `new_token`) does NOT
    /// rotate the FIFO and does NOT evict — the new entry takes
    /// over the old slot, returns the old value, insertion order
    /// is preserved.
    #[test]
    fn replace_existing_token_preserves_fifo_position() {
        let mut s = DeclaredJobStore::with_capacity(2);
        s.insert(job(0x01, 1_000, None));
        s.insert(job(0x02, 2_000, None));
        let replaced = s.insert(job(0x01, 9_999, None));
        assert!(replaced.is_some(), "replace returns old value");
        assert_eq!(replaced.unwrap().declared_at_ms, 1_000);
        assert_eq!(s.len(), 2);
        // Next insert evicts 0x01 (still at the front), not 0x02.
        let evicted = s.insert(job(0x03, 3_000, None));
        assert_eq!(evicted.unwrap().new_token, tok(0x01));
    }

    // ── remove ─────────────────────────────────────────────────────

    #[test]
    fn remove_drops_and_compacts_order() {
        let mut s = DeclaredJobStore::new();
        s.insert(job(0x01, 1_000, None));
        s.insert(job(0x02, 2_000, None));
        s.insert(job(0x03, 3_000, None));
        let removed = s.remove(&tok(0x02));
        assert!(removed.is_some());
        assert_eq!(s.len(), 2);
        // Insertion order after remove: [0x01, 0x03]. Next insert
        // brings us to cap; 4th insert evicts 0x01.
        s.insert(job(0x04, 4_000, None));
        let evicted = s.insert(job(0x05, 5_000, None));
        assert_eq!(evicted.unwrap().new_token, tok(0x01));
    }

    #[test]
    fn remove_unknown_is_idempotent() {
        let mut s = DeclaredJobStore::new();
        assert!(s.remove(&tok(0xAA)).is_none());
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
        s.insert(job(0x01, 1_000, Some(ph(0xAA))));
        s.insert(job(0x02, 2_000, Some(ph(0xBB))));
        let matched = s.match_for_solution(&ph(0xAA)).unwrap();
        assert_eq!(matched.new_token, tok(0x01));
    }

    /// When multiple jobs match the prev_hash, pick the most-recently
    /// declared one.
    #[test]
    fn match_for_solution_prefers_most_recent_prev_hash_match() {
        let mut s = DeclaredJobStore::new();
        s.insert(job(0x01, 1_000, Some(ph(0xAA))));
        s.insert(job(0x02, 5_000, Some(ph(0xAA)))); // newer same prev_hash
        s.insert(job(0x03, 3_000, Some(ph(0xAA)))); // older same prev_hash
        let matched = s.match_for_solution(&ph(0xAA)).unwrap();
        assert_eq!(matched.new_token, tok(0x02));
    }

    /// No prev_hash match → fall back to most-recently-declared overall.
    #[test]
    fn match_for_solution_falls_back_to_most_recent_when_no_prev_hash_match() {
        let mut s = DeclaredJobStore::new();
        s.insert(job(0x01, 1_000, Some(ph(0xAA))));
        s.insert(job(0x02, 5_000, Some(ph(0xBB))));
        s.insert(job(0x03, 3_000, Some(ph(0xCC))));
        // Solution carries 0xFF — none stored.
        let matched = s.match_for_solution(&ph(0xFF)).unwrap();
        assert_eq!(matched.new_token, tok(0x02), "0x02 declared last");
    }

    /// Jobs with `prev_hash = None` participate in the most-recent
    /// fallback but never in the prev_hash-match pool.
    #[test]
    fn match_for_solution_skips_none_prev_hash_for_match_path() {
        let mut s = DeclaredJobStore::new();
        s.insert(job(0x01, 1_000, None));
        s.insert(job(0x02, 5_000, None));
        // Solution carries any value — no prev_hash matches, fall
        // through to most-recent.
        let matched = s.match_for_solution(&ph(0xAA)).unwrap();
        assert_eq!(matched.new_token, tok(0x02));
    }

    // ── iter ───────────────────────────────────────────────────────

    /// `iter` yields jobs in insertion order (oldest first).
    #[test]
    fn iter_yields_jobs_in_insertion_order() {
        let mut s = DeclaredJobStore::new();
        s.insert(job(0x01, 1_000, None));
        s.insert(job(0x02, 2_000, None));
        s.insert(job(0x03, 3_000, None));
        let tokens: Vec<Token> = s.iter().map(|j| j.new_token).collect();
        assert_eq!(tokens, vec![tok(0x01), tok(0x02), tok(0x03)]);
    }
}
