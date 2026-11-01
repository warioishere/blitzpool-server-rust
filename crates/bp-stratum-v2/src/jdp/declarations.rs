// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection store of accepted JDP declarations, FIFO-bounded at
//! [`MAX_DECLARED_JOBS`]. `PushSolution` takes the declaration its header
//! solves at the pool's target.

use std::collections::{HashMap, VecDeque};

use bp_common::AddressId;

use super::dynamic_outputs::PayoutBooking;
use crate::tokens::Token;

/// Declarations a found block can still be booked on. A JDC keeps mining a
/// declaration for a moment after declaring the next, so more than the newest
/// is kept; the bound keeps a session's store small.
pub const MAX_DECLARED_JOBS: usize = 3;

// ── DeclaredJob ──────────────────────────────────────────────────────

/// One declared job: everything `PushSolution` needs to identify and book
/// the block solved on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredJob {
    /// The token issued in `DeclareMiningJobSuccess`.
    pub new_token: Token,
    /// Stamped at allocation: a found block books against this address, and
    /// a later lookup could miss or answer differently.
    pub miner_address: AddressId,
    pub version: u32,
    /// Everything before the extranonce slot.
    pub coinbase_tx_prefix: Vec<u8>,
    /// Everything after the extranonce slot.
    pub coinbase_tx_suffix: Vec<u8>,
    /// The coinbase's merkle branch over the declared transactions, from
    /// [`declared_merkle_path`](crate::jdp::custom_job_binding::declared_merkle_path);
    /// `None` when one of them does not decode.
    pub merkle_path: Option<Vec<[u8; 32]>>,
    /// The pool's tip at declaration; every `SetCustomMiningJob` on this
    /// declaration is held to it.
    pub prev_hash: [u8; 32],
    pub declared_at_ms: u64,
    /// `None` when no ext 0x0003 check proved the coinbase pays the issued
    /// payout set: a found block is then reported, not booked.
    pub booking: Option<PayoutBooking>,
    /// Set whenever the declaration was accepted against a distribution, even
    /// a non-bookable one, so it passes the `custom-jobs-require-solo` gate.
    /// Hence not derived from [`Self::booking`].
    pub distribution_id: Option<u64>,
}

// ── DeclaredJobStore ─────────────────────────────────────────────────

/// Owned by the JDP connection task (no locking).
#[derive(Debug)]
pub struct DeclaredJobStore {
    jobs: HashMap<Token, DeclaredJob>,
    /// Insertion order, oldest first.
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

    /// Evicts the oldest past [`MAX_DECLARED_JOBS`]. A known token replaces
    /// its entry in place.
    pub fn insert(&mut self, job: DeclaredJob) {
        let token = job.new_token;
        if self.jobs.insert(token, job).is_some() {
            return;
        }
        self.order.push_back(token);
        if self.jobs.len() > MAX_DECLARED_JOBS {
            if let Some(oldest_token) = self.order.pop_front() {
                self.jobs.remove(&oldest_token);
            }
        }
    }

    pub fn get(&self, new_token: &Token) -> Option<&DeclaredJob> {
        self.jobs.get(new_token)
    }

    /// Oldest first.
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
            merkle_path: Some(Vec::new()),
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
        assert!(s.get(&tok(0x01)).is_none(), "oldest is evicted");
        assert!(s.get(&tok(0x02)).is_some());
        assert!(s.get(&tok(0x03)).is_some());
        assert!(s.get(&tok(0x04)).is_some());
    }

    #[test]
    fn replace_existing_token_preserves_fifo_position() {
        let mut s = DeclaredJobStore::new();
        s.insert(job(0x01, 1_000, ph(0x00)));
        s.insert(job(0x02, 2_000, ph(0x00)));
        s.insert(job(0x03, 3_000, ph(0x00)));
        s.insert(job(0x01, 9_999, ph(0x00)));
        assert_eq!(s.len(), 3, "a replace does not evict");
        assert_eq!(s.get(&tok(0x01)).unwrap().declared_at_ms, 9_999);
        // 0x01 is still at the front.
        s.insert(job(0x04, 4_000, ph(0x00)));
        assert!(s.get(&tok(0x01)).is_none());
        assert!(s.get(&tok(0x02)).is_some());
    }

    fn ph(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    // ── iter ───────────────────────────────────────────────────────

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
