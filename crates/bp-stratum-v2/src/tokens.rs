// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection JDP-token store for `AllocateMiningJobToken`.
//!
//! A token is a big-endian u32 counter (from 1) plus 12 CSPRNG bytes, so a JDC
//! cannot forge another connection's token. TTL is 1 h (pool policy); allocation
//! is rate-limited to one per second with a burst of [`ALLOCATE_BURST`]
//! (SV2 JDP/AllocateMiningJobToken). One allocated token authorises exactly one
//! declaration attempt.

use std::collections::HashMap;

use bp_common::AddressId;

/// RNG hook for [`TokenStore::set_rng`]; tests inject deterministic bytes.
pub type RngFn = dyn FnMut(&mut [u8]) -> Result<(), String> + Send + 'static;

/// Token length: 4 counter bytes plus 96 random bits (the spec sets no length).
pub const TOKEN_LEN: usize = 16;

pub const TOKEN_COUNTER_LEN: usize = 4;

pub const DEFAULT_TOKEN_TTL_MS: u64 = 3_600_000;

/// SV2 JDP/AllocateMiningJobToken: "rate limited to a rather slow rate".
pub const DEFAULT_RATE_LIMIT_MS: u64 = 1_000;

/// A JDC requests two tokens back to back on connect and never re-requests an
/// unanswered one, so the burst must cover both.
pub const ALLOCATE_BURST: u64 = 2;

// ── Token ────────────────────────────────────────────────────────────

/// Opaque JDP token. Debug prints only the counter prefix: the full bytes
/// let anyone who reads the log act as the JDC.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token(pub [u8; TOKEN_LEN]);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Token({:02x}{:02x}{:02x}{:02x}…)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

// ── AllocatedToken ───────────────────────────────────────────────────

/// One issued token. `coinbase_outputs` is what `AllocateMiningJobTokenSuccess`
/// returned; the fallback when a JDC skips the ext 0x0003 step.
#[derive(Clone, Debug)]
pub struct AllocatedToken {
    pub token: Token,
    pub miner_address: AddressId,
    pub coinbase_outputs: Vec<u8>,
    pub expires_at_ms: u64,
}

impl AllocatedToken {
    /// The boundary millisecond is still active.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms > self.expires_at_ms
    }
}

// ── Errors ───────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenAllocError {
    /// Dropped silently: SV2 JDP/AllocateMiningJobToken has no rate-limit reply.
    #[error("allocation rate limited: next allocation possible in {retry_in_ms} ms")]
    RateLimited { retry_in_ms: u64 },
    /// Dropped rather than issue a token with a predictable suffix.
    #[error("token entropy: {0}")]
    EntropyFailed(String),
    #[error("token counter saturated")]
    CounterSaturated,
}

// ── TokenStore ───────────────────────────────────────────────────────

/// Per-connection token store, owned by the JDP connection task (no locking).
pub struct TokenStore {
    counter: u32,
    /// Each allocation pushes this one interval further; allocating is allowed
    /// while it lies at most `ALLOCATE_BURST - 1` intervals ahead.
    budget_refilled_at_ms: u64,
    allocated: HashMap<Token, AllocatedToken>,
    rate_limit_ms: u64,
    ttl_ms: u64,
    rng: Option<Box<RngFn>>,
}

impl std::fmt::Debug for TokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenStore")
            .field("counter", &self.counter)
            .field("budget_refilled_at_ms", &self.budget_refilled_at_ms)
            .field("allocated_count", &self.allocated.len())
            .field("rate_limit_ms", &self.rate_limit_ms)
            .field("ttl_ms", &self.ttl_ms)
            .finish()
    }
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStore {
    pub fn new() -> Self {
        Self::with_config(DEFAULT_RATE_LIMIT_MS, DEFAULT_TOKEN_TTL_MS)
    }

    pub fn with_config(rate_limit_ms: u64, ttl_ms: u64) -> Self {
        Self {
            counter: 0,
            budget_refilled_at_ms: 0,
            allocated: HashMap::new(),
            rate_limit_ms,
            ttl_ms,
            rng: None,
        }
    }

    /// Override the random-suffix source; `None` reverts to `getrandom`.
    pub fn set_rng(&mut self, rng: Option<Box<RngFn>>) {
        self.rng = rng;
    }

    pub fn len(&self) -> usize {
        self.allocated.len()
    }

    pub fn is_empty(&self) -> bool {
        self.allocated.is_empty()
    }

    /// Mint the `new_mining_job_token` of a `DeclareMiningJobSuccess`.
    ///
    /// Not rate-limited: the limit is the client's budget, and a JDC that
    /// allocates and declares within one second must still get an answer.
    /// Not stored, so it is never accepted as a later declaration's token.
    pub fn mint_for_declaration(&mut self) -> Result<Token, TokenAllocError> {
        self.next_token()
    }

    /// Allocate and store a rate-limited token. Sweeps expired entries on the
    /// way in, which is what removes tokens that are never presented.
    pub fn allocate(
        &mut self,
        now_ms: u64,
        miner_address: AddressId,
        coinbase_outputs: Vec<u8>,
    ) -> Result<&AllocatedToken, TokenAllocError> {
        let allowed_from_ms = self
            .budget_refilled_at_ms
            .saturating_sub((ALLOCATE_BURST - 1) * self.rate_limit_ms);
        if now_ms < allowed_from_ms {
            return Err(TokenAllocError::RateLimited {
                retry_in_ms: allowed_from_ms - now_ms,
            });
        }
        self.budget_refilled_at_ms = self.budget_refilled_at_ms.max(now_ms) + self.rate_limit_ms;
        self.cleanup_expired(now_ms);
        let token = self.next_token()?;
        let entry = AllocatedToken {
            token,
            miner_address,
            coinbase_outputs,
            expires_at_ms: now_ms.saturating_add(self.ttl_ms),
        };
        self.allocated.insert(token, entry);
        Ok(self.allocated.get(&token).expect("token was just inserted"))
    }

    fn next_token(&mut self) -> Result<Token, TokenAllocError> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(TokenAllocError::CounterSaturated)?;
        let mut bytes = [0u8; TOKEN_LEN];
        bytes[..TOKEN_COUNTER_LEN].copy_from_slice(&self.counter.to_be_bytes());
        if let Some(ref mut rng) = self.rng {
            rng(&mut bytes[TOKEN_COUNTER_LEN..]).map_err(TokenAllocError::EntropyFailed)?;
        } else {
            getrandom::getrandom(&mut bytes[TOKEN_COUNTER_LEN..])
                .map_err(|e| TokenAllocError::EntropyFailed(e.to_string()))?;
        }
        Ok(Token(bytes))
    }

    /// Tests only: no expiry check, not consumed. Production uses
    /// [`Self::take_active`].
    pub fn lookup(&self, token: &Token) -> Option<&AllocatedToken> {
        self.allocated.get(token)
    }

    /// Remove and return the token a declaration presents, unless expired.
    /// One token is one attempt, spent even when the declaration is refused
    /// (SV2 JDP/Full-Template Mode). The mining side differs: its token
    /// survives a rejection because the JDC retries the same job on it.
    pub fn take_active(&mut self, token: &Token, now_ms: u64) -> Option<AllocatedToken> {
        let entry = self.allocated.remove(token)?;
        (!entry.is_expired(now_ms)).then_some(entry)
    }

    /// Returns how many were removed.
    pub fn cleanup_expired(&mut self, now_ms: u64) -> usize {
        let before = self.allocated.len();
        self.allocated.retain(|_, entry| !entry.is_expired(now_ms));
        before - self.allocated.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> AddressId {
        AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap()
    }

    fn const_rng(byte: u8) -> Box<RngFn> {
        Box::new(move |buf: &mut [u8]| {
            buf.fill(byte);
            Ok(())
        })
    }

    fn fresh_store_with_rng(byte: u8) -> TokenStore {
        let mut s = TokenStore::new();
        s.set_rng(Some(const_rng(byte)));
        s
    }

    // ── Token format ───────────────────────────────────────────────

    #[test]
    fn first_allocation_has_counter_one_in_big_endian() {
        let mut s = fresh_store_with_rng(0xAB);
        let token = s.allocate(0, addr(), vec![]).unwrap().token;
        assert_eq!(token.0[0..4], [0x00, 0x00, 0x00, 0x01]);
        assert_eq!(token.0[4..16], [0xAB; 12]);
    }

    #[test]
    fn counter_increments_monotonically() {
        let mut s = fresh_store_with_rng(0x00);
        let t1 = s.allocate(0, addr(), vec![]).unwrap().token;
        let t2 = s.allocate(1_000, addr(), vec![]).unwrap().token;
        let t3 = s.allocate(2_000, addr(), vec![]).unwrap().token;
        assert_eq!(t1.0[0..4], [0, 0, 0, 1]);
        assert_eq!(t2.0[0..4], [0, 0, 0, 2]);
        assert_eq!(t3.0[0..4], [0, 0, 0, 3]);
    }

    #[test]
    fn debug_impl_truncates_to_first_4_bytes() {
        let token = Token([
            0x12, 0x34, 0x56, 0x78, 0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let dbg = format!("{token:?}");
        assert!(dbg.contains("12345678"));
        assert!(!dbg.contains("aabbcc"));
    }

    // ── Rate limit ─────────────────────────────────────────────────

    #[test]
    fn rate_limit_blocks_the_call_after_the_burst() {
        let mut s = fresh_store_with_rng(0x00);
        for _ in 0..ALLOCATE_BURST {
            s.allocate(0, addr(), vec![]).unwrap();
        }
        let err = s.allocate(999, addr(), vec![]).unwrap_err();
        assert_eq!(err, TokenAllocError::RateLimited { retry_in_ms: 1 });
    }

    #[test]
    fn after_the_burst_the_sustained_rate_is_one_per_interval() {
        let mut s = fresh_store_with_rng(0x00);
        for _ in 0..ALLOCATE_BURST {
            s.allocate(0, addr(), vec![]).unwrap();
        }
        assert!(s.allocate(1_000, addr(), vec![]).is_ok());
        assert!(s.allocate(1_000, addr(), vec![]).is_err());
        assert!(s.allocate(2_000, addr(), vec![]).is_ok());
    }

    #[test]
    fn idle_time_refills_the_burst_and_no_further() {
        let mut s = fresh_store_with_rng(0x00);
        s.allocate(0, addr(), vec![]).unwrap();
        let later = 60_000;
        for _ in 0..ALLOCATE_BURST {
            s.allocate(later, addr(), vec![]).unwrap();
        }
        assert!(s.allocate(later, addr(), vec![]).is_err());
    }

    #[test]
    fn custom_rate_limit_honoured() {
        let mut s = TokenStore::with_config(500, DEFAULT_TOKEN_TTL_MS);
        s.set_rng(Some(const_rng(0x00)));
        for _ in 0..ALLOCATE_BURST {
            s.allocate(0, addr(), vec![]).unwrap();
        }
        assert!(s.allocate(499, addr(), vec![]).is_err());
        assert!(s.allocate(500, addr(), vec![]).is_ok());
    }

    // ── TTL ────────────────────────────────────────────────────────

    #[test]
    fn expires_at_is_now_plus_ttl() {
        let mut s = fresh_store_with_rng(0x00);
        let alloc = s.allocate(5_000, addr(), vec![]).unwrap();
        assert_eq!(alloc.expires_at_ms, 5_000 + DEFAULT_TOKEN_TTL_MS);
    }

    #[test]
    fn is_expired_boundary_is_inclusive() {
        let alloc = AllocatedToken {
            token: Token([0; TOKEN_LEN]),
            miner_address: addr(),
            coinbase_outputs: vec![],
            expires_at_ms: 100,
        };
        assert!(!alloc.is_expired(100), "exact boundary is still active");
        assert!(alloc.is_expired(101), "1 ms past expires");
    }

    // ── lookup / take_active ───────────────────────────────────────

    #[test]
    fn lookup_finds_active_token() {
        let mut s = fresh_store_with_rng(0x00);
        let token = s.allocate(0, addr(), vec![1, 2, 3]).unwrap().token;
        let entry = s.lookup(&token).unwrap();
        assert_eq!(entry.coinbase_outputs, vec![1, 2, 3]);
    }

    #[test]
    fn taking_a_token_removes_it() {
        let mut s = fresh_store_with_rng(0x00);
        let token = s.allocate(0, addr(), vec![1, 2, 3]).unwrap().token;
        let taken = s.take_active(&token, 100).expect("first take resolves");
        assert_eq!(taken.coinbase_outputs, vec![1, 2, 3]);
        assert!(
            s.take_active(&token, 100).is_none(),
            "a second declaration on the same allocate token must find nothing"
        );
        assert!(
            s.lookup(&token).is_none(),
            "and the entry is gone, not merely hidden"
        );
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn take_active_refuses_and_prunes_an_expired_token() {
        let mut s = TokenStore::with_config(0, 1_000);
        s.set_rng(Some(const_rng(0x00)));
        let boundary = s.allocate(0, addr(), vec![]).unwrap().token;
        assert!(
            s.take_active(&boundary, 1_000).is_some(),
            "the boundary millisecond is still active"
        );

        let token = s.allocate(0, addr(), vec![]).unwrap().token;
        assert!(s.take_active(&token, 5_000).is_none());
        // Pruned on the way out, not left for the sweep.
        assert!(s.lookup(&token).is_none());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn take_active_unknown_is_none() {
        let mut s = TokenStore::new();
        assert!(s.take_active(&Token([0xFF; TOKEN_LEN]), 0).is_none());
    }

    // ── cleanup_expired ────────────────────────────────────────────

    #[test]
    fn cleanup_expired_removes_only_expired() {
        let mut s = TokenStore::with_config(0, 1_000);
        s.set_rng(Some(const_rng(0x00)));
        let t1 = s.allocate(0, addr(), vec![]).unwrap().token;
        let t2 = s.allocate(500, addr(), vec![]).unwrap().token;
        let removed = s.cleanup_expired(1_200);
        assert_eq!(removed, 1);
        assert!(s.lookup(&t1).is_none(), "t1 should be evicted");
        assert!(s.lookup(&t2).is_some(), "t2 still active");
    }

    #[test]
    fn cleanup_expired_keeps_boundary_entry() {
        let mut s = TokenStore::with_config(0, 1_000);
        s.set_rng(Some(const_rng(0x00)));
        let token = s.allocate(0, addr(), vec![]).unwrap().token;
        let removed = s.cleanup_expired(1_000);
        assert_eq!(removed, 0);
        assert!(s.lookup(&token).is_some());
    }
}
