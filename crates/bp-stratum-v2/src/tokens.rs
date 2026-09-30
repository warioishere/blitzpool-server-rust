// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection JDP-token store. Tokens are opaque 16-byte identifiers the
//! JDS hands to a JDC on `AllocateMiningJobToken`; the JDC references them in
//! `DeclareMiningJob` and `SetCustomMiningJob`. The 1 h TTL is pool policy
//! (the spec sets no lifetime). Allocations are rate-limited to one per 1 s
//! per connection with a burst of [`ALLOCATE_BURST`]
//! (SV2 JDP/AllocateMiningJobToken — "rate limited to a rather slow rate").
//!
//! ## Format
//!
//! - **bytes 0..4** — per-connection counter, big-endian, starting at 1
//!   (zero is reserved).
//! - **bytes 4..16** — 12 CSPRNG bytes, so a JDC cannot forge tokens for a
//!   different connection.
//!
//! ## Lifecycle
//!
//! - `allocate` enforces the rate limit, stores the token with its expiry
//!   and sweeps expired entries.
//! - `mint_for_declaration` makes the pool's own `new_mining_job_token`:
//!   same shape, no rate limit, not stored (nothing looks it up here).
//! - `take_active` consumes the token a `DeclareMiningJob` presents: one
//!   allocate authorises one declaration attempt.
//! - `cleanup_expired` is the sweep, also usable from a periodic tick.

use std::collections::HashMap;

use bp_common::AddressId;

/// Boxed RNG closure type used by [`TokenStore::set_rng`]: production uses
/// `getrandom`, tests inject a deterministic byte stream. Public so wrappers
/// (e.g. `jdp::client::JdpSessionState`) can expose the same hook.
pub type RngFn = dyn FnMut(&mut [u8]) -> Result<(), String> + Send + 'static;

/// Token length in bytes. SV2 spec doesn't pin a specific length;
/// 16 bytes leaves 12 random bytes (96 bits) after the counter prefix,
/// which is collision-resistant enough for a per-connection identifier.
pub const TOKEN_LEN: usize = 16;

/// Counter-prefix length (big-endian u32).
pub const TOKEN_COUNTER_LEN: usize = 4;

/// Default token TTL: 1 hour (3600000 milliseconds).
pub const DEFAULT_TOKEN_TTL_MS: u64 = 3_600_000;

/// Default rate limit between allocations on the same connection.
/// SV2 JDP/AllocateMiningJobToken: "rate limited to a rather slow rate"
/// — 1 second.
pub const DEFAULT_RATE_LIMIT_MS: u64 = 1_000;

/// How many allocations a connection may make at once before the rate limit
/// applies. A JDC requests two tokens back to back on connect and does not
/// re-request an unanswered one. The sustained rate stays one per
/// `rate_limit_ms`, so the store stays bounded.
pub const ALLOCATE_BURST: u64 = 2;

// ── Token ────────────────────────────────────────────────────────────

/// Opaque 16-byte JDP token. Hash/Eq compare full byte content;
/// Debug shows only the first 8 hex chars to avoid leaking active
/// tokens into logs verbatim.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token(pub [u8; TOKEN_LEN]);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Full bytes let anyone who sees them act as the JDC.
        write!(
            f,
            "Token({:02x}{:02x}{:02x}{:02x}…)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

// ── AllocatedToken ───────────────────────────────────────────────────

/// One issued token's bookkeeping. `coinbase_outputs` is the single-output
/// payload returned in `AllocateMiningJobTokenSuccess.coinbase_outputs`;
/// `jdp::dynamic_outputs` falls back to it when a 0x0003-unaware JDC skips
/// the dynamic step.
#[derive(Clone, Debug)]
pub struct AllocatedToken {
    pub token: Token,
    pub miner_address: AddressId,
    pub coinbase_outputs: Vec<u8>,
    pub expires_at_ms: u64,
}

impl AllocatedToken {
    /// `true` iff `now_ms > expires_at_ms` (strict greater than).
    /// The boundary timestamp is still active.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms > self.expires_at_ms
    }
}

// ── Errors ───────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenAllocError {
    /// The [`ALLOCATE_BURST`] is spent and not yet refilled. The caller drops
    /// the request silently: SV2 JDP/AllocateMiningJobToken defines no wire
    /// response for rate limiting.
    #[error("allocation rate limited: next allocation possible in {retry_in_ms} ms")]
    RateLimited { retry_in_ms: u64 },
    /// `getrandom` failed. The caller drops the request rather than issue a
    /// token with a predictable suffix.
    #[error("token entropy: {0}")]
    EntropyFailed(String),
    /// The 32-bit counter saturated (~4 billion tokens on one connection).
    #[error("token counter saturated")]
    CounterSaturated,
}

// ── TokenStore ───────────────────────────────────────────────────────

/// Per-connection token bookkeeping. Owned `&mut` by the JDP
/// connection task — no internal locking.
pub struct TokenStore {
    counter: u32,
    /// When the allocation budget is fully refilled: every allocation pushes
    /// it one `rate_limit_ms` further, starting from now at the latest. An
    /// allocation is allowed while it lies no more than
    /// `ALLOCATE_BURST - 1` intervals ahead.
    budget_refilled_at_ms: u64,
    allocated: HashMap<Token, AllocatedToken>,
    rate_limit_ms: u64,
    ttl_ms: u64,
    /// Test override for the random-suffix source; `None` uses `getrandom`.
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

    /// Override the random-suffix source. Pass `Some(closure)` to
    /// inject a deterministic byte stream for tests; pass `None` to
    /// revert to the OS `getrandom`.
    pub fn set_rng(&mut self, rng: Option<Box<RngFn>>) {
        self.rng = rng;
    }

    pub fn len(&self) -> usize {
        self.allocated.len()
    }

    pub fn is_empty(&self) -> bool {
        self.allocated.is_empty()
    }

    /// Mint a token for a message the POOL originates: the
    /// `new_mining_job_token` of a `DeclareMiningJobSuccess`.
    ///
    /// Not rate-limited: SV2 JDP/AllocateMiningJobToken limits the client's
    /// `AllocateMiningJobToken`, and the pool's own answer must not draw from
    /// that budget (a JDC that allocates and declares within one second would
    /// otherwise get no answer at all).
    ///
    /// Not stored: nothing looks a declaration token up here (the mining side
    /// resolves it through the bridge, `PushSolution` through
    /// [`crate::jdp::declarations::DeclaredJobStore`]). Keeping it out of the
    /// allocated set also means a `new_mining_job_token` is never accepted as
    /// the `mining_job_token` of a later `DeclareMiningJob`.
    pub fn mint_for_declaration(&mut self) -> Result<Token, TokenAllocError> {
        self.next_token()
    }

    /// Allocate a new token and record it under `(miner_address,
    /// coinbase_outputs)`. Enforces the SV2 JDP/AllocateMiningJobToken rate
    /// limit (see [`Self::mint_for_declaration`] for the path that must not).
    ///
    /// Sweeps expired entries on the way in, which is what removes tokens
    /// that are allocated but never presented. Rate limit plus TTL bound the
    /// map, and the rate limit also keeps one sweep per insert cheap.
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

    /// The token shape (counter prefix + entropy suffix), shared by
    /// `allocate` and `mint_for_declaration`. Storage, TTL and the rate limit
    /// live in the callers because that is where the two differ; the
    /// allocation budget is the client's and is charged only by `allocate`.
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

    /// Look up a token without expiry check or consuming it.
    ///
    /// For tests only: production paths must honour expiry AND consume the
    /// token, which is [`Self::take_active`]. This is the non-consuming view
    /// that tells "taken" or "pruned" apart from "still there".
    pub fn lookup(&self, token: &Token) -> Option<&AllocatedToken> {
        self.allocated.get(token)
    }

    /// TAKE the token a declaration presents: remove it from the map and
    /// hand back its entry, unless it had already expired.
    ///
    /// An allocate token authorises exactly ONE declaration attempt
    /// (SV2 JDP/Full-Template Mode: a token "to identify some unique work"),
    /// spent whether the declaration is accepted or refused. Removing before
    /// the expiry check also drops an expired entry.
    ///
    /// ⚠️ The mining side differs: its token survives a rejection, because on
    /// `stale-chain-tip` the JDC retries the SAME custom job on the SAME
    /// token. Here the JDC re-declares with the next token it holds.
    pub fn take_active(&mut self, token: &Token, now_ms: u64) -> Option<AllocatedToken> {
        let entry = self.allocated.remove(token)?;
        (!entry.is_expired(now_ms)).then_some(entry)
    }

    /// Sweep expired entries and return how many were removed.
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

    /// Deterministic RNG that fills with a constant byte. Lets tests
    /// assert exact token byte content.
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

    /// Counter is encoded big-endian in the first 4 bytes; the random
    /// suffix fills the rest. First allocation has counter=1.
    #[test]
    fn first_allocation_has_counter_one_in_big_endian() {
        let mut s = fresh_store_with_rng(0xAB);
        let token = s.allocate(0, addr(), vec![]).unwrap().token;
        assert_eq!(token.0[0..4], [0x00, 0x00, 0x00, 0x01]);
        assert_eq!(token.0[4..16], [0xAB; 12]);
    }

    /// Subsequent allocations bump the counter.
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

    /// Debug impl truncates to first 4 bytes — never leaks the full
    /// token into logs.
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

    /// The burst goes out at once; the allocation after it waits for a
    /// refill, and is told how long.
    #[test]
    fn rate_limit_blocks_the_call_after_the_burst() {
        let mut s = fresh_store_with_rng(0x00);
        for _ in 0..ALLOCATE_BURST {
            s.allocate(0, addr(), vec![]).unwrap();
        }
        let err = s.allocate(999, addr(), vec![]).unwrap_err();
        assert_eq!(err, TokenAllocError::RateLimited { retry_in_ms: 1 });
    }

    /// After the burst, exactly one allocation per interval: at the refill
    /// boundary one goes through, a second one at the same instant does not.
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

    /// A connection that stayed quiet gets its burst back, not more: idle
    /// time does not bank allocations beyond it.
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

    /// Custom rate limit honoured.
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

    /// `expires_at_ms = now + ttl_ms`.
    #[test]
    fn expires_at_is_now_plus_ttl() {
        let mut s = fresh_store_with_rng(0x00);
        let alloc = s.allocate(5_000, addr(), vec![]).unwrap();
        assert_eq!(alloc.expires_at_ms, 5_000 + DEFAULT_TOKEN_TTL_MS);
    }

    /// At exact expiry boundary `is_expired = false` (strict greater-than).
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

    /// `lookup` finds active tokens.
    #[test]
    fn lookup_finds_active_token() {
        let mut s = fresh_store_with_rng(0x00);
        let token = s.allocate(0, addr(), vec![1, 2, 3]).unwrap().token;
        let entry = s.lookup(&token).unwrap();
        assert_eq!(entry.coinbase_outputs, vec![1, 2, 3]);
    }

    /// `take_active` hands the entry back once; a second attempt on the same
    /// token finds nothing.
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

    /// An expired token is dropped rather than handed out; the boundary
    /// timestamp is still active, same rule as `AllocatedToken::is_expired`.
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
        // Way past TTL.
        assert!(s.take_active(&token, 5_000).is_none());
        // Pruned on the way out, not left behind for the sweep.
        assert!(s.lookup(&token).is_none());
        assert_eq!(s.len(), 0);
    }

    /// `take_active` for an unknown token returns None without panic.
    #[test]
    fn take_active_unknown_is_none() {
        let mut s = TokenStore::new();
        assert!(s.take_active(&Token([0xFF; TOKEN_LEN]), 0).is_none());
    }

    // ── cleanup_expired ────────────────────────────────────────────

    /// Sweep removes only expired entries.
    #[test]
    fn cleanup_expired_removes_only_expired() {
        let mut s = TokenStore::with_config(0, 1_000);
        s.set_rng(Some(const_rng(0x00)));
        let t1 = s.allocate(0, addr(), vec![]).unwrap().token;
        let t2 = s.allocate(500, addr(), vec![]).unwrap().token;
        // t1 expires at 1000, t2 expires at 1500.
        let removed = s.cleanup_expired(1_200);
        assert_eq!(removed, 1);
        assert!(s.lookup(&t1).is_none(), "t1 should be evicted");
        assert!(s.lookup(&t2).is_some(), "t2 still active");
    }

    /// Sweep at boundary keeps the entry alive (strict greater-than).
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
