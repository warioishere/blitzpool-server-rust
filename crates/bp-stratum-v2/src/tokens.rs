// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection JDP-token store. Tokens are opaque 16-byte
//! identifiers the JDS hands to a JDC on
//! `AllocateMiningJobToken`. The JDC then references them in
//! `RequestPayoutOutputs` (ext 0x0003) and `DeclareMiningJob`. Each
//! token has a 1 h TTL (SV2 spec 6.4.2 — "the JDC SHOULD use the token
//! within a reasonable amount of time") and the pool rate-limits
//! allocations to one per 1 s per connection (spec 6.4.2 — "rate
//! limited to a rather slow rate").
//!
//! ## Format
//!
//! 16 bytes laid out as:
//! - **bytes 0..4** — per-connection counter, **big-endian**. The
//!   counter is incremented BEFORE encoding, so the first token allocated
//!   on a connection has `counter = 1` → bytes `00 00 00 01`. Zero is
//!   reserved.
//! - **bytes 4..16** — 12 CSPRNG bytes from `getrandom`. Makes the
//!   token unguessable so a misbehaving JDC can't forge tokens for a
//!   different connection.
//!
//! ## Lifecycle
//!
//! - `allocate` enforces the rate limit, generates a fresh token,
//!   stamps `expires_at_ms = now + TTL`, stores the `(token →
//!   AllocatedToken)` mapping.
//! - `lookup_active` checks expiry on read and self-prunes expired
//!   entries lazily.
//! - `remove` is for the `DeclareMiningJob` path: once the JDC uses
//!   the token to declare a job, the JDS issues a NEW token for the
//!   declared-job side. The original AllocateMiningJobToken token is
//!   NOT deleted; `remove` is for explicit teardown only.
//! - `cleanup_expired` is a periodic-tick helper; the lazy
//!   `lookup_active` is the primary GC path.

use std::collections::HashMap;

use bp_common::AddressId;

/// Test-side RNG hook signature. The store holds an `Option<Box<…>>`
/// of this so production code uses `getrandom::getrandom` and tests
/// can inject a deterministic byte-stream. Returning the `String`
/// error matches what `getrandom::Error::to_string` would produce.
/// Boxed RNG closure type used by [`TokenStore::set_rng`]. Public so
/// callers wrapping `TokenStore` (e.g. `jdp::client::JdpSessionState`)
/// can expose a deterministic-RNG hook without re-declaring the
/// `dyn FnMut` shape and tripping `clippy::type_complexity`.
pub type RngFn = dyn FnMut(&mut [u8]) -> Result<(), String> + Send + 'static;

/// Token length in bytes. SV2 spec doesn't pin a specific length;
/// 16 bytes provides sufficient collision-resistance with 12 random
/// bits of entropy.
pub const TOKEN_LEN: usize = 16;

/// Counter-prefix length (big-endian u32).
pub const TOKEN_COUNTER_LEN: usize = 4;

/// CSPRNG-suffix length.
pub const TOKEN_RANDOM_LEN: usize = TOKEN_LEN - TOKEN_COUNTER_LEN;

/// Default token TTL: 1 hour (3600000 milliseconds).
pub const DEFAULT_TOKEN_TTL_MS: u64 = 3_600_000;

/// Default rate limit between allocations on the same connection.
/// SV2 spec 6.4.2: "rate limited to a rather slow rate" — 1 second.
pub const DEFAULT_RATE_LIMIT_MS: u64 = 1_000;

// ── Token ────────────────────────────────────────────────────────────

/// Opaque 16-byte JDP token. Hash/Eq compare full byte content;
/// Debug shows only the first 8 hex chars to avoid leaking active
/// tokens into logs verbatim.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token(pub [u8; TOKEN_LEN]);

impl Token {
    pub fn as_bytes(&self) -> &[u8; TOKEN_LEN] {
        &self.0
    }

    /// Lowercase hex of the full 16 bytes — a stable, log-safe-ish
    /// string form of the token (used in diagnostics).
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(TOKEN_LEN * 2);
        for byte in &self.0 {
            out.push(hex_digit((byte >> 4) & 0xF));
            out.push(hex_digit(byte & 0xF));
        }
        out
    }
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => unreachable!(),
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show only the first 4 bytes (8 hex chars) — full bytes are
        // secret-ish (anyone who sees them can act as the JDC).
        write!(
            f,
            "Token({:02x}{:02x}{:02x}{:02x}…)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

// ── AllocatedToken ───────────────────────────────────────────────────

/// One issued token's bookkeeping. `coinbase_outputs` is the
/// §6.4.3 fallback single-output payload returned in
/// `AllocateMiningJobTokenSuccess.coinbase_outputs`. Used later by
/// `jdp::dynamic_outputs` as the fallback when a 0x0003-unaware JDC
/// skips the dynamic step.
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
    /// Caller breached the per-connection allocation rate limit
    /// (`now - last_alloc_ms < rate_limit_ms`). The caller should
    /// silently drop the request — SV2 spec 6.4.2 says nothing about a
    /// wire response for rate limiting.
    #[error("allocation rate limited: {elapsed_ms} ms since last (min {min_ms} ms)")]
    RateLimited { elapsed_ms: u64, min_ms: u64 },
    /// `getrandom` returned an error. The OS RNG only fails in
    /// pathological cases (closed FDs in a hardened seccomp sandbox).
    /// On failure the caller should drop the request — never proceed
    /// with a predictable token suffix.
    #[error("token entropy: {0}")]
    EntropyFailed(String),
    /// The 32-bit counter saturated. Would require ~4 billion
    /// allocations on a single connection — defensive only.
    #[error("token counter saturated")]
    CounterSaturated,
}

// ── TokenStore ───────────────────────────────────────────────────────

/// Per-connection token bookkeeping. Owned `&mut` by the JDP
/// connection task — no internal locking.
pub struct TokenStore {
    counter: u32,
    last_alloc_ms: Option<u64>,
    allocated: HashMap<Token, AllocatedToken>,
    rate_limit_ms: u64,
    ttl_ms: u64,
    /// Optional override for the random-suffix source — exposes a
    /// hook for deterministic tests. Production calls use
    /// `getrandom::getrandom`.
    rng: Option<Box<RngFn>>,
}

impl std::fmt::Debug for TokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenStore")
            .field("counter", &self.counter)
            .field("last_alloc_ms", &self.last_alloc_ms)
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
            last_alloc_ms: None,
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

    /// Allocate a new token + record it under `(miner_address,
    /// coinbase_outputs)`. Enforces rate limit. Bumps the per-connection
    /// counter (BE-encoded into the token prefix).
    pub fn allocate(
        &mut self,
        now_ms: u64,
        miner_address: AddressId,
        coinbase_outputs: Vec<u8>,
    ) -> Result<&AllocatedToken, TokenAllocError> {
        if let Some(last) = self.last_alloc_ms {
            let elapsed = now_ms.saturating_sub(last);
            if elapsed < self.rate_limit_ms {
                return Err(TokenAllocError::RateLimited {
                    elapsed_ms: elapsed,
                    min_ms: self.rate_limit_ms,
                });
            }
        }
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(TokenAllocError::CounterSaturated)?;
        let mut bytes = [0u8; TOKEN_LEN];
        bytes[..4].copy_from_slice(&self.counter.to_be_bytes());
        // Fill bytes[4..16] from RNG.
        if let Some(ref mut rng) = self.rng {
            rng(&mut bytes[TOKEN_COUNTER_LEN..]).map_err(TokenAllocError::EntropyFailed)?;
        } else {
            getrandom::getrandom(&mut bytes[TOKEN_COUNTER_LEN..])
                .map_err(|e| TokenAllocError::EntropyFailed(e.to_string()))?;
        }
        let token = Token(bytes);
        self.last_alloc_ms = Some(now_ms);
        let entry = AllocatedToken {
            token,
            miner_address,
            coinbase_outputs,
            expires_at_ms: now_ms.saturating_add(self.ttl_ms),
        };
        self.allocated.insert(token, entry);
        // Returning &AllocatedToken from the insert path requires
        // a re-lookup since `insert` returns `Option<V>` (the previous
        // value). Tokens are unique so the lookup always succeeds.
        Ok(self.allocated.get(&token).expect("token was just inserted"))
    }

    /// Look up a token without expiry-check. Returns the entry
    /// regardless of `expires_at_ms`. Use when the caller will check
    /// expiry separately or when introspecting for diagnostics.
    pub fn lookup(&self, token: &Token) -> Option<&AllocatedToken> {
        self.allocated.get(token)
    }

    /// Look up a token AND check expiry. On expiry self-prunes the
    /// entry and returns `None`.
    pub fn lookup_active(&mut self, token: &Token, now_ms: u64) -> Option<&AllocatedToken> {
        let expired = self
            .allocated
            .get(token)
            .map(|entry| entry.is_expired(now_ms))
            .unwrap_or(true);
        if expired {
            self.allocated.remove(token);
            return None;
        }
        self.allocated.get(token)
    }

    /// Explicitly drop a token. Idempotent for unknown tokens.
    /// Returns the entry that was dropped (or `None`).
    pub fn remove(&mut self, token: &Token) -> Option<AllocatedToken> {
        self.allocated.remove(token)
    }

    /// Sweep expired entries. Returns the count removed. Use as a
    /// periodic tick if `lookup_active` isn't enough on its own —
    /// e.g. when the connection is being inspected without a fresh
    /// request.
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

    /// `to_hex` produces lowercase 32-char hex of the full 16 bytes.
    #[test]
    fn token_to_hex_is_lowercase_32_chars() {
        let mut s = fresh_store_with_rng(0xCD);
        let token = s.allocate(0, addr(), vec![]).unwrap().token;
        let hex = token.to_hex();
        assert_eq!(hex.len(), 32);
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert!(hex.starts_with("00000001"));
        assert!(hex.ends_with("cdcdcdcdcdcdcdcdcdcdcdcd"));
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

    /// Two allocations within `rate_limit_ms` → second is rejected.
    #[test]
    fn rate_limit_blocks_second_call_within_window() {
        let mut s = fresh_store_with_rng(0x00);
        s.allocate(0, addr(), vec![]).unwrap();
        let err = s.allocate(999, addr(), vec![]).unwrap_err();
        assert_eq!(
            err,
            TokenAllocError::RateLimited {
                elapsed_ms: 999,
                min_ms: 1_000,
            }
        );
    }

    /// At exactly the rate-limit boundary the call goes through
    /// (strict less-than check allows `elapsed == rate_limit`).
    #[test]
    fn rate_limit_allows_call_at_boundary() {
        let mut s = fresh_store_with_rng(0x00);
        s.allocate(0, addr(), vec![]).unwrap();
        assert!(s.allocate(1_000, addr(), vec![]).is_ok());
    }

    /// Custom rate limit honoured.
    #[test]
    fn custom_rate_limit_honoured() {
        let mut s = TokenStore::with_config(500, DEFAULT_TOKEN_TTL_MS);
        s.set_rng(Some(const_rng(0x00)));
        s.allocate(0, addr(), vec![]).unwrap();
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

    // ── lookup / lookup_active ─────────────────────────────────────

    /// `lookup` finds active tokens.
    #[test]
    fn lookup_finds_active_token() {
        let mut s = fresh_store_with_rng(0x00);
        let token = s.allocate(0, addr(), vec![1, 2, 3]).unwrap().token;
        let entry = s.lookup(&token).unwrap();
        assert_eq!(entry.coinbase_outputs, vec![1, 2, 3]);
    }

    /// `lookup_active` returns None + self-prunes for expired entries.
    #[test]
    fn lookup_active_self_prunes_expired() {
        let mut s = TokenStore::with_config(0, 1_000);
        s.set_rng(Some(const_rng(0x00)));
        let token = s.allocate(0, addr(), vec![]).unwrap().token;
        // Way past TTL.
        assert!(s.lookup_active(&token, 5_000).is_none());
        // Already pruned — second lookup also None.
        assert!(s.lookup(&token).is_none());
        assert_eq!(s.len(), 0);
    }

    /// `lookup_active` for unknown token returns None without panic.
    #[test]
    fn lookup_active_unknown_is_none() {
        let mut s = TokenStore::new();
        assert!(s.lookup_active(&Token([0xFF; TOKEN_LEN]), 0).is_none());
    }

    // ── remove ─────────────────────────────────────────────────────

    /// `remove` drops + returns the entry; idempotent for unknown.
    #[test]
    fn remove_drops_and_returns_entry() {
        let mut s = fresh_store_with_rng(0x00);
        let token = s.allocate(0, addr(), vec![]).unwrap().token;
        assert!(s.remove(&token).is_some());
        assert!(s.remove(&token).is_none());
        assert_eq!(s.len(), 0);
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
