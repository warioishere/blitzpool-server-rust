// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-connection JDP-token store. Tokens are opaque 16-byte identifiers the
//! JDS hands to a JDC on `AllocateMiningJobToken`. The JDC then references
//! them in `DeclareMiningJob` and `SetCustomMiningJob`. Each token has a 1 h
//! TTL — OUR policy, the spec sets no lifetime — and the pool rate-limits
//! allocations to one per 1 s per connection, which is the spec's only
//! constraint here (SV2 JDP/AllocateMiningJobToken — "rate limited to a rather
//! slow rate", no number given).
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
//!   AllocatedToken)` mapping, and sweeps expired entries on the way in.
//! - `mint_for_declaration` generates the pool's own
//!   `new_mining_job_token`. Same shape, NO rate limit and NO storage —
//!   nothing ever looks a declaration token up here, and an unbounded
//!   write-only map is what it would otherwise be.
//! - `take_active` CONSUMES the token a `DeclareMiningJob` presents —
//!   one allocate authorises one declaration attempt, and the pool answers
//!   the declared-job side with a separate token of its own. For a session
//!   that declares, this is what keeps the map small: one entry in, one
//!   entry out. `allocate`'s sweep covers the rest — tokens allocated and
//!   never presented, which nothing else would ever touch.
//! - `cleanup_expired` is the sweep itself, also exposed for a
//!   periodic tick.

use std::collections::HashMap;

use bp_common::AddressId;

/// Boxed RNG closure type used by [`TokenStore::set_rng`].
///
/// The store holds an `Option<Box<…>>` of this so production code uses
/// `getrandom::getrandom` while tests inject a deterministic byte-stream.
/// The `String` error matches what `getrandom::Error::to_string` produces.
///
/// Public so callers wrapping `TokenStore` (e.g.
/// `jdp::client::JdpSessionState`) can expose a deterministic-RNG hook
/// without re-declaring the `dyn FnMut` shape and tripping
/// `clippy::type_complexity`.
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

// ── Token ────────────────────────────────────────────────────────────

/// Opaque 16-byte JDP token. Hash/Eq compare full byte content;
/// Debug shows only the first 8 hex chars to avoid leaking active
/// tokens into logs verbatim.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token(pub [u8; TOKEN_LEN]);

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
/// SV2 JDP/AllocateMiningJobToken.Success fallback single-output payload
/// returned in `AllocateMiningJobTokenSuccess.coinbase_outputs`. Used later by
/// `jdp::dynamic_outputs` as the fallback when a 0x0003-unaware JDC skips the
/// dynamic step.
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
    /// silently drop the request — SV2 JDP/AllocateMiningJobToken says
    /// nothing about a wire response for rate limiting.
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

    /// Mint a token for a message the POOL originates — today only the
    /// `new_mining_job_token` of a `DeclareMiningJobSuccess`.
    ///
    /// Deliberately not rate-limited, and that is the whole point of it
    /// existing separately. SV2 JDP/AllocateMiningJobToken asks for the limit
    /// on `AllocateMiningJobToken`, the message a client sends; minting
    /// through [`Self::allocate`] made the pool's own answer draw from the
    /// client's budget. A JDC that allocates and then declares inside the
    /// same second — which the reference client does on every block change,
    /// since it refills its token queue fire-and-forget from four call sites
    /// — had its `DeclareMiningJob` silently dropped, no frame at all, and
    /// waited for an answer that never came.
    ///
    /// It is also **not stored**, and that is not an optimisation. Nothing
    /// ever looks a declaration token up here: the declare path's only
    /// resolution ([`Self::take_active`]) consumes the ALLOCATE token a
    /// `DeclareMiningJob` presents, the mining side resolves the declaration
    /// through the bridge, and `PushSolution` through
    /// [`crate::jdp::declarations::DeclaredJobStore`]. So the entry was
    /// write-only — and, being unbounded once the rate limit came off, the
    /// one thing on this connection that could grow without end.
    ///
    /// Not storing it also closes what storing it opened: a JDC could present
    /// a `new_mining_job_token` as the `mining_job_token` of the NEXT
    /// `DeclareMiningJob` and chain declarations off declaration tokens, each
    /// one minting another. The reference JDS rejects that — `is_allocated`
    /// consults the allocated set only, and activation moves a token OUT of
    /// it (`token_management::TokenManager`, sv2-apps v0.7.0) — so this
    /// matches it rather than diverging.
    pub fn mint_for_declaration(&mut self) -> Result<Token, TokenAllocError> {
        self.next_token()
    }

    /// Allocate a new token + record it under `(miner_address,
    /// coinbase_outputs)`. Enforces the SV2 JDP/AllocateMiningJobToken rate
    /// limit — see [`Self::mint_for_declaration`] for the path that must
    /// not. Bumps the per-connection counter (BE-encoded into the token
    /// prefix).
    ///
    /// Sweeps expired entries on the way in. A session that declares empties
    /// the map as it fills it — [`Self::take_active`] removes the entry it
    /// resolves — so what this sweep is for is the tokens NOBODY presents: a
    /// connection that allocates and never declares left every entry behind
    /// for as long as it stayed open, and nothing else would have touched
    /// them. The rate limit caps inserts at one per second and the TTL caps
    /// their lifetime, so the two together cap the map, but only once
    /// something actually drops the expired ones. One sweep per insert is
    /// affordable for exactly the reason the map is bounded at all: inserts
    /// are rate-limited.
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
        self.last_alloc_ms = Some(now_ms);
        self.cleanup_expired(now_ms);
        let token = self.next_token()?;
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

    /// The token SHAPE — counter prefix + entropy suffix — in one place, so
    /// it cannot drift between the client-facing allocate and the pool's own
    /// minting. Storage, TTL and the rate limit all live in the callers,
    /// because those are the three things that legitimately differ.
    ///
    /// `last_alloc_ms` is deliberately NOT stamped here: it is the
    /// SV2 JDP/AllocateMiningJobToken budget of the CLIENT's allocate message,
    /// and `allocate` stamps it before calling in. Stamping here would make a
    /// pool-minted declaration token block the miner's next allocate for a
    /// second — the same interop bug mirrored.
    fn next_token(&mut self) -> Result<Token, TokenAllocError> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(TokenAllocError::CounterSaturated)?;
        let mut bytes = [0u8; TOKEN_LEN];
        bytes[..TOKEN_COUNTER_LEN].copy_from_slice(&self.counter.to_be_bytes());
        // Fill bytes[4..16] from RNG.
        if let Some(ref mut rng) = self.rng {
            rng(&mut bytes[TOKEN_COUNTER_LEN..]).map_err(TokenAllocError::EntropyFailed)?;
        } else {
            getrandom::getrandom(&mut bytes[TOKEN_COUNTER_LEN..])
                .map_err(|e| TokenAllocError::EntropyFailed(e.to_string()))?;
        }
        Ok(Token(bytes))
    }

    /// Look up a token without expiry-check. Returns the entry
    /// regardless of `expires_at_ms`.
    ///
    /// No production caller, and none is wanted: every path that resolves a
    /// token a JDC presented must honour expiry AND consume it, which is
    /// [`Self::take_active`]. What needs this is the TESTS — it is the only
    /// non-consuming window into the map, so it is what tells "the entry is
    /// still there" apart from "it was taken", and "it was pruned" apart from
    /// "it is there but expired". `take_active` answers `None` to the last
    /// two alike, which is exactly the distinction
    /// `taking_a_token_removes_it` and the `cleanup_expired` tests are
    /// making.
    pub fn lookup(&self, token: &Token) -> Option<&AllocatedToken> {
        self.allocated.get(token)
    }

    /// TAKE the token a declaration presents: remove it from the map and
    /// hand back its entry, unless it had already expired.
    ///
    /// Consuming rather than reading IS the rule. An allocate token
    /// authorises exactly ONE declaration attempt: SV2 JDP/Full-Template Mode
    /// describes it as "a token (allocated by JDS), so it can use it to
    /// identify some unique work", and a token that identifies one piece of
    /// work cannot answer for the next one. It is spent whichever way that
    /// declaration ends, accepted or refused. A read-only lookup let a single
    /// token carry declarations for its whole 1 h TTL, which is not what a
    /// `mining_job_token` identifies.
    ///
    /// Removing before judging expiry subsumes what the old read-only lookup
    /// did on the side: an expired entry is dropped either way.
    ///
    /// ⚠️ The mining side looks like the same rule and is not. A token there
    /// likewise authorises exactly one `SetCustomMiningJob`, but it SURVIVES
    /// a rejection: `stale-chain-tip` on that side means the JDC retries the
    /// SAME custom job on the SAME token, so consuming it would turn a benign
    /// tip race into the fatal fallback every declaration error but that one
    /// triggers. Here `stale-chain-tip` means the JDC rebuilds against its
    /// new template and declares with the next token it holds, so there is
    /// nothing to keep the spent one for.
    pub fn take_active(&mut self, token: &Token, now_ms: u64) -> Option<AllocatedToken> {
        let entry = self.allocated.remove(token)?;
        (!entry.is_expired(now_ms)).then_some(entry)
    }

    /// Sweep expired entries. Returns the count removed. Use as a
    /// periodic tick if `take_active` isn't enough on its own —
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

    // ── lookup / take_active ───────────────────────────────────────

    /// `lookup` finds active tokens.
    #[test]
    fn lookup_finds_active_token() {
        let mut s = fresh_store_with_rng(0x00);
        let token = s.allocate(0, addr(), vec![1, 2, 3]).unwrap().token;
        let entry = s.lookup(&token).unwrap();
        assert_eq!(entry.coinbase_outputs, vec![1, 2, 3]);
    }

    /// `take_active` hands the entry back ONCE. The second attempt on the
    /// same token finds nothing — that is the whole rule an allocate token
    /// carries: it identifies one piece of work, not a session's worth.
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

    /// An expired token is dropped rather than handed out — and the boundary
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
