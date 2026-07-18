// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-server (JDP → Mining) declared-job registry.
//!
//! `bp-stratum-v2` is a single crate with two SV2 sub-protocols served
//! on separate TCP ports:
//!
//! - The **JDP server** ([`crate::jdp::client`]) accepts JDC connections
//!   and stores declared jobs per-connection in
//!   [`crate::jdp::declarations::DeclaredJobStore`].
//! - The **Mining server** ([`crate::mining::client`]) accepts miner
//!   connections and handles the `SetCustomMiningJob` frame when a
//!   JDC miner finalises its declared job.
//!
//! The two share a process but live in independent per-connection
//! tasks. When a JDC sends `SetCustomMiningJob{mining_job_token: T}`
//! on its **mining** connection, the mining-side handler needs to
//! retrieve the [`crate::jdp::declarations::DeclaredJob`] payload
//! that was stored on its **JDP** connection — same miner, different
//! connection, different task.
//!
//! [`JdpDeclaredJobRegistry`] is the bridge: a pool-wide token-keyed
//! map populated by the JDP-server (via the
//! [`crate::jdp::client::JdpSessionEvent::JobDeclared`] event hook in
//! the IO layer) and queried by the mining-server in
//! `mining::client::handle_set_custom_mining_job` for the SetCustomMiningJob
//! security cross-check.
//!
//! The registry is a **pure data structure** — no internal locking,
//! no async. The IO layer wraps a single instance in
//! `Arc<RwLock<JdpDeclaredJobRegistry>>` (production) or
//! `Arc<Mutex<...>>` (tests, single-writer parity) and shares the
//! handle to both server tasks. Read-heavy access patterns favour
//! `RwLock`; writes only happen on `JobDeclared` (cadence ≈ once per
//! JDC declaration round, sub-second) and on connection close.
//!
//! Each entry carries:
//! - The full cloned [`crate::jdp::declarations::DeclaredJob`] (so the
//!   mining-handler can build the ExtendedJob + emit
//!   `SetCustomMiningJobSuccess` without a second cross-connection
//!   hop).
//! - The owning JDP session id (used by
//!   [`JdpDeclaredJobRegistry::evict_for_jdp_session`] on connection
//!   close — keeps the registry bounded as JDC connections come and
//!   go).
//! - The miner address (cross-checked against the mining-connection's
//!   locked address when the mining-handler resolves the token, so
//!   one miner can't steal another's declared job).
//! - The wall-clock ms when the entry was registered (drives the
//!   periodic-cleanup tick).
//!
//! ## Lifecycle
//!
//! ```text
//! JDC opens JDP connection
//!     ↓
//! JDP-server emits JdpSessionEvent::JobDeclared{...}
//!     ↓
//! IO-layer calls registry.register(...)              (write)
//!     ↓
//! JDC opens mining connection, sends SetCustomMiningJob
//!     ↓
//! Mining-handler calls registry.lookup(&token)        (read)
//!     ↓ Some(...)
//! Mining-handler builds ExtendedJob, emits Success
//!     ↓
//! JDC disconnects (either side)
//!     ↓
//! IO-layer calls registry.evict_for_jdp_session(id)   (write)
//! ```

use std::collections::HashMap;

use bp_common::AddressId;

use crate::jdp::declarations::DeclaredJob;
use crate::tokens::Token;

// ── Registered job entry ─────────────────────────────────────────────

/// One bridge entry. Owns its data — the JDP-side
/// [`crate::jdp::declarations::DeclaredJobStore`] keeps its own copy
/// (so prev_hash-match-for-PushSolution still works there); this
/// registry holds the cross-connection copy the mining-side handler
/// will consume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredDeclaredJob {
    /// The declared job's full payload — coinbase prefix/suffix +
    /// merkle context + raw tx data. Mining-handler reads this to
    /// build the ExtendedJob.
    pub declared_job: DeclaredJob,
    /// Miner address bound to this token. Cross-checked at lookup
    /// time against the mining-connection's locked address.
    pub miner_address: AddressId,
    /// JDP session id that registered the entry. Used by
    /// [`JdpDeclaredJobRegistry::evict_for_jdp_session`] when the
    /// JDP connection closes.
    pub jdp_session_id: u32,
    /// Wall-clock ms when the entry was registered. Drives
    /// [`JdpDeclaredJobRegistry::cleanup_expired`].
    pub registered_at_ms: u64,
}

/// Slim projection of a bridge entry for the mining-side
/// `SetCustomMiningJob` cross-checks: the miner identity plus the tip the
/// declaration was accepted under — not the (potentially large)
/// declared-job payload the handler doesn't need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeJobRef {
    /// Miner address bound to the token (cross-checked against the mining
    /// channel's locked address).
    pub miner_address: AddressId,
    /// Pool chain-tip the declaration was accepted under. `None` when the
    /// pool had no tip at accept time (cold start) — then the mining-side
    /// tip binding is not checkable.
    pub declared_prev_hash: Option<[u8; 32]>,
}

// ── IssuedPayoutSet (ext 0x0003) ─────────────────────────────────────

/// One issued ext-0x0003 payout output set, tracked pool-wide so the
/// mining-server's `SetCustomMiningJob` handler can validate — and
/// single-use-consume — the coinbase outputs a JDC submits. This covers
/// BOTH Job-Declaration modes: in Full-Template mode it re-validates the
/// mined coinbase against the committed set (binding it to the set the
/// JDS already checked at declare-time, so a JDC can't swap the coinbase
/// after `DeclareMiningJob.Success`), and in Coinbase-only mode it is the
/// Pool's sole validation point (spec §5.3).
///
/// Keyed by `mining_job_token`: the JDS registers it under the allocation
/// token at `RequestPayoutOutputs.Success`, then re-keys it to the
/// `new_mining_job_token` on `DeclareMiningJob.Success` so a Full-Template
/// `SetCustomMiningJob` (which carries the new token) still resolves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedPayoutSet {
    /// Consensus-serialised `Vec<TxOut>` the pool committed to (the bytes
    /// returned in `RequestPayoutOutputs.Success.coinbase_tx_outputs`).
    pub outputs: Vec<u8>,
    /// Miner address bound to the token — cross-checked against the mining
    /// channel's locked address (the only such check in Coinbase-only mode,
    /// where there is no `RegisteredDeclaredJob`).
    pub miner_address: AddressId,
    /// JDP session that issued it (evicted on that session's disconnect).
    pub jdp_session_id: u32,
    /// Wall-clock ms when issued (drives `cleanup_expired`).
    pub registered_at_ms: u64,
    /// Pool chain-tip (`prev_hash`) the set was issued under, if known. The
    /// `SetCustomMiningJob` validator rejects the set as stale when the
    /// submitted job's `prev_hash` differs — the payout distribution was
    /// computed for a now-superseded accounting epoch (spec §4 MAY: stale /
    /// superseded). `None` when the pool had no tip at issuance (not
    /// checkable). A JDC can't bypass this: building on a stale `prev_hash`
    /// to match an old set orphans the block, so there is no payout to steal.
    pub issued_prev_hash: Option<[u8; 32]>,
    /// Single-use flag (spec §4): set once a `SetCustomMiningJob` consumed it.
    pub used: bool,
}

// ── JdpDeclaredJobRegistry ───────────────────────────────────────────

/// Pool-wide cross-connection registry shared by the JDP server (writer)
/// and the mining server (reader). Holds two token-keyed maps:
///
/// - **declared jobs** keyed by the `new_mining_job_token` issued in
///   `DeclareMiningJobSuccess` — the mining-side `SetCustomMiningJob`
///   handler's payload + miner-address cross-check.
/// - **issued payout sets** ([`IssuedPayoutSet`], ext 0x0003) keyed by
///   `mining_job_token` — the committed coinbase outputs a
///   `SetCustomMiningJob` MUST carry.
///
/// Owned by the IO layer inside `Arc<RwLock<...>>` (or `Mutex`) so
/// both servers can share it. The struct itself is sync + has no internal
/// locking — the outer lock wrapper sequences cross-task access.
#[derive(Debug, Default)]
pub struct JdpDeclaredJobRegistry {
    entries: HashMap<Token, RegisteredDeclaredJob>,
    payout_sets: HashMap<Token, IssuedPayoutSet>,
}

impl JdpDeclaredJobRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Register a declared job. Returns the previously-registered
    /// entry if the token was already in the map (which should not
    /// happen with a unique-token-per-allocation invariant — kept
    /// for symmetry with [`HashMap::insert`]).
    pub fn register(
        &mut self,
        token: Token,
        entry: RegisteredDeclaredJob,
    ) -> Option<RegisteredDeclaredJob> {
        self.entries.insert(token, entry)
    }

    /// Look up a token. Returns `None` for unknown / evicted tokens
    /// (mining-handler emits `invalid-job-id`-equivalent).
    pub fn lookup(&self, token: &Token) -> Option<&RegisteredDeclaredJob> {
        self.entries.get(token)
    }

    /// Slim projection of a token's bridge entry for the mining-side
    /// `SetCustomMiningJob` cross-checks. `None` for unknown / evicted
    /// tokens (the mining-handler fails closed on that, together with an
    /// absent payout set).
    pub fn job_ref(&self, token: &Token) -> Option<BridgeJobRef> {
        self.entries.get(token).map(|e| BridgeJobRef {
            miner_address: e.miner_address.clone(),
            declared_prev_hash: e.declared_job.prev_hash,
        })
    }

    /// Register an issued ext-0x0003 payout set. Overwrites any prior set
    /// for the same token — the JDC requests a fresh set per custom job, so
    /// the latest is authoritative.
    pub fn register_payout_set(&mut self, token: Token, set: IssuedPayoutSet) {
        self.payout_sets.insert(token, set);
    }

    /// Look up the issued payout set for a token (for `SetCustomMiningJob`
    /// coinbase-output validation).
    pub fn lookup_payout_set(&self, token: &Token) -> Option<&IssuedPayoutSet> {
        self.payout_sets.get(token)
    }

    /// Re-key a payout set from the allocation token to the
    /// `new_mining_job_token` issued by `DeclareMiningJob.Success`, so a
    /// Full-Template `SetCustomMiningJob` (which references the new token)
    /// resolves it. No-op if no set is registered under `old`, or `old == new`.
    pub fn rekey_payout_set(&mut self, old: &Token, new: &Token) {
        if old == new {
            return;
        }
        if let Some(set) = self.payout_sets.remove(old) {
            self.payout_sets.insert(*new, set);
        }
    }

    /// Mark a payout set consumed (spec §4 single-use). Idempotent; no-op
    /// for an unknown token.
    pub fn consume_payout_set(&mut self, token: &Token) {
        if let Some(set) = self.payout_sets.get_mut(token) {
            set.used = true;
        }
    }

    /// Number of tracked payout sets. Diagnostics / tests.
    pub fn payout_set_count(&self) -> usize {
        self.payout_sets.len()
    }

    /// Drop one specific token. Idempotent.
    pub fn remove(&mut self, token: &Token) -> Option<RegisteredDeclaredJob> {
        self.entries.remove(token)
    }

    /// Drop every entry owned by a closing JDP session. Returns the
    /// count removed — useful for diagnostics + the IO layer's
    /// connection-close log.
    pub fn evict_for_jdp_session(&mut self, jdp_session_id: u32) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, e| e.jdp_session_id != jdp_session_id);
        // Drop this session's issued payout sets too — they're only
        // meaningful while the JDC connection that requested them is live.
        self.payout_sets
            .retain(|_, s| s.jdp_session_id != jdp_session_id);
        before - self.entries.len()
    }

    /// Sweep entries older than `max_age_ms`. Returns the count
    /// removed. Run on a slow timer (e.g. once per minute) — most
    /// entries are evicted by [`Self::evict_for_jdp_session`] on
    /// connection close, this is just a backstop for tokens that
    /// outlive their JDP session's clean teardown (forced
    /// disconnect, OS-level reset). Boundary inclusive: an entry
    /// whose age **equals** `max_age_ms` is kept.
    pub fn cleanup_expired(&mut self, now_ms: u64, max_age_ms: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, e| now_ms.saturating_sub(e.registered_at_ms) <= max_age_ms);
        // Same age-out for issued payout sets — bounds the map for sets that
        // outlive a clean JDP teardown (forced disconnect / OS reset).
        self.payout_sets
            .retain(|_, s| now_ms.saturating_sub(s.registered_at_ms) <= max_age_ms);
        before - self.entries.len()
    }

    /// Iterate all registered tokens. Order is unspecified (HashMap
    /// iteration). Used by diagnostics / tests.
    pub fn iter(&self) -> impl Iterator<Item = (&Token, &RegisteredDeclaredJob)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as Map;

    const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    fn addr() -> AddressId {
        AddressId::new(ADDR.to_string()).unwrap()
    }

    fn token(byte: u8) -> Token {
        Token([byte; 16])
    }

    fn declared(token: Token) -> DeclaredJob {
        DeclaredJob {
            new_token: token,
            original_token: Token([0u8; 16]),
            request_id: 1,
            version: 0x2000_0000,
            coinbase_tx_prefix: vec![0xAA; 8],
            coinbase_tx_suffix: vec![0xBB; 8],
            wtxid_list: vec![],
            raw_transactions: Map::new(),
            prev_hash: Some([0xAB; 32]),
            declared_at_ms: 1_000,
        }
    }

    fn registration(token: Token, session_id: u32, now_ms: u64) -> RegisteredDeclaredJob {
        RegisteredDeclaredJob {
            declared_job: declared(token),
            miner_address: addr(),
            jdp_session_id: session_id,
            registered_at_ms: now_ms,
        }
    }

    // ── basic CRUD ─────────────────────────────────────────────────

    #[test]
    fn register_and_lookup_roundtrips() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(1);
        reg.register(t, registration(t, 42, 1_000));
        let got = reg.lookup(&t).expect("must find");
        assert_eq!(got.jdp_session_id, 42);
        assert_eq!(got.declared_job.new_token, t);
        assert_eq!(got.miner_address.as_str(), ADDR);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let reg = JdpDeclaredJobRegistry::new();
        assert!(reg.lookup(&token(0xFF)).is_none());
    }

    #[test]
    fn register_overwrites_existing_token() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(1);
        reg.register(t, registration(t, 42, 1_000));
        let prev = reg
            .register(t, registration(t, 99, 2_000))
            .expect("must return previous");
        assert_eq!(prev.jdp_session_id, 42);
        assert_eq!(reg.lookup(&t).unwrap().jdp_session_id, 99);
        assert_eq!(reg.len(), 1, "no duplicate stored");
    }

    #[test]
    fn remove_drops_entry() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(1);
        reg.register(t, registration(t, 1, 1_000));
        let removed = reg.remove(&t).expect("must remove");
        assert_eq!(removed.jdp_session_id, 1);
        assert!(reg.is_empty());
    }

    #[test]
    fn remove_unknown_is_idempotent_noop() {
        let mut reg = JdpDeclaredJobRegistry::new();
        assert!(reg.remove(&token(0xFF)).is_none());
    }

    // ── evict_for_jdp_session ──────────────────────────────────────

    #[test]
    fn evict_for_jdp_session_removes_only_matching_session() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.register(token(1), registration(token(1), 42, 1_000));
        reg.register(token(2), registration(token(2), 42, 1_100));
        reg.register(token(3), registration(token(3), 99, 1_200));
        let evicted = reg.evict_for_jdp_session(42);
        assert_eq!(evicted, 2);
        assert_eq!(reg.len(), 1);
        assert!(reg.lookup(&token(3)).is_some());
        assert!(reg.lookup(&token(1)).is_none());
    }

    #[test]
    fn evict_for_unknown_session_returns_zero() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.register(token(1), registration(token(1), 42, 1_000));
        assert_eq!(reg.evict_for_jdp_session(999), 0);
        assert_eq!(reg.len(), 1);
    }

    // ── cleanup_expired ────────────────────────────────────────────

    #[test]
    fn cleanup_expired_removes_only_aged_entries() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.register(token(1), registration(token(1), 1, 1_000));
        reg.register(token(2), registration(token(2), 1, 5_000));
        // max_age = 1500 ms, now = 4_000:
        //   entry 1: age 3_000 > 1_500 → evict
        //   entry 2: now < registered_at → saturating_sub → 0 ≤ 1_500 → keep
        let evicted = reg.cleanup_expired(4_000, 1_500);
        assert_eq!(evicted, 1);
        assert!(reg.lookup(&token(1)).is_none());
        assert!(reg.lookup(&token(2)).is_some());
    }

    #[test]
    fn cleanup_expired_boundary_is_inclusive() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.register(token(1), registration(token(1), 1, 1_000));
        let evicted = reg.cleanup_expired(1_000 + 1_500, 1_500);
        assert_eq!(evicted, 0, "boundary age == max_age must keep");
        assert!(reg.lookup(&token(1)).is_some());
    }

    #[test]
    fn cleanup_expired_zero_age_returns_zero() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.register(token(1), registration(token(1), 1, 1_000));
        // now < registered_at: saturating_sub → 0, always ≤ max_age.
        assert_eq!(reg.cleanup_expired(500, 100), 0);
        assert!(reg.lookup(&token(1)).is_some());
    }

    // ── iter ───────────────────────────────────────────────────────

    #[test]
    fn iter_yields_all_entries() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.register(token(1), registration(token(1), 1, 1_000));
        reg.register(token(2), registration(token(2), 2, 2_000));
        let collected: Vec<u32> = reg.iter().map(|(_, e)| e.jdp_session_id).collect();
        assert_eq!(collected.len(), 2);
    }

    // ── issued payout sets (ext 0x0003) ────────────────────────────

    fn payout_set(session_id: u32, now_ms: u64) -> IssuedPayoutSet {
        IssuedPayoutSet {
            outputs: vec![0x01, 0x02, 0x03],
            miner_address: addr(),
            jdp_session_id: session_id,
            registered_at_ms: now_ms,
            issued_prev_hash: Some([0xAB; 32]),
            used: false,
        }
    }

    #[test]
    fn payout_set_register_lookup_consume() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(1);
        reg.register_payout_set(t, payout_set(7, 1_000));
        assert_eq!(reg.payout_set_count(), 1);
        assert!(!reg.lookup_payout_set(&t).unwrap().used);
        reg.consume_payout_set(&t);
        assert!(reg.lookup_payout_set(&t).unwrap().used);
        // Consuming an unknown token is a harmless no-op.
        reg.consume_payout_set(&token(0xFF));
    }

    #[test]
    fn payout_set_rekey_moves_to_new_token() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let old = token(1);
        let new = token(2);
        reg.register_payout_set(old, payout_set(7, 1_000));
        reg.rekey_payout_set(&old, &new);
        assert!(reg.lookup_payout_set(&old).is_none());
        assert!(reg.lookup_payout_set(&new).is_some());
        assert_eq!(reg.payout_set_count(), 1);
        // No-op when old == new or old is unknown.
        reg.rekey_payout_set(&new, &new);
        reg.rekey_payout_set(&token(9), &token(10));
        assert_eq!(reg.payout_set_count(), 1);
    }

    #[test]
    fn payout_set_evicted_with_jdp_session() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.register_payout_set(token(1), payout_set(42, 1_000));
        reg.register_payout_set(token(2), payout_set(99, 1_000));
        reg.evict_for_jdp_session(42);
        assert!(reg.lookup_payout_set(&token(1)).is_none());
        assert!(reg.lookup_payout_set(&token(2)).is_some());
    }

    #[test]
    fn payout_set_cleanup_expired_ages_out() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.register_payout_set(token(1), payout_set(1, 1_000));
        reg.cleanup_expired(4_000, 1_500); // age 3_000 > 1_500 → drop
        assert!(reg.lookup_payout_set(&token(1)).is_none());
    }
}
