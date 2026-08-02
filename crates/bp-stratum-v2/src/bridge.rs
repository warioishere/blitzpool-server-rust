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
use std::sync::Arc;

use bp_common::AddressId;

use crate::jdp::declarations::DeclaredJob;
use crate::jdp::payout_distribution::WeightedOutput;
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

// ── Payout distributions (ext 0x0003 push model) ─────────────────────

/// One published `SetPayoutDistribution` (ext 0x0003 §3.1), tracked
/// pool-wide so both the JDP declare path and the mining-side
/// `SetCustomMiningJob` path can resolve a `distribution_id` TLV to
/// the weights it references and validate the coinbase per §7.1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutDistributionEntry {
    /// §3.1: strictly increasing, universal across all connections.
    pub distribution_id: u64,
    /// The pool output (`weight_P` in the amount field).
    pub pool_payout: WeightedOutput,
    /// Miner payout slots in §4 coinbase order.
    pub payouts: Vec<WeightedOutput>,
    /// Parallel to `payouts` (§3.1).
    pub dust_limits: Vec<u32>,
    /// Consensus-serialized 0-value TxOuts the pool appends.
    pub additional_outputs: Vec<Vec<u8>>,
    /// Revenue the distribution's weight boosts were projected against
    /// — the booking band is checked against this.
    pub reference_reward_sats: u64,
    /// Settlement-snapshot identity (weights fingerprint). `None` when
    /// the owning mode books without a snapshot (Solo / Blockparty).
    pub payouts_fingerprint: Option<[u8; 32]>,
    /// Whether a booking may be stamped on jobs built from this
    /// distribution (`false` e.g. when the snapshot write failed — the
    /// job is still served, but a found block is reported-not-booked).
    pub bookable: bool,
    /// `None` = pool-wide (every connection may reference it);
    /// `Some` = tailored to one miner (Solo / Group-Solo / Blockparty).
    pub owner: Option<AddressId>,
    /// JDP session a tailored entry was published to (evicted with it).
    pub jdp_session_id: Option<u32>,
    /// Wall-clock ms at publish (drives the cleanup backstop).
    pub published_at_ms: u64,
}

/// Which acceptance scope a `distribution_id` is resolved under.
#[derive(Clone, Copy, Debug)]
pub enum DistributionScope<'a> {
    /// JDP declare path — the session id picks its tailored slot.
    JdpSession(u32),
    /// Mining-side `SetCustomMiningJob` — no JDP session id on that
    /// connection; tailored entries are matched by owner address.
    MinerAddress(&'a AddressId),
}

/// Outcome of resolving a `distribution_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DistributionAcceptance {
    /// Within the acceptance window — validate against these weights.
    Accepted(Arc<PayoutDistributionEntry>),
    /// Known but superseded / settlement-invalidated (§7.2 / §10)
    /// → `stale-payout-distribution`.
    Stale,
    /// Never published (or long pruned). The spec folds this into the
    /// same error code — a JDC can't distinguish "too old" from
    /// "unknown", both mean "re-fetch and re-declare".
    Unknown,
}

/// A published entry plus the settlement epoch it was published in.
/// Entries from an older epoch are stale (§10: a found block
/// invalidates every distribution); the epoch lives here, registry-
/// side, so [`PayoutDistributionEntry`] stays plainly constructible by
/// the publisher.
#[derive(Clone, Debug)]
struct PublishedDistribution {
    entry: Arc<PayoutDistributionEntry>,
    epoch: u64,
}

/// Latest + immediately-previous published entry (§7.2 grace window of
/// exactly one distribution).
#[derive(Debug, Default)]
struct DistributionSlot {
    latest: Option<PublishedDistribution>,
    previous: Option<PublishedDistribution>,
}

impl DistributionSlot {
    fn publish(&mut self, entry: Arc<PayoutDistributionEntry>, epoch: u64) {
        self.previous = self.latest.take();
        self.latest = Some(PublishedDistribution { entry, epoch });
    }

    fn find(&self, id: u64) -> Option<&PublishedDistribution> {
        [self.latest.as_ref(), self.previous.as_ref()]
            .into_iter()
            .flatten()
            .find(|p| p.entry.distribution_id == id)
    }
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
    /// Pool-wide distribution (PPLNS) — what every connection gets
    /// pushed on open and on the publisher's timer.
    pool_wide_distribution: DistributionSlot,
    /// Tailored per-JDP-session distributions (Solo / Group-Solo /
    /// Blockparty, published after the session's identity is known).
    tailored_distributions: HashMap<u32, DistributionSlot>,
    /// Bumped by [`Self::invalidate_all_distributions`] (§10). Every
    /// entry published under an older epoch resolves as `Stale`.
    settlement_epoch: u64,
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

    // ── Payout distributions (ext 0x0003 push model) ────────────────

    /// Publish a fresh pool-wide distribution. The prior latest slides
    /// into the §7.2 grace slot.
    pub fn publish_pool_wide(&mut self, entry: PayoutDistributionEntry) {
        let epoch = self.settlement_epoch;
        self.pool_wide_distribution.publish(Arc::new(entry), epoch);
    }

    /// Publish a tailored distribution to one JDP session. On the
    /// FIRST tailored publish, the session's grace slot is seeded with
    /// the current pool-wide latest — the JDC may have a declaration
    /// against the pool-wide distribution in flight while this push
    /// travels (§7.2's honest race, cross-slot edition).
    pub fn publish_tailored(&mut self, jdp_session_id: u32, entry: PayoutDistributionEntry) {
        let epoch = self.settlement_epoch;
        let pool_wide_latest = self.pool_wide_distribution.latest.clone();
        let slot = self
            .tailored_distributions
            .entry(jdp_session_id)
            .or_default();
        let first_tailored = slot.latest.is_none();
        slot.publish(Arc::new(entry), epoch);
        // Seed AFTER publish — publish() slides latest into the grace
        // slot, which on the first tailored push is empty; the grace
        // entry the session actually needs is the pool-wide
        // distribution it was declaring against until now.
        if first_tailored {
            slot.previous = pool_wide_latest;
        }
    }

    /// The current pool-wide distribution, if one is USABLE (for the
    /// connection-open push and the publisher's skip-if-unchanged
    /// comparison).
    ///
    /// `None` once a settlement invalidated it (§10), even though the
    /// entry is still held for history: handing it out would push a
    /// JDC a distribution that every declaration referencing it is then
    /// answered `stale-payout-distribution` for, and would let the
    /// publisher compare a rebuilt distribution equal to it and skip
    /// the republish the settlement exists to force.
    pub fn current_pool_wide(&self) -> Option<Arc<PayoutDistributionEntry>> {
        self.pool_wide_distribution
            .latest
            .as_ref()
            .filter(|p| p.epoch == self.settlement_epoch)
            .map(|p| p.entry.clone())
    }

    /// The current tailored distribution for a JDP session, if one is
    /// usable. Settlement-invalidated entries are withheld for the same
    /// reason as in [`Self::current_pool_wide`].
    pub fn current_tailored(&self, jdp_session_id: u32) -> Option<Arc<PayoutDistributionEntry>> {
        self.tailored_distributions
            .get(&jdp_session_id)
            .and_then(|s| s.latest.as_ref())
            .filter(|p| p.epoch == self.settlement_epoch)
            .map(|p| p.entry.clone())
    }

    /// Resolve a `distribution_id` under `scope` (§7.2 acceptance:
    /// latest + immediately-previous; a session with a tailored slot
    /// uses that slot — its grace entry may be the pool-wide
    /// distribution it saw before the tailored push).
    pub fn distribution_acceptance(
        &self,
        distribution_id: u64,
        scope: DistributionScope<'_>,
    ) -> DistributionAcceptance {
        let slot = match scope {
            DistributionScope::JdpSession(id) => self
                .tailored_distributions
                .get(&id)
                .filter(|s| s.latest.is_some())
                .unwrap_or(&self.pool_wide_distribution),
            // One address can own several tailored slots — a JDC that
            // dropped ungracefully leaves a ghost behind until the
            // cleanup sweep, and its reconnect gets a new session. Take
            // the NEWEST publish rather than whichever slot the map
            // happens to yield first, or the live distribution is
            // rejected as stale on an arbitrary fraction of lookups.
            DistributionScope::MinerAddress(addr) => self
                .tailored_distributions
                .values()
                .filter(|s| {
                    s.latest
                        .as_ref()
                        .is_some_and(|p| p.entry.owner.as_ref() == Some(addr))
                })
                .max_by_key(|s| {
                    s.latest
                        .as_ref()
                        .map(|p| (p.entry.published_at_ms, p.entry.distribution_id))
                })
                .unwrap_or(&self.pool_wide_distribution),
        };
        match slot.find(distribution_id) {
            Some(published) if published.epoch == self.settlement_epoch => {
                DistributionAcceptance::Accepted(published.entry.clone())
            }
            Some(_) => DistributionAcceptance::Stale, // settlement-invalidated (§10)
            // A stale-but-still-referenced id may also sit in the OTHER
            // slot's history (e.g. pool-wide k-2 while tailored is
            // active) — everything not in the acceptance window reads
            // as Stale/Unknown identically on the wire; distinguish
            // only for observability.
            None => {
                let anywhere = self.pool_wide_distribution.find(distribution_id).is_some()
                    || self
                        .tailored_distributions
                        .values()
                        .any(|s| s.find(distribution_id).is_some());
                if anywhere {
                    DistributionAcceptance::Stale
                } else {
                    DistributionAcceptance::Unknown
                }
            }
        }
    }

    /// §10 settlement invalidation: a block was found and settled per
    /// its winning distribution — every currently-published
    /// distribution becomes stale at once (the grace window MUST NOT
    /// span a settlement event). The publisher is expected to push a
    /// fresh distribution immediately after.
    pub fn invalidate_all_distributions(&mut self) {
        self.settlement_epoch += 1;
        // The grace slots are meaningless across the boundary.
        self.pool_wide_distribution.previous = None;
        for slot in self.tailored_distributions.values_mut() {
            slot.previous = None;
        }
    }

    /// Number of live tailored slots. Diagnostics / tests.
    pub fn tailored_distribution_count(&self) -> usize {
        self.tailored_distributions.len()
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
        // A tailored distribution dies with the session it was
        // published to.
        self.tailored_distributions.remove(&jdp_session_id);
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
        // Tailored distribution slots are NOT aged out here. They die
        // with their session (`evict_for_jdp_session`, which the IO
        // layer calls whenever a JDP connection task ends, clean or
        // not), and a live session can hold one for days without ever
        // republishing — a Solo distribution has a single payout entry
        // and simply does not change. Ageing them on publish time would
        // drop the slot underneath a connected miner, whose every later
        // declaration then resolves against the pool-wide slot that
        // never held its id and is answered `stale-payout-distribution`.
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
            booking: None,
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

    // ── Payout distributions (ext 0x0003 push model) ────────────────

    fn distribution(
        id: u64,
        owner: Option<AddressId>,
        session: Option<u32>,
    ) -> PayoutDistributionEntry {
        PayoutDistributionEntry {
            distribution_id: id,
            pool_payout: WeightedOutput {
                script_pubkey: vec![0x51],
                weight: 1,
            },
            payouts: vec![WeightedOutput {
                script_pubkey: vec![0x00, 0x14, 0xAA],
                weight: 100,
            }],
            dust_limits: vec![546],
            additional_outputs: vec![],
            reference_reward_sats: 312_500_000,
            payouts_fingerprint: Some([id as u8; 32]),
            bookable: true,
            owner,
            jdp_session_id: session,
            published_at_ms: 1_000 + id,
        }
    }

    fn accepted_id(a: &DistributionAcceptance) -> Option<u64> {
        match a {
            DistributionAcceptance::Accepted(e) => Some(e.distribution_id),
            _ => None,
        }
    }

    /// `grace window: latest + previous accepted, k-2 stale, never-published unknown`
    #[test]
    fn distribution_grace_window_latest_plus_previous() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, None, None));
        reg.publish_pool_wide(distribution(2, None, None));
        reg.publish_pool_wide(distribution(3, None, None));
        let scope = DistributionScope::JdpSession(7);
        assert_eq!(accepted_id(&reg.distribution_acceptance(3, scope)), Some(3));
        assert_eq!(accepted_id(&reg.distribution_acceptance(2, scope)), Some(2));
        assert_eq!(
            reg.distribution_acceptance(1, scope),
            DistributionAcceptance::Unknown, // k-2 fell out of retention
        );
        assert_eq!(
            reg.distribution_acceptance(99, scope),
            DistributionAcceptance::Unknown
        );
    }

    /// A settled distribution must not be handed out as the current
    /// one: the connection-open push would send a JDC an id that every
    /// declaration is then rejected for, and the publisher's
    /// skip-if-unchanged compare would swallow the forced republish.
    #[test]
    fn settled_distribution_is_no_longer_current() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let owner = addr();
        reg.publish_pool_wide(distribution(1, None, None));
        reg.publish_tailored(7, distribution(2, Some(owner.clone()), Some(7)));
        assert!(reg.current_pool_wide().is_some());
        assert!(reg.current_tailored(7).is_some());

        reg.invalidate_all_distributions();
        assert!(
            reg.current_pool_wide().is_none(),
            "a settled pool-wide distribution is not current"
        );
        assert!(
            reg.current_tailored(7).is_none(),
            "a settled tailored distribution is not current"
        );

        // A fresh publish restores it.
        reg.publish_pool_wide(distribution(3, None, None));
        assert_eq!(reg.current_pool_wide().map(|e| e.distribution_id), Some(3));
    }

    /// A reconnecting JDC leaves its old tailored slot behind until the
    /// cleanup sweep. Address-scoped lookups must resolve against the
    /// NEWEST slot, not an arbitrary one, or the live distribution is
    /// rejected as stale on a fraction of declarations.
    #[test]
    fn address_scope_prefers_the_newest_tailored_slot() {
        let owner = addr();
        // Both orders of session ids, and many registry instances: each
        // gets its own hash seed, so a first-match lookup would pick the
        // ghost about half the time. 16 rounds per order makes the old
        // behaviour practically impossible to slip through.
        let rounds = [(7u32, 8u32), (8, 7)].into_iter().flat_map(|p| [p; 16]);
        for (ghost_session, live_session) in rounds {
            let mut reg = JdpDeclaredJobRegistry::new();
            reg.publish_pool_wide(distribution(1, None, None));
            reg.publish_tailored(
                ghost_session,
                distribution(10, Some(owner.clone()), Some(ghost_session)),
            );
            reg.publish_tailored(
                live_session,
                distribution(20, Some(owner.clone()), Some(live_session)),
            );
            let scope = DistributionScope::MinerAddress(&owner);
            assert_eq!(
                accepted_id(&reg.distribution_acceptance(20, scope)),
                Some(20),
                "the live distribution must be accepted (ghost {ghost_session})"
            );
        }
    }

    /// `settlement invalidation: everything published before is stale`
    #[test]
    fn distribution_settlement_invalidates_all() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, None, None));
        reg.publish_pool_wide(distribution(2, None, None));
        reg.invalidate_all_distributions();
        let scope = DistributionScope::JdpSession(7);
        assert_eq!(
            reg.distribution_acceptance(2, scope),
            DistributionAcceptance::Stale
        );
        // Grace slot cleared — the window never spans a settlement.
        assert_eq!(
            reg.distribution_acceptance(1, scope),
            DistributionAcceptance::Unknown
        );
        // A fresh publish after settlement is accepted again.
        reg.publish_pool_wide(distribution(3, None, None));
        assert_eq!(accepted_id(&reg.distribution_acceptance(3, scope)), Some(3));
        // And the settled one stays stale even though it sits in the
        // grace slot now.
        assert_eq!(
            reg.distribution_acceptance(2, scope),
            DistributionAcceptance::Stale
        );
    }

    /// `tailored slot: session resolves its own, first grace = pool-wide`
    #[test]
    fn tailored_slot_graces_the_pool_wide_it_replaced() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, None, None));
        reg.publish_tailored(7, distribution(2, Some(addr()), Some(7)));
        let scope = DistributionScope::JdpSession(7);
        assert_eq!(accepted_id(&reg.distribution_acceptance(2, scope)), Some(2));
        // The pool-wide distribution the session saw pre-tailored
        // stays acceptable (in-flight declaration race).
        assert_eq!(accepted_id(&reg.distribution_acceptance(1, scope)), Some(1));
        // Another session without a tailored slot uses pool-wide only.
        let other = DistributionScope::JdpSession(9);
        assert_eq!(accepted_id(&reg.distribution_acceptance(1, other)), Some(1));
        assert_eq!(
            reg.distribution_acceptance(2, other),
            DistributionAcceptance::Stale, // known, but not in THIS scope's window
        );
    }

    /// `mining-side scope resolves tailored entries by owner address`
    #[test]
    fn miner_address_scope_matches_owner() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, None, None));
        reg.publish_tailored(7, distribution(2, Some(addr()), Some(7)));
        let owner = addr();
        let scope = DistributionScope::MinerAddress(&owner);
        assert_eq!(accepted_id(&reg.distribution_acceptance(2, scope)), Some(2));
        // An address without a tailored slot falls back to pool-wide.
        let stranger = AddressId::new("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap();
        let scope = DistributionScope::MinerAddress(&stranger);
        assert_eq!(accepted_id(&reg.distribution_acceptance(1, scope)), Some(1));
    }

    /// `tailored slot dies with its JDP session`
    #[test]
    fn tailored_slot_evicted_with_session() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, None, None));
        reg.publish_tailored(7, distribution(2, Some(addr()), Some(7)));
        assert_eq!(reg.tailored_distribution_count(), 1);
        reg.evict_for_jdp_session(7);
        assert_eq!(reg.tailored_distribution_count(), 0);
        // The session id (were it reused) is back on pool-wide.
        let scope = DistributionScope::JdpSession(7);
        assert_eq!(accepted_id(&reg.distribution_acceptance(1, scope)), Some(1));
    }

    /// A tailored slot must survive the age sweep: a Solo distribution
    /// never changes, so its publish timestamp says nothing about
    /// whether the session still exists. Only the session's own
    /// eviction removes it.
    #[test]
    fn tailored_slot_outlives_the_age_sweep() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, None, None));
        reg.publish_tailored(7, distribution(2, Some(addr()), Some(7))); // published_at 1_002
                                                                         // Far beyond any job-token horizon.
        reg.cleanup_expired(10_000_000, 1_500);
        assert_eq!(reg.tailored_distribution_count(), 1);
        let scope = DistributionScope::JdpSession(7);
        assert_eq!(
            accepted_id(&reg.distribution_acceptance(2, scope)),
            Some(2),
            "a connected miner's declarations must still resolve"
        );
        reg.evict_for_jdp_session(7);
        assert_eq!(reg.tailored_distribution_count(), 0);
    }
}
