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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bp_common::AddressId;

use crate::jdp::custom_job_binding::{binding_from_declared_job, DeclaredJobBinding};
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

/// Projection of a bridge entry for the mining-side `SetCustomMiningJob`
/// cross-checks: the miner identity, the tip the declaration was accepted
/// under, and the declared job's own fields — not the (potentially large)
/// declared-job payload, whose raw transactions the handler never reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeJobRef {
    /// Miner address bound to the token (cross-checked against the mining
    /// channel's locked address).
    pub miner_address: AddressId,
    /// Pool chain-tip the declaration was accepted under. `None` when the
    /// pool had no tip at accept time (cold start) — then the mining-side
    /// tip binding is not checkable.
    pub declared_prev_hash: Option<[u8; 32]>,
    /// The declared job's coinbase and transaction set, projected down to
    /// what `SetCustomMiningJob` repeats
    /// ([`crate::jdp::custom_job_binding`]). `None` when the stored
    /// declaration cannot be projected — a coinbase that will not rebuild,
    /// or a transaction that will not decode. The handler REJECTS on `None`;
    /// it is the one state where a declaration exists but nothing about the
    /// job it authorises can be established.
    pub binding: Option<DeclaredJobBinding>,
    /// ext 0x0003 §6: the `distribution_id` this job's DECLARATION referenced,
    /// carried over from the JDP connection.
    ///
    /// It exists because §6 places the TLV per mode, and only one of the two
    /// placements is on the mining connection:
    ///
    /// | Mode          | TLV rides on         |
    /// |---------------|----------------------|
    /// | Coinbase-only | `SetCustomMiningJob` |
    /// | Full-Template | `DeclareMiningJob`   |
    ///
    /// So a conformant Full-Template JDC sends NO TLV here, and reading the
    /// reference off the mining frame alone would leave the job looking like
    /// an unbacked self-built one. `None` for a base-protocol declaration
    /// (nothing referenced), which is a different thing from "referenced but
    /// no longer acceptable" — that stays [`DistributionAcceptance`]'s answer.
    pub distribution_id: Option<u64>,
    /// JDP session that accepted the declaration. Carried so an inherited
    /// reference can be resolved under the scope it was accepted in — see
    /// [`DistributionReference::FromDeclaration`].
    pub jdp_session_id: u32,
}

/// Where the distribution reference for a `SetCustomMiningJob` came from.
///
/// The two arms are NOT interchangeable. They were accepted under different
/// [`DistributionScope`]s, so they have to be resolved under different ones —
/// which is why this is an enum and not a bare `Option<u64>`. Returning only
/// the id would leave the scope to be re-derived at the call site, and a
/// scope that disagrees with the acceptance answers for a distribution the
/// declaration was never judged against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DistributionReference {
    /// Coinbase-only: the JDC put the §6 TLV on this frame. No declaration
    /// stands behind it, so tailored slots resolve by owner address.
    FromFrame { distribution_id: u64 },
    /// Full-Template: §6 puts the TLV on `DeclareMiningJob`, so the reference
    /// comes across with the declaration.
    ///
    /// It MUST resolve under the declaring JDP session, not by owner address.
    /// One payout address can own several tailored slots — a JDC that dropped
    /// ungracefully leaves a ghost behind until the cleanup sweep, and a
    /// second client on the same address is entirely normal since the address
    /// is the account. `DistributionScope::MinerAddress` answers with the
    /// NEWEST slot for that address, which for an older session's declaration
    /// is a slot that never held its id — permanent
    /// `stale-payout-distribution`, and fatal for an SRI jd-client.
    FromDeclaration {
        distribution_id: u64,
        jdp_session_id: u32,
    },
}

impl DistributionReference {
    pub fn distribution_id(&self) -> u64 {
        match self {
            Self::FromFrame { distribution_id }
            | Self::FromDeclaration {
                distribution_id, ..
            } => *distribution_id,
        }
    }
}

/// Which distribution a `SetCustomMiningJob` is judged against, decided ONCE
/// for both the IO layer (which resolves §7.2/§10 acceptance from it) and
/// [`crate::mining::client::handle_set_custom_mining_job`] (which runs the
/// gates on it). Split in two they would drift into resolving one
/// distribution and validating against another.
///
/// A reference is inherited from the declaration only where that is both
/// permitted and load-bearing — see the two guards below. Everywhere else the
/// job is judged exactly as it was before this path existed.
pub fn resolve_distribution_reference(
    frame_tlv: Option<u64>,
    bridge_job: Option<&BridgeJobRef>,
    stream: bp_common::StreamKind,
    negotiated_on_this_connection: bool,
) -> Option<DistributionReference> {
    // What the JDC actually sent wins, on every stream. The §2 negotiation
    // gate judges it in the handler, as it did before this path existed.
    if let Some(distribution_id) = frame_tlv {
        return Some(DistributionReference::FromFrame { distribution_id });
    }

    // §2: a JDC that negotiated the extension on only one connection MUST NOT
    // use it. Synthesising a reference for such a client would be using it on
    // its behalf, so there is nothing to inherit — the job falls back to the
    // base-protocol custom-job path and its Solo gate, which is where it
    // landed before too.
    if !negotiated_on_this_connection {
        return None;
    }

    // The reference is only load-bearing where the Solo gate would otherwise
    // refuse, i.e. on a stream whose shares enter shared accounting. A Solo
    // stream pays its own finder, has no shared window to freeload on, and
    // has always been served without any distribution reference. Inheriting
    // one there would subject it — for the first time — to the §7.2/§10
    // acceptance window and the owner/stream checks, every one of them a new
    // way to refuse a job that used to be served. A refusal here is fatal for
    // an SRI jd-client, so this stays a `match`: a stream kind added later
    // must be classified deliberately rather than default into inheriting.
    let feeds_shared_accounting = match stream {
        bp_common::StreamKind::Solo => false,
        bp_common::StreamKind::Pplns
        | bp_common::StreamKind::GroupSolo
        | bp_common::StreamKind::Blockparty => true,
    };
    if !feeds_shared_accounting {
        return None;
    }

    bridge_job.and_then(|j| {
        j.distribution_id
            .map(|distribution_id| DistributionReference::FromDeclaration {
                distribution_id,
                jdp_session_id: j.jdp_session_id,
            })
    })
}

/// A registered entry plus the projection the mining side compares against.
///
/// The projection is built ONCE, here, and never again: a
/// [`RegisteredDeclaredJob`] is immutable from the moment it lands, so
/// rebuilding it per `SetCustomMiningJob` would deserialise every declared
/// transaction and rebuild the whole merkle tree to arrive at the same bytes
/// — for a mainnet-sized declaration, thousands of transactions over a
/// megabyte or two, on a per-message path, while the registry's lock is held
/// and the JDP side waits behind it to register declarations and publish
/// distributions.
#[derive(Debug)]
struct StoredJob {
    entry: RegisteredDeclaredJob,
    binding: Option<DeclaredJobBinding>,
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
/// - **payout distributions** (ext 0x0003 push model): the pool-wide
///   slot plus tailored per-session slots, resolved by
///   [`JdpDeclaredJobRegistry::distribution_acceptance`] on both the
///   declare path and the mining-side `SetCustomMiningJob` path.
///
/// Owned by the IO layer inside `Arc<RwLock<...>>` (or `Mutex`) so
/// both servers can share it. The struct itself is sync + has no internal
/// locking — the outer lock wrapper sequences cross-task access.
#[derive(Debug, Default)]
pub struct JdpDeclaredJobRegistry {
    entries: HashMap<Token, StoredJob>,
    /// Pool-wide distribution (PPLNS) — what every connection gets
    /// pushed on open and on the publisher's timer.
    pool_wide_distribution: DistributionSlot,
    /// Tailored per-JDP-session distributions (Solo / Group-Solo /
    /// Blockparty, published after the session's identity is known).
    tailored_distributions: HashMap<u32, DistributionSlot>,
    /// JDP sessions whose miner NEEDS a tailored distribution but whose
    /// build failed. Without this they would silently resolve against
    /// `pool_wide_distribution` — see [`Self::deny_pool_wide`].
    pool_wide_denied: HashSet<u32>,
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
        // The one place the projection is built. Doing it here rather than
        // per lookup keeps the message path O(1) — see [`StoredJob`].
        let binding = binding_from_declared_job(&entry.declared_job);
        self.entries
            .insert(token, StoredJob { entry, binding })
            .map(|s| s.entry)
    }

    /// Look up a token. Returns `None` for unknown / evicted tokens
    /// (mining-handler emits `invalid-job-id`-equivalent).
    pub fn lookup(&self, token: &Token) -> Option<&RegisteredDeclaredJob> {
        self.entries.get(token).map(|s| &s.entry)
    }

    /// Projection of a token's bridge entry for the mining-side
    /// `SetCustomMiningJob` cross-checks. `None` for unknown / evicted
    /// tokens (the mining-handler fails closed on that, together with an
    /// absent payout set).
    pub fn job_ref(&self, token: &Token) -> Option<BridgeJobRef> {
        self.entries.get(token).map(|s| BridgeJobRef {
            miner_address: s.entry.miner_address.clone(),
            declared_prev_hash: s.entry.declared_job.prev_hash,
            binding: s.binding.clone(),
            // Proven at declare time: set only by the ext-0x0003 check that
            // recomputed §4 against this coinbase. NOT taken from `booking`,
            // which additionally requires the settlement snapshot to have
            // landed — see `DeclaredJob::distribution_id`.
            distribution_id: s.entry.declared_job.distribution_id,
            jdp_session_id: s.entry.jdp_session_id,
        })
    }

    // ── Payout distributions (ext 0x0003 push model) ────────────────

    /// Publish a fresh pool-wide distribution. The prior latest slides
    /// into the §7.2 grace slot.
    pub fn publish_pool_wide(&mut self, entry: PayoutDistributionEntry) {
        let epoch = self.settlement_epoch;
        self.pool_wide_distribution.publish(Arc::new(entry), epoch);
    }

    /// Publish a tailored distribution to one JDP session.
    ///
    /// The §7.2 grace slot holds only this session's OWN previous
    /// tailored entry. It used to be seeded, on the first tailored
    /// publish, with the current pool-wide latest — for an honest reason
    /// (a JDC that pipelines `AllocateMiningJobToken` and
    /// `DeclareMiningJob` may still be referencing the pool-wide
    /// distribution it was pushed at `RequestExtensions`, before its
    /// identity was known) and with a dishonest consequence.
    ///
    /// The pool-wide distribution is the PPLNS window's. A Solo or
    /// Group-Solo session honouring it declares a coinbase that pays the
    /// PPLNS window — and the seeded entry stayed in the acceptance
    /// window for the whole session (nothing republishes a tailored
    /// entry except a §10 settlement), so this was not a brief race but a
    /// standing offer. A block found on such a job pays miners whose
    /// accounting it does not belong to, and the booking then resolves
    /// the mode from the miner's ADDRESS, so for Solo nothing is booked
    /// at all: the PPLNS miners are paid on-chain and their ledger never
    /// hears about it.
    ///
    /// The right answer to that race is the wire error the spec already
    /// has: the session's own slot does not hold the pool-wide id, so it
    /// resolves as `stale-payout-distribution` and the JDC re-declares
    /// against the distribution it has just been sent. That costs one
    /// round-trip at session start and cannot pay the wrong accounting.
    pub fn publish_tailored(&mut self, jdp_session_id: u32, entry: PayoutDistributionEntry) {
        let epoch = self.settlement_epoch;
        self.tailored_distributions
            .entry(jdp_session_id)
            .or_default()
            .publish(Arc::new(entry), epoch);
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
            // A session that NEEDS a tailored distribution and has none
            // must not silently borrow the pool-wide one: the pool-wide
            // distribution is the PPLNS window's, and this miner's
            // shares do not enter it. Answering Unknown makes the JDC
            // re-fetch and the declare fail closed, instead of paying
            // its block to the wrong accounting.
            DistributionScope::JdpSession(id)
                if self.pool_wide_denied.contains(&id)
                    && self
                        .tailored_distributions
                        .get(&id)
                        .is_none_or(|s| s.latest.is_none()) =>
            {
                return DistributionAcceptance::Unknown;
            }
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

    /// Mark a JDP session as requiring a tailored distribution it does
    /// not have — its miner is Solo / Group-Solo / Blockparty and the
    /// tailored build failed (no fee address, engine error, no
    /// template).
    ///
    /// Without this the session falls through to the pool-wide slot and
    /// declares against the PPLNS weights, so a group's block pays the
    /// PPLNS window instead of the group's members — and books under the
    /// PPLNS fingerprint. "Serve nothing" is the only safe answer: the
    /// pool cannot say what this miner's coinbase should pay.
    pub fn deny_pool_wide(&mut self, jdp_session_id: u32) {
        self.pool_wide_denied.insert(jdp_session_id);
    }

    /// Clear the denial once a tailored distribution was published for
    /// the session (a later build succeeded).
    pub fn allow_pool_wide(&mut self, jdp_session_id: u32) {
        self.pool_wide_denied.remove(&jdp_session_id);
    }

    /// Drop one specific token. Idempotent.
    pub fn remove(&mut self, token: &Token) -> Option<RegisteredDeclaredJob> {
        self.entries.remove(token).map(|s| s.entry)
    }

    /// Drop every entry owned by a closing JDP session. Returns the
    /// count removed — useful for diagnostics + the IO layer's
    /// connection-close log.
    pub fn evict_for_jdp_session(&mut self, jdp_session_id: u32) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, s| s.entry.jdp_session_id != jdp_session_id);
        // A tailored distribution dies with the session it was
        // published to.
        self.tailored_distributions.remove(&jdp_session_id);
        self.pool_wide_denied.remove(&jdp_session_id);
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
            .retain(|_, s| now_ms.saturating_sub(s.entry.registered_at_ms) <= max_age_ms);
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
        self.entries.iter().map(|(t, s)| (t, &s.entry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::StreamKind;
    use std::collections::HashMap as Map;

    const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    fn addr() -> AddressId {
        AddressId::new(ADDR.to_string()).unwrap()
    }

    fn token(byte: u8) -> Token {
        Token([byte; 16])
    }

    /// Scripts the fixture declaration commits to.
    const SCRIPT_SIG_PREFIX: [u8; 3] = [0x03, 0xC8, 0x00]; // BIP-34 height push
    const SLOT: usize = 12;

    /// A coinbase that actually rebuilds. It used to be opaque filler
    /// (`vec![0xAA; 8]`), whose fifth byte reads as an input count of 170 —
    /// so anything projected from it came out `None`, and a test of the
    /// projection would have been testing the nothing-to-see case.
    fn declared(token: Token) -> DeclaredJob {
        use bitcoin::consensus::Encodable;

        let script_sig_len = SCRIPT_SIG_PREFIX.len() + SLOT;
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&2u32.to_le_bytes()); // coinbase_tx_version
        prefix.push(0x01); // input count
        prefix.extend_from_slice(&[0u8; 32]); // null outpoint hash
        prefix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // outpoint index
                                                                 // Library encoder rather than a truncating cast — see the note in
                                                                 // `custom_job_binding::tests::coinbase_parts`.
        bitcoin::VarInt(script_sig_len as u64)
            .consensus_encode(&mut prefix)
            .expect("Vec<u8> writer cannot fail");
        prefix.extend_from_slice(&SCRIPT_SIG_PREFIX);

        let mut suffix = Vec::new();
        suffix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // nSequence
        suffix.push(0x00); // empty output vector
        suffix.extend_from_slice(&0u32.to_le_bytes()); // locktime

        DeclaredJob {
            new_token: token,
            original_token: Token([0u8; 16]),
            request_id: 1,
            version: 0x2000_0000,
            coinbase_tx_prefix: prefix,
            coinbase_tx_suffix: suffix,
            wtxid_list: vec![],
            raw_transactions: Map::new(),
            prev_hash: Some([0xAB; 32]),
            declared_at_ms: 1_000,
            booking: None,
            distribution_id: None,
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

    // ── the projection the mining side actually consumes ───────────

    /// `job_ref()` is the ONLY production site that builds
    /// `BridgeJobRef.binding` — `server.rs` calls it, nothing else. The
    /// mining-handler tests build the field through their own copy of this
    /// projection, so without this test the registry could stop projecting
    /// entirely and the whole suite would stay green while every real
    /// Full-Template `SetCustomMiningJob` was hard-rejected. The binding
    /// fails closed, so such a defect is indistinguishable from a correct
    /// refusal from the outside.
    #[test]
    fn job_ref_carries_the_declaration_projected() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(1);
        reg.register(t, registration(t, 7, 1_000));

        let job_ref = reg.job_ref(&t).expect("registered token must resolve");
        assert_eq!(job_ref.miner_address, addr());
        assert_eq!(job_ref.declared_prev_hash, Some([0xAB; 32]));

        let binding = job_ref
            .binding
            .expect("a rebuildable declaration must project");
        // Read back off the declared bytes, not off a second copy of the
        // projection — these are what the mining side compares against.
        assert_eq!(binding.version, 0x2000_0000);
        assert_eq!(binding.coinbase_tx_version, 2);
        assert_eq!(binding.coinbase_script_sig_prefix, SCRIPT_SIG_PREFIX);
        assert_eq!(binding.coinbase_tx_input_n_sequence, 0xFFFF_FFFF);
        assert_eq!(binding.coinbase_tx_outputs, vec![0x00]);
        assert_eq!(binding.coinbase_tx_locktime, 0);
        assert_eq!(binding.extranonce_slot, SLOT);
        // No declared transactions, so the coinbase is the only leaf.
        assert!(binding.merkle_path.is_empty());
    }

    /// ext 0x0003 §6 puts the `distribution_id` TLV on `DeclareMiningJob` in
    /// Full-Template mode, so the mining side never sees it on the wire and
    /// has to read it off the projection. Both directions: a declaration that
    /// referenced one projects it, a base-protocol declaration projects
    /// `None` — otherwise "everything inherits" would read the same as
    /// "inheritance works".
    #[test]
    fn job_ref_carries_the_declarations_distribution_reference() {
        let mut reg = JdpDeclaredJobRegistry::new();

        let declared_under_0x0003 = token(1);
        let mut entry = registration(declared_under_0x0003, 7, 1_000);
        entry.declared_job.distribution_id = Some(9);
        reg.register(declared_under_0x0003, entry);

        let base_protocol = token(2);
        reg.register(base_protocol, registration(base_protocol, 7, 1_000));

        assert_eq!(
            reg.job_ref(&declared_under_0x0003)
                .expect("registered")
                .distribution_id,
            Some(9)
        );
        assert_eq!(
            reg.job_ref(&base_protocol)
                .expect("registered")
                .distribution_id,
            None
        );
        // Without this the inherited reference resolves under the wrong
        // scope — see `DistributionReference::FromDeclaration`.
        assert_eq!(
            reg.job_ref(&declared_under_0x0003)
                .expect("registered")
                .jdp_session_id,
            7
        );
    }

    /// A job_ref for a declaration accepted under `distribution_id` on JDP
    /// session `session`.
    fn declared_ref(distribution_id: Option<u64>, session: u32) -> BridgeJobRef {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(1);
        let mut entry = registration(t, session, 1_000);
        entry.declared_job.distribution_id = distribution_id;
        reg.register(t, entry);
        reg.job_ref(&t).expect("registered")
    }

    /// The frame's own TLV wins where there is one (Coinbase-only); the
    /// declaration's fills in where there is not (Full-Template), and it
    /// carries the session so the acceptance is resolved in the scope the
    /// declaration was accepted under.
    #[test]
    fn a_frames_own_tlv_outranks_the_declarations_reference() {
        let job_ref = declared_ref(Some(9), 7);

        assert_eq!(
            resolve_distribution_reference(Some(11), Some(&job_ref), StreamKind::Pplns, true),
            Some(DistributionReference::FromFrame {
                distribution_id: 11
            }),
            "a TLV on the frame is the JDC's own statement about THIS job"
        );
        assert_eq!(
            resolve_distribution_reference(None, Some(&job_ref), StreamKind::Pplns, true),
            Some(DistributionReference::FromDeclaration {
                distribution_id: 9,
                jdp_session_id: 7,
            })
        );
        assert_eq!(
            resolve_distribution_reference(None, None, StreamKind::Pplns, true),
            None
        );
        assert_eq!(
            resolve_distribution_reference(
                None,
                Some(&declared_ref(None, 7)),
                StreamKind::Pplns,
                true
            ),
            None,
            "a base-protocol declaration references nothing to inherit"
        );
    }

    /// A Solo stream pays its own finder and has always been served without
    /// any distribution reference. Inheriting one would drag it into the §2
    /// gate, the §7.2/§10 window and the owner checks for the first time —
    /// each a new way to refuse a job that used to be served, and fatal for
    /// an SRI jd-client. Its own TLV still counts, exactly as before.
    #[test]
    fn a_solo_stream_inherits_nothing_but_still_honours_its_own_tlv() {
        let job_ref = declared_ref(Some(9), 7);

        assert_eq!(
            resolve_distribution_reference(None, Some(&job_ref), StreamKind::Solo, true),
            None
        );
        assert_eq!(
            resolve_distribution_reference(Some(11), Some(&job_ref), StreamKind::Solo, true),
            Some(DistributionReference::FromFrame {
                distribution_id: 11
            })
        );
        // Every stream whose shares DO enter shared accounting inherits, so
        // the carve-out above is about Solo and not about "non-PPLNS".
        for stream in [
            StreamKind::Pplns,
            StreamKind::GroupSolo,
            StreamKind::Blockparty,
        ] {
            assert!(
                resolve_distribution_reference(None, Some(&job_ref), stream, true).is_some(),
                "{stream:?} feeds shared accounting and must inherit"
            );
        }
    }

    /// §2: a JDC that negotiated the extension on only one connection MUST NOT
    /// use it. Synthesising a reference for such a client would be using it on
    /// its behalf, so there is nothing to inherit and the job falls back to
    /// the base-protocol custom-job path — where it landed before this path
    /// existed. Its own TLV is still seen, so the handler's §2 gate keeps a
    /// TLV-carrying non-negotiated client to reject.
    #[test]
    fn a_connection_that_never_negotiated_inherits_nothing() {
        let job_ref = declared_ref(Some(9), 7);

        assert_eq!(
            resolve_distribution_reference(None, Some(&job_ref), StreamKind::Pplns, false),
            None
        );
        assert_eq!(
            resolve_distribution_reference(Some(11), Some(&job_ref), StreamKind::Pplns, false),
            Some(DistributionReference::FromFrame {
                distribution_id: 11
            }),
            "the handler's §2 gate needs to see the TLV in order to reject it"
        );
    }

    /// The negative half: a declaration that cannot be rebuilt still
    /// registers and still resolves, but projects to nothing — which is what
    /// the mining handler turns into a refusal.
    #[test]
    fn job_ref_projects_none_for_an_unrebuildable_declaration() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(2);
        let mut entry = registration(t, 7, 1_000);
        entry.declared_job.coinbase_tx_prefix = vec![0xAA; 8];
        reg.register(t, entry);

        let job_ref = reg.job_ref(&t).expect("registered token must resolve");
        assert!(job_ref.binding.is_none());
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

    /// A session whose tailored build failed must NOT quietly resolve
    /// against the pool-wide distribution.
    ///
    /// The pool-wide entry is the PPLNS window's. A Group-Solo /
    /// Solo / Blockparty miner's shares never enter that window, so
    /// serving it would have their block pay the PPLNS miners and book
    /// under the PPLNS fingerprint. Answering `Unknown` fails the
    /// declare closed instead.
    #[test]
    fn a_denied_session_does_not_fall_back_to_the_pool_wide_distribution() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, None, None));
        let scope = DistributionScope::JdpSession(7);
        // Before the denial the fallback is the documented behaviour.
        assert_eq!(accepted_id(&reg.distribution_acceptance(1, scope)), Some(1));

        reg.deny_pool_wide(7);
        assert_eq!(
            reg.distribution_acceptance(1, scope),
            DistributionAcceptance::Unknown,
            "a tailored-required session must not borrow the PPLNS distribution"
        );
        // Other sessions are untouched.
        assert_eq!(
            accepted_id(&reg.distribution_acceptance(1, DistributionScope::JdpSession(8))),
            Some(1)
        );
    }

    /// Once a tailored distribution IS published for the session the
    /// denial lifts, and its own entry resolves normally.
    #[test]
    fn publishing_a_tailored_distribution_lifts_the_denial() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, None, None));
        reg.deny_pool_wide(7);
        let owner = AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string())
            .expect("addr");
        reg.publish_tailored(7, distribution(2, Some(owner), Some(7)));
        reg.allow_pool_wide(7);
        let scope = DistributionScope::JdpSession(7);
        assert_eq!(accepted_id(&reg.distribution_acceptance(2, scope)), Some(2));
    }

    /// The denial dies with the session, so a reconnecting JDC that
    /// reuses the id is not stuck behind a stale flag.
    #[test]
    fn evicting_a_session_clears_its_pool_wide_denial() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, None, None));
        reg.deny_pool_wide(7);
        reg.evict_for_jdp_session(7);
        assert_eq!(
            accepted_id(&reg.distribution_acceptance(1, DistributionScope::JdpSession(7))),
            Some(1)
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

    /// MONEY: a tailored session must NEVER resolve the pool-wide
    /// distribution.
    ///
    /// The pool-wide distribution is the PPLNS window's. A tailored
    /// session is Solo or Group-Solo, whose shares do not enter that
    /// window — so a coinbase built against it pays miners this session's
    /// accounting has nothing to do with. And the booking resolves the
    /// mode from the miner's ADDRESS, so for Solo the block is booked
    /// NOWHERE: the PPLNS miners are paid on-chain, their withheld ones
    /// never get the credit, and the published ones are never debited.
    ///
    /// `publish_tailored` used to seed exactly that entry into the
    /// session's §7.2 grace slot, for the honest in-flight-declaration
    /// race — and since nothing republishes a tailored entry except a §10
    /// settlement, it stayed acceptable for the WHOLE session, not for a
    /// race. The test this replaces asserted the seeding as the contract.
    ///
    /// The race is answered by the wire error the spec has for it: the id
    /// is not in this session's window, so the JDC is told
    /// `stale-payout-distribution` and re-declares against the tailored
    /// distribution it has just been sent.
    #[test]
    fn a_tailored_session_cannot_resolve_the_pool_wide_distribution() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, None, None));
        reg.publish_tailored(7, distribution(2, Some(addr()), Some(7)));
        let scope = DistributionScope::JdpSession(7);
        // Its own is accepted — the fixture is a live tailored session.
        assert_eq!(accepted_id(&reg.distribution_acceptance(2, scope)), Some(2));
        // The PPLNS one is not, at any point in the session's life.
        assert_eq!(
            reg.distribution_acceptance(1, scope),
            DistributionAcceptance::Stale,
            "a Solo/Group-Solo session resolving the PPLNS distribution pays the wrong \
             accounting, and for Solo the block is then booked nowhere"
        );
        // Nor after the pool-wide slot moves on, which is the state the
        // seeded entry used to survive into.
        reg.publish_pool_wide(distribution(3, None, None));
        assert_eq!(
            reg.distribution_acceptance(1, scope),
            DistributionAcceptance::Stale
        );
        assert_eq!(
            reg.distribution_acceptance(3, scope),
            DistributionAcceptance::Stale
        );

        // A session with NO tailored slot is PPLNS and still uses
        // pool-wide — this must not have become a blanket refusal.
        let pplns = DistributionScope::JdpSession(9);
        assert_eq!(accepted_id(&reg.distribution_acceptance(3, pplns)), Some(3));
        assert_eq!(
            reg.distribution_acceptance(2, pplns),
            DistributionAcceptance::Stale, // known, but not in THIS scope's window
        );
    }

    /// A tailored session's own grace slot still works — the §7.2 window
    /// is latest + previous of ITS OWN entries, and only the cross-scope
    /// seed is gone.
    #[test]
    fn a_tailored_session_still_graces_its_own_previous_entry() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, None, None));
        reg.publish_tailored(7, distribution(2, Some(addr()), Some(7)));
        reg.publish_tailored(7, distribution(3, Some(addr()), Some(7)));
        let scope = DistributionScope::JdpSession(7);
        assert_eq!(accepted_id(&reg.distribution_acceptance(3, scope)), Some(3));
        assert_eq!(
            accepted_id(&reg.distribution_acceptance(2, scope)),
            Some(2),
            "the session's own previous tailored entry stays in the grace window"
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
