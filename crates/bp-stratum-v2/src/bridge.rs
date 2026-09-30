// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-server (JDP → Mining) declared-job registry.
//!
//! The JDP server ([`crate::jdp::client`]) and the mining server
//! ([`crate::mining::client`]) run on separate ports in independent
//! per-connection tasks. A JDC declares a job on its JDP connection and then
//! sends `SetCustomMiningJob` for that token on its mining connection, so the
//! mining side needs the [`crate::jdp::declarations::DeclaredJob`] stored on
//! the other connection.
//!
//! [`JdpDeclaredJobRegistry`] is that bridge: a pool-wide, token-keyed map
//! written by the JDP side and read by
//! `mining::client::handle_set_custom_mining_job` for its cross-checks. It is
//! a pure data structure with no locking of its own; the IO layer shares one
//! instance behind an `Arc<RwLock<_>>`.
//!
//! The miner address is not a field of its own: it lives on the declared job
//! and [`JdpDeclaredJobRegistry::job_ref`] projects it, so an entry can never
//! name a different miner than the job the block-found path books against.
//!
//! Entries are evicted with their JDP session
//! ([`JdpDeclaredJobRegistry::evict_for_jdp_session`]), which every exit path
//! of the per-connection task runs, so no age-based sweep is needed.
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
//! Mining-handler calls registry.job_ref(&token)       (read)
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

/// One bridge entry. The JDP-side
/// [`crate::jdp::declarations::DeclaredJobStore`] keeps its own copy (for
/// `PushSolution` matching); this is the cross-connection copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredDeclaredJob {
    /// The declared job's full payload: coinbase prefix/suffix, merkle
    /// context and raw tx data.
    pub declared_job: DeclaredJob,
    /// JDP session that registered the entry; evicted with it by
    /// [`JdpDeclaredJobRegistry::evict_for_jdp_session`].
    pub jdp_session_id: u32,
}

/// What the allocate gave the mining side to judge a Coinbase-only job by.
///
/// A type rather than an `Option<Vec<u8>>`, because "no designated script by
/// design" and "a broken allocate" have the same shape but are different
/// events (see `crate::jdp_server::classify_allocation`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllocationKind {
    /// Base protocol: the script SV2 JDP/AllocateMiningJobToken.Success
    /// designated as the pool payout output. The custom job's coinbase must
    /// pay it — see
    /// [`crate::jdp::dynamic_outputs::pays_designated_output`].
    DesignatedOutput(Vec<u8>),
    /// ext 0x0003: ext 0x0003/Negotiation requires the allocate's
    /// `coinbase_tx_outputs` to be empty, so there is no designated script.
    /// The ext 0x0003/Output Verification recompute judges the coinbase
    /// instead, which is why this is its own kind, not a degraded allocate.
    JudgedByDistribution,
}

/// An allocated token the pool answered, for a mode that never declares.
///
/// Coinbase-only mode takes the allocate token straight to
/// `SetCustomMiningJob` (SV2 JDP/Coinbase-only Mode: "the `DeclareMiningJob`
/// message is never used"), so this is the mining side's only record of it.
///
/// Both Coinbase-only kinds land here, base protocol and ext 0x0003:
/// ext 0x0003/Negotiation removes the script, not the token, and the token
/// still binds the miner address and the chain tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocatedTokenRef {
    /// Miner address the token was issued to (cross-checked against the
    /// mining channel's locked address, exactly as for a declared job).
    pub miner_address: AddressId,
    /// Which of the two Coinbase-only kinds this token is.
    pub kind: AllocationKind,
    /// JDP session that issued it (evicted with the session).
    pub jdp_session_id: u32,
    /// The issuing token's own expiry, carried verbatim from
    /// [`crate::tokens::AllocatedToken`]. It bounds the map on a long-lived
    /// session, whose entries would otherwise pile up under the lock the
    /// mining hot path takes.
    pub expires_at_ms: u64,
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
    /// Pool chain-tip the declaration was accepted under.
    pub declared_prev_hash: [u8; 32],
    /// The declared job's coinbase and transaction set, projected down to
    /// what `SetCustomMiningJob` repeats
    /// ([`crate::jdp::custom_job_binding`]). `None` when the stored
    /// declaration cannot be projected — a coinbase that will not rebuild,
    /// or a transaction that will not decode. The handler REJECTS on `None`;
    /// it is the one state where a declaration exists but nothing about the
    /// job it authorises can be established.
    pub binding: Option<DeclaredJobBinding>,
    /// ext 0x0003/distribution_id TLV Field: the `distribution_id` this job's
    /// DECLARATION referenced, carried over from the JDP connection, because
    /// the TLV placement depends on the mode:
    ///
    /// | Mode          | TLV rides on         |
    /// |---------------|----------------------|
    /// | Coinbase-only | `SetCustomMiningJob` |
    /// | Full-Template | `DeclareMiningJob`   |
    ///
    /// A conformant Full-Template JDC sends no TLV on the mining frame.
    /// `None` for a base-protocol declaration (nothing referenced), which is
    /// not "referenced but no longer acceptable"; that is
    /// [`DistributionAcceptance`]'s answer.
    pub distribution_id: Option<u64>,
    /// JDP session that accepted the declaration. Carried so an inherited
    /// reference can be resolved under the scope it was accepted in — see
    /// [`DistributionReference::FromDeclaration`].
    pub jdp_session_id: u32,
}

/// Where the distribution reference for a `SetCustomMiningJob` came from.
///
/// The two arms are accepted under different [`DistributionScope`]s and must
/// be resolved under the same one, which is why this is an enum and not a
/// bare `Option<u64>` that leaves the scope to the call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DistributionReference {
    /// Coinbase-only: the JDC put the ext 0x0003/distribution_id TLV Field on
    /// this frame. No declaration stands behind it, so tailored slots resolve
    /// by owner address.
    FromFrame { distribution_id: u64 },
    /// Full-Template: ext 0x0003/distribution_id TLV Field puts the TLV on
    /// `DeclareMiningJob`, so the reference comes across with the declaration.
    ///
    /// It MUST resolve under the declaring JDP session, not by owner address:
    /// one address can own several tailored slots (several clients, or a
    /// dropped session not yet swept), and `DistributionScope::MinerAddress`
    /// answers with the newest, which for an older session's declaration
    /// never held its id and yields a fatal `stale-payout-distribution`.
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
/// for both the IO layer (which resolves ext 0x0003/Grace Window +
/// Implementation Notes acceptance from it) and
/// [`crate::mining::client::handle_set_custom_mining_job`] (which runs the
/// gates on it), so the two cannot resolve one distribution and validate
/// against another.
///
/// A reference is inherited from the declaration wherever
/// ext 0x0003/Negotiation lets this connection use the extension.
///
/// **It takes no stream, and must not.** A job whose declaration referenced a
/// distribution is judged against it, Solo included: a connection whose
/// accounting now reads Solo may hold a declaration bound to a pool-wide plan,
/// and skipping the check there would let its coinbase pay the PPLNS window
/// while the booking resolves Solo, so the window's claims get paid twice.
pub fn resolve_distribution_reference(
    frame_tlv: Option<u64>,
    bridge_job: Option<&BridgeJobRef>,
    negotiated_on_this_connection: bool,
) -> Option<DistributionReference> {
    // What the JDC actually sent wins; the ext 0x0003/Negotiation gate
    // judges it in the handler.
    if let Some(distribution_id) = frame_tlv {
        return Some(DistributionReference::FromFrame { distribution_id });
    }

    // ext 0x0003/Negotiation: a JDC that negotiated the extension on only one
    // connection MUST NOT use it, and synthesising a reference would use it on
    // its behalf. The job takes the base-protocol custom-job path.
    if !negotiated_on_this_connection {
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

/// What the pool has on file for a `SetCustomMiningJob`'s
/// `mining_job_token` — the record its coinbase is judged against.
///
/// The three states are the SV2 JDP/Job Declaration Modes as the mining side
/// sees them. One exhaustive type, because the handler asks several questions
/// of them (whose address must match, which tip binds, what pins the coinbase,
/// who records a found block) and a new mode must be classified, not fall
/// through `is_some()` tests.
///
/// **This is the token's authority, not its payout coverage.** Whether a
/// published distribution pins the coinbase split is a separate question,
/// answered by [`resolve_distribution_reference`]; either kind of token may or
/// may not carry a reference, and a declared job with one still gets the
/// ext 0x0003/Output Verification recompute.
///
/// [`crate::jdp::dynamic_outputs::CandidateBacking`] is that other axis
/// (payout coverage). Do not collapse the two: they answer different
/// questions about the same job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenBacking<'a> {
    /// Full-Template (SV2 JDP/Full-Template Mode): a `DeclareMiningJob` stands
    /// behind the token and the node validated its transaction set
    /// (SV2 JDP/Job Declarator Server), so the custom job is held to the
    /// declaration: address, declared tip, and the binding of
    /// [`crate::jdp::custom_job_binding`].
    Declared(&'a BridgeJobRef),
    /// Coinbase-only on the base protocol (SV2 JDP/Coinbase-only Mode:
    /// `DeclareMiningJob` "is never used"): the allocate is the pool's only
    /// record, so the job is held to what
    /// SV2 JDP/AllocateMiningJobToken.Success gives — the coinbase pays
    /// `payout_script` — and to the token's own miner address and the pool's
    /// tip.
    ///
    /// The script rides on the variant so the handler never asks again
    /// whether this allocate has one; [`AllocationKind`] decides that once.
    BaseAllocation {
        token: &'a AllocatedTokenRef,
        payout_script: &'a [u8],
    },
    /// Coinbase-only under ext 0x0003: the allocate is on file, but
    /// ext 0x0003/Negotiation left it without a designated output, so the
    /// ext 0x0003/Output Verification recompute against the published
    /// distribution is what judges the coinbase.
    ///
    /// The token is bound exactly as the base-protocol one is (miner address,
    /// tip); only the coinbase test differs.
    DistributionAllocation(&'a AllocatedTokenRef),
}

/// Which of the three a token is — or `None`, meaning the pool has no record
/// of it (unknown / expired / evicted with its JDP session). The handler fails
/// closed on `None`: accepting would register an arbitrary self-built coinbase
/// into the share pipeline.
///
/// The frame's distribution TLV deliberately does NOT rescue an unknown token:
/// only a token the pool issued is subject to the allocate rate limit, the
/// TTL and session eviction. A conformant 0x0003 JDC allocates like any other
/// (ext 0x0003/Negotiation empties the outputs, not the exchange).
///
/// Pure and total, like `crate::jdp_server::classify_allocation`, so every
/// combination can be asserted without a connection.
///
/// `Declared` wins over `BaseAllocation`. Full-Template registers no
/// allocation at all (`AllocationDisposition::LeftToTheDeclaration`), and
/// otherwise the two maps are keyed by different random tokens, so a clash is
/// not expected; should one occur, the declaration is the stronger record,
/// since the node validated its transaction set
/// (SV2 JDP/Job Declarator Server).
pub fn classify_backing<'a>(
    bridge_job: Option<&'a BridgeJobRef>,
    allocation: Option<&'a AllocatedTokenRef>,
) -> Option<TokenBacking<'a>> {
    match (bridge_job, allocation) {
        (Some(job), _) => Some(TokenBacking::Declared(job)),
        (None, Some(token)) => Some(match &token.kind {
            AllocationKind::DesignatedOutput(payout_script) => TokenBacking::BaseAllocation {
                token,
                payout_script,
            },
            AllocationKind::JudgedByDistribution => TokenBacking::DistributionAllocation(token),
        }),
        (None, None) => None,
    }
}

/// A registered entry plus the projection the mining side compares against.
///
/// The projection is built once at registration: a [`RegisteredDeclaredJob`]
/// is immutable, and rebuilding it per `SetCustomMiningJob` would deserialise
/// every declared transaction and rebuild the merkle tree while the registry
/// lock is held.
#[derive(Debug)]
struct StoredJob {
    entry: RegisteredDeclaredJob,
    binding: Option<DeclaredJobBinding>,
}

// ── Payout distributions (ext 0x0003 push model) ─────────────────────

/// Which accounting a published distribution belongs to.
///
/// "Who owns it" is not enough: a Solo plan and a Group-Solo plan are both
/// tailored to one address, and a Solo plan mined on a Group-Solo stream pays
/// the finder alone instead of splitting across the group.
///
/// The pool builds exactly one of these per mode
/// (`crate::jdp_server::TailoredDistribution`): PPLNS rides the pool-wide
/// push, Solo and Group-Solo get their own, Blockparty is served none at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DistributionAccounting {
    /// The PPLNS window's. Every connection may REFERENCE it — that is the
    /// acceptance window — but only a PPLNS stream may be paid by it.
    PoolWide,
    /// Tailored to one miner mining Solo: its block pays that miner.
    Solo(AddressId),
    /// Tailored to one group's finder: its block splits across the group by
    /// round shares, which is a different payout vector from `Solo` for the
    /// very same address.
    GroupSolo(AddressId),
}

impl DistributionAccounting {
    /// The address a tailored entry names; `None` for pool-wide.
    pub fn owner(&self) -> Option<&AddressId> {
        match self {
            Self::PoolWide => None,
            Self::Solo(owner) | Self::GroupSolo(owner) => Some(owner),
        }
    }
}

/// Does a distribution built for `accounting` belong to a miner on `stream`?
///
/// The one answer to "whose money does this plan pay, and is that this
/// miner?", shared by three callers:
///
/// - `SetCustomMiningJob`: may this connection MINE this plan?
/// - the JDP declare: may this session DECLARE a coinbase paying it?
/// - the JDP connection loop: is the plan it serves still the right one?
///
/// The declare check is not redundant: a block found on a Full-Template job is
/// booked from its declaration alone (`handle_push_solution`) and never passes
/// the mining-side check.
///
/// The entry carries the accounting it was BUILT for, so this is a direct
/// comparison, not an inference from the owner address (the owner check stays
/// at the call site that has an address). Every pair is spelled out, so a new
/// stream or accounting kind fails to compile instead of landing in a
/// catch-all.
pub fn accounting_matches_stream(
    accounting: &DistributionAccounting,
    stream: bp_common::StreamKind,
) -> bool {
    use bp_common::StreamKind as Sk;
    use DistributionAccounting as Acct;
    match (accounting, stream) {
        (Acct::Solo(_), Sk::Solo) | (Acct::GroupSolo(_), Sk::GroupSolo) => true,
        // Pool-wide is the PPLNS window's and pays only a PPLNS stream.
        (Acct::PoolWide, Sk::Pplns) => true,

        (Acct::PoolWide, Sk::Solo)
        | (Acct::PoolWide, Sk::GroupSolo)
        | (Acct::PoolWide, Sk::Blockparty)
        | (Acct::Solo(_), Sk::Pplns)
        | (Acct::Solo(_), Sk::GroupSolo)
        | (Acct::Solo(_), Sk::Blockparty)
        | (Acct::GroupSolo(_), Sk::Pplns)
        | (Acct::GroupSolo(_), Sk::Solo)
        | (Acct::GroupSolo(_), Sk::Blockparty) => false,
    }
}

/// Is a plan built for `accounting` still the right one, given what the pool
/// knows about the address's mode right now?
///
/// `None` means the mode gate has no live mining session for the address (a
/// reboot or reconnect). That is the absence of an answer, not a changed one,
/// so the plan stands; a mode that really moves comes back as a different
/// `Some`.
///
/// One function for both callers (the JDP loop deciding whether to rebuild,
/// the declare path deciding whether to accept a coinbase), so the `None`
/// rule cannot differ between them.
pub fn accounting_fits_mode(
    accounting: &DistributionAccounting,
    current_mode: Option<bp_common::StreamKind>,
) -> bool {
    match current_mode {
        None => true,
        Some(stream) => accounting_matches_stream(accounting, stream),
    }
}

/// A freshly-built payout distribution, ready to publish as
/// `SetPayoutDistribution` (ext 0x0003/SetPayoutDistribution) and to register
/// in the bridge for ext 0x0003/Output Verification validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltPayoutDistribution {
    /// The pool output (`weight_P` in the amount field).
    pub pool_payout: WeightedOutput,
    /// Miner payout slots in ext 0x0003/Payout Computation coinbase order.
    pub payouts: Vec<WeightedOutput>,
    /// Parallel to `payouts` (ext 0x0003/SetPayoutDistribution).
    pub dust_limits: Vec<u32>,
    /// Consensus-serialized 0-value TxOuts the pool appends.
    pub additional_outputs: Vec<Vec<u8>>,
    /// Revenue the weight boosts were projected against.
    pub reference_reward_sats: u64,
    /// Settlement-snapshot identity. `None` = the owning mode books
    /// without a snapshot (Solo).
    pub payouts_fingerprint: Option<[u8; 32]>,
    /// Whether a found block on this distribution may be booked
    /// (`false` when the snapshot write failed).
    pub bookable: bool,
}

/// One published `SetPayoutDistribution` (ext 0x0003/SetPayoutDistribution),
/// tracked pool-wide so both the JDP declare path and the mining-side
/// `SetCustomMiningJob` path can resolve a `distribution_id` TLV to the
/// weights it references and validate the coinbase per
/// ext 0x0003/Output Verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutDistributionEntry {
    /// ext 0x0003/SetPayoutDistribution: strictly increasing, universal across
    /// all connections.
    pub distribution_id: u64,
    /// The payout plan itself, as the pool built it.
    pub built: BuiltPayoutDistribution,
    /// Which accounting this distribution belongs to — see
    /// [`DistributionAccounting`].
    pub accounting: DistributionAccounting,
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
    /// Known but superseded / settlement-invalidated
    /// (ext 0x0003/Grace Window + Implementation Notes) →
    /// `stale-payout-distribution`.
    Stale,
    /// Never published (or long pruned). The spec folds this into the same
    /// error code: both mean "re-fetch and re-declare".
    Unknown,
}

/// A published entry plus the settlement epoch it was published in. Entries
/// from an older epoch are stale (ext 0x0003/Implementation Notes: a found
/// block invalidates every distribution); the epoch lives here, registry-
/// side, so [`PayoutDistributionEntry`] stays plainly constructible by the
/// publisher.
#[derive(Clone, Debug)]
struct PublishedDistribution {
    entry: Arc<PayoutDistributionEntry>,
    epoch: u64,
}

/// Latest + immediately-previous published entry (ext 0x0003/Grace Window
/// grace window of exactly one distribution).
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
/// and the mining server (reader). Holds:
///
/// - **declared jobs** keyed by the `new_mining_job_token` issued in
///   `DeclareMiningJobSuccess`, and Coinbase-only **allocate tokens**;
/// - **payout distributions** (ext 0x0003 push model): the pool-wide slot
///   plus tailored per-session slots, resolved by
///   [`JdpDeclaredJobRegistry::distribution_acceptance`] on both the declare
///   path and the mining-side `SetCustomMiningJob` path.
///
/// No internal locking; the IO layer's outer lock sequences access.
#[derive(Debug, Default)]
pub struct JdpDeclaredJobRegistry {
    entries: HashMap<Token, StoredJob>,
    /// Coinbase-only allocate tokens (that mode has no declaration to key
    /// on); see [`AllocatedTokenRef`].
    allocations: HashMap<Token, AllocatedTokenRef>,
    /// Pool-wide distribution (PPLNS) — what every connection gets
    /// pushed on open and on the publisher's timer.
    pool_wide_distribution: DistributionSlot,
    /// Tailored per-JDP-session distributions (Solo or Group-Solo,
    /// published after the session's identity is known).
    tailored_distributions: HashMap<u32, DistributionSlot>,
    /// JDP sessions whose miner NEEDS a tailored distribution but has none,
    /// so they must not resolve against `pool_wide_distribution`; see
    /// [`Self::deny_pool_wide`].
    pool_wide_denied: HashSet<u32>,
    /// Bumped by [`Self::invalidate_all_distributions`]
    /// (ext 0x0003/Implementation Notes). Every entry published under an older
    /// epoch resolves as `Stale`.
    settlement_epoch: u64,
}

impl JdpDeclaredJobRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a declared job. Returns the previous entry for the token,
    /// like [`HashMap::insert`] (not expected, tokens are unique).
    pub fn register(
        &mut self,
        token: Token,
        entry: RegisteredDeclaredJob,
    ) -> Option<RegisteredDeclaredJob> {
        // The one place the projection is built; see [`StoredJob`].
        let binding = binding_from_declared_job(&entry.declared_job);
        self.entries
            .insert(token, StoredJob { entry, binding })
            .map(|s| s.entry)
    }

    /// Drop a declared job's entry once its token has authorised a custom
    /// job: one declaration authorises exactly one `SetCustomMiningJob`.
    ///
    /// This removes only the mining side's record. The JDP session keeps its
    /// own copy, which `PushSolution` reassembles the found block from.
    pub fn consume_declared_job(&mut self, token: &Token) -> bool {
        self.entries.remove(token).is_some()
    }

    /// Projection of a token's bridge entry for the mining-side
    /// `SetCustomMiningJob` cross-checks. `None` for unknown / evicted
    /// tokens (the mining-handler fails closed on that, together with an
    /// absent payout set).
    pub fn job_ref(&self, token: &Token) -> Option<BridgeJobRef> {
        self.entries.get(token).map(|s| BridgeJobRef {
            // Off the declaration itself, so it cannot name a different
            // miner than the job does.
            miner_address: s.entry.declared_job.miner_address.clone(),
            declared_prev_hash: s.entry.declared_job.prev_hash,
            binding: s.binding.clone(),
            // Set only by the declare-time ext 0x0003/Payout Computation
            // recompute. Not taken from `booking`, which also requires the
            // settlement snapshot; see `DeclaredJob::distribution_id`.
            distribution_id: s.entry.declared_job.distribution_id,
            jdp_session_id: s.entry.jdp_session_id,
        })
    }

    // ── Base-protocol allocate tokens ───────────────────────────────

    /// Register a Coinbase-only allocate token (either [`AllocationKind`]) so
    /// the mining side can resolve it when `SetCustomMiningJob` arrives.
    ///
    /// Sweeps expired entries on the way in, which bounds the map; the scan
    /// is affordable because allocations are rate-limited per connection.
    pub fn register_allocation(&mut self, token: Token, entry: AllocatedTokenRef, now_ms: u64) {
        self.allocations.retain(|_, a| a.expires_at_ms > now_ms);
        self.allocations.insert(token, entry);
    }

    /// Drop an allocation's entry once its token has authorised a custom
    /// job. The mirror of [`Self::consume_declared_job`]: one token, one
    /// `SetCustomMiningJob`, whichever record answered for it.
    pub fn consume_allocation(&mut self, token: &Token) -> bool {
        self.allocations.remove(token).is_some()
    }

    /// The allocation behind a token, if any. `None` for an unknown, evicted
    /// or EXPIRED token.
    ///
    /// Expiry is judged here as well as at insert time, so an expired token
    /// stops authorising jobs even if nothing has been allocated since.
    pub fn allocation_ref(&self, token: &Token, now_ms: u64) -> Option<&AllocatedTokenRef> {
        self.allocations
            .get(token)
            .filter(|a| a.expires_at_ms > now_ms)
    }

    // ── Payout distributions (ext 0x0003 push model) ────────────────

    /// Publish a fresh pool-wide distribution. The prior latest slides
    /// into the ext 0x0003/Grace Window slot.
    pub fn publish_pool_wide(&mut self, entry: PayoutDistributionEntry) {
        let epoch = self.settlement_epoch;
        self.pool_wide_distribution.publish(Arc::new(entry), epoch);
    }

    /// Publish a tailored distribution to one JDP session.
    ///
    /// The ext 0x0003/Grace Window slot holds only this session's OWN
    /// previous tailored entry, never the pool-wide one: that is the PPLNS
    /// window's, and a Solo or Group-Solo coinbase paying it would pay miners
    /// whose accounting the block does not belong to.
    ///
    /// A JDC still referencing the pool-wide distribution it was pushed
    /// before its identity was known gets `stale-payout-distribution` and
    /// re-declares against the one just sent: one round-trip at session start.
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
    /// `None` once a settlement invalidated it
    /// (ext 0x0003/Implementation Notes), even though the entry is still held:
    /// handing it out would push a JDC a distribution every declaration would
    /// be refused for, and could make the publisher skip the forced republish.
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

    /// Resolve a `distribution_id` under `scope` (ext 0x0003/Grace Window
    /// acceptance: latest + immediately-previous; a session with a tailored
    /// slot uses that slot).
    pub fn distribution_acceptance(
        &self,
        distribution_id: u64,
        scope: DistributionScope<'_>,
    ) -> DistributionAcceptance {
        let slot = match scope {
            // A session that NEEDS a tailored distribution and has none must
            // not borrow the pool-wide one (the PPLNS window's). Unknown makes
            // the JDC re-fetch and the declare fail closed.
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
            // One address can own several tailored slots (a dropped session
            // lingers until the cleanup sweep). Take the NEWEST publish, not
            // whichever slot the map yields first.
            DistributionScope::MinerAddress(addr) => self
                .tailored_distributions
                .values()
                .filter(|s| {
                    s.latest
                        .as_ref()
                        .is_some_and(|p| p.entry.accounting.owner() == Some(addr))
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
            Some(_) => DistributionAcceptance::Stale, // settlement-invalidated (ext 0x0003/Implementation Notes)
            // The id may sit in another slot's history. Stale and Unknown
            // are identical on the wire; they differ only for observability.
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

    /// ext 0x0003/Implementation Notes settlement invalidation: a block was
    /// found and settled per its winning distribution — every
    /// currently-published distribution becomes stale at once (the grace
    /// window MUST NOT span a settlement event). The publisher is expected to
    /// push a fresh distribution immediately after.
    pub fn invalidate_all_distributions(&mut self) {
        self.settlement_epoch += 1;
        // The grace slots are meaningless across the boundary.
        self.pool_wide_distribution.previous = None;
        for slot in self.tailored_distributions.values_mut() {
            slot.previous = None;
        }
    }

    /// Mark a JDP session as requiring a tailored distribution it does not
    /// have: a Solo or Group-Solo miner whose tailored build failed, or a
    /// Blockparty one, which JDP does not serve.
    ///
    /// Otherwise the session would fall through to the pool-wide slot and
    /// its block would pay the PPLNS window. "Serve nothing" is the only safe
    /// answer when the pool cannot say what the coinbase should pay.
    pub fn deny_pool_wide(&mut self, jdp_session_id: u32) {
        self.pool_wide_denied.insert(jdp_session_id);
    }

    /// Clear the denial once a tailored distribution was published for
    /// the session (a later build succeeded).
    pub fn allow_pool_wide(&mut self, jdp_session_id: u32) {
        self.pool_wide_denied.remove(&jdp_session_id);
    }

    /// Whether the session is currently denied the pool-wide distribution.
    ///
    /// Lets a caller that re-decides per inbound frame see under a READ lock
    /// that nothing changes, instead of taking the write lock the mining side
    /// also contends for.
    pub fn is_pool_wide_denied(&self, jdp_session_id: u32) -> bool {
        self.pool_wide_denied.contains(&jdp_session_id)
    }

    /// Drop a session's tailored slot when it stops being a tailored session
    /// — its miner turned out to be, or became, a PPLNS one.
    ///
    /// Clearing the denial is not enough: `distribution_acceptance` under
    /// [`DistributionScope::JdpSession`] prefers a tailored slot whenever its
    /// `latest` is `Some`, so a leftover slot would resolve every pool-wide id
    /// the session is pushed as `Stale`.
    ///
    /// Returns whether a slot was removed, so the caller logs only a real
    /// transition.
    pub fn clear_tailored(&mut self, jdp_session_id: u32) -> bool {
        self.tailored_distributions
            .remove(&jdp_session_id)
            .is_some()
    }

    /// Drop every entry owned by a closing JDP session. Returns the count
    /// removed across both token maps, for the connection-close log.
    pub fn evict_for_jdp_session(&mut self, jdp_session_id: u32) -> usize {
        let before = self.entries.len() + self.allocations.len();
        self.entries
            .retain(|_, s| s.entry.jdp_session_id != jdp_session_id);
        // A token is only meaningful while the JDP connection that issued it
        // is alive.
        self.allocations
            .retain(|_, a| a.jdp_session_id != jdp_session_id);
        // A tailored distribution dies with the session it was
        // published to.
        self.tailored_distributions.remove(&jdp_session_id);
        self.pool_wide_denied.remove(&jdp_session_id);
        before - (self.entries.len() + self.allocations.len())
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

    /// Scripts the fixture declaration commits to.
    const SCRIPT_SIG_PREFIX: [u8; 3] = [0x03, 0xC8, 0x00]; // BIP-34 height push
    const SLOT: usize = 12;

    /// A coinbase that actually rebuilds, so the projection is `Some` and
    /// its fields can be checked.
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
            miner_address: addr(),
            version: 0x2000_0000,
            coinbase_tx_prefix: prefix,
            coinbase_tx_suffix: suffix,
            wtxid_list: vec![],
            raw_transactions: Map::new(),
            prev_hash: [0xAB; 32],
            declared_at_ms: 1_000,
            booking: None,
            distribution_id: None,
        }
    }

    fn registration(token: Token, session_id: u32) -> RegisteredDeclaredJob {
        RegisteredDeclaredJob {
            declared_job: declared(token),
            jdp_session_id: session_id,
        }
    }

    // ── the projection the mining side actually consumes ───────────

    /// `job_ref()` is the only production site that builds
    /// `BridgeJobRef.binding`. This pins WHICH bytes come through, which a
    /// verdict-only check cannot see on a binding that fails closed.
    #[test]
    fn job_ref_carries_the_declaration_projected() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(1);
        reg.register(t, registration(t, 7));

        let job_ref = reg.job_ref(&t).expect("registered token must resolve");
        assert_eq!(job_ref.miner_address, addr());
        assert_eq!(job_ref.declared_prev_hash, [0xAB; 32]);

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

    /// ext 0x0003/distribution_id TLV Field puts the `distribution_id` TLV on
    /// `DeclareMiningJob` in Full-Template mode, so the mining side never sees
    /// it on the wire and reads it off the projection. Both directions: a
    /// declaration that referenced one projects it, a base-protocol one
    /// projects `None`.
    #[test]
    fn job_ref_carries_the_declarations_distribution_reference() {
        let mut reg = JdpDeclaredJobRegistry::new();

        let declared_under_0x0003 = token(1);
        let mut entry = registration(declared_under_0x0003, 7);
        entry.declared_job.distribution_id = Some(9);
        reg.register(declared_under_0x0003, entry);

        let base_protocol = token(2);
        reg.register(base_protocol, registration(base_protocol, 7));

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
        // The inherited reference resolves under this session's scope; see
        // `DistributionReference::FromDeclaration`.
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
        let mut entry = registration(t, session);
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
            resolve_distribution_reference(Some(11), Some(&job_ref), true),
            Some(DistributionReference::FromFrame {
                distribution_id: 11
            }),
            "a TLV on the frame is the JDC's own statement about THIS job"
        );
        assert_eq!(
            resolve_distribution_reference(None, Some(&job_ref), true),
            Some(DistributionReference::FromDeclaration {
                distribution_id: 9,
                jdp_session_id: 7,
            })
        );
        assert_eq!(resolve_distribution_reference(None, None, true), None);
        assert_eq!(
            resolve_distribution_reference(None, Some(&declared_ref(None, 7)), true),
            None,
            "a base-protocol declaration references nothing to inherit"
        );
    }

    /// What a declaration referenced is inherited on EVERY stream, including
    /// Solo — the resolver takes no stream at all.
    ///
    /// A connection whose accounting moved to Solo may hold a declaration
    /// bound to a pool-wide plan; dropping the reference there would skip
    /// ext 0x0003/Output Verification and let the PPLNS window be paid twice.
    /// A job that referenced nothing stays untouched.
    #[test]
    fn a_declarations_reference_is_inherited_on_every_stream() {
        let job_ref = declared_ref(Some(9), 7);
        assert_eq!(
            resolve_distribution_reference(None, Some(&job_ref), true),
            Some(DistributionReference::FromDeclaration {
                distribution_id: 9,
                jdp_session_id: 7,
            }),
        );
        assert_eq!(
            resolve_distribution_reference(Some(11), Some(&job_ref), true),
            Some(DistributionReference::FromFrame {
                distribution_id: 11
            })
        );
        assert_eq!(
            resolve_distribution_reference(None, Some(&declared_ref(None, 7)), true),
            None,
            "a declaration that referenced nothing stays a base-protocol job"
        );
    }

    /// ext 0x0003/Negotiation: a JDC that negotiated the extension on only one
    /// connection MUST NOT use it, so nothing is inherited. Its own TLV is
    /// still passed through, so the handler's ext 0x0003/Negotiation gate can
    /// reject it.
    #[test]
    fn a_connection_that_never_negotiated_inherits_nothing() {
        let job_ref = declared_ref(Some(9), 7);

        assert_eq!(
            resolve_distribution_reference(None, Some(&job_ref), false),
            None
        );
        assert_eq!(
            resolve_distribution_reference(Some(11), Some(&job_ref), false),
            Some(DistributionReference::FromFrame {
                distribution_id: 11
            }),
            "the handler's ext 0x0003/Negotiation gate needs to see the TLV in order to reject it"
        );
    }

    fn allocated_ref(kind: AllocationKind) -> AllocatedTokenRef {
        AllocatedTokenRef {
            miner_address: addr(),
            kind,
            jdp_session_id: 7,
            expires_at_ms: u64::MAX,
        }
    }

    /// Every shape, asserted as a value; through the mining handler only the
    /// verdict would show, and the two allocate kinds share most of theirs.
    #[test]
    fn a_token_is_classified_by_what_the_pool_has_on_file() {
        let declared = declared_ref(Some(9), 7);
        let base = allocated_ref(AllocationKind::DesignatedOutput(vec![0x51]));
        let ext = allocated_ref(AllocationKind::JudgedByDistribution);

        assert_eq!(
            classify_backing(Some(&declared), None),
            Some(TokenBacking::Declared(&declared))
        );
        // Base-protocol Coinbase-only: the designated script rides on the
        // variant.
        assert_eq!(
            classify_backing(None, Some(&base)),
            Some(TokenBacking::BaseAllocation {
                token: &base,
                payout_script: &[0x51],
            })
        );
        // ext 0x0003 Coinbase-only: on file like any other allocate, only
        // without a script to compare.
        assert_eq!(
            classify_backing(None, Some(&ext)),
            Some(TokenBacking::DistributionAllocation(&ext))
        );
        // Fail-closed: unknown / expired / evicted.
        assert_eq!(classify_backing(None, None), None);
    }

    /// A declaration outranks an allocation. Not a reachable job; this pins
    /// which record wins should both ever exist for one token.
    #[test]
    fn a_declaration_outranks_an_allocation() {
        let declared = declared_ref(None, 7);
        let allocated = allocated_ref(AllocationKind::DesignatedOutput(vec![0x51]));

        assert_eq!(
            classify_backing(Some(&declared), Some(&allocated)),
            Some(TokenBacking::Declared(&declared)),
            "the declaration is the stronger record — bitcoin-core validated its tx set (SV2 JDP/Job Declarator Server)"
        );
    }

    /// A declaration that cannot be rebuilt still registers and resolves, but
    /// projects to nothing, which the mining handler refuses.
    #[test]
    fn job_ref_projects_none_for_an_unrebuildable_declaration() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(2);
        let mut entry = registration(t, 7);
        entry.declared_job.coinbase_tx_prefix = vec![0xAA; 8];
        reg.register(t, entry);

        let job_ref = reg.job_ref(&t).expect("registered token must resolve");
        assert!(job_ref.binding.is_none());
    }

    // ── basic CRUD ─────────────────────────────────────────────────
    //
    // Asserted through `job_ref`, the same call the mining server makes.

    #[test]
    fn register_and_resolve_roundtrips() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(1);
        reg.register(t, registration(t, 42));
        let got = reg.job_ref(&t).expect("must resolve");
        assert_eq!(got.jdp_session_id, 42);
        assert_eq!(got.miner_address.as_str(), ADDR);
    }

    #[test]
    fn unknown_token_does_not_resolve() {
        let reg = JdpDeclaredJobRegistry::new();
        assert!(reg.job_ref(&token(0xFF)).is_none());
    }

    #[test]
    fn register_overwrites_existing_token() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(1);
        reg.register(t, registration(t, 42));
        let prev = reg
            .register(t, registration(t, 99))
            .expect("must return previous");
        assert_eq!(prev.jdp_session_id, 42);
        assert_eq!(reg.job_ref(&t).unwrap().jdp_session_id, 99);
        // No duplicate stored: evicting the surviving session takes the
        // single entry with it, so the count is the assertion.
        assert_eq!(reg.evict_for_jdp_session(99), 1, "exactly one entry held");
    }

    // ── evict_for_jdp_session ──────────────────────────────────────

    #[test]
    fn evict_for_jdp_session_removes_only_matching_session() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.register(token(1), registration(token(1), 42));
        reg.register(token(2), registration(token(2), 42));
        reg.register(token(3), registration(token(3), 99));
        let evicted = reg.evict_for_jdp_session(42);
        assert_eq!(evicted, 2);
        assert!(reg.job_ref(&token(3)).is_some());
        assert!(reg.job_ref(&token(1)).is_none());
        assert!(reg.job_ref(&token(2)).is_none());
    }

    #[test]
    fn evict_for_unknown_session_returns_zero() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.register(token(1), registration(token(1), 42));
        assert_eq!(reg.evict_for_jdp_session(999), 0);
        assert!(reg.job_ref(&token(1)).is_some(), "untouched");
    }

    // ── Payout distributions (ext 0x0003 push model) ────────────────

    fn distribution(
        id: u64,
        accounting: DistributionAccounting,
        session: Option<u32>,
    ) -> PayoutDistributionEntry {
        PayoutDistributionEntry {
            distribution_id: id,
            built: crate::bridge::BuiltPayoutDistribution {
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
            },
            accounting,
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
        reg.publish_pool_wide(distribution(1, DistributionAccounting::PoolWide, None));
        reg.publish_pool_wide(distribution(2, DistributionAccounting::PoolWide, None));
        reg.publish_pool_wide(distribution(3, DistributionAccounting::PoolWide, None));
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

    /// A session whose tailored build failed must NOT resolve against the
    /// pool-wide (PPLNS) distribution; `Unknown` fails the declare closed.
    #[test]
    fn a_denied_session_does_not_fall_back_to_the_pool_wide_distribution() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, DistributionAccounting::PoolWide, None));
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
        reg.publish_pool_wide(distribution(1, DistributionAccounting::PoolWide, None));
        reg.deny_pool_wide(7);
        let owner = AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string())
            .expect("addr");
        reg.publish_tailored(
            7,
            distribution(2, DistributionAccounting::Solo(owner), Some(7)),
        );
        reg.allow_pool_wide(7);
        let scope = DistributionScope::JdpSession(7);
        assert_eq!(accepted_id(&reg.distribution_acceptance(2, scope)), Some(2));
    }

    /// The denial dies with the session, so a reconnecting JDC that
    /// reuses the id is not stuck behind a stale flag.
    #[test]
    fn evicting_a_session_clears_its_pool_wide_denial() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, DistributionAccounting::PoolWide, None));
        reg.deny_pool_wide(7);
        reg.evict_for_jdp_session(7);
        assert_eq!(
            accepted_id(&reg.distribution_acceptance(1, DistributionScope::JdpSession(7))),
            Some(1)
        );
    }

    /// A settled distribution is not handed out as the current one.
    #[test]
    fn settled_distribution_is_no_longer_current() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let owner = addr();
        reg.publish_pool_wide(distribution(1, DistributionAccounting::PoolWide, None));
        reg.publish_tailored(
            7,
            distribution(2, DistributionAccounting::Solo(owner.clone()), Some(7)),
        );
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
        reg.publish_pool_wide(distribution(3, DistributionAccounting::PoolWide, None));
        assert_eq!(reg.current_pool_wide().map(|e| e.distribution_id), Some(3));
    }

    /// A reconnecting JDC leaves its old tailored slot behind until the
    /// cleanup sweep. Address-scoped lookups must resolve against the
    /// NEWEST slot, not an arbitrary one.
    #[test]
    fn address_scope_prefers_the_newest_tailored_slot() {
        let owner = addr();
        // Both orders of session ids, and many registry instances: each gets
        // its own hash seed, so a first-match lookup would pick the ghost
        // about half the time.
        let rounds = [(7u32, 8u32), (8, 7)].into_iter().flat_map(|p| [p; 16]);
        for (ghost_session, live_session) in rounds {
            let mut reg = JdpDeclaredJobRegistry::new();
            reg.publish_pool_wide(distribution(1, DistributionAccounting::PoolWide, None));
            reg.publish_tailored(
                ghost_session,
                distribution(
                    10,
                    DistributionAccounting::Solo(owner.clone()),
                    Some(ghost_session),
                ),
            );
            reg.publish_tailored(
                live_session,
                distribution(
                    20,
                    DistributionAccounting::Solo(owner.clone()),
                    Some(live_session),
                ),
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
        reg.publish_pool_wide(distribution(1, DistributionAccounting::PoolWide, None));
        reg.publish_pool_wide(distribution(2, DistributionAccounting::PoolWide, None));
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
        reg.publish_pool_wide(distribution(3, DistributionAccounting::PoolWide, None));
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
    /// The pool-wide distribution is the PPLNS window's; a Solo or Group-Solo
    /// coinbase built against it pays miners this session's accounting has
    /// nothing to do with, and for Solo the block is then booked nowhere.
    ///
    /// A JDC still referencing it is told `stale-payout-distribution` and
    /// re-declares against the tailored distribution it was just sent.
    #[test]
    fn a_tailored_session_cannot_resolve_the_pool_wide_distribution() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, DistributionAccounting::PoolWide, None));
        reg.publish_tailored(
            7,
            distribution(2, DistributionAccounting::Solo(addr()), Some(7)),
        );
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
        // Nor after the pool-wide slot moves on.
        reg.publish_pool_wide(distribution(3, DistributionAccounting::PoolWide, None));
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

    /// A tailored session's ext 0x0003/Grace Window is latest + previous of
    /// ITS OWN entries.
    #[test]
    fn a_tailored_session_still_graces_its_own_previous_entry() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, DistributionAccounting::PoolWide, None));
        reg.publish_tailored(
            7,
            distribution(2, DistributionAccounting::Solo(addr()), Some(7)),
        );
        reg.publish_tailored(
            7,
            distribution(3, DistributionAccounting::Solo(addr()), Some(7)),
        );
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
        reg.publish_pool_wide(distribution(1, DistributionAccounting::PoolWide, None));
        reg.publish_tailored(
            7,
            distribution(2, DistributionAccounting::Solo(addr()), Some(7)),
        );
        let owner = addr();
        let scope = DistributionScope::MinerAddress(&owner);
        assert_eq!(accepted_id(&reg.distribution_acceptance(2, scope)), Some(2));
        // An address without a tailored slot falls back to pool-wide.
        let stranger = AddressId::new("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap();
        let scope = DistributionScope::MinerAddress(&stranger);
        assert_eq!(accepted_id(&reg.distribution_acceptance(1, scope)), Some(1));
    }

    /// `tailored slot dies with its JDP session — and only with it`
    ///
    /// Asserted through `current_tailored`, which is what the connection
    /// task asks before deciding whether to republish.
    #[test]
    fn tailored_slot_evicted_with_session() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, DistributionAccounting::PoolWide, None));
        reg.publish_tailored(
            7,
            distribution(2, DistributionAccounting::Solo(addr()), Some(7)),
        );
        assert!(reg.current_tailored(7).is_some());
        // A pool-wide republish must not disturb it: only the session's
        // own eviction may take the slot away.
        reg.publish_pool_wide(distribution(3, DistributionAccounting::PoolWide, None));
        assert!(
            reg.current_tailored(7).is_some(),
            "a connected miner keeps its tailored slot"
        );

        reg.evict_for_jdp_session(7);
        assert!(reg.current_tailored(7).is_none());
        // The session id (were it reused) is back on pool-wide.
        let scope = DistributionScope::JdpSession(7);
        assert_eq!(accepted_id(&reg.distribution_acceptance(3, scope)), Some(3));
    }
}
