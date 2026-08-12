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
//!
//! The miner address is NOT a field of its own: it lives on the declared
//! job, and [`JdpDeclaredJobRegistry::job_ref`] projects it from there for
//! the mining-side cross-check (so one miner can't claim another's
//! declared job). A second copy could name a different miner than the job
//! it belongs to, and the block-found path books against that name.
//!
//! There is no age-based sweep, and none is owed: every exit path of
//! the per-connection task — cancel, read error, write error — falls
//! through to `evict_for_jdp_session`, so an entry cannot outlive its
//! session.
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
    /// JDP session id that registered the entry. Used by
    /// [`JdpDeclaredJobRegistry::evict_for_jdp_session`] when the
    /// JDP connection closes — which every exit path of the
    /// per-connection task runs, so there is no age-based sweep.
    pub jdp_session_id: u32,
}

/// What the allocate gave the mining side to judge a Coinbase-only job by.
///
/// A type rather than an `Option<Vec<u8>>`, because "there is no designated
/// script" and "the pool built a broken allocate" are the same shape and not
/// the same event — the distinction `crate::jdp_server::classify_allocation`
/// already draws on the way in, kept rather than flattened on the way out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllocationKind {
    /// Base protocol: the script §6.4.3 designated as the pool payout output.
    /// The custom job's coinbase must pay it — see
    /// [`crate::jdp::dynamic_outputs::pays_designated_output`].
    DesignatedOutput(Vec<u8>),
    /// ext 0x0003: §2 requires the allocate's `coinbase_tx_outputs` to be
    /// empty, so there is no designated script to hold the coinbase to. The
    /// §7.1 recompute against the published distribution judges it instead —
    /// a stronger check, and the reason this is not a degraded base-protocol
    /// allocate but its own kind.
    JudgedByDistribution,
}

/// An allocated token the pool answered, for a mode that never declares.
///
/// It exists because Coinbase-only mode has no `DeclareMiningJob` — the JDC
/// takes the allocate token straight to `SetCustomMiningJob` on the mining
/// connection (§6.3.1: "the `DeclareMiningJob` message is never used"). So
/// the declared-job map cannot resolve that token, and without this one the
/// mining side has nothing to judge the job by.
///
/// **Both Coinbase-only kinds land here, base protocol and ext 0x0003.** The
/// 0x0003 half used to be left out on the grounds that §2 empties the
/// allocate's outputs and the §7.1 recompute is the stronger check — true of
/// the COINBASE, and irrelevant to the token. With no entry the mining side
/// could not tell that job from one bearing 16 invented bytes, so it bound
/// neither the miner address nor the chain tip and served both. §2 removes
/// the script, not the token; only the script is missing here.
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
    /// [`crate::tokens::AllocatedToken`].
    ///
    /// Without it this map has no bound at all: the token store rate-limits
    /// to one allocation per second and expires each after an hour, but a
    /// bridge entry used to live until its whole session ended — so one
    /// connection held open for a day left ~86 400 entries behind, under the
    /// same lock the mining hot path takes.
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
/// A reference is inherited from the declaration wherever §2 lets this
/// connection use the extension at all. Everything else about the job is
/// judged exactly as it was before this path existed.
///
/// **It takes no stream, and must not.** It used to skip inheritance on a Solo
/// stream, on the reasoning that a Solo job pays its own finder and had always
/// been served without a reference — so subjecting it to the §7.2/§10 window
/// would be a new way to refuse a job that used to work. Two things were wrong
/// with that:
///
/// 1. It made the answer depend on an operand the two callers could disagree
///    about, and they did. One passed the frozen template stream, the other the
///    live accounting; on a mode that moved mid-connection they resolved
///    different things.
/// 2. It is not a Solo job's own plan that the carve-out let through. A
///    connection whose accounting reads Solo may be holding a declaration bound
///    to a POOL-WIDE plan — its address flipped after the declare — and
///    dropping the reference there sent it to the base-protocol arm, which
///    serves a Solo connection with no acceptance check and no §7.1 recompute.
///    The coinbase then pays the PPLNS window on-chain while the booking
///    resolves Solo and writes nothing, so the window's claims survive and the
///    pool pays them a second time.
///
/// The rule that replaces it is simpler and has no operand to get wrong: **a
/// job whose declaration referenced a distribution is judged against it.** Solo
/// included — which is what the acceptance window costs, and it is the same
/// cost every other mode already pays.
pub fn resolve_distribution_reference(
    frame_tlv: Option<u64>,
    bridge_job: Option<&BridgeJobRef>,
    negotiated_on_this_connection: bool,
) -> Option<DistributionReference> {
    // What the JDC actually sent wins. The §2 negotiation gate judges it in the
    // handler, as it did before this path existed.
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
/// Three states, and they are the JOB DECLARATION modes of ext 0x0003 §6.3
/// as the mining side sees them. Spelled out as one type because the handler
/// asks several questions of them (whose address must match, which tip binds,
/// what pins the coinbase, who records a found block) and the answers do not
/// line up with any single `Option` on the inputs.
///
/// Derived before this type existed by asking `bridge_job.is_some()` /
/// `allocation.is_some()` at four separate places, which is what SV2 §6.3
/// modes look like when nothing names them: a fourth mode would have fallen
/// through every one of those tests without the compiler saying a word.
///
/// **This is the token's authority, not its payout coverage.** Whether a
/// published distribution pins the coinbase split is a SEPARATE question,
/// answered by [`resolve_distribution_reference`], and the two are not
/// derivable from each other: a Full-Template job may or may not carry a
/// distribution reference, and so may a base-protocol allocation. Folding
/// them into one enum would drop the §7.1 recompute for a declared job that
/// references a distribution — which the handler runs today, and must.
///
/// [`crate::jdp::dynamic_outputs::CandidateBacking`] is the OTHER axis given
/// the same treatment, not this one restated: its arms are payout coverage
/// (was a distribution referenced, and can it be booked). Do not collapse the
/// two under "one concept, one implementation" — they answer different
/// questions about the same job, which is the whole reason both exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenBacking<'a> {
    /// Full-Template (§6.3.2): a `DeclareMiningJob` stands behind the token.
    /// bitcoin-core validated the declared transaction set (§6.1), so the
    /// custom job is held to the declaration — address, declared tip, and the
    /// binding of [`crate::jdp::custom_job_binding`].
    Declared(&'a BridgeJobRef),
    /// Coinbase-only on the base protocol (§6.3.1: `DeclareMiningJob` "is
    /// never used"): the allocate is the pool's only record, so the job is
    /// held to what §6.4.3 gives — the coinbase pays `payout_script` — and to
    /// the token's own miner address and the pool's tip.
    ///
    /// The script rides on the variant so the handler never has to ask a
    /// second time whether this allocate has one. Deciding that is
    /// [`AllocationKind`]'s job, and it is done here, once.
    BaseAllocation {
        token: &'a AllocatedTokenRef,
        payout_script: &'a [u8],
    },
    /// Coinbase-only under ext 0x0003: the allocate is on file, but §2 left it
    /// without a designated output, so the §7.1 recompute against the
    /// published distribution is what judges the coinbase.
    ///
    /// The token is still the pool's own record and is bound exactly as the
    /// base-protocol one is — same miner address, same tip. Only the coinbase
    /// test differs, because only that is what §2 took away.
    DistributionAllocation(&'a AllocatedTokenRef),
}

/// Which of the three a token is — or `None`, meaning the pool has no record
/// of it (unknown / expired / evicted with its JDP session). The handler fails
/// closed on `None`: accepting would register an arbitrary self-built coinbase
/// into the share pipeline.
///
/// The frame's distribution TLV deliberately does NOT rescue a token here. It
/// used to: a job with no declaration and no allocation was served on the
/// strength of its `distribution_id` alone, which meant 16 invented bytes plus
/// the current pool-wide id got work — past the §6.4.2 rate limit, the token
/// TTL and JDP-session eviction, none of which have anything to expire for a
/// token that was never issued. A conformant 0x0003 JDC allocates like any
/// other (§2 empties the outputs, not the exchange), so it resolves here.
///
/// Pure and total on purpose, the same way
/// `crate::jdp_server::classify_allocation` is: it takes only the three
/// inputs that decide it, so every combination can be asserted without a
/// connection, and a mode added later has to be classified here rather than
/// fall into an existing arm.
///
/// `Declared` wins over `BaseAllocation`, an order that decides nothing today
/// but is stated rather than left to chance, because the argument for that
/// lives in two other files and has two halves of different strength:
///
/// - Full-Template registers no allocation AT ALL
///   (`AllocationDisposition::LeftToTheDeclaration`), precisely so an allocate
///   token cannot authorise a job that skipped `DeclareMiningJob`. Structural,
///   and the case that matters.
/// - Outside that mode the two maps are keyed by different tokens — a
///   declaration lands under the `new_mining_job_token` that
///   `TokenStore::mint_for_declaration` freshly minted, never under the
///   allocate token — but both draw from the same `next_token()`, so this half
///   rests on 12 random bytes not colliding, not on the key spaces being
///   disjoint.
///
/// Should it ever occur, the declaration is the record to hold the job to:
/// bitcoin-core validated its transaction set (§6.1), which the §6.4.3
/// single-output test does not approach. What pins the payout split is a
/// separate question and is answered either way.
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

/// Which accounting a published distribution belongs to.
///
/// This replaced a bare `owner: Option<AddressId>`, because "who owns it" and
/// "whose accounting is it" are different questions and the mining side needs
/// the second one. A Solo plan and a Group-Solo plan are BOTH tailored to one
/// address, so the owner alone cannot tell them apart — and a Solo plan mined
/// on a Group-Solo stream pays the finder alone instead of splitting across
/// the group. The owner check passed that through happily; it is the same
/// miner either way.
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
/// The one place the question "whose money does this plan pay, and is that
/// this miner?" is answered, and it has three callers that would otherwise
/// each answer it their own way:
///
/// - `SetCustomMiningJob` — may this connection MINE this plan?
/// - the JDP declare — may this session DECLARE a coinbase paying it?
/// - the JDP connection loop — is the plan it is serving still the right one?
///
/// The declare caller is not redundant with the mining one. A block found on
/// a Full-Template job is booked from its DECLARATION alone (`PushSolution` →
/// `handle_push_solution`), so it never passes the mining-side check; without
/// this question asked at declare time, a plan built for the wrong accounting
/// can still be blessed and booked.
///
/// Decided over the PAIR, because both halves are questions about a mode and
/// neither is checkable on its own. A guard like `if stream == Pplns` would be
/// an `if mode ==` in disguise: a stream added later would slip through it
/// silently. As a pair the match is exhaustive over `StreamKind`, so a new
/// stream has to be classified rather than default into being served.
///
/// The entry carries the accounting it was BUILT for, so this is a direct
/// comparison and not an inference from the owner address. That distinction is
/// the whole point: a Solo plan and a Group-Solo plan are both tailored to the
/// same one address, and an owner check waves the wrong one through — a Solo
/// plan mined on a Group-Solo stream pays the finder alone instead of
/// splitting across the group. The owner check itself stays at the call site
/// that has an address to check.
///
/// Every pair is spelled out. A new stream or a new accounting kind then fails
/// to compile instead of landing in a catch-all.
pub fn accounting_matches_stream(
    accounting: &DistributionAccounting,
    stream: bp_common::StreamKind,
) -> bool {
    use bp_common::StreamKind as Sk;
    use DistributionAccounting as Acct;
    match (accounting, stream) {
        (Acct::Solo(_), Sk::Solo) | (Acct::GroupSolo(_), Sk::GroupSolo) => true,
        // Pool-wide is the PPLNS window's. Without this a Group-Solo
        // connection could point at it: its blocks would pay the PPLNS window
        // while its shares kept earning a cut of the group's.
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
/// The `None` half is the whole reason this exists as one function. `None`
/// means the mode gate has no live mining session for the address — the rig
/// rebooted, or is between reconnects — and that is the ABSENCE of an answer,
/// not a changed one. Treating it as a change tears up a correct plan every
/// time a miner blips; a mode that really moves comes back as a different
/// `Some` and is caught by the pair.
///
/// Two callers ask it, and they used to ask it separately and in opposite
/// polarity: the JDP loop deciding whether to rebuild, and the declare path
/// deciding whether to bless a coinbase. Split, a maintainer revisiting the
/// `None` rule changes one and the compiler says nothing — and the declare
/// path keeps blessing what the rebuild path already considers stale.
pub fn accounting_fits_mode(
    accounting: &DistributionAccounting,
    current_mode: Option<bp_common::StreamKind>,
) -> bool {
    match current_mode {
        None => true,
        Some(stream) => accounting_matches_stream(accounting, stream),
    }
}

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
    /// Revenue the distribution's weight boosts were projected against —
    /// carried to the block-found path, which uses it as the fallback
    /// reward when the block's own coinbase value is unavailable.
    pub reference_reward_sats: u64,
    /// Settlement-snapshot identity (weights fingerprint). `None` when
    /// the owning mode books without a snapshot (Solo).
    pub payouts_fingerprint: Option<[u8; 32]>,
    /// Whether a booking may be stamped on jobs built from this
    /// distribution (`false` e.g. when the snapshot write failed — the
    /// job is still served, but a found block is reported-not-booked).
    pub bookable: bool,
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
    /// Base-protocol allocate tokens (Coinbase-only mode has no
    /// declaration to key on) — see [`AllocatedTokenRef`].
    allocations: HashMap<Token, AllocatedTokenRef>,
    /// Pool-wide distribution (PPLNS) — what every connection gets
    /// pushed on open and on the publisher's timer.
    pool_wide_distribution: DistributionSlot,
    /// Tailored per-JDP-session distributions (Solo or Group-Solo,
    /// published after the session's identity is known).
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

    /// Drop a declared job's entry once its token has authorised a custom
    /// job. One declaration authorises exactly one `SetCustomMiningJob`,
    /// which is the rule the reference JDS enforces.
    ///
    /// This removes only the MINING side's record. The JDP session keeps its
    /// own copy of the declaration — that is what a `PushSolution`
    /// reassembles the found block from, and dropping it here would lose
    /// every JDC-found block.
    pub fn consume_declared_job(&mut self, token: &Token) -> bool {
        self.entries.remove(token).is_some()
    }

    /// Projection of a token's bridge entry for the mining-side
    /// `SetCustomMiningJob` cross-checks. `None` for unknown / evicted
    /// tokens (the mining-handler fails closed on that, together with an
    /// absent payout set).
    pub fn job_ref(&self, token: &Token) -> Option<BridgeJobRef> {
        self.entries.get(token).map(|s| BridgeJobRef {
            // Off the declaration itself — the entry keeps no second copy,
            // so this cannot name a different miner than the job does.
            miner_address: s.entry.declared_job.miner_address.clone(),
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

    // ── Base-protocol allocate tokens ───────────────────────────────

    /// Register a base-protocol allocate token so the mining side can
    /// resolve it when a Coinbase-only `SetCustomMiningJob` arrives.
    ///
    /// Called only with a designated payout script; an ext 0x0003 session
    /// has none and registers nothing (see [`AllocatedTokenRef`]).
    ///
    /// Sweeps expired entries on the way in. That is the only bound this
    /// map has, and one insert's worth of scanning is affordable precisely
    /// because inserts are rate-limited to one per second per connection —
    /// the same limit that would otherwise fill it.
    pub fn register_allocation(&mut self, token: Token, entry: AllocatedTokenRef, now_ms: u64) {
        self.allocations.retain(|_, a| a.expires_at_ms > now_ms);
        self.allocations.insert(token, entry);
    }

    /// The base-protocol allocation behind a token, if any. `None` for an
    /// unknown/evicted token, for an EXPIRED one, and for every ext 0x0003
    /// allocation.
    ///
    /// Expiry is judged here as well as at insert time: a token that
    /// outlived its hour must stop authorising jobs even if nothing has
    /// been allocated since, and the JDP and mining connections do not
    /// share a clock tick.
    pub fn allocation_ref(&self, token: &Token, now_ms: u64) -> Option<&AllocatedTokenRef> {
        self.allocations
            .get(token)
            .filter(|a| a.expires_at_ms > now_ms)
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

    /// Mark a JDP session as requiring a tailored distribution it does
    /// not have — either its miner is Solo or Group-Solo and the
    /// tailored build failed (no fee address, engine error, no
    /// template), or it is Blockparty, which JDP refuses to serve.
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

    /// Whether the session is currently denied the pool-wide distribution.
    ///
    /// Exists so a caller that re-decides per inbound frame can find out
    /// under a READ lock that there is nothing to change. A session waiting
    /// for its mode re-denies itself on every frame it sends, and taking the
    /// write lock to re-insert an id that is already in the set serializes
    /// the registry against the mining side for no state change at all.
    pub fn is_pool_wide_denied(&self, jdp_session_id: u32) -> bool {
        self.pool_wide_denied.contains(&jdp_session_id)
    }

    /// Drop a session's tailored slot when it stops being a tailored session
    /// — its miner turned out to be, or became, a PPLNS one.
    ///
    /// Clearing the denial is not enough on its own. `distribution_acceptance`
    /// under [`DistributionScope::JdpSession`] prefers a session's tailored
    /// slot whenever its `latest` is `Some`, so a slot left behind keeps
    /// answering for every pool-wide id the session is subsequently pushed —
    /// and every one of them resolves `Stale`. The session then declares
    /// against distributions the pool believes it is serving correctly and is
    /// refused for the life of the connection.
    ///
    /// Returns whether a slot was actually removed, so the caller can log a
    /// real transition rather than a no-op.
    pub fn clear_tailored(&mut self, jdp_session_id: u32) -> bool {
        self.tailored_distributions
            .remove(&jdp_session_id)
            .is_some()
    }

    /// Drop every entry owned by a closing JDP session. Returns the
    /// count removed — useful for diagnostics + the IO layer's
    /// connection-close log.
    ///
    /// The count spans BOTH maps: it is a diagnostic for "how much did this
    /// session hold", and a number that silently ignored one of the two
    /// would understate exactly the map that can grow.
    pub fn evict_for_jdp_session(&mut self, jdp_session_id: u32) -> usize {
        let before = self.entries.len() + self.allocations.len();
        self.entries
            .retain(|_, s| s.entry.jdp_session_id != jdp_session_id);
        // Allocate tokens die with their session for the same reason the
        // declared jobs do: the token is only meaningful while the JDP
        // connection that issued it is alive.
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
            miner_address: addr(),
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

    fn registration(token: Token, session_id: u32) -> RegisteredDeclaredJob {
        RegisteredDeclaredJob {
            declared_job: declared(token),
            jdp_session_id: session_id,
        }
    }

    // ── the projection the mining side actually consumes ───────────

    /// `job_ref()` is the ONLY production site that builds
    /// `BridgeJobRef.binding` — `server.rs` calls it, nothing else.
    ///
    /// It reads the projection back off the declared bytes rather than
    /// through a second copy of the projection, which is what makes it
    /// worth having next to the mining-handler tests: those drive the real
    /// registry too (`job_ref_for` registers and calls `job_ref`), so a
    /// registry that stopped projecting takes 20 tests down with it —
    /// measured. What this one adds is WHICH bytes came through, on a
    /// binding that fails closed and is therefore indistinguishable from a
    /// correct refusal when only the verdict is checked.
    #[test]
    fn job_ref_carries_the_declaration_projected() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(1);
        reg.register(t, registration(t, 7));

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
    /// It used to skip Solo, so that a Solo job kept being served without ever
    /// consulting the acceptance window. What that actually let through was a
    /// connection whose accounting had FLIPPED to Solo while holding a
    /// declaration bound to a pool-wide plan: the reference was dropped, the
    /// base-protocol arm served it with no §7.1 recompute, and the coinbase
    /// paid the PPLNS window on-chain while the booking resolved Solo and
    /// wrote nothing — the window's claims survive and the pool pays twice.
    ///
    /// A job that referenced nothing is still untouched; that is the property
    /// the carve-out was reaching for, and it needs no stream to express.
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
            resolve_distribution_reference(None, Some(&job_ref), false),
            None
        );
        assert_eq!(
            resolve_distribution_reference(Some(11), Some(&job_ref), false),
            Some(DistributionReference::FromFrame {
                distribution_id: 11
            }),
            "the handler's §2 gate needs to see the TLV in order to reject it"
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

    /// Every shape, asserted as a value — the point of the classifier being
    /// pure. Driving these through the mining handler instead would only show
    /// the verdict, and the two allocate kinds share most of theirs.
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
        // variant, so the handler never asks a second time whether there is
        // one.
        assert_eq!(
            classify_backing(None, Some(&base)),
            Some(TokenBacking::BaseAllocation {
                token: &base,
                payout_script: &[0x51],
            })
        );
        // ext 0x0003 Coinbase-only: on file like any other allocate, only
        // without a script to compare. It used to resolve to nothing at all.
        assert_eq!(
            classify_backing(None, Some(&ext)),
            Some(TokenBacking::DistributionAllocation(&ext))
        );
        // Fail-closed: unknown / expired / evicted. A distribution reference
        // no longer rescues a token the pool has no record of.
        assert_eq!(classify_backing(None, None), None);
    }

    /// The order between the first two arms, stated as a test because the
    /// argument for it lives in two other files: Full-Template registers no
    /// allocation, and outside that mode the two tokens differ. Not a
    /// reachable job — the assertion is about which record wins if that ever
    /// stops holding.
    #[test]
    fn a_declaration_outranks_an_allocation() {
        let declared = declared_ref(None, 7);
        let allocated = allocated_ref(AllocationKind::DesignatedOutput(vec![0x51]));

        assert_eq!(
            classify_backing(Some(&declared), Some(&allocated)),
            Some(TokenBacking::Declared(&declared)),
            "the declaration is the stronger record — bitcoin-core validated its tx set (§6.1)"
        );
    }

    /// The negative half: a declaration that cannot be rebuilt still
    /// registers and still resolves, but projects to nothing — which is what
    /// the mining handler turns into a refusal.
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
    // Asserted through `job_ref` — the same call the mining server
    // makes. A test-only accessor would prove less: it is not the
    // surface that can break in production.

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

    /// A settled distribution must not be handed out as the current
    /// one: the connection-open push would send a JDC an id that every
    /// declaration is then rejected for, and the publisher's
    /// skip-if-unchanged compare would swallow the forced republish.
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
        // Nor after the pool-wide slot moves on, which is the state the
        // seeded entry used to survive into.
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

    /// A tailored session's own grace slot still works — the §7.2 window
    /// is latest + previous of ITS OWN entries, and only the cross-scope
    /// seed is gone.
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
    /// task actually asks before deciding whether to republish. A slot
    /// count would answer a weaker question.
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
