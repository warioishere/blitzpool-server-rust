// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-server (JDP → Mining) registry of declared jobs, allocate tokens and
//! payout distributions: a JDC declares on its JDP connection and sends
//! `SetCustomMiningJob` on its mining connection, and [`JdpDeclaredJobRegistry`]
//! carries the record between them. Entries die with their JDP session.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bp_common::AddressId;

use crate::jdp::custom_job_binding::{binding_from_declared_job, DeclaredJobBinding};
use crate::jdp::declarations::DeclaredJob;
use crate::jdp::payout_distribution::WeightedOutput;
use crate::tokens::Token;

/// What the allocate gave the mining side to judge a Coinbase-only job by.
/// An enum, not `Option<Vec<u8>>`: "no script by design" is not "broken allocate".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllocationKind {
    /// Base protocol: the coinbase must pay the script that
    /// SV2 JDP/AllocateMiningJobToken.Success designated.
    DesignatedOutput(Vec<u8>),
    /// ext 0x0003/Negotiation empties the allocate's outputs; the
    /// ext 0x0003/Output Verification recompute judges the coinbase instead.
    JudgedByDistribution,
}

/// A Coinbase-only allocate token: the mining side's only record of it, since
/// SV2 JDP/Coinbase-only Mode never sends `DeclareMiningJob`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocatedTokenRef {
    /// Cross-checked against the mining channel's locked address.
    pub miner_address: AddressId,
    pub kind: AllocationKind,
    /// JDP session that issued it (evicted with the session).
    pub jdp_session_id: u32,
    /// The token's own expiry; bounds the map on a long-lived session.
    pub expires_at_ms: u64,
}

/// Projection of a bridge entry for the `SetCustomMiningJob` cross-checks,
/// without the declared job's raw transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeJobRef {
    /// Cross-checked against the mining channel's locked address.
    pub miner_address: AddressId,
    /// Pool chain-tip the declaration was accepted under.
    pub declared_prev_hash: [u8; 32],
    /// What `SetCustomMiningJob` must repeat ([`crate::jdp::custom_job_binding`]).
    /// `None` when the declaration cannot be projected; the handler rejects then.
    pub binding: Option<DeclaredJobBinding>,
    /// The `distribution_id` the declaration referenced: in Full-Template the
    /// TLV rides on `DeclareMiningJob` (ext 0x0003/distribution_id TLV Field),
    /// never on the mining frame. `None` for a base-protocol declaration.
    pub distribution_id: Option<u64>,
    /// JDP session that accepted the declaration; see
    /// [`DistributionReference::FromDeclaration`].
    pub jdp_session_id: u32,
}

/// Where the distribution reference for a `SetCustomMiningJob` came from; each
/// arm carries the [`DistributionScope`] it must be resolved under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DistributionReference {
    /// Coinbase-only: TLV on this frame; tailored slots resolve by owner address.
    FromFrame { distribution_id: u64 },
    /// Full-Template: inherited from the declaration. MUST resolve under the
    /// declaring JDP session, not by owner address: an address can own several
    /// tailored slots, and the newest never held an older session's id, which
    /// would yield a fatal `stale-payout-distribution`.
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

/// Which distribution a `SetCustomMiningJob` is judged against, shared by the
/// IO layer and [`crate::mining::client::handle_set_custom_mining_job`]. It
/// must take no stream: a Solo connection's declaration may be bound to the
/// pool-wide plan, and skipping the check would pay PPLNS claims twice.
pub fn resolve_distribution_reference(
    frame_tlv: Option<u64>,
    bridge_job: Option<&BridgeJobRef>,
    negotiated_on_this_connection: bool,
) -> Option<DistributionReference> {
    // The frame's own TLV wins; the handler's ext 0x0003/Negotiation gate judges it.
    if let Some(distribution_id) = frame_tlv {
        return Some(DistributionReference::FromFrame { distribution_id });
    }

    // ext 0x0003/Negotiation: negotiated on one connection only MUST NOT use
    // it, so no reference is synthesised on the JDC's behalf.
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

/// What the pool has on file for a `SetCustomMiningJob`'s token (SV2 JDP/Job
/// Declaration Modes). The token's authority, not its payout coverage, which is
/// [`crate::jdp::dynamic_outputs::CandidateBacking`]; do not collapse the two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenBacking<'a> {
    /// Full-Template: held to the declaration (address, declared tip, and
    /// [`crate::jdp::custom_job_binding`]).
    Declared(&'a BridgeJobRef),
    /// Base-protocol Coinbase-only: the coinbase must pay `payout_script`;
    /// held to the token's miner address and the pool's tip.
    BaseAllocation {
        token: &'a AllocatedTokenRef,
        payout_script: &'a [u8],
    },
    /// Coinbase-only under ext 0x0003: bound like `BaseAllocation`, but the
    /// ext 0x0003/Output Verification recompute judges the coinbase.
    DistributionAllocation(&'a AllocatedTokenRef),
}

/// `None` (no record) fails closed; the frame's TLV never rescues an unknown
/// token, since only an issued one is rate-limited, TTL-bound and evicted.
/// `Declared` wins a clash: the node validated its transaction set (SV2
/// JDP/Job Declarator Server).
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

// ── Payout distributions (ext 0x0003 push model) ─────────────────────

/// Which accounting a published distribution belongs to. The owner alone is
/// not enough: Solo and Group-Solo plans for one address pay differently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DistributionAccounting {
    /// The PPLNS window's: any connection may reference it, only PPLNS is paid by it.
    PoolWide,
    /// Tailored to one Solo miner: its block pays that miner.
    Solo(AddressId),
    /// Tailored to one group's finder: its block splits across the group.
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
/// Shared by `SetCustomMiningJob`, the JDP declare (a Full-Template block is
/// booked from its declaration alone) and the JDP connection loop. Every pair
/// is spelled out so a new kind fails to compile.
pub fn accounting_matches_stream(
    accounting: &DistributionAccounting,
    stream: bp_common::StreamKind,
) -> bool {
    use bp_common::StreamKind as Sk;
    use DistributionAccounting as Acct;
    match (accounting, stream) {
        (Acct::Solo(_), Sk::Solo) | (Acct::GroupSolo(_), Sk::GroupSolo) => true,
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

/// Is a plan built for `accounting` still right for the address's current mode?
/// `None` (no live mining session, e.g. after a reconnect) is no answer, so the plan stands.
pub fn accounting_fits_mode(
    accounting: &DistributionAccounting,
    current_mode: Option<bp_common::StreamKind>,
) -> bool {
    match current_mode {
        None => true,
        Some(stream) => accounting_matches_stream(accounting, stream),
    }
}

/// A built payout distribution, ready to publish as
/// ext 0x0003/SetPayoutDistribution and to register for Output Verification.
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
    /// Settlement-snapshot identity; `None` for Solo, which books without one.
    pub payouts_fingerprint: Option<[u8; 32]>,
    /// `false` when the snapshot write failed: a found block cannot be booked.
    pub bookable: bool,
}

/// One published ext 0x0003/SetPayoutDistribution, resolvable by both the
/// declare path and the mining-side `SetCustomMiningJob` path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutDistributionEntry {
    /// ext 0x0003/SetPayoutDistribution: strictly increasing across all connections.
    pub distribution_id: u64,
    pub built: BuiltPayoutDistribution,
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
    /// Known but superseded or settlement-invalidated →
    /// `stale-payout-distribution`.
    Stale,
    /// Never published or pruned; same error code on the wire.
    Unknown,
}

/// A published entry plus its settlement epoch; an older epoch is stale
/// (ext 0x0003/Implementation Notes).
#[derive(Clone, Debug)]
struct PublishedDistribution {
    entry: Arc<PayoutDistributionEntry>,
    epoch: u64,
}

/// Latest + previous published entry (ext 0x0003/Grace Window).
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

/// Pool-wide registry written by the JDP server and read by the mining server:
/// declared jobs, Coinbase-only allocate tokens, and payout distributions.
#[derive(Debug, Default)]
pub struct JdpDeclaredJobRegistry {
    /// Keyed by the token issued in `DeclareMiningJobSuccess`.
    entries: HashMap<Token, BridgeJobRef>,
    allocations: HashMap<Token, AllocatedTokenRef>,
    /// The PPLNS distribution every connection is pushed.
    pool_wide_distribution: DistributionSlot,
    /// Solo / Group-Solo distributions per JDP session.
    tailored_distributions: HashMap<u32, DistributionSlot>,
    /// Sessions that need a tailored distribution but have none; see
    /// [`Self::deny_pool_wide`].
    pool_wide_denied: HashSet<u32>,
    /// Entries published under an older epoch resolve as `Stale`.
    settlement_epoch: u64,
}

impl JdpDeclaredJobRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a declared job as its projection, built once here so no
    /// merkle rebuild happens per `SetCustomMiningJob` under the registry lock.
    /// The JDP session keeps the full job for `PushSolution`.
    pub fn register(&mut self, token: Token, job: &DeclaredJob, jdp_session_id: u32) {
        let job_ref = BridgeJobRef {
            // Off the declaration, so it cannot name a different miner than the job.
            miner_address: job.miner_address.clone(),
            declared_prev_hash: job.prev_hash,
            binding: binding_from_declared_job(job),
            // Not from `booking`, which also requires the settlement snapshot.
            distribution_id: job.distribution_id,
            jdp_session_id,
        };
        self.entries.insert(token, job_ref);
    }

    /// One declaration authorises exactly one `SetCustomMiningJob`. Removes
    /// only the mining side's record; the JDP session keeps its own copy.
    pub fn consume_declared_job(&mut self, token: &Token) -> bool {
        self.entries.remove(token).is_some()
    }

    /// Projection for the `SetCustomMiningJob` cross-checks; `None` for an
    /// unknown or evicted token.
    pub fn job_ref(&self, token: &Token) -> Option<BridgeJobRef> {
        self.entries.get(token).cloned()
    }

    // ── Base-protocol allocate tokens ───────────────────────────────

    /// Register a Coinbase-only allocate token. Sweeps expired entries on the
    /// way in, affordable because allocations are rate-limited.
    pub fn register_allocation(&mut self, token: Token, entry: AllocatedTokenRef, now_ms: u64) {
        self.allocations.retain(|_, a| a.expires_at_ms >= now_ms);
        self.allocations.insert(token, entry);
    }

    /// One token, one `SetCustomMiningJob`; mirror of [`Self::consume_declared_job`].
    pub fn consume_allocation(&mut self, token: &Token) -> bool {
        self.allocations.remove(token).is_some()
    }

    /// The allocation behind a token; `None` if unknown, evicted or expired
    /// (judged here too, so expiry needs no later insert).
    pub fn allocation_ref(&self, token: &Token, now_ms: u64) -> Option<&AllocatedTokenRef> {
        self.allocations
            .get(token)
            .filter(|a| a.expires_at_ms >= now_ms)
    }

    // ── Payout distributions (ext 0x0003 push model) ────────────────

    /// Publish a pool-wide distribution; the prior latest becomes the grace slot.
    pub fn publish_pool_wide(&mut self, entry: PayoutDistributionEntry) {
        let epoch = self.settlement_epoch;
        self.pool_wide_distribution.publish(Arc::new(entry), epoch);
    }

    /// Publish a tailored distribution to one JDP session. Its grace slot holds
    /// only the session's OWN previous entry, never the pool-wide (PPLNS) one,
    /// which a Solo or Group-Solo coinbase must not pay.
    pub fn publish_tailored(&mut self, jdp_session_id: u32, entry: PayoutDistributionEntry) {
        let epoch = self.settlement_epoch;
        self.tailored_distributions
            .entry(jdp_session_id)
            .or_default()
            .publish(Arc::new(entry), epoch);
    }

    /// The current pool-wide distribution; `None` once a settlement invalidated
    /// it, so the publisher does not skip the forced republish.
    pub fn current_pool_wide(&self) -> Option<Arc<PayoutDistributionEntry>> {
        self.pool_wide_distribution
            .latest
            .as_ref()
            .filter(|p| p.epoch == self.settlement_epoch)
            .map(|p| p.entry.clone())
    }

    /// The current tailored distribution for a session; see [`Self::current_pool_wide`].
    pub fn current_tailored(&self, jdp_session_id: u32) -> Option<Arc<PayoutDistributionEntry>> {
        self.tailored_distributions
            .get(&jdp_session_id)
            .and_then(|s| s.latest.as_ref())
            .filter(|p| p.epoch == self.settlement_epoch)
            .map(|p| p.entry.clone())
    }

    /// Resolve a `distribution_id` under `scope` (ext 0x0003/Grace Window:
    /// latest + previous of the session's tailored slot if it has one).
    pub fn distribution_acceptance(
        &self,
        distribution_id: u64,
        scope: DistributionScope<'_>,
    ) -> DistributionAcceptance {
        let slot = match scope {
            // A denied session must not borrow the PPLNS distribution; fail closed.
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
            // An address can own several tailored slots; take the NEWEST publish.
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
            // Stale vs Unknown differs only for observability, not on the wire.
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

    /// A found block makes every published distribution stale at once; the
    /// grace window MUST NOT span a settlement (ext 0x0003/Implementation Notes).
    /// The publisher pushes a fresh distribution right after.
    pub fn invalidate_all_distributions(&mut self) {
        self.settlement_epoch += 1;
        self.pool_wide_distribution.previous = None;
        for slot in self.tailored_distributions.values_mut() {
            slot.previous = None;
        }
    }

    /// Mark a session that needs a tailored distribution it does not have
    /// (failed Solo/Group-Solo build, or Blockparty). Otherwise its block would
    /// pay the PPLNS window; serving nothing is the only safe answer.
    pub fn deny_pool_wide(&mut self, jdp_session_id: u32) {
        self.pool_wide_denied.insert(jdp_session_id);
    }

    /// Clear the denial once a tailored distribution was published.
    pub fn allow_pool_wide(&mut self, jdp_session_id: u32) {
        self.pool_wide_denied.remove(&jdp_session_id);
    }

    /// Lets a per-frame caller check under a read lock instead of the write lock.
    pub fn is_pool_wide_denied(&self, jdp_session_id: u32) -> bool {
        self.pool_wide_denied.contains(&jdp_session_id)
    }

    /// Drop a session's tailored slot once its miner is PPLNS; a leftover slot
    /// would resolve every pool-wide id as `Stale`. Returns whether one was removed.
    pub fn clear_tailored(&mut self, jdp_session_id: u32) -> bool {
        self.tailored_distributions
            .remove(&jdp_session_id)
            .is_some()
    }

    /// Drop everything a closing JDP session owns; returns the token entries removed.
    pub fn evict_for_jdp_session(&mut self, jdp_session_id: u32) -> usize {
        let before = self.entries.len() + self.allocations.len();
        self.entries
            .retain(|_, j| j.jdp_session_id != jdp_session_id);
        self.allocations
            .retain(|_, a| a.jdp_session_id != jdp_session_id);
        self.tailored_distributions.remove(&jdp_session_id);
        self.pool_wide_denied.remove(&jdp_session_id);
        before - (self.entries.len() + self.allocations.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A coinbase that rebuilds, so the projection is `Some`.
    fn declared(token: Token) -> DeclaredJob {
        use bitcoin::consensus::Encodable;

        let script_sig_len = SCRIPT_SIG_PREFIX.len() + SLOT;
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&2u32.to_le_bytes()); // coinbase_tx_version
        prefix.push(0x01); // input count
        prefix.extend_from_slice(&[0u8; 32]); // null outpoint hash
        prefix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // outpoint index
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
            raw_transactions: Vec::new(),
            merkle_path: Some(Vec::new()),
            prev_hash: [0xAB; 32],
            declared_at_ms: 1_000,
            booking: None,
            distribution_id: None,
        }
    }

    // ── the projection the mining side actually consumes ───────────

    /// Pins which declared bytes `job_ref()` projects into the binding.
    #[test]
    fn job_ref_carries_the_declaration_projected() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(1);
        reg.register(t, &declared(t), 7);

        let job_ref = reg.job_ref(&t).expect("registered token must resolve");
        assert_eq!(job_ref.miner_address, addr());
        assert_eq!(job_ref.declared_prev_hash, [0xAB; 32]);

        let binding = job_ref
            .binding
            .expect("a rebuildable declaration must project");
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

    /// The declaration's `distribution_id` (and session) reach the projection;
    /// a base-protocol declaration projects `None`.
    #[test]
    fn job_ref_carries_the_declarations_distribution_reference() {
        let mut reg = JdpDeclaredJobRegistry::new();

        let declared_under_0x0003 = token(1);
        let mut job = declared(declared_under_0x0003);
        job.distribution_id = Some(9);
        reg.register(declared_under_0x0003, &job, 7);

        let base_protocol = token(2);
        reg.register(base_protocol, &declared(base_protocol), 7);

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
        assert_eq!(
            reg.job_ref(&declared_under_0x0003)
                .expect("registered")
                .jdp_session_id,
            7
        );
    }

    fn declared_ref(distribution_id: Option<u64>, session: u32) -> BridgeJobRef {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(1);
        let mut job = declared(t);
        job.distribution_id = distribution_id;
        reg.register(t, &job, session);
        reg.job_ref(&t).expect("registered")
    }

    /// The frame's TLV wins; otherwise the declaration's reference, with its session.
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

    /// MONEY: a declaration's reference is inherited on every stream, Solo
    /// included, or the PPLNS window could be paid twice.
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

    /// ext 0x0003/Negotiation: nothing is inherited without negotiation; the
    /// frame's own TLV still passes through for the handler to reject.
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

    /// The expiry millisecond is still active here, as in
    /// `crate::tokens::AllocatedToken::is_expired`; one after it is not.
    #[test]
    fn an_allocation_is_live_through_its_expiry_millisecond() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(5);
        let entry = AllocatedTokenRef {
            expires_at_ms: 100,
            ..allocated_ref(AllocationKind::JudgedByDistribution)
        };
        reg.register_allocation(t, entry, 0);
        assert!(
            reg.allocation_ref(&t, 100).is_some(),
            "the boundary ms is still active"
        );
        assert!(reg.allocation_ref(&t, 101).is_none());
        reg.register_allocation(
            token(6),
            allocated_ref(AllocationKind::JudgedByDistribution),
            100,
        );
        assert!(
            reg.allocation_ref(&t, 100).is_some(),
            "a sweep at the boundary keeps it"
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

    /// Every on-file shape maps to its `TokenBacking`; nothing on file is `None`.
    #[test]
    fn a_token_is_classified_by_what_the_pool_has_on_file() {
        let declared = declared_ref(Some(9), 7);
        let base = allocated_ref(AllocationKind::DesignatedOutput(vec![0x51]));
        let ext = allocated_ref(AllocationKind::JudgedByDistribution);

        assert_eq!(
            classify_backing(Some(&declared), None),
            Some(TokenBacking::Declared(&declared))
        );
        assert_eq!(
            classify_backing(None, Some(&base)),
            Some(TokenBacking::BaseAllocation {
                token: &base,
                payout_script: &[0x51],
            })
        );
        assert_eq!(
            classify_backing(None, Some(&ext)),
            Some(TokenBacking::DistributionAllocation(&ext))
        );
        // Fail-closed: unknown / expired / evicted.
        assert_eq!(classify_backing(None, None), None);
    }

    /// A declaration outranks an allocation should both exist for one token.
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

    /// An unrebuildable declaration still resolves, with `binding: None`.
    #[test]
    fn job_ref_projects_none_for_an_unrebuildable_declaration() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(2);
        let mut job = declared(t);
        job.coinbase_tx_prefix = vec![0xAA; 8];
        reg.register(t, &job, 7);

        let job_ref = reg.job_ref(&t).expect("registered token must resolve");
        assert!(job_ref.binding.is_none());
    }

    // ── basic CRUD ─────────────────────────────────────────────────

    #[test]
    fn register_and_resolve_roundtrips() {
        let mut reg = JdpDeclaredJobRegistry::new();
        let t = token(1);
        reg.register(t, &declared(t), 42);
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
        reg.register(t, &declared(t), 42);
        reg.register(t, &declared(t), 99);
        assert_eq!(reg.job_ref(&t).unwrap().jdp_session_id, 99);
        assert_eq!(reg.evict_for_jdp_session(99), 1, "exactly one entry held");
    }

    // ── evict_for_jdp_session ──────────────────────────────────────

    #[test]
    fn evict_for_jdp_session_removes_only_matching_session() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.register(token(1), &declared(token(1)), 42);
        reg.register(token(2), &declared(token(2)), 42);
        reg.register(token(3), &declared(token(3)), 99);
        let evicted = reg.evict_for_jdp_session(42);
        assert_eq!(evicted, 2);
        assert!(reg.job_ref(&token(3)).is_some());
        assert!(reg.job_ref(&token(1)).is_none());
        assert!(reg.job_ref(&token(2)).is_none());
    }

    #[test]
    fn evict_for_unknown_session_returns_zero() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.register(token(1), &declared(token(1)), 42);
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

    /// Grace window: latest + previous accepted, older and never-published unknown.
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

    /// A denied session resolves the pool-wide distribution as `Unknown`.
    #[test]
    fn a_denied_session_does_not_fall_back_to_the_pool_wide_distribution() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, DistributionAccounting::PoolWide, None));
        let scope = DistributionScope::JdpSession(7);
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

    /// After a tailored publish lifts the denial, the session's own entry resolves.
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

    /// The denial dies with the session.
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

    /// Address scope resolves against the NEWEST of an owner's tailored slots.
    #[test]
    fn address_scope_prefers_the_newest_tailored_slot() {
        let owner = addr();
        // Many instances, each with its own hash seed, so a first-match lookup fails.
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

    /// Settlement invalidation: everything published before is stale.
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
        reg.publish_pool_wide(distribution(3, DistributionAccounting::PoolWide, None));
        assert_eq!(accepted_id(&reg.distribution_acceptance(3, scope)), Some(3));
        // Stale even though it now sits in the grace slot.
        assert_eq!(
            reg.distribution_acceptance(2, scope),
            DistributionAcceptance::Stale
        );
    }

    /// MONEY: a tailored session never resolves the pool-wide (PPLNS)
    /// distribution, while a session without a tailored slot still does.
    #[test]
    fn a_tailored_session_cannot_resolve_the_pool_wide_distribution() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, DistributionAccounting::PoolWide, None));
        reg.publish_tailored(
            7,
            distribution(2, DistributionAccounting::Solo(addr()), Some(7)),
        );
        let scope = DistributionScope::JdpSession(7);
        assert_eq!(accepted_id(&reg.distribution_acceptance(2, scope)), Some(2));
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

        // Not a blanket refusal: a PPLNS session still uses pool-wide.
        let pplns = DistributionScope::JdpSession(9);
        assert_eq!(accepted_id(&reg.distribution_acceptance(3, pplns)), Some(3));
        assert_eq!(
            reg.distribution_acceptance(2, pplns),
            DistributionAcceptance::Stale, // known, but not in THIS scope's window
        );
    }

    /// A tailored session's ext 0x0003/Grace Window covers its own previous entry.
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

    /// Mining-side scope resolves tailored entries by owner address.
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

    /// A tailored slot dies with its JDP session, and only with it.
    #[test]
    fn tailored_slot_evicted_with_session() {
        let mut reg = JdpDeclaredJobRegistry::new();
        reg.publish_pool_wide(distribution(1, DistributionAccounting::PoolWide, None));
        reg.publish_tailored(
            7,
            distribution(2, DistributionAccounting::Solo(addr()), Some(7)),
        );
        assert!(reg.current_tailored(7).is_some());
        reg.publish_pool_wide(distribution(3, DistributionAccounting::PoolWide, None));
        assert!(
            reg.current_tailored(7).is_some(),
            "a connected miner keeps its tailored slot"
        );

        reg.evict_for_jdp_session(7);
        assert!(reg.current_tailored(7).is_none());
        let scope = DistributionScope::JdpSession(7);
        assert_eq!(accepted_id(&reg.distribution_acceptance(3, scope)), Some(3));
    }
}
