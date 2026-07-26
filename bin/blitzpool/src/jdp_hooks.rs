// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production JDP hooks — Phase 7.4d.4.
//!
//! Replaces the four `JdpServerHooks::no_op()` placeholders so a
//! Job-Declaration-Client can actually go through the
//! `AllocateMiningJobToken` → `DeclareMiningJob` →
//! `ProvideMissingTransactions` → `PushSolution` choreography against
//! a real pool template + real block submission to bitcoin-core.
//!
//! ## The four hooks
//!
//! 1. **[`ProductionJdpAllocateResolver`]** — parses the JDC's
//!    `user_identifier` as a BTC address, calls into
//!    [`bp_mining_mode::ModeResolver`]-equivalent (via the same
//!    [`crate::payout_resolver::ProductionPayoutResolver`] the SV1/SV2
//!    mining paths use), and encodes the resolved single-output
//!    coinbase as a consensus-serialised `Vec<TxOut>` blob through
//!    [`bp_stratum_v2::jdp::dynamic_outputs::encode_coinbase_outputs`].
//!    Pre-7.4d.4 was a stub returning `[0x00]`; production rejects
//!    JDC connections with unparseable identifiers (the spec says
//!    "JDS MAY accept any identifier"; we choose to require a parseable
//!    BTC address — typical JDC operators run their own dev-fee
//!    addresses anyway).
//!
//! 2. **[`TdpTemplateTxProvider`]** — returns the wtxid→tx_bytes map
//!    for the **current** template. Phase 7.4d.4 ships this as an
//!    empty map: the JDC will respond to `ProvideMissingTransactions`
//!    with the full tx-set. That's bandwidth-suboptimal (1–2 MB per
//!    declaration vs ~80 KB if pool knew most txs) but functionally
//!    correct. A proper TDP tx-cache is deferred — see DEFERRED.md
//!    "JDP tx-cache (bandwidth optimisation)".
//!
//! 3. **[`TdpCurrentPrevHashProvider`]** — reads
//!    `TdpHandle::current_snapshot().set_new_prev_hash.prev_hash`.
//!    Trivial.
//!
//! 4. **[`ProductionJdpBlockSink`]** — on a JDC `PushSolution`,
//!    reconstructs the full SegWit block from (a) the declared
//!    coinbase prefix+suffix + JDC extranonce (witness-formed via
//!    [`bp_stratum_v2::mining::submit::assemble_witness_coinbase`]),
//!    (b) the JDC-supplied raw transactions from
//!    `JdpSessionEvent::BlockSubmissionCandidate.transactions`, and
//!    (c) the header fields — **once** — then hands that one block to
//!    both things that want it. First the **orphan-protection
//!    redundancy** resubmit via [`BitcoinRpc::submit_block`]: the JDC
//!    also submits via its own TDP connection, so the pool-side submit
//!    is a hot-path Anti-Orphan measure consistent with the SV2 spec
//!    §6.4.9 "JDS SHOULD propagate". Then the payout ledger, which
//!    books the block only once its header proves work against the
//!    pool's OWN target and tip. Either half can be switched off
//!    (`[sv2].jdp_orphan_submitblock`, no ledger fan-out wired) without
//!    touching the other.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use bitcoin::block::{Block, Header, Version as BlockVersion};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::{encode::serialize_hex, Decodable};
use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use bitcoin::{BlockHash, Network as BitcoinNetwork, TxMerkleNode};
use bp_bitcoin::BitcoinRpc;
use bp_common::{AddressId, Sats};
use bp_mining_job::PayoutEntry;
use bp_stratum_v2::jdp::client::{
    parse_user_identifier_as_address, AllocateTokenContext, PayoutOutputsResolution,
};
use bp_stratum_v2::jdp::dynamic_outputs::{
    coinbase_outputs_fit_reservation, encode_coinbase_outputs, fold_residual_to_exact_sum,
    DynamicOutput, PayoutBooking,
};
use bp_stratum_v2::jdp_server::{
    CurrentPrevHashProvider, JdpAllocateResolver, JdpBlockSubmissionSink, JdpServerHooks,
    PayoutOutputsResolver, TemplateTxProvider,
};
use bp_stratum_v2::mining::submit::assemble_witness_coinbase;
use bp_stratum_v2::tokens::Token;
use bp_template_distribution::{TdpHandle, TemplateTxCache};
use tracing::{info, warn};

use crate::payout_resolver::ProductionPayoutResolver;

/// Build the production `JdpServerHooks` aggregate. The four hooks
/// share clones of the long-lived foundation handles — cheap to
/// construct, cheap to clone per-connection.
///
/// `orphan_submitblock_enabled` controls the resubmit half of the
/// block-submission sink: `true` → real RPC resubmit (full anti-orphan
/// redundancy); `false` → the JDC is the sole propagator via its own
/// TDP connection and the pool only reports the block. Source:
/// `[sv2].jdp_orphan_submitblock` in the TOML. `ledger_booker` switches
/// the other half, independently.
pub(crate) fn build_jdp_hooks(
    tdp: TdpHandle,
    bitcoin_rpc: BitcoinRpc,
    payout_resolver: Arc<ProductionPayoutResolver>,
    template_tx_cache: Option<Arc<TemplateTxCache>>,
    network: BitcoinNetwork,
    orphan_submitblock_enabled: bool,
    ledger_booker: Option<Arc<crate::block_sink::TdpBlockSubmissionSink>>,
) -> JdpServerHooks {
    let propagator: Option<Arc<dyn BlockPropagator>> = if orphan_submitblock_enabled {
        info!(
            "jdp: orphan-protection submitblock RPC ENABLED \
             (`[sv2].jdp_orphan_submitblock = true`)"
        );
        Some(Arc::new(bitcoin_rpc))
    } else {
        info!(
            "jdp: orphan-protection submitblock RPC DISABLED — JDC is sole \
             block propagator (set `[sv2].jdp_orphan_submitblock = true` to enable \
             pool-side resubmit for commercial JDC deployments)"
        );
        None
    };
    if ledger_booker.is_none() {
        info!("jdp: ledger fan-out not wired — a JDC-found block will be reported but not booked");
    }
    // One sink for both halves. The block was found whether or not the pool
    // resubmits it, so booking hangs off its own switch, not the resubmit one.
    let block_sink: Arc<dyn JdpBlockSubmissionSink> = Arc::new(ProductionJdpBlockSink {
        propagator,
        booker: ledger_booker.map(|b| b as Arc<dyn DeclaredBlockBooker>),
        chain: Arc::new(tdp.clone()),
        booked: StdMutex::new(VecDeque::new()),
    });
    JdpServerHooks {
        allocate_resolver: Arc::new(ProductionJdpAllocateResolver {
            payout_resolver: payout_resolver.clone(),
            tdp: tdp.clone(),
            network,
        }),
        template_tx_provider: Arc::new(TdpTemplateTxProvider {
            cache: template_tx_cache,
        }),
        prev_hash_provider: Arc::new(TdpCurrentPrevHashProvider { tdp: tdp.clone() }),
        block_submission_sink: block_sink,
        payout_outputs_resolver: Arc::new(ProductionPayoutOutputsResolver {
            payout_resolver,
            tdp,
            network,
        }),
    }
}

// ─── 1. ProductionJdpAllocateResolver ────────────────────────────

pub(crate) struct ProductionJdpAllocateResolver {
    payout_resolver: Arc<ProductionPayoutResolver>,
    tdp: TdpHandle,
    network: BitcoinNetwork,
}

#[async_trait]
impl JdpAllocateResolver for ProductionJdpAllocateResolver {
    async fn resolve_allocate_context(
        &self,
        user_identifier: &str,
        _remote_addr: &str,
    ) -> Option<AllocateTokenContext> {
        let miner_address = parse_user_identifier_as_address(user_identifier)?;

        // Reward estimate for the upcoming block — read the latest TDP
        // template's `coinbase_tx_value_remaining`. If TDP hasn't seen
        // its first NewTemplate yet, fall back to a subsidy estimate
        // (~3.125 BTC post-Apr-2024 halving). The actual block reward
        // at submission may differ slightly; this is just the
        // resolver's input to compute output sats.
        let reward_sats = self
            .tdp
            .current_snapshot()
            .new_template
            .as_ref()
            .map(|t| t.coinbase_tx_value_remaining)
            .unwrap_or(312_500_000); // ~3.125 BTC subsidy fallback

        // Use the production resolver — same as SV1/SV2 mining paths
        // so JDP-mode miners inherit the per-mode (solo / PPLNS /
        // group-solo) coinbase output distribution.
        let payouts = bp_stratum_v2::hooks::PayoutResolver::resolve_payouts(
            &*self.payout_resolver,
            &miner_address,
            reward_sats,
        )
        .await;

        if payouts.is_empty() {
            warn!(
                user_identifier,
                "JDP allocate: PayoutResolver returned empty payouts; using single-output fallback"
            );
            return Some(AllocateTokenContext {
                miner_address: miner_address.clone(),
                coinbase_outputs: solo_fallback_outputs(&miner_address, self.network),
            });
        }

        // Convert each PayoutEntry to a DynamicOutput, placing the exact
        // per-output sats the distributor already computed verbatim — no
        // percent re-derivation (see `payouts_to_dynamic_outputs`).
        let outputs = payouts_to_dynamic_outputs(&payouts);
        match encode_coinbase_outputs(self.network, &outputs) {
            Ok(bytes) => Some(AllocateTokenContext {
                miner_address,
                coinbase_outputs: bytes,
            }),
            Err(err) => {
                warn!(
                    %err,
                    user_identifier, "JDP allocate: encode_coinbase_outputs failed; falling back"
                );
                Some(AllocateTokenContext {
                    miner_address: AddressId::new(
                        payouts
                            .first()
                            .map(|p| p.address.clone())
                            .unwrap_or_default(),
                    )
                    .ok()?,
                    coinbase_outputs: vec![0u8],
                })
            }
        }
    }
}

/// Translate `PayoutEntry { address, sats }` to `DynamicOutput { address, sats }`
/// — the exact per-output sats are placed verbatim. Dust
/// (`< DUST_LIMIT_SATS = 546`) entries are dropped — the production PPLNS /
/// Group-Solo distributors handle this upstream but defensive in case a manual /
/// test fixture leaks a sub-dust entry through.
fn payouts_to_dynamic_outputs(payouts: &[PayoutEntry]) -> Vec<DynamicOutput> {
    let mut out = Vec::with_capacity(payouts.len());
    for entry in payouts {
        // Exact sats from the distributor — placed verbatim, never re-derived.
        let raw_sats = entry.sats as i64;
        if raw_sats < 546 {
            continue;
        }
        let address = match AddressId::new(entry.address.clone()) {
            Ok(a) => a,
            Err(_) => continue,
        };
        out.push(DynamicOutput {
            address,
            sats: Sats(raw_sats),
        });
    }
    out
}

/// Last-ditch fallback: a single 100%-to-miner output, no fee
/// allocation. Used when the PayoutResolver returns nothing
/// (shouldn't happen in production — but ensures the JDC always
/// receives a parseable token rather than an `AllocateMiningJobToken.Error`).
fn solo_fallback_outputs(miner: &AddressId, network: BitcoinNetwork) -> Vec<u8> {
    let outputs = vec![DynamicOutput {
        address: miner.clone(),
        sats: Sats(312_500_000),
    }];
    encode_coinbase_outputs(network, &outputs).unwrap_or(vec![0u8])
}

// ─── 2. TdpTemplateTxProvider ────────────────────────────────────

/// Production tx-provider: pulls the newest template's
/// `wtxid → raw_witness_tx` map from the long-lived
/// [`TemplateTxCache`] when present. The cache is gated on
/// `[sv2].jdp_orphan_submitblock = true` (see `main.rs`); in default
/// mode (orphan-resubmit off) the cache is `None` and snapshot returns
/// an empty map — the JDC then fills in via the standard
/// `ProvideMissingTransactions` round-trip.
///
/// A cache-miss with the cache present means either the cache hasn't
/// been warmed yet (first few seconds of pool boot) or the JDC
/// declared against a template older than the FIFO — either way the
/// JDC handles it by sending the full tx-set via
/// `ProvideMissingTransactions`.
pub(crate) struct TdpTemplateTxProvider {
    cache: Option<Arc<TemplateTxCache>>,
}

#[async_trait]
impl TemplateTxProvider for TdpTemplateTxProvider {
    async fn snapshot(&self) -> HashMap<[u8; 32], Vec<u8>> {
        match &self.cache {
            Some(cache) => cache.current_template_txs().unwrap_or_default(),
            None => HashMap::new(),
        }
    }
}

// ─── 3. TdpCurrentPrevHashProvider ───────────────────────────────

pub(crate) struct TdpCurrentPrevHashProvider {
    tdp: TdpHandle,
}

#[async_trait]
impl CurrentPrevHashProvider for TdpCurrentPrevHashProvider {
    async fn current_prev_hash(&self) -> Option<[u8; 32]> {
        self.tdp
            .current_snapshot()
            .set_new_prev_hash
            .map(|s| s.prev_hash)
    }
}

// ─── 4. ProductionJdpBlockSink ───────────────────────────────────

/// Where a found block goes for the pool's own anti-orphan resubmit.
///
/// A seam, so the tests can pin that a candidate reaches propagation whatever
/// the ledger decides about it — the failure this guards against is a change
/// to the booking half quietly taking block propagation down with it.
#[async_trait]
pub(crate) trait BlockPropagator: Send + Sync {
    async fn propagate(&self, miner_address: &AddressId, block: &Block);
}

#[async_trait]
impl BlockPropagator for BitcoinRpc {
    async fn propagate(&self, miner_address: &AddressId, block: &Block) {
        let block_hex = serialize_hex(block);
        let block_bytes = block_hex.len() / 2;
        info!(
            block_bytes,
            tx_count = block.txdata.len(),
            "JDP submit: dispatching submitblock RPC"
        );
        match self.submit_block(block_hex).await {
            Ok(None) => info!(
                miner = miner_address.as_str(),
                "JDP block accepted by bitcoin-core (orphan-protection redundancy)"
            ),
            Ok(Some(reason)) => warn!(
                miner = miner_address.as_str(),
                reason, "JDP block rejected by bitcoin-core"
            ),
            Err(err) => warn!(
                %err,
                miner = miner_address.as_str(),
                "JDP submitblock RPC failed (best-effort; JDC also submits via TDP)"
            ),
        }
    }
}

/// Shortest byte count that can hold a transaction's version + locktime, which
/// is what the witness-form assembly indexes against.
const MIN_COINBASE_LEN: usize = 8;

/// How far a JD-client's reported payout value may sit from what the pool's own
/// template says, in either direction, and still be booked automatically.
///
/// Separate from the `revenue-too-large` ceiling on purpose. That one decides
/// whether a coinbase gets built at all and is generous, because a client
/// whose mempool is fuller than the pool's really does pay more and refusing
/// it would break honest mining. This one decides whether the pool writes a
/// number into its ledger, where being generous means crediting miners for
/// money the block never paid — and in a non-custodial pool that credit is
/// what the next block's coinbase pays out.
///
/// The margin covers ordinary mempool divergence between two nodes; anything
/// beyond it is served but not vouched for, and the chain→ledger check reports
/// the block if it turns out to have been real.
const BOOKABLE_DIVERGENCE_DIVISOR: u64 = 4;

/// The most a client may report and still be booked.
fn bookable_ceiling(pool_template_value: u64) -> u64 {
    pool_template_value.saturating_add(pool_template_value / BOOKABLE_DIVERGENCE_DIVISOR)
}

/// The least it may report and still be booked.
///
/// A ceiling alone leaves the gate open in the direction that costs the most.
/// `available_payout_value` is what the client hands the pool to distribute, and
/// it is free to keep the rest — so an understated value is not malformed, it is
/// a client keeping more. But booking one settles the whole PPLNS window or group
/// round against it: report a few thousand sats for a block paying 3.125 BTC and
/// the round is closed out, balances written and reset, for pocket change. The
/// coinbase is still served; only the promise is withheld.
fn bookable_floor(pool_template_value: u64) -> u64 {
    pool_template_value.saturating_sub(pool_template_value / BOOKABLE_DIVERGENCE_DIVISOR)
}

/// Is the client's reported payout value close enough to the pool's own template
/// to be written into the ledger?
fn reported_value_is_bookable(available_payout_value: u64, pool_template_value: u64) -> bool {
    available_payout_value >= bookable_floor(pool_template_value)
        && available_payout_value <= bookable_ceiling(pool_template_value)
}

/// What the pool's own node says the next block must satisfy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChainDemands {
    /// The tip a new block must build on.
    pub prev_hash: [u8; 32],
    /// The target that block's header hash must not exceed, as bitcoin-core
    /// reported it in `SetNewPrevHash`: an SV2 U256, so **little-endian** —
    /// the same form [`bp_share::Target::from_le_bytes`] takes and every other
    /// reader of this field in the tree assumes.
    pub target: [u8; 32],
}

/// Why a pushed solution may not be booked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotEvidence {
    /// The pool has no tip of its own to check against yet.
    NoChainView,
    /// Built on a different tip than the pool's. Either the JDC is on another
    /// chain or the solution is stale — in both cases the declared job this
    /// was matched against is not the job that was solved.
    WrongTip,
    /// The header does not meet the network target: no work was done.
    InsufficientWork,
}

/// Is this pushed solution *evidence* that a block was found, or merely the
/// JD-client's claim that one was?
///
/// The distinction decides whether the pool may write to its payout ledger. A
/// JDC owns its coinbase and sends whatever bytes it likes; the only thing it
/// cannot fabricate is a header that hashes below the network target. So that
/// is what gets checked — against the target the pool's OWN node published for
/// the next block, never the `n_bits` the sender supplied, which it chooses.
///
/// The tip must match too. A solution for a different tip cannot have been
/// mined on the job it was matched to, and booking that job's distribution
/// would credit the wrong miners.
pub(crate) fn solution_is_evidence(
    header: &Header,
    demands: Option<ChainDemands>,
) -> Result<(), NotEvidence> {
    let Some(demands) = demands else {
        return Err(NotEvidence::NoChainView);
    };
    if header.prev_blockhash.to_byte_array() != demands.prev_hash {
        return Err(NotEvidence::WrongTip);
    }
    // Both operands are little-endian U256: the target is copied verbatim out
    // of the `SetNewPrevHash` wire field, and `block_hash().to_byte_array()` is
    // rust-bitcoin's internal little-endian form. So they go into the numeric
    // compare unreversed.
    //
    // Reading either as big-endian is not a near-miss, it inverts the test. A
    // real target is small, so its little-endian bytes START with the zero
    // bytes; a winning hash reversed to big-endian starts with fewer. Compared
    // the wrong way round, every genuine block looks like insufficient work and
    // nothing is ever booked.
    if !bp_share::Target::from_le_bytes(demands.target)
        .is_met_by_le(&header.block_hash().to_byte_array())
    {
        return Err(NotEvidence::InsufficientWork);
    }
    Ok(())
}

/// The pool's view of what the next block must satisfy.
///
/// A seam, so the decision below can be tested without a live template feed —
/// the logic that decides whether money moves is worth exercising directly.
pub(crate) trait ChainView: Send + Sync {
    fn demands(&self) -> Option<ChainDemands>;
}

impl ChainView for TdpHandle {
    fn demands(&self) -> Option<ChainDemands> {
        let prev = self.current_snapshot().set_new_prev_hash?;
        Some(ChainDemands {
            prev_hash: prev.prev_hash,
            target: prev.target,
        })
    }
}

/// Books a block the pool did not build the coinbase for.
///
/// Returns whether the booking got as far as the ledger fan-out. A `false` means
/// nothing was written and the caller must not record the block as handled —
/// otherwise the JD-client's retry, which is the only remaining chance to book
/// it in-process, gets discarded as a duplicate.
#[async_trait]
pub(crate) trait DeclaredBlockBooker: Send + Sync {
    async fn book(
        &self,
        miner_address: String,
        session_id: String,
        reward_sats: u64,
        block_hash: String,
        block_data: String,
        payouts_fingerprint: [u8; 32],
    ) -> bool;
}

#[async_trait]
impl DeclaredBlockBooker for crate::block_sink::TdpBlockSubmissionSink {
    async fn book(
        &self,
        miner_address: String,
        session_id: String,
        reward_sats: u64,
        block_hash: String,
        block_data: String,
        payouts_fingerprint: [u8; 32],
    ) -> bool {
        self.book_declared_block_found(
            miner_address,
            session_id,
            reward_sats,
            block_hash,
            block_data,
            payouts_fingerprint,
        )
        .await
    }
}

/// Reassemble the block a `PushSolution` describes: the JDC's coinbase plus
/// the transactions it declared, with the merkle root computed over them.
///
/// The expensive step on the block-found path: every declared transaction is
/// consensus-decoded and the merkle root computed over the whole set. Both
/// things that want the block — the orphan-protection resubmit and the ledger
/// booking, which needs the header to name the block — are served from one
/// call. Returns `None` when the JDC's bytes don't parse; the caller logs and
/// moves on, because the JDC submits through its own node regardless.
#[allow(clippy::too_many_arguments)]
fn assemble_declared_block(
    coinbase_raw: &[u8],
    transactions: &[Vec<u8>],
    prev_hash: [u8; 32],
    version: u32,
    ntime: u32,
    nonce: u32,
    n_bits: u32,
) -> Option<Block> {
    // These bytes come off the wire from the JDC. `assemble_witness_coinbase`
    // indexes from the tail (version + locktime), so anything shorter than
    // that would panic the connection task rather than be rejected.
    if coinbase_raw.len() < MIN_COINBASE_LEN {
        warn!(
            len = coinbase_raw.len(),
            "JDP block: declared coinbase is too short to be a transaction"
        );
        return None;
    }
    // Non-witness coinbase → witness form (BIP-141 marker + flag + reserved
    // witness value). Required for bitcoin-core to accept a SegWit block.
    let coinbase_witness_bytes = assemble_witness_coinbase(coinbase_raw);
    let coinbase_tx: Transaction =
        match Transaction::consensus_decode(&mut coinbase_witness_bytes.as_slice()) {
            Ok(t) => t,
            Err(err) => {
                warn!(%err, "JDP block: coinbase tx parse failed");
                return None;
            }
        };
    let mut txdata: Vec<Transaction> = Vec::with_capacity(1 + transactions.len());
    txdata.push(coinbase_tx);
    for (i, raw) in transactions.iter().enumerate() {
        match Transaction::consensus_decode(&mut raw.as_slice()) {
            Ok(tx) => txdata.push(tx),
            Err(err) => {
                warn!(%err, idx = i, "JDP block: tx parse failed");
                return None;
            }
        }
    }
    let mut header = Header {
        version: BlockVersion::from_consensus(version as i32),
        prev_blockhash: BlockHash::from_byte_array(prev_hash),
        merkle_root: TxMerkleNode::all_zeros(),
        time: ntime,
        bits: CompactTarget::from_consensus(n_bits),
        nonce,
    };
    let mut block = Block { header, txdata };
    let merkle_root = block.compute_merkle_root().unwrap_or_else(|| {
        warn!("JDP block: merkle root compute returned None (empty block?); using zero");
        TxMerkleNode::all_zeros()
    });
    header = block.header;
    header.merkle_root = merkle_root;
    block.header = header;
    Some(block)
}

/// The pool's end of a JDC-found block: reassemble it once, propagate it, book
/// it.
///
/// One sink rather than a chain of them, because both halves want the same
/// reassembled block and reassembly is the only expensive step. Each half has
/// its own switch and neither answers to the other's: the resubmit is
/// `[sv2].jdp_orphan_submitblock`, the booking is whether a ledger fan-out was
/// wired. The block was found either way.
pub(crate) struct ProductionJdpBlockSink {
    /// `Some` → the pool resubmits the block to its own node as anti-orphan
    /// redundancy. `None` → the JDC is the sole propagator.
    propagator: Option<Arc<dyn BlockPropagator>>,
    /// `Some` → a proven block is booked against the distribution its coinbase
    /// paid. `None` → no ledger fan-out on this deployment; report only.
    booker: Option<Arc<dyn DeclaredBlockBooker>>,
    /// The pool's own chain view. Booking is checked against this, never
    /// against anything the JD-client sent.
    chain: Arc<dyn ChainView>,
    /// Block hashes already booked by this process. A JDC may re-send a
    /// solution (reconnect, unseen ack) and the same block must not be booked
    /// twice. Bounded — only the newest few matter, a repeat arrives right
    /// after the original.
    booked: StdMutex<VecDeque<[u8; 32]>>,
}

/// How many recently-booked block hashes are remembered for the repeat check.
const BOOKED_MEMORY: usize = 16;

impl ProductionJdpBlockSink {
    /// Has this block already been booked? Read-only on purpose — see
    /// [`Self::remember_booked`].
    fn already_booked(&self, hash: &[u8; 32]) -> bool {
        self.booked
            .lock()
            .expect("booked-hash mutex")
            .contains(hash)
    }

    /// Record a block as booked. Called only once the booking actually reached
    /// the ledger fan-out, never on first sight of the hash: a booking can fail
    /// before writing anything (no height derivable, RPC down — most likely
    /// right after a block was found, when the node is busiest), and the
    /// JD-client's re-send is then the only chance left to get the row written.
    /// Marking on sight would answer that re-send with "already booked" and lose
    /// the payout to a manual reprocess.
    fn remember_booked(&self, hash: [u8; 32]) {
        let mut booked = self.booked.lock().expect("booked-hash mutex");
        if booked.contains(&hash) {
            return;
        }
        booked.push_back(hash);
        while booked.len() > BOOKED_MEMORY {
            booked.pop_front();
        }
    }

    /// Is this block proven, given what the chain demanded when the solution
    /// arrived?
    ///
    /// `WrongTip` gets a second look, because by now the pool's own node may
    /// have connected this very block — from the resubmit a few lines up, or
    /// from p2p because the JD-client's own node published it first. A block
    /// its own node holds as the tip has passed every consensus rule there is,
    /// which is a stronger proof than the target compare, not a weaker one. On
    /// a busy tip that is the ordinary case, so treating it as the wrong tip
    /// would refuse to book almost every real block.
    fn block_is_proven(
        &self,
        block: &Block,
        demands_on_arrival: Option<ChainDemands>,
    ) -> Result<(), NotEvidence> {
        match solution_is_evidence(&block.header, demands_on_arrival) {
            Err(NotEvidence::WrongTip) => {
                let our_tip = self.chain.demands().map(|d| d.prev_hash);
                if our_tip == Some(block.header.block_hash().to_byte_array()) {
                    return Ok(());
                }
                Err(NotEvidence::WrongTip)
            }
            other => other,
        }
    }

    /// Book only what the chain can vouch for.
    async fn book_if_evidence(
        &self,
        booker: &dyn DeclaredBlockBooker,
        miner_address: &AddressId,
        new_token: Token,
        block: &Block,
        booking: PayoutBooking,
        demands_on_arrival: Option<ChainDemands>,
    ) {
        if let Err(reason) = self.block_is_proven(block, demands_on_arrival) {
            warn!(
                miner = miner_address.as_str(),
                ?reason,
                "JDP block-found: not booked — the pushed solution is the client's claim, not \
                 proof a block was found"
            );
            return;
        }
        let hash = block.header.block_hash();
        if self.already_booked(&hash.to_byte_array()) {
            info!(
                miner = miner_address.as_str(),
                block_hash = %hash,
                "JDP block-found: already booked; ignoring the repeat"
            );
            return;
        }
        let booked = booker
            .book(
                miner_address.as_str().to_string(),
                hex::encode(new_token.0),
                booking.block_reward_sats,
                hash.to_string(),
                serialize_hex(&block.header),
                booking.payouts_fingerprint,
            )
            .await;
        if booked {
            self.remember_booked(hash.to_byte_array());
        } else {
            warn!(
                miner = miner_address.as_str(),
                block_hash = %hash,
                "JDP block-found: the booking wrote nothing — leaving the block un-recorded so a \
                 re-sent solution can still book it"
            );
        }
    }
}

#[async_trait]
impl JdpBlockSubmissionSink for ProductionJdpBlockSink {
    async fn submit_block_candidate(
        &self,
        miner_address: AddressId,
        new_token: Token,
        booking: Option<PayoutBooking>,
        coinbase_raw: Vec<u8>,
        transactions: Vec<Vec<u8>>,
        prev_hash: [u8; 32],
        version: u32,
        ntime: u32,
        nonce: u32,
        n_bits: u32,
    ) {
        info!(
            miner = miner_address.as_str(),
            token = ?new_token,
            tx_count = transactions.len(),
            coinbase_len = coinbase_raw.len(),
            bookable = booking.is_some(),
            pool_resubmit = self.propagator.is_some(),
            "JDP block-candidate received"
        );
        log_booking_status(&miner_address, booking);

        // Nothing downstream wants the block, so don't pay to build it: a
        // deployment with the resubmit off and no ledger wired is the JDC
        // propagating alone, and reassembly would be work for a log line.
        let to_book = booking.zip(self.booker.as_ref());
        if self.propagator.is_none() && to_book.is_none() {
            return;
        }
        let Some(block) = assemble_declared_block(
            &coinbase_raw,
            &transactions,
            prev_hash,
            version,
            ntime,
            nonce,
            n_bits,
        ) else {
            warn!(
                miner = miner_address.as_str(),
                "JDP block: reassembly failed — the block can be neither resubmitted nor booked"
            );
            return;
        };
        // What the chain demanded when this solution arrived. Read BEFORE
        // propagating, because the resubmit below advances our own node's tip
        // and the booking would then be judged against the block it is about
        // to book — a reading in which every found block is on the wrong tip.
        // Costs one mutex-guarded clone, and only when there is a booking.
        let demands_on_arrival = to_book.is_some().then(|| self.chain.demands()).flatten();

        // Propagation first, and nothing that only the ledger needs before it.
        // The resubmit exists to shrink the orphan window; the booking changes
        // nothing about how fast the block travels, so it waits.
        if let Some(propagator) = &self.propagator {
            propagator.propagate(&miner_address, &block).await;
        }
        if let Some((booking, booker)) = to_book {
            self.book_if_evidence(
                booker.as_ref(),
                &miner_address,
                new_token,
                &block,
                booking,
                demands_on_arrival,
            )
            .await;
        }
    }
}

// ─── 5. ProductionPayoutOutputsResolver (ext 0x0003) ────────────────

/// Production resolver for ext 0x0003 `RequestPayoutOutputs` —
/// PPLNS / Group-Solo non-custodial multi-output coinbases.
///
/// The JDC sends `RequestPayoutOutputs(token, available_payout_value)`
/// per declared job; we re-route through the same
/// [`ProductionPayoutResolver`] that drives the SV1/SV2-mining +
/// AllocateMiningJobToken paths. Difference vs. AllocateMiningJobToken:
/// the resolver is invoked **per job** with the JDC-reported
/// `available_payout_value`, so PPLNS distributions reflect the actual
/// block reward (no estimate drift; see spec §1).
///
/// **Solo mode**: when the extension is NOT negotiated, the
/// AllocateMiningJobToken single-output path applies unchanged. We
/// still service ext 0x0003 requests in solo mode (the JDC may
/// negotiate the extension regardless of pool's payout model) — we
/// emit a single 100 %-to-miner output, equivalent to what the JDC
/// would derive from the AllocateMiningJobToken fallback.
///
/// **No stale check here**: spec §4 makes freshness a *validator-side*
/// property — the JDS rejects a stale/superseded payout set at
/// declare-time (single-use tracking in `PayoutOutputsTracker`), not at
/// request-time. There is no `prev_hash` on the wire to compare.
///
/// **Exact-sum (spec §2.2)**: the returned set MUST sum to exactly
/// `available_payout_value`. We fold the floor-rounding + sub-dust
/// residual into the largest output via [`fold_residual_to_exact_sum`].
///
/// **Revenue plausibility** (internal guard): we use the current
/// template's `coinbase_tx_value_remaining` as the upper bound + a 2×
/// tolerance for mempool fee spikes. Higher values trigger
/// `revenue-too-large`.
pub(crate) struct ProductionPayoutOutputsResolver {
    payout_resolver: Arc<ProductionPayoutResolver>,
    tdp: TdpHandle,
    network: BitcoinNetwork,
}

#[async_trait]
impl PayoutOutputsResolver for ProductionPayoutOutputsResolver {
    async fn resolve_payout_outputs(
        &self,
        miner_address: &AddressId,
        committed_outputs: &[u8],
        available_payout_value: u64,
        request_id: u32,
    ) -> PayoutOutputsResolution {
        use bp_stratum_v2::extensions::payout_outputs_error_codes;

        // ── Revenue plausibility (internal guard) ───────────────────
        //
        // ONE snapshot for both gates below. TDP rotates it continuously (every
        // tip, and on mempool growth), so two reads can hand the serve gate and
        // the bookable band different templates — and then a request can pass
        // the first against a template the second no longer holds.
        let pool_template_value = self
            .tdp
            .current_snapshot()
            .new_template
            .as_ref()
            .map(|t| t.coinbase_tx_value_remaining);
        if let Some(template_value) = pool_template_value {
            // 2× tolerance for mempool fee variance; rejects clearly
            // implausible (>2× current template value).
            let ceiling = template_value.saturating_mul(2);
            if available_payout_value > ceiling {
                warn!(
                    request_id,
                    address = miner_address.as_str(),
                    available_payout_value,
                    ceiling,
                    "ext 0x0003: available_payout_value exceeds 2× current-template ceiling"
                );
                return PayoutOutputsResolution::Error {
                    request_id,
                    error_code: payout_outputs_error_codes::REVENUE_TOO_LARGE.to_string(),
                };
            }
        }

        // ── Compute the FRESH per-job distribution (spec §1, §5) ──────
        //
        // The accuracy win of ext 0x0003 is computing the output set per
        // job from current pool state and the JDC-reported
        // `available_payout_value` — recipients AND amounts both reflect
        // the moment of the request, not the token-time estimate.
        let (payouts, pool_can_book) = self
            .payout_resolver
            .resolve_payouts_reporting_source(miner_address, available_payout_value)
            .await;
        if payouts.is_empty() {
            warn!(
                request_id,
                address = miner_address.as_str(),
                "ext 0x0003: PayoutResolver returned empty payouts — internal error"
            );
            return PayoutOutputsResolution::Error {
                request_id,
                error_code: payout_outputs_error_codes::INTERNAL.to_string(),
            };
        }
        // Σ MUST equal available_payout_value (spec §2.2): fold the
        // floor-rounding + dropped-sub-dust residual into the largest
        // kept output. An empty result means everything was sub-dust —
        // we can't build a set summing to a positive value.
        // The pool's own accounting identity for this distribution — the key
        // its snapshot was just stored under. Computed from the resolver's
        // list, before the wire lowering below can touch it.
        let payouts_fingerprint =
            bp_mining_job::payouts_fingerprint(available_payout_value, &payouts);
        let mut outputs = payouts_to_dynamic_outputs(&payouts);
        if outputs.is_empty() {
            warn!(
                request_id,
                address = miner_address.as_str(),
                "ext 0x0003: every payout was sub-dust — cannot construct a valid output set"
            );
            return PayoutOutputsResolution::Error {
                request_id,
                error_code: payout_outputs_error_codes::INTERNAL.to_string(),
            };
        }
        fold_residual_to_exact_sum(&mut outputs, available_payout_value as i64);
        // Only vouch for booking when the set going out is the distribution
        // that was snapshotted. The lowering drops sub-dust entries and the
        // fold moves the residual onto the largest output; either would make
        // the block pay something other than what the snapshot records, and
        // booking that would be the drift this whole mechanism exists to
        // remove. Both are no-ops while the distributor consumes the whole
        // reward and its floor is the dust limit — if that ever stops holding,
        // the block is reported and left for an operator instead.
        // A fallback list has no distribution snapshot behind it — vouching for
        // one would send an operator chasing a fingerprint that resolves to
        // nothing. The coinbase is still correct and still goes out; it just
        // cannot be booked automatically.
        // The reward that goes into the ledger is a number the JD-client
        // reported. The guard above keeps a wildly wrong one from producing a
        // coinbase at all, but its tolerance is deliberately generous — a
        // client with a fuller mempool legitimately pays more than the pool's
        // own template says. Booking cannot be that generous: an overstated
        // value makes the pool credit miners for money the block never paid,
        // and they are paid that credit out of the NEXT block, which is real.
        // So the promise is withheld outside a narrow band even where the
        // coinbase is still served.
        let value_is_bookable = match pool_template_value {
            Some(pool_value) => {
                let ok = reported_value_is_bookable(available_payout_value, pool_value);
                if !ok {
                    warn!(
                        request_id,
                        address = miner_address.as_str(),
                        available_payout_value,
                        pool_template_value = pool_value,
                        bookable_floor = bookable_floor(pool_value),
                        bookable_ceiling = bookable_ceiling(pool_value),
                        "ext 0x0003: reported payout value sits outside the band the pool's own \
                         template can account for — the coinbase still goes out, but a block \
                         found on it will not be booked automatically"
                    );
                }
                ok
            }
            // No template of our own to compare against — no basis to promise.
            // Said as its own case: claiming the value was out of band would
            // name a comparison that never happened, and `tracing` drops a
            // `None` field entirely, so the line would not even show that the
            // template was what was missing.
            None => {
                warn!(
                    request_id,
                    address = miner_address.as_str(),
                    available_payout_value,
                    "ext 0x0003: the pool has no template of its own yet, so the reported payout \
                     value cannot be checked against anything — the coinbase still goes out, but \
                     a block found on it will not be booked automatically"
                );
                false
            }
        };
        if !pool_can_book {
            warn!(
                request_id,
                address = miner_address.as_str(),
                "ext 0x0003: this payout set is not one the pool could book against — the list \
                 did not come from the engine that would have to resolve it, or that engine's \
                 snapshot did not land — a block found on it will be reported but not booked"
            );
        }
        // Each reason warns for itself above, so this arm speaks only for the
        // one that has no other voice. Blaming the lowering for all three sent
        // an operator to the dust floor and the residual fold when the actual
        // cause was the value band or a missing engine.
        let outputs_still_match = outputs_match_payouts(&outputs, &payouts);
        if !outputs_still_match {
            warn!(
                request_id,
                address = miner_address.as_str(),
                "ext 0x0003: issued output set differs from the distribution it came from \
                 (sub-dust drop or residual fold) — a block found on it will be reported \
                 but not booked"
            );
        }
        let booking = if pool_can_book && value_is_bookable && outputs_still_match {
            Some(PayoutBooking {
                payouts_fingerprint,
                block_reward_sats: available_payout_value,
            })
        } else {
            None
        };
        let bytes = match encode_coinbase_outputs(self.network, &outputs) {
            Ok(b) => b,
            Err(err) => {
                warn!(
                    %err,
                    request_id,
                    address = miner_address.as_str(),
                    "ext 0x0003: encode_coinbase_outputs failed"
                );
                return PayoutOutputsResolution::Error {
                    request_id,
                    error_code: payout_outputs_error_codes::INTERNAL.to_string(),
                };
            }
        };

        // ── Size guard against the token's reserved coinbase space (§6) ──
        //
        // The JDC sized its Template-Provider `coinbase_output_max_additional_size`
        // reservation from the serialized size of this token's
        // `AllocateMiningJobToken.Success.coinbase_tx_outputs` (= `committed_outputs`)
        // and cannot grow it mid-job. Normally the fresh set fits — per-job
        // `available_payout_value` ≤ the token-time block-reward estimate, so it
        // has ≤ recipients. It exceeds only when the payout window grew (or the
        // coinbase budget was raised) since the token was issued; then we
        // return `coinbase-size-budget-exceeded` so the JDC obtains a larger
        // token rather than building a coinbase that overflows its reservation.
        if !coinbase_outputs_fit_reservation(&bytes, committed_outputs) {
            warn!(
                request_id,
                address = miner_address.as_str(),
                fresh_bytes = bytes.len(),
                reserved_bytes = committed_outputs.len(),
                "ext 0x0003: per-job set outgrew the token's reserved coinbase size"
            );
            return PayoutOutputsResolution::Error {
                request_id,
                error_code: payout_outputs_error_codes::COINBASE_SIZE_BUDGET_EXCEEDED.to_string(),
            };
        }

        PayoutOutputsResolution::Success {
            request_id,
            outputs: bytes,
            booking,
        }
    }
}

/// Report what the pool can say about a JDC-found block's payouts.
///
/// The distinction it draws is the one that decides whether anything is
/// booked: a block whose declared coinbase was proven to pay the pool's issued
/// set can be booked from that distribution, while one without that proof must
/// not be booked from anything.
fn log_booking_status(miner_address: &AddressId, booking: Option<PayoutBooking>) {
    match booking {
        Some(b) => info!(
            miner = miner_address.as_str(),
            block_reward_sats = b.block_reward_sats,
            fingerprint = %hex::encode(b.payouts_fingerprint),
            "JDP block-found: coinbase proven to pay the pool's issued payout set"
        ),
        None => warn!(
            miner = miner_address.as_str(),
            "JDP block-found: no proof this coinbase pays a pool distribution \
             (base-protocol declaration, or the issued set was altered) — NOT bookable"
        ),
    }
}

/// `true` when the wire output set is entry-for-entry the distribution it was
/// lowered from — same order, same addresses, same sats.
///
/// The lowering may drop sub-dust entries and the residual fold may move sats
/// onto the largest output. Either makes the block pay something the pool's
/// snapshot does not record, so it must not be booked.
fn outputs_match_payouts(outputs: &[DynamicOutput], payouts: &[PayoutEntry]) -> bool {
    outputs.len() == payouts.len()
        && outputs.iter().zip(payouts).all(|(out, p)| {
            out.address.as_str() == p.address && out.sats.to_i64().max(0) as u64 == p.sats
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The JDC's bytes are untrusted input; garbage must not panic or produce
    /// a block, it must decline so the caller reports instead of booking.
    #[test]
    fn assemble_declared_block_declines_unparsable_bytes() {
        assert!(assemble_declared_block(
            &[0xFF, 0xFF, 0xFF],
            &[],
            [0u8; 32],
            0x2000_0000,
            1_700_000_000,
            42,
            0x1d00_ffff,
        )
        .is_none());
    }

    /// A well-formed coinbase reassembles, and the header it yields is what
    /// names the block for the ledger — so the merkle root has to be computed,
    /// not left at zero.
    #[test]
    fn assemble_declared_block_computes_the_merkle_root() {
        use bitcoin::absolute::LockTime;
        use bitcoin::consensus::Encodable;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let coinbase = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x51, 0x00, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let mut raw = Vec::new();
        coinbase
            .consensus_encode(&mut raw)
            .expect("encode coinbase");

        let block = assemble_declared_block(
            &raw,
            &[],
            [0xABu8; 32],
            0x2000_0000,
            1_700_000_000,
            42,
            0x1d00_ffff,
        )
        .expect("a well-formed coinbase must reassemble");
        assert_ne!(
            block.header.merkle_root,
            TxMerkleNode::all_zeros(),
            "an uncomputed merkle root would name the wrong block"
        );
        assert_eq!(block.txdata.len(), 1);
    }

    /// A JD-client may re-send a solution (reconnect, an ack it never saw).
    /// The same block must be booked once — the ledger it writes into is not
    /// idempotent across differing heights.
    ///
    /// Driven through the real sink's own bookkeeping. An earlier version of
    /// this test re-implemented that bookkeeping as a local closure, so deleting
    /// the production code left it green.
    #[tokio::test]
    async fn a_repeated_block_is_booked_only_once() {
        let sink = sink_with_halves(None, Some(Arc::new(RecordingBooker::default())), None);
        assert!(!sink.already_booked(&[1u8; 32]), "first sighting");
        sink.remember_booked([1u8; 32]);
        assert!(sink.already_booked(&[1u8; 32]), "the same block again");
        assert!(!sink.already_booked(&[2u8; 32]), "a different block");

        // Recording the same hash twice must not consume two slots, or the
        // bound would evict on repeats instead of on new blocks.
        sink.remember_booked([1u8; 32]);

        // The memory is bounded, so an old hash eventually ages out rather
        // than growing without limit on a long-lived connection.
        for i in 0..BOOKED_MEMORY as u8 {
            sink.remember_booked([100 + i; 32]);
        }
        assert!(
            !sink.already_booked(&[1u8; 32]),
            "past the bound the oldest is forgotten — bounded memory is the trade"
        );
    }

    /// The one job of this function is surviving bytes a JD-client chose. A
    /// coinbase long enough to pass the length guard but malformed must be
    /// declined, not indexed into.
    #[test]
    fn assemble_declared_block_declines_a_malformed_but_long_coinbase() {
        let garbage = vec![0xFFu8; 64];
        assert!(assemble_declared_block(
            &garbage,
            &[],
            [0u8; 32],
            0x2000_0000,
            1_700_000_000,
            42,
            0x1d00_ffff,
        )
        .is_none());
    }

    /// A corrupt entry among the declared transactions must decline the whole
    /// block rather than assemble a partial one whose merkle root would name
    /// a block that does not exist.
    #[test]
    fn assemble_declared_block_declines_a_corrupt_transaction() {
        use bitcoin::absolute::LockTime;
        use bitcoin::consensus::Encodable;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let coinbase = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x51, 0x00, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let mut raw = Vec::new();
        coinbase.consensus_encode(&mut raw).expect("encode");
        assert!(assemble_declared_block(
            &raw,
            &[vec![0xFFu8; 40]],
            [0u8; 32],
            0x2000_0000,
            1_700_000_000,
            42,
            0x1d00_ffff,
        )
        .is_none());
    }

    /// The value the pool books is a number the client reported. Serving a
    /// coinbase may be generous about it; crediting miners may not, because
    /// that credit is paid out of the next real block.
    #[test]
    fn the_bookable_band_is_tighter_than_the_serve_ceiling() {
        let template = 312_500_000u64;
        // Ordinary mempool divergence between two nodes stays bookable.
        assert!(reported_value_is_bookable(
            template + template / 10,
            template
        ));
        assert!(reported_value_is_bookable(
            template - template / 10,
            template
        ));
        assert_eq!(bookable_ceiling(template), 390_625_000);
        // The serve ceiling is 2x; that is far outside what may be booked.
        assert!(
            template * 2 > bookable_ceiling(template),
            "a claim the coinbase path still tolerates must not be bookable"
        );
        // No overflow / underflow at absurd inputs.
        assert!(bookable_ceiling(u64::MAX) >= u64::MAX / 2);
        assert_eq!(bookable_floor(0), 0);
    }

    /// The band has to close in BOTH directions. An understated value is not a
    /// malformed one — the client keeps the rest — but booking it settles the
    /// whole PPLNS window or group round against that number. A few thousand
    /// sats reported for a block paying 3.125 BTC would close the round out for
    /// pocket change.
    #[test]
    fn an_understated_payout_value_is_not_bookable() {
        let template = 312_500_000u64;
        assert!(
            !reported_value_is_bookable(10_000, template),
            "a tip-sized report must not settle a whole round"
        );
        assert!(!reported_value_is_bookable(0, template));
        assert!(
            !reported_value_is_bookable(template / 2, template),
            "keeping half the block is legal, but it is not what the pool books"
        );
        // Just inside the floor stays bookable, so honest divergence is unaffected.
        assert!(reported_value_is_bookable(
            bookable_floor(template),
            template
        ));
        assert!(!reported_value_is_bookable(
            bookable_floor(template) - 1,
            template
        ));
    }

    // ── ProductionJdpBlockSink ──────────────────────────────────────

    #[derive(Default)]
    struct RecordingPropagator {
        propagated: StdMutex<Vec<BlockHash>>,
    }
    #[async_trait]
    impl BlockPropagator for RecordingPropagator {
        async fn propagate(&self, _: &AddressId, block: &Block) {
            self.propagated
                .lock()
                .unwrap()
                .push(block.header.block_hash());
        }
    }

    #[derive(Default)]
    struct RecordingBooker {
        booked: StdMutex<Vec<(u64, [u8; 32])>>,
        hashes: StdMutex<Vec<String>>,
        /// What the ledger reports back. `false` stands for the real booking
        /// paths that return without writing anything.
        wrote_nothing: bool,
    }
    impl RecordingBooker {
        fn that_writes_nothing() -> Self {
            RecordingBooker {
                wrote_nothing: true,
                ..Default::default()
            }
        }
    }
    #[async_trait]
    impl DeclaredBlockBooker for RecordingBooker {
        async fn book(
            &self,
            _: String,
            _: String,
            reward: u64,
            block_hash: String,
            _: String,
            fp: [u8; 32],
        ) -> bool {
            self.booked.lock().unwrap().push((reward, fp));
            self.hashes.lock().unwrap().push(block_hash);
            !self.wrote_nothing
        }
    }

    struct FixedChain(Option<ChainDemands>);
    impl ChainView for FixedChain {
        fn demands(&self) -> Option<ChainDemands> {
            self.0
        }
    }

    /// A chain whose tip can move, the way the real one does when a block is
    /// connected.
    #[derive(Clone)]
    struct MovingChain(Arc<StdMutex<Option<ChainDemands>>>);
    impl MovingChain {
        fn at(demands: ChainDemands) -> Self {
            MovingChain(Arc::new(StdMutex::new(Some(demands))))
        }
        fn move_to(&self, demands: ChainDemands) {
            *self.0.lock().unwrap() = Some(demands);
        }
    }
    impl ChainView for MovingChain {
        fn demands(&self) -> Option<ChainDemands> {
            *self.0.lock().unwrap()
        }
    }

    /// Stands in for the real resubmit, which advances our own node's tip as a
    /// side effect of connecting the block.
    struct PropagatorThatMovesTheTip {
        chain: MovingChain,
        to: ChainDemands,
    }
    #[async_trait]
    impl BlockPropagator for PropagatorThatMovesTheTip {
        async fn propagate(&self, _: &AddressId, _: &Block) {
            self.chain.move_to(self.to);
        }
    }

    /// The block `push` below reassembles, so a test can name it.
    fn pushed_block(nonce: u32) -> Block {
        assemble_declared_block(
            &coinbase_bytes(),
            &[],
            [0u8; 32],
            0x2000_0000,
            1_700_000_000,
            nonce,
            0x1d00_ffff,
        )
        .expect("fixture coinbase reassembles")
    }

    fn coinbase_bytes() -> Vec<u8> {
        use bitcoin::absolute::LockTime;
        use bitcoin::consensus::Encodable;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
        let tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x51, 0x00, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let mut raw = Vec::new();
        tx.consensus_encode(&mut raw).expect("encode");
        raw
    }

    /// A sink with whichever halves the test cares about wired up. Both are
    /// independently switchable in production, so both are here.
    fn sink_with_halves(
        propagator: Option<Arc<RecordingPropagator>>,
        booker: Option<Arc<RecordingBooker>>,
        chain: Option<ChainDemands>,
    ) -> ProductionJdpBlockSink {
        ProductionJdpBlockSink {
            propagator: propagator.map(|p| p as Arc<dyn BlockPropagator>),
            booker: booker.map(|b| b as Arc<dyn DeclaredBlockBooker>),
            chain: Arc::new(FixedChain(chain)),
            booked: StdMutex::new(VecDeque::new()),
        }
    }

    /// The fully-wired production shape: resubmit on, ledger wired.
    fn sink_with(
        chain: Option<ChainDemands>,
    ) -> (
        ProductionJdpBlockSink,
        Arc<RecordingPropagator>,
        Arc<RecordingBooker>,
    ) {
        let propagator = Arc::new(RecordingPropagator::default());
        let booker = Arc::new(RecordingBooker::default());
        (
            sink_with_halves(Some(propagator.clone()), Some(booker.clone()), chain),
            propagator,
            booker,
        )
    }

    async fn push(sink: &ProductionJdpBlockSink, booking: Option<PayoutBooking>, nonce: u32) {
        sink.submit_block_candidate(
            AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap(),
            Token([9u8; 16]),
            booking,
            coinbase_bytes(),
            vec![],
            [0u8; 32],
            0x2000_0000,
            1_700_000_000,
            nonce,
            0x1d00_ffff,
        )
        .await;
    }

    fn a_booking() -> PayoutBooking {
        PayoutBooking {
            payouts_fingerprint: [0x11; 32],
            block_reward_sats: 5_000_000_000,
        }
    }

    /// The resubmit is the pool's anti-orphan redundancy. It must happen for
    /// every candidate, whatever the ledger decides — dropping it would
    /// silently disable block propagation while bookings kept working.
    #[tokio::test]
    async fn the_block_always_reaches_the_resubmit_sink() {
        let easy = ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        };
        for (chain, booking) in [
            (Some(easy), Some(a_booking())),
            (Some(easy), None),
            (None, Some(a_booking())),
        ] {
            let (sink, propagator, _) = sink_with(chain);
            push(&sink, booking, 1).await;
            assert_eq!(propagator.propagated.lock().unwrap().len(), 1);
        }
    }

    /// The two halves share one reassembly but not one switch. A deployment
    /// with the resubmit off still books: the block was found either way, and
    /// `[sv2].jdp_orphan_submitblock` only says who propagates it.
    #[tokio::test]
    async fn booking_does_not_hinge_on_the_resubmit_switch() {
        let booker = Arc::new(RecordingBooker::default());
        let sink = sink_with_halves(
            None,
            Some(booker.clone()),
            Some(ChainDemands {
                prev_hash: [0u8; 32],
                target: [0xFFu8; 32],
            }),
        );
        push(&sink, Some(a_booking()), 1).await;
        assert_eq!(
            *booker.booked.lock().unwrap(),
            vec![(5_000_000_000, [0x11; 32])]
        );
    }

    /// And the reverse: with no ledger wired the block still gets propagated.
    /// The resubmit answers to nothing the ledger does.
    #[tokio::test]
    async fn propagation_does_not_hinge_on_a_wired_ledger() {
        let propagator = Arc::new(RecordingPropagator::default());
        let sink = sink_with_halves(
            Some(propagator.clone()),
            None,
            Some(ChainDemands {
                prev_hash: [0u8; 32],
                target: [0xFFu8; 32],
            }),
        );
        push(&sink, Some(a_booking()), 1).await;
        assert_eq!(propagator.propagated.lock().unwrap().len(), 1);
    }

    /// The pool's own resubmit advances the pool's own tip. Judging the booking
    /// against the tip read afterwards means judging it against the block it is
    /// about to book — under which no found block is ever on the right tip. The
    /// decision must rest on what the chain demanded when the solution arrived.
    #[tokio::test]
    async fn the_tip_is_judged_as_of_the_solutions_arrival() {
        let easy = ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        };
        // Where the tip lands after our submit: some other block entirely, so
        // re-reading it cannot rescue the check by the already-our-tip route.
        let moved_on = ChainDemands {
            prev_hash: [0x77u8; 32],
            target: [0xFFu8; 32],
        };
        let chain = MovingChain::at(easy);
        let booker = Arc::new(RecordingBooker::default());
        let sink = ProductionJdpBlockSink {
            propagator: Some(Arc::new(PropagatorThatMovesTheTip {
                chain: chain.clone(),
                to: moved_on,
            })),
            booker: Some(booker.clone()),
            chain: Arc::new(chain),
            booked: StdMutex::new(VecDeque::new()),
        };
        push(&sink, Some(a_booking()), 1).await;
        assert_eq!(
            booker.booked.lock().unwrap().len(),
            1,
            "the tip moved because we submitted the block — that must not un-book it"
        );
    }

    /// By booking time the pool's own node may already hold the found block as
    /// its tip: our resubmit connected it, or the JD-client's node published it
    /// first and we got it over p2p. A block our own node accepted has passed
    /// every consensus rule, which outranks our target compare — so it books.
    #[tokio::test]
    async fn a_block_our_node_already_holds_as_its_tip_is_proven() {
        // Hard enough that no target compare could pass: the proof can only
        // come from our node having accepted the block.
        let mut unreachable_target = [0u8; 32];
        unreachable_target[0] = 0x01;
        let booker = Arc::new(RecordingBooker::default());
        let sink = sink_with_halves(
            None,
            Some(booker.clone()),
            Some(ChainDemands {
                prev_hash: pushed_block(1).header.block_hash().to_byte_array(),
                target: unreachable_target,
            }),
        );
        push(&sink, Some(a_booking()), 1).await;
        assert_eq!(booker.booked.lock().unwrap().len(), 1);
    }

    /// A tip that is neither the one mined on nor the found block itself stays
    /// refused — the second look must not turn into a blanket pass.
    #[tokio::test]
    async fn a_foreign_tip_is_still_refused() {
        let booker = Arc::new(RecordingBooker::default());
        let sink = sink_with_halves(
            None,
            Some(booker.clone()),
            Some(ChainDemands {
                prev_hash: [0x99u8; 32],
                target: [0xFFu8; 32],
            }),
        );
        push(&sink, Some(a_booking()), 1).await;
        assert!(booker.booked.lock().unwrap().is_empty());
    }

    /// The block the ledger names must be the block that was propagated —
    /// one reassembly feeding both is what guarantees they cannot diverge.
    #[tokio::test]
    async fn the_booked_block_is_the_propagated_block() {
        let (sink, propagator, booker) = sink_with(Some(ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        }));
        push(&sink, Some(a_booking()), 1).await;
        let propagated = propagator.propagated.lock().unwrap()[0];
        assert_eq!(booker.hashes.lock().unwrap()[0], propagated.to_string());
    }

    /// Work on the pool's own tip is evidence, and gets booked with the
    /// distribution the declaration vouched for.
    #[tokio::test]
    async fn evidence_books_the_vouched_distribution() {
        let (sink, _, booker) = sink_with(Some(ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        }));
        push(&sink, Some(a_booking()), 1).await;
        assert_eq!(
            *booker.booked.lock().unwrap(),
            vec![(5_000_000_000, [0x11; 32])]
        );
    }

    /// A claim that did no work must not move money, however well-formed.
    #[tokio::test]
    async fn a_claim_without_work_books_nothing() {
        // Little-endian: index 0 is the least-significant byte, so this is the
        // number 1 — the hardest target there is.
        let mut hard = [0u8; 32];
        hard[0] = 0x01;
        let (sink, propagator, booker) = sink_with(Some(ChainDemands {
            prev_hash: [0u8; 32],
            target: hard,
        }));
        push(&sink, Some(a_booking()), 42).await;
        assert!(booker.booked.lock().unwrap().is_empty());
        assert_eq!(
            propagator.propagated.lock().unwrap().len(),
            1,
            "still propagated — bitcoin-core is the one to reject it"
        );
    }

    /// Nothing vouched for the distribution, so there is nothing to book even
    /// though the work is real.
    #[tokio::test]
    async fn work_without_a_vouched_distribution_books_nothing() {
        let (sink, _, booker) = sink_with(Some(ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        }));
        push(&sink, None, 1).await;
        assert!(booker.booked.lock().unwrap().is_empty());
    }

    /// A booking can return without writing anything — no height derivable, RPC
    /// down, which is likeliest in the seconds after a block was found. The
    /// JD-client's re-send is then the last chance to get the row written, so
    /// the block must not already be marked as handled.
    #[tokio::test]
    async fn a_booking_that_wrote_nothing_leaves_the_retry_open() {
        let booker = Arc::new(RecordingBooker::that_writes_nothing());
        let sink = sink_with_halves(
            None,
            Some(booker.clone()),
            Some(ChainDemands {
                prev_hash: [0u8; 32],
                target: [0xFFu8; 32],
            }),
        );
        push(&sink, Some(a_booking()), 1).await;
        push(&sink, Some(a_booking()), 1).await;
        assert_eq!(
            booker.booked.lock().unwrap().len(),
            2,
            "the re-send must reach the ledger again — the first attempt wrote nothing"
        );
    }

    /// The flip side: once a booking really did write, the repeat is dropped.
    /// Both properties come from the same bookkeeping, so both are pinned.
    #[tokio::test]
    async fn a_booking_that_wrote_suppresses_the_repeat() {
        let booker = Arc::new(RecordingBooker::default());
        let sink = sink_with_halves(
            None,
            Some(booker.clone()),
            Some(ChainDemands {
                prev_hash: [0u8; 32],
                target: [0xFFu8; 32],
            }),
        );
        push(&sink, Some(a_booking()), 1).await;
        push(&sink, Some(a_booking()), 1).await;
        assert_eq!(booker.booked.lock().unwrap().len(), 1);
    }

    /// A re-sent solution is the same block; booking it twice would credit
    /// the same payout twice.
    #[tokio::test]
    async fn the_same_block_pushed_twice_books_once() {
        let (sink, propagator, booker) = sink_with(Some(ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        }));
        push(&sink, Some(a_booking()), 1).await;
        push(&sink, Some(a_booking()), 1).await;
        assert_eq!(booker.booked.lock().unwrap().len(), 1);
        assert_eq!(
            propagator.propagated.lock().unwrap().len(),
            2,
            "propagation is not deduped — only the ledger write is"
        );
    }

    fn header_with(prev: [u8; 32], nonce: u32) -> Header {
        Header {
            version: BlockVersion::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::from_byte_array(prev),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x1d00_ffff),
            nonce,
        }
    }

    /// Without a chain view of its own the pool has nothing to check against,
    /// so it must not book — an unverified claim is not evidence.
    #[test]
    fn no_chain_view_is_not_evidence() {
        assert_eq!(
            solution_is_evidence(&header_with([0u8; 32], 0), None),
            Err(NotEvidence::NoChainView)
        );
    }

    /// A solution for another tip cannot have been mined on the job it was
    /// matched to; booking that job's distribution would credit the wrong
    /// miners.
    #[test]
    fn a_solution_for_another_tip_is_not_evidence() {
        let demands = ChainDemands {
            prev_hash: [0xAAu8; 32],
            target: [0xFFu8; 32],
        };
        assert_eq!(
            solution_is_evidence(&header_with([0xBBu8; 32], 0), Some(demands)),
            Err(NotEvidence::WrongTip)
        );
    }

    /// The whole point: a header that did not meet the network target is a
    /// claim anybody can send at no cost.
    #[test]
    fn a_header_that_did_no_work_is_not_evidence() {
        let demands = ChainDemands {
            prev_hash: [0u8; 32],
            // Little-endian, so the least-significant byte is index 0: this is
            // the number 1, the hardest target expressible. Nothing passes.
            target: {
                let mut t = [0u8; 32];
                t[0] = 0x01;
                t
            },
        };
        assert_eq!(
            solution_is_evidence(&header_with([0u8; 32], 12345), Some(demands)),
            Err(NotEvidence::InsufficientWork)
        );
    }

    /// The target the pool checks against is its own node's, never the
    /// `n_bits` in the message — the sender picks that one.
    #[test]
    fn the_senders_own_n_bits_cannot_lower_the_bar() {
        let mut header = header_with([0u8; 32], 999);
        // Claim the easiest possible difficulty.
        header.bits = CompactTarget::from_consensus(0x207f_ffff);
        let demands = ChainDemands {
            prev_hash: [0u8; 32],
            // The number 1 in little-endian form — see above.
            target: {
                let mut t = [0u8; 32];
                t[0] = 0x01;
                t
            },
        };
        assert_eq!(
            solution_is_evidence(&header, Some(demands)),
            Err(NotEvidence::InsufficientWork),
            "a self-declared easy target must not make a claim into evidence"
        );
    }

    /// The target is a little-endian U256, and this test refuses to pass under
    /// any other reading.
    ///
    /// Both earlier work tests used `[0xFF; 32]` and `0x…01`, which mean the
    /// same thing whichever end you start from — so they held while the compare
    /// was reversed and every real block was being rejected as workless. The
    /// fixture here is deliberately lopsided: read little-endian it is nearly
    /// the easiest target expressible, read big-endian it is 31 leading zero
    /// bytes and nearly the hardest. The assertions below prove both halves of
    /// that before checking the outcome, so the test cannot silently degrade
    /// into a byte-order-blind one again.
    #[test]
    fn the_target_is_read_little_endian() {
        let mut target = [0u8; 32];
        target[31] = 0xFF; // little-endian: the most-significant byte
        let header = header_with([0u8; 32], 7);
        let hash_le = header.block_hash().to_byte_array();

        assert!(
            hash_le[31] < 0xFF,
            "fixture must sit under the target when read little-endian"
        );
        let mut hash_be = hash_le;
        hash_be.reverse();
        assert!(
            hash_be > target,
            "and must fail when the same bytes are read big-endian — otherwise \
             this test proves nothing about the byte order"
        );

        assert_eq!(
            solution_is_evidence(
                &header,
                Some(ChainDemands {
                    prev_hash: [0u8; 32],
                    target,
                })
            ),
            Ok(()),
            "work below a little-endian target is evidence"
        );
    }

    /// A header on the right tip that meets the target is real work, and the
    /// one thing a client cannot fabricate.
    #[test]
    fn work_on_the_current_tip_is_evidence() {
        let demands = ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        };
        assert_eq!(
            solution_is_evidence(&header_with([0u8; 32], 7), Some(demands)),
            Ok(())
        );
    }

    fn entry(address: &str, sats: u64) -> PayoutEntry {
        PayoutEntry {
            address: address.to_string(),
            sats,
        }
    }

    /// The pool only vouches for a block when the set it hands the JDC IS the
    /// distribution its snapshot records.
    #[test]
    fn outputs_match_payouts_accepts_an_untouched_lowering() {
        let payouts = vec![
            entry("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", 5_000),
            entry("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", 7_000),
        ];
        let outputs = payouts_to_dynamic_outputs(&payouts);
        assert!(outputs_match_payouts(&outputs, &payouts));
    }

    /// A dropped sub-dust entry means the block pays fewer recipients than the
    /// snapshot books — no vouching.
    #[test]
    fn outputs_match_payouts_rejects_a_dropped_sub_dust_entry() {
        let payouts = vec![
            entry("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", 5_000),
            entry("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", 100),
        ];
        let outputs = payouts_to_dynamic_outputs(&payouts);
        assert!(
            !outputs_match_payouts(&outputs, &payouts),
            "the 100-sat entry is below the dust floor and gets dropped"
        );
    }

    /// A folded residual means the block pays one recipient more than the
    /// snapshot books — no vouching.
    #[test]
    fn outputs_match_payouts_rejects_a_folded_residual() {
        let payouts = vec![
            entry("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", 5_000),
            entry("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", 7_000),
        ];
        let mut outputs = payouts_to_dynamic_outputs(&payouts);
        // Distribution summed to 12_000; the JDC asked to pay out 12_500.
        fold_residual_to_exact_sum(&mut outputs, 12_500);
        assert!(!outputs_match_payouts(&outputs, &payouts));
    }

    #[test]
    fn payouts_to_dynamic_outputs_drops_sub_dust() {
        let payouts = vec![
            PayoutEntry {
                address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".into(),
                sats: 5_000, // > 546 dust limit → survives
            },
            PayoutEntry {
                address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".into(),
                sats: 4_999_995_000,
            },
        ];
        let outs = payouts_to_dynamic_outputs(&payouts);
        // 5_000 sats > 546 dust limit, so first entry survives.
        assert_eq!(outs.len(), 2);
        assert_eq!(outs[0].sats.to_i64(), 5_000);
    }

    #[test]
    fn payouts_to_dynamic_outputs_drops_truly_sub_dust() {
        let payouts = vec![PayoutEntry {
            address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".into(),
            sats: 500, // below the 546 dust limit → dropped
        }];
        let outs = payouts_to_dynamic_outputs(&payouts);
        assert!(outs.is_empty());
    }

    #[test]
    fn payouts_to_dynamic_outputs_skips_malformed_address_shape() {
        // `AddressId::new` rejects empty / >62-char / non-ASCII-graphic
        // shapes. Real address-parseability check happens downstream
        // in `encode_coinbase_outputs`. Test a too-long string here
        // (>62 chars) to verify the defensive filter at this layer.
        let payouts = vec![PayoutEntry {
            address: "x".repeat(70),
            sats: 5_000_000_000,
        }];
        let outs = payouts_to_dynamic_outputs(&payouts);
        assert!(outs.is_empty());
    }

    /// `solo_fallback_outputs` should produce non-empty bytes for a
    /// valid regtest address (covers the "PayoutResolver returned
    /// nothing" defensive path).
    #[test]
    fn solo_fallback_outputs_encodes_for_valid_address() {
        let addr = AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").expect("valid");
        let bytes = solo_fallback_outputs(&addr, BitcoinNetwork::Regtest);
        // Not the `[0x00]` empty-sentinel — actual encoded output.
        assert!(bytes.len() > 1);
    }
}
