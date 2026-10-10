// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production JDP hooks. [`ProductionJdpAllocateResolver`] gives ext 0x0003
//! empty token outputs, and the base protocol one 0-sat output only for a Solo
//! miner who is exactly that output; [`ProductionJdpBlockSink`] books a pushed
//! block only if its header proves work against the pool's target.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use bitcoin::block::{Block, Header, Version as BlockVersion};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use bitcoin::{BlockHash, Network as BitcoinNetwork, TxMerkleNode};
use bp_bitcoin::BitcoinRpc;
use bp_common::{AddressId, StreamKind};
use bp_stratum_v2::jdp::client::{
    parse_user_identifier_as_address, AllocateTokenContext, DeclarationRef, SolutionHeader,
};
use bp_stratum_v2::jdp::dynamic_outputs::{
    declared_coinbase_tx, designated_output_blob, CandidateBacking,
};
use bp_stratum_v2::jdp_server::{
    AllocateOutcome, ChainTipProvider, JdpAllocateResolver, JdpBlockSubmissionSink, JdpServerHooks,
    PayoutDistributionSource, TemplateTxProvider,
};
use bp_template_distribution::{TdpHandle, TemplateTxCache};
use tracing::{debug, info, warn};

use crate::block_sink::{decode_whole_tx, FoundBlockRecord};
use crate::payout_resolver::ProductionPayoutResolver;

/// Build the production `JdpServerHooks`. `orphan_submitblock_enabled` only
/// switches the pool-side resubmit; ledger booking runs either way.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_jdp_hooks(
    tdp: TdpHandle,
    bitcoin_rpc: BitcoinRpc,
    payout_resolver: Arc<ProductionPayoutResolver>,
    template_tx_cache: Option<Arc<TemplateTxCache>>,
    network: BitcoinNetwork,
    orphan_submitblock_enabled: bool,
    ledger_booker: Arc<crate::block_sink::TdpBlockSubmissionSink>,
    distribution_source: Arc<dyn PayoutDistributionSource>,
    settle: crate::settlement::SettlementSignal,
    job_validator: Option<Arc<dyn DeclaredJobValidator>>,
) -> JdpServerHooks {
    let propagator: Option<Arc<dyn BlockPropagator>> = if orphan_submitblock_enabled {
        info!(
            "jdp: pool-side block propagation ENABLED (submitblock RPC) — \
             the pool's half of the SV2 JDP/PushSolution redundancy"
        );
        Some(Arc::new(bitcoin_rpc))
    } else {
        info!(
            "jdp: pool-side block propagation DISABLED \
             (`[sv2].jdp_orphan_submitblock = false`) — the JDC is the sole \
             propagator, so the pool does not do what SV2 JDP/PushSolution asks of a JDS"
        );
        None
    };
    let block_sink: Arc<dyn JdpBlockSubmissionSink> = Arc::new(ProductionJdpBlockSink {
        propagator,
        booker: ledger_booker,
        chain: Arc::new(tdp.clone()),
        booked: StdMutex::new(VecDeque::new()),
        network,
        settle,
    });
    JdpServerHooks {
        allocate_resolver: Arc::new(ProductionJdpAllocateResolver {
            payout_resolver: payout_resolver as Arc<dyn bp_stratum_v2::hooks::PayoutResolver>,
            chain: Arc::new(tdp.clone()),
            network,
        }),
        template_tx_provider: Arc::new(TdpTemplateTxProvider {
            cache: template_tx_cache,
        }),
        chain_tip: Arc::new(TdpChainTipProvider { tdp }),
        block_submission_sink: block_sink,
        distribution_source,
        job_validator,
    }
}

// ─── 1. ProductionJdpAllocateResolver ────────────────────────────

/// Answers `AllocateMiningJobToken` from the mining paths' payout resolver, so
/// every payout guard applies here too. Resolving writes the PPLNS settlement
/// snapshot, so the reward must be [`ChainView::reference_revenue`], never an
/// estimate.
pub(crate) struct ProductionJdpAllocateResolver {
    payout_resolver: Arc<dyn bp_stratum_v2::hooks::PayoutResolver>,
    chain: Arc<dyn ChainView>,
    network: BitcoinNetwork,
}

#[async_trait]
impl JdpAllocateResolver for ProductionJdpAllocateResolver {
    async fn resolve_allocate_context(
        &self,
        user_identifier: &str,
        payout_distribution_negotiated: bool,
    ) -> AllocateOutcome {
        let Some(miner_address) = parse_user_identifier_as_address(user_identifier) else {
            return AllocateOutcome::Ignored;
        };

        // ext 0x0003/Negotiation: `coinbase_tx_outputs` must be empty.
        if payout_distribution_negotiated {
            return AllocateOutcome::Granted(AllocateTokenContext {
                miner_address,
                coinbase_outputs: Vec::new(),
            });
        }

        // SV2 JDP/AllocateMiningJobToken.Success. Gate 1: Solo only (the mining
        // side refuses others, fatally for a JDC), checked before resolving so a
        // refused allocate cannot rewrite the PPLNS snapshot. Unknown is served;
        // `match`, not `!= Solo`, so a new stream kind is classified deliberately.
        let servable = match bp_stratum_v2::hooks::PayoutResolver::resolve_stream_known(
            &*self.payout_resolver,
            &miner_address,
        ) {
            Some(StreamKind::Solo) => true,
            Some(StreamKind::Pplns | StreamKind::GroupSolo | StreamKind::Blockparty) => false,
            None => {
                debug!(
                    user_identifier,
                    "JDP allocate: no mining session for this address yet, so its mode is \
                     unknown — serving the base-protocol token on the strength of the mining \
                     side's Solo gate, which by then has a session to read"
                );
                true
            }
        };
        if !servable {
            warn!(
                user_identifier,
                "JDP allocate: base protocol is Solo-only (a shared window needs every payout \
                 slot pinned, and SV2 JDP/AllocateMiningJobToken.Success expresses one output) — refusing the token rather than \
                 issuing one every SetCustomMiningJob would be refused with; use ext 0x0003"
            );
            return AllocateOutcome::Refused {
                reason: "base-protocol JDP is served on the Solo stream only",
            };
        }

        // Gate 2: the payout must be exactly this miner (e.g. a DRAFT
        // Blockparty admin is Solo but routed to the pool fee address).
        let Some(reward_sats) = self.chain.reference_revenue() else {
            warn!(
                user_identifier,
                "JDP allocate: no template yet, so no revenue to resolve the payout list at — \
                 refusing rather than resolving against a guess (the pool is serving no jobs \
                 either way; the JDC's reconnect will get a token)"
            );
            return AllocateOutcome::Refused {
                reason: "no template yet — nothing to resolve a payout list against",
            };
        };
        let payouts = bp_stratum_v2::hooks::PayoutResolver::resolve_payouts(
            &*self.payout_resolver,
            &miner_address,
            reward_sats,
        )
        .await;

        let designated = match payouts.entries.as_slice() {
            // `ResolvedPayouts::none()`: the "serve no job" verdict.
            [] => {
                warn!(
                    user_identifier,
                    "JDP allocate: the resolver produced no payout list at all — that is its \
                     `serving NO JOB` verdict, not a payout shape. Refusing rather than \
                     designating nobody; the cause is the failed distribution build logged \
                     above, and the JDC's reconnect gets a token once it succeeds"
                );
                return AllocateOutcome::Refused {
                    reason: "no payout list for this miner — the pool is serving it no job",
                };
            }
            // Only checkable shape: shorting the output shorts the miner itself.
            [only] if only.address == miner_address.as_str() => only.address.clone(),
            // Another payee: only "script paid" is checkable, so 1 sat would pass.
            [only] => {
                warn!(
                    user_identifier,
                    routed_to = %only.address,
                    "JDP allocate: this miner's block is routed to another payee, which the base \
                     protocol cannot enforce (the JDC would satisfy the designated output with \
                     1 sat) — refusing the token; use ext 0x0003"
                );
                return AllocateOutcome::Refused {
                    reason: "base-protocol JDP cannot enforce a payout routed away from the miner",
                };
            }
            // A split: every payee but the designated one would get 0.
            entries @ [_, _, ..] => {
                warn!(
                    user_identifier,
                    payees = entries.len(),
                    "JDP allocate: base-protocol JDC whose payout needs more than one output — \
                     refusing the token (SV2 JDP/AllocateMiningJobToken.Success designates exactly one; use ext 0x0003)"
                );
                return AllocateOutcome::Refused {
                    reason: "base-protocol JDP cannot express this miner's payout split",
                };
            }
        };

        let Ok(designated) = AddressId::new(designated) else {
            warn!(
                user_identifier,
                "JDP allocate: resolver named an unusable payout address; refusing"
            );
            return AllocateOutcome::Refused {
                reason: "payout address unusable",
            };
        };
        // 0 sats per SV2 JDP/AllocateMiningJobToken.Success.
        match bp_mining_job::address_to_script(self.network, designated.as_str()) {
            Ok(script) => AllocateOutcome::Granted(AllocateTokenContext {
                miner_address,
                coinbase_outputs: designated_output_blob(&script),
            }),
            Err(err) => {
                warn!(
                    %err,
                    user_identifier, "JDP allocate: payout address does not encode; refusing"
                );
                AllocateOutcome::Refused {
                    reason: "payout address does not encode on this network",
                }
            }
        }
    }
}

// ─── 2. TdpTemplateTxProvider ────────────────────────────────────

/// The newest template's `wtxid -> raw_witness_tx` map; empty without the
/// cache. Anything missing the JDC sends via `ProvideMissingTransactions`.
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

// ─── 3. TdpChainTipProvider ───────────────────────────────────────

pub(crate) struct TdpChainTipProvider {
    tdp: TdpHandle,
}

#[async_trait]
impl ChainTipProvider for TdpChainTipProvider {
    async fn current_prev_hash(&self) -> Option<[u8; 32]> {
        self.tdp
            .current_snapshot()
            .set_new_prev_hash
            .map(|s| s.prev_hash)
    }

    async fn current_target(&self) -> Option<[u8; 32]> {
        self.tdp
            .current_snapshot()
            .set_new_prev_hash
            .map(|s| s.target)
    }
}

// ─── 4. ProductionJdpBlockSink ───────────────────────────────────

/// Where a found block goes for the pool's own anti-orphan resubmit.
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

/// What the pool's own node says the next block must satisfy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChainDemands {
    pub prev_hash: [u8; 32],
    /// Network target from `SetNewPrevHash`; an SV2 U256, so **little-endian**.
    pub target: [u8; 32],
}

/// Why a pushed solution may not be booked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotEvidence {
    NoChainView,
    /// Built on another tip, so the matched declared job is not the one solved.
    WrongTip,
    InsufficientWork,
}

/// Only evidence may reach the payout ledger: a header on the pool's tip that
/// meets the target the pool's OWN node published, never the sender's `n_bits`.
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
    // Both operands are little-endian; reversing either rejects every real block.
    if !bp_share::Target::from_le_bytes(demands.target)
        .is_met_by_le(&header.block_hash().to_byte_array())
    {
        return Err(NotEvidence::InsufficientWork);
    }
    Ok(())
}

/// The pool's view of what the next block must satisfy.
pub(crate) trait ChainView: Send + Sync {
    fn demands(&self) -> Option<ChainDemands>;

    /// The current template's `coinbase_tx_value_remaining`; `None` before the
    /// first template. Callers must NOT substitute an estimate.
    fn reference_revenue(&self) -> Option<u64>;
}

impl ChainView for TdpHandle {
    fn demands(&self) -> Option<ChainDemands> {
        let prev = self.current_snapshot().set_new_prev_hash?;
        Some(ChainDemands {
            prev_hash: prev.prev_hash,
            target: prev.target,
        })
    }

    fn reference_revenue(&self) -> Option<u64> {
        Some(
            self.current_snapshot()
                .new_template
                .as_ref()?
                .coinbase_tx_value_remaining,
        )
    }
}

/// Books a block the pool did not build the coinbase for. On `false` nothing
/// was written and the caller must not mark the block handled, or the JDC's
/// retry is dropped as a duplicate.
#[async_trait]
pub(crate) trait DeclaredBlockBooker: Send + Sync {
    async fn book(
        &self,
        record: FoundBlockRecord,
        reward_sats: u64,
        payouts_fingerprint: [u8; 32],
        actual_coinbase: Option<bp_coinbase_snapshot::ActualCoinbase>,
    ) -> bool;

    /// Record a block the pool CANNOT book: `blocks_entity` row and
    /// notification only, ledger untouched.
    async fn record_unbookable(&self, record: FoundBlockRecord) -> bool;
}

#[async_trait]
impl DeclaredBlockBooker for crate::block_sink::TdpBlockSubmissionSink {
    async fn book(
        &self,
        record: FoundBlockRecord,
        reward_sats: u64,
        payouts_fingerprint: [u8; 32],
        actual_coinbase: Option<bp_coinbase_snapshot::ActualCoinbase>,
    ) -> bool {
        self.book_declared_block_found(record, reward_sats, payouts_fingerprint, actual_coinbase)
            .await
    }

    async fn record_unbookable(&self, record: FoundBlockRecord) -> bool {
        self.record_declared_block_without_booking(record).await
    }
}

/// Reassemble the block a `PushSolution` describes; `None` when the JDC's
/// bytes don't parse.
fn assemble_declared_block(
    coinbase_raw: &[u8],
    transactions: &[Vec<u8>],
    solution: SolutionHeader,
) -> Option<Block> {
    let Some(coinbase_tx) =
        bp_stratum_v2::jdp::dynamic_outputs::decode_solution_coinbase(coinbase_raw)
    else {
        warn!(
            len = coinbase_raw.len(),
            "JDP block: declared coinbase parses in neither serialisation — not submitting"
        );
        return None;
    };
    let mut txdata: Vec<Transaction> = Vec::with_capacity(1 + transactions.len());
    txdata.push(coinbase_tx);
    for (i, raw) in transactions.iter().enumerate() {
        match decode_whole_tx(raw) {
            Some(tx) => txdata.push(tx),
            None => {
                warn!(idx = i, "JDP block: declared tx parse failed");
                return None;
            }
        }
    }
    let mut header = Header {
        version: BlockVersion::from_consensus(solution.version as i32),
        prev_blockhash: BlockHash::from_byte_array(solution.prev_hash),
        merkle_root: TxMerkleNode::all_zeros(),
        time: solution.ntime,
        bits: CompactTarget::from_consensus(solution.n_bits),
        nonce: solution.nonce,
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
/// it. The resubmit is switchable; booking a proven block is not.
pub(crate) struct ProductionJdpBlockSink {
    /// `None`: the JDC is the sole propagator.
    propagator: Option<Arc<dyn BlockPropagator>>,
    booker: Arc<dyn DeclaredBlockBooker>,
    /// Booking is checked against this, never against what the JDC sent.
    chain: Arc<dyn ChainView>,
    /// Recently booked hashes, so a re-sent solution is not booked twice.
    booked: StdMutex<VecDeque<[u8; 32]>>,
    network: BitcoinNetwork,
    /// ext 0x0003/Implementation Notes settlement hook, filled in by `jdp::spawn`.
    settle: crate::settlement::SettlementSignal,
}

/// How many recently-booked block hashes are remembered for the repeat check.
const BOOKED_MEMORY: usize = 16;

impl ProductionJdpBlockSink {
    /// Read-only on purpose; see [`Self::remember_booked`].
    fn already_booked(&self, hash: &[u8; 32]) -> bool {
        self.booked
            .lock()
            .expect("booked-hash mutex")
            .contains(hash)
    }

    /// Call only after the booking reached the ledger: if it failed, the JDC's
    /// re-send is the only chance left to write it.
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

    /// `WrongTip` also passes when the pool's node already holds this block as
    /// its tip, the ordinary case once the block has propagated.
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

    /// Book a proven solution. Settling republishes from the LIVE ledger, so a
    /// `Bookable` block is settled by the confirmation watcher after the apply;
    /// only [`CandidateBacking::UnbookableDistribution`] settles here. Both stay
    /// behind [`Self::block_is_proven`], or any JDC could invalidate distributions.
    async fn settle_and_book(
        &self,
        backing: CandidateBacking,
        miner_address: &AddressId,
        declaration: DeclarationRef,
        block: &Block,
        demands_on_arrival: Option<ChainDemands>,
    ) {
        if let Err(reason) = self.block_is_proven(block, demands_on_arrival) {
            // Either a false claim, or the pool matched an older declaration on
            // this tip (`PushSolution` carries no token) and got the merkle wrong.
            warn!(
                miner = miner_address.as_str(),
                ?reason,
                "JDP block-found: neither settled nor booked. Either the pushed solution is a \
                 claim the client cannot back, OR the pool matched it to the wrong declaration \
                 (PushSolution carries no token; several declarations share a tip). Check \
                 whether a block at this height exists on-chain before blaming the JDC."
            );
            return;
        }
        let hash = block.header.block_hash();
        if self.already_booked(&hash.to_byte_array()) {
            info!(
                miner = miner_address.as_str(),
                block_hash = %hash,
                "JDP block-found: already handled; ignoring the repeat"
            );
            return;
        }
        // ext 0x0003/Implementation Notes; `Bookable` is settled by the watcher.
        if backing.settles_here() {
            self.settle.settle().await;
        }
        let booking = match backing {
            CandidateBacking::Bookable(booking) => booking,
            // Still the pool's block: record it so it shows in API and UI.
            CandidateBacking::UnbookableDistribution { distribution_id } => {
                let recorded = self
                    .booker
                    .record_unbookable(FoundBlockRecord {
                        miner_address: miner_address.as_str().to_string(),
                        session_id: declaration_session_id(declaration.jdp_session_id),
                        block_hash: hash.to_string(),
                        block_data: serialize_hex(&block.header),
                    })
                    .await;
                if recorded {
                    self.remember_booked(hash.to_byte_array());
                }
                warn!(
                    miner = miner_address.as_str(),
                    block_hash = %hash,
                    distribution_id,
                    recorded,
                    "JDP block-found: recorded WITHOUT a ledger entry — the distribution's \
                     settlement snapshot never landed, so `claim − paid` cannot be computed. \
                     The miners were paid by the coinbase; the pool's ledger is short one \
                     reconciliation."
                );
                return;
            }
            // The mining side already records it; a second insert would duplicate.
            CandidateBacking::BaseProtocol => return,
        };
        // Book what the block's own coinbase ACTUALLY pays, never the intent.
        let actual = block
            .txdata
            .first()
            .map(|cb| bp_coinbase_snapshot::ActualCoinbase::from_coinbase(cb, self.network));
        let reward_sats = actual
            .as_ref()
            .map(|a| a.total_value_sats)
            .unwrap_or(booking.reference_reward_sats);
        let booked = self
            .booker
            .book(
                FoundBlockRecord {
                    miner_address: miner_address.as_str().to_string(),
                    session_id: declaration_session_id(declaration.jdp_session_id),
                    block_hash: hash.to_string(),
                    block_data: serialize_hex(&block.header),
                },
                reward_sats,
                booking.payouts_fingerprint,
                actual,
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
        declaration: DeclarationRef,
        backing: CandidateBacking,
        coinbase_raw: Vec<u8>,
        transactions: Vec<Vec<u8>>,
        solution: SolutionHeader,
    ) {
        info!(
            miner = miner_address.as_str(),
            token = ?declaration.new_token,
            session = %declaration_session_id(declaration.jdp_session_id),
            tx_count = transactions.len(),
            coinbase_len = coinbase_raw.len(),
            ?backing,
            pool_resubmit = self.propagator.is_some(),
            "JDP block-candidate received"
        );
        log_booking_status(&miner_address, backing);

        let bookable = match backing {
            CandidateBacking::Bookable(_) => true,
            CandidateBacking::UnbookableDistribution { .. } | CandidateBacking::BaseProtocol => {
                false
            }
        };
        // Skip reassembly when nothing (resubmit, booking, settle) needs the block.
        if self.propagator.is_none() && !bookable && !backing.paid_a_published_distribution() {
            return;
        }
        let Some(block) = assemble_declared_block(&coinbase_raw, &transactions, solution) else {
            warn!(
                miner = miner_address.as_str(),
                "JDP block: reassembly failed — the block can be neither resubmitted nor booked"
            );
            return;
        };
        // Read BEFORE propagating: the resubmit advances the tip, and every
        // found block would then look like it is on the wrong tip.
        let needs_evidence = bookable || backing.paid_a_published_distribution();
        let demands_on_arrival = needs_evidence.then(|| self.chain.demands()).flatten();

        // Propagation first: it shrinks the orphan window, booking can wait.
        if let Some(propagator) = &self.propagator {
            propagator.propagate(&miner_address, &block).await;
        }
        if needs_evidence {
            self.settle_and_book(
                backing,
                &miner_address,
                declaration,
                &block,
                demands_on_arrival,
            )
            .await;
        }
    }
}

/// `blocks_entity."sessionId"` (`varchar(8)`) for a JDP block: the connection
/// id, never the token, because `sessionId` is public.
fn declaration_session_id(jdp_session_id: u32) -> String {
    format!("{jdp_session_id:08x}")
}

/// Log whether a JDC-found block is bookable (ext 0x0003/Output Verification).
fn log_booking_status(miner_address: &AddressId, backing: CandidateBacking) {
    match backing {
        CandidateBacking::Bookable(b) => info!(
            miner = miner_address.as_str(),
            distribution_id = b.distribution_id,
            reference_reward_sats = b.reference_reward_sats,
            fingerprint = %hex::encode(b.payouts_fingerprint),
            "JDP block-found: coinbase validated against a published payout distribution"
        ),
        CandidateBacking::UnbookableDistribution { distribution_id } => warn!(
            miner = miner_address.as_str(),
            distribution_id,
            "JDP block-found: coinbase pays a published distribution whose settlement \
             snapshot never landed — the distribution IS settled, the block is NOT booked"
        ),
        CandidateBacking::BaseProtocol => warn!(
            miner = miner_address.as_str(),
            "JDP block-found: base-protocol declaration — no published distribution behind \
             this coinbase, so nothing to settle and nothing to book"
        ),
    }
}

// ─── 6. ProductionJobValidator (SV2 JDP/Job Declarator Server) ───────
// Asks bitcoin-core's `job_declaration_protocol` IPC (`checkBlock`) for a
// consensus verdict.

use bitcoin_core_sv2::runtime_api::BitcoinCoreVersion;
use bp_stratum_v2::jdp_server::{
    DeclarationLeg, DeclaredJobToValidate, DeclaredJobValidator, JobVerdict,
};
use jd_server_sv2::job_declarator::job_validation::{
    bitcoin_core_ipc::BitcoinCoreIPCEngine, DeclareMiningJobResult, JobValidationEngine,
};
use stratum_apps::tp_type::BitcoinNetwork as SriBitcoinNetwork;
use stratum_core::job_declaration_sv2::{
    DeclareMiningJobOwned as Sv2DeclareMiningJob,
    ProvideMissingTransactionsSuccessOwned as Sv2ProvideMissingTransactionsSuccess,
};

pub(crate) struct ProductionJobValidator {
    engine: Arc<BitcoinCoreIPCEngine>,
}

/// Whether the engine can rebuild this declared coinbase safely. It reads the
/// scriptSig length at fixed byte 43 (segwit layout) and trusts it, so only a
/// segwit-marked coinbase that [`declared_coinbase_tx`] also accepts is admitted.
fn upstream_can_rebuild_coinbase(prefix: &[u8], suffix: &[u8]) -> bool {
    prefix.get(4..6) == Some(&[0x00, 0x01][..]) && declared_coinbase_tx(prefix, suffix).is_some()
}

impl ProductionJobValidator {
    /// The data directory from which the engine derives `socket_path`
    /// (`<dir>/<network>/node.sock`); a path no derivation produces is an error.
    pub(crate) fn data_dir_for_socket(
        socket_path: &std::path::Path,
        network: SriBitcoinNetwork,
    ) -> Result<std::path::PathBuf, String> {
        let strip_levels = match network {
            SriBitcoinNetwork::Mainnet => 1, // <dir>/node.sock
            _ => 2,                          // <dir>/<network>/node.sock
        };
        let mut dir = socket_path.to_path_buf();
        for _ in 0..strip_levels {
            if !dir.pop() {
                return Err(format!(
                    "{} is too short to be a bitcoin-core IPC socket path",
                    socket_path.display()
                ));
            }
        }
        let rebuilt = match network {
            SriBitcoinNetwork::Mainnet => dir.join("node.sock"),
            SriBitcoinNetwork::Testnet4 => dir.join("testnet4").join("node.sock"),
            SriBitcoinNetwork::Signet => dir.join("signet").join("node.sock"),
            SriBitcoinNetwork::Regtest => dir.join("regtest").join("node.sock"),
        };
        if rebuilt != socket_path {
            return Err(format!(
                "bitcoin-core lays its IPC socket out as {}, but the config says {} — \
                 upstream derives the path from a data directory and cannot be pointed \
                 at an arbitrary one",
                rebuilt.display(),
                socket_path.display()
            ));
        }
        Ok(dir)
    }

    /// Connect to bitcoin-core's job-declaration IPC. `Err` stops the boot;
    /// `Ok(None)` on testnet3, which has no socket layout.
    pub(crate) async fn connect(
        socket_path: std::path::PathBuf,
        network: bp_config::Network,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Option<Arc<dyn DeclaredJobValidator>>, String> {
        let sri_network = match network {
            bp_config::Network::Mainnet => SriBitcoinNetwork::Mainnet,
            bp_config::Network::Testnet4 => SriBitcoinNetwork::Testnet4,
            bp_config::Network::Regtest => SriBitcoinNetwork::Regtest,
            bp_config::Network::Testnet => {
                warn!(
                    "jdp: declared-job validation not available on testnet3 \
                     (upstream has no socket layout for it) — declarations stay trusted"
                );
                return Ok(None);
            }
        };
        let data_dir = Self::data_dir_for_socket(&socket_path, sri_network.clone())?;
        match BitcoinCoreIPCEngine::new(
            BitcoinCoreVersion::V31X,
            sri_network,
            Some(data_dir),
            cancel,
        )
        .await
        {
            Ok(engine) => {
                info!(
                    socket = %socket_path.display(),
                    "jdp: declared jobs are validated against bitcoin-core (SV2 JDP/Job Declarator Server)"
                );
                Ok(Some(Arc::new(Self {
                    engine: Arc::new(engine),
                }) as Arc<dyn DeclaredJobValidator>))
            }
            Err(err) => Err(format!(
                "cannot reach bitcoin-core's job-declaration IPC at {}: {err:?}",
                socket_path.display()
            )),
        }
    }
}

#[async_trait]
impl DeclaredJobValidator for ProductionJobValidator {
    async fn validate_declaration(&self, job: DeclaredJobToValidate<'_>) -> JobVerdict {
        if !upstream_can_rebuild_coinbase(job.coinbase_tx_prefix, job.coinbase_tx_suffix) {
            warn!(
                session_id = job.session_id,
                prefix_len = job.coinbase_tx_prefix.len(),
                "jdp: declared coinbase is not a single-input segwit coinbase with a scriptSig \
                 of at most 100 bytes — rejecting before it reaches the validation engine"
            );
            return JobVerdict::Rejected("invalid-coinbase-tx".to_string());
        }
        // Token and excess data play no part in validation; placeholders.
        let wtxids: Vec<stratum_core::binary_sv2::U256Owned> = job
            .wtxid_list
            .iter()
            .map(|w| stratum_core::binary_sv2::U256Owned::from(*w))
            .collect();
        let Ok(wtxid_list) = stratum_core::binary_sv2::Seq064KOwned::new(wtxids) else {
            warn!("jdp: wtxid list too long to validate — rejecting");
            return JobVerdict::Rejected("invalid-job-declaration".to_string());
        };
        let (Ok(mining_job_token), Ok(prefix), Ok(suffix), Ok(excess_data)) = (
            vec![0u8; 8].try_into(),
            job.coinbase_tx_prefix.to_vec().try_into(),
            job.coinbase_tx_suffix.to_vec().try_into(),
            Vec::new().try_into(),
        ) else {
            warn!("jdp: declared coinbase does not fit the SV2 wire shape — rejecting");
            return JobVerdict::Rejected("invalid-coinbase-tx".to_string());
        };
        let declare = Sv2DeclareMiningJob {
            request_id: 0,
            mining_job_token,
            version: job.version,
            coinbase_tx_prefix: prefix,
            coinbase_tx_suffix: suffix,
            wtxid_list,
            excess_data,
        };

        // One engine slot per session: a new declaration resets it, or its
        // first leg is judged against the previous declaration's chain context.
        match job.leg {
            DeclarationLeg::Declare => self.engine.cleanup_downstream(job.session_id as usize),
            DeclarationLeg::Completed => {}
        }

        let provided: Vec<stratum_core::binary_sv2::B016MOwned> = job
            .known_raw_txs
            .iter()
            .filter_map(|tx| tx.to_vec().try_into().ok())
            .collect();
        let provide = stratum_core::binary_sv2::Seq064KOwned::new(provided)
            .ok()
            .map(|transaction_list| Sv2ProvideMissingTransactionsSuccess {
                request_id: 0,
                transaction_list,
            });

        match self
            .engine
            .handle_declare_mining_job(job.session_id as usize, declare, provide)
            .await
        {
            DeclareMiningJobResult::Success => JobVerdict::Accepted,
            DeclareMiningJobResult::Error(code) => JobVerdict::Rejected(code.to_string()),
            // Fetched from the JDC; the second leg asks again with the full set.
            DeclareMiningJobResult::MissingTransactions(_) => JobVerdict::NeedsTransactions,
        }
    }

    fn session_closed(&self, session_id: u32) {
        self.engine.cleanup_downstream(session_id as usize);
    }
}

#[cfg(test)]
mod session_id_for_blocks_entity {
    use super::*;

    /// Always eight characters, the width of `blocks_entity."sessionId"`.
    #[test]
    fn a_session_id_is_always_eight_characters() {
        for id in [0u32, 1, 0xFFFF, u32::MAX, 0x1234_5678] {
            let s = declaration_session_id(id);
            assert_eq!(s.len(), 8, "session id {s:?} for id {id}");
            assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    /// Matches the `jdp-{session_id:08x}` the connection logs.
    #[test]
    fn a_session_id_joins_a_found_block_to_its_connection_log() {
        let id = 0x0000_002au32;
        assert_eq!(
            format!("jdp-{}", declaration_session_id(id)),
            format!("jdp-{id:08x}"),
            "the durable row and the connection log must name the same session"
        );
    }

    #[test]
    fn distinct_sessions_get_distinct_ids() {
        assert_ne!(declaration_session_id(1), declaration_session_id(2));
    }
}

#[cfg(test)]
mod jdp_validation_regtest {
    use super::*;

    /// The validator reaches a REAL bitcoin-core's job-declaration IPC
    /// (socket layout, Core version, network mapping).
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::print_stderr)]
    async fn validator_connects_to_a_real_node_over_the_jdp_ipc() {
        let cfg = bp_regtest_harness::RegtestConfig::default();
        if !cfg.is_available() {
            eprintln!(
                "skipping JDP-validation regtest — {}",
                cfg.unavailable_reason()
            );
            return;
        }
        let node = bp_regtest_harness::RegtestNode::start_with(cfg)
            .await
            .expect("regtest start");
        // Core v31 blocks IPC work during IBD.
        node.generate_to_self(101)
            .await
            .expect("mine 101 blocks for IBD-exit");

        let cancel = tokio_util::sync::CancellationToken::new();
        let validator = ProductionJobValidator::connect(
            node.ipc_socket_path(),
            bp_config::Network::Regtest,
            cancel.clone(),
        )
        .await;

        let outcome = validator.as_ref().err().cloned().unwrap_or_default();
        assert!(
            matches!(validator, Ok(Some(_))),
            "the validator must reach the node's job-declaration IPC at {} — if this \
             fails the socket layout or the Core version mapping is wrong, and production \
             would refuse to boot rather than run unvalidated: {outcome}",
            node.ipc_socket_path().display()
        );

        cancel.cancel();
        node.shutdown().await.expect("regtest shutdown");
    }

    /// A validator on a fresh regtest node past IBD; `None` without `bitcoin-node`.
    async fn real_validator() -> Option<(
        bp_regtest_harness::RegtestNode,
        Arc<dyn DeclaredJobValidator>,
        tokio_util::sync::CancellationToken,
    )> {
        let cfg = bp_regtest_harness::RegtestConfig::default();
        if !cfg.is_available() {
            #[allow(clippy::print_stderr)]
            {
                eprintln!(
                    "skipping JDP-validation regtest — {}",
                    cfg.unavailable_reason()
                );
            }
            return None;
        }
        let node = bp_regtest_harness::RegtestNode::start_with(cfg)
            .await
            .expect("regtest start");
        node.generate_to_self(101)
            .await
            .expect("mine 101 blocks for IBD-exit");
        let cancel = tokio_util::sync::CancellationToken::new();
        let validator = ProductionJobValidator::connect(
            node.ipc_socket_path(),
            bp_config::Network::Regtest,
            cancel.clone(),
        )
        .await
        .expect("connect")
        .expect("regtest has a socket layout");
        Some((node, validator, cancel))
    }

    /// One declared coinbase, no transactions, declare leg.
    fn declaration<'a>(
        prefix: &'a [u8],
        suffix: &'a [u8],
        wtxid_list: &'a [[u8; 32]],
        known_raw_txs: &'a [&'a [u8]],
        leg: DeclarationLeg,
    ) -> DeclaredJobToValidate<'a> {
        DeclaredJobToValidate {
            session_id: 1,
            version: 0x2000_0000,
            coinbase_tx_prefix: prefix,
            coinbase_tx_suffix: suffix,
            wtxid_list,
            known_raw_txs,
            leg,
        }
    }

    /// The real node's verdict on one declared coinbase.
    async fn verdict_from_a_real_node(prefix: &[u8], suffix: &[u8]) -> Option<JobVerdict> {
        let (node, validator, cancel) = real_validator().await?;
        let verdict = validator
            .validate_declaration(declaration(
                prefix,
                suffix,
                &[],
                &[],
                DeclarationLeg::Declare,
            ))
            .await;
        cancel.cancel();
        node.shutdown().await.expect("regtest shutdown");
        Some(verdict)
    }

    fn assert_refused_as_invalid_coinbase(verdict: Option<JobVerdict>, shape: &str) {
        match verdict {
            None => {} // skipped, reported above
            Some(JobVerdict::Rejected(code)) => assert_eq!(code, "invalid-coinbase-tx", "{shape}"),
            Some(JobVerdict::Accepted) => panic!("{shape}: accepted"),
            Some(JobVerdict::NeedsTransactions) => panic!("{shape}: asked for transactions"),
        }
    }

    // Shapes outside the engine's coinbase assumptions, sent through the REAL engine.

    /// A prefix shorter than the 43 bytes the engine slices from.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_prefix_too_short_for_upstream_is_refused() {
        let verdict = verdict_from_a_real_node(&[0u8; 10], &[]).await;
        assert_refused_as_invalid_coinbase(verdict, "10-byte prefix");
    }

    /// A scriptSig length far past the consensus bound.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_scriptsig_length_upstream_would_allocate_is_refused() {
        let prefix = super::coinbase_shapes::segwit_header_with_script_sig_len(1 << 42);
        let verdict = verdict_from_a_real_node(&prefix, &[]).await;
        assert_refused_as_invalid_coinbase(verdict, "segwit prefix, scriptSig length 2^42");
    }

    /// No segwit marker: offset 43 reads inside the JDC-written scriptSig.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_coinbase_without_the_segwit_marker_is_refused() {
        let (prefix, suffix) = super::coinbase_shapes::legacy_with_huge_length_at_offset_43();
        assert!(
            bp_stratum_v2::jdp::dynamic_outputs::declared_coinbase_tx(&prefix, &suffix).is_some(),
            "precondition: the pool's own reconstruction accepts this coinbase"
        );
        let verdict = verdict_from_a_real_node(&prefix, &suffix).await;
        assert_refused_as_invalid_coinbase(verdict, "non-segwit coinbase");
    }

    /// Long enough for the engine's template monitor (`waitNext`) to see a new tip.
    const ENGINE_SEES_NEW_TIP: std::time::Duration = std::time::Duration::from_secs(2);

    /// A first leg is not judged against the previous declaration's tip; a
    /// second leg straddling a tip change still is `stale-chain-tip`.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_tip_change_between_two_declarations_is_not_a_stale_tip() {
        let Some((node, validator, cancel)) = real_validator().await else {
            return;
        };
        let (prefix, suffix) = super::coinbase_shapes::honest_segwit();
        // Unknown wtxid: the engine stops at "missing".
        let unknown = [[0x5a; 32]];
        let leg =
            |leg| validator.validate_declaration(declaration(&prefix, &suffix, &unknown, &[], leg));

        let first = leg(DeclarationLeg::Declare).await;
        assert!(
            matches!(first, JobVerdict::NeedsTransactions),
            "precondition: the engine reports the unknown wtxid missing, got {first:?}"
        );

        node.generate_to_self(1).await.expect("mine a block");
        tokio::time::sleep(ENGINE_SEES_NEW_TIP).await;
        let next = leg(DeclarationLeg::Declare).await;
        assert!(
            matches!(next, JobVerdict::NeedsTransactions),
            "a new declaration after a tip change is not stale, got {next:?}"
        );

        node.generate_to_self(1).await.expect("mine a block");
        tokio::time::sleep(ENGINE_SEES_NEW_TIP).await;
        let completed = leg(DeclarationLeg::Completed).await;
        assert!(
            matches!(&completed, JobVerdict::Rejected(code) if code == "stale-chain-tip"),
            "negative control: the second leg of a declaration that straddles a tip change \
             IS stale, got {completed:?}"
        );

        cancel.cancel();
        node.shutdown().await.expect("regtest shutdown");
    }

    /// A correct coinbase the guard admits is accepted by the real engine.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_valid_segwit_coinbase_is_accepted_by_the_engine() {
        let Some((node, validator, cancel)) = real_validator().await else {
            return;
        };
        let height = node.current_height().await.expect("height") + 1;
        let (prefix, suffix) = super::coinbase_shapes::valid_segwit_coinbase(height);
        assert!(
            upstream_can_rebuild_coinbase(&prefix, &suffix),
            "precondition: the guard admits the coinbase"
        );

        let verdict = validator
            .validate_declaration(declaration(
                &prefix,
                &suffix,
                &[],
                &[],
                DeclarationLeg::Declare,
            ))
            .await;
        assert!(matches!(verdict, JobVerdict::Accepted), "got {verdict:?}");

        // Negative control: the wrong height is refused.
        let (prefix, suffix) = super::coinbase_shapes::valid_segwit_coinbase(height + 1);
        let verdict = validator
            .validate_declaration(declaration(
                &prefix,
                &suffix,
                &[],
                &[],
                DeclarationLeg::Declare,
            ))
            .await;
        assert!(
            matches!(verdict, JobVerdict::Rejected(_)),
            "got {verdict:?}"
        );

        cancel.cancel();
        node.shutdown().await.expect("regtest shutdown");
    }

    /// A supplied transaction fills only its own wtxid's slot (and the declared
    /// one does get past the lookup).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_supplied_transaction_counts_only_under_its_own_wtxid() {
        let Some((node, validator, cancel)) = real_validator().await else {
            return;
        };
        let height = node.current_height().await.expect("height") + 1;
        let (prefix, suffix) = super::coinbase_shapes::valid_segwit_coinbase(height);
        let declared = super::coinbase_shapes::unrelated_transaction(1);
        let other = super::coinbase_shapes::unrelated_transaction(2);
        let wtxids = [declared.compute_wtxid().to_byte_array()];
        let supply = |tx: &bitcoin::Transaction| bitcoin::consensus::serialize(tx);

        let mismatched = supply(&other);
        let verdict = validator
            .validate_declaration(declaration(
                &prefix,
                &suffix,
                &wtxids,
                &[mismatched.as_slice()],
                DeclarationLeg::Completed,
            ))
            .await;
        assert!(
            matches!(verdict, JobVerdict::NeedsTransactions),
            "a transaction under another wtxid must not fill the slot, got {verdict:?}"
        );

        let matching = supply(&declared);
        let verdict = validator
            .validate_declaration(declaration(
                &prefix,
                &suffix,
                &wtxids,
                &[matching.as_slice()],
                DeclarationLeg::Completed,
            ))
            .await;
        assert!(
            matches!(verdict, JobVerdict::Rejected(_)),
            "negative control: the declared transaction is found, and the block with its \
             unspendable input is judged, got {verdict:?}"
        );

        cancel.cancel();
        node.shutdown().await.expect("regtest shutdown");
    }
}

/// Coinbase byte shapes for the guard in front of the validation engine.
#[cfg(test)]
mod coinbase_shapes {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    /// The 43-byte segwit header the engine assumes, then a scriptSig length.
    pub(super) fn segwit_header_with_script_sig_len(len: u64) -> Vec<u8> {
        let mut prefix = vec![2, 0, 0, 0, 0x00, 0x01, 0x01];
        prefix.extend_from_slice(&[0u8; 32]);
        prefix.extend_from_slice(&[0xff; 4]);
        prefix.extend_from_slice(&bitcoin::consensus::serialize(&bitcoin::VarInt(len)));
        prefix
    }

    /// `(prefix, suffix)` of `tx`, with the last `slot` scriptSig bytes cut
    /// out as the extranonce slot.
    fn split_at_slot(tx: &Transaction, slot: usize) -> (Vec<u8>, Vec<u8>) {
        let raw = bitcoin::consensus::serialize(tx);
        let script_sig = tx.input[0].script_sig.as_bytes();
        let marker = if tx.input[0].witness.is_empty() { 0 } else { 2 };
        // version + marker + input count + outpoint + scriptSig length byte
        let script_start = 4 + marker + 1 + 36 + 1;
        let slot_start = script_start + script_sig.len() - slot;
        (
            raw[..slot_start].to_vec(),
            raw[slot_start + slot..].to_vec(),
        )
    }

    fn coinbase(script_sig: Vec<u8>, witness: Witness) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(script_sig),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new_op_return([]),
            }],
        }
    }

    /// A coinbase a node accepts at `height` in a block with no other transactions.
    pub(super) fn valid_segwit_coinbase(height: u32) -> (Vec<u8>, Vec<u8>) {
        use bitcoin::hashes::{sha256d, Hash};
        let mut script_sig = bitcoin::script::Builder::new()
            .push_int(i64::from(height))
            .into_script()
            .into_bytes();
        script_sig.extend_from_slice(&[0u8; 8]);
        // Coinbase wtxid counts as zero: sha256d(zero root || zero reserved).
        let commitment = sha256d::Hash::hash(&[0u8; 64]);
        let mut commitment_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commitment_script.extend_from_slice(commitment.as_byte_array());
        let mut tx = coinbase(script_sig, Witness::from_slice(&[[0u8; 32]]));
        tx.output = vec![
            TxOut {
                value: Amount::from_sat(100_000_000),
                script_pubkey: ScriptBuf::new_op_return([]),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(commitment_script),
            },
        ];
        split_at_slot(&tx, 8)
    }

    /// A non-witness tx spending a nonexistent output; `tag` makes it distinct.
    pub(super) fn unrelated_transaction(tag: u32) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                    vout: tag,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_op_return([]),
            }],
        }
    }

    /// What a JDC declares: height push, 8-byte slot, segwit marker.
    pub(super) fn honest_segwit() -> (Vec<u8>, Vec<u8>) {
        let mut script_sig = vec![0x03, 0x65, 0x00, 0x00];
        script_sig.extend_from_slice(&[0u8; 8]);
        let tx = coinbase(script_sig, Witness::from_slice(&[[0u8; 32]]));
        split_at_slot(&tx, 8)
    }

    /// The same coinbase without witness, so without the marker.
    pub(super) fn honest_legacy() -> (Vec<u8>, Vec<u8>) {
        let mut script_sig = vec![0x03, 0x65, 0x00, 0x00];
        script_sig.extend_from_slice(&[0u8; 8]);
        split_at_slot(&coinbase(script_sig, Witness::new()), 8)
    }

    /// A valid marker-less coinbase whose byte 43 reads as CompactSize 2^42.
    pub(super) fn legacy_with_huge_length_at_offset_43() -> (Vec<u8>, Vec<u8>) {
        let mut script_sig = vec![0x01, 0xff];
        script_sig.extend_from_slice(&(1u64 << 42).to_le_bytes());
        split_at_slot(&coinbase(script_sig, Witness::new()), 0)
    }
}

#[cfg(test)]
mod upstream_coinbase_guard_tests {
    use super::coinbase_shapes::*;
    use super::*;

    /// The shape an honest JDC declares still reaches the node.
    #[test]
    fn an_honest_segwit_coinbase_passes() {
        let (prefix, suffix) = honest_segwit();
        assert!(upstream_can_rebuild_coinbase(&prefix, &suffix));
    }

    /// Refused by the marker clause; the pool's own reconstruction accepts it.
    #[test]
    fn a_coinbase_without_the_segwit_marker_is_refused() {
        for (label, (prefix, suffix)) in [
            ("honest legacy", honest_legacy()),
            (
                "legacy with 0xff at byte 43",
                legacy_with_huge_length_at_offset_43(),
            ),
        ] {
            assert!(
                declared_coinbase_tx(&prefix, &suffix).is_some(),
                "{label}: precondition — our own reconstruction accepts it"
            );
            assert!(!upstream_can_rebuild_coinbase(&prefix, &suffix), "{label}");
        }
    }

    #[test]
    fn a_prefix_shorter_than_the_segwit_header_is_refused() {
        assert!(!upstream_can_rebuild_coinbase(&[0u8; 10], &[]));
        assert!(!upstream_can_rebuild_coinbase(&[], &[]));
    }

    /// Over the consensus bound of 100 bytes.
    #[test]
    fn a_scriptsig_length_past_the_consensus_bound_is_refused() {
        for len in [101, 1 << 42] {
            let prefix = segwit_header_with_script_sig_len(len);
            assert!(!upstream_can_rebuild_coinbase(&prefix, &[]), "len {len}");
        }
    }
}

#[cfg(test)]
mod base_allocate_tests {
    //! Base-protocol allocate (SV2 JDP/AllocateMiningJobToken.Success): who
    //! gets a token, and what is designated.
    use super::*;

    const MINER: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    const OTHER: &str = "bcrt1qvs8k07ggszru23v9p42vpg4jxts9y2k8kkujja";

    /// Deliberately not a round subsidy, so it cannot match a code constant.
    const TEMPLATE_REVENUE: u64 = 316_042_137;

    use bp_mining_job::PayoutEntry;

    /// A fixed payout list that records the reward it was asked at.
    struct FixedPayouts {
        entries: Vec<PayoutEntry>,
        asked_at: StdMutex<Vec<u64>>,
        /// Explicit: the trait default is `Pplns`, which the base path refuses.
        stream: StreamKind,
        /// `false`: the JDC allocated before its mining channel opened.
        mode_known: bool,
    }

    #[async_trait]
    impl bp_stratum_v2::hooks::PayoutResolver for FixedPayouts {
        async fn resolve_payouts(
            &self,
            _miner_address: &AddressId,
            reward_sats: u64,
        ) -> bp_mining_job::ResolvedPayouts {
            self.asked_at.lock().unwrap().push(reward_sats);
            bp_mining_job::ResolvedPayouts::unsnapshotted(self.entries.clone())
        }

        fn resolve_stream(&self, _miner_address: &AddressId) -> StreamKind {
            self.stream
        }

        fn resolve_stream_known(&self, _miner_address: &AddressId) -> Option<StreamKind> {
            self.mode_known.then_some(self.stream)
        }
    }

    /// Stands in for the TDP snapshot; `None` is the pre-first-template state.
    struct TemplateAt(Option<u64>);
    impl ChainView for TemplateAt {
        fn demands(&self) -> Option<ChainDemands> {
            // Never asked on the allocate path.
            None
        }
        fn reference_revenue(&self) -> Option<u64> {
            self.0
        }
    }

    /// A Solo resolver on a pool that has a template.
    fn pays(entries: &[(&str, u64)]) -> ProductionJdpAllocateResolver {
        resolver_with(entries, Some(TEMPLATE_REVENUE)).0
    }

    /// The same, plus the handle on what the resolver was asked.
    fn resolver_with(
        entries: &[(&str, u64)],
        revenue: Option<u64>,
    ) -> (ProductionJdpAllocateResolver, Arc<FixedPayouts>) {
        resolver_on(entries, revenue, StreamKind::Solo)
    }

    fn resolver_on(
        entries: &[(&str, u64)],
        revenue: Option<u64>,
        stream: StreamKind,
    ) -> (ProductionJdpAllocateResolver, Arc<FixedPayouts>) {
        resolver_on_known(entries, revenue, stream, true)
    }

    fn resolver_on_known(
        entries: &[(&str, u64)],
        revenue: Option<u64>,
        stream: StreamKind,
        mode_known: bool,
    ) -> (ProductionJdpAllocateResolver, Arc<FixedPayouts>) {
        let payouts = Arc::new(FixedPayouts {
            entries: entries
                .iter()
                .map(|(a, s)| PayoutEntry {
                    address: a.to_string(),
                    sats: *s,
                })
                .collect(),
            asked_at: StdMutex::new(Vec::new()),
            stream,
            mode_known,
        });
        (
            ProductionJdpAllocateResolver {
                payout_resolver: payouts.clone(),
                chain: Arc::new(TemplateAt(revenue)),
                network: BitcoinNetwork::Regtest,
            },
            payouts,
        )
    }

    fn granted(outcome: AllocateOutcome) -> AllocateTokenContext {
        match outcome {
            AllocateOutcome::Granted(ctx) => ctx,
            AllocateOutcome::Refused { reason } => panic!("refused: {reason}"),
            AllocateOutcome::Ignored => panic!("ignored"),
        }
    }

    fn designated_script(ctx: &AllocateTokenContext) -> bitcoin::ScriptBuf {
        let outputs: Vec<bitcoin::TxOut> =
            bitcoin::consensus::deserialize(&ctx.coinbase_outputs).expect("outputs must decode");
        assert_eq!(
            outputs.len(),
            1,
            "SV2 JDP/AllocateMiningJobToken.Success designates exactly ONE output"
        );
        assert_eq!(
            outputs[0].value,
            bitcoin::Amount::ZERO,
            "SV2 JDP/AllocateMiningJobToken.Success: the designated output goes out with a 0 amount — a conformant \
             JD-client overwrites it with its own template revenue, and any OTHER \
             valued output would then push the coinbase past what the block pays"
        );
        outputs[0].script_pubkey.clone()
    }

    /// One payee, the miner: designated at 0 sats.
    #[tokio::test]
    async fn a_single_payee_is_designated_at_zero_sats() {
        let ctx = granted(
            pays(&[(MINER, 312_500_000)])
                .resolve_allocate_context(MINER, false)
                .await,
        );
        assert_eq!(ctx.miner_address.as_str(), MINER);
        assert_eq!(
            designated_script(&ctx),
            bp_mining_job::address_to_script(BitcoinNetwork::Regtest, MINER).unwrap()
        );
    }

    /// MONEY: a block routed AWAY from the miner (e.g. a DRAFT Blockparty
    /// admin) is refused: the designated output is only checked as paid, so
    /// the JDC could pay it 1 sat and keep the block.
    #[tokio::test]
    async fn a_block_routed_away_from_the_miner_is_refused_on_the_base_protocol() {
        let outcome = pays(&[(OTHER, 312_500_000)])
            .resolve_allocate_context(MINER, false)
            .await;
        assert!(
            matches!(outcome, AllocateOutcome::Refused { .. }),
            "a pending-party route must refuse the token, not designate a script the JDC \
             can satisfy with 1 sat"
        );
    }

    /// Negative control for the above: the same shape is served when the payee
    /// IS the miner.
    #[tokio::test]
    async fn the_same_single_payee_shape_is_served_when_it_is_the_miner() {
        let ctx = granted(
            pays(&[(MINER, 312_500_000)])
                .resolve_allocate_context(MINER, false)
                .await,
        );
        assert_eq!(
            designated_script(&ctx),
            bp_mining_job::address_to_script(BitcoinNetwork::Regtest, MINER).unwrap()
        );
    }

    /// ext 0x0003 serves the routed payout (ext 0x0003/Output Verification enforces it).
    #[tokio::test]
    async fn a_negotiated_session_still_serves_a_routed_payout() {
        let ctx = granted(
            pays(&[(OTHER, 312_500_000)])
                .resolve_allocate_context(MINER, true)
                .await,
        );
        assert!(ctx.coinbase_outputs.is_empty());
    }

    /// A split cannot be expressed in one output, so it is refused.
    #[tokio::test]
    async fn a_split_payout_is_refused_rather_than_silently_dropped() {
        let outcome = pays(&[(OTHER, 3_125_000), (MINER, 309_375_000)])
            .resolve_allocate_context(MINER, false)
            .await;
        assert!(
            matches!(outcome, AllocateOutcome::Refused { .. }),
            "a two-payee split must be refused, not truncated to one output"
        );
    }

    /// An empty list is refused with its own reason, distinct from a split.
    #[tokio::test]
    async fn an_empty_payout_list_is_refused_as_an_absent_list_not_as_a_split() {
        let AllocateOutcome::Refused { reason: absent } =
            pays(&[]).resolve_allocate_context(MINER, false).await
        else {
            panic!("an empty payout list must be refused");
        };
        let AllocateOutcome::Refused { reason: split } =
            pays(&[(OTHER, 3_125_000), (MINER, 309_375_000)])
                .resolve_allocate_context(MINER, false)
                .await
        else {
            panic!("a two-payee split must be refused");
        };

        assert_eq!(
            absent, "no payout list for this miner — the pool is serving it no job",
            "an absent list has to be named as one"
        );
        assert_eq!(
            split, "base-protocol JDP cannot express this miner's payout split",
            "a real split still has to be named a split"
        );
        assert_ne!(
            absent, split,
            "\"no list at all\" and \"too many payees\" are opposite causes and must not \
             share a verdict text"
        );
    }

    /// ext 0x0003/Negotiation: empty outputs, served on any split.
    #[tokio::test]
    async fn a_negotiated_session_gets_no_outputs_and_is_served_on_any_split() {
        let ctx = granted(
            pays(&[(OTHER, 3_125_000), (MINER, 309_375_000)])
                .resolve_allocate_context(MINER, true)
                .await,
        );
        assert!(
            ctx.coinbase_outputs.is_empty(),
            "ext 0x0003/Negotiation requires empty coinbase_tx_outputs when 0x0003 is negotiated"
        );
    }

    /// A non-address identifier is ignored, not refused (refusing closes the
    /// connection). Only shape is checked, hence the over-long string.
    #[tokio::test]
    async fn an_unparseable_identifier_is_ignored_not_refused() {
        let outcome = pays(&[(MINER, 1)])
            .resolve_allocate_context(&"x".repeat(200), false)
            .await;
        assert!(matches!(outcome, AllocateOutcome::Ignored));
    }

    /// MONEY: resolved at the LIVE template revenue, because for PPLNS it is
    /// written into the shared settlement snapshot.
    #[tokio::test]
    async fn the_payout_list_is_resolved_at_the_live_template_revenue() {
        let (resolver, payouts) = resolver_with(&[(MINER, 1)], Some(TEMPLATE_REVENUE));
        let _ = resolver.resolve_allocate_context(MINER, false).await;
        assert_eq!(
            payouts.asked_at.lock().unwrap().as_slice(),
            &[TEMPLATE_REVENUE],
            "the resolver must be asked at the template's own revenue"
        );
        assert_ne!(
            TEMPLATE_REVENUE,
            bp_share::INITIAL_BLOCK_SUBSIDY_SATS,
            "the fixture must be able to tell the two apart"
        );
    }

    /// No template: refuse without resolving, never estimate a revenue.
    #[tokio::test]
    async fn no_template_refuses_instead_of_resolving_against_a_guess() {
        let (resolver, payouts) = resolver_with(&[(MINER, 1)], None);
        let outcome = resolver.resolve_allocate_context(MINER, false).await;
        assert!(
            matches!(outcome, AllocateOutcome::Refused { .. }),
            "no template must refuse, not serve a token off an invented revenue"
        );
        assert!(
            payouts.asked_at.lock().unwrap().is_empty(),
            "the resolver must not be CALLED at all — the call itself is the write"
        );
    }

    /// A negotiated session resolves nothing, so it is served before the first template.
    #[tokio::test]
    async fn a_negotiated_session_is_served_before_the_first_template() {
        let (resolver, payouts) = resolver_with(&[(MINER, 1)], None);
        let ctx = granted(resolver.resolve_allocate_context(MINER, true).await);
        assert!(ctx.coinbase_outputs.is_empty());
        assert!(
            payouts.asked_at.lock().unwrap().is_empty(),
            "0x0003 resolves no payout list, so it writes no snapshot either"
        );
    }

    /// Off Solo the token is refused even with a single-miner payout list, since
    /// the mining side's refusal of every job would be fatal for the JDC.
    #[tokio::test]
    async fn a_shared_stream_is_refused_a_base_protocol_token() {
        for stream in [
            StreamKind::Pplns,
            StreamKind::GroupSolo,
            StreamKind::Blockparty,
        ] {
            let (resolver, payouts) =
                resolver_on(&[(MINER, 312_500_000)], Some(TEMPLATE_REVENUE), stream);
            let outcome = resolver.resolve_allocate_context(MINER, false).await;
            assert!(
                matches!(outcome, AllocateOutcome::Refused { .. }),
                "{stream:?}: the mining side would refuse every job on this token"
            );
            // Resolving writes the PPLNS snapshot, so a refusal must not resolve.
            assert!(
                payouts.asked_at.lock().unwrap().is_empty(),
                "{stream:?}: a refused allocate must not resolve — the call itself is the write"
            );
        }
    }

    /// An unknown mode is served on the base protocol; the mining side's Solo
    /// gate still checks every job.
    #[tokio::test]
    async fn an_address_with_no_mining_session_is_served_a_base_protocol_token() {
        // Pplns behind "unknown": reading the stream would refuse.
        let (resolver, payouts) = resolver_on_known(
            &[(MINER, 312_500_000)],
            Some(TEMPLATE_REVENUE),
            StreamKind::Pplns,
            false,
        );
        let ctx = granted(resolver.resolve_allocate_context(MINER, false).await);
        assert_eq!(
            designated_script(&ctx),
            bp_mining_job::address_to_script(BitcoinNetwork::Regtest, MINER).unwrap(),
            "the designated output is the miner's own — SV2 JDP/AllocateMiningJobToken.Success has one to give"
        );
        assert_eq!(
            payouts.asked_at.lock().unwrap().as_slice(),
            &[TEMPLATE_REVENUE],
            "the payout-list guard still runs; only the stream question was unanswerable"
        );
    }

    /// Negative control: the same payout list on the Solo stream is served.
    #[tokio::test]
    async fn the_same_payout_list_is_served_on_the_solo_stream() {
        let (resolver, payouts) = resolver_on(
            &[(MINER, 312_500_000)],
            Some(TEMPLATE_REVENUE),
            StreamKind::Solo,
        );
        let ctx = granted(resolver.resolve_allocate_context(MINER, false).await);
        assert_eq!(
            designated_script(&ctx),
            bp_mining_job::address_to_script(BitcoinNetwork::Regtest, MINER).unwrap()
        );
        assert_eq!(
            payouts.asked_at.lock().unwrap().as_slice(),
            &[TEMPLATE_REVENUE],
            "a servable allocate still goes through the payout list"
        );
    }

    /// A Solo stream routed away from the miner (DRAFT Blockparty) still
    /// reaches and fails the payout-list guard.
    #[tokio::test]
    async fn a_solo_stream_routed_away_from_the_miner_is_still_refused() {
        let (resolver, payouts) = resolver_on(
            &[(OTHER, 312_500_000)],
            Some(TEMPLATE_REVENUE),
            StreamKind::Solo,
        );
        let outcome = resolver.resolve_allocate_context(MINER, false).await;
        assert!(
            matches!(outcome, AllocateOutcome::Refused { .. }),
            "the pending-party route must still be caught by the payout list"
        );
        assert_eq!(
            payouts.asked_at.lock().unwrap().len(),
            1,
            "and it must have been REACHED — a stream gate that short-circuits it would \
             refuse for the wrong reason and hide the guard"
        );
    }

    /// The Solo-only rule is base-path only; a negotiated session is served anywhere.
    #[tokio::test]
    async fn a_negotiated_session_is_served_on_a_shared_stream() {
        let (resolver, payouts) = resolver_on(
            &[(OTHER, 3_125_000), (MINER, 309_375_000)],
            Some(TEMPLATE_REVENUE),
            StreamKind::Pplns,
        );
        let ctx = granted(resolver.resolve_allocate_context(MINER, true).await);
        assert!(ctx.coinbase_outputs.is_empty());
        assert!(payouts.asked_at.lock().unwrap().is_empty());
    }
}

#[cfg(test)]
mod jdp_validation_socket_tests {
    use super::*;
    use std::path::PathBuf;

    /// Mainnet has no network subdirectory.
    #[test]
    fn mainnet_socket_reverses_to_its_directory() {
        assert_eq!(
            ProductionJobValidator::data_dir_for_socket(
                &PathBuf::from("/ipc/node.sock"),
                SriBitcoinNetwork::Mainnet
            ),
            Ok(PathBuf::from("/ipc"))
        );
    }

    #[test]
    fn non_mainnet_socket_strips_the_network_directory() {
        assert_eq!(
            ProductionJobValidator::data_dir_for_socket(
                &PathBuf::from("/ipc/regtest/node.sock"),
                SriBitcoinNetwork::Regtest
            ),
            Ok(PathBuf::from("/ipc"))
        );
    }

    /// A socket name no derivation produces is refused, not approximated.
    #[test]
    fn a_socket_name_upstream_cannot_produce_is_refused() {
        let err = ProductionJobValidator::data_dir_for_socket(
            &PathBuf::from("/var/run/bitcoind/bp-tdp.sock"),
            SriBitcoinNetwork::Mainnet,
        )
        .expect_err("a non-node.sock filename must not be accepted");
        assert!(
            err.contains("bp-tdp.sock"),
            "the error names what was configured: {err}"
        );
        assert!(
            err.contains("node.sock"),
            "and what was expected instead: {err}"
        );
    }

    /// The mainnet layout on testnet4 fails boot rather than run unvalidated.
    #[test]
    fn the_mainnet_layout_is_refused_on_testnet4() {
        assert!(ProductionJobValidator::data_dir_for_socket(
            &PathBuf::from("/ipc/node.sock"),
            SriBitcoinNetwork::Testnet4
        )
        .is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_stratum_v2::jdp::dynamic_outputs::PayoutBooking;

    /// Garbage bytes decline, without panic.
    #[test]
    fn assemble_declared_block_declines_unparsable_bytes() {
        assert!(assemble_declared_block(
            &[0xFF, 0xFF, 0xFF],
            &[],
            SolutionHeader {
                prev_hash: [0u8; 32],
                version: 0x2000_0000,
                ntime: 1_700_000_000,
                nonce: 42,
                n_bits: 0x1d00_ffff,
            },
        )
        .is_none());
    }

    /// The merkle root is computed, not left at zero.
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
            SolutionHeader {
                prev_hash: [0xABu8; 32],
                version: 0x2000_0000,
                ntime: 1_700_000_000,
                nonce: 42,
                n_bits: 0x1d00_ffff,
            },
        )
        .expect("a well-formed coinbase must reassemble");
        assert_ne!(
            block.header.merkle_root,
            TxMerkleNode::all_zeros(),
            "an uncomputed merkle root would name the wrong block"
        );
        assert_eq!(block.txdata.len(), 1);
    }

    /// A regtest JDC's declared coinbase off the wire, already witness-serialised.
    const JDC_DECLARED_COINBASE_WITNESS_FORM: &str = "\
02000000000101000000000000000000000000000000000000000000000000000000000000\
0000ffffffff2102b80b0e2f2f62702d6a64632d746573742f0e00000001000000000000000\
00000feffffff0288250000000000001600149b19fbdf3afc1136b235f38967276ff2e16319\
fa0000000000000000266a24aa21a9edbfb3fcf6fc1b9e46c9dc5e85fde2375dc46d51f45e6\
be619409085a2ef15b0a8012000000000000000000000000000000000000000000000000000\
00000000000000b70b0000";

    /// A witness-form coinbase reassembles byte-identically, not double-wrapped.
    #[test]
    fn a_witness_serialised_declared_coinbase_reassembles_verbatim() {
        let raw = hex::decode(JDC_DECLARED_COINBASE_WITNESS_FORM).expect("fixture hex");
        assert_eq!(raw.len(), 198, "fixture must be the captured bytes");

        let block = assemble_declared_block(
            &raw,
            &[],
            SolutionHeader {
                prev_hash: [0xABu8; 32],
                version: 0x2000_0000,
                ntime: 1_700_000_000,
                nonce: 42,
                n_bits: 0x1d00_ffff,
            },
        )
        .expect("the reference client's own coinbase must reassemble");

        let cb = &block.txdata[0];
        assert_eq!(cb.input.len(), 1, "the coinbase input was read as data");
        assert_eq!(cb.output.len(), 2, "payout + witness commitment");
        assert_eq!(
            bitcoin::consensus::serialize(cb),
            raw,
            "the reassembled coinbase must be the declared bytes, unchanged"
        );
    }

    /// A non-witness coinbase still reassembles (via the wrapping).
    #[test]
    fn a_non_witness_declared_coinbase_still_reassembles() {
        use bitcoin::absolute::LockTime;
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
        let raw = bitcoin::consensus::serialize(&coinbase);
        assert_ne!(raw[4], 0x00, "fixture must NOT be witness-serialised");

        let block = assemble_declared_block(
            &raw,
            &[],
            SolutionHeader {
                prev_hash: [0xABu8; 32],
                version: 0x2000_0000,
                ntime: 1_700_000_000,
                nonce: 42,
                n_bits: 0x1d00_ffff,
            },
        )
        .expect("a non-witness coinbase must still reassemble");
        assert_eq!(block.txdata[0].input.len(), 1);
        assert_eq!(block.txdata[0].output.len(), 1);
    }

    /// Trailing bytes after a complete transaction are a decode failure.
    #[test]
    fn a_transaction_that_decodes_from_a_prefix_only_is_rejected() {
        let mut raw = hex::decode(JDC_DECLARED_COINBASE_WITNESS_FORM).expect("fixture hex");
        assert!(
            decode_whole_tx(&raw).is_some(),
            "precondition: the clean bytes decode"
        );
        raw.extend_from_slice(&[0xAB; 8]);
        assert!(
            decode_whole_tx(&raw).is_none(),
            "trailing bytes mean these are not the declared transaction"
        );
    }

    /// A re-sent solution is booked once; the memory stays bounded.
    #[tokio::test]
    async fn a_repeated_block_is_booked_only_once() {
        let sink = sink_with_halves(None, Arc::new(RecordingBooker::default()), None);
        assert!(!sink.already_booked(&[1u8; 32]), "first sighting");
        sink.remember_booked([1u8; 32]);
        assert!(sink.already_booked(&[1u8; 32]), "the same block again");
        assert!(!sink.already_booked(&[2u8; 32]), "a different block");

        // A repeat must not consume a second slot.
        sink.remember_booked([1u8; 32]);

        for i in 0..BOOKED_MEMORY as u8 {
            sink.remember_booked([100 + i; 32]);
        }
        assert!(
            !sink.already_booked(&[1u8; 32]),
            "past the bound the oldest is forgotten — bounded memory is the trade"
        );
    }

    /// A malformed coinbase past the length guard declines, not indexed into.
    #[test]
    fn assemble_declared_block_declines_a_malformed_but_long_coinbase() {
        let garbage = vec![0xFFu8; 64];
        assert!(assemble_declared_block(
            &garbage,
            &[],
            SolutionHeader {
                prev_hash: [0u8; 32],
                version: 0x2000_0000,
                ntime: 1_700_000_000,
                nonce: 42,
                n_bits: 0x1d00_ffff,
            },
        )
        .is_none());
    }

    /// One corrupt declared transaction declines the whole block.
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
            SolutionHeader {
                prev_hash: [0u8; 32],
                version: 0x2000_0000,
                ntime: 1_700_000_000,
                nonce: 42,
                n_bits: 0x1d00_ffff,
            },
        )
        .is_none());
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
        wrote_nothing: bool,
        /// Blocks recorded WITHOUT a ledger entry, kept apart from `booked`.
        recorded: StdMutex<Vec<String>>,
        /// `blocks_entity."sessionId"` values from both paths.
        session_ids: StdMutex<Vec<String>>,
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
            record: FoundBlockRecord,
            reward: u64,
            fp: [u8; 32],
            _: Option<bp_coinbase_snapshot::ActualCoinbase>,
        ) -> bool {
            self.booked.lock().unwrap().push((reward, fp));
            self.session_ids.lock().unwrap().push(record.session_id);
            self.hashes.lock().unwrap().push(record.block_hash);
            !self.wrote_nothing
        }

        async fn record_unbookable(&self, record: FoundBlockRecord) -> bool {
            self.session_ids.lock().unwrap().push(record.session_id);
            self.recorded.lock().unwrap().push(record.block_hash);
            !self.wrote_nothing
        }
    }

    /// The booking call site writes the JDP session id, eight hex characters.
    #[tokio::test(flavor = "current_thread")]
    async fn the_booking_path_records_the_jdp_session_id() {
        let booker = Arc::new(RecordingBooker::default());
        let (sink, _bridge, _server) =
            sink_and_published_distribution(booker.clone(), Some(met_by_the_fixture()));

        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;

        assert_eq!(
            booker.booked.lock().unwrap().len(),
            1,
            "precondition: the booking WAS attempted — otherwise this proves nothing"
        );
        let ids = booker.session_ids.lock().unwrap().clone();
        assert_eq!(
            ids,
            vec![format!("{TEST_JDP_SESSION_ID:08x}")],
            "the durable row must carry the JDP session id, eight characters wide"
        );
        assert_eq!(ids[0].len(), 8, "blocks_entity.\"sessionId\" is varchar(8)");
    }

    /// A tip and no template; booking takes revenue from the block's coinbase.
    struct FixedChain(Option<ChainDemands>);
    impl ChainView for FixedChain {
        fn demands(&self) -> Option<ChainDemands> {
            self.0
        }
        fn reference_revenue(&self) -> Option<u64> {
            None
        }
    }

    /// A chain whose tip can move.
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
        fn reference_revenue(&self) -> Option<u64> {
            None
        }
    }

    /// A resubmit that advances the tip, as the real one does.
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
            SolutionHeader {
                prev_hash: [0u8; 32],
                version: 0x2000_0000,
                ntime: 1_700_000_000,
                nonce,
                n_bits: 0x1d00_ffff,
            },
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

    /// A sink with whichever halves the test cares about wired up.
    fn sink_with_halves(
        propagator: Option<Arc<RecordingPropagator>>,
        booker: Arc<RecordingBooker>,
        chain: Option<ChainDemands>,
    ) -> ProductionJdpBlockSink {
        ProductionJdpBlockSink {
            network: BitcoinNetwork::Regtest,
            propagator: propagator.map(|p| p as Arc<dyn BlockPropagator>),
            booker,
            settle: crate::settlement::SettlementSignal::local_only(),
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
            sink_with_halves(Some(propagator.clone()), booker.clone(), chain),
            propagator,
            booker,
        )
    }

    /// The JDP session every pushed candidate in these tests belongs to.
    const TEST_JDP_SESSION_ID: u32 = 0x00c0_ffee;

    async fn push(sink: &ProductionJdpBlockSink, backing: CandidateBacking, nonce: u32) {
        sink.submit_block_candidate(
            AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap(),
            DeclarationRef {
                new_token: bp_stratum_v2::tokens::Token([9u8; 16]),
                jdp_session_id: TEST_JDP_SESSION_ID,
            },
            backing,
            coinbase_bytes(),
            vec![],
            SolutionHeader {
                prev_hash: [0u8; 32],
                version: 0x2000_0000,
                ntime: 1_700_000_000,
                nonce,
                n_bits: 0x1d00_ffff,
            },
        )
        .await;
    }

    fn a_booking() -> PayoutBooking {
        PayoutBooking {
            distribution_id: 7,
            payouts_fingerprint: [0x11; 32],
            reference_reward_sats: 5_000_000_000,
        }
    }

    // ── ext 0x0003/Implementation Notes settle: separate from the booking, on
    // purpose ──────────
    // Published weights encode pre-settlement balances: left standing after
    // their block, they would be paid again.

    /// A sink whose settle signal reaches a registry with one published distribution.
    fn sink_and_published_distribution(
        booker: Arc<RecordingBooker>,
        chain: Option<ChainDemands>,
    ) -> (
        ProductionJdpBlockSink,
        Arc<std::sync::RwLock<bp_stratum_v2::bridge::JdpDeclaredJobRegistry>>,
        bp_stratum_v2::jdp_server::StratumV2JdpServer,
    ) {
        use bp_stratum_v2::bridge::{JdpDeclaredJobRegistry, PayoutDistributionEntry};
        use bp_stratum_v2::jdp::payout_distribution::WeightedOutput;
        use bp_stratum_v2::jdp_server::{JdpServerHooks, StratumV2JdpServer};
        use bp_stratum_v2::noise::NoiseConfig;

        let bridge = Arc::new(std::sync::RwLock::new(JdpDeclaredJobRegistry::new()));
        bridge
            .write()
            .unwrap()
            .publish_pool_wide(PayoutDistributionEntry {
                distribution_id: 7,
                built: bp_stratum_v2::bridge::BuiltPayoutDistribution {
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
                    payouts_fingerprint: Some([0x11; 32]),
                    bookable: true,
                },
                accounting: bp_stratum_v2::bridge::DistributionAccounting::PoolWide,
                jdp_session_id: None,
                published_at_ms: 1_001,
            });
        let noise = NoiseConfig::new(
            "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
                .parse()
                .unwrap(),
            "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
                .parse()
                .unwrap(),
        );
        let server = StratumV2JdpServer::spawn(
            noise,
            JdpServerHooks::no_op(),
            bridge.clone(),
            std::time::Duration::from_secs(3600),
        );
        let settle = crate::settlement::SettlementSignal::local_only();
        let _ = settle.registry_slot().set(server.distribution_handle());

        let sink = ProductionJdpBlockSink {
            network: BitcoinNetwork::Regtest,
            propagator: None,
            booker,
            settle,
            chain: Arc::new(FixedChain(chain)),
            booked: StdMutex::new(VecDeque::new()),
        };
        (sink, bridge, server)
    }

    /// A tip and target the fixture's header meets.
    fn met_by_the_fixture() -> ChainDemands {
        ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        }
    }

    /// MONEY: an unbookable distribution is still settled, or its weights
    /// would be paid a second time.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unbookable_distribution_is_still_settled() {
        let booker = Arc::new(RecordingBooker::default());
        let (sink, bridge, server) =
            sink_and_published_distribution(booker.clone(), Some(met_by_the_fixture()));
        assert!(
            bridge.read().unwrap().current_pool_wide().is_some(),
            "precondition: a distribution is published"
        );

        push(
            &sink,
            CandidateBacking::UnbookableDistribution { distribution_id: 7 },
            1,
        )
        .await;

        assert!(
            bridge.read().unwrap().current_pool_wide().is_none(),
            "the block paid these weights — they must stop being published"
        );
        assert!(
            booker.booked.lock().unwrap().is_empty(),
            "and nothing may be booked: there are no settlement inputs"
        );
        server.shutdown().await;
    }

    /// An unbookable block is recorded (row) but not booked (ledger).
    #[tokio::test(flavor = "current_thread")]
    async fn an_unbookable_block_is_recorded_but_not_booked() {
        let booker = Arc::new(RecordingBooker::default());
        let (sink, _bridge, server) =
            sink_and_published_distribution(booker.clone(), Some(met_by_the_fixture()));

        push(
            &sink,
            CandidateBacking::UnbookableDistribution { distribution_id: 7 },
            1,
        )
        .await;

        assert_eq!(
            booker.recorded.lock().unwrap().len(),
            1,
            "the block belongs in the pool's history even with no ledger entry"
        );
        assert!(
            booker.booked.lock().unwrap().is_empty(),
            "there are no settlement inputs — booking would invent them"
        );
        server.shutdown().await;
    }

    /// A base-protocol block is neither recorded nor booked here; the mining
    /// side records it. Pins the outcome, not the match arm.
    #[tokio::test(flavor = "current_thread")]
    async fn a_base_protocol_block_is_not_recorded_twice() {
        let booker = Arc::new(RecordingBooker::default());
        let (sink, _bridge, server) =
            sink_and_published_distribution(booker.clone(), Some(met_by_the_fixture()));

        push(&sink, CandidateBacking::BaseProtocol, 1).await;

        assert!(
            booker.recorded.lock().unwrap().is_empty(),
            "the mining side owns this one — recording it here too duplicates the row"
        );
        assert!(booker.booked.lock().unwrap().is_empty());
        server.shutdown().await;
    }

    /// MONEY: a bookable block does NOT settle here; a settle before the
    /// ledger write would republish the balances the block just paid.
    #[tokio::test(flavor = "current_thread")]
    async fn a_bookable_block_leaves_the_settle_to_its_booking() {
        let booker = Arc::new(RecordingBooker::default());
        let (sink, bridge, server) =
            sink_and_published_distribution(booker.clone(), Some(met_by_the_fixture()));

        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;

        assert_eq!(
            booker.booked.lock().unwrap().len(),
            1,
            "precondition: the booking WAS attempted — otherwise this proves nothing"
        );
        assert!(
            bridge.read().unwrap().current_pool_wide().is_some(),
            "the distribution must still stand: settling now would republish the same \
             balances, and the ledger write that makes a republish meaningful has not run"
        );
        server.shutdown().await;
    }

    /// A booking that wrote nothing settles nothing either.
    #[tokio::test(flavor = "current_thread")]
    async fn a_booking_that_wrote_nothing_settles_nothing() {
        let booker = Arc::new(RecordingBooker::that_writes_nothing());
        let (sink, bridge, server) =
            sink_and_published_distribution(booker.clone(), Some(met_by_the_fixture()));

        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;

        assert_eq!(
            booker.booked.lock().unwrap().len(),
            1,
            "precondition: the booking was attempted and reported writing nothing"
        );
        assert!(
            bridge.read().unwrap().current_pool_wide().is_some(),
            "a ledger write that did not happen cannot make a republish meaningful"
        );
        server.shutdown().await;
    }

    /// Negative controls: no settle for a base-protocol block or an unproven
    /// solution (or any JDC could wipe the published weights).
    #[tokio::test(flavor = "current_thread")]
    async fn nothing_settles_without_a_published_distribution_or_without_proof() {
        let (sink, bridge, server) =
            sink_and_published_distribution(Arc::default(), Some(met_by_the_fixture()));
        push(&sink, CandidateBacking::BaseProtocol, 1).await;
        assert!(
            bridge.read().unwrap().current_pool_wide().is_some(),
            "a base-protocol block settles nothing"
        );
        server.shutdown().await;

        // A backing that would settle, against a target the header cannot meet.
        let impossible = ChainDemands {
            prev_hash: [0u8; 32],
            target: [0u8; 32],
        };
        let (sink, bridge, server) =
            sink_and_published_distribution(Arc::default(), Some(impossible));
        push(
            &sink,
            CandidateBacking::UnbookableDistribution { distribution_id: 7 },
            1,
        )
        .await;
        assert!(
            bridge.read().unwrap().current_pool_wide().is_some(),
            "an unproven solution must not be able to invalidate a distribution"
        );
        server.shutdown().await;
    }

    /// Every candidate is resubmitted, whatever the ledger decides.
    #[tokio::test]
    async fn the_block_always_reaches_the_resubmit_sink() {
        let easy = ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        };
        for (chain, backing) in [
            (Some(easy), CandidateBacking::Bookable(a_booking())),
            (Some(easy), CandidateBacking::BaseProtocol),
            (None, CandidateBacking::Bookable(a_booking())),
        ] {
            let (sink, propagator, _) = sink_with(chain);
            push(&sink, backing, 1).await;
            assert_eq!(propagator.propagated.lock().unwrap().len(), 1);
        }
    }

    /// With the resubmit off the block is still booked.
    #[tokio::test]
    async fn booking_does_not_hinge_on_the_resubmit_switch() {
        let booker = Arc::new(RecordingBooker::default());
        let sink = sink_with_halves(
            None,
            booker.clone(),
            Some(ChainDemands {
                prev_hash: [0u8; 32],
                target: [0xFFu8; 32],
            }),
        );
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
        assert_eq!(
            *booker.booked.lock().unwrap(),
            vec![(5_000_000_000, [0x11; 32])]
        );
    }

    /// The tip is read before the resubmit advances it.
    #[tokio::test]
    async fn the_tip_is_judged_as_of_the_solutions_arrival() {
        let easy = ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        };
        // Not the pushed block, so the already-the-tip route cannot rescue it.
        let moved_on = ChainDemands {
            prev_hash: [0x77u8; 32],
            target: [0xFFu8; 32],
        };
        let chain = MovingChain::at(easy);
        let booker = Arc::new(RecordingBooker::default());
        let sink = ProductionJdpBlockSink {
            network: BitcoinNetwork::Regtest,
            propagator: Some(Arc::new(PropagatorThatMovesTheTip {
                chain: chain.clone(),
                to: moved_on,
            })),
            booker: booker.clone(),
            settle: crate::settlement::SettlementSignal::local_only(),
            chain: Arc::new(chain),
            booked: StdMutex::new(VecDeque::new()),
        };
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
        assert_eq!(
            booker.booked.lock().unwrap().len(),
            1,
            "the tip moved because we submitted the block — that must not un-book it"
        );
    }

    /// A block the pool's node already holds as its tip is proven.
    #[tokio::test]
    async fn a_block_our_node_already_holds_as_its_tip_is_proven() {
        // Unreachable target: the proof can only be the node's acceptance.
        let mut unreachable_target = [0u8; 32];
        unreachable_target[0] = 0x01;
        let booker = Arc::new(RecordingBooker::default());
        let sink = sink_with_halves(
            None,
            booker.clone(),
            Some(ChainDemands {
                prev_hash: pushed_block(1).header.block_hash().to_byte_array(),
                target: unreachable_target,
            }),
        );
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
        assert_eq!(booker.booked.lock().unwrap().len(), 1);
    }

    /// Any other tip stays refused; the second look is not a blanket pass.
    #[tokio::test]
    async fn a_foreign_tip_is_still_refused() {
        let booker = Arc::new(RecordingBooker::default());
        let sink = sink_with_halves(
            None,
            booker.clone(),
            Some(ChainDemands {
                prev_hash: [0x99u8; 32],
                target: [0xFFu8; 32],
            }),
        );
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
        assert!(booker.booked.lock().unwrap().is_empty());
    }

    /// The booked block is the propagated block.
    #[tokio::test]
    async fn the_booked_block_is_the_propagated_block() {
        let (sink, propagator, booker) = sink_with(Some(ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        }));
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
        let propagated = propagator.propagated.lock().unwrap()[0];
        assert_eq!(booker.hashes.lock().unwrap()[0], propagated.to_string());
    }

    /// Evidence is booked with the distribution the declaration vouched for.
    #[tokio::test]
    async fn evidence_books_the_vouched_distribution() {
        let (sink, _, booker) = sink_with(Some(ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        }));
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
        assert_eq!(
            *booker.booked.lock().unwrap(),
            vec![(5_000_000_000, [0x11; 32])]
        );
    }

    /// A claim that did no work must not move money, however well-formed.
    #[tokio::test]
    async fn a_claim_without_work_books_nothing() {
        // Little-endian 1: the hardest target there is.
        let mut hard = [0u8; 32];
        hard[0] = 0x01;
        let (sink, propagator, booker) = sink_with(Some(ChainDemands {
            prev_hash: [0u8; 32],
            target: hard,
        }));
        push(&sink, CandidateBacking::Bookable(a_booking()), 42).await;
        assert!(booker.booked.lock().unwrap().is_empty());
        assert_eq!(
            propagator.propagated.lock().unwrap().len(),
            1,
            "still propagated — bitcoin-core is the one to reject it"
        );
    }

    /// Real work without a vouched distribution books nothing.
    #[tokio::test]
    async fn work_without_a_vouched_distribution_books_nothing() {
        let (sink, _, booker) = sink_with(Some(ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        }));
        push(&sink, CandidateBacking::BaseProtocol, 1).await;
        assert!(booker.booked.lock().unwrap().is_empty());
    }

    /// A booking that wrote nothing leaves the block unmarked for the re-send.
    #[tokio::test]
    async fn a_booking_that_wrote_nothing_leaves_the_retry_open() {
        let booker = Arc::new(RecordingBooker::that_writes_nothing());
        let sink = sink_with_halves(
            None,
            booker.clone(),
            Some(ChainDemands {
                prev_hash: [0u8; 32],
                target: [0xFFu8; 32],
            }),
        );
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
        assert_eq!(
            booker.booked.lock().unwrap().len(),
            2,
            "the re-send must reach the ledger again — the first attempt wrote nothing"
        );
    }

    /// Once a booking wrote, the repeat is dropped.
    #[tokio::test]
    async fn a_booking_that_wrote_suppresses_the_repeat() {
        let booker = Arc::new(RecordingBooker::default());
        let sink = sink_with_halves(
            None,
            booker.clone(),
            Some(ChainDemands {
                prev_hash: [0u8; 32],
                target: [0xFFu8; 32],
            }),
        );
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
        assert_eq!(booker.booked.lock().unwrap().len(), 1);
    }

    /// A re-sent solution books once but propagates twice.
    #[tokio::test]
    async fn the_same_block_pushed_twice_books_once() {
        let (sink, propagator, booker) = sink_with(Some(ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        }));
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
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

    /// Without its own chain view the pool has nothing to check against.
    #[test]
    fn no_chain_view_is_not_evidence() {
        assert_eq!(
            solution_is_evidence(&header_with([0u8; 32], 0), None),
            Err(NotEvidence::NoChainView)
        );
    }

    /// A solution on another tip was not mined on the matched job.
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

    /// A header below the network target is a free claim, not evidence.
    #[test]
    fn a_header_that_did_no_work_is_not_evidence() {
        let demands = ChainDemands {
            prev_hash: [0u8; 32],
            // Little-endian 1: nothing passes.
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

    /// The sender's own `n_bits` cannot lower the bar.
    #[test]
    fn the_senders_own_n_bits_cannot_lower_the_bar() {
        let mut header = header_with([0u8; 32], 999);
        header.bits = CompactTarget::from_consensus(0x207f_ffff);
        let demands = ChainDemands {
            prev_hash: [0u8; 32],
            // Little-endian 1.
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

    /// The target is read little-endian; the lopsided fixture fails any other reading.
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

    /// `block_hash()` bytes equal `bp_share::sha256d`, the form the regtests prove.
    #[test]
    fn our_hash_bytes_are_the_form_the_regtests_prove_against_core() {
        use bitcoin::consensus::Encodable;

        let header = header_with([0xABu8; 32], 42);
        let mut raw = Vec::new();
        header.consensus_encode(&mut raw).expect("encode header");
        assert_eq!(raw.len(), 80, "a block header is 80 consensus bytes");
        assert_eq!(
            header.block_hash().to_byte_array(),
            bp_share::sha256d(&raw),
            "rust-bitcoin's block_hash bytes must be the same little-endian digest the \
             regtests brute-force against, or this check no longer inherits their proof"
        );
    }

    /// Work on the current tip that meets the target is evidence.
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
}
