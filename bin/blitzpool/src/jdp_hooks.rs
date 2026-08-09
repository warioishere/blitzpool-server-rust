// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production JDP hooks.
//!
//! Replaces the `JdpServerHooks::no_op()` placeholders so a
//! Job-Declaration-Client can actually go through the
//! `AllocateMiningJobToken` → `DeclareMiningJob` →
//! `ProvideMissingTransactions` → `PushSolution` choreography against
//! a real pool template + real block submission to bitcoin-core. The
//! fifth hook slot — the ext 0x0003 `PayoutDistributionSource` — is
//! wired by `jdp::spawn` from
//! [`crate::payout_resolver::ProductionDistributionSource`], not here.
//!
//! ## The hooks built here
//!
//! 1. **[`ProductionJdpAllocateResolver`]** — parses the JDC's
//!    `user_identifier` as a BTC address and answers with the token's
//!    coinbase outputs, which differ per payout regime:
//!    - **ext 0x0003 negotiated** → empty, per spec §2; the pushed
//!      payout distribution replaces them and §7.1 validates the job.
//!    - **base protocol** → the single §6.4.3 designated payout output
//!      at 0 sats, paying the miner itself, consensus-serialised through
//!      [`bp_stratum_v2::jdp::dynamic_outputs::encode_coinbase_outputs`].
//!      Only a Solo miner gets one, and two independent checks say so:
//!      the miner's stream must be Solo (which is what the mining side
//!      will serve a base custom job on), and its payout list must fit
//!      the single output §6.4.3 designates — the JD-client writes the
//!      whole template revenue into that one, so a shared list cannot be
//!      expressed. Either failing refuses the allocate. The list is
//!      resolved at the pool's CURRENT template revenue
//!      ([`ChainView::reference_revenue`]) — resolving is not a
//!      read-only operation, see [`ProductionJdpAllocateResolver`].
//!
//!    Production rejects JDC connections with unparseable identifiers
//!    (the spec says "JDS MAY accept any identifier"; we choose to
//!    require a parseable BTC address — typical JDC operators run their
//!    own dev-fee addresses anyway).
//!
//! 2. **[`TdpTemplateTxProvider`]** — returns the wtxid→tx_bytes map
//!    for the **current** template, out of the long-lived
//!    [`TemplateTxCache`]. The cache is gated on
//!    `[sv2].jdp_orphan_submitblock`; without it the provider answers
//!    with an empty map and the JDC fills in the whole transaction set
//!    over `ProvideMissingTransactions` — correct either way, but 1–2 MB
//!    per declaration instead of the handful of txs the pool is missing.
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
//!    is the pool's half of the redundancy §6.4.9 asks for ("JDS MUST
//!    attempt to reconstruct and propagate the block" — a MUST, not a
//!    SHOULD). Then the payout ledger, which
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
use bp_common::{AddressId, Sats, StreamKind};
use bp_stratum_v2::jdp::client::{parse_user_identifier_as_address, AllocateTokenContext};
use bp_stratum_v2::jdp::dynamic_outputs::{
    encode_coinbase_outputs, CandidateBacking, DynamicOutput, PayoutBooking,
};
use bp_stratum_v2::jdp_server::{
    AllocateOutcome, CurrentPrevHashProvider, JdpAllocateResolver, JdpBlockSubmissionSink,
    JdpServerHooks, PayoutDistributionSource, TemplateTxProvider,
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_jdp_hooks(
    tdp: TdpHandle,
    bitcoin_rpc: BitcoinRpc,
    payout_resolver: Arc<ProductionPayoutResolver>,
    template_tx_cache: Option<Arc<TemplateTxCache>>,
    network: BitcoinNetwork,
    orphan_submitblock_enabled: bool,
    ledger_booker: Option<Arc<crate::block_sink::TdpBlockSubmissionSink>>,
    distribution_source: Arc<dyn PayoutDistributionSource>,
    settle: crate::settlement::SettlementSignal,
    job_validator: Option<Arc<dyn DeclaredJobValidator>>,
) -> JdpServerHooks {
    let propagator: Option<Arc<dyn BlockPropagator>> = if orphan_submitblock_enabled {
        info!(
            "jdp: pool-side block propagation ENABLED (submitblock RPC) — \
             the pool's half of the §6.4.9 redundancy"
        );
        Some(Arc::new(bitcoin_rpc))
    } else {
        info!(
            "jdp: pool-side block propagation DISABLED \
             (`[sv2].jdp_orphan_submitblock = false`) — the JDC is the sole \
             propagator, so the pool does not do what §6.4.9 asks of a JDS"
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
        prev_hash_provider: Arc::new(TdpCurrentPrevHashProvider { tdp }),
        block_submission_sink: block_sink,
        distribution_source,
        job_validator,
    }
}

// ─── 1. ProductionJdpAllocateResolver ────────────────────────────

/// Answers `AllocateMiningJobToken`. It asks the same
/// [`crate::payout_resolver::ProductionPayoutResolver`] the SV1/SV2 mining
/// paths ask — not for the amounts, which §6.4.3 leaves to the JDC, but
/// because the payout list is the only thing that knows who this miner's
/// block is owed to, including the guards (pending Blockparty routes, mode
/// fallbacks) layered into it. Typed as the trait so the hook can be tested
/// without engines or a database.
///
/// ## Why it needs the live template revenue
///
/// §6.4.3 leaves the amounts to the JDC, so it is tempting to ask the
/// resolver with any plausible number and throw the sats away. That reads
/// the resolver as a query, and it is not one: for PPLNS it runs
/// `build_distribution`, which writes the block's SETTLEMENT INPUTS to
/// Redis under `pplns:snapshot:fp:<fingerprint>` — and the fingerprint is
/// revenue-independent by design (`bp_pplns::weights`,
/// `fingerprint_ignores_reference_revenue`). So the reward handed in here
/// lands verbatim in `referenceRevenueSats` on the very key the mining
/// path's build uses, and settlement re-projects every ledger promise from
/// it (`StoredWeightSnapshot::extras_total`). A made-up number silently
/// rewrites the projection base of a real coinbase.
///
/// Hence [`ChainView::reference_revenue`], the same value the mining path
/// and the distribution publisher resolve against. There is no estimate
/// and no fallback: with no template the pool serves no jobs at all, so a
/// token would be useless anyway, and guessing is the same bug one order
/// of magnitude smaller.
pub(crate) struct ProductionJdpAllocateResolver {
    payout_resolver: Arc<dyn bp_stratum_v2::hooks::PayoutResolver>,
    /// Source of the reward the payout list is resolved at — production
    /// wires the `TdpHandle` itself.
    chain: Arc<dyn ChainView>,
    network: BitcoinNetwork,
}

#[async_trait]
impl JdpAllocateResolver for ProductionJdpAllocateResolver {
    async fn resolve_allocate_context(
        &self,
        user_identifier: &str,
        _remote_addr: &str,
        payout_distribution_negotiated: bool,
    ) -> AllocateOutcome {
        let Some(miner_address) = parse_user_identifier_as_address(user_identifier) else {
            return AllocateOutcome::Ignored;
        };

        // ext 0x0003 negotiated ⇒ the published payout distribution
        // replaces the base §6.4.3 output semantics and §2 REQUIRES
        // `coinbase_tx_outputs` to be empty — don't build outputs at all.
        if payout_distribution_negotiated {
            return AllocateOutcome::Granted(AllocateTokenContext {
                miner_address,
                coinbase_outputs: Vec::new(),
            });
        }

        // ── Base protocol from here on ──────────────────────────────
        //
        // §6.4.3 gives a pool exactly ONE payout output to designate, and
        // requires it to go out with a 0 amount: "JDS MUST reserve the
        // first output with a locking script where the pool payout will
        // go. While this output is initially set with a 0 amount of sats,
        // this convention designates this locking script as the pool
        // payout output." Any further output the JDS adds MUST also be
        // 0-value; the JDC then allocates the template's revenue into the
        // designated one.
        //
        // TWO questions, in this order, and they are not the same one.
        //
        // First: will the mining side serve a base-protocol custom job on
        // this miner's stream at all? `handle_set_custom_mining_job` answers
        // `custom-jobs-require-solo` off Solo, and an SRI jd-client treats
        // that — like every code but `stale-chain-tip` — as a reason to leave
        // the pool. Granting a token there hands out one that every job built
        // on it is refused with, which is worse than refusing the token.
        //
        // It is asked HERE and not left to the mining side for two reasons:
        //
        // - The payout list cannot answer it. Today the two agree for PPLNS
        //   and Group-Solo by accident of shape (`payout_entries_at` emits
        //   the pool output unconditionally, so such a list never holds
        //   exactly one entry that is the miner) — but Blockparty falls back
        //   to `solo_payouts` on four error paths, and with no dev fee
        //   configured that is exactly the shape §6.4.3 can carry, on a
        //   stream that will refuse it.
        // - The call below is not free and not a query: for PPLNS it runs
        //   `build_distribution`, which WRITES the settlement snapshot (see
        //   the struct doc). A refusal closes the connection and an SRI
        //   jd-client reconnects, so an allocate that was never going to be
        //   servable would repeat that write once per reconnect, forever —
        //   the §6.4.2 rate limit cannot throttle it, because it lives in
        //   `TokenStore::allocate`, which such an allocate never reaches.
        //
        // `match` and not `!= Solo`: a stream added later has to be
        // classified deliberately rather than default into being served.
        let servable = match bp_stratum_v2::hooks::PayoutResolver::resolve_stream(
            &*self.payout_resolver,
            &miner_address,
        ) {
            StreamKind::Solo => true,
            StreamKind::Pplns | StreamKind::GroupSolo | StreamKind::Blockparty => false,
        };
        if !servable {
            warn!(
                user_identifier,
                "JDP allocate: base protocol is Solo-only (a shared window needs every payout \
                 slot pinned, and §6.4.3 expresses one output) — refusing the token rather than \
                 issuing one every SetCustomMiningJob would be refused with; use ext 0x0003"
            );
            return AllocateOutcome::Refused {
                reason: "base-protocol JDP is served on the Solo stream only",
            };
        }

        // Second, and this is the one the payout list owns: does this
        // miner's payout fit in ONE output? The stream gate above does NOT
        // subsume it, and must not be read as doing so — a Blockparty admin
        // whose party is still DRAFT resolves to the Solo *mode*, i.e. it
        // passes the gate, while `resolve_payouts` routes 100 % of the block
        // to the pool fee address precisely so the admin cannot pocket it
        // before the members confirm. Going through the resolver keeps that
        // guard — and every future one — on this path, instead of quietly
        // reimplementing a subset of it.
        //
        // The reward decides no output here — the JDC fills in the real one
        // from its own template. It is NOT free to invent, though: for PPLNS
        // the call below writes this number into the settlement snapshot the
        // mining path's own build shares. See the struct doc.
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
            // The one shape §6.4.3 can carry: a single payee who IS this
            // miner. The JD-client writes the whole template revenue into
            // the designated output, so the pool's only enforcement is
            // "some sats went to that script" — which is enough precisely
            // because shorting it shorts the miner itself.
            [only] if only.address == miner_address.as_str() => only.address.clone(),
            // A single payee who is SOMEBODY ELSE. The resolver routing the
            // block away from the miner is a guard — today the pending
            // Blockparty route, which sends 100 % to the pool fee address so
            // an admin cannot pocket a block before the members confirm
            // their splits — and the base protocol cannot enforce it. The
            // pool would designate the fee script, and a JDC honours that
            // with one satoshi: `pays_designated_output` can only ask
            // whether the script was paid, never how much, because §6.4.3
            // answers the shortfall economically and names no threshold.
            // Designating it anyway is the guard in name only.
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
            // A split. The base protocol cannot express it — a conformant
            // JD-client writes the whole revenue into the designated output
            // and leaves every other one at the 0 the pool had to send, so
            // the other payees would silently receive nothing. Refusing is
            // the honest answer, and it is what makes a configured solo fee
            // take effect rather than evaporate.
            entries => {
                warn!(
                    user_identifier,
                    payees = entries.len(),
                    "JDP allocate: base-protocol JDC whose payout needs more than one output — \
                     refusing the token (§6.4.3 designates exactly one; use ext 0x0003)"
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
        // 0 sats per §6.4.3 — the amount is the JDC's to fill in.
        let outputs = [DynamicOutput {
            address: designated,
            sats: Sats(0),
        }];
        match encode_coinbase_outputs(self.network, &outputs) {
            Ok(bytes) => AllocateOutcome::Granted(AllocateTokenContext {
                miner_address,
                coinbase_outputs: bytes,
            }),
            Err(err) => {
                // Refuse the allocate outright. An unencodable output set
                // must not degrade into a bogus 1-byte blob the JDC would
                // size its coinbase reservation from.
                warn!(
                    %err,
                    user_identifier, "JDP allocate: encode_coinbase_outputs failed; refusing"
                );
                AllocateOutcome::Refused {
                    reason: "payout address does not encode on this network",
                }
            }
        }
    }
}

// ─── 2. TdpTemplateTxProvider ────────────────────────────────────

/// Production tx-provider: pulls the newest template's
/// `wtxid → raw_witness_tx` map from the long-lived
/// [`TemplateTxCache`] when present. The cache is gated on
/// `[sv2].jdp_orphan_submitblock` (see `main.rs`), which now defaults to
/// on — the pool needs the raw txs to rebuild a JDC block it propagates.
/// With the switch off the cache is `None` and snapshot returns an empty
/// map; the JDC then fills in every tx via the standard
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

    /// What the pool's current template pays out — the same
    /// `coinbase_tx_value_remaining` every SV1/SV2 job build resolves its
    /// payouts against, and the same one
    /// [`crate::payout_resolver::ProductionDistributionSource`] publishes
    /// its distributions against.
    ///
    /// It is a separate `Option` from [`Self::demands`] because it reads a
    /// different half of the TDP snapshot: `demands` needs a
    /// `SetNewPrevHash`, this needs a `NewTemplate`, and either can be
    /// absent on its own.
    ///
    /// `None` means the pool has not been handed a template yet. Callers
    /// must NOT substitute an estimate — see
    /// [`ProductionJdpAllocateResolver`] for what a guessed revenue costs.
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

/// Books a block the pool did not build the coinbase for.
///
/// Returns whether the booking got as far as the ledger fan-out. A `false` means
/// nothing was written and the caller must not record the block as handled —
/// otherwise the JD-client's retry, which is the only remaining chance to book
/// it in-process, gets discarded as a duplicate.
#[async_trait]
pub(crate) trait DeclaredBlockBooker: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn book(
        &self,
        miner_address: String,
        session_id: String,
        reward_sats: u64,
        block_hash: String,
        block_data: String,
        payouts_fingerprint: [u8; 32],
        actual_coinbase: Option<bp_coinbase_snapshot::ActualCoinbase>,
    ) -> bool;

    /// Record a found block the pool CANNOT book: write the durable
    /// `blocks_entity` row and fire the notification, and deliberately leave
    /// the ledger alone.
    ///
    /// The one caller is a block on a distribution whose settlement snapshot
    /// never landed. There are no inputs to book against, but the block is
    /// the pool's and belongs in its history — without the row it shows up in
    /// no API and no UI, and the only trace is a log line.
    ///
    /// Separate from [`Self::book`] rather than a flag on it, because the
    /// difference is not a parameter: `book` promises a ledger write and
    /// returns whether it happened, this one promises the opposite.
    async fn record_unbookable(
        &self,
        miner_address: String,
        session_id: String,
        block_hash: String,
        block_data: String,
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
        actual_coinbase: Option<bp_coinbase_snapshot::ActualCoinbase>,
    ) -> bool {
        self.book_declared_block_found(
            miner_address,
            session_id,
            reward_sats,
            block_hash,
            block_data,
            payouts_fingerprint,
            actual_coinbase,
        )
        .await
    }

    async fn record_unbookable(
        &self,
        miner_address: String,
        session_id: String,
        block_hash: String,
        block_data: String,
    ) -> bool {
        self.record_declared_block_without_booking(
            miner_address,
            session_id,
            block_hash,
            block_data,
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
    /// Address-display network for decomposing the block's coinbase into
    /// per-address payments (the weight-model settlement input).
    network: BitcoinNetwork,
    /// ext 0x0003 §10 settlement hook, filled in by `jdp::spawn` once the
    /// JDP server exists (the sink is built first). A booked block settles
    /// the distribution its coinbase paid — every published distribution
    /// is then invalidated and a fresh one force-published.
    settle: crate::settlement::SettlementSignal,
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

    /// Act on a pushed solution the chain can vouch for: settle the
    /// distribution it paid, and book it if there is anything to book with.
    ///
    /// ## The two are separate, and that is the point
    ///
    /// Booking needs settlement INPUTS (`booking`). Settling needs only the
    /// fact that a block paid a published distribution — see
    /// [`CandidateBacking`]. The §10 settle therefore runs for an
    /// `UnbookableDistribution` too, and it runs even when the ledger write
    /// reports it wrote nothing.
    ///
    /// It used to sit inside `if booked`, so neither of those fired it. The
    /// published weights encode pre-settlement balances; the block's coinbase
    /// has just paid them out on-chain; leaving the distribution standing
    /// means the next block pays them a SECOND time. That is not a lost
    /// record, it is lost money.
    ///
    /// Both halves stay behind [`Self::block_is_proven`]. A `PushSolution` is
    /// the client's claim until the header is checked against what the chain
    /// demanded — settling on an unproven claim would let any JDC invalidate
    /// the pool's published distributions at will.
    async fn settle_and_book(
        &self,
        to_book: Option<(PayoutBooking, &dyn DeclaredBlockBooker)>,
        backing: CandidateBacking,
        miner_address: &AddressId,
        new_token: Token,
        block: &Block,
        demands_on_arrival: Option<ChainDemands>,
    ) {
        if let Err(reason) = self.block_is_proven(block, demands_on_arrival) {
            // TWO causes, and the second one is ours. Naming only the first
            // sends an operator to investigate a JDC that did nothing wrong.
            //
            // 1. The client claimed a block it did not find. That is what the
            //    check exists for.
            // 2. WE reassembled the wrong block. `PushSolution` carries no
            //    token (§6.4.9), so `DeclaredJobStore::match_for_solution`
            //    picks the most recently declared job on this tip — and a JDC
            //    re-declares per template, so several share a tip. If the
            //    solution belongs to an older one, the merkle root we compute
            //    is a different job's, the header hash changes, and the real
            //    nonce no longer meets the target. A genuine block then looks
            //    exactly like a false claim.
            //
            // Telling them apart means reassembling every candidate on the
            // tip (≤ MAX_DECLARED_JOBS) and keeping the one that verifies —
            // deliberately NOT built: bitcoin-core is meant to own this
            // (`JdRequest::PushSolution`, still a `// todo` stub upstream as
            // of sv2-apps main 2026-08-07), which lands with Core v32 and
            // takes the whole reassembly with it. Revisit then, not before.
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
        // §10 first, and unconditionally: the block is proven, so whatever it
        // paid is spent. A booking failure below must not leave the weights
        // standing, and a distribution with no settlement inputs still has to
        // stop being mined.
        if backing.paid_a_published_distribution() {
            self.settle.settle().await;
        }
        let Some((booking, booker)) = to_book else {
            // Nothing to book. For an `UnbookableDistribution` the block is
            // still the pool's, and without a row it appears in no API and no
            // UI — the operator would have to find it in a log line. Record
            // it, ledger untouched.
            //
            // A base-protocol declaration gets nothing here on purpose: the
            // mining side already records that one off its own share
            // (`ExtendedJob::jdp_claims_the_block`), and a second record would
            // be a duplicate row on an insert with no `ON CONFLICT`.
            if let (CandidateBacking::UnbookableDistribution { distribution_id }, Some(recorder)) =
                (backing, self.booker.as_ref())
            {
                let recorded = recorder
                    .record_unbookable(
                        miner_address.as_str().to_string(),
                        hex::encode(new_token.0),
                        hash.to_string(),
                        serialize_hex(&block.header),
                    )
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
            }
            return;
        };
        // The block's own coinbase is the settlement ground truth —
        // `claim − paid` is booked from what it ACTUALLY pays. The
        // recorded reward is that coinbase's total; the distribution's
        // reference revenue is only the fallback when the block has no
        // parseable coinbase (which `block_is_proven` all but excludes).
        let actual = block
            .txdata
            .first()
            .map(|cb| bp_coinbase_snapshot::ActualCoinbase::from_coinbase(cb, self.network));
        let reward_sats = actual
            .as_ref()
            .map(|a| a.total_value_sats)
            .unwrap_or(booking.reference_reward_sats);
        let booked = booker
            .book(
                miner_address.as_str().to_string(),
                hex::encode(new_token.0),
                reward_sats,
                hash.to_string(),
                serialize_hex(&block.header),
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
        new_token: Token,
        backing: CandidateBacking,
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
            ?backing,
            pool_resubmit = self.propagator.is_some(),
            "JDP block-candidate received"
        );
        log_booking_status(&miner_address, backing);

        let to_book = match backing {
            CandidateBacking::Bookable(booking) => {
                self.booker.as_ref().map(|booker| (booking, booker))
            }
            CandidateBacking::UnbookableDistribution { .. } | CandidateBacking::BaseProtocol => {
                None
            }
        };
        // Nothing downstream wants the block, so don't pay to build it: a
        // deployment with the resubmit off and no ledger wired is the JDC
        // propagating alone, and reassembly would be work for a log line.
        //
        // The §10 settle counts as "wants it": it needs the assembled block
        // to check the solution is real before invalidating anything.
        if self.propagator.is_none()
            && to_book.is_none()
            && !backing.paid_a_published_distribution()
        {
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
        // Needed for the settle as well as the booking: both act only on a
        // block the chain can vouch for.
        let needs_evidence = to_book.is_some() || backing.paid_a_published_distribution();
        let demands_on_arrival = needs_evidence.then(|| self.chain.demands()).flatten();

        // Propagation first, and nothing that only the ledger needs before it.
        // The resubmit exists to shrink the orphan window; the booking changes
        // nothing about how fast the block travels, so it waits.
        if let Some(propagator) = &self.propagator {
            propagator.propagate(&miner_address, &block).await;
        }
        if needs_evidence {
            self.settle_and_book(
                to_book.map(|(booking, booker)| (booking, booker.as_ref())),
                backing,
                &miner_address,
                new_token,
                &block,
                demands_on_arrival,
            )
            .await;
        }
    }
}

/// Report what the pool can say about a JDC-found block's payouts.
///
/// The distinction it draws is the one that decides whether anything is
/// booked: a block whose declared coinbase was validated positionally against
/// a published payout distribution (ext 0x0003 §7.1) can be settled from that
/// distribution's snapshot, while one without that proof must not be booked
/// from anything.
fn log_booking_status(miner_address: &AddressId, backing: CandidateBacking) {
    match backing {
        CandidateBacking::Bookable(b) => info!(
            miner = miner_address.as_str(),
            distribution_id = b.distribution_id,
            reference_reward_sats = b.reference_reward_sats,
            fingerprint = %hex::encode(b.payouts_fingerprint),
            "JDP block-found: coinbase validated against a published payout distribution"
        ),
        // Its own line, not folded in with the base protocol: this one PAID a
        // published distribution and therefore settles, it just cannot be
        // booked. Reading the two as one `None` is what left the weights
        // standing.
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

// ─── 6. ProductionJobValidator (SV2 §6.1, node-side validation) ───────
//
// SRI's own JDS library owns the hard part: a dedicated thread running the
// !Send Cap'n-Proto client against bitcoin-core's `job_declaration_protocol`
// IPC interface, where `checkBlock` gives a real consensus verdict on a
// declared job. We hold it and translate between its SV2 wire types and the
// pool's own decoded shapes.
//
// Note this is a DIFFERENT core interface than the one the pool already uses:
// templates and block submission ride `template_distribution_protocol` on the
// same `node.sock`. Nothing here replaces that path.

use bitcoin_core_sv2::runtime_api::BitcoinCoreVersion;
use bp_stratum_v2::jdp_server::{DeclaredJobToValidate, DeclaredJobValidator, JobVerdict};
use jd_server_sv2::job_declarator::job_validation::{
    bitcoin_core_ipc::BitcoinCoreIPCEngine, DeclareMiningJobResult, JobValidationEngine,
};
use stratum_apps::tp_type::BitcoinNetwork as SriBitcoinNetwork;
use stratum_core::job_declaration_sv2::{
    DeclareMiningJob as Sv2DeclareMiningJob,
    ProvideMissingTransactionsSuccess as Sv2ProvideMissingTransactionsSuccess,
};

pub(crate) struct ProductionJobValidator {
    engine: Arc<BitcoinCoreIPCEngine>,
}

impl ProductionJobValidator {
    /// The data directory upstream's engine needs to arrive at `socket_path`.
    ///
    /// It derives `<dir>/<network>/node.sock` (no subdirectory on mainnet) and
    /// takes no socket path of its own, so this reverses that derivation and
    /// then checks it by rebuilding the path. A socket that no derivation can
    /// produce — a different filename, a different layout — is a config error,
    /// not something to paper over: connecting elsewhere, or nowhere, while the
    /// log claims validation is on is exactly the silent failure worth avoiding.
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

    /// Connect to bitcoin-core's job-declaration IPC. Normally the very socket
    /// `[tdp] socket_path` already uses — validation is a second interface on
    /// the one node.
    ///
    /// `Err` is a boot-stopping config error. `Ok(None)` means the network has
    /// no mapping upstream (testnet3), where staying off beats rejecting every
    /// declaration.
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
        // Core v31 is what the pool's TDP path already speaks.
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
                    "jdp: declared jobs are validated against bitcoin-core (SV2 §6.1)"
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
        // Rebuild the SV2 message the engine expects. Every field comes
        // straight from the frame the JDC sent; `mining_job_token` and
        // `excess_data` are not part of the consensus question, so a
        // placeholder token and empty excess keep the shape valid without
        // pretending to carry meaning.
        let wtxids: Vec<stratum_core::binary_sv2::U256<'static>> = job
            .wtxid_list
            .iter()
            .map(|w| stratum_core::binary_sv2::U256::from(*w))
            .collect();
        let Ok(wtxid_list) = stratum_core::binary_sv2::Seq064K::new(wtxids) else {
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

        // Hand over every raw transaction we already hold, so the node only
        // reports what is genuinely missing rather than everything.
        let provided: Vec<stratum_core::binary_sv2::B016M<'static>> = job
            .known_raw_txs
            .iter()
            .filter_map(|tx| tx.clone().try_into().ok())
            .collect();
        let provide =
            stratum_core::binary_sv2::Seq064K::new(provided)
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
            // The node still lacks transactions we could not supply. The
            // pool's own ProvideMissingTransactions round-trip fetches them
            // from the JDC; the second leg asks again with the full set.
            DeclareMiningJobResult::MissingTransactions(_) => JobVerdict::NeedsTransactions,
        }
    }
}

#[cfg(test)]
mod jdp_validation_regtest {
    use super::*;

    /// The §6.1 validator must reach a REAL bitcoin-core over its
    /// job-declaration IPC. Everything this asserts is a deployment fact that
    /// unit tests cannot see: that the socket really is
    /// `<data_dir>/regtest/node.sock` (upstream derives it, we only hand over
    /// the data dir), that `BitcoinCoreVersion::V31X` matches the node we run,
    /// and that our network mapping lands on the right subdirectory.
    ///
    /// Skipped with a warning when `bitcoin-node` is absent — same policy as
    /// every other regtest here.
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::print_stderr)]
    async fn validator_connects_to_a_real_node_over_the_jdp_ipc() {
        let cfg = bp_regtest_harness::RegtestConfig::default();
        if !cfg.is_available() {
            eprintln!(
                "skipping JDP-validation regtest — bitcoin-node not found at {} \
                 (set BITCOIN_NODE_PATH to override)",
                cfg.bitcoin_node_path.display()
            );
            return;
        }
        let node = bp_regtest_harness::RegtestNode::start_with(cfg)
            .await
            .expect("regtest start");
        // Core v31 blocks IPC work while IBD is active; a short chain of
        // recent blocks exits it.
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
}

#[cfg(test)]
mod base_allocate_tests {
    //! The §6.4.3 base-protocol allocate: which miners get a token at
    //! all, and what the pool designates when they do.
    use super::*;

    const MINER: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    const OTHER: &str = "bcrt1qvs8k07ggszru23v9p42vpg4jxts9y2k8kkujja";

    /// The revenue the fixture's template pays. Deliberately NOT a round
    /// subsidy: the assertion that matters is that this exact number is
    /// what reaches the resolver, and a value that coincides with any
    /// constant in the code could pass while the wiring was wrong.
    const TEMPLATE_REVENUE: u64 = 316_042_137;

    /// A resolver that answers with a fixed payout list — the only thing
    /// the allocate path asks it, and the thing every payout guard in
    /// production expresses itself through. It also records the reward it
    /// was asked at, because in production that number is not discarded:
    /// it is written into the settlement snapshot (see
    /// [`ProductionJdpAllocateResolver`]).
    use bp_mining_job::PayoutEntry;

    struct FixedPayouts {
        entries: Vec<PayoutEntry>,
        asked_at: StdMutex<Vec<u64>>,
        /// The stream this miner's shares enter. Spelled out rather than
        /// left to the trait default, because the default is `Pplns` and
        /// the base path is Solo-only — a double that took the default
        /// would refuse every fixture below for the wrong reason.
        stream: StreamKind,
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
    }

    /// Stands in for the TDP snapshot. `None` is the pre-first-template
    /// state, which is a real state and not a test artefact.
    struct TemplateAt(Option<u64>);
    impl ChainView for TemplateAt {
        fn demands(&self) -> Option<ChainDemands> {
            // The allocate path never asks what the tip must satisfy — that
            // question belongs to the block-found side.
            None
        }
        fn reference_revenue(&self) -> Option<u64> {
            self.0
        }
    }

    /// A resolver on a pool that HAS a template, which is the ordinary case.
    /// Solo, because that is the only stream the base path serves.
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
        assert_eq!(outputs.len(), 1, "§6.4.3 designates exactly ONE output");
        assert_eq!(
            outputs[0].value,
            bitcoin::Amount::ZERO,
            "§6.4.3: the designated output goes out with a 0 amount — a conformant \
             JD-client overwrites it with its own template revenue, and any OTHER \
             valued output would then push the coinbase past what the block pays"
        );
        outputs[0].script_pubkey.clone()
    }

    /// The plain case: no fee configured, so the resolver names one payee —
    /// the miner — and that is what gets designated.
    #[tokio::test]
    async fn a_single_payee_is_designated_at_zero_sats() {
        let ctx = granted(
            pays(&[(MINER, 312_500_000)])
                .resolve_allocate_context(MINER, "127.0.0.1:1", false)
                .await,
        );
        assert_eq!(ctx.miner_address.as_str(), MINER);
        assert_eq!(
            designated_script(&ctx),
            bp_mining_job::address_to_script(BitcoinNetwork::Regtest, MINER).unwrap()
        );
    }

    /// MONEY: a block the resolver routes AWAY from the miner cannot be
    /// served on the base protocol at all.
    ///
    /// The live case is a Blockparty admin whose party is still DRAFT: it
    /// resolves to the Solo *mode*, but `resolve_payouts` sends 100 % to the
    /// pool fee address so the admin cannot pocket a block before the
    /// members confirm their splits. Asking the mode instead of the payout
    /// list would hand the admin its own address — which is why the allocate
    /// goes through the resolver at all, and this test is what pins that.
    ///
    /// Designating the fee script is NOT enough, though, and that was the
    /// bug: §6.4.3 lets the pool check only that the script was paid, never
    /// how much (it names no threshold and answers a shortfall
    /// economically), so the admin's JDC satisfies it with one satoshi and
    /// keeps the block. The guard survives only by refusing.
    #[tokio::test]
    async fn a_block_routed_away_from_the_miner_is_refused_on_the_base_protocol() {
        let outcome = pays(&[(OTHER, 312_500_000)])
            .resolve_allocate_context(MINER, "127.0.0.1:1", false)
            .await;
        assert!(
            matches!(outcome, AllocateOutcome::Refused { .. }),
            "a pending-party route must refuse the token, not designate a script the JDC \
             can satisfy with 1 sat"
        );
    }

    /// The counterpart, so the rule above is a routing test and not "the
    /// base protocol is off": the very same shape — one payee, whole block —
    /// is served when that payee IS the miner. This is the case §6.4.3's
    /// pay-something check actually covers, because shorting the designated
    /// output then shorts the miner itself.
    #[tokio::test]
    async fn the_same_single_payee_shape_is_served_when_it_is_the_miner() {
        let ctx = granted(
            pays(&[(MINER, 312_500_000)])
                .resolve_allocate_context(MINER, "127.0.0.1:1", false)
                .await,
        );
        assert_eq!(
            designated_script(&ctx),
            bp_mining_job::address_to_script(BitcoinNetwork::Regtest, MINER).unwrap()
        );
    }

    /// ext 0x0003 is the way out: it expresses the routed payout the base
    /// path has to refuse, and §7.1 recomputes the coinbase against it — so
    /// the admin's own JDC is held to paying the fee address in full.
    #[tokio::test]
    async fn a_negotiated_session_still_serves_a_routed_payout() {
        let ctx = granted(
            pays(&[(OTHER, 312_500_000)])
                .resolve_allocate_context(MINER, "127.0.0.1:1", true)
                .await,
        );
        assert!(ctx.coinbase_outputs.is_empty());
    }

    /// A split needs more than one valued output, which §6.4.3 cannot
    /// express — refuse rather than serve a token whose block silently pays
    /// only the first payee. This is what makes a configured solo fee take
    /// effect instead of evaporating, and it covers every shared-payout
    /// mode (PPLNS, Group-Solo) for the same reason.
    #[tokio::test]
    async fn a_split_payout_is_refused_rather_than_silently_dropped() {
        let outcome = pays(&[(OTHER, 3_125_000), (MINER, 309_375_000)])
            .resolve_allocate_context(MINER, "127.0.0.1:1", false)
            .await;
        assert!(
            matches!(outcome, AllocateOutcome::Refused { .. }),
            "a two-payee split must be refused, not truncated to one output"
        );
    }

    /// An empty list means the resolver could not say who the block belongs
    /// to. Serving a token then would designate nobody.
    #[tokio::test]
    async fn an_empty_payout_list_is_refused() {
        let outcome = pays(&[])
            .resolve_allocate_context(MINER, "127.0.0.1:1", false)
            .await;
        assert!(matches!(outcome, AllocateOutcome::Refused { .. }));
    }

    /// With ext 0x0003 negotiated the base convention does not apply at all:
    /// §2 requires empty outputs, and the pushed distribution carries the
    /// payouts — including the splits the base path has to refuse.
    #[tokio::test]
    async fn a_negotiated_session_gets_no_outputs_and_is_served_on_any_split() {
        let ctx = granted(
            pays(&[(OTHER, 3_125_000), (MINER, 309_375_000)])
                .resolve_allocate_context(MINER, "127.0.0.1:1", true)
                .await,
        );
        assert!(
            ctx.coinbase_outputs.is_empty(),
            "§2 requires empty coinbase_tx_outputs when 0x0003 is negotiated"
        );
    }

    /// An identifier that is not an address SHAPE at all is IGNORED, not
    /// refused: refusing closes the connection, and that verdict is
    /// reserved for "the pool cannot serve this miner", not for a frame it
    /// could not read. (`parse_user_identifier_as_address` checks shape
    /// only — length and character class — so it takes an over-long string
    /// to fail it, not merely a non-address word.)
    #[tokio::test]
    async fn an_unparseable_identifier_is_ignored_not_refused() {
        let outcome = pays(&[(MINER, 1)])
            .resolve_allocate_context(&"x".repeat(200), "127.0.0.1:1", false)
            .await;
        assert!(matches!(outcome, AllocateOutcome::Ignored));
    }

    /// MONEY: the payout list must be resolved at the pool's LIVE template
    /// revenue, not at a stand-in.
    ///
    /// It reads like a number nobody uses — §6.4.3 leaves the amounts to
    /// the JDC and the sats here are thrown away. But `resolve_payouts` is
    /// not a query: for PPLNS it runs `build_distribution`, which writes
    /// this very number into `referenceRevenueSats` of the settlement
    /// snapshot at `pplns:snapshot:fp:<fingerprint>` — and the fingerprint
    /// is revenue-independent (`fingerprint_ignores_reference_revenue`), so
    /// it is the SAME key the mining path's build writes. Settlement then
    /// re-projects every ledger promise from it
    /// (`StoredWeightSnapshot::extras_total`), which is what makes a
    /// fabricated revenue here a wrong `claim − paid` on a real block.
    ///
    /// Asking with `bp_share::INITIAL_BLOCK_SUBSIDY_SATS` (50 BTC, ~16× a
    /// post-halving block) is what this pins shut.
    #[tokio::test]
    async fn the_payout_list_is_resolved_at_the_live_template_revenue() {
        let (resolver, payouts) = resolver_with(&[(MINER, 1)], Some(TEMPLATE_REVENUE));
        let _ = resolver
            .resolve_allocate_context(MINER, "127.0.0.1:1", false)
            .await;
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

    /// The other half: before the first template there is no revenue, and
    /// the answer is to refuse — NOT to estimate one. An estimate would
    /// reach the same shared snapshot key as the real build and rewrite its
    /// projection base, which is the same bug the test above pins, one
    /// order of magnitude smaller.
    ///
    /// Refusing costs the JDC nothing it would have had: with no template
    /// the pool serves no jobs at all, and an SRI jd-client reconnects on a
    /// closed socket, so the next allocate lands once TDP has delivered.
    #[tokio::test]
    async fn no_template_refuses_instead_of_resolving_against_a_guess() {
        let (resolver, payouts) = resolver_with(&[(MINER, 1)], None);
        let outcome = resolver
            .resolve_allocate_context(MINER, "127.0.0.1:1", false)
            .await;
        assert!(
            matches!(outcome, AllocateOutcome::Refused { .. }),
            "no template must refuse, not serve a token off an invented revenue"
        );
        assert!(
            payouts.asked_at.lock().unwrap().is_empty(),
            "the resolver must not be CALLED at all — the call itself is the write"
        );
    }

    /// A negotiated session needs no revenue: §2 empties the outputs, so
    /// nothing is resolved and nothing is written. It must therefore still
    /// be served before the first template — the refusal above belongs to
    /// the base path alone.
    #[tokio::test]
    async fn a_negotiated_session_is_served_before_the_first_template() {
        let (resolver, payouts) = resolver_with(&[(MINER, 1)], None);
        let ctx = granted(
            resolver
                .resolve_allocate_context(MINER, "127.0.0.1:1", true)
                .await,
        );
        assert!(ctx.coinbase_outputs.is_empty());
        assert!(
            payouts.asked_at.lock().unwrap().is_empty(),
            "0x0003 resolves no payout list, so it writes no snapshot either"
        );
    }

    /// The base path is Solo-only, and the refusal has to happen HERE — the
    /// mining side's `custom-jobs-require-solo` is fatal for an SRI
    /// jd-client, so a token issued off Solo is a token every job built on it
    /// dies with.
    ///
    /// The payout list is deliberately the ONE shape §6.4.3 can carry: a
    /// single payee who is the miner. That is what a Blockparty group falls
    /// back to on its four `solo_payouts` error paths when no dev fee is
    /// configured — i.e. the list agrees while the stream does not, which is
    /// exactly why the list cannot answer this question.
    #[tokio::test]
    async fn a_shared_stream_is_refused_a_base_protocol_token() {
        for stream in [
            StreamKind::Pplns,
            StreamKind::GroupSolo,
            StreamKind::Blockparty,
        ] {
            let (resolver, payouts) =
                resolver_on(&[(MINER, 312_500_000)], Some(TEMPLATE_REVENUE), stream);
            let outcome = resolver
                .resolve_allocate_context(MINER, "127.0.0.1:1", false)
                .await;
            assert!(
                matches!(outcome, AllocateOutcome::Refused { .. }),
                "{stream:?}: the mining side would refuse every job on this token"
            );
            // The other half of the same fix: the refusal must cost nothing.
            // `resolve_payouts` WRITES the PPLNS settlement snapshot, and a
            // refusal closes the connection — an SRI jd-client reconnects, so
            // a resolve here would repeat that write per reconnect with no
            // rate limit in reach (§6.4.2 lives in `TokenStore::allocate`,
            // which a refused allocate never reaches).
            assert!(
                payouts.asked_at.lock().unwrap().is_empty(),
                "{stream:?}: a refused allocate must not resolve — the call itself is the write"
            );
        }
    }

    /// The negative control: the very same payout list on the Solo stream IS
    /// served. Without it, "shared streams are refused" would read the same
    /// as "the base path is off".
    #[tokio::test]
    async fn the_same_payout_list_is_served_on_the_solo_stream() {
        let (resolver, payouts) = resolver_on(
            &[(MINER, 312_500_000)],
            Some(TEMPLATE_REVENUE),
            StreamKind::Solo,
        );
        let ctx = granted(
            resolver
                .resolve_allocate_context(MINER, "127.0.0.1:1", false)
                .await,
        );
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

    /// The stream gate must not swallow the payout-list guard it now sits in
    /// front of. A Blockparty admin whose party is still DRAFT resolves to
    /// the Solo *stream*, so it passes the gate — and `resolve_payouts` then
    /// routes 100 % of the block to the pool fee address, which §6.4.3 cannot
    /// enforce. Both checks have to fire, in that order.
    #[tokio::test]
    async fn a_solo_stream_routed_away_from_the_miner_is_still_refused() {
        let (resolver, payouts) = resolver_on(
            &[(OTHER, 312_500_000)],
            Some(TEMPLATE_REVENUE),
            StreamKind::Solo,
        );
        let outcome = resolver
            .resolve_allocate_context(MINER, "127.0.0.1:1", false)
            .await;
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

    /// A negotiated session is unaffected: §2 empties the outputs, the pool's
    /// published distribution carries the payouts, and every stream is served
    /// — the Solo-only rule belongs to the base path alone.
    #[tokio::test]
    async fn a_negotiated_session_is_served_on_a_shared_stream() {
        let (resolver, payouts) = resolver_on(
            &[(OTHER, 3_125_000), (MINER, 309_375_000)],
            Some(TEMPLATE_REVENUE),
            StreamKind::Pplns,
        );
        let ctx = granted(
            resolver
                .resolve_allocate_context(MINER, "127.0.0.1:1", true)
                .await,
        );
        assert!(ctx.coinbase_outputs.is_empty());
        assert!(payouts.asked_at.lock().unwrap().is_empty());
    }
}

#[cfg(test)]
mod jdp_validation_socket_tests {
    use super::*;
    use std::path::PathBuf;

    /// The prod layout: one named docker volume at `/ipc`, mainnet, so upstream
    /// derives `<dir>/node.sock` with no network subdirectory. Checked against
    /// the live pool on 2026-08-03 — `[tdp] socket_path = "/ipc/node.sock"`.
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

    /// Off mainnet upstream inserts the network directory, so the same data dir
    /// implies a deeper socket path.
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

    /// A socket upstream can never be pointed at must be refused, not
    /// approximated. Silently connecting to `/var/run/bitcoind/node.sock` when
    /// the operator wrote `bp-tdp.sock` would validate against the wrong thing
    /// — or nothing — while the log says validation is on.
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

    /// The prod path on a non-mainnet network is a mismatch too: the same
    /// `/ipc/node.sock` cannot serve testnet4, where upstream looks one level
    /// deeper. Better to fail boot than to run unvalidated.
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
        /// Blocks recorded WITHOUT a ledger entry — kept apart from `booked`
        /// so the two outcomes cannot be confused by an assertion.
        recorded: StdMutex<Vec<String>>,
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
            _: Option<bp_coinbase_snapshot::ActualCoinbase>,
        ) -> bool {
            self.booked.lock().unwrap().push((reward, fp));
            self.hashes.lock().unwrap().push(block_hash);
            !self.wrote_nothing
        }

        async fn record_unbookable(
            &self,
            _: String,
            _: String,
            block_hash: String,
            _: String,
        ) -> bool {
            // Recorded in its OWN list, not in `booked` — a test that cannot
            // tell "wrote the row" from "wrote the ledger" would pass on
            // either, which is the whole distinction being built here.
            self.recorded.lock().unwrap().push(block_hash);
            !self.wrote_nothing
        }
    }

    /// Carries a tip and nothing else. `reference_revenue` is `None` and
    /// that is the truthful answer, not a stub: this double is built from a
    /// [`ChainDemands`] alone, so it holds no template — and the booking
    /// path below never asks, because a JDC-found block's revenue comes
    /// from its own coinbase.
    struct FixedChain(Option<ChainDemands>);
    impl ChainView for FixedChain {
        fn demands(&self) -> Option<ChainDemands> {
            self.0
        }
        fn reference_revenue(&self) -> Option<u64> {
            None
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
        /// As for [`FixedChain`]: a tip double holds no template.
        fn reference_revenue(&self) -> Option<u64> {
            None
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
            network: BitcoinNetwork::Regtest,
            propagator: propagator.map(|p| p as Arc<dyn BlockPropagator>),
            booker: booker.map(|b| b as Arc<dyn DeclaredBlockBooker>),
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
            sink_with_halves(Some(propagator.clone()), Some(booker.clone()), chain),
            propagator,
            booker,
        )
    }

    async fn push(sink: &ProductionJdpBlockSink, backing: CandidateBacking, nonce: u32) {
        sink.submit_block_candidate(
            AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap(),
            Token([9u8; 16]),
            backing,
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
            distribution_id: 7,
            payouts_fingerprint: [0x11; 32],
            reference_reward_sats: 5_000_000_000,
        }
    }

    // ── §10 settle: separate from the booking, on purpose ──────────
    //
    // Settling means "these published weights are spent". Booking means
    // "write the ledger deltas". The first is owed the moment a proven block
    // pays a published distribution; the second needs settlement inputs that
    // may not exist. Deriving both from one `Option` fired neither in the
    // case that matters, and the published weights encode pre-settlement
    // balances — so the next block paid them a second time.

    /// A sink whose settle signal is wired to a real registry holding one
    /// published pool-wide distribution, so the test can watch it disappear.
    fn sink_and_published_distribution(
        booker: Option<Arc<RecordingBooker>>,
        chain: Option<ChainDemands>,
    ) -> (
        ProductionJdpBlockSink,
        Arc<std::sync::RwLock<bp_stratum_v2::bridge::JdpDeclaredJobRegistry>>,
        bp_stratum_v2::jdp_server::StratumV2JdpServer,
    ) {
        use bp_stratum_v2::bridge::{JdpDeclaredJobRegistry, PayoutDistributionEntry};
        use bp_stratum_v2::jdp::payout_distribution::WeightedOutput;
        use bp_stratum_v2::jdp_server::{JdpServerHooks, StratumV2JdpServer};
        use bp_stratum_v2::noise::{NoiseConfig, DEFAULT_CERT_VALIDITY};

        let bridge = Arc::new(std::sync::RwLock::new(JdpDeclaredJobRegistry::new()));
        bridge
            .write()
            .unwrap()
            .publish_pool_wide(PayoutDistributionEntry {
                distribution_id: 7,
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
                owner: None,
                jdp_session_id: None,
                published_at_ms: 1_001,
            });
        let noise = NoiseConfig::parse_strings(
            "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72",
            "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n",
            DEFAULT_CERT_VALIDITY,
        )
        .expect("noise config");
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
            booker: booker.map(|b| b as Arc<dyn DeclaredBlockBooker>),
            settle,
            chain: Arc::new(FixedChain(chain)),
            booked: StdMutex::new(VecDeque::new()),
        };
        (sink, bridge, server)
    }

    /// A target the fixture's header actually meets, so `block_is_proven`
    /// passes and the settle is reached.
    fn met_by_the_fixture() -> ChainDemands {
        ChainDemands {
            prev_hash: [0u8; 32],
            target: [0xFFu8; 32],
        }
    }

    /// MONEY: a block on a distribution whose settlement snapshot never
    /// landed still SETTLES it.
    ///
    /// Nothing can be booked — there are no inputs — but the coinbase has
    /// paid the published weights on-chain. Leaving them published means the
    /// next distribution promises the same balances again, which the pool's
    /// own code calls out: "a 0x0003 JDC still mining them would pay those
    /// balances out a second time" (`block_sink.rs`).
    #[tokio::test(flavor = "current_thread")]
    async fn an_unbookable_distribution_is_still_settled() {
        let booker = Arc::new(RecordingBooker::default());
        let (sink, bridge, server) =
            sink_and_published_distribution(Some(booker.clone()), Some(met_by_the_fixture()));
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

    /// A block the pool cannot book must still be RECORDED — otherwise it
    /// exists on-chain and in no API, no UI and no history, and the only
    /// trace is a log line that rotates away.
    ///
    /// The two halves are asserted separately on purpose: the row must
    /// appear, and the ledger must stay untouched. An assertion that could
    /// not tell them apart would pass on "booked it anyway", which would book
    /// `claim − paid` against settlement inputs that do not exist.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unbookable_block_is_recorded_but_not_booked() {
        let booker = Arc::new(RecordingBooker::default());
        let (sink, _bridge, server) =
            sink_and_published_distribution(Some(booker.clone()), Some(met_by_the_fixture()));

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

    /// The counterpart: a BASE-PROTOCOL block must reach neither the record
    /// nor the ledger on this path. The mining side already records that one
    /// off its own share, and `blocks_entity` has no `ON CONFLICT` — a second
    /// write is a duplicate row for one block.
    ///
    /// What this pins is the OUTCOME, not the match arm. Such a candidate
    /// never reaches `settle_and_book` at all: with no booking, no published
    /// distribution and no propagator it returns at the "nothing downstream
    /// wants this block" gate. Both barriers have to fall for a duplicate to
    /// appear, and this test notices either way — but if you are changing the
    /// arm, know that this test alone will not catch you.
    #[tokio::test(flavor = "current_thread")]
    async fn a_base_protocol_block_is_not_recorded_twice() {
        let booker = Arc::new(RecordingBooker::default());
        let (sink, _bridge, server) =
            sink_and_published_distribution(Some(booker.clone()), Some(met_by_the_fixture()));

        push(&sink, CandidateBacking::BaseProtocol, 1).await;

        assert!(
            booker.recorded.lock().unwrap().is_empty(),
            "the mining side owns this one — recording it here too duplicates the row"
        );
        assert!(booker.booked.lock().unwrap().is_empty());
        server.shutdown().await;
    }

    /// The other half of the same split: a booking that WROTE NOTHING must
    /// still settle. The ledger retry stays open (that is deliberate), but
    /// the weights are spent either way.
    #[tokio::test(flavor = "current_thread")]
    async fn a_booking_that_wrote_nothing_still_settles() {
        let booker = Arc::new(RecordingBooker::that_writes_nothing());
        let (sink, bridge, server) =
            sink_and_published_distribution(Some(booker.clone()), Some(met_by_the_fixture()));

        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;

        assert_eq!(
            booker.booked.lock().unwrap().len(),
            1,
            "precondition: the booking was attempted and reported writing nothing"
        );
        assert!(
            bridge.read().unwrap().current_pool_wide().is_none(),
            "a failed ledger write does not un-spend the published weights"
        );
        server.shutdown().await;
    }

    /// The negative controls, both of them, because "settles" would
    /// otherwise read the same as "settles on anything".
    ///
    /// - A base-protocol declaration published nothing, so there is nothing
    ///   to invalidate — settling would throw away a live distribution
    ///   belonging to other miners.
    /// - An UNPROVEN solution must not settle at all: `PushSolution` is the
    ///   client's claim, and if a claim could invalidate distributions, any
    ///   JDC could wipe the pool's published weights on demand.
    #[tokio::test(flavor = "current_thread")]
    async fn nothing_settles_without_a_published_distribution_or_without_proof() {
        let (sink, bridge, server) =
            sink_and_published_distribution(None, Some(met_by_the_fixture()));
        push(&sink, CandidateBacking::BaseProtocol, 1).await;
        assert!(
            bridge.read().unwrap().current_pool_wide().is_some(),
            "a base-protocol block settles nothing"
        );
        server.shutdown().await;

        // Same block, same backing that WOULD settle — but the chain demands
        // a target the fixture header cannot meet.
        let impossible = ChainDemands {
            prev_hash: [0u8; 32],
            target: [0u8; 32],
        };
        let (sink, bridge, server) = sink_and_published_distribution(None, Some(impossible));
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

    /// The resubmit is the pool's anti-orphan redundancy. It must happen for
    /// every candidate, whatever the ledger decides — dropping it would
    /// silently disable block propagation while bookings kept working.
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
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
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
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
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
            network: BitcoinNetwork::Regtest,
            propagator: Some(Arc::new(PropagatorThatMovesTheTip {
                chain: chain.clone(),
                to: moved_on,
            })),
            booker: Some(booker.clone()),
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
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
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
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
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
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
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
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
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
        push(&sink, CandidateBacking::Bookable(a_booking()), 42).await;
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
        push(&sink, CandidateBacking::BaseProtocol, 1).await;
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
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
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
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
        push(&sink, CandidateBacking::Bookable(a_booking()), 1).await;
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

    /// Closes the last gap between this check and the proof that it agrees with
    /// bitcoin-core.
    ///
    /// The regtests that establish the target reading empirically — take a real
    /// `SetNewPrevHash.target`, read it with `Target::from_le_bytes`, brute-force
    /// a nonce until `is_met_by_le` accepts, submit, assert the tip rises — feed
    /// that comparison `bp_share::sha256d(&header_bytes)`. This check feeds it
    /// `header.block_hash().to_byte_array()` instead. Both are meant to be the
    /// same little-endian digest, and everything above rests on that, so it is
    /// asserted here rather than assumed. If the two ever diverge, the work check
    /// silently stops meaning what those regtests proved.
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
}
