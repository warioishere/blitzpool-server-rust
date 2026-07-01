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
//! 4. **[`JdpRpcBlockSubmissionSink`]** — on a JDC `PushSolution`,
//!    reconstructs the full SegWit block from (a) the declared
//!    coinbase prefix+suffix + JDC extranonce (witness-formed via
//!    [`bp_stratum_v2::mining::submit::assemble_witness_coinbase`]),
//!    (b) the JDC-supplied raw transactions from
//!    `JdpSessionEvent::BlockSubmissionCandidate.transactions`, and
//!    (c) the header fields. Computes the merkle root,
//!    consensus-serialises the block, and submits via
//!    [`BitcoinRpc::submit_block`]. This is the **orphan-protection
//!    redundancy** path: the JDC also submits via its own TDP
//!    connection; the pool-side submit is a hot-path Anti-Orphan
//!    measure consistent with the SV2 spec §6.4.9 "JDS SHOULD propagate".

use std::collections::HashMap;
use std::sync::Arc;

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
    DynamicOutput,
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
/// `orphan_submitblock_enabled` controls the block-submission sink:
/// `true` → real RPC resubmit (full anti-orphan redundancy);
/// `false` → log-only NoOp (SRI behaviour, JDC
/// is the sole propagator). Source: `[sv2].jdp_orphan_submitblock`
/// in the TOML.
pub(crate) fn build_jdp_hooks(
    tdp: TdpHandle,
    bitcoin_rpc: BitcoinRpc,
    payout_resolver: Arc<ProductionPayoutResolver>,
    template_tx_cache: Option<Arc<TemplateTxCache>>,
    network: BitcoinNetwork,
    orphan_submitblock_enabled: bool,
) -> JdpServerHooks {
    let block_sink: Arc<dyn JdpBlockSubmissionSink> = if orphan_submitblock_enabled {
        info!(
            "jdp: orphan-protection submitblock RPC ENABLED \
             (`[sv2].jdp_orphan_submitblock = true`)"
        );
        Arc::new(JdpRpcBlockSubmissionSink { bitcoin_rpc })
    } else {
        info!(
            "jdp: orphan-protection submitblock RPC DISABLED — JDC is sole \
             block propagator (set `[sv2].jdp_orphan_submitblock = true` to enable \
             pool-side resubmit for commercial JDC deployments)"
        );
        Arc::new(LogOnlyBlockSubmissionSink)
    };
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

// ─── LogOnlyBlockSubmissionSink (orphan-resubmit off) ────────────

/// [`JdpBlockSubmissionSink`] impl that logs the block-found event
/// at INFO and returns. Matches SRI's reference pool behaviour: JDC
/// is the sole block propagator via its own `TdpHandle::submit_solution`.
pub(crate) struct LogOnlyBlockSubmissionSink;

#[async_trait]
impl JdpBlockSubmissionSink for LogOnlyBlockSubmissionSink {
    async fn submit_block_candidate(
        &self,
        miner_address: AddressId,
        new_token: Token,
        coinbase_raw: Vec<u8>,
        transactions: Vec<Vec<u8>>,
        prev_hash: [u8; 32],
        version: u32,
        ntime: u32,
        nonce: u32,
        _n_bits: u32,
    ) {
        let _ = (coinbase_raw, transactions, prev_hash, version, ntime, nonce);
        info!(
            miner = miner_address.as_str(),
            token = ?new_token,
            "JDP block-candidate received; pool-side resubmit disabled — JDC \
             propagates via its own TDP submit_solution. Enable \
             `[sv2].jdp_orphan_submitblock` for anti-orphan redundancy."
        );
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

        // Convert PayoutEntry (address + percent) → DynamicOutput
        // (address + sats) by applying the percent to reward_sats.
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

// ─── 4. JdpRpcBlockSubmissionSink ────────────────────────────────

pub(crate) struct JdpRpcBlockSubmissionSink {
    bitcoin_rpc: BitcoinRpc,
}

#[async_trait]
impl JdpBlockSubmissionSink for JdpRpcBlockSubmissionSink {
    async fn submit_block_candidate(
        &self,
        miner_address: AddressId,
        new_token: Token,
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
            "JDP block-candidate received; reconstructing for submitblock"
        );

        // 1. Convert non-witness coinbase to witness form (BIP-141
        //    marker + flag + reserved witness value). Required for
        //    bitcoin-core to accept a SegWit block.
        let coinbase_witness_bytes = assemble_witness_coinbase(&coinbase_raw);
        let coinbase_tx: Transaction =
            match Transaction::consensus_decode(&mut coinbase_witness_bytes.as_slice()) {
                Ok(t) => t,
                Err(err) => {
                    warn!(%err, "JDP submit: coinbase tx parse failed; skipping submit");
                    return;
                }
            };

        // 2. Parse every JDC-provided non-coinbase tx. Per the SV2
        //    spec, `transactions` from `ProvideMissingTransactions.Success`
        //    + cached entries come in witness-serialised form.
        let mut txdata: Vec<Transaction> = Vec::with_capacity(1 + transactions.len());
        txdata.push(coinbase_tx);
        for (i, raw) in transactions.iter().enumerate() {
            match Transaction::consensus_decode(&mut raw.as_slice()) {
                Ok(tx) => txdata.push(tx),
                Err(err) => {
                    warn!(%err, idx = i, "JDP submit: tx parse failed; skipping submit");
                    return;
                }
            }
        }

        // 3. Build a block with a placeholder merkle root, then
        //    compute the real root from the assembled tx list and
        //    patch the header.
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
            warn!("JDP submit: merkle root compute returned None (empty block?); using zero");
            TxMerkleNode::all_zeros()
        });
        header = block.header;
        header.merkle_root = merkle_root;
        block.header = header;

        // 4. Serialise + submit.
        let block_hex = serialize_hex(&block);
        let block_bytes = block_hex.len() / 2;
        info!(
            block_bytes,
            tx_count = block.txdata.len(),
            "JDP submit: dispatching submitblock RPC"
        );
        match self.bitcoin_rpc.submit_block(block_hex).await {
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
        if let Some(t) = self.tdp.current_snapshot().new_template {
            // 2× tolerance for mempool fee variance; rejects clearly
            // implausible (>2× current template value).
            let ceiling = t.coinbase_tx_value_remaining.saturating_mul(2);
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
        let payouts = bp_stratum_v2::hooks::PayoutResolver::resolve_payouts(
            &*self.payout_resolver,
            miner_address,
            available_payout_value,
        )
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
