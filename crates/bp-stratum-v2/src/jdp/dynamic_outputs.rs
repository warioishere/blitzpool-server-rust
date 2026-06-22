// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ext 0x0003 (Non-Custodial Pool Payouts) — pure-logic helpers.
//!
//! The handler-layer in `jdp::client` (deferred) wires these together
//! when `RequestPayoutOutputs` arrives:
//!
//! 1. Resolve the distribution per mining-mode (PPLNS / group-solo /
//!    solo), applying the pool's dust floor + a revenue-plausibility
//!    guard. I/O — happens at the handler/resolver layer (see
//!    `bin/blitzpool::jdp_hooks::ProductionPayoutOutputsResolver`).
//! 2. Call [`fold_residual_to_exact_sum`] so the kept outputs sum
//!    **exactly** to `available_payout_value` (spec §2.2:
//!    `Σ MUST equal available_payout_value`): the floor-rounding loss
//!    plus any dropped sub-dust sats fold into the largest kept output.
//! 3. Encode to consensus-serialised `Vec<TxOut>` via
//!    [`encode_coinbase_outputs`]. The output bytes go in
//!    `RequestPayoutOutputs.Success.coinbase_tx_outputs` AND get
//!    recorded by [`PayoutOutputsTracker::record`] as a single-use
//!    pending set so a later `DeclareMiningJob` can be validated
//!    against the exact pool-committed outputs.
//! 4. At declare-time, [`PayoutOutputsTracker::validate_and_consume_for_declare`]
//!    confirms the declared coinbase carries the pending set, marks it
//!    used (spec §4: single-use), and rejects unknown / already-used /
//!    stale sets.
//! 5. [`PayoutOutputsTracker::observe_epoch`] tracks the pool's own
//!    `current_prev_hash`; when the chain tip advances it marks pending
//!    sets stale (they reference a superseded payout window) and drops
//!    spent + previously-stale ones. This is the pool's internal
//!    accounting state — there is no `prev_hash` on the wire (spec §4
//!    freshness is validator-side).
//!
//! ## What this module deliberately doesn't do
//!
//! - **Mode resolution** (PPLNS / group-solo / solo). Lives in the
//!   handler-layer because it touches `bp-mining-mode` +
//!   `bp-pplns` + `bp-group-solo` service-state.
//! - **Network / template I/O**. `latest_coinbase_value`,
//!   `current_prev_hash`, the JDC's `available_payout_value` request —
//!   all provided by the caller.
//! - **Wire deserialisation** of the `RequestPayoutOutputs`
//!   frame. That's `crate::extensions::RequestPayoutOutputs::deserialize`.

use std::collections::HashMap;

use bitcoin::consensus::Encodable;
use bitcoin::{Amount, Network, TxOut};
use bp_common::{AddressId, Sats};
use bp_mining_job::address_to_script;

use crate::tokens::Token;

// ── Re-exports of wire-error codes ──────────────────────────────────
//
// The canonical strings live in `crate::extensions` next to the
// `RequestPayoutOutputs*` codecs; re-export here so handler code
// has them in one place per concern.
pub use crate::extensions::payout_outputs_error_codes::{
    COINBASE_SIZE_BUDGET_EXCEEDED, INTERNAL, INVALID_MINING_JOB_TOKEN, REVENUE_TOO_LARGE,
    STALE_PAYOUT_OUTPUTS,
};

// ── DynamicOutput ────────────────────────────────────────────────────

/// One entry in the dynamic-output distribution. The handler-layer
/// fills these from a PPLNS / group-solo / solo distribution and
/// hands the list to [`fold_residual_to_exact_sum`] + [`encode_coinbase_outputs`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicOutput {
    pub address: AddressId,
    pub sats: Sats,
}

// ── Errors ───────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    /// Address didn't parse or didn't match the configured network
    /// (delegated to `bp_mining_job::address_to_script`). Caller
    /// maps to the wire code [`INTERNAL`] — a misconfigured pool
    /// shouldn't leak a specific address-validation error to the
    /// JDC.
    #[error("address-to-script failed: {0}")]
    InvalidAddress(String),
    /// `bitcoin::consensus::encode` failure. Shouldn't fire in
    /// practice (we write to a `Vec<u8>`) but kept total so the
    /// caller can map to [`INTERNAL`].
    #[error("consensus encoding: {0}")]
    Consensus(String),
}

// ── fold_residual_to_exact_sum ──────────────────────────────────────

/// Adjust `outputs` in place so their amounts sum **exactly** to
/// `target_sats`, folding any residual into the largest output.
///
/// The residual = `target_sats − Σ(outputs)`. In normal use it is a
/// small *positive* value: the floor-rounding loss from a per-recipient
/// percentage split plus the sats of any sub-dust entries that were
/// dropped. Spec #202 §2.2 requires the returned set to sum to exactly
/// `available_payout_value`, so the remainder cannot be silently
/// forfeited — it is assigned to the largest kept output (the pool's
/// payout policy; mirrors the TS `coinbase-distribution.ts` Phase-5b
/// residual redistribution).
///
/// No-op on an empty slice (the caller must treat an empty output set
/// against a positive `target_sats` as "cannot construct a valid set").
/// Pure aside from the in-place mutation; no allocation.
pub fn fold_residual_to_exact_sum(outputs: &mut [DynamicOutput], target_sats: i64) {
    if outputs.is_empty() {
        return;
    }
    let current: i64 = outputs.iter().map(|d| d.sats.to_i64()).sum();
    let residual = target_sats - current;
    if residual == 0 {
        return;
    }
    if residual > 0 {
        // Surplus (floor-rounding loss + dropped sub-dust) → largest output.
        // `current + residual == target` and the largest stays positive.
        let max_idx = (0..outputs.len())
            .max_by_key(|&i| outputs[i].sats.to_i64())
            .unwrap_or(0);
        let folded = outputs[max_idx].sats.to_i64() + residual;
        outputs[max_idx].sats = Sats(folded);
        return;
    }
    // residual < 0: the distribution overshoots `target_sats`. A
    // resolver-built set never does this (Σ floor(pct·value) ≤ value), but
    // the helper must stay sound rather than clamp one output negative and
    // silently break the Σ invariant. Trim the excess from the largest
    // outputs downward, never below zero. Since `target_sats ≥ 0` the total
    // overshoot (≤ current) is always fully absorbable.
    let mut overshoot = -residual;
    let mut idx: Vec<usize> = (0..outputs.len()).collect();
    idx.sort_by_key(|&i| std::cmp::Reverse(outputs[i].sats.to_i64()));
    for &i in idx.iter() {
        if overshoot == 0 {
            break;
        }
        let v = outputs[i].sats.to_i64();
        let take = v.min(overshoot);
        outputs[i].sats = Sats(v - take);
        overshoot -= take;
    }
}

// ── encode_coinbase_outputs ─────────────────────────────────────────

/// Serialise `outputs` as a consensus-encoded `Vec<TxOut>` (the wire
/// shape of `RequestPayoutOutputs.Success.coinbase_tx_outputs`).
///
/// Layout (per Bitcoin consensus):
/// - `VarInt(outputs.len())`
/// - Per output: `u64-LE value` + `VarInt(script_len)` + `script_pubkey`
///
/// Address-to-script conversion goes through
/// `bp_mining_job::address_to_script`, which validates network +
/// parses bech32 / legacy / p2tr correctly.
///
/// Empty `outputs` returns `[0x00]` (single varint zero). SV2
/// spec doesn't require non-empty; an empty list is the
/// not-yet-determined / under-construction sentinel.
pub fn encode_coinbase_outputs(
    network: Network,
    outputs: &[DynamicOutput],
) -> Result<Vec<u8>, EncodeError> {
    if outputs.is_empty() {
        return Ok(vec![0x00]);
    }
    // Build TxOuts, then consensus-encode the whole vector.
    let mut txouts = Vec::with_capacity(outputs.len());
    for out in outputs {
        let script = address_to_script(network, out.address.as_str())
            .map_err(|e| EncodeError::InvalidAddress(format!("{e}")))?;
        let value_sats = out.sats.to_i64().max(0) as u64;
        txouts.push(TxOut {
            value: Amount::from_sat(value_sats),
            script_pubkey: script,
        });
    }
    let mut buf = Vec::with_capacity(64 + outputs.len() * 40);
    txouts
        .consensus_encode(&mut buf)
        .map_err(|e| EncodeError::Consensus(format!("{e}")))?;
    Ok(buf)
}

// ── coinbase_outputs_fit_reservation (ext 0x0003 size guard) ────────

/// Does a freshly-built per-job coinbase output set fit the coinbase
/// space the JDC reserved for this token?
///
/// Ext 0x0003 computes the per-job output set fresh from current pool
/// state and the JDC-reported `available_payout_value`. The JDC sized its
/// `coinbase_output_max_additional_size` reservation (against its own
/// Template Provider) from the serialized size of the token's
/// `AllocateMiningJobToken.Success.coinbase_tx_outputs` and cannot grow
/// it mid-job. The per-job set is therefore valid only while its
/// serialized size does not exceed that reserved size; when it would
/// (the payout window grew, or the coinbase budget was raised, since the
/// token was issued) the JDS returns `coinbase-size-budget-exceeded` and
/// the JDC obtains a larger token. Both arguments are the consensus-
/// serialized `Vec<TxOut>` blobs, so comparing their byte lengths is the
/// exact check.
pub fn coinbase_outputs_fit_reservation(candidate: &[u8], reserved: &[u8]) -> bool {
    candidate.len() <= reserved.len()
}

// ── EmittedPayoutOutputs ────────────────────────────────────────────

/// One issued `RequestPayoutOutputs.Success` payout set, tracked as a
/// single-use pending entry (spec §4). Used later by `DeclareMiningJob`
/// validation to confirm the JDC's coinbase carries exactly what the
/// JDS committed to, and to enforce that each set is consumed at most
/// once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmittedPayoutOutputs {
    pub request_id: u32,
    /// Consensus-serialised `Vec<TxOut>` (the bytes returned on the wire).
    pub outputs: Vec<u8>,
    pub emitted_at_ms: u64,
    /// Set once the matching job has been declared (spec §4: single-use).
    pub used: bool,
    /// Set when the chain tip advanced past the epoch this set was
    /// issued under (its payout window is superseded). Marked by
    /// [`PayoutOutputsTracker::observe_epoch`].
    pub stale: bool,
}

// ── Declare-time validation outcome ─────────────────────────────────

/// Outcome of [`PayoutOutputsTracker::validate_and_consume_for_declare`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeclareOutputsCheck {
    /// No payout set was ever issued for this token. With 0x0003
    /// negotiated the caller treats this as a protocol error (a fresh set
    /// is required per declared job, spec §4); the variant itself stays
    /// neutral so a non-negotiated caller can fall through.
    NoneIssued,
    /// The pending set's outputs all appear in the declared coinbase;
    /// the set has been marked used.
    Ok,
    /// A pending set existed but the declared coinbase is missing /
    /// modifies / reduces the output at `index`.
    MissingOutput { index: usize },
    /// The pool-committed output blob didn't parse as a `Vec<TxOut>`.
    UnparsablePoolOutputs,
    /// The declared coinbase didn't parse into an output vector
    /// (fail-closed). Caller rejects with the coinbase-param error.
    UnparsableDeclaredCoinbase,
    /// The token's payout sets are all already used (single-use
    /// violation) — the JDC reused a set or declared without a fresh
    /// request. Caller emits `stale-payout-outputs`.
    AlreadyUsed,
    /// The pending set was superseded by a chain-tip advance since it
    /// was issued. Caller emits `stale-payout-outputs`.
    Stale,
}

// ── PayoutOutputsTracker ────────────────────────────────────────────

/// Per-JDS-connection single-use tracker for issued payout output sets
/// (spec §4). Keyed by `Token`, valued by a list of
/// [`EmittedPayoutOutputs`] (multiple requests per token are legal —
/// same allocation, different `request_id`).
///
/// Freshness is the *pool's own* accounting state, never a wire field:
/// [`observe_epoch`](Self::observe_epoch) is fed the pool's
/// `current_prev_hash`; when the tip advances it marks pending sets
/// stale and drops spent + previously-stale ones, keeping memory
/// bounded as the chain advances (each set survives at most one epoch
/// after going stale). Combined with the per-token TTL (managed by
/// [`crate::tokens`]) each token holds at most a handful of entries.
#[derive(Debug, Default)]
pub struct PayoutOutputsTracker {
    by_token: HashMap<Token, Vec<EmittedPayoutOutputs>>,
    /// Last pool `prev_hash` observed via [`observe_epoch`](Self::observe_epoch).
    /// `None` until the first observation establishes the baseline.
    last_prev_hash: Option<[u8; 32]>,
}

impl PayoutOutputsTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of tokens with at least one tracked entry.
    pub fn len(&self) -> usize {
        self.by_token.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_token.is_empty()
    }

    /// Count tracked entries for one token.
    pub fn entries_for_token(&self, token: &Token) -> usize {
        self.by_token.get(token).map(|v| v.len()).unwrap_or(0)
    }

    /// Most-recently-observed pool `prev_hash`. Exposed for diagnostics.
    pub fn last_prev_hash(&self) -> Option<&[u8; 32]> {
        self.last_prev_hash.as_ref()
    }

    /// Record a freshly-issued payout set as single-use pending.
    /// Entries are appended in arrival order; validation scans
    /// newest-first.
    pub fn record(&mut self, token: Token, response: EmittedPayoutOutputs) {
        self.by_token.entry(token).or_default().push(response);
    }

    /// Note the pool's current `prev_hash` (its own chain-tip view). On
    /// a change: drop every *used* entry (terminal) **and** every entry
    /// already staled by a prior epoch (a one-epoch grace then prune, so
    /// abandoned stale-unused sets can't accumulate), then mark every
    /// remaining *unused* entry `stale` (its payout window is
    /// superseded). Returns the number of entries newly marked stale —
    /// useful for diagnostics, tests, and metrics.
    ///
    /// The first observation only establishes the baseline (it cannot
    /// stale anything, since nothing was issued under a prior epoch).
    /// Idempotent for the same `prev_hash`.
    pub fn observe_epoch(&mut self, prev_hash: [u8; 32]) -> usize {
        if self.last_prev_hash == Some(prev_hash) {
            return 0;
        }
        let first = self.last_prev_hash.is_none();
        self.last_prev_hash = Some(prev_hash);
        if first {
            return 0;
        }
        let mut staled = 0usize;
        self.by_token.retain(|_, list| {
            // Drop terminal entries: spent (used) sets, and sets already
            // staled by a PRIOR epoch that the JDC never re-declared. The
            // latter gives a stale set a one-epoch grace (so a declare can
            // still report `Stale`) and then prunes it — without this,
            // stale-unused entries would accumulate unboundedly as the
            // chain advances on a long-lived connection.
            list.retain(|e| !e.used && !e.stale);
            // Mark the survivors (fresh, unused) stale for this epoch.
            for e in list.iter_mut() {
                e.stale = true;
                staled += 1;
            }
            !list.is_empty()
        });
        staled
    }

    /// Validate a `DeclareMiningJob` against this token's pending payout
    /// set and consume it (spec §4: single-use). Picks the most-recent
    /// *unused* set for `token`:
    ///
    /// - none ever issued → [`DeclareOutputsCheck::NoneIssued`] (caller
    ///   decides — with 0x0003 negotiated it rejects, since a fresh set is
    ///   required per declared job);
    /// - all issued sets already used → [`DeclareOutputsCheck::AlreadyUsed`];
    /// - the set is stale (chain advanced) → [`DeclareOutputsCheck::Stale`];
    /// - otherwise the declared `coinbase_tx_suffix` MUST carry every
    ///   output verbatim ([`declared_coinbase_contains_pool_outputs`]) —
    ///   on success the set is marked used and [`DeclareOutputsCheck::Ok`]
    ///   is returned; a missing/modified output yields
    ///   [`DeclareOutputsCheck::MissingOutput`] WITHOUT consuming the set
    ///   (a corrected re-declaration may still succeed).
    pub fn validate_and_consume_for_declare(
        &mut self,
        token: &Token,
        coinbase_tx_suffix: &[u8],
    ) -> DeclareOutputsCheck {
        let list = match self.by_token.get_mut(token) {
            Some(l) if !l.is_empty() => l,
            _ => return DeclareOutputsCheck::NoneIssued,
        };
        let entry = match list.iter_mut().rev().find(|e| !e.used) {
            Some(e) => e,
            None => return DeclareOutputsCheck::AlreadyUsed,
        };
        if entry.stale {
            return DeclareOutputsCheck::Stale;
        }
        match declared_coinbase_contains_pool_outputs(coinbase_tx_suffix, &entry.outputs) {
            CoinbaseOutputCheck::Ok => {
                entry.used = true;
                DeclareOutputsCheck::Ok
            }
            CoinbaseOutputCheck::MissingOutput { index } => {
                DeclareOutputsCheck::MissingOutput { index }
            }
            CoinbaseOutputCheck::UnparsablePoolOutputs => {
                DeclareOutputsCheck::UnparsablePoolOutputs
            }
            CoinbaseOutputCheck::UnparsableDeclaredCoinbase => {
                DeclareOutputsCheck::UnparsableDeclaredCoinbase
            }
        }
    }
}

// ── Declared-coinbase output validation (SV2 §6.4.3 / ext 0x0003) ─────

/// Outcome of [`declared_coinbase_contains_pool_outputs`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoinbaseOutputCheck {
    /// Every pool-committed output is present in the declared coinbase
    /// output multiset.
    Ok,
    /// The pool-committed output blob didn't parse as a `Vec<TxOut>`.
    UnparsablePoolOutputs,
    /// The declared `coinbase_tx_suffix` didn't parse into a coinbase output
    /// vector (too short / non-standard layout). Fail-closed → reject.
    UnparsableDeclaredCoinbase,
    /// The pool-committed output at `index` (value + script) is absent from
    /// the declared coinbase output multiset (missing, modified, reduced, or
    /// under-counted against a duplicate).
    MissingOutput { index: usize },
}

/// Verify the JDC's declared `coinbase_tx_suffix` carries **every** pool-
/// committed coinbase output (spec §4: validation over the multiset
/// `{(amount, scriptPubKey)}` — ordering MUST NOT matter, multiplicity MUST).
///
/// `pool_outputs_consensus` is the exact byte blob the pool returned from
/// `RequestPayoutOutputs` — a consensus-serialised `Vec<TxOut>` produced by
/// [`encode_coinbase_outputs`] and tracked in [`PayoutOutputsTracker`].
///
/// We parse BOTH sides into real `TxOut` vectors and run a multiset-superset
/// check ([`first_uncovered_committed_output`]) rather than a raw byte-run
/// search. A substring search is unsound: it under-counts duplicate outputs
/// and — worse — is satisfied by a JDC that buries the committed output's
/// bytes inside an attacker-controlled script (e.g. OP_RETURN data) while
/// paying the pool nothing. Parsing the declared output vector and matching
/// whole, properly-delimited `TxOut`s closes both holes. Without this a JDC
/// could declare a job whose coinbase omits the pool's payout / fee outputs
/// and keep the full block reward.
pub fn declared_coinbase_contains_pool_outputs(
    coinbase_tx_suffix: &[u8],
    pool_outputs_consensus: &[u8],
) -> CoinbaseOutputCheck {
    let committed: Vec<TxOut> = match bitcoin::consensus::deserialize(pool_outputs_consensus) {
        Ok(v) => v,
        Err(_) => return CoinbaseOutputCheck::UnparsablePoolOutputs,
    };
    if committed.is_empty() {
        // The pool committed nothing (e.g. everything was dust-trimmed) —
        // there is nothing to enforce.
        return CoinbaseOutputCheck::Ok;
    }
    let declared = match parse_coinbase_suffix_outputs(coinbase_tx_suffix) {
        Some(v) => v,
        None => return CoinbaseOutputCheck::UnparsableDeclaredCoinbase,
    };
    match first_uncovered_committed_output(&declared, &committed) {
        None => CoinbaseOutputCheck::Ok,
        Some(index) => CoinbaseOutputCheck::MissingOutput { index },
    }
}

/// Parse the coinbase output vector out of a SV2 `coinbase_tx_suffix`.
///
/// The suffix is the coinbase bytes AFTER the extranonce slot:
/// `[nSequence: 4][output_count: CompactSize][TxOuts][nLockTime: 4]`. The
/// output vector is parsed as a consensus `Vec<TxOut>` that MUST consume the
/// region between nSequence and nLockTime exactly. Returns `None` if the
/// suffix is shorter than the 8 framing bytes or doesn't match this layout —
/// callers treat that as a validation failure (fail-closed: never accept an
/// output set we cannot actually verify).
fn parse_coinbase_suffix_outputs(coinbase_tx_suffix: &[u8]) -> Option<Vec<TxOut>> {
    if coinbase_tx_suffix.len() < 8 {
        return None;
    }
    // Strip the leading nSequence (4) and trailing nLockTime (4); the middle
    // MUST be exactly a consensus Vec<TxOut> (`deserialize` rejects trailing
    // bytes, so a non-standard scriptSig tail fails closed).
    let body = &coinbase_tx_suffix[4..coinbase_tx_suffix.len() - 4];
    bitcoin::consensus::deserialize::<Vec<TxOut>>(body).ok()
}

/// Index of the first `committed` output not covered by `declared` with
/// sufficient multiplicity, or `None` when every committed output is present.
///
/// Implements the spec §4 multiset `{(amount, scriptPubKey)}` containment:
/// outputs are keyed by their consensus serialisation (value + script), so
/// ordering is irrelevant and multiplicity is honoured (committed `[A, A]`
/// requires `declared` to carry `A` at least twice). `declared` MAY carry
/// additional outputs (the JDC's own) — only the committed set must be a
/// sub-multiset.
pub(crate) fn first_uncovered_committed_output(
    declared: &[TxOut],
    committed: &[TxOut],
) -> Option<usize> {
    let mut available: HashMap<Vec<u8>, usize> = HashMap::with_capacity(declared.len());
    for o in declared {
        *available
            .entry(bitcoin::consensus::serialize(o))
            .or_insert(0) += 1;
    }
    for (index, c) in committed.iter().enumerate() {
        let key = bitcoin::consensus::serialize(c);
        match available.get_mut(&key) {
            Some(n) if *n > 0 => *n -= 1,
            _ => return Some(index),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(seed: u8) -> Token {
        let mut b = [0u8; 16];
        b[0] = seed;
        Token(b)
    }

    fn addr() -> AddressId {
        AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap()
    }

    fn out(sats: i64) -> DynamicOutput {
        DynamicOutput {
            address: addr(),
            sats: Sats::from(sats),
        }
    }

    fn resp(request_id: u32, outputs: Vec<u8>) -> EmittedPayoutOutputs {
        EmittedPayoutOutputs {
            request_id,
            outputs,
            emitted_at_ms: 0,
            used: false,
            stale: false,
        }
    }

    /// Sum of the sats in a dynamic-output list.
    fn sum(d: &[DynamicOutput]) -> i64 {
        d.iter().map(|x| x.sats.to_i64()).sum()
    }

    /// Wrap a consensus `Vec<TxOut>` blob as a realistic coinbase suffix
    /// (`nSequence(4) + outputs + nLockTime(4)`) — the layout
    /// [`parse_coinbase_suffix_outputs`] expects.
    fn suffix(outputs_consensus: &[u8]) -> Vec<u8> {
        let mut s = Vec::with_capacity(8 + outputs_consensus.len());
        s.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // nSequence
        s.extend_from_slice(outputs_consensus);
        s.extend_from_slice(&0u32.to_le_bytes()); // nLockTime
        s
    }

    // ── fold_residual_to_exact_sum (Σ = available_payout_value) ────

    /// No-op when the distribution already sums to the target.
    #[test]
    fn fold_residual_noop_when_exact() {
        let mut outs = vec![out(600), out(400)];
        fold_residual_to_exact_sum(&mut outs, 1000);
        assert_eq!(sum(&outs), 1000);
        assert_eq!(outs[0].sats.to_i64(), 600);
    }

    /// Positive residual (floor-rounding + dropped sub-dust) folds into
    /// the largest output so Σ == target.
    #[test]
    fn fold_residual_positive_goes_to_largest() {
        let mut outs = vec![out(1000), out(2000), out(294)];
        fold_residual_to_exact_sum(&mut outs, 3444); // residual +150
        assert_eq!(sum(&outs), 3444, "Σ must equal target");
        let sats: Vec<i64> = outs.iter().map(|d| d.sats.to_i64()).collect();
        assert_eq!(sats, vec![1000, 2150, 294], "residual folded into largest");
    }

    /// Negative residual (overshoot) is trimmed soundly from the largest
    /// outputs without clamping any output negative — Σ still == target.
    #[test]
    fn fold_residual_negative_trims_without_breaking_sum() {
        let mut outs = vec![out(1000), out(2000), out(500)];
        // current 3500, target 3000 → overshoot 500, trimmed off the 2000.
        fold_residual_to_exact_sum(&mut outs, 3000);
        assert_eq!(sum(&outs), 3000, "Σ must equal target even on overshoot");
        assert!(
            outs.iter().all(|d| d.sats.to_i64() >= 0),
            "no negative output"
        );
        let sats: Vec<i64> = outs.iter().map(|d| d.sats.to_i64()).collect();
        assert_eq!(sats, vec![1000, 1500, 500]);
    }

    /// Overshoot larger than the single largest output cascades to the
    /// next outputs, never going negative.
    #[test]
    fn fold_residual_large_overshoot_cascades() {
        let mut outs = vec![out(1000), out(800), out(600)];
        // current 2400, target 500 → overshoot 1900: 1000→0, 800→0, 600→500.
        fold_residual_to_exact_sum(&mut outs, 500);
        assert_eq!(sum(&outs), 500);
        assert!(outs.iter().all(|d| d.sats.to_i64() >= 0));
    }

    /// Empty input stays empty (caller treats this as "cannot construct").
    #[test]
    fn fold_residual_empty_input_stays_empty() {
        let mut empty: Vec<DynamicOutput> = vec![];
        fold_residual_to_exact_sum(&mut empty, 5000);
        assert!(empty.is_empty());
    }

    // ── encode_coinbase_outputs ────────────────────────────────────

    /// Empty input → single zero byte (the varint-count of 0).
    #[test]
    fn encode_empty_outputs_is_single_zero() {
        let bytes = encode_coinbase_outputs(Network::Regtest, &[]).unwrap();
        assert_eq!(bytes, vec![0x00]);
    }

    /// Single P2WPKH output: VarInt(1) + value(LE8) + VarInt(22) +
    /// script(22 bytes for P2WPKH = OP_0 + 0x14 + 20-byte hash).
    #[test]
    fn encode_single_p2wpkh_output_has_expected_size() {
        let bytes = encode_coinbase_outputs(Network::Regtest, &[out(5_000_000_000)]).unwrap();
        // Layout: 1 (count varint, value 1) + 8 (value LE) + 1
        // (script-len varint, 22 < 0xfd) + 22 (P2WPKH script) = 32.
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0x01, "varint count = 1");
        // Value at offset 1..9 is u64 LE 5_000_000_000.
        let value = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
        assert_eq!(value, 5_000_000_000);
        // Script-len varint at offset 9.
        assert_eq!(bytes[9], 22, "script len varint = 22");
        // P2WPKH starts with 0x00 (OP_0) + 0x14 (push 20 bytes).
        assert_eq!(bytes[10], 0x00);
        assert_eq!(bytes[11], 0x14);
    }

    #[test]
    fn encode_multi_output_count_byte_correct() {
        let bytes =
            encode_coinbase_outputs(Network::Regtest, &[out(1_000), out(2_000), out(3_000)])
                .unwrap();
        assert_eq!(bytes[0], 0x03, "varint count = 3");
    }

    #[test]
    fn encode_invalid_address_returns_error() {
        let bad = DynamicOutput {
            address: AddressId::new("not-a-bitcoin-address").unwrap(),
            sats: Sats::from(1000),
        };
        let err = encode_coinbase_outputs(Network::Regtest, &[bad]).unwrap_err();
        assert!(matches!(err, EncodeError::InvalidAddress(_)));
    }

    // ── PayoutOutputsTracker (single-use) ──────────────────────────

    /// A consensus-serialised single P2WPKH output for the canonical
    /// regtest address, valued `sats` — used as a realistic pending set
    /// the declared coinbase can embed.
    fn pool_set(sats: i64) -> Vec<u8> {
        encode_coinbase_outputs(Network::Regtest, &[out(sats)]).unwrap()
    }

    #[test]
    fn tracker_starts_empty() {
        let c = PayoutOutputsTracker::new();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
        assert!(c.last_prev_hash().is_none());
    }

    /// NoneIssued when the token never had a payout set — the caller
    /// falls through (base-protocol declaration).
    #[test]
    fn validate_none_issued_for_unknown_token() {
        let mut c = PayoutOutputsTracker::new();
        assert_eq!(
            c.validate_and_consume_for_declare(&tok(0xFF), &[]),
            DeclareOutputsCheck::NoneIssued
        );
    }

    /// A declared coinbase carrying the pending set validates, and the
    /// set is consumed (single-use) — a second declare is AlreadyUsed.
    #[test]
    fn validate_consumes_pending_set_then_rejects_reuse() {
        let mut c = PayoutOutputsTracker::new();
        let token = tok(0x01);
        let outputs = pool_set(600);
        c.record(token, resp(1, outputs.clone()));

        // Declared coinbase suffix carries the committed output.
        let decl = suffix(&outputs);
        assert_eq!(
            c.validate_and_consume_for_declare(&token, &decl),
            DeclareOutputsCheck::Ok
        );
        // Single-use: the same token's set is now spent.
        assert_eq!(
            c.validate_and_consume_for_declare(&token, &decl),
            DeclareOutputsCheck::AlreadyUsed
        );
    }

    /// A failed match does NOT consume the set — a corrected
    /// re-declaration can still succeed.
    #[test]
    fn validate_missing_output_does_not_consume() {
        let mut c = PayoutOutputsTracker::new();
        let token = tok(0x01);
        let outputs = pool_set(600);
        c.record(token, resp(1, outputs.clone()));

        // A coinbase that pays a DIFFERENT value → committed output missing,
        // and the set is NOT consumed (a corrected re-declaration can retry).
        let wrong = suffix(&pool_set(599));
        assert_eq!(
            c.validate_and_consume_for_declare(&token, &wrong),
            DeclareOutputsCheck::MissingOutput { index: 0 }
        );
        // Retry with the committed output present succeeds.
        let good = suffix(&outputs);
        assert_eq!(
            c.validate_and_consume_for_declare(&token, &good),
            DeclareOutputsCheck::Ok
        );
    }

    /// `observe_epoch` marks pending unused sets stale on a tip change;
    /// validation then returns Stale. The first observation only sets
    /// the baseline.
    #[test]
    fn observe_epoch_marks_pending_stale_on_tip_change() {
        let mut c = PayoutOutputsTracker::new();
        let token = tok(0x01);
        // Baseline epoch, then record a fresh (non-stale) set.
        assert_eq!(c.observe_epoch([0xAA; 32]), 0, "first observe is baseline");
        let outputs = pool_set(600);
        c.record(token, resp(1, outputs.clone()));

        // Tip advances → the pending set is superseded.
        assert_eq!(c.observe_epoch([0xBB; 32]), 1);
        let decl = suffix(&outputs);
        assert_eq!(
            c.validate_and_consume_for_declare(&token, &decl),
            DeclareOutputsCheck::Stale
        );
        assert_eq!(c.last_prev_hash(), Some(&[0xBB; 32]));
    }

    /// `observe_epoch` drops spent (used) entries on a tip change while
    /// staling the rest — keeps memory bounded as the chain advances.
    #[test]
    fn observe_epoch_drops_used_entries() {
        let mut c = PayoutOutputsTracker::new();
        let token = tok(0x01);
        c.observe_epoch([0xAA; 32]);
        let outputs = pool_set(600);
        c.record(token, resp(1, outputs.clone()));
        // Consume it.
        let decl = suffix(&outputs);
        assert_eq!(
            c.validate_and_consume_for_declare(&token, &decl),
            DeclareOutputsCheck::Ok
        );
        // Tip advances: the used entry is dropped; token entry vanishes.
        assert_eq!(c.observe_epoch([0xBB; 32]), 0, "no unused entries to stale");
        assert_eq!(c.entries_for_token(&token), 0);
        assert!(c.is_empty());
    }

    /// Idempotent for the same prev_hash.
    #[test]
    fn observe_epoch_same_prev_hash_is_noop() {
        let mut c = PayoutOutputsTracker::new();
        let t = tok(0x01);
        c.observe_epoch([0xAA; 32]);
        c.record(t, resp(1, pool_set(600)));
        assert_eq!(c.observe_epoch([0xAA; 32]), 0);
        assert_eq!(c.entries_for_token(&t), 1);
    }

    /// A stale-unused set is pruned on the NEXT epoch (one-epoch grace),
    /// so abandoned stale entries can't accumulate without bound.
    #[test]
    fn observe_epoch_prunes_prior_stale_unused() {
        let mut c = PayoutOutputsTracker::new();
        let token = tok(0x01);
        c.observe_epoch([0xAA; 32]);
        c.record(token, resp(1, pool_set(600)));
        // Tip advances: the set is staled but kept (one-epoch grace so a
        // late declare can still report Stale).
        assert_eq!(c.observe_epoch([0xBB; 32]), 1);
        assert_eq!(c.entries_for_token(&token), 1);
        // Tip advances again, JDC never re-declared → the stale set is pruned.
        assert_eq!(c.observe_epoch([0xCC; 32]), 0, "no fresh entries to stale");
        assert_eq!(c.entries_for_token(&token), 0);
        assert!(c.is_empty());
    }

    // ── coinbase_outputs_fit_reservation (size guard) ───────────────

    /// A per-job set no larger than the token-time committed set fits
    /// (the common case: per-job revenue ≤ token estimate ⇒ ≤ recipients).
    #[test]
    fn fit_smaller_or_equal_per_job_set_fits() {
        let committed =
            encode_coinbase_outputs(Network::Regtest, &[out(6_000), out(4_000), out(3_000)])
                .unwrap();
        let per_job = encode_coinbase_outputs(Network::Regtest, &[out(6_000), out(4_000)]).unwrap();
        assert!(coinbase_outputs_fit_reservation(&per_job, &committed));
        // Exactly-equal also fits.
        assert!(coinbase_outputs_fit_reservation(&committed, &committed));
    }

    /// A per-job set with more recipients than the token reserved for
    /// (window grew / budget raised since token issue) does NOT fit —
    /// the caller maps this to `coinbase-size-budget-exceeded`.
    #[test]
    fn fit_grown_per_job_set_does_not_fit() {
        let committed = encode_coinbase_outputs(Network::Regtest, &[out(6_000)]).unwrap();
        let grown =
            encode_coinbase_outputs(Network::Regtest, &[out(6_000), out(4_000), out(3_000)])
                .unwrap();
        assert!(!coinbase_outputs_fit_reservation(&grown, &committed));
    }

    // ── declared_coinbase_contains_pool_outputs ──────────────────────

    const REGTEST_ADDR_A: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    fn dyn_out(addr: &str, sats: i64) -> DynamicOutput {
        DynamicOutput {
            address: AddressId::new(addr.to_string()).unwrap(),
            sats: Sats(sats),
        }
    }

    #[test]
    fn validation_ok_when_declared_carries_all_pool_outputs() {
        let committed = encode_coinbase_outputs(
            Network::Regtest,
            &[dyn_out(REGTEST_ADDR_A, 600), dyn_out(REGTEST_ADDR_A, 400)],
        )
        .unwrap();
        // Declared coinbase carries the pool outputs (in a DIFFERENT order)
        // PLUS the JDC's own output — a multiset superset → Ok. Exercises
        // both the order-independence and superset properties of spec §4.
        let declared = encode_coinbase_outputs(
            Network::Regtest,
            &[
                dyn_out(REGTEST_ADDR_A, 400),
                dyn_out(REGTEST_ADDR_A, 999),
                dyn_out(REGTEST_ADDR_A, 600),
            ],
        )
        .unwrap();
        assert_eq!(
            declared_coinbase_contains_pool_outputs(&suffix(&declared), &committed),
            CoinbaseOutputCheck::Ok
        );
    }

    #[test]
    fn validation_flags_missing_output() {
        // Pool committed two outputs; the declared coinbase carries only the
        // first → the second is reported missing.
        let declared =
            encode_coinbase_outputs(Network::Regtest, &[dyn_out(REGTEST_ADDR_A, 600)]).unwrap();
        let committed = encode_coinbase_outputs(
            Network::Regtest,
            &[dyn_out(REGTEST_ADDR_A, 600), dyn_out(REGTEST_ADDR_A, 400)],
        )
        .unwrap();
        match declared_coinbase_contains_pool_outputs(&suffix(&declared), &committed) {
            CoinbaseOutputCheck::MissingOutput { index } => assert_eq!(index, 1),
            other => panic!("expected MissingOutput{{1}}, got {other:?}"),
        }
    }

    #[test]
    fn validation_flags_wrong_value_as_missing() {
        // Same address, reduced value → the committed TxOut isn't present
        // (the full value+script multiset key differs) → reported missing.
        let committed =
            encode_coinbase_outputs(Network::Regtest, &[dyn_out(REGTEST_ADDR_A, 600)]).unwrap();
        let declared =
            encode_coinbase_outputs(Network::Regtest, &[dyn_out(REGTEST_ADDR_A, 599)]).unwrap();
        assert_eq!(
            declared_coinbase_contains_pool_outputs(&suffix(&declared), &committed),
            CoinbaseOutputCheck::MissingOutput { index: 0 }
        );
    }

    #[test]
    fn validation_unparsable_pool_outputs() {
        // 0xFF varint prefix promises 8 more length bytes that aren't there.
        assert_eq!(
            declared_coinbase_contains_pool_outputs(&[0x00], &[0xFF, 0x01]),
            CoinbaseOutputCheck::UnparsablePoolOutputs
        );
    }

    #[test]
    fn validation_rejects_unparsable_declared_coinbase() {
        let committed =
            encode_coinbase_outputs(Network::Regtest, &[dyn_out(REGTEST_ADDR_A, 600)]).unwrap();
        // Too short to hold nSequence + outputs + nLockTime → fail-closed.
        assert_eq!(
            declared_coinbase_contains_pool_outputs(&[0x01, 0x02], &committed),
            CoinbaseOutputCheck::UnparsableDeclaredCoinbase
        );
    }

    #[test]
    fn validation_ok_for_empty_pool_outputs() {
        // Pool committed nothing (all dust-trimmed) → nothing to enforce.
        let empty = encode_coinbase_outputs(Network::Regtest, &[]).unwrap();
        assert_eq!(
            declared_coinbase_contains_pool_outputs(&[0xAB, 0xCD], &empty),
            CoinbaseOutputCheck::Ok
        );
    }

    /// Multiset multiplicity: two identical committed outputs are NOT
    /// satisfied by a single declared occurrence (the old byte-containment
    /// check wrongly accepted this).
    #[test]
    fn validation_multiset_honours_duplicate_multiplicity() {
        let committed = encode_coinbase_outputs(
            Network::Regtest,
            &[dyn_out(REGTEST_ADDR_A, 600), dyn_out(REGTEST_ADDR_A, 600)],
        )
        .unwrap();
        let once =
            encode_coinbase_outputs(Network::Regtest, &[dyn_out(REGTEST_ADDR_A, 600)]).unwrap();
        assert_eq!(
            declared_coinbase_contains_pool_outputs(&suffix(&once), &committed),
            CoinbaseOutputCheck::MissingOutput { index: 1 }
        );
        // Carrying it twice satisfies the multiset.
        assert_eq!(
            declared_coinbase_contains_pool_outputs(&suffix(&committed), &committed),
            CoinbaseOutputCheck::Ok
        );
    }

    /// SECURITY: a JDC that buries the committed output's verbatim bytes
    /// inside an OP_RETURN payload (paying the pool nothing) is rejected.
    /// The old contiguous-byte-run check would have been satisfied by the
    /// embedded needle; the multiset parser sees only an OP_RETURN output.
    #[test]
    fn validation_rejects_committed_bytes_buried_in_op_return() {
        use bitcoin::ScriptBuf;
        let committed_blob = pool_set(600);
        let committed: Vec<TxOut> = bitcoin::consensus::deserialize(&committed_blob).unwrap();
        let needle = bitcoin::consensus::serialize(&committed[0]);
        // OP_RETURN + single-byte push of the verbatim committed-TxOut bytes.
        let mut spk = vec![0x6a, needle.len() as u8];
        spk.extend_from_slice(&needle);
        let evil = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(spk),
        };
        let declared = bitcoin::consensus::serialize(&vec![evil]);
        assert_eq!(
            declared_coinbase_contains_pool_outputs(&suffix(&declared), &committed_blob),
            CoinbaseOutputCheck::MissingOutput { index: 0 }
        );
    }
}
