// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coinbase transaction construction with multi-output payouts, BIP-34 block-height
//! encoding, BIP-141 witness commitment, and stateless extranonce splicing.

use bitcoin::Network;
use bp_share::sha256d_from_parts;

use crate::address;

/// Length in bytes of the extranonce slot embedded in the scriptsig.
/// 4 bytes enonce1 + 8 bytes enonce2 — matches ckpool's
/// default `nonce2length = 8` (Braiins Hashpower spec requires ≥ 7).
pub const EXTRANONCE_SLOT_LEN: usize = 12;

const MAX_SCRIPT_SIZE: usize = 100;
const WITNESS_COMMIT_MAGIC: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

/// Non-final coinbase input `nSequence` required by BIP-54 (anything but
/// `0xffffffff`). Matches the value Core 31's template provider emits.
const COINBASE_NONFINAL_SEQUENCE: u32 = 0xffff_fffe;

/// A miner-payout entry for the coinbase outputs.
///
/// Carries the EXACT satoshi amount for the output — the payout distributors
/// (PPLNS / Group-Solo / Blockparty) already do the precise integer allocation
/// (largest-remainder residuum, fixed finder bonus, solvency cap), so the
/// coinbase builder must place those sats verbatim. Deriving amounts from a
/// float percentage here would re-floor each output and silently drop up to a
/// sat per output (e.g. a 50 000 000-sat finder bonus rounding to 49 999 999).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PayoutEntry {
    pub address: String,
    /// Exact output amount in satoshis.
    pub sats: u64,
}

impl PayoutEntry {
    /// Percentage-based convenience: floor `percent`% of `reward_sats` to an
    /// exact output. For the Solo split (dev-fee / 100%-to-miner) and the
    /// percentage-oriented tests. The PPLNS / Group-Solo / Blockparty
    /// distributors bypass this — they carry exact per-output sats already.
    pub fn from_percent(address: impl Into<String>, percent: f64, reward_sats: u64) -> Self {
        Self {
            address: address.into(),
            sats: ((percent / 100.0) * reward_sats as f64).floor() as u64,
        }
    }
}

/// The block-template fields needed for coinbase construction.
#[derive(Clone, Debug)]
pub struct CoinbaseTemplate {
    pub block_height: u32,
    pub coinbase_value_sats: u64,
    /// 32-byte witness commitment hash, already double-SHA256'd by the
    /// template provider (TDP `NewTemplate.witness_commitment` or RPC
    /// `getblocktemplate.default_witness_commitment`).
    pub witness_commitment: [u8; 32],
}

/// A coinbase transaction split into its non-witness bytes before and
/// after the extranonce slot. Per-share submission splices the
/// miner-supplied extranonce in to compute the coinbase txid without
/// re-building or mutating shared state.
///
/// `MiningJob` is immutable after construction — `&MiningJob` is `Send + Sync`.
#[derive(Clone, Debug)]
pub struct MiningJob {
    coinbase_prefix: Vec<u8>,
    coinbase_suffix: Vec<u8>,
}

impl MiningJob {
    pub fn coinbase_prefix(&self) -> &[u8] {
        &self.coinbase_prefix
    }

    pub fn coinbase_suffix(&self) -> &[u8] {
        &self.coinbase_suffix
    }

    /// Splice the 4-byte extranonce1 and 8-byte extranonce2 into the
    /// scriptsig and return the resulting coinbase txid (sha256d of the
    /// non-witness serialization).
    pub fn coinbase_txid_with_extranonce(&self, enonce1: &[u8; 4], enonce2: &[u8; 8]) -> [u8; 32] {
        // Stream prefix + extranonce + suffix straight into the hasher — no
        // per-share `Vec` (SHA-256 is a streaming hash, so this yields the exact
        // same txid as hashing the concatenation).
        sha256d_from_parts(&[
            self.coinbase_prefix.as_slice(),
            enonce1.as_slice(),
            enonce2.as_slice(),
            self.coinbase_suffix.as_slice(),
        ])
    }

    /// Splice the extranonce in and return the **witness-form** coinbase
    /// bytes for block submission (BIP-141 layout: marker `0x00` + flag
    /// `0x01` inserted after version, 32-zero witness reserved value
    /// inserted before locktime).
    ///
    /// Used by the block-found path (TDP `SubmitSolution`); the
    /// share-validation hot path stays on `coinbase_txid_with_extranonce`
    /// which only needs the non-witness form.
    pub fn witness_coinbase_with_extranonce(
        &self,
        enonce1: &[u8; 4],
        enonce2: &[u8; 8],
    ) -> Vec<u8> {
        // Non-witness layout (what we have stored, split around the slot):
        //   prefix = [version:4][input_count:1][prev_txid:32][prev_vout:4]
        //            [scriptsig_len:varint][scriptsig: prefix_part]
        //   slot    = [enonce1:4][enonce2:8]
        //   suffix = [scriptsig: suffix_part][sequence:4][output_count:varint]
        //            [outputs...][locktime:4]
        //
        // Witness layout differs only at two points:
        //   - bytes 4..4: insert [marker=0x00][flag=0x01] (right after version)
        //   - before the trailing locktime: insert
        //     [witness_count=0x01][witness_len=0x20][32 zero bytes]
        let prefix = &self.coinbase_prefix;
        let suffix = &self.coinbase_suffix;
        let locktime_at = suffix.len() - 4;

        let total = prefix.len() + 2 + EXTRANONCE_SLOT_LEN + locktime_at + 1 + 1 + 32 + 4;
        let mut buf = Vec::with_capacity(total);
        // version
        buf.extend_from_slice(&prefix[..4]);
        // BIP-141 marker + flag
        buf.push(0x00);
        buf.push(0x01);
        // rest of the non-witness prefix (input_count onwards)
        buf.extend_from_slice(&prefix[4..]);
        // extranonce slot
        buf.extend_from_slice(enonce1);
        buf.extend_from_slice(enonce2);
        // non-witness suffix up to (not including) locktime
        buf.extend_from_slice(&suffix[..locktime_at]);
        // witness stack: 1 item of 32 bytes (the coinbase's mandatory reserved value)
        buf.push(0x01);
        buf.push(0x20);
        buf.extend_from_slice(&[0u8; 32]);
        // locktime
        buf.extend_from_slice(&suffix[locktime_at..]);
        buf
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MiningJobError {
    #[error("scriptsig would exceed 100-byte consensus limit ({0} bytes)")]
    ScriptSigTooLong(usize),
    #[error("invalid payout address: {0}")]
    InvalidAddress(#[from] address::AddressError),
    #[error("at least one payout entry is required")]
    NoPayouts,
}

/// Build a `MiningJob` for the given template + payouts.
///
/// Scriptsig layout: BIP-34 height push, pool identifier (dropped if it
/// would exceed the 100-byte consensus limit), `extranonce_slot_size`
/// bytes for the extranonce slot (zeroed at build time, spliced per
/// share).
///
/// `extranonce_slot_size` is the total channel-negotiated extranonce
/// width baked into the scriptsig. SV1 callers pass
/// [`EXTRANONCE_SLOT_LEN`] (the pool default of 4-byte enonce1 +
/// 8-byte enonce2 = 12); SV2 Extended callers pass
/// `channel.extranonce_prefix.len() + channel.extranonce_size` so the
/// scriptsig_len varint matches the wire bytes exactly.
///
/// Each `PayoutEntry` carries its exact sats, placed verbatim. Any shortfall
/// vs `coinbase_value_sats` (normally zero — the distributor sums to the
/// reward) is swept onto `outs[0]` so the coinbase consumes it exactly.
///
/// The coinbase is built BIP-54-compliant: `nLockTime = block_height - 1`
/// and a non-final `nSequence` (`0xfffffffe`). The TDP path
/// ([`build_mining_job_from_tdp`]) instead passes through Core's
/// `NewTemplate` values, which a BIP-54-aware node already sets compliantly.
pub fn build_mining_job(
    network: Network,
    payouts: &[PayoutEntry],
    template: &CoinbaseTemplate,
    pool_identifier: &str,
    extranonce_slot_size: usize,
) -> Result<MiningJob, MiningJobError> {
    if payouts.is_empty() {
        return Err(MiningJobError::NoPayouts);
    }

    let height_encoded = encode_block_height_minimal(template.block_height);
    let height_len = height_encoded.len();
    let padding_len = extranonce_slot_size + 3usize.saturating_sub(height_len);
    let padding = vec![0u8; padding_len];

    // Try with identifier first; drop it if the resulting scriptsig would
    // exceed the consensus limit.
    let identifier_bytes = pool_identifier.as_bytes();
    let mut script_sig = build_scriptsig(&height_encoded, identifier_bytes, &padding);
    if script_sig.len() > MAX_SCRIPT_SIZE {
        script_sig = build_scriptsig(&height_encoded, &[], &padding);
    }
    if script_sig.len() > MAX_SCRIPT_SIZE {
        return Err(MiningJobError::ScriptSigTooLong(script_sig.len()));
    }

    let outputs = build_outputs(
        network,
        payouts,
        template.coinbase_value_sats,
        &template.witness_commitment,
    )?;

    // BIP-54: nLockTime = block_height - 1, non-final nSequence.
    let locktime = template.block_height.saturating_sub(1);
    let serialized =
        serialize_coinbase_non_witness(&script_sig, &outputs, COINBASE_NONFINAL_SEQUENCE, locktime);

    // Compute the split offsets. Layout:
    //   version(4) + input_count(1) + prev_txid(32) + prev_vout(4)
    //   + scriptsig_varint(varint_len) + scriptsig(N: last `extranonce_slot_size` = extranonce)
    //   + sequence(4) + output_count(varint) + ... outputs ... + locktime(4)
    let varint_len = varint_size(script_sig.len() as u64);
    let prefix_end = 4 + 1 + 32 + 4 + varint_len + script_sig.len() - extranonce_slot_size;
    let suffix_start = prefix_end + extranonce_slot_size;

    let coinbase_prefix = serialized[..prefix_end].to_vec();
    let coinbase_suffix = serialized[suffix_start..].to_vec();

    Ok(MiningJob {
        coinbase_prefix,
        coinbase_suffix,
    })
}

/// TDP-side template fields needed for coinbase assembly.
///
/// Mirrors the relevant `template_distribution_sv2::NewTemplate` fields:
/// the BIP-34-prepared scriptsig prefix, the input sequence, the value
/// remaining after bitcoin-core's required outputs, the pre-serialized
/// required outputs blob (typically just the witness-commitment
/// OP_RETURN — bitcoin-core has already done the SegWit work for us),
/// and the locktime / version. All fields come straight from
/// `NewTemplate`, no transformation needed.
#[derive(Clone, Debug)]
pub struct TdpCoinbaseTemplate<'a> {
    /// `NewTemplate.coinbase_prefix` — BIP-34 height push + any pool-side
    /// data bitcoin-core was configured to inject. We append our own pool
    /// identifier + the 12-byte extranonce slot after this.
    pub coinbase_prefix: &'a [u8],
    /// `NewTemplate.coinbase_tx_version` — typically 2.
    pub coinbase_tx_version: u32,
    /// `NewTemplate.coinbase_tx_input_sequence` — typically 0xFFFFFFFF or
    /// 0xFFFFFFFE.
    pub coinbase_tx_input_sequence: u32,
    /// `NewTemplate.coinbase_tx_value_remaining` — subsidy + fees minus
    /// the value already allocated to bitcoin-core's required outputs.
    /// This is what gets split across our payout entries.
    pub coinbase_tx_value_remaining: u64,
    /// `NewTemplate.coinbase_tx_outputs` — raw concatenated TxOut bytes
    /// (each output = 8-byte LE value + scriptlen varint + script).
    /// **NOT** prefixed with an output-count varint; the count lives in
    /// `coinbase_tx_outputs_count` separately.
    pub coinbase_tx_outputs: &'a [u8],
    /// `NewTemplate.coinbase_tx_outputs_count` — number of TxOuts encoded
    /// in `coinbase_tx_outputs`. Combined with our payout count to form
    /// the final coinbase's output-count varint.
    pub coinbase_tx_outputs_count: u32,
    /// `NewTemplate.coinbase_tx_locktime` — typically 0.
    pub coinbase_tx_locktime: u32,
}

/// Build a `MiningJob` from a TDP `NewTemplate`'s coinbase fields plus
/// the pool's per-job payout split.
///
/// Differences from [`build_mining_job`]:
///
/// - Scriptsig prefix is taken from `template.coinbase_prefix` (bitcoin-core
///   has already encoded BIP-34 height + any other configured data) — we
///   only append the pool identifier (if it fits) and the 12-byte
///   extranonce slot.
/// - Required outputs come from `template.coinbase_tx_outputs` verbatim
///   (typically the witness-commitment OP_RETURN). We prepend our payout
///   outputs in front, so the final output order is:
///   `[payout_0, payout_1, …, payout_N-1, tdp_outputs…]`.
/// - `version`, `input_sequence`, and `locktime` are taken from the
///   template fields rather than hard-coded.
///
/// The returned `MiningJob` carries the same `coinbase_prefix` /
/// `coinbase_suffix` split shape as `build_mining_job`, so the per-share
/// hot path (`coinbase_txid_with_extranonce`) and the block-found path
/// (`witness_coinbase_with_extranonce`) work identically.
pub fn build_mining_job_from_tdp(
    network: Network,
    payouts: &[PayoutEntry],
    template: &TdpCoinbaseTemplate<'_>,
    pool_identifier: &str,
    extranonce_slot_size: usize,
) -> Result<MiningJob, MiningJobError> {
    if payouts.is_empty() {
        return Err(MiningJobError::NoPayouts);
    }

    // Scriptsig FIRST, outputs second — keeps the error precedence
    // (NoPayouts → ScriptSigTooLong → InvalidAddress) identical to the
    // pre-split function so callers matching/logging the variant see
    // the same failure cause for the same inputs.
    let script_sig = checked_tdp_scriptsig(
        template.coinbase_prefix,
        pool_identifier,
        extranonce_slot_size,
    )?;

    let payout_outputs =
        build_payout_outputs(network, payouts, template.coinbase_tx_value_remaining)?;

    Ok(assemble_tdp_job(
        script_sig,
        &payout_outputs,
        template,
        extranonce_slot_size,
    ))
}

/// Build the TDP scriptsig (template prefix + pool identifier +
/// extranonce slot), dropping the identifier if the result would exceed
/// the 100-byte consensus limit — mirrors `build_mining_job`'s "drop on
/// overflow" behavior. Split out so [`crate::cache::MiningJobCache`]
/// runs the same check in the same order as
/// [`build_mining_job_from_tdp`].
pub(crate) fn checked_tdp_scriptsig(
    tdp_prefix: &[u8],
    pool_identifier: &str,
    extranonce_slot_size: usize,
) -> Result<Vec<u8>, MiningJobError> {
    let mut script_sig =
        build_tdp_scriptsig(tdp_prefix, pool_identifier.as_bytes(), extranonce_slot_size);
    if script_sig.len() > MAX_SCRIPT_SIZE {
        script_sig = build_tdp_scriptsig(tdp_prefix, &[], extranonce_slot_size);
    }
    if script_sig.len() > MAX_SCRIPT_SIZE {
        return Err(MiningJobError::ScriptSigTooLong(script_sig.len()));
    }
    Ok(script_sig)
}

/// Assemble a `MiningJob` from an ALREADY-CHECKED scriptsig and
/// ALREADY-BUILT payout outputs — the two fallible steps
/// ([`checked_tdp_scriptsig`], [`build_payout_outputs`]) factored out
/// so [`crate::cache::MiningJobCache`] can reuse parsed outputs across
/// builds that differ only in slot size / template coinbase fields.
/// Serialization itself cannot fail.
pub(crate) fn assemble_tdp_job(
    script_sig: Vec<u8>,
    payout_outputs: &[(u64, Vec<u8>)],
    template: &TdpCoinbaseTemplate<'_>,
    extranonce_slot_size: usize,
) -> MiningJob {
    let total_output_count =
        payout_outputs.len() as u64 + u64::from(template.coinbase_tx_outputs_count);

    let serialized = serialize_coinbase_with_raw_tdp_outputs(
        template.coinbase_tx_version,
        &script_sig,
        template.coinbase_tx_input_sequence,
        total_output_count,
        payout_outputs,
        template.coinbase_tx_outputs,
        template.coinbase_tx_locktime,
    );

    // Split offsets. Layout:
    //   version(4) + input_count(1) + prev_txid(32) + prev_vout(4)
    //   + scriptsig_varint(varint_len) + scriptsig(N: last `extranonce_slot_size` = extranonce)
    //   + sequence(4) + output_count(varint) + ... outputs ... + locktime(4)
    let varint_len = varint_size(script_sig.len() as u64);
    let prefix_end = 4 + 1 + 32 + 4 + varint_len + script_sig.len() - extranonce_slot_size;
    let suffix_start = prefix_end + extranonce_slot_size;

    let coinbase_prefix = serialized[..prefix_end].to_vec();
    let coinbase_suffix = serialized[suffix_start..].to_vec();

    MiningJob {
        coinbase_prefix,
        coinbase_suffix,
    }
}

fn build_tdp_scriptsig(tdp_prefix: &[u8], identifier: &[u8], slot_len: usize) -> Vec<u8> {
    let mut s = Vec::with_capacity(tdp_prefix.len() + identifier.len() + slot_len);
    s.extend_from_slice(tdp_prefix);
    s.extend_from_slice(identifier);
    s.extend(std::iter::repeat_n(0u8, slot_len));
    s
}

fn serialize_coinbase_with_raw_tdp_outputs(
    version: u32,
    scriptsig: &[u8],
    input_sequence: u32,
    total_output_count: u64,
    payout_outputs: &[(u64, Vec<u8>)],
    raw_tdp_outputs: &[u8],
    locktime: u32,
) -> Vec<u8> {
    let payout_size: usize = payout_outputs.iter().map(|(_, s)| 8 + 9 + s.len()).sum();
    let cap =
        4 + 1 + 32 + 4 + 9 + scriptsig.len() + 4 + 9 + payout_size + raw_tdp_outputs.len() + 4;
    let mut buf = Vec::with_capacity(cap);

    // version (LE u32 — consensus-equivalent to i32 for positive values)
    buf.extend_from_slice(&version.to_le_bytes());
    // input count = 1
    buf.push(0x01);
    // prev txid (32 zeros)
    buf.extend_from_slice(&[0u8; 32]);
    // prev vout = 0xFFFFFFFF
    buf.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    // scriptsig length + scriptsig
    encode_varint(&mut buf, scriptsig.len() as u64);
    buf.extend_from_slice(scriptsig);
    // input sequence
    buf.extend_from_slice(&input_sequence.to_le_bytes());
    // total output count (payouts + TDP-provided outputs)
    encode_varint(&mut buf, total_output_count);
    // our payout outputs first
    for (value, script) in payout_outputs {
        buf.extend_from_slice(&value.to_le_bytes());
        encode_varint(&mut buf, script.len() as u64);
        buf.extend_from_slice(script);
    }
    // TDP-provided outputs (already in raw TxOut wire form)
    buf.extend_from_slice(raw_tdp_outputs);
    // locktime
    buf.extend_from_slice(&locktime.to_le_bytes());
    buf
}

fn build_scriptsig(height_encoded: &[u8], identifier: &[u8], padding: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(1 + height_encoded.len() + identifier.len() + padding.len());
    // BIP-34 push opcode = length of the encoded height (1..=4 typically).
    s.push(height_encoded.len() as u8);
    s.extend_from_slice(height_encoded);
    s.extend_from_slice(identifier);
    s.extend_from_slice(padding);
    s
}

pub(crate) fn build_payout_outputs(
    network: Network,
    payouts: &[PayoutEntry],
    reward_sats: u64,
) -> Result<Vec<(u64, Vec<u8>)>, MiningJobError> {
    let mut outputs: Vec<(u64, Vec<u8>)> = Vec::with_capacity(payouts.len());
    let mut total_paid: u64 = 0;

    for p in payouts {
        // Place the exact sats the distributor computed. No percent re-derivation
        // — the distribution already summed to `reward_sats` precisely.
        let amount = p.sats;
        total_paid = total_paid.saturating_add(amount);
        let script = address::address_to_script(network, &p.address)?.into_bytes();
        outputs.push((amount, script));
    }

    // Reconcile to consume EXACTLY `reward_sats` so the coinbase can never be
    // rejected as bad-cb-amount. The distributors already sum to the reward, so
    // this is normally a no-op — it's a defensive guard, not the primary path.
    match total_paid.cmp(&reward_sats) {
        // Undershoot (an edge-case forfeited residuum): sweep the shortfall onto
        // the first output so the full reward is claimed.
        std::cmp::Ordering::Less => {
            outputs[0].0 = outputs[0].0.saturating_add(reward_sats - total_paid);
        }
        // Overshoot must never happen — the PPLNS solvency cap / group-solo /
        // blockparty allocators bound the sum at the reward. If a distributor bug
        // ever breaches that, a verbatim over-value coinbase would forfeit a real
        // found block; trimming the excess off the trailing outputs keeps the
        // block valid (strictly better than a lost block). `debug_assert` makes
        // the invariant loud in tests.
        std::cmp::Ordering::Greater => {
            debug_assert!(
                false,
                "coinbase payout overshoot: total_paid {total_paid} > reward {reward_sats}"
            );
            let mut excess = total_paid - reward_sats;
            for out in outputs.iter_mut().rev() {
                if excess == 0 {
                    break;
                }
                let cut = out.0.min(excess);
                out.0 -= cut;
                excess -= cut;
            }
        }
        std::cmp::Ordering::Equal => {}
    }

    Ok(outputs)
}

fn build_outputs(
    network: Network,
    payouts: &[PayoutEntry],
    reward_sats: u64,
    witness_commitment: &[u8; 32],
) -> Result<Vec<(u64, Vec<u8>)>, MiningJobError> {
    let mut outputs = build_payout_outputs(network, payouts, reward_sats)?;

    // Witness commitment OP_RETURN: OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed || commit
    let mut commit_data = [0u8; 36];
    commit_data[..4].copy_from_slice(&WITNESS_COMMIT_MAGIC);
    commit_data[4..].copy_from_slice(witness_commitment);
    let mut commit_script = Vec::with_capacity(38);
    commit_script.push(0x6a); // OP_RETURN
    commit_script.push(0x24); // OP_PUSHBYTES_36
    commit_script.extend_from_slice(&commit_data);
    outputs.push((0, commit_script));

    Ok(outputs)
}

fn serialize_coinbase_non_witness(
    scriptsig: &[u8],
    outputs: &[(u64, Vec<u8>)],
    sequence: u32,
    locktime: u32,
) -> Vec<u8> {
    let cap = 4
        + 1
        + 32
        + 4
        + 9
        + scriptsig.len()
        + 4
        + 9
        + outputs.iter().map(|(_, s)| 8 + 9 + s.len()).sum::<usize>()
        + 4;
    let mut buf = Vec::with_capacity(cap);

    // version = 2 (LE i32)
    buf.extend_from_slice(&2u32.to_le_bytes());
    // input count = 1
    buf.push(0x01);
    // prev txid (32 zeros)
    buf.extend_from_slice(&[0u8; 32]);
    // prev vout = 0xFFFFFFFF
    buf.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    // scriptsig length + scriptsig
    encode_varint(&mut buf, scriptsig.len() as u64);
    buf.extend_from_slice(scriptsig);
    // sequence (BIP-54: must be non-final)
    buf.extend_from_slice(&sequence.to_le_bytes());
    // output count
    encode_varint(&mut buf, outputs.len() as u64);
    for (value, script) in outputs {
        buf.extend_from_slice(&value.to_le_bytes());
        encode_varint(&mut buf, script.len() as u64);
        buf.extend_from_slice(script);
    }
    // locktime (BIP-54: block_height - 1)
    buf.extend_from_slice(&locktime.to_le_bytes());
    buf
}

/// BIP-34 minimal CScriptNum encoding of a positive block height.
/// Strips trailing zero bytes (high-order in LE) and appends a 0x00 sign
/// disambiguator if the most-significant byte's high bit would otherwise
/// indicate a negative number.
fn encode_block_height_minimal(height: u32) -> Vec<u8> {
    if height == 0 {
        return vec![];
    }
    let mut bytes = height.to_le_bytes().to_vec();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if let Some(&last) = bytes.last() {
        if last & 0x80 != 0 {
            bytes.push(0x00);
        }
    }
    bytes
}

fn encode_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

fn varint_size(n: u64) -> usize {
    if n < 0xfd {
        1
    } else if n <= 0xffff {
        3
    } else if n <= 0xffffffff {
        5
    } else {
        9
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::Decodable;

    fn template_with_height(height: u32) -> CoinbaseTemplate {
        CoinbaseTemplate {
            block_height: height,
            coinbase_value_sats: 5_000_000_000, // 50 BTC subsidy
            witness_commitment: [0u8; 32],
        }
    }

    fn single_payout(addr: &str) -> Vec<PayoutEntry> {
        // Single output → the builder's remainder guard tops it up to the full
        // reward regardless of the exact value seeded here.
        vec![PayoutEntry {
            address: addr.to_string(),
            sats: 5_000_000_000,
        }]
    }

    // ---- encode_block_height_minimal ----

    #[test]
    fn encode_block_height_well_known() {
        assert_eq!(encode_block_height_minimal(0), Vec::<u8>::new());
        assert_eq!(encode_block_height_minimal(1), vec![0x01]);
        assert_eq!(encode_block_height_minimal(0x7f), vec![0x7f]);
        // High bit set in single byte → append 0x00 disambiguator.
        assert_eq!(encode_block_height_minimal(0x80), vec![0x80, 0x00]);
        assert_eq!(encode_block_height_minimal(0xff), vec![0xff, 0x00]);
        // Multi-byte: 800000 = 0xC3500 → LE [0x00, 0x35, 0x0C, 0x00] → strip → [0x00, 0x35, 0x0C]
        assert_eq!(encode_block_height_minimal(800_000), vec![0x00, 0x35, 0x0c]);
    }

    // ---- varint ----

    #[test]
    fn varint_encoding_boundaries() {
        let mut buf = Vec::new();
        encode_varint(&mut buf, 0xFC);
        assert_eq!(buf, vec![0xFC]);

        buf.clear();
        encode_varint(&mut buf, 0xFD);
        assert_eq!(buf, vec![0xFD, 0xFD, 0x00]);

        buf.clear();
        encode_varint(&mut buf, 0xFFFF);
        assert_eq!(buf, vec![0xFD, 0xFF, 0xFF]);

        buf.clear();
        encode_varint(&mut buf, 0x10000);
        assert_eq!(buf, vec![0xFE, 0x00, 0x00, 0x01, 0x00]);
    }

    // ---- build_mining_job ----

    #[test]
    fn build_rejects_empty_payouts() {
        let template = template_with_height(100);
        assert!(matches!(
            build_mining_job(Network::Bitcoin, &[], &template, "BP", EXTRANONCE_SLOT_LEN),
            Err(MiningJobError::NoPayouts)
        ));
    }

    #[test]
    fn build_returns_non_empty_prefix_and_suffix() {
        let template = template_with_height(800_000);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "Blitzpool",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();
        assert!(!job.coinbase_prefix().is_empty());
        assert!(!job.coinbase_suffix().is_empty());
    }

    #[test]
    fn coinbase_txid_changes_with_extranonce() {
        let template = template_with_height(800_000);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "Blitzpool",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();

        let h1 = job.coinbase_txid_with_extranonce(&[1; 4], &[2; 8]);
        let h2 = job.coinbase_txid_with_extranonce(&[1; 4], &[3; 8]);
        let h3 = job.coinbase_txid_with_extranonce(&[9; 4], &[3; 8]);
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
    }

    #[test]
    fn coinbase_with_extranonce_parses_as_valid_bitcoin_tx() {
        let template = template_with_height(800_000);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();

        let enonce1 = [0x01, 0x02, 0x03, 0x04];
        let enonce2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20];

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&enonce1);
        full.extend_from_slice(&enonce2);
        full.extend_from_slice(job.coinbase_suffix());

        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice())
            .expect("non-witness coinbase must parse as a valid bitcoin tx");

        assert_eq!(tx.input.len(), 1);
        // 1 payout output + 1 witness-commit OP_RETURN.
        assert_eq!(tx.output.len(), 2);
        // First output value matches the full reward (single payout = 100%).
        assert_eq!(tx.output[0].value.to_sat(), 5_000_000_000);
        // Second output is the OP_RETURN witness commitment (zero value, 38-byte script).
        assert_eq!(tx.output[1].value.to_sat(), 0);
        assert_eq!(tx.output[1].script_pubkey.to_bytes().len(), 38);
        // Scriptsig must contain our spliced extranonce in the right slot.
        let scriptsig_bytes = tx.input[0].script_sig.to_bytes();
        let slot_start = scriptsig_bytes.len() - EXTRANONCE_SLOT_LEN;
        assert_eq!(&scriptsig_bytes[slot_start..slot_start + 4], &enonce1);
        assert_eq!(&scriptsig_bytes[slot_start + 4..], &enonce2);
    }

    #[test]
    fn build_mining_job_is_bip54_compliant() {
        // BIP-54: coinbase nLockTime = height-1, non-final nSequence,
        // witness-stripped size != 64.
        let height = 800_000;
        let template = template_with_height(height);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());

        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();
        assert_eq!(tx.lock_time.to_consensus_u32(), height - 1);
        assert_eq!(tx.input[0].sequence.0, COINBASE_NONFINAL_SEQUENCE);
        assert_ne!(tx.input[0].sequence.0, 0xffff_ffff);

        // Full BIP-54 validation against the non-witness bytes.
        crate::bip54::check_coinbase(&full, height).expect("BIP-54 compliant");
    }

    #[test]
    fn build_payout_outputs_places_exact_sats_verbatim() {
        // Regression: the distributor computes exact per-output sats (fixed
        // finder bonus, largest-remainder residuum). The coinbase builder must
        // place them verbatim — NOT re-derive `floor(percent/100 × reward)`,
        // which silently dropped a sat (a 50 000 000-sat bonus rounding to
        // 49 999 999). Mirrors a real Group-Solo block-template payout set.
        let reward = 316_672_616;
        let payouts = vec![
            PayoutEntry {
                address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
                sats: 4_750_092,
            },
            PayoutEntry {
                address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".into(),
                sats: 50_000_000, // finder bonus — must stay EXACT
            },
            PayoutEntry {
                address: "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy".into(),
                sats: reward - 4_750_092 - 50_000_000,
            },
        ];
        let outs = build_payout_outputs(Network::Bitcoin, &payouts, reward).unwrap();
        assert_eq!(outs[0].0, 4_750_092);
        assert_eq!(
            outs[1].0, 50_000_000,
            "finder bonus placed verbatim, not floored"
        );
        assert_eq!(outs[2].0, reward - 4_750_092 - 50_000_000);
        let total: u64 = outs.iter().map(|(amt, _)| *amt).sum();
        assert_eq!(total, reward, "coinbase sums to exactly the reward");
    }

    #[test]
    fn floor_remainder_added_to_first_output() {
        // 5_000_000_000 split 3 ways with floor: each gets 1_666_666_666, total = 4_999_999_998.
        // Remainder of 2 sats goes to outs[0] → 1_666_666_668.
        let template = template_with_height(100);
        let percent = 100.0 / 3.0;
        let payouts = vec![
            PayoutEntry::from_percent(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                percent,
                5_000_000_000,
            ),
            PayoutEntry::from_percent("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", percent, 5_000_000_000),
            PayoutEntry::from_percent("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", percent, 5_000_000_000),
        ];
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();

        // Parse the full coinbase via rust-bitcoin and inspect outputs.
        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();

        assert_eq!(tx.output[0].value.to_sat(), 1_666_666_668);
        assert_eq!(tx.output[1].value.to_sat(), 1_666_666_666);
        assert_eq!(tx.output[2].value.to_sat(), 1_666_666_666);
        // Sum of payouts must equal the full reward.
        let payout_sum: u64 = tx.output.iter().take(3).map(|o| o.to_sat_value()).sum();
        assert_eq!(payout_sum, 5_000_000_000);
    }

    #[test]
    fn witness_coinbase_is_valid_segwit_tx() {
        // The witness-form coinbase must round-trip through rust-bitcoin's
        // SegWit-aware decoder with marker/flag present and the 32-zero
        // witness reserved value attached to input 0.
        let template = template_with_height(800_000);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();

        let enonce1 = [0x01, 0x02, 0x03, 0x04];
        let enonce2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20];
        let bytes = job.witness_coinbase_with_extranonce(&enonce1, &enonce2);

        // BIP-141 marker + flag must sit right after the 4-byte version.
        assert_eq!(bytes[4], 0x00);
        assert_eq!(bytes[5], 0x01);

        let tx = bitcoin::Transaction::consensus_decode(&mut bytes.as_slice())
            .expect("witness-form coinbase must decode as a SegWit tx");

        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        // Coinbase witness: exactly one stack item, 32 zero bytes.
        let witness = &tx.input[0].witness;
        assert_eq!(witness.len(), 1);
        let item = witness.iter().next().unwrap();
        assert_eq!(item, &[0u8; 32]);
        // Scriptsig still contains our extranonce in the slot position.
        let ss = tx.input[0].script_sig.to_bytes();
        let slot_start = ss.len() - EXTRANONCE_SLOT_LEN;
        assert_eq!(&ss[slot_start..slot_start + 4], &enonce1);
        assert_eq!(&ss[slot_start + 4..], &enonce2);
    }

    #[test]
    fn witness_and_non_witness_share_the_same_outputs_and_scriptsig() {
        // Beyond the marker/flag insertion + witness-stack append, the two
        // forms must encode the same coinbase. Confirms our witness path
        // doesn't accidentally diverge from the non-witness path.
        let template = template_with_height(100);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();

        let e1 = [0x11; 4];
        let e2 = [0x22; 8];

        let mut non_witness = Vec::new();
        non_witness.extend_from_slice(job.coinbase_prefix());
        non_witness.extend_from_slice(&e1);
        non_witness.extend_from_slice(&e2);
        non_witness.extend_from_slice(job.coinbase_suffix());

        let nw_tx = bitcoin::Transaction::consensus_decode(&mut non_witness.as_slice()).unwrap();
        let witness_bytes = job.witness_coinbase_with_extranonce(&e1, &e2);
        let w_tx = bitcoin::Transaction::consensus_decode(&mut witness_bytes.as_slice()).unwrap();

        assert_eq!(nw_tx.version, w_tx.version);
        assert_eq!(nw_tx.lock_time, w_tx.lock_time);
        assert_eq!(nw_tx.input[0].script_sig, w_tx.input[0].script_sig);
        assert_eq!(nw_tx.input[0].sequence, w_tx.input[0].sequence);
        assert_eq!(nw_tx.output, w_tx.output);
        // txid (non-witness hash) must be identical.
        assert_eq!(nw_tx.compute_txid(), w_tx.compute_txid());
    }

    #[test]
    fn pool_identifier_dropped_when_scriptsig_overflows() {
        // 90-char pool identifier + height push + padding will exceed 100 bytes.
        let template = template_with_height(800_000);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let long_id = "x".repeat(90);
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            &long_id,
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();

        let scriptsig = tx.input[0].script_sig.to_bytes();
        assert!(scriptsig.len() <= MAX_SCRIPT_SIZE);
        // Identifier bytes ('x'*90) must NOT appear in the scriptsig.
        let xxx = b"xxxxxxxxxx";
        assert!(!scriptsig.windows(10).any(|w| w == xxx));
    }

    // Small helper shim because rust-bitcoin's `Amount` doesn't expose
    // `to_sat_value` — readability of the assertion above.
    trait ToSatVal {
        fn to_sat_value(&self) -> u64;
    }
    impl ToSatVal for bitcoin::TxOut {
        fn to_sat_value(&self) -> u64 {
            self.value.to_sat()
        }
    }

    // ---- build_mining_job_from_tdp ----

    /// Synthesize a witness-commit OP_RETURN TxOut as bitcoin-core would
    /// emit it in `NewTemplate.coinbase_tx_outputs`. Layout per TxOut:
    /// `[value:8 LE][scriptlen:varint][script:N]`.
    fn synthetic_witness_commit_txout_bytes(commit: [u8; 32]) -> Vec<u8> {
        let mut script = Vec::with_capacity(38);
        script.push(0x6a); // OP_RETURN
        script.push(0x24); // OP_PUSHBYTES_36
        script.extend_from_slice(&WITNESS_COMMIT_MAGIC);
        script.extend_from_slice(&commit);
        let mut out = Vec::with_capacity(8 + 1 + 38);
        out.extend_from_slice(&0u64.to_le_bytes()); // value = 0
        out.push(0x26); // 38-byte varint (<0xfd path, single byte)
        out.extend_from_slice(&script);
        out
    }

    /// Build a minimal-realistic `TdpCoinbaseTemplate`: BIP-34 height push
    /// as the coinbase_prefix (height 800k), one OP_RETURN witness-commit
    /// output, version 2, sequence 0xFFFFFFFF, locktime 0.
    fn tdp_template_for(commit: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        // BIP-34 prefix = `[push_height_len][height_LE_minimal]`.
        // For height 800_000 → [0x03, 0x00, 0x35, 0x0c].
        let mut prefix = Vec::new();
        prefix.push(0x03);
        prefix.extend_from_slice(&[0x00, 0x35, 0x0c]);
        let outputs = synthetic_witness_commit_txout_bytes(commit);
        (prefix, outputs)
    }

    #[test]
    fn tdp_build_rejects_empty_payouts() {
        let (prefix, outputs) = tdp_template_for([0u8; 32]);
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        assert!(matches!(
            build_mining_job_from_tdp(Network::Bitcoin, &[], &template, "BP", EXTRANONCE_SLOT_LEN),
            Err(MiningJobError::NoPayouts)
        ));
    }

    #[test]
    fn tdp_build_returns_decodable_coinbase() {
        let (prefix, outputs) = tdp_template_for([0xAA; 32]);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "Blitzpool",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();

        let e1 = [0x01, 0x02, 0x03, 0x04];
        let e2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20];
        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&e1);
        full.extend_from_slice(&e2);
        full.extend_from_slice(job.coinbase_suffix());

        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice())
            .expect("TDP-built coinbase must parse as a valid bitcoin tx");

        assert_eq!(tx.input.len(), 1);
        // 1 payout output + 1 TDP-provided witness-commit OP_RETURN.
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value.to_sat(), 5_000_000_000);
        assert_eq!(tx.output[1].value.to_sat(), 0);
        // Second output is the OP_RETURN witness commitment (38-byte script).
        assert_eq!(tx.output[1].script_pubkey.to_bytes().len(), 38);
        // Scriptsig must end with our spliced extranonce.
        let ss = tx.input[0].script_sig.to_bytes();
        let slot_start = ss.len() - EXTRANONCE_SLOT_LEN;
        assert_eq!(&ss[slot_start..slot_start + 4], &e1);
        assert_eq!(&ss[slot_start + 4..], &e2);
        // BIP-34 height push must still be at the start.
        assert_eq!(&ss[..4], &prefix[..]);
    }

    #[test]
    fn tdp_build_honors_version_sequence_and_locktime() {
        // Non-default values for all three fields. Verifies they aren't
        // hard-coded to the build_mining_job(...) constants.
        let (prefix, outputs) = tdp_template_for([0u8; 32]);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 1,
            coinbase_tx_input_sequence: 0xFFFFFFFE, // BIP-125 RBF signal
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0x12345678,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();

        assert_eq!(tx.version.0, 1);
        assert_eq!(tx.input[0].sequence.0, 0xFFFFFFFE);
        assert_eq!(tx.lock_time.to_consensus_u32(), 0x12345678);
    }

    #[test]
    fn tdp_build_floor_remainder_goes_to_first_payout() {
        // Same arithmetic as the non-TDP test: 5_000_000_000 / 3 with floor
        // leaves 2 sats remainder that lands on outs[0].
        let (prefix, outputs) = tdp_template_for([0u8; 32]);
        let percent = 100.0 / 3.0;
        let payouts = vec![
            PayoutEntry::from_percent(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                percent,
                5_000_000_000,
            ),
            PayoutEntry::from_percent("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", percent, 5_000_000_000),
            PayoutEntry::from_percent("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", percent, 5_000_000_000),
        ];
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();

        // Output order: payouts first, then TDP-provided OP_RETURN.
        assert_eq!(tx.output.len(), 4);
        assert_eq!(tx.output[0].value.to_sat(), 1_666_666_668);
        assert_eq!(tx.output[1].value.to_sat(), 1_666_666_666);
        assert_eq!(tx.output[2].value.to_sat(), 1_666_666_666);
        assert_eq!(tx.output[3].value.to_sat(), 0); // witness-commit
        let payout_sum: u64 = tx.output.iter().take(3).map(|o| o.to_sat_value()).sum();
        assert_eq!(payout_sum, 5_000_000_000);
    }

    #[test]
    fn tdp_build_pool_identifier_dropped_on_overflow() {
        // TDP prefix already 4 bytes (BIP-34 height push for 800k); add a
        // 90-char identifier and the resulting scriptsig (4 + 90 + 12 = 106)
        // overflows the 100-byte limit. Function must drop identifier.
        let (prefix, outputs) = tdp_template_for([0u8; 32]);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let long_id = "x".repeat(90);
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            &long_id,
            EXTRANONCE_SLOT_LEN,
        )
        .expect("must succeed by dropping the identifier");

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();
        let ss = tx.input[0].script_sig.to_bytes();
        // BIP-34 prefix (4) + slot (12) = 16 bytes. No identifier bytes.
        assert_eq!(ss.len(), 4 + EXTRANONCE_SLOT_LEN);
        assert_eq!(&ss[..4], &prefix[..]);
        // No 'x' bytes anywhere.
        assert!(!ss.contains(&b'x'));
    }

    #[test]
    fn tdp_build_pool_identifier_kept_when_it_fits() {
        // 4-byte prefix + 10-byte identifier + 12-byte slot = 26 bytes — fits.
        let (prefix, outputs) = tdp_template_for([0u8; 32]);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "Blitzpool",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();
        let ss = tx.input[0].script_sig.to_bytes();
        // Identifier must be present between prefix and slot.
        let id_start = prefix.len();
        let id_end = ss.len() - EXTRANONCE_SLOT_LEN;
        assert_eq!(&ss[id_start..id_end], b"Blitzpool");
    }

    #[test]
    fn tdp_build_txid_changes_with_extranonce() {
        let (prefix, outputs) = tdp_template_for([0u8; 32]);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();

        let h1 = job.coinbase_txid_with_extranonce(&[1; 4], &[2; 8]);
        let h2 = job.coinbase_txid_with_extranonce(&[1; 4], &[3; 8]);
        let h3 = job.coinbase_txid_with_extranonce(&[9; 4], &[3; 8]);
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
    }

    #[test]
    fn tdp_build_witness_coinbase_decodes_as_segwit_tx() {
        // The shared MiningJob layout means the witness path works
        // identically for TDP-built jobs.
        let (prefix, outputs) = tdp_template_for([0xCC; 32]);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();

        let e1 = [0x01, 0x02, 0x03, 0x04];
        let e2 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20];
        let bytes = job.witness_coinbase_with_extranonce(&e1, &e2);

        let tx = bitcoin::Transaction::consensus_decode(&mut bytes.as_slice())
            .expect("witness-form TDP coinbase must decode as a SegWit tx");
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        let witness = &tx.input[0].witness;
        assert_eq!(witness.len(), 1);
        assert_eq!(witness.iter().next().unwrap(), &[0u8; 32]);
    }

    #[test]
    fn tdp_build_multiple_tdp_outputs_are_passed_through() {
        // Synthesize TWO TDP outputs (an OP_RETURN witness-commit + a
        // policy output bitcoin-core's `CoinbaseOutputConstraints` might
        // include later). Both must land in the final coinbase verbatim,
        // after our payout outputs, in the order given.
        let mut tdp_outputs = synthetic_witness_commit_txout_bytes([0xEE; 32]);
        // Second TDP output: 100-sat OP_RETURN with "POL".
        tdp_outputs.extend_from_slice(&100u64.to_le_bytes());
        tdp_outputs.push(0x05); // scriptlen = 5
        tdp_outputs.extend_from_slice(&[0x6a, 0x03, b'P', b'O', b'L']);

        let (prefix, _) = tdp_template_for([0u8; 32]);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFFFFFF,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &tdp_outputs,
            coinbase_tx_outputs_count: 2,
            coinbase_tx_locktime: 0,
        };
        let job = build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap();

        let mut full = Vec::new();
        full.extend_from_slice(job.coinbase_prefix());
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(job.coinbase_suffix());
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice()).unwrap();

        // 1 payout + 2 TDP outputs.
        assert_eq!(tx.output.len(), 3);
        assert_eq!(tx.output[0].value.to_sat(), 5_000_000_000);
        assert_eq!(tx.output[1].value.to_sat(), 0); // witness-commit
        assert_eq!(tx.output[2].value.to_sat(), 100); // policy output
                                                      // Policy output script is exactly what we put in the TDP blob.
        assert_eq!(
            tx.output[2].script_pubkey.to_bytes(),
            vec![0x6a, 0x03, b'P', b'O', b'L']
        );
    }
}
