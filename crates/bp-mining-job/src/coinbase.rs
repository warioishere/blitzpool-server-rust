// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coinbase transaction construction with multi-output payouts, BIP-34 block-height
//! encoding, BIP-141 witness commitment, and stateless extranonce splicing.

use bitcoin::Network;
use bp_share::sha256d_from_parts;
use tracing::warn;

use crate::address;

/// Length in bytes of the extranonce slot embedded in the scriptsig:
/// 4 bytes enonce1 + 8 bytes enonce2 (Braiins Hashpower requires an
/// enonce2 of at least 7 bytes).
pub const EXTRANONCE_SLOT_LEN: usize = 12;

const MAX_SCRIPT_SIZE: usize = 100;
const WITNESS_COMMIT_MAGIC: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

/// Non-final coinbase input `nSequence` required by BIP-54 (anything but
/// `0xffffffff`). Matches the value Core 31's template provider emits.
const COINBASE_NONFINAL_SEQUENCE: u32 = 0xffff_fffe;

/// A miner-payout entry carrying the exact satoshis, placed verbatim:
/// re-deriving them from a float percentage would drop up to a sat per output.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PayoutEntry {
    pub address: String,
    /// Exact output amount in satoshis.
    pub sats: u64,
}

impl PayoutEntry {
    /// Floor `percent`% of `reward_sats` to an exact output. Used by the Solo
    /// split and tests; the other distributors carry exact sats already.
    pub fn from_percent(address: impl Into<String>, percent: f64, reward_sats: u64) -> Self {
        Self {
            address: address.into(),
            sats: ((percent / 100.0) * reward_sats as f64).floor() as u64,
        }
    }
}

/// A resolved payout list plus the fingerprint of the distribution behind it.
/// The fingerprint travels with the entries because one distribution yields
/// different sats at different revenues yet settles through one snapshot; a
/// zeroed fingerprint means "books without a snapshot".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPayouts {
    pub entries: Vec<PayoutEntry>,
    pub payouts_fingerprint: [u8; 32],
}

impl ResolvedPayouts {
    /// A list that books without a settlement snapshot (zeroed
    /// fingerprint): Solo and Blockparty, plus every fallback path.
    pub fn unsnapshotted(entries: Vec<PayoutEntry>) -> Self {
        Self {
            entries,
            payouts_fingerprint: [0u8; 32],
        }
    }

    /// Serve no job: the answer when a mode's distribution could not be built.
    /// A solo list instead would pay a PPLNS or Group-Solo block entirely to
    /// the connecting miner; withholding the job costs only hashing time.
    pub fn none() -> Self {
        Self::unsnapshotted(Vec::new())
    }

    /// Is this "serve no job"?
    pub fn is_none(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The block-template fields needed for coinbase construction.
#[derive(Clone, Debug)]
pub struct CoinbaseTemplate {
    pub block_height: u32,
    pub coinbase_value_sats: u64,
    /// Witness commitment hash, already double-SHA256'd by the template
    /// provider.
    pub witness_commitment: [u8; 32],
}

/// A coinbase split into its non-witness bytes before and after the
/// extranonce slot, so each share splices its extranonce in without rebuilding
/// or mutating shared state.
#[derive(Clone, Debug)]
pub struct MiningJob {
    coinbase_prefix: Vec<u8>,
    coinbase_suffix: Vec<u8>,
    /// Precomputed hex, because SV1 `mining.notify` borrows it for every client.
    coinbase_prefix_hex: String,
    coinbase_suffix_hex: String,
    /// Identity of the distribution this coinbase pays, so a block found on
    /// it books exactly that distribution rather than whatever the shared
    /// snapshot key holds by then.
    payouts_fingerprint: [u8; 32],
}

impl MiningJob {
    pub fn coinbase_prefix(&self) -> &[u8] {
        &self.coinbase_prefix
    }

    pub fn coinbase_suffix(&self) -> &[u8] {
        &self.coinbase_suffix
    }

    /// Identity of the payout list this job's coinbase pays.
    pub fn payouts_fingerprint(&self) -> &[u8; 32] {
        &self.payouts_fingerprint
    }

    /// Hex of the coinbase prefix: the `coinb1` slot of a `mining.notify`.
    pub fn coinbase_prefix_hex(&self) -> &str {
        &self.coinbase_prefix_hex
    }

    /// Hex of the coinbase suffix: the `coinb2` slot of a `mining.notify`.
    pub fn coinbase_suffix_hex(&self) -> &str {
        &self.coinbase_suffix_hex
    }

    /// Splice the 4-byte extranonce1 and 8-byte extranonce2 into the
    /// scriptsig and return the resulting coinbase txid (sha256d of the
    /// non-witness serialization).
    pub fn coinbase_txid_with_extranonce(&self, enonce1: &[u8; 4], enonce2: &[u8; 8]) -> [u8; 32] {
        // Streamed, so no per-share `Vec`.
        sha256d_from_parts(&[
            self.coinbase_prefix.as_slice(),
            enonce1.as_slice(),
            enonce2.as_slice(),
            self.coinbase_suffix.as_slice(),
        ])
    }

    /// Splice the extranonce in and return the witness-form coinbase for block
    /// submission; share validation needs only the non-witness txid.
    pub fn witness_coinbase_with_extranonce(
        &self,
        enonce1: &[u8; 4],
        enonce2: &[u8; 8],
    ) -> Vec<u8> {
        let mut stratum = Vec::with_capacity(
            self.coinbase_prefix.len() + EXTRANONCE_SLOT_LEN + self.coinbase_suffix.len(),
        );
        stratum.extend_from_slice(&self.coinbase_prefix);
        stratum.extend_from_slice(enonce1);
        stratum.extend_from_slice(enonce2);
        stratum.extend_from_slice(&self.coinbase_suffix);
        assemble_witness_coinbase(&stratum)
    }
}

/// Convert a non-witness coinbase into the BIP-141 witness form `submitblock`
/// expects (marker + flag after `version`, the 32-zero reserved value before
/// `locktime`). The one implementation, shared by SV1
/// ([`MiningJob::witness_coinbase_with_extranonce`]), SV2 and JDP.
pub fn assemble_witness_coinbase(stratum_coinbase: &[u8]) -> Vec<u8> {
    debug_assert!(
        stratum_coinbase.len() >= 8,
        "stratum coinbase smaller than version+locktime"
    );
    let locktime_at = stratum_coinbase.len() - 4;
    let mut buf = Vec::with_capacity(stratum_coinbase.len() + 2 + 1 + 1 + 32);
    // version
    buf.extend_from_slice(&stratum_coinbase[..4]);
    // BIP-141 marker + flag
    buf.push(0x00);
    buf.push(0x01);
    // everything between version and locktime (input + outputs)
    buf.extend_from_slice(&stratum_coinbase[4..locktime_at]);
    // witness stack: 1 item of 32 zero bytes
    buf.push(0x01);
    buf.push(0x20);
    buf.extend_from_slice(&[0u8; 32]);
    // locktime
    buf.extend_from_slice(&stratum_coinbase[locktime_at..]);
    buf
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

/// Build a `MiningJob` (RPC path). The pool identifier is dropped if the
/// scriptsig would exceed the consensus limit; `extranonce_slot_size` is the
/// full negotiated width so the scriptsig varint matches the wire. BIP-54:
/// `nLockTime = height - 1` and a non-final `nSequence`.
pub fn build_mining_job(
    network: Network,
    payouts: &[PayoutEntry],
    template: &CoinbaseTemplate,
    pool_identifier: &str,
    extranonce_slot_size: usize,
    payouts_fingerprint: [u8; 32],
) -> Result<MiningJob, MiningJobError> {
    if payouts.is_empty() {
        return Err(MiningJobError::NoPayouts);
    }

    let height_encoded = encode_block_height_minimal(template.block_height);
    let height_len = height_encoded.len();
    let padding_len = extranonce_slot_size + 3usize.saturating_sub(height_len);
    let padding = vec![0u8; padding_len];

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

    // The extranonce slot between prefix and suffix is never materialized.
    let locktime = template.block_height.saturating_sub(1);
    let coinbase_prefix = serialize_coinbase_prefix(
        2,
        &script_sig[..script_sig.len() - extranonce_slot_size],
        script_sig.len(),
    );
    let coinbase_suffix = serialize_coinbase_suffix(
        COINBASE_NONFINAL_SEQUENCE,
        outputs.len() as u64,
        &outputs,
        &[], // RPC path: no template-provided raw outputs (witness commit is in `outputs`)
        locktime,
    );
    let coinbase_prefix_hex = hex::encode(&coinbase_prefix);
    let coinbase_suffix_hex = hex::encode(&coinbase_suffix);

    Ok(MiningJob {
        coinbase_prefix,
        coinbase_suffix,
        coinbase_prefix_hex,
        coinbase_suffix_hex,
        payouts_fingerprint,
    })
}

/// The `NewTemplate` fields needed for coinbase assembly, taken verbatim.
#[derive(Clone, Debug)]
pub struct TdpCoinbaseTemplate<'a> {
    /// BIP-34 height push plus any Core-injected data; the pool identifier and
    /// extranonce slot are appended after it.
    pub coinbase_prefix: &'a [u8],
    pub coinbase_tx_version: u32,
    pub coinbase_tx_input_sequence: u32,
    /// Value left after Core's required outputs: what the payouts split.
    pub coinbase_tx_value_remaining: u64,
    /// Raw concatenated TxOuts, without an output-count varint (the count is
    /// `coinbase_tx_outputs_count`).
    pub coinbase_tx_outputs: &'a [u8],
    pub coinbase_tx_outputs_count: u32,
    pub coinbase_tx_locktime: u32,
}

/// Build a `MiningJob` from a TDP `NewTemplate`: the scriptsig extends the
/// template's prefix, payouts come before the template outputs, and
/// version / sequence / locktime come from the template. Same prefix/suffix
/// split as [`build_mining_job`].
pub fn build_mining_job_from_tdp(
    network: Network,
    payouts: &[PayoutEntry],
    template: &TdpCoinbaseTemplate<'_>,
    pool_identifier: &str,
    extranonce_slot_size: usize,
    payouts_fingerprint: [u8; 32],
) -> Result<MiningJob, MiningJobError> {
    if payouts.is_empty() {
        return Err(MiningJobError::NoPayouts);
    }

    // Scriptsig before outputs: NoPayouts → ScriptSigTooLong → InvalidAddress,
    // as in `MiningJobCache`, so both report the same cause for the same inputs.
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
        payouts_fingerprint,
    ))
}

/// Build the TDP scriptsig, dropping the pool identifier if it would exceed
/// the consensus limit. Shared so [`crate::cache::MiningJobCache`] runs the
/// same check in the same order as [`build_mining_job_from_tdp`].
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

/// Assemble a `MiningJob` from an already-checked scriptsig and already-built
/// outputs, so [`crate::cache::MiningJobCache`] can reuse parsed outputs across
/// builds that differ only in slot size or template fields.
pub(crate) fn assemble_tdp_job(
    script_sig: Vec<u8>,
    payout_outputs: &[(u64, Vec<u8>)],
    template: &TdpCoinbaseTemplate<'_>,
    extranonce_slot_size: usize,
    // Passed in: it identifies the distribution, which `payout_outputs`
    // (sats, script) cannot express.
    payouts_fingerprint: [u8; 32],
) -> MiningJob {
    let total_output_count =
        payout_outputs.len() as u64 + u64::from(template.coinbase_tx_outputs_count);

    let coinbase_prefix = serialize_coinbase_prefix(
        template.coinbase_tx_version,
        &script_sig[..script_sig.len() - extranonce_slot_size],
        script_sig.len(),
    );
    let coinbase_suffix = serialize_coinbase_suffix(
        template.coinbase_tx_input_sequence,
        total_output_count,
        payout_outputs,
        template.coinbase_tx_outputs,
        template.coinbase_tx_locktime,
    );
    let coinbase_prefix_hex = hex::encode(&coinbase_prefix);
    let coinbase_suffix_hex = hex::encode(&coinbase_suffix);

    MiningJob {
        coinbase_prefix,
        coinbase_suffix,
        coinbase_prefix_hex,
        coinbase_suffix_hex,
        payouts_fingerprint,
    }
}

fn build_tdp_scriptsig(tdp_prefix: &[u8], identifier: &[u8], slot_len: usize) -> Vec<u8> {
    let mut s = Vec::with_capacity(tdp_prefix.len() + identifier.len() + slot_len);
    s.extend_from_slice(tdp_prefix);
    s.extend_from_slice(identifier);
    s.extend(std::iter::repeat_n(0u8, slot_len));
    s
}

/// Serialize the coinbase up to the extranonce slot. `scriptsig_len` is the
/// full length including the slot spliced in per share. The one implementation,
/// shared with SV2's `SetCustomMiningJob`, whose head comes from the JDC.
pub fn serialize_coinbase_prefix(
    version: u32,
    scriptsig_head: &[u8],
    scriptsig_len: usize,
) -> Vec<u8> {
    debug_assert!(scriptsig_head.len() <= scriptsig_len);
    let mut buf = Vec::with_capacity(4 + 1 + 32 + 4 + 9 + scriptsig_head.len());
    // version (LE u32 — consensus-equivalent to i32 for positive values)
    buf.extend_from_slice(&version.to_le_bytes());
    // input count = 1
    buf.push(0x01);
    // prev txid (32 zeros) + prev vout = 0xFFFFFFFF
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    // scriptsig length (FULL length, incl. the slot) + scriptsig up to the slot
    encode_varint(&mut buf, scriptsig_len as u64);
    buf.extend_from_slice(scriptsig_head);
    buf
}

/// Serialize the coinbase from nSequence on; counterpart to
/// [`serialize_coinbase_prefix`]. `raw_extra_outputs` is empty on the RPC path.
fn serialize_coinbase_suffix(
    input_sequence: u32,
    total_output_count: u64,
    payout_outputs: &[(u64, Vec<u8>)],
    raw_extra_outputs: &[u8],
    locktime: u32,
) -> Vec<u8> {
    let payout_size: usize = payout_outputs.iter().map(|(_, s)| 8 + 9 + s.len()).sum();
    let cap = 4 + 9 + payout_size + raw_extra_outputs.len() + 4;
    let mut buf = Vec::with_capacity(cap);
    // input sequence
    buf.extend_from_slice(&input_sequence.to_le_bytes());
    // total output count (payouts + any template-provided outputs)
    encode_varint(&mut buf, total_output_count);
    // payout outputs first
    for (value, script) in payout_outputs {
        buf.extend_from_slice(&value.to_le_bytes());
        encode_varint(&mut buf, script.len() as u64);
        buf.extend_from_slice(script);
    }
    // template-provided outputs (already in raw TxOut wire form; empty on RPC)
    buf.extend_from_slice(raw_extra_outputs);
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
        let amount = p.sats;
        total_paid = total_paid.saturating_add(amount);
        let script = address::address_to_script(network, &p.address)?.into_bytes();
        outputs.push((amount, script));
    }

    // Consume exactly `reward_sats`, so the coinbase is never bad-cb-amount.
    match total_paid.cmp(&reward_sats) {
        // Sweep a shortfall onto the first output so the full reward is claimed.
        std::cmp::Ordering::Less => {
            outputs[0].0 = outputs[0].0.saturating_add(reward_sats - total_paid);
        }
        // Never expected; an over-value coinbase would invalidate a found
        // block, so trim the excess off the trailing outputs.
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

/// BIP-34 minimal CScriptNum encoding of a positive block height; a 0x00 is
/// appended when the top bit would otherwise read as negative.
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

/// Solo-mode dev-fee settings, the inputs of `solo_payouts`.
#[derive(Clone, Debug)]
pub struct SoloFeeConfig {
    /// Bitcoin address that receives the dev fee on solo payouts.
    /// `None` disables dev fee — full reward to miner.
    pub dev_fee_address: Option<String>,
    /// Dev fee in `[0.0, 100.0]`. Ignored when `dev_fee_address` is `None`.
    pub dev_fee_percent: f64,
}

impl Default for SoloFeeConfig {
    fn default() -> Self {
        Self {
            dev_fee_address: None,
            dev_fee_percent: 0.0,
        }
    }
}

/// Solo-mode coinbase split, shared by the payout resolver and the
/// block-template preview so the preview shows exactly the job's outputs. The
/// dev fee floors and the miner takes the remainder, so the sum is exact.
pub fn solo_payouts(
    miner_address: &str,
    fee: &SoloFeeConfig,
    reward_sats: u64,
) -> Vec<PayoutEntry> {
    let dev_addr = fee
        .dev_fee_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let percent = fee.dev_fee_percent;
    let full_to_miner = || {
        vec![PayoutEntry {
            address: miner_address.to_string(),
            sats: reward_sats,
        }]
    };
    match (miner_address.is_empty(), dev_addr) {
        (true, _) => vec![],
        (false, None) => full_to_miner(),
        (false, Some(_dev)) if !(0.0..=100.0).contains(&percent) => {
            warn!(
                percent,
                "solo dev_fee_percent out of [0,100]; ignoring fee + paying 100% to miner"
            );
            full_to_miner()
        }
        (false, Some(_dev)) if percent <= 0.0 => {
            // No zero-value dev output.
            full_to_miner()
        }
        (false, Some(dev)) => {
            let dev = PayoutEntry::from_percent(dev, percent, reward_sats);
            let miner_sats = reward_sats.saturating_sub(dev.sats);
            vec![
                dev,
                PayoutEntry {
                    address: miner_address.to_string(),
                    sats: miner_sats,
                },
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the BIP-141 witness layout byte by byte.
    #[test]
    fn assemble_witness_coinbase_pins_bip141_layout() {
        // Minimal coinbase: 4B version + 4B body + 4B locktime = 12B.
        let mut stratum = Vec::with_capacity(12);
        stratum.extend_from_slice(&1u32.to_le_bytes()); // version=1
        stratum.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // body
        stratum.extend_from_slice(&[0xEE, 0xEE, 0xEE, 0xEE]); // locktime
        let w = assemble_witness_coinbase(&stratum);
        // 12 stratum bytes + 2 marker/flag + 1 stack-count + 1 item-len
        // + 32 witness bytes = 48.
        assert_eq!(w.len(), 12 + 2 + 1 + 1 + 32);
        // Version intact.
        assert_eq!(&w[..4], &1u32.to_le_bytes());
        // Marker + flag.
        assert_eq!(w[4], 0x00);
        assert_eq!(w[5], 0x01);
        // Body intact.
        assert_eq!(&w[6..10], &[0xAA, 0xBB, 0xCC, 0xDD]);
        // Witness stack: count=1, len=0x20, 32 zero bytes.
        assert_eq!(w[10], 0x01);
        assert_eq!(w[11], 0x20);
        assert!(w[12..44].iter().all(|b| *b == 0));
        // Locktime intact.
        assert_eq!(&w[44..], &[0xEE, 0xEE, 0xEE, 0xEE]);
    }
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
            build_mining_job(
                Network::Bitcoin,
                &[],
                &template,
                "BP",
                EXTRANONCE_SLOT_LEN,
                [0u8; 32]
            ),
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
            [0u8; 32],
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
            [0u8; 32],
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
            [0u8; 32],
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
        // Scriptsig must contain the spliced extranonce in the right slot.
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
            [0u8; 32],
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
        // Exact per-output sats (fixed finder bonus, largest-remainder
        // residuum) are placed verbatim, not re-derived from a percentage,
        // which would floor a 50 000 000-sat bonus to 49 999 999.
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
            [0u8; 32],
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
            [0u8; 32],
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
        // Scriptsig still contains the extranonce in the slot position.
        let ss = tx.input[0].script_sig.to_bytes();
        let slot_start = ss.len() - EXTRANONCE_SLOT_LEN;
        assert_eq!(&ss[slot_start..slot_start + 4], &enonce1);
        assert_eq!(&ss[slot_start + 4..], &enonce2);
    }

    #[test]
    fn witness_and_non_witness_share_the_same_outputs_and_scriptsig() {
        // Beyond the marker/flag insertion + witness-stack append, the two
        // forms must encode the same coinbase.
        let template = template_with_height(100);
        let payouts = single_payout("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let job = build_mining_job(
            Network::Bitcoin,
            &payouts,
            &template,
            "BP",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
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
            [0u8; 32],
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

    /// The direct prefix/suffix equal the full coinbase sliced around the slot.
    #[test]
    fn tdp_direct_split_matches_full_serialize_then_split() {
        let (prefix, outputs) = tdp_template_for([0x5A; 32]);
        // Two payouts so the output loop + the count varint are exercised, and
        // a non-default sequence / locktime so those fields can't silently drift.
        let payouts = vec![
            PayoutEntry {
                address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                sats: 3_000_000_000,
            },
            PayoutEntry {
                address: "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
                    .to_string(),
                sats: 2_000_000_000,
            },
        ];
        let slot = EXTRANONCE_SLOT_LEN;
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &prefix,
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xFFFF_FFFE,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: &outputs,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 42,
        };
        let job =
            build_mining_job_from_tdp(Network::Bitcoin, &payouts, &template, "BP", slot, [0u8; 32])
                .unwrap();

        // Reference oracle: build the full coinbase, then slice.
        let script_sig = checked_tdp_scriptsig(template.coinbase_prefix, "BP", slot).unwrap();
        let payout_outputs = build_payout_outputs(
            Network::Bitcoin,
            &payouts,
            template.coinbase_tx_value_remaining,
        )
        .unwrap();
        let total_output_count =
            payout_outputs.len() as u64 + u64::from(template.coinbase_tx_outputs_count);
        let mut full = Vec::new();
        full.extend_from_slice(&template.coinbase_tx_version.to_le_bytes());
        full.push(0x01);
        full.extend_from_slice(&[0u8; 32]);
        full.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        encode_varint(&mut full, script_sig.len() as u64);
        full.extend_from_slice(&script_sig);
        full.extend_from_slice(&template.coinbase_tx_input_sequence.to_le_bytes());
        encode_varint(&mut full, total_output_count);
        for (v, s) in &payout_outputs {
            full.extend_from_slice(&v.to_le_bytes());
            encode_varint(&mut full, s.len() as u64);
            full.extend_from_slice(s);
        }
        full.extend_from_slice(template.coinbase_tx_outputs);
        full.extend_from_slice(&template.coinbase_tx_locktime.to_le_bytes());

        let varint_len = match script_sig.len() as u64 {
            n if n < 0xfd => 1,
            n if n <= 0xffff => 3,
            n if n <= 0xffff_ffff => 5,
            _ => 9,
        };
        let prefix_end = 4 + 1 + 32 + 4 + varint_len + script_sig.len() - slot;
        let suffix_start = prefix_end + slot;

        assert_eq!(
            job.coinbase_prefix(),
            &full[..prefix_end],
            "direct prefix must equal the old full-then-split prefix"
        );
        assert_eq!(
            job.coinbase_suffix(),
            &full[suffix_start..],
            "direct suffix must equal the old full-then-split suffix"
        );
        // The precomputed hex mirrors the bytes exactly.
        assert_eq!(job.coinbase_prefix_hex(), hex::encode(&full[..prefix_end]));
        assert_eq!(
            job.coinbase_suffix_hex(),
            hex::encode(&full[suffix_start..])
        );
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
            build_mining_job_from_tdp(
                Network::Bitcoin,
                &[],
                &template,
                "BP",
                EXTRANONCE_SLOT_LEN,
                [0u8; 32]
            ),
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
            [0u8; 32],
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
        // Scriptsig must end with the spliced extranonce.
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
            [0u8; 32],
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
            [0u8; 32],
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
            [0u8; 32],
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
            [0u8; 32],
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
            [0u8; 32],
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
            [0u8; 32],
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
        // second policy output). Both must land in the final coinbase
        // verbatim, after the payout outputs, in the order given.
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
            [0u8; 32],
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
                                                      // Policy output script is exactly the bytes from the TDP blob.
        assert_eq!(
            tx.output[2].script_pubkey.to_bytes(),
            vec![0x6a, 0x03, b'P', b'O', b'L']
        );
    }
}

#[cfg(test)]
mod solo_split_tests {
    use super::*;

    const REWARD: u64 = 5_000_000_000;

    fn fee(address: Option<&str>, percent: f64) -> SoloFeeConfig {
        SoloFeeConfig {
            dev_fee_address: address.map(str::to_string),
            dev_fee_percent: percent,
        }
    }

    /// With no solo dev fee configured the split is a single output to the
    /// miner, whatever the PPLNS fee config says.
    #[test]
    fn without_a_dev_fee_the_solo_split_is_a_single_output() {
        let out = solo_payouts("bc1qminer", &fee(None, 0.0), REWARD);
        assert_eq!(out.len(), 1, "no second output: {out:?}");
        assert_eq!(out[0].address, "bc1qminer");
        assert_eq!(out[0].sats, REWARD);
    }

    /// A dev address with the default 0 % yields no zero-value output.
    #[test]
    fn a_zero_percent_dev_fee_is_not_an_output() {
        let out = solo_payouts("bc1qminer", &fee(Some("bc1qdev"), 0.0), REWARD);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].sats, REWARD);
    }

    /// A configured fee splits, and the two outputs sum to exactly the reward.
    #[test]
    fn a_configured_dev_fee_splits_and_conserves_every_satoshi() {
        let out = solo_payouts("bc1qminer", &fee(Some("bc1qdev"), 1.0), REWARD);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].address, "bc1qdev");
        assert_eq!(out[1].address, "bc1qminer");
        assert_eq!(
            out[0].sats + out[1].sats,
            REWARD,
            "the split must conserve the reward exactly"
        );
    }

    #[test]
    fn an_empty_or_whitespace_dev_address_is_ignored() {
        assert_eq!(
            solo_payouts("bc1qminer", &fee(Some(""), 1.0), REWARD).len(),
            1
        );
        assert_eq!(
            solo_payouts("bc1qminer", &fee(Some("   "), 1.0), REWARD).len(),
            1
        );
    }

    #[test]
    fn an_out_of_range_percent_falls_back_to_the_miner() {
        assert_eq!(
            solo_payouts("bc1qminer", &fee(Some("bc1qdev"), 101.0), REWARD).len(),
            1
        );
        assert_eq!(
            solo_payouts("bc1qminer", &fee(Some("bc1qdev"), -1.0), REWARD).len(),
            1
        );
    }

    #[test]
    fn an_empty_miner_address_yields_nothing() {
        assert!(solo_payouts("", &fee(None, 0.0), REWARD).is_empty());
    }
}
