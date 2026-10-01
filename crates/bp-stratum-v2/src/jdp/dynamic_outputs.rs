// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coinbase-output byte helpers shared by the JDP allocate and declare paths.
//!
//! The ext 0x0003 payout logic lives in [`crate::jdp::payout_distribution`].
//! Here: the SV2 JDP/AllocateMiningJobToken.Success designated payout output,
//! the fail-closed rebuild of a declared coinbase ([`declared_coinbase_tx`]),
//! and the booking identity a proven declaration carries ([`PayoutBooking`]).

use bitcoin::{Amount, Script, TxOut};

// ── SV2 JDP/AllocateMiningJobToken.Success base-protocol payout output ───

/// The base-path `coinbase_tx_outputs` blob: one 0-sat output paying `script`,
/// the pool payout output per SV2 JDP/AllocateMiningJobToken.Success.
pub fn designated_output_blob(script: &Script) -> Vec<u8> {
    bitcoin::consensus::serialize(&vec![TxOut {
        value: Amount::ZERO,
        script_pubkey: script.to_owned(),
    }])
}

/// The designated payout script, read back from the allocate blob's first
/// output (SV2 JDP/AllocateMiningJobToken.Success). `None` when there is none;
/// the caller then refuses the custom job.
pub fn designated_payout_script(coinbase_outputs: &[u8]) -> Option<Vec<u8>> {
    let outputs: Vec<TxOut> = bitcoin::consensus::deserialize(coinbase_outputs).ok()?;
    outputs.first().map(|o| o.script_pubkey.as_bytes().to_vec())
}

/// Does this coinbase pay the designated script a non-zero amount, at any
/// position (SV2 JDP/AllocateMiningJobToken.Success lets the JDC reorder and add
/// outputs)? The amount is not checked: the spec names no threshold.
///
/// ⚠️ Sufficient only because the allocate designates a script solely when it
/// is the asking miner's own, so a short payment shorts only that miner. Relax
/// neither rule on the strength of the other.
pub fn pays_designated_output(outputs: &[TxOut], designated_script: &[u8]) -> bool {
    outputs
        .iter()
        .any(|o| o.script_pubkey.as_bytes() == designated_script && o.value > Amount::ZERO)
}

/// The declared coinbase rebuilt as a whole transaction, with the extranonce
/// slot zero-filled. The one reconstruction both the payout check and
/// [`crate::jdp::custom_job_binding`] read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredCoinbase {
    pub tx: bitcoin::Transaction,
    /// Bytes of scriptSig the prefix left for the extranonce.
    pub extranonce_slot: usize,
    /// The scriptSig bytes before the slot, which the JDC committed to.
    pub script_sig_prefix: Vec<u8>,
}

/// Rebuild the declared coinbase from the SV2 prefix/suffix pair, slot
/// zero-filled, and decode it by consensus rules so the transaction's own
/// framing locates the outputs.
///
/// Fail-closed for scriptSig bytes AFTER the extranonce (T>0): the rebuilt
/// scriptSig runs long and the decode fails, never a wrong accept.
pub fn declared_coinbase_tx(
    coinbase_tx_prefix: &[u8],
    coinbase_tx_suffix: &[u8],
) -> Option<DeclaredCoinbase> {
    let slot = extranonce_slot_width(coinbase_tx_prefix)?;

    let mut raw = Vec::with_capacity(coinbase_tx_prefix.len() + slot + coinbase_tx_suffix.len());
    raw.extend_from_slice(coinbase_tx_prefix);
    raw.resize(raw.len() + slot, 0);
    raw.extend_from_slice(coinbase_tx_suffix);

    // `deserialize` rejects trailing bytes, so a shape mismatch cannot pass.
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw).ok()?;

    // Safe: `extranonce_slot_width` required exactly one input and derived
    // `slot` from this same scriptSig length.
    let script_sig = tx.input[0].script_sig.as_bytes();
    let script_sig_prefix = script_sig[..script_sig.len() - slot].to_vec();

    Some(DeclaredCoinbase {
        tx,
        extranonce_slot: slot,
        script_sig_prefix,
    })
}

/// Consensus maximum of a coinbase scriptSig (`bad-cb-length`); bounds the
/// rebuild buffer the declared length sizes.
const MAX_COINBASE_SCRIPT_SIG_LEN: usize = 100;

/// Bytes of scriptSig the prefix leaves for the extranonce, found by walking
/// the header (segwit marker+flag optional, so 41 or 43 bytes).
///
/// ⚠️ The one place "the declaration is a coinbase" is decided: every later
/// reader of `tx.output` and `input[0]` relies on the single-input test here.
fn extranonce_slot_width(coinbase_tx_prefix: &[u8]) -> Option<usize> {
    use bitcoin::consensus::Decodable;

    let mut cursor = coinbase_tx_prefix;
    let read = |cursor: &mut &[u8], n: usize| -> Option<()> {
        if cursor.len() < n {
            return None;
        }
        *cursor = &cursor[n..];
        Some(())
    };

    read(&mut cursor, 4)?; // version
    if cursor.starts_with(&[0x00, 0x01]) {
        read(&mut cursor, 2)?; // segwit marker + flag
    }
    if bitcoin::VarInt::consensus_decode(&mut cursor).ok()?.0 != 1 {
        return None; // a coinbase has exactly one input
    }
    read(&mut cursor, 36)?; // outpoint: 32-byte txid + 4-byte index
    let script_sig_len = bitcoin::VarInt::consensus_decode(&mut cursor).ok()?.0;
    if script_sig_len > MAX_COINBASE_SCRIPT_SIG_LEN as u64 {
        return None;
    }

    (script_sig_len as usize).checked_sub(cursor.len())
}

// ── PayoutBooking ───────────────────────────────────────────────────

/// The accounting identity a declaration carries once its coinbase was proven
/// to pay the referenced distribution (ext 0x0003/Output Verification), so the
/// block-found path books exactly what the coinbase paid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayoutBooking {
    /// ext 0x0003/SetPayoutDistribution `distribution_id` the declaration
    /// referenced.
    pub distribution_id: u64,
    /// Settlement-snapshot weights fingerprint. Zeroed = the mode books
    /// without a snapshot.
    pub payouts_fingerprint: [u8; 32],
    /// Revenue the boosts were projected against; fallback reward when the
    /// block's own coinbase value cannot be read.
    pub reference_reward_sats: u64,
}

/// What a `PushSolution`'s declaration was backed by.
///
/// Not an `Option<PayoutBooking>`: an unbookable block still paid a published
/// distribution, which must then be settled (see [`Self::settles_here`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateBacking {
    /// Base-protocol declaration; no distribution referenced.
    BaseProtocol,
    /// Proven to pay a published distribution whose settlement snapshot never
    /// landed, so there is nothing to book against.
    UnbookableDistribution { distribution_id: u64 },
    /// Referenced, proven, and its settlement inputs are on file.
    Bookable(PayoutBooking),
}

impl CandidateBacking {
    /// Did this block's coinbase pay a distribution the pool published?
    /// Decides whether the block is worth assembling and proving at all.
    pub fn paid_a_published_distribution(&self) -> bool {
        match self {
            Self::BaseProtocol => false,
            Self::UnbookableDistribution { .. } | Self::Bookable(_) => true,
        }
    }

    /// Must the ext 0x0003/Implementation Notes settle fire at block-found?
    ///
    /// Only for [`Self::UnbookableDistribution`], since no ledger write follows.
    /// A [`Self::Bookable`] block is settled after its booking: settling earlier
    /// would republish the balances the block just paid.
    pub fn settles_here(&self) -> bool {
        match self {
            Self::BaseProtocol | Self::Bookable(_) => false,
            Self::UnbookableDistribution { .. } => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::Encodable;
    use bitcoin::hex::DisplayHex;
    use bitcoin::Network;

    const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    // ── SV2 JDP/AllocateMiningJobToken.Success designated payout output ───

    fn txout(sats: u64, script: Vec<u8>) -> TxOut {
        TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(script),
        }
    }

    /// The allocate blob round-trips the miner's script and matches its wire form byte for byte.
    #[test]
    fn the_designated_script_round_trips_through_the_allocate_blob() {
        let script = bp_mining_job::address_to_script(Network::Regtest, ADDR).unwrap();
        let blob = designated_output_blob(&script);
        assert_eq!(
            blob.to_lower_hex_string(),
            "01\
             0000000000000000\
             16\
             0014751e76e8199196d454941c45d1b3a323f1433bd6",
        );
        assert_eq!(
            designated_payout_script(&blob).as_deref(),
            Some(script.as_bytes())
        );
    }

    /// An empty (ext 0x0003/Negotiation) or undecodable blob designates no script.
    #[test]
    fn no_designated_script_without_outputs() {
        assert_eq!(designated_payout_script(&[0x00]), None);
        assert_eq!(designated_payout_script(&[]), None);
        assert_eq!(designated_payout_script(&[0xFF, 0xFF]), None);
    }

    /// Rewritten amount, reordering and extra valued outputs still pay the designated output.
    #[test]
    fn a_reordered_coinbase_with_extra_outputs_still_pays_the_designated_output() {
        let pool = vec![0x00, 0x14, 0xAA];
        let jdc = vec![0x00, 0x14, 0xBB];
        assert!(pays_designated_output(
            &[
                txout(0, vec![0x6A, 0x01, 0x42]), // JDC OP_RETURN, first
                txout(1_000, jdc.clone()),        // JDC keeps some revenue
                txout(311_499_000, pool.clone()), // designated, amount rewritten
            ],
            &pool
        ));
    }

    /// An absent or 0-value designated output (the untouched blob) does not pay.
    #[test]
    fn a_designated_output_that_is_missing_or_unfunded_does_not_pay() {
        let pool = vec![0x00, 0x14, 0xAA];
        let jdc = vec![0x00, 0x14, 0xBB];
        assert!(
            !pays_designated_output(&[txout(312_500_000, jdc.clone())], &pool),
            "paying someone else is not paying the designated output"
        );
        assert!(
            !pays_designated_output(&[txout(0, pool.clone()), txout(312_500_000, jdc)], &pool),
            "a 0-value designated output is the untouched blob, not a payment"
        );
        assert!(!pays_designated_output(&[], &pool));
    }

    /// The outputs of a rebuilt declaration.
    fn declared_outputs(prefix: &[u8], suffix: &[u8]) -> Option<Vec<TxOut>> {
        Some(declared_coinbase_tx(prefix, suffix)?.tx.output)
    }

    fn suffix_with(outputs_bytes: &[u8]) -> Vec<u8> {
        let mut suffix = vec![0xFE, 0xFF, 0xFF, 0xFF]; // nSequence
        suffix.extend_from_slice(outputs_bytes);
        suffix.extend_from_slice(&[0, 0, 0, 0]); // nLockTime
        suffix
    }

    /// A prefix declaring scriptSig length `head + slot + tail`; `tail` is the
    /// T>0 case (bytes after the extranonce).
    fn prefix_with(script_sig_head: &[u8], slot: usize, tail: usize) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&2u32.to_le_bytes()); // version
        p.push(0x01); // input count
        p.extend_from_slice(&[0u8; 32]); // prevout txid
        p.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // prevout index
        bitcoin::VarInt((script_sig_head.len() + slot + tail) as u64)
            .consensus_encode(&mut p)
            .unwrap();
        p.extend_from_slice(script_sig_head);
        p
    }

    fn one_output_bytes(sats: u64) -> Vec<u8> {
        let script = bp_mining_job::address_to_script(Network::Regtest, ADDR).unwrap();
        bitcoin::consensus::serialize(&vec![txout(sats, script.into_bytes())])
    }

    #[test]
    fn declared_outputs_roundtrip_through_a_rebuilt_transaction() {
        let parsed = declared_outputs(
            &prefix_with(&[0x03, 0xC8, 0x00], /*slot=*/ 12, /*tail=*/ 0),
            &suffix_with(&one_output_bytes(42)),
        )
        .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].value.to_sat(), 42);
    }

    // Any slot width up to the consensus scriptSig ceiling parses.
    #[test]
    fn the_slot_width_is_read_from_the_prefix_not_assumed() {
        // 3-byte committed prefix, so slot 97 lands exactly on the 100-byte max.
        for slot in [1usize, 8, 12, 32, 97] {
            let parsed = declared_outputs(
                &prefix_with(&[0x03, 0xC8, 0x00], slot, 0),
                &suffix_with(&one_output_bytes(7)),
            );
            assert!(parsed.is_some(), "slot width {slot} should parse");
        }
    }

    /// Pins the single-input test every later reader of `input[0]` relies on.
    #[test]
    fn a_prefix_declaring_more_than_one_input_is_refused() {
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&2u32.to_le_bytes()); // version
        prefix.push(0x02); // input count = 2 — not a coinbase
        prefix.extend_from_slice(&[0u8; 32]);
        prefix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        prefix.push(0x0F); // scriptSig length
        prefix.extend_from_slice(&[0x03, 0xC8, 0x00]);
        assert!(extranonce_slot_width(&prefix).is_none());

        // Negative control: with one input the same bytes parse.
        prefix[4] = 0x01;
        assert_eq!(extranonce_slot_width(&prefix), Some(0x0F - 3));
    }

    /// A scriptSig length past 100 bytes is refused before allocating; exactly 100 still parses.
    #[test]
    fn an_oversized_declared_script_sig_is_refused_before_allocating() {
        let outputs = suffix_with(&one_output_bytes(7));
        assert!(
            declared_outputs(&prefix_with(&[0x03, 0xC8, 0x00], 97, 0), &outputs).is_some(),
            "a 100-byte scriptSig is the consensus maximum and must parse"
        );
        assert!(
            declared_outputs(&prefix_with(&[0x03, 0xC8, 0x00], 98, 0), &outputs).is_none(),
            "101 bytes is bad-cb-length and must be refused"
        );
        // A CompactSize claiming gigabytes with almost nothing behind it.
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&2u32.to_le_bytes());
        prefix.push(0x01);
        prefix.extend_from_slice(&[0u8; 32]);
        prefix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        prefix.push(0xFE); // CompactSize, u32 follows
        prefix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ~4 GiB
        assert!(
            declared_outputs(&prefix, &outputs).is_none(),
            "a 4 GiB scriptSig claim must not reach the allocation"
        );
    }

    // A real JDC slices a segwit-serialised coinbase: marker+flag in the
    // prefix, the witness in the suffix.
    #[test]
    fn a_declaration_shaped_like_channels_sv2_sends_it_roundtrips() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, Witness};

        const SLOT: usize = 12;
        let script_sig_head: [u8; 3] = [0x03, 0xC8, 0x00]; // BIP-34 height push

        let mut script_sig = script_sig_head.to_vec();
        script_sig.extend_from_slice(&[0u8; SLOT]); // the extranonce slot

        let mut witness = Witness::new();
        witness.push([0u8; 32]); // witness reserved value — makes it segwit-serialised

        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(script_sig),
                sequence: Sequence(0xFFFF_FFFF),
                witness,
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(312_400_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14, 0xAA]),
                },
            ],
        };

        let raw = bitcoin::consensus::serialize(&tx);
        let index = 4 + 2 + 1 + 32 + 4 + 1 + script_sig_head.len();
        let prefix = &raw[..index];
        let suffix = &raw[index + SLOT..];

        assert_eq!(
            extranonce_slot_width(prefix),
            Some(SLOT),
            "the slot width must come out of a segwit-serialised prefix too"
        );
        assert_eq!(
            declared_outputs(prefix, suffix).as_deref(),
            Some(tx.output.as_slice()),
            "a declaration in the shape channels-sv2 emits must round-trip"
        );
    }

    // Both header lengths (41 / 43 bytes) yield the same slot width.
    #[test]
    fn the_header_length_is_parsed_for_both_serialisations() {
        let plain = prefix_with(&[0x03, 0xC8, 0x00], /*slot=*/ 12, /*tail=*/ 0);
        assert_eq!(extranonce_slot_width(&plain), Some(12));

        let mut segwit = Vec::new();
        segwit.extend_from_slice(&2u32.to_le_bytes());
        segwit.extend_from_slice(&[0x00, 0x01]); // marker + flag
        segwit.push(0x01);
        segwit.extend_from_slice(&[0u8; 32]);
        segwit.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        bitcoin::VarInt(15).consensus_encode(&mut segwit).unwrap(); // 3 head + 12 slot
        segwit.extend_from_slice(&[0x03, 0xC8, 0x00]);
        assert_eq!(
            extranonce_slot_width(&segwit),
            Some(12),
            "skipping marker+flag must land on the same scriptSig length"
        );
    }

    #[test]
    fn trailing_garbage_in_the_output_region_fails_closed() {
        let mut bytes = one_output_bytes(42);
        bytes.push(0xAA);
        assert!(declared_outputs(
            &prefix_with(&[0x03, 0xC8, 0x00], 12, 0),
            &suffix_with(&bytes)
        )
        .is_none());
    }

    // T>0 (scriptSig bytes after the extranonce) fails closed.
    #[test]
    fn a_declaration_with_scriptsig_bytes_after_the_extranonce_is_refused() {
        let mut suffix = vec![0xAB, 0xCD]; // T = 2 scriptSig bytes
        suffix.extend_from_slice(&suffix_with(&one_output_bytes(42)));
        assert!(
            declared_outputs(
                &prefix_with(&[0x03, 0xC8, 0x00], /*slot=*/ 12, /*tail=*/ 2),
                &suffix
            )
            .is_none(),
            "T>0 is not supported and must fail closed"
        );
    }

    #[test]
    fn a_prefix_that_is_not_a_coinbase_header_is_refused() {
        assert!(declared_outputs(&[0u8; 7], &suffix_with(&one_output_bytes(1))).is_none());
        // input count != 1 is not a coinbase.
        let mut two_inputs = prefix_with(&[0x03, 0xC8, 0x00], 12, 0);
        two_inputs[4] = 0x02;
        assert!(declared_outputs(&two_inputs, &suffix_with(&one_output_bytes(1))).is_none());
    }

    #[test]
    fn a_prefix_claiming_less_scriptsig_than_it_carries_is_refused() {
        // declared scriptSig length 1, but 3 head bytes present → underflow.
        let mut p = Vec::new();
        p.extend_from_slice(&2u32.to_le_bytes());
        p.push(0x01);
        p.extend_from_slice(&[0u8; 32]);
        p.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        bitcoin::VarInt(1).consensus_encode(&mut p).unwrap();
        p.extend_from_slice(&[0x03, 0xC8, 0x00]);
        assert!(declared_outputs(&p, &suffix_with(&one_output_bytes(1))).is_none());
    }
}
