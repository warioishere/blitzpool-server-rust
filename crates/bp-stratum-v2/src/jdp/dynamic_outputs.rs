// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coinbase-output byte helpers shared by the JDP paths.
//!
//! The ext 0x0003 payout logic itself lives in
//! [`crate::jdp::payout_distribution`] (push model: `SetPayoutDistribution`
//! weights, §4 recompute-and-compare). What remains here are the byte-level
//! helpers both the base-protocol allocate path and the declare-time
//! validator need:
//!
//! - [`encode_coinbase_outputs`] — `(address, sats)` list → consensus
//!   `Vec<TxOut>` bytes (`AllocateMiningJobToken.Success.coinbase_tx_outputs`
//!   on the non-negotiated base path).
//! - [`declared_coinbase_tx`] — the declared prefix/suffix pair → the
//!   rebuilt transaction, its extranonce slot width and its committed
//!   scriptSig prefix, fail-closed.
//! - [`PayoutBooking`] — the accounting identity a proven declaration
//!   carries to the block-found path.

use bitcoin::consensus::Encodable;
use bitcoin::{Amount, Network, TxOut};
use bp_common::{AddressId, Sats};
use bp_mining_job::address_to_script;

// ── DynamicOutput ────────────────────────────────────────────────────

/// One entry in a concrete coinbase output list (base-path allocate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicOutput {
    pub address: AddressId,
    pub sats: Sats,
}

// ── Errors ───────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    /// Address didn't parse or didn't match the configured network
    /// (delegated to `bp_mining_job::address_to_script`).
    #[error("address-to-script failed: {0}")]
    InvalidAddress(String),
}

/// Serialise `outputs` as a consensus-encoded `Vec<TxOut>`.
///
/// Layout (per Bitcoin consensus):
/// - `VarInt(outputs.len())`
/// - Per output: `u64-LE value` + `VarInt(script_len)` + `script_pubkey`
///
/// Empty `outputs` returns `[0x00]` (single varint zero) — the
/// consensus encoding of an empty vector.
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
    // Same answer as everywhere else in this crate that consensus-encodes
    // into a `Vec<u8>` (`WeightedOutput::to_wire_txout`, the declared-job
    // fixtures): the writer has no failure mode, so an error variant for it
    // would be one the caller can never see.
    txouts
        .consensus_encode(&mut buf)
        .expect("Vec<u8> writer cannot fail");
    Ok(buf)
}

/// The declared coinbase rebuilt as a whole transaction, plus the width of the
/// extranonce slot that was zero-filled to get there.
///
/// Every consumer that needs more than the outputs — the §7.1 payout check
/// reads `tx.output`, the declared-job binding
/// ([`crate::jdp::custom_job_binding`]) reads the version, scriptSig,
/// nSequence and locktime as well, and both need the coinbase txid for the
/// merkle branch — goes through this one reconstruction. The scriptSig it
/// returns carries the slot as zeroes, so `script_sig[..len - slot]` is the
/// prefix the JDC actually committed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredCoinbase {
    pub tx: bitcoin::Transaction,
    /// Bytes of scriptSig the prefix left for the extranonce.
    pub extranonce_slot: usize,
    /// The scriptSig bytes the declaration committed to, i.e. everything
    /// before the slot. Cut here rather than by the caller: this is the one
    /// place that knows `slot <= script_sig.len()` holds, because it is the
    /// same place that derived `slot` from that same length.
    pub script_sig_prefix: Vec<u8>,
}

/// Rebuild the declared coinbase transaction from the SV2 prefix/suffix pair.
///
/// A JDC declares its coinbase split around the extranonce slot it does not
/// control: `coinbase_tx_prefix` ends where the slot begins,
/// `coinbase_tx_suffix` resumes after it. To read the outputs we reassemble
/// the whole transaction with the slot zero-filled and let
/// `Transaction::consensus_decode` do the parsing — **the transaction's own
/// framing tells us where the outputs are**, so nothing here assumes a byte
/// layout for the suffix.
///
/// The slot width comes from the prefix itself: it carries the scriptSig
/// length as a CompactSize, and it stops at the slot, so
/// `slot = declared_script_sig_len − script_sig_bytes_already_in_prefix`.
/// This is the same derivation SRI's `jd-server` uses
/// (`job_validation/bitcoin_core_ipc.rs::get_coinbase_tx`) — except they
/// hardcode the header at 43 bytes, which assumes a segwit-serialised coinbase
/// (marker+flag). Ours are serialised without it (41), so the header is parsed
/// rather than assumed.
///
/// **Fail-closed**, and it stays that way for the case this cannot express: a
/// JDC that puts its own scriptSig bytes AFTER the extranonce (T>0 — see
/// `deferred-jds-coinbase-suffix-parse`). The derivation above yields `N + T`,
/// so the rebuilt scriptSig comes out T bytes long and the decode fails. That
/// is a rejection, never a wrong ACCEPT; SRI has the identical limitation.
pub fn declared_coinbase_tx(
    coinbase_tx_prefix: &[u8],
    coinbase_tx_suffix: &[u8],
) -> Option<DeclaredCoinbase> {
    let slot = extranonce_slot_width(coinbase_tx_prefix)?;

    let mut raw = Vec::with_capacity(coinbase_tx_prefix.len() + slot + coinbase_tx_suffix.len());
    raw.extend_from_slice(coinbase_tx_prefix);
    raw.resize(raw.len() + slot, 0);
    raw.extend_from_slice(coinbase_tx_suffix);

    // `deserialize` (not `deserialize_partial`) rejects trailing bytes, so a
    // coinbase whose real shape disagrees with the declared scriptSig length
    // cannot squeeze through.
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw).ok()?;

    // `input[0]` and the slice below are safe by construction, and only
    // here: `extranonce_slot_width` refused the prefix unless its input
    // count decoded to exactly 1, and it derived `slot` by subtracting from
    // the same scriptSig length `deserialize` just read back — so the input
    // exists and the scriptSig is at least `slot` long. Restating either as
    // a runtime check would add a branch that cannot be taken, and teach the
    // next reader a failure mode that does not exist.
    let script_sig = tx.input[0].script_sig.as_bytes();
    let script_sig_prefix = script_sig[..script_sig.len() - slot].to_vec();

    Some(DeclaredCoinbase {
        tx,
        extranonce_slot: slot,
        script_sig_prefix,
    })
}

/// Consensus bound on a coinbase's scriptSig: 2 to 100 bytes, else
/// `bad-cb-length`. Only the upper end is enforced below, and it is enforced
/// for one reason — the declared length decides how many bytes get allocated
/// to rebuild the transaction, so an unchecked one turns a handful of wire
/// bytes into an arbitrary allocation.
const MAX_COINBASE_SCRIPT_SIG_LEN: usize = 100;

/// How many bytes of scriptSig the prefix leaves for the extranonce slot.
///
/// Walks the coinbase header instead of assuming its size: version (4), the
/// optional segwit marker+flag (`00 01`), input count (CompactSize, must be 1),
/// the 36-byte outpoint, then the scriptSig length. Whatever that length
/// exceeds the scriptSig bytes already present in the prefix is the slot.
///
/// **This is where "the declaration is a coinbase" is decided**, and the only
/// place. The input-count test below is not a formality on the way to a
/// length: every later reader — the payout check reading `tx.output`, the
/// binding reading `input[0]` — relies on it having run. Relax it and a
/// multi-input transaction reaches those readers as if it were a coinbase.
///
/// The scriptSig length arrives as a CompactSize with no inherent ceiling, and
/// the caller turns it straight into `Vec::resize`. Refusing anything past the
/// consensus maximum keeps the largest rebuildable coinbase small, and costs
/// nothing real: a longer scriptSig is `bad-cb-length`, so such a declaration
/// describes a block that can never be valid.
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

    // `cursor` now points at the scriptSig bytes the prefix carries.
    (script_sig_len as usize).checked_sub(cursor.len())
}

// ── PayoutBooking ───────────────────────────────────────────────────

/// The pool-side accounting identity riding on a proven declaration.
///
/// A JDC builds and owns its own coinbase; the pool only publishes a
/// weight distribution (ext 0x0003 §3.1). A found block may only be
/// booked once the declared coinbase was validated positionally against
/// that distribution (§7.1) — this rides along on that proof so the
/// block-found path can settle exactly the distribution the coinbase
/// pays (`claim(T_actual) − paid` from the settlement snapshot).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayoutBooking {
    /// §3.1 `distribution_id` the declaration referenced.
    pub distribution_id: u64,
    /// Settlement-snapshot identity (weights fingerprint) of that
    /// distribution. Zeroed = the owning mode books without a snapshot.
    pub payouts_fingerprint: [u8; 32],
    /// The revenue the distribution's boosts were projected against —
    /// carried for the booking band + logs.
    pub reference_reward_sats: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::Decodable;

    const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    #[test]
    fn encode_empty_is_varint_zero() {
        assert_eq!(
            encode_coinbase_outputs(Network::Regtest, &[]).unwrap(),
            vec![0x00]
        );
    }

    #[test]
    fn encode_roundtrips_via_consensus_decode() {
        let outputs = vec![DynamicOutput {
            address: AddressId::new(ADDR).unwrap(),
            sats: Sats(312_500_000),
        }];
        let bytes = encode_coinbase_outputs(Network::Regtest, &outputs).unwrap();
        let decoded = <Vec<TxOut>>::consensus_decode(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].value.to_sat(), 312_500_000);
    }

    #[test]
    fn encode_rejects_invalid_address() {
        let outputs = vec![DynamicOutput {
            address: AddressId::new("notanaddress").unwrap(),
            sats: Sats(1_000),
        }];
        assert!(matches!(
            encode_coinbase_outputs(Network::Regtest, &outputs),
            Err(EncodeError::InvalidAddress(_))
        ));
    }

    #[test]
    fn encode_clamps_negative_sats_to_zero() {
        let outputs = vec![DynamicOutput {
            address: AddressId::new(ADDR).unwrap(),
            sats: Sats(-5),
        }];
        let bytes = encode_coinbase_outputs(Network::Regtest, &outputs).unwrap();
        let decoded = <Vec<TxOut>>::consensus_decode(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded[0].value.to_sat(), 0);
    }

    /// The outputs of a rebuilt declaration — what the removed
    /// `declared_coinbase_outputs` wrapper used to return. Kept as a test
    /// helper only: production reads the whole [`DeclaredCoinbase`], so a
    /// public wrapper would have been scaffolding for an API shape nothing
    /// calls.
    fn declared_outputs(prefix: &[u8], suffix: &[u8]) -> Option<Vec<TxOut>> {
        Some(declared_coinbase_tx(prefix, suffix)?.tx.output)
    }

    fn suffix_with(outputs_bytes: &[u8]) -> Vec<u8> {
        let mut suffix = vec![0xFE, 0xFF, 0xFF, 0xFF]; // nSequence
        suffix.extend_from_slice(outputs_bytes);
        suffix.extend_from_slice(&[0, 0, 0, 0]); // nLockTime
        suffix
    }

    /// A declared `coinbase_tx_prefix`: header, then `script_sig_head` bytes of
    /// scriptSig, with `slot` further bytes reserved for the extranonce. The
    /// declared scriptSig length therefore covers `script_sig_head + slot + tail`,
    /// where `tail` is the T>0 case (bytes the JDC keeps AFTER the extranonce).
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

    fn one_output_bytes(sats: i64) -> Vec<u8> {
        encode_coinbase_outputs(
            Network::Regtest,
            &[DynamicOutput {
                address: AddressId::new(ADDR).unwrap(),
                sats: Sats(sats),
            }],
        )
        .unwrap()
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

    // The whole point of rebuilding the transaction: the slot width is derived
    // from the prefix, so it does not have to be a fixed size — anywhere up to
    // the consensus ceiling on a coinbase scriptSig.
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

    /// "A coinbase has exactly one input" is decided in exactly one place —
    /// the input-count test inside `extranonce_slot_width` — and every later
    /// reader depends on it: the §7.1 payout check takes `tx.output` on
    /// trust, and the declaration binding indexes `input[0]` without a guard
    /// of its own, because a guard there could not fire.
    ///
    /// So the check gets a test rather than a second copy. Relax it and this
    /// fails, instead of a non-coinbase quietly reaching the payout path.
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

        // The same bytes with a coinbase's single input DO parse, so the
        // refusal above is the input count and nothing else.
        prefix[4] = 0x01;
        assert_eq!(extranonce_slot_width(&prefix), Some(0x0F - 3));
    }

    /// The declared scriptSig length decides how many bytes get allocated to
    /// rebuild the transaction, and it arrives as a CompactSize with no
    /// inherent ceiling — so a few wire bytes could ask for an arbitrary
    /// allocation. Anything past the consensus maximum is refused before the
    /// buffer is sized.
    ///
    /// The pair matters: 97 (a 100-byte scriptSig) must still parse, or the
    /// bound would be refusing coinbases that are perfectly valid.
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
        // The shape that turns a small message into a huge allocation: a
        // CompactSize claiming gigabytes, with almost nothing behind it.
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

    // ── the shape a real JDC actually sends ──────────────────────────
    //
    // `channels-sv2`'s `JobFactory` (which every SRI jd-client builds its
    // declaration with) slices a **segwit-serialised** coinbase:
    //
    //   index  = 4 version + 2 segwit + 1 inputs + 32 outpoint + 4 index
    //          + 1 scriptSig len + script_sig_head
    //   prefix = serialize(coinbase)[..index]
    //   suffix = serialize(coinbase)[index + full_extranonce_size..]
    //
    // so the prefix carries marker+flag (SRI's hardcoded 43) and the suffix
    // carries the **witness** as well as nSequence/outputs/nLockTime. Rebuilding
    // prefix + zeroed slot + suffix therefore reproduces the serialised
    // transaction byte for byte. This is the realistic path; the fixtures above
    // use the witness-less form our own coinbase builder emits.
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

    // The header is WALKED, not assumed at a fixed offset — SRI hardcodes 43,
    // which holds for the segwit-serialised coinbase a JDC declares but not for
    // the witness-less one our own builder emits (41). Both must yield the same
    // slot width, asserted on the derivation itself because the surrounding
    // `deserialize` would fail for either reason and could not tell them apart.
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

    // The known interop limit, pinned so it is a decision and not a surprise:
    // scriptSig bytes AFTER the extranonce make the derived width N+T, the
    // rebuilt scriptSig runs long, and the decode fails. Rejection, never a
    // wrong accept. SRI's jd-server behaves identically.
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
