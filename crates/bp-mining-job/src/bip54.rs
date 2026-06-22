// SPDX-License-Identifier: AGPL-3.0-or-later

//! BIP-54 (Consensus Cleanup) coinbase rules.
//!
//! Three of BIP-54's consensus changes are properties of the coinbase
//! transaction — the only transaction a mining pool builds itself; every
//! other transaction in the block comes from bitcoin-core's template.
//! bitcoin-core owns and enforces the rest (timewarp timestamp limits, the
//! 2500-sigop per-transaction cap, transaction selection).
//!
//! The Rust pool sources its coinbase fields from Core's SV2 `NewTemplate`
//! over IPC, so against a BIP-54-aware node (Core 31 emits `nLockTime =
//! height - 1` and a non-final `nSequence` of `0xfffffffe`) the constructed
//! coinbase is already compliant. This module codifies the rules so the
//! property can be asserted in tests and re-checked on coinbase bytes the
//! pool assembles itself.
//!
//! The three coinbase rules:
//!  1. the witness-stripped serialized size must NOT be exactly 64 bytes,
//!  2. the sole input's `nSequence` must NOT be `0xffffffff` (non-final), and
//!  3. `nLockTime` must equal `block_height - 1`.
//!
//! See <https://github.com/bitcoin/bips/blob/master/bip-0054.md>.

use bitcoin::consensus::Decodable;

/// The "final" sequence value BIP-54 forbids on the coinbase input.
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;

/// A BIP-54 coinbase rule violation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Bip54Violation {
    #[error(
        "coinbase witness-stripped size is exactly 64 bytes (BIP-54 forbids 64-byte transactions)"
    )]
    SixtyFourByteTransaction,
    #[error("coinbase input nSequence is 0xffffffff (BIP-54 requires a non-final sequence)")]
    FinalSequence,
    #[error("coinbase nLockTime is {found}, expected block_height - 1 = {expected}")]
    LockTimeMismatch { expected: u32, found: u32 },
    #[error("coinbase bytes did not decode as a transaction")]
    Undecodable,
}

/// Decode the BIP-34 block height from the leading minimal-`CScriptNum`
/// push of a coinbase scriptsig (or the `NewTemplate.coinbase_prefix`,
/// which begins with that push). Returns `None` if the first byte isn't a
/// direct 1..=4-byte push or the buffer is too short.
pub fn decode_bip34_height(scriptsig: &[u8]) -> Option<u32> {
    let len = *scriptsig.first()? as usize;
    // BIP-34 heights use a direct push opcode whose value is the byte length
    // (1..=4 covers every height bitcoin will ever reach).
    if len == 0 || len > 4 || scriptsig.len() < 1 + len {
        return None;
    }
    let mut height: u32 = 0;
    for (i, b) in scriptsig[1..1 + len].iter().enumerate() {
        height |= u32::from(*b) << (8 * i);
    }
    Some(height)
}

/// Validate the pool-relevant BIP-54 coinbase rules against the
/// **non-witness** serialization of a coinbase transaction mined at
/// `block_height`.
pub fn check_coinbase(
    non_witness_coinbase: &[u8],
    block_height: u32,
) -> Result<(), Bip54Violation> {
    // Rule 1 — 64-byte transaction prohibition. The witness-stripped size is
    // exactly the non-witness serialization length, so check it before any
    // decode (and so a 64-byte buffer is caught even if it wouldn't parse).
    if non_witness_coinbase.len() == 64 {
        return Err(Bip54Violation::SixtyFourByteTransaction);
    }

    let tx = bitcoin::Transaction::consensus_decode(&mut &non_witness_coinbase[..])
        .map_err(|_| Bip54Violation::Undecodable)?;

    // Rule 2 — non-final sequence on the (single) coinbase input.
    let sequence = tx
        .input
        .first()
        .ok_or(Bip54Violation::Undecodable)?
        .sequence
        .0;
    if sequence == SEQUENCE_FINAL {
        return Err(Bip54Violation::FinalSequence);
    }

    // Rule 3 — nLockTime == block_height - 1.
    let expected = block_height.saturating_sub(1);
    let found = tx.lock_time.to_consensus_u32();
    if found != expected {
        return Err(Bip54Violation::LockTimeMismatch { expected, found });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::LockTime, consensus, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Witness,
    };

    /// Build the non-witness serialization of a coinbase-shaped tx with the
    /// given locktime / sequence. The empty witness means rust-bitcoin emits
    /// the legacy (witness-stripped) encoding.
    fn coinbase_bytes(locktime: u32, sequence: u32, scriptsig: Vec<u8>) -> Vec<u8> {
        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::from_consensus(locktime),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(scriptsig),
                sequence: Sequence(sequence),
                witness: Witness::new(),
            }],
            // 22-byte P2WPKH-shaped script (OP_0 OP_PUSHBYTES_20 <20 bytes>).
            // Keeps the serialized size clear of the 64-byte boundary that a
            // minimal single-OP_RETURN coinbase would otherwise hit exactly.
            output: vec![TxOut {
                value: Amount::from_sat(50 * 100_000_000),
                script_pubkey: ScriptBuf::from_bytes(
                    [&[0x00u8, 0x14][..], &[0x11u8; 20][..]].concat(),
                ),
            }],
        };
        consensus::serialize(&tx)
    }

    // ---- decode_bip34_height ----

    #[test]
    fn decode_height_single_and_multi_byte() {
        assert_eq!(decode_bip34_height(&[0x01, 0x64]), Some(100));
        assert_eq!(decode_bip34_height(&[0x01, 0x67, 0xAB, 0xCD]), Some(103));
        // 800_000 = 0x0C3500 → minimal LE push [0x00, 0x35, 0x0c].
        assert_eq!(
            decode_bip34_height(&[0x03, 0x00, 0x35, 0x0c]),
            Some(800_000)
        );
    }

    #[test]
    fn decode_height_rejects_malformed() {
        assert_eq!(decode_bip34_height(&[]), None);
        assert_eq!(decode_bip34_height(&[0x00]), None); // zero-length push
        assert_eq!(decode_bip34_height(&[0x05, 1, 2, 3, 4, 5]), None); // > 4 bytes
        assert_eq!(decode_bip34_height(&[0x02, 0x01]), None); // truncated
    }

    // ---- check_coinbase ----

    #[test]
    fn compliant_coinbase_passes() {
        let bytes = coinbase_bytes(102, 0xffff_fffe, vec![0x01, 0x67]);
        assert_eq!(check_coinbase(&bytes, 103), Ok(()));
    }

    #[test]
    fn final_sequence_is_rejected() {
        let bytes = coinbase_bytes(102, SEQUENCE_FINAL, vec![0x01, 0x67]);
        assert_eq!(
            check_coinbase(&bytes, 103),
            Err(Bip54Violation::FinalSequence)
        );
    }

    #[test]
    fn wrong_locktime_is_rejected() {
        // locktime 0 (the pre-BIP-54 default) at height 103 → must equal 102.
        let bytes = coinbase_bytes(0, 0xffff_fffe, vec![0x01, 0x67]);
        assert_eq!(
            check_coinbase(&bytes, 103),
            Err(Bip54Violation::LockTimeMismatch {
                expected: 102,
                found: 0
            })
        );
    }

    #[test]
    fn sixty_four_byte_transaction_is_rejected() {
        // Caught purely on length, before any decode attempt.
        let buf = vec![0u8; 64];
        assert_eq!(
            check_coinbase(&buf, 100),
            Err(Bip54Violation::SixtyFourByteTransaction)
        );
    }

    #[test]
    fn undecodable_bytes_are_rejected() {
        let buf = vec![0xFFu8; 10];
        assert_eq!(check_coinbase(&buf, 100), Err(Bip54Violation::Undecodable));
    }
}
