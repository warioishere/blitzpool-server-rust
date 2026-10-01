// SPDX-License-Identifier: AGPL-3.0-or-later

//! BIP-54 (Consensus Cleanup) rules on the coinbase, the one transaction the
//! pool builds itself: witness-stripped size not 64 bytes, input `nSequence`
//! not final, `nLockTime == height - 1`. Core enforces the rest of BIP-54.
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

/// Decode the BIP-34 height from the leading push of a coinbase scriptsig or
/// `NewTemplate.coinbase_prefix`; `None` unless it is a direct 1..=4-byte push.
pub fn decode_bip34_height(scriptsig: &[u8]) -> Option<u32> {
    let len = *scriptsig.first()? as usize;
    if len == 0 || len > 4 || scriptsig.len() < 1 + len {
        return None;
    }
    let mut height: u32 = 0;
    for (i, b) in scriptsig[1..1 + len].iter().enumerate() {
        height |= u32::from(*b) << (8 * i);
    }
    Some(height)
}

/// Check the BIP-54 coinbase rules on the non-witness serialization.
pub fn check_coinbase(
    non_witness_coinbase: &[u8],
    block_height: u32,
) -> Result<(), Bip54Violation> {
    // Checked before decoding, so a 64-byte buffer is caught even if it
    // would not parse.
    if non_witness_coinbase.len() == 64 {
        return Err(Bip54Violation::SixtyFourByteTransaction);
    }

    let tx = bitcoin::Transaction::consensus_decode(&mut &non_witness_coinbase[..])
        .map_err(|_| Bip54Violation::Undecodable)?;

    let sequence = tx
        .input
        .first()
        .ok_or(Bip54Violation::Undecodable)?
        .sequence
        .0;
    if sequence == SEQUENCE_FINAL {
        return Err(Bip54Violation::FinalSequence);
    }

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

    /// Non-witness serialization of a coinbase-shaped tx (empty witness).
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
            // P2WPKH-shaped output keeps the size clear of the 64-byte boundary.
            output: vec![TxOut {
                value: Amount::from_sat(50 * 100_000_000),
                script_pubkey: ScriptBuf::from_bytes(
                    [&[0x00u8, 0x14][..], &[0x11u8; 20][..]].concat(),
                ),
            }],
        };
        consensus::serialize(&tx)
    }

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
        // locktime 0 at height 103 → must equal 102.
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
