// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bind the job a JDC MINES (`SetCustomMiningJob`) to the job it DECLARED,
//! which base SV2 ties only by token: otherwise an unvalidated transaction set
//! could earn window share for blocks that cannot land. The payout split is
//! guarded by [`crate::jdp::payout_distribution`]; `nbits`/`min_ntime` are not bound.

use bitcoin::hashes::Hash;

use crate::jdp::declarations::DeclaredJob;
use crate::jdp::dynamic_outputs::declared_coinbase_tx;

/// A declared job projected down to the fields `SetCustomMiningJob` repeats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredJobBinding {
    pub version: u32,
    pub coinbase_tx_version: u32,
    /// Everything before the extranonce slot.
    pub coinbase_script_sig_prefix: Vec<u8>,
    pub coinbase_tx_input_n_sequence: u32,
    /// CompactSize-prefixed, re-serialised so it compares byte-for-byte.
    pub coinbase_tx_outputs: Vec<u8>,
    pub coinbase_tx_locktime: u32,
    /// Over the declared transaction set.
    pub merkle_path: Vec<[u8; 32]>,
    /// The `PushSolution` rebuild splices the channel's extranonce into this
    /// gap, so the widths must agree.
    pub extranonce_slot: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingViolation {
    Version,
    CoinbaseTxVersion,
    CoinbaseScriptSigPrefix,
    CoinbaseInputNSequence,
    CoinbaseOutputs,
    CoinbaseLocktime,
    MerklePath,
    ExtranonceSlotWidth,
}

/// `None` when the coinbase or a declared transaction cannot be decoded: the
/// caller must reject, never read it as "nothing to check".
pub fn binding_from_declared_job(job: &DeclaredJob) -> Option<DeclaredJobBinding> {
    let declared = declared_coinbase_tx(&job.coinbase_tx_prefix, &job.coinbase_tx_suffix)?;
    let tx = &declared.tx;

    let mut txids = Vec::with_capacity(1 + job.raw_transactions.len());
    txids.push(tx.compute_txid().to_byte_array());
    for raw in &job.raw_transactions {
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(raw).ok()?;
        txids.push(tx.compute_txid().to_byte_array());
    }

    Some(DeclaredJobBinding {
        version: job.version,
        coinbase_tx_version: tx.version.0 as u32,
        coinbase_script_sig_prefix: declared.script_sig_prefix,
        coinbase_tx_input_n_sequence: tx.input[0].sequence.0,
        coinbase_tx_outputs: bitcoin::consensus::serialize(&tx.output),
        coinbase_tx_locktime: tx.lock_time.to_consensus_u32(),
        merkle_path: bp_mining_job::coinbase_merkle_branch(&txids),
        extranonce_slot: declared.extranonce_slot,
    })
}

/// What a `SetCustomMiningJob` claims.
#[derive(Clone, Copy, Debug)]
pub struct MinedJobFields<'a> {
    pub version: u32,
    pub coinbase_tx_version: u32,
    pub coinbase_prefix: &'a [u8],
    pub coinbase_tx_input_n_sequence: u32,
    pub coinbase_tx_outputs: &'a [u8],
    pub coinbase_tx_locktime: u32,
    pub merkle_path: &'a [[u8; 32]],
    pub full_extranonce_size: usize,
}

/// Every field must match exactly. The scriptSig prefix too: a prefix match
/// would admit an empty one, i.e. no BIP-34 height push.
pub fn check_custom_job(
    binding: &DeclaredJobBinding,
    mined: MinedJobFields<'_>,
) -> Result<(), BindingViolation> {
    // BIP-323 bits included: rolling happens at hashing time, but the two
    // base versions may not differ (SV2 Mining/SetCustomMiningJob).
    if binding.version != mined.version {
        return Err(BindingViolation::Version);
    }
    if binding.coinbase_tx_version != mined.coinbase_tx_version {
        return Err(BindingViolation::CoinbaseTxVersion);
    }
    if binding.coinbase_script_sig_prefix != mined.coinbase_prefix {
        return Err(BindingViolation::CoinbaseScriptSigPrefix);
    }
    if binding.coinbase_tx_input_n_sequence != mined.coinbase_tx_input_n_sequence {
        return Err(BindingViolation::CoinbaseInputNSequence);
    }
    if binding.coinbase_tx_outputs != mined.coinbase_tx_outputs {
        return Err(BindingViolation::CoinbaseOutputs);
    }
    if binding.coinbase_tx_locktime != mined.coinbase_tx_locktime {
        return Err(BindingViolation::CoinbaseLocktime);
    }
    if binding.merkle_path != mined.merkle_path {
        return Err(BindingViolation::MerklePath);
    }
    // The pool reassembles a found block into the DECLARED gap; another width
    // breaks the scriptSig length and the merkle root.
    if binding.extranonce_slot != mined.full_extranonce_size {
        return Err(BindingViolation::ExtranonceSlotWidth);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jdp::declarations::DeclaredJob;
    use crate::tokens::Token;
    use bp_common::AddressId;

    const SCRIPT_SIG_PREFIX: [u8; 3] = [0x03, 0xC8, 0x00];
    const SLOT: usize = 8;

    /// A declared coinbase split at the extranonce slot.
    fn coinbase_parts(script_sig_prefix: &[u8], outputs_blob: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use bitcoin::consensus::Encodable;

        let script_sig_len = script_sig_prefix.len() + SLOT;
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&2u32.to_le_bytes());
        prefix.push(0x01);
        prefix.extend_from_slice(&[0u8; 32]);
        prefix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // A wrong length would make the "projects to None" tests pass falsely.
        bitcoin::VarInt(script_sig_len as u64)
            .consensus_encode(&mut prefix)
            .expect("Vec<u8> writer cannot fail");
        prefix.extend_from_slice(script_sig_prefix);

        let mut suffix = Vec::new();
        suffix.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // nSequence
        suffix.extend_from_slice(outputs_blob);
        suffix.extend_from_slice(&7u32.to_le_bytes()); // locktime
        (prefix, suffix)
    }

    fn a_transaction(tag: u8) -> Vec<u8> {
        use bitcoin::hashes::Hash as _;
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([tag; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        bitcoin::consensus::serialize(&tx)
    }

    fn declared_job(tx_count: usize) -> DeclaredJob {
        let (coinbase_tx_prefix, coinbase_tx_suffix) = coinbase_parts(&SCRIPT_SIG_PREFIX, &[0x00]);
        let raw_transactions = (0..tx_count)
            .map(|position| a_transaction(0xA0 + position as u8))
            .collect();
        DeclaredJob {
            new_token: Token([1u8; 16]),
            miner_address: AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap(),
            version: 0x2000_0000,
            coinbase_tx_prefix,
            coinbase_tx_suffix,
            raw_transactions,
            prev_hash: [0xAB; 32],
            declared_at_ms: 1_000,
            booking: None,
            distribution_id: None,
        }
    }

    fn mined_from(binding: &DeclaredJobBinding) -> MinedJobFields<'_> {
        MinedJobFields {
            version: binding.version,
            coinbase_tx_version: binding.coinbase_tx_version,
            coinbase_prefix: &binding.coinbase_script_sig_prefix,
            coinbase_tx_input_n_sequence: binding.coinbase_tx_input_n_sequence,
            coinbase_tx_outputs: &binding.coinbase_tx_outputs,
            coinbase_tx_locktime: binding.coinbase_tx_locktime,
            merkle_path: &binding.merkle_path,
            full_extranonce_size: binding.extranonce_slot,
        }
    }

    #[test]
    fn projection_reads_the_declared_coinbase() {
        let binding = binding_from_declared_job(&declared_job(2)).expect("must project");
        assert_eq!(binding.version, 0x2000_0000);
        assert_eq!(binding.coinbase_tx_version, 2);
        assert_eq!(binding.coinbase_script_sig_prefix, SCRIPT_SIG_PREFIX);
        assert_eq!(binding.coinbase_tx_input_n_sequence, 0x1234_5678);
        assert_eq!(binding.coinbase_tx_outputs, vec![0x00]);
        assert_eq!(binding.coinbase_tx_locktime, 7);
        // 3 leaves ⇒ two siblings.
        assert_eq!(binding.merkle_path.len(), 2);
    }

    #[test]
    fn an_honest_job_matches_its_declaration() {
        let binding = binding_from_declared_job(&declared_job(2)).expect("must project");
        assert_eq!(check_custom_job(&binding, mined_from(&binding)), Ok(()));
    }

    #[test]
    fn every_bound_field_is_checked() {
        let binding = binding_from_declared_job(&declared_job(2)).expect("must project");

        let mut m = mined_from(&binding);
        m.version ^= 1;
        assert_eq!(
            check_custom_job(&binding, m),
            Err(BindingViolation::Version)
        );

        let mut m = mined_from(&binding);
        m.coinbase_tx_version = 1;
        assert_eq!(
            check_custom_job(&binding, m),
            Err(BindingViolation::CoinbaseTxVersion)
        );

        let mut m = mined_from(&binding);
        m.coinbase_prefix = &[0xFF, 0xFF];
        assert_eq!(
            check_custom_job(&binding, m),
            Err(BindingViolation::CoinbaseScriptSigPrefix)
        );

        let mut m = mined_from(&binding);
        m.coinbase_tx_input_n_sequence = 0xFFFF_FFFF;
        assert_eq!(
            check_custom_job(&binding, m),
            Err(BindingViolation::CoinbaseInputNSequence)
        );

        let other_outputs = bitcoin::consensus::serialize(&vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
        }]);
        let mut m = mined_from(&binding);
        m.coinbase_tx_outputs = &other_outputs;
        assert_eq!(
            check_custom_job(&binding, m),
            Err(BindingViolation::CoinbaseOutputs)
        );

        let mut m = mined_from(&binding);
        m.coinbase_tx_locktime = 0;
        assert_eq!(
            check_custom_job(&binding, m),
            Err(BindingViolation::CoinbaseLocktime)
        );

        let other_path = vec![[0xEE; 32]];
        let mut m = mined_from(&binding);
        m.merkle_path = &other_path;
        assert_eq!(
            check_custom_job(&binding, m),
            Err(BindingViolation::MerklePath)
        );
    }

    /// Pins that the version compare is never masked to the BIP-323 bits.
    #[test]
    fn a_bip323_only_difference_is_still_a_version_violation() {
        use bp_mining_job::BIP323_VERSION_ROLLING_MASK as BIP323_MASK;

        let binding = binding_from_declared_job(&declared_job(2)).expect("must project");
        assert_eq!(check_custom_job(&binding, mined_from(&binding)), Ok(()));

        for bit in [5u32, 12, 28] {
            let mut m = mined_from(&binding);
            m.version = binding.version | (1 << bit);
            assert_ne!(
                m.version, binding.version,
                "bit {bit} must change the value"
            );
            assert_eq!(
                m.version & !BIP323_MASK,
                binding.version & !BIP323_MASK,
                "bit {bit} must lie inside the BIP-323 mask"
            );
            assert_eq!(
                check_custom_job(&binding, m),
                Err(BindingViolation::Version),
                "a BIP-323-only difference in bit {bit} must not pass"
            );
        }
    }

    #[test]
    fn any_script_sig_prefix_other_than_the_declared_one_is_refused() {
        let binding = binding_from_declared_job(&declared_job(2)).expect("must project");

        assert_eq!(check_custom_job(&binding, mined_from(&binding)), Ok(()));

        for (label, prefix) in [
            ("empty", &[][..]),
            ("truncated", &SCRIPT_SIG_PREFIX[..2]),
            ("different", &[0x03, 0xC9][..]),
            ("extended", &[0x03, 0xC8, 0x00, 0xFF][..]),
        ] {
            let mut m = mined_from(&binding);
            m.coinbase_prefix = prefix;
            assert_eq!(
                check_custom_job(&binding, m),
                Err(BindingViolation::CoinbaseScriptSigPrefix),
                "a {label} scriptSig prefix must not pass"
            );
        }
    }

    #[test]
    fn an_unrebuildable_coinbase_projects_to_none() {
        let mut job = declared_job(2);
        job.coinbase_tx_prefix = vec![0x02, 0x00];
        assert!(binding_from_declared_job(&job).is_none());
    }

    /// A branch that skipped it would authorise a different block.
    #[test]
    fn an_undecodable_declared_transaction_projects_to_none() {
        let mut job = declared_job(2);
        job.raw_transactions[1] = vec![0xFF, 0xFF];
        assert!(binding_from_declared_job(&job).is_none());
    }

    #[test]
    fn an_empty_transaction_set_projects_with_an_empty_branch() {
        let binding = binding_from_declared_job(&declared_job(0)).expect("must project");
        assert!(binding.merkle_path.is_empty());
    }
}
