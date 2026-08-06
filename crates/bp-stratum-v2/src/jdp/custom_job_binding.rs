// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bind the job a JDC asks to MINE to the job it DECLARED.
//!
//! The two arrive on different connections: `DeclareMiningJob` on JDP and
//! `SetCustomMiningJob` on the Mining Protocol, the latter carrying its own
//! `coinbase_tx_outputs` and `merkle_path`. Base SV2 ties them only by
//! `mining_job_token`; nothing in either spec requires the fields to agree.
//!
//! ## What this is NOT about
//!
//! Revenue. This module does not look at fees, does not compare the block's
//! value against anything, and does not reject a JDC for declaring an empty
//! or low-fee template. **Which transactions a JDC mines is its own call —
//! that is the entire point of job declaration**, and a small `T` is a
//! smaller block for everyone in the distribution, not a fault. §4 already
//! requires the coinbase to pay out exactly the `T` its own template yields,
//! and `SetCustomMiningJob` is checked against the published distribution
//! independently ([`crate::jdp::payout_distribution`]), so the split is
//! guarded regardless of what was declared. Settlement then books from the
//! block's own coinbase at whatever `T` it actually paid, so a low-revenue
//! block needs no detection to be booked correctly.
//!
//! ## What it IS about
//!
//! Making the node validation apply to the job being mined.
//!
//! `jdp_server` hands every declaration to bitcoin-core before accepting it
//! (SV2 §6.1 — `checkBlock` over the job-declaration IPC). That establishes
//! that the DECLARED transaction set is one a block could be built from.
//! The mining side never repeats it: `SetCustomMiningJob.merkle_path` goes
//! into the [`crate::mining::jobs::ExtendedJob`] unexamined, and the §7.1
//! coinbase check says nothing about the transaction set hanging off it.
//!
//! Without this comparison, "the declaration passed the node" and "this job
//! pays the published distribution" are two true statements about two
//! possibly different jobs. A JDC could have a valid set approved, then mine
//! a set nobody validated — collecting window share for hashrate whose
//! blocks cannot land. That is a different thing from mining an empty block,
//! which is valid and pays.
//!
//! ## Two honest limits
//!
//! - It is only worth as much as the validator behind it. `job_validator` is
//!   optional; with none wired, declarations are accepted untested and this
//!   binds a job to an unverified one.
//! - Coinbase-only jobs have no declaration to bind, so the same freedom
//!   over the transaction set exists there. That is base JDP §6.3.1 and is
//!   accepted, not closed here. This raises a Full-Template declaration back
//!   to meaning what it says, nothing wider.
//!
//! This module is pure. It projects a stored [`DeclaredJob`] down to the
//! fields `SetCustomMiningJob` repeats ([`DeclaredJobBinding`]) and compares
//! them ([`check_custom_job`]).
//!
//! ## What it does NOT cover
//!
//! `nbits` and `min_ntime`. Both are properties of the template the
//! declaration was validated against, and neither reaches
//! [`DeclaredJob`] — the JDP-side validator resolves them inside
//! bitcoin-core's job-declaration IPC and the response we consume
//! (`DeclareMiningJobResult`) does not carry them back. Adding them means
//! plumbing the validator's view out first; until then they are unchecked,
//! and a mismatch in either produces a block the network rejects rather than
//! a payout that goes wrong.

use bitcoin::hashes::Hash;

use crate::jdp::declarations::DeclaredJob;
use crate::jdp::dynamic_outputs::declared_coinbase_tx;

/// A declared job projected down to the fields `SetCustomMiningJob` repeats.
///
/// Built once per bridge lookup from the stored declaration, so the mining
/// handler compares against a small owned value instead of carrying the whole
/// declared-job payload (raw transactions included) across the connection
/// boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredJobBinding {
    /// Block-header version as declared.
    pub version: u32,
    /// Coinbase transaction `nVersion`.
    pub coinbase_tx_version: u32,
    /// The scriptSig bytes the declaration committed to, i.e. everything
    /// before the extranonce slot.
    pub coinbase_script_sig_prefix: Vec<u8>,
    /// Coinbase input `nSequence`.
    pub coinbase_tx_input_n_sequence: u32,
    /// CompactSize-prefixed consensus output vector, re-serialised from the
    /// rebuilt coinbase so it compares byte-for-byte against the wire field.
    pub coinbase_tx_outputs: Vec<u8>,
    /// Coinbase `nLockTime`.
    pub coinbase_tx_locktime: u32,
    /// Sibling hashes from the coinbase leaf up to the root, over the
    /// declared transaction set.
    pub merkle_path: Vec<[u8; 32]>,
    /// Bytes the declaration reserved for the extranonce. The mining channel
    /// sizes its own extranonce independently, and the JDP `PushSolution`
    /// rebuild splices the channel's into the declared gap — so the two have
    /// to agree or the rebuilt coinbase contradicts its own scriptSig length.
    pub extranonce_slot: usize,
}

/// Which field of the mined job disagrees with the declaration.
///
/// Every variant is reachable: the JDC composes both messages itself and
/// nothing before this check compared them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingViolation {
    Version,
    CoinbaseTxVersion,
    CoinbaseScriptSigPrefix,
    CoinbaseInputNSequence,
    CoinbaseOutputs,
    CoinbaseLocktime,
    /// The mined job commits to a different transaction set than the one the
    /// node validated — the variant this module exists for.
    MerklePath,
    /// The mining channel's extranonce does not fit the gap the declaration
    /// left for it. Accepting would build a job whose found block cannot be
    /// reassembled.
    ExtranonceSlotWidth,
}

/// Project a stored declaration into the comparable fields.
///
/// `None` when the declared coinbase cannot be rebuilt (see
/// [`declared_coinbase_tx`]) or a declared transaction is missing/unparseable
/// — the caller must treat that as a rejection, never as "nothing to check".
pub fn binding_from_declared_job(job: &DeclaredJob) -> Option<DeclaredJobBinding> {
    let declared = declared_coinbase_tx(&job.coinbase_tx_prefix, &job.coinbase_tx_suffix)?;
    let tx = &declared.tx;

    let mut txids = Vec::with_capacity(1 + job.wtxid_list.len());
    txids.push(tx.compute_txid().to_byte_array());
    for position in 0..job.wtxid_list.len() as u32 {
        let raw = job.raw_transactions.get(&position)?;
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

/// What a `SetCustomMiningJob` claims, in the shape this check needs.
///
/// A borrowed view rather than the frame itself, so the comparison stays
/// testable without building a whole mining-session input.
#[derive(Clone, Copy, Debug)]
pub struct MinedJobFields<'a> {
    pub version: u32,
    pub coinbase_tx_version: u32,
    pub coinbase_prefix: &'a [u8],
    pub coinbase_tx_input_n_sequence: u32,
    pub coinbase_tx_outputs: &'a [u8],
    pub coinbase_tx_locktime: u32,
    pub merkle_path: &'a [[u8; 32]],
    /// The mining channel's own extranonce width, which the pool will splice
    /// into the declared gap when a block is pushed.
    pub full_extranonce_size: usize,
}

/// Compare a mined job against its declaration. Every field for exact
/// equality.
///
/// The scriptSig was once compared with `starts_with`, on the reasoning that
/// the declaration and the mining channel size the extranonce slot
/// independently. They do — but that sizes the SLOT, not the committed
/// prefix: one coinbase built by one JDC yields the same prefix bytes in both
/// messages, whatever the slot around them measures. So the relaxation bought
/// nothing, and it cost everything: the mined prefix is the NEEDLE, and
/// `starts_with(&[])` is true of every slice, so an empty `coinbase_prefix`
/// passed unconditionally. The pool then assembles a scriptSig that is bare
/// extranonce — no BIP-34 height push — and every block found on that job is
/// invalid, while its shares keep earning.
pub fn check_custom_job(
    binding: &DeclaredJobBinding,
    mined: MinedJobFields<'_>,
) -> Result<(), BindingViolation> {
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
    // The one field that is not a byte-compare against the declaration: the
    // channel decides its own extranonce width, and the declaration reserved
    // a gap of its own. Comparing the committed scriptSig prefix does not
    // catch a mismatch between the two, because the prefix stops where the
    // gap starts. But `handle_push_solution` rebuilds a found block as
    // `declared_prefix || channel extranonce || declared_suffix`, and the
    // declared prefix's scriptSig length covers the DECLARED gap — splice a
    // different width in and the coinbase contradicts its own length field,
    // the merkle root stops matching what was hashed, and the block is lost
    // at submit with nothing having objected when the job was accepted.
    //
    // SCAFFOLDING, and it should go when its reason does: this check exists
    // only because WE reassemble the block. The reference stack forwards
    // `PushSolution` to bitcoin-core's job-declaration IPC instead and
    // reassembles nothing — no splice, nothing to bind. That path is an
    // unimplemented stub today (`handle_push_solution` is a `// todo`), which
    // is why we submit over JSON-RPC ourselves. If a later Core lets us hand
    // the solution over instead, `handle_push_solution`'s reconstruction and
    // this check retire together.
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
    use std::collections::HashMap;

    const SCRIPT_SIG_PREFIX: [u8; 3] = [0x03, 0xC8, 0x00];
    const SLOT: usize = 8;

    /// Build a declared coinbase split at the extranonce slot, the way SV2
    /// carries it.
    fn coinbase_parts(script_sig_prefix: &[u8], outputs_blob: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use bitcoin::consensus::Encodable;

        let script_sig_len = script_sig_prefix.len() + SLOT;
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&2u32.to_le_bytes());
        prefix.push(0x01);
        prefix.extend_from_slice(&[0u8; 32]);
        prefix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // The library encoder, not `push(len as u8)`. A truncating cast is
        // right only while the length stays under 253 — and a fixture that
        // silently writes the wrong length still "passes" any test asserting
        // the projection returns None, for a reason that has nothing to do
        // with the coinbase it meant to build.
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
        let mut raw_transactions = HashMap::new();
        let mut wtxid_list = Vec::new();
        for position in 0..tx_count {
            raw_transactions.insert(position as u32, a_transaction(0xA0 + position as u8));
            wtxid_list.push([0xA0 + position as u8; 32]);
        }
        DeclaredJob {
            new_token: Token([1u8; 16]),
            version: 0x2000_0000,
            coinbase_tx_prefix,
            coinbase_tx_suffix,
            wtxid_list,
            raw_transactions,
            prev_hash: Some([0xAB; 32]),
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

    /// The projection reads the fields off the rebuilt transaction, not off
    /// assumed byte offsets — pin each one against what was declared.
    #[test]
    fn projection_reads_the_declared_coinbase() {
        let binding = binding_from_declared_job(&declared_job(2)).expect("must project");
        assert_eq!(binding.version, 0x2000_0000);
        assert_eq!(binding.coinbase_tx_version, 2);
        assert_eq!(binding.coinbase_script_sig_prefix, SCRIPT_SIG_PREFIX);
        assert_eq!(binding.coinbase_tx_input_n_sequence, 0x1234_5678);
        assert_eq!(binding.coinbase_tx_outputs, vec![0x00]);
        assert_eq!(binding.coinbase_tx_locktime, 7);
        // 3 leaves (coinbase + 2) ⇒ two levels ⇒ two siblings.
        assert_eq!(binding.merkle_path.len(), 2);
    }

    /// The honest job passes. Every test below tampers with exactly one
    /// field, so what each proves is that field.
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

    /// The scriptSig prefix carries the BIP-34 height push, and the pool
    /// assembles its scriptSig from the MINED prefix alone. So every
    /// departure from the declared bytes has to be refused — a shortened one
    /// as much as a different one, and above all an EMPTY one, which is what
    /// the `starts_with` this replaced accepted from every declaration
    /// (`starts_with(&[])` is true of every slice). An empty prefix yields a
    /// scriptSig of bare extranonce, no height push, and a block the network
    /// rejects while the job's shares keep earning.
    #[test]
    fn any_script_sig_prefix_other_than_the_declared_one_is_refused() {
        let binding = binding_from_declared_job(&declared_job(2)).expect("must project");

        // Positive control: the declared bytes are accepted.
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

    /// A coinbase that will not rebuild projects to nothing — fail-closed,
    /// so the caller cannot read it as "nothing to check".
    #[test]
    fn an_unrebuildable_coinbase_projects_to_none() {
        let mut job = declared_job(2);
        job.coinbase_tx_prefix = vec![0x02, 0x00];
        assert!(binding_from_declared_job(&job).is_none());
    }

    /// Same for a declared transaction we do not hold: without it the
    /// merkle branch cannot be computed, and a branch computed over a
    /// SHORTER set would silently authorise a different block.
    #[test]
    fn a_missing_declared_transaction_projects_to_none() {
        let mut job = declared_job(2);
        job.raw_transactions.remove(&1);
        assert!(binding_from_declared_job(&job).is_none());

        let mut job = declared_job(2);
        job.raw_transactions.insert(1, vec![0xFF, 0xFF]);
        assert!(binding_from_declared_job(&job).is_none());
    }

    /// A declaration with no transactions but a real coinbase still
    /// projects — an empty block is a legitimate declaration.
    #[test]
    fn an_empty_transaction_set_projects_with_an_empty_branch() {
        let binding = binding_from_declared_job(&declared_job(0)).expect("must project");
        assert!(binding.merkle_path.is_empty());
    }
}
