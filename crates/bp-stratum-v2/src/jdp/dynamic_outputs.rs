// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coinbase-output byte helpers shared by the JDP paths.
//!
//! The ext 0x0003 payout logic itself lives in
//! [`crate::jdp::payout_distribution`] (push model: `SetPayoutDistribution`
//! weights, ext 0x0003/Payout Computation recompute-and-compare). What remains
//! here are the byte-level helpers both the base-protocol allocate path and
//! the declare-time validator need:
//!
//! - [`designated_output_blob`] / [`designated_payout_script`] /
//!   [`pays_designated_output`] — the SV2 JDP/AllocateMiningJobToken.Success
//!   base-protocol convention: the blob that designates the pool's payout
//!   script, reading that script back, and whether a coinbase honours it.
//! - [`declared_coinbase_tx`] — the declared prefix/suffix pair → the
//!   rebuilt transaction, its extranonce slot width and its committed
//!   scriptSig prefix, fail-closed.
//! - [`PayoutBooking`] — the accounting identity a proven declaration
//!   carries to the block-found path.

use bitcoin::{Amount, Script, TxOut};

// ── SV2 JDP/AllocateMiningJobToken.Success base-protocol payout output ───

/// The `AllocateMiningJobToken.Success.coinbase_tx_outputs` blob on the
/// base path: ONE output paying `script`, at 0 sats — SV2
/// JDP/AllocateMiningJobToken.Success leaves the amount to the JDC and
/// designates the first output's script as the pool payout output. Read back
/// by [`designated_payout_script`].
pub fn designated_output_blob(script: &Script) -> Vec<u8> {
    bitcoin::consensus::serialize(&vec![TxOut {
        value: Amount::ZERO,
        script_pubkey: script.to_owned(),
    }])
}

/// The script the pool designated as its payout output, read back out of
/// the blob it sent as `AllocateMiningJobToken.Success.coinbase_tx_outputs`.
///
/// SV2 JDP/AllocateMiningJobToken.Success fixes the convention: "JDS MUST
/// reserve the **first** output with a locking script where the pool payout
/// will go. While this output is initially set with a 0 amount of sats, this
/// convention designates this locking script as the **pool payout output**."
/// The designation is positional in the ALLOCATE message *only* — see
/// [`pays_designated_output`] for why the check side cannot index.
///
/// Read back rather than carried alongside, so the blob the pool sent stays
/// the one source of truth. `None` when the blob does not decode or holds no
/// output; the caller then has nothing to hold a custom job to and refuses it.
pub fn designated_payout_script(coinbase_outputs: &[u8]) -> Option<Vec<u8>> {
    let outputs: Vec<TxOut> = bitcoin::consensus::deserialize(coinbase_outputs).ok()?;
    outputs.first().map(|o| o.script_pubkey.as_bytes().to_vec())
}

/// Does this coinbase honour the pool's designated payout output
/// (SV2 JDP/AllocateMiningJobToken.Success)?
///
/// The rule the spec states is narrow, and everything around it is
/// explicitly free: "JDC MUST allocate sats into the pool payout output in
/// order to qualify for pooled mining rewards. JDS and Pool SHOULD reject
/// custom jobs that fail to do so." The JDC MAY add further 0-value AND
/// non-0-value outputs, and MAY "arbitrarily reorder the outputs" — so this
/// searches for the script and requires a non-zero amount. A positional or
/// byte-for-byte comparison would reject every conformant client, since the
/// pool sends the amount as 0 and the JD-client rewrites it.
///
/// How MUCH is not checked: the spec names no threshold and answers a
/// shortfall economically ("Pool MAY pay proportionally smaller rewards").
///
/// ⚠️ "Some sats reached the script" is sufficient only because the allocate
/// designates a script solely when it is the asking miner's own
/// (`ProductionJdpAllocateResolver::resolve_allocate_context`), so a short
/// payment shorts only that miner. A payout routed to a third party (e.g. a
/// Blockparty fee route) is refused a base-protocol token for that reason.
/// The two rules are halves of one guarantee: relax neither on the strength
/// of the other.
pub fn pays_designated_output(outputs: &[TxOut], designated_script: &[u8]) -> bool {
    outputs
        .iter()
        .any(|o| o.script_pubkey.as_bytes() == designated_script && o.value > Amount::ZERO)
}

/// The declared coinbase rebuilt as a whole transaction, plus the width of the
/// extranonce slot that was zero-filled to get there.
///
/// Every consumer that needs more than the outputs — the
/// ext 0x0003/Output Verification payout check reads `tx.output`, the
/// declared-job binding ([`crate::jdp::custom_job_binding`]) reads the
/// version, scriptSig, nSequence and locktime as well, and both need the
/// coinbase txid for the merkle branch — goes through this one reconstruction.
/// The scriptSig it returns carries the slot as zeroes, so `script_sig[..len -
/// slot]` is the prefix the JDC actually committed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredCoinbase {
    pub tx: bitcoin::Transaction,
    /// Bytes of scriptSig the prefix left for the extranonce.
    pub extranonce_slot: usize,
    /// The scriptSig bytes the declaration committed to, i.e. everything
    /// before the slot. Cut here because this is where `slot` was derived
    /// from that length, so `slot <= script_sig.len()` is known to hold.
    pub script_sig_prefix: Vec<u8>,
}

/// Rebuild the declared coinbase transaction from the SV2 prefix/suffix pair.
///
/// A JDC declares its coinbase split around the extranonce slot it does not
/// control: `coinbase_tx_prefix` ends where the slot begins,
/// `coinbase_tx_suffix` resumes after it. The whole transaction is
/// reassembled with the slot zero-filled and decoded by consensus rules, so
/// **the transaction's own framing locates the outputs** and nothing assumes
/// a byte layout for the suffix.
///
/// The slot width comes from the prefix itself: it carries the scriptSig
/// length as a CompactSize and stops at the slot, so
/// `slot = declared_script_sig_len − script_sig_bytes_already_in_prefix`.
/// The header is parsed rather than assumed, because it is 43 bytes when
/// segwit-serialised and 41 without marker+flag.
///
/// **Fail-closed** for a JDC that puts scriptSig bytes AFTER the extranonce
/// (T>0): the derivation yields `N + T`, the rebuilt scriptSig runs T bytes
/// long and the decode fails. A rejection, never a wrong accept.
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

    // `input[0]` and the slice below are safe by construction:
    // `extranonce_slot_width` refused the prefix unless its input count was
    // exactly 1, and derived `slot` from the same scriptSig length
    // `deserialize` just read back, so the input exists and the scriptSig is
    // at least `slot` long.
    let script_sig = tx.input[0].script_sig.as_bytes();
    let script_sig_prefix = script_sig[..script_sig.len() - slot].to_vec();

    Some(DeclaredCoinbase {
        tx,
        extranonce_slot: slot,
        script_sig_prefix,
    })
}

/// Consensus bound on a coinbase's scriptSig: 2 to 100 bytes, else
/// `bad-cb-length`. Only the upper end is enforced below, because the
/// declared length sizes the buffer the transaction is rebuilt in.
const MAX_COINBASE_SCRIPT_SIG_LEN: usize = 100;

/// How many bytes of scriptSig the prefix leaves for the extranonce slot.
///
/// Walks the coinbase header instead of assuming its size: version (4), the
/// optional segwit marker+flag (`00 01`), input count (CompactSize, must be 1),
/// the 36-byte outpoint, then the scriptSig length. Whatever that length
/// exceeds the scriptSig bytes already present in the prefix is the slot.
///
/// ⚠️ **This is the one place "the declaration is a coinbase" is decided.**
/// Every later reader (the payout check on `tx.output`, the binding on
/// `input[0]`) relies on the single-input test below.
///
/// A scriptSig length past the consensus maximum is refused: it keeps the
/// rebuilt coinbase small, and such a declaration could never form a valid
/// block anyway.
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
/// A JDC builds and owns its own coinbase; the pool only publishes a weight
/// distribution (ext 0x0003/SetPayoutDistribution). A found block may only be
/// booked once the declared coinbase was validated positionally against that
/// distribution (ext 0x0003/Output Verification); this rides along on that
/// proof so the block-found path settles exactly the distribution the
/// coinbase pays (`claim(T_actual) − paid` from the settlement snapshot).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayoutBooking {
    /// ext 0x0003/SetPayoutDistribution `distribution_id` the declaration
    /// referenced.
    pub distribution_id: u64,
    /// Settlement-snapshot identity (weights fingerprint) of that
    /// distribution. Zeroed = the owning mode books without a snapshot.
    pub payouts_fingerprint: [u8; 32],
    /// The revenue the distribution's boosts were projected against —
    /// the block-found path's fallback reward when the block's own
    /// coinbase value cannot be read, plus logs.
    pub reference_reward_sats: u64,
}

/// What a `PushSolution`'s declaration was backed by.
///
/// Three states in one type because the block-found path asks two DIFFERENT
/// questions about them, with different answers:
///
/// | backing | book it? | ext 0x0003/Implementation Notes settle, and where |
/// |---|---|---|
/// | [`Self::BaseProtocol`] | no — nothing published | never — nothing published to invalidate |
/// | [`Self::UnbookableDistribution`] | no — its snapshot never landed | **at block-found**, see [`Self::settles_here`] |
/// | [`Self::Bookable`] | yes | after the booking, with every other block |
///
/// The middle row is why this is not an `Option<PayoutBooking>`: collapsed
/// into the top row, a block whose coinbase paid a published distribution
/// would leave that distribution standing for good.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateBacking {
    /// Base-protocol declaration — no distribution was referenced.
    BaseProtocol,
    /// A published distribution was referenced and the declared coinbase was
    /// proven to pay it (ext 0x0003/Output Verification), but its settlement
    /// snapshot never landed, so there are no inputs to book against. The
    /// coinbase still paid it.
    UnbookableDistribution { distribution_id: u64 },
    /// Referenced, proven, and its settlement inputs are on file.
    Bookable(PayoutBooking),
}

impl CandidateBacking {
    /// Did this block's coinbase pay a distribution the pool PUBLISHED?
    ///
    /// Not "can it be booked" and not [`Self::settles_here`]: this decides
    /// whether the block is worth assembling and proving at all.
    pub fn paid_a_published_distribution(&self) -> bool {
        match self {
            Self::BaseProtocol => false,
            Self::UnbookableDistribution { .. } | Self::Bookable(_) => true,
        }
    }

    /// Must the ext 0x0003/Implementation Notes settle fire at block-found, or
    /// does something later own it?
    ///
    /// Only [`Self::UnbookableDistribution`]. Settling invalidates every
    /// published distribution and forces a republish from the LIVE ledger;
    /// before the ledger write that would republish the balances the block
    /// just paid.
    ///
    /// - [`Self::Bookable`]: the confirmation watcher settles after the
    ///   booking is applied, the moment the ledger has actually moved.
    /// - [`Self::UnbookableDistribution`]: no ledger write is coming, so no
    ///   later settle either. Settling here is fail-closed: new declarations
    ///   stop binding to a distribution whose snapshot is unresolvable.
    /// - [`Self::BaseProtocol`]: nothing was published.
    ///
    /// The window between a found block and its confirmation stays open
    /// deliberately: closing it would make the distribution builder account
    /// for parked blocks, and two blocks inside one confirmation window need
    /// a far larger pool share.
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

    /// The allocate path's round trip: build the blob for the miner's script,
    /// then read the script back. It must be the miner's, since the mining
    /// side holds a custom job to it.
    ///
    /// Also pinned byte-for-byte, as the wire form a JDC receives: output
    /// count 1, value 0, `OP_0 <20-byte program>` for the BIP-173 P2WPKH
    /// test vector.
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

    /// An ext 0x0003 allocate sends `[0x00]` (ext 0x0003/Negotiation: outputs
    /// MUST be empty), and a blob may fail to decode. Both answer `None` so
    /// the caller refuses rather than holding a job to a script the pool
    /// never designated.
    #[test]
    fn no_designated_script_without_outputs() {
        assert_eq!(designated_payout_script(&[0x00]), None);
        assert_eq!(designated_payout_script(&[]), None);
        assert_eq!(designated_payout_script(&[0xFF, 0xFF]), None);
    }

    /// The freedoms SV2 JDP/AllocateMiningJobToken.Success grants the JDC,
    /// each of which a byte-for-byte or positional check would reject: it
    /// rewrites the amount (the pool sends 0), reorders, and appends outputs
    /// of its own, including valued ones.
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

    /// The two ways to fail it: the script is absent, or it is present but
    /// carries nothing — which is exactly the state the pool sent it in, so
    /// "the JDC did not touch it" must not read as "paid".
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

    /// The outputs of a rebuilt declaration. Test-only: production reads the
    /// whole [`DeclaredCoinbase`].
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

    // The slot width is derived from the prefix, so any width up to the
    // consensus ceiling on a coinbase scriptSig works.
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

    /// "A coinbase has exactly one input" is decided only in
    /// `extranonce_slot_width`, and every later reader depends on it: the
    /// ext 0x0003/Output Verification payout check takes `tx.output` on
    /// trust, and the declaration binding indexes `input[0]` unguarded.
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

    /// A declared scriptSig length past the consensus maximum is refused
    /// before the rebuild buffer is sized.
    ///
    /// The pair matters: 97 (a 100-byte scriptSig) must still parse, so the
    /// bound refuses no valid coinbase.
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

    // ── the shape a real JDC actually sends ──────────────────────────
    //
    // JD-clients typically slice a **segwit-serialised** coinbase:
    //
    //   index  = 4 version + 2 segwit + 1 inputs + 32 outpoint + 4 index
    //          + 1 scriptSig len + script_sig_head
    //   prefix = serialize(coinbase)[..index]
    //   suffix = serialize(coinbase)[index + full_extranonce_size..]
    //
    // so the prefix carries marker+flag and the suffix carries the
    // **witness** as well as nSequence/outputs/nLockTime. Rebuilding prefix +
    // zeroed slot + suffix reproduces the serialised transaction byte for
    // byte. The fixtures above use the witness-less form the pool's own
    // coinbase builder emits.
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

    // The header is WALKED, not assumed at a fixed offset: 43 bytes
    // segwit-serialised, 41 without. Both must yield the same slot width,
    // asserted on the derivation itself because the surrounding `deserialize`
    // could not tell the failure causes apart.
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

    // The known interop limit, pinned as a decision: scriptSig bytes AFTER
    // the extranonce make the derived width N+T, the rebuilt scriptSig runs
    // long, and the decode fails. Rejection, never a wrong accept.
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
