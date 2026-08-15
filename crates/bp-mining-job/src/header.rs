// SPDX-License-Identifier: AGPL-3.0-or-later

//! Direct 80-byte block-header assembly for the share-validation hot path.
//! No `bitcoin::Block` / `Transaction` allocations.

/// The lowest `nVersion` bitcoin-core will accept in a block header, read
/// as a **signed** `i32`. Below it the block is rejected with
/// `bad-version(0x%08x)` and the pool loses the block silently, because
/// `submit_solution` is fire-and-forget.
///
/// From `ContextualCheckBlockHeader` in core v31.0 (`src/validation.cpp`),
/// where `CBlockHeader::nVersion` is declared `int32_t`:
///
/// ```text
/// if ((block.nVersion < 2 && DeploymentActiveAfter(..., DEPLOYMENT_HEIGHTINCB)) ||
///     (block.nVersion < 3 && DeploymentActiveAfter(..., DEPLOYMENT_DERSIG)) ||
///     (block.nVersion < 4 && DeploymentActiveAfter(..., DEPLOYMENT_CLTV)))
/// ```
///
/// The `< 4` rung is gated on CLTV being active; every network the pool can
/// reach has it, so 4 is the operative floor.
///
/// ⚠️ **This is a property of the resulting version, not of which bits a
/// miner rolled.** Measured against core v31 with a template version of
/// `0x20000000`: rolling bit 29 lands on `0x00000000` (rejected), bit 31 on
/// `0xA0000000` (rejected, negative as `i32`), bit 30 on `0x60000000`
/// (**accepted**). Against a template of `0x30000000` the same bit 29 gives
/// `0x10000000` and is accepted. No function of the rolled delta alone can
/// tell those apart.
pub const MIN_CONSENSUS_BLOCK_VERSION: i32 = 4;

/// Whether a block carrying this header version can be submitted at all.
/// See [`MIN_CONSENSUS_BLOCK_VERSION`].
pub fn version_meets_consensus_floor(version: u32) -> bool {
    (version as i32) >= MIN_CONSENSUS_BLOCK_VERSION
}

/// Assemble the canonical 80-byte block header from a finished `version`.
///
/// Wire layout (matches `bitcoin::block::Header::consensus_encode` byte for byte):
///
/// | bytes  | field        | encoding  |
/// |--------|--------------|-----------|
/// | 0..4   | version      | Int32LE   |
/// | 4..36  | prev_hash    | 32 raw bytes (already LE per template wire format) |
/// | 36..68 | merkle_root  | 32 raw bytes (LE) |
/// | 68..72 | timestamp    | UInt32LE  |
/// | 72..76 | bits         | UInt32LE  |
/// | 76..80 | nonce        | UInt32LE  |
///
/// ⚠️ **`version` is used verbatim — no version-rolling arithmetic happens
/// here, deliberately.** This function used to take a `version_mask` and
/// XOR it in, which is not what BIP-310 specifies
/// (`nVersion = (job_version & ~mask) | (version_bits & mask)`) and agreed
/// with it only while the job version set no bit inside the mask.
///
/// The two protocols reach a finished version differently and neither
/// needs a mask here:
///
/// - **SV1** submits `version_bits`, a masked subset, so
///   `bp_stratum_v1::submit` applies BIP-310's reconstruction against the
///   session's negotiated mask and passes the result.
/// - **SV2** submits the *full* nVersion (spec: `SubmitSharesStandard.version`
///   is the "Full nVersion field"), so there is nothing to reconstruct.
///
/// Keeping a mask parameter would let either caller reintroduce XOR
/// semantics silently. There is nothing to pass, so there is no parameter.
pub fn build_block_header(
    version: i32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    timestamp: u32,
    bits: u32,
    nonce: u32,
) -> [u8; 80] {
    let mut h = [0u8; 80];
    h[0..4].copy_from_slice(&(version as u32).to_le_bytes());
    h[4..36].copy_from_slice(prev_hash);
    h[36..68].copy_from_slice(merkle_root);
    h[68..72].copy_from_slice(&timestamp.to_le_bytes());
    h[72..76].copy_from_slice(&bits.to_le_bytes());
    h[76..80].copy_from_slice(&nonce.to_le_bytes());
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_header_matches_known_bytes() {
        // Mainnet genesis block header — known 80 bytes.
        let merkle: [u8; 32] =
            hex::decode("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a")
                .unwrap()
                .try_into()
                .unwrap();
        let header = build_block_header(
            1, &[0u8; 32], &merkle, 0x495fab29, // timestamp
            0x1d00ffff, // bits
            0x7c2bac1d, // nonce
        );
        let expected = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000\
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
             4b1e5e4a29ab5f49ffff001d1dac2b7c",
        )
        .unwrap();
        assert_eq!(header.as_slice(), expected.as_slice());
    }

    #[test]
    fn the_consensus_floor_is_the_signed_comparison_core_makes() {
        // Core reads nVersion as int32 and rejects `< 4`. An unsigned
        // comparison would call 0x80000000 the largest version there is
        // instead of the smallest.
        assert!(!version_meets_consensus_floor(0));
        assert!(!version_meets_consensus_floor(3));
        assert!(version_meets_consensus_floor(4));
        assert!(version_meets_consensus_floor(0x2000_0000));
        for v in [0x8000_0000u32, 0xA000_0000, u32::MAX] {
            assert!(
                !version_meets_consensus_floor(v),
                "0x{v:08x} is negative as i32 and must fail the floor"
            );
        }
    }
}
