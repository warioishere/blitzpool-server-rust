// SPDX-License-Identifier: AGPL-3.0-or-later

//! Direct 80-byte block-header assembly for the share-validation hot path.
//! No `bitcoin::Block` / `Transaction` allocations.

/// Lowest `nVersion` core accepts (`bad-version`), compared as a SIGNED `i32`
/// with CLTV active. Below it the block is lost silently, since
/// `submit_solution` is fire-and-forget. Check the resulting version: the
/// rolled bits alone cannot tell an accepted version from a rejected one.
pub const MIN_CONSENSUS_BLOCK_VERSION: i32 = 4;

/// Whether a block with this version passes [`MIN_CONSENSUS_BLOCK_VERSION`].
pub fn version_meets_consensus_floor(version: u32) -> bool {
    (version as i32) >= MIN_CONSENSUS_BLOCK_VERSION
}

/// Assemble the 80-byte header, byte-identical to `consensus_encode`.
/// `version` is used verbatim with no mask parameter: SV1 applies BIP-310's
/// `(job & ~mask) | (bits & mask)` before calling, and SV2 already submits
/// the full nVersion.
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

/// Whether a share hash is a block: the one block-found gate of SV1 and SV2.
/// Exact U256 comparison against the consensus-decoded target, never an `f64`
/// difficulty. `hash_le` is the hasher's internal little-endian order;
/// reversing it to display order inverts the test.
pub fn meets_network_target(hash_le: &[u8; 32], n_bits: u32) -> bool {
    let target =
        bitcoin::pow::Target::from_compact(bitcoin::pow::CompactTarget::from_consensus(n_bits));
    bp_share::Target::from_le_bytes(target.to_le_bytes()).is_met_by_le(hash_le)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The target itself is a block, target + 1 is not.
    #[test]
    fn the_network_target_boundary_is_exact() {
        for n_bits in [0x1d00_ffff_u32, 0x1703_4e33, 0x207f_ffff] {
            let target = bitcoin::pow::Target::from_compact(
                bitcoin::pow::CompactTarget::from_consensus(n_bits),
            )
            .to_le_bytes();
            assert!(
                meets_network_target(&target, n_bits),
                "{n_bits:#x}: target itself"
            );

            let mut above = target;
            for byte in above.iter_mut() {
                let (v, carry) = byte.overflowing_add(1);
                *byte = v;
                if !carry {
                    break;
                }
            }
            assert!(
                !meets_network_target(&above, n_bits),
                "{n_bits:#x}: target + 1"
            );
        }
    }

    /// The hash is read little-endian; the wrong order flips both verdicts.
    #[test]
    fn the_network_target_reads_the_hash_little_endian() {
        let mut below = [0u8; 32];
        below[27] = 0xff;
        below[26] = 0xfe;
        assert!(meets_network_target(&below, 0x1d00_ffff));

        let mut above = [0u8; 32];
        above[28] = 0x01;
        assert!(!meets_network_target(&above, 0x1d00_ffff));
    }

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
        // Unsigned, 0x80000000 would be the largest version, not the smallest.
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
