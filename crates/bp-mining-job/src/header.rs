// SPDX-License-Identifier: AGPL-3.0-or-later

//! Direct 80-byte block-header assembly for the share-validation hot path.
//! No `bitcoin::Block` / `Transaction` allocations.

/// Assemble the canonical 80-byte block header.
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
/// `version_mask` is XOR'd into `version` when non-zero (BIP-310 version rolling).
pub fn build_block_header(
    version: i32,
    version_mask: u32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    timestamp: u32,
    bits: u32,
    nonce: u32,
) -> [u8; 80] {
    let v = (version as u32) ^ version_mask;
    let mut h = [0u8; 80];
    h[0..4].copy_from_slice(&v.to_le_bytes());
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
            1, 0, &[0u8; 32], &merkle, 0x495fab29, // timestamp
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
    fn version_mask_xor_applied() {
        let h = build_block_header(0x20000000, 0x00400000, &[0u8; 32], &[0u8; 32], 0, 0, 0);
        let expected_version: u32 = 0x20000000 ^ 0x00400000;
        assert_eq!(&h[0..4], &expected_version.to_le_bytes());
    }

    #[test]
    fn version_mask_zero_is_no_op() {
        let h = build_block_header(0x20000000, 0, &[0u8; 32], &[0u8; 32], 0, 0, 0);
        assert_eq!(&h[0..4], &0x20000000u32.to_le_bytes());
    }
}
