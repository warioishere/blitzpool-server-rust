// SPDX-License-Identifier: AGPL-3.0-or-later

//! Merkle root reconstruction from a coinbase txid plus a branch of sibling hashes.

use bp_share::sha256d;

/// Fold the coinbase txid up through the merkle branch to produce the root.
/// At each level, the hash is `sha256d(current || sibling)`.
///
/// - `coinbase_hash` is the non-witness coinbase txid (LE bytes).
/// - `merkle_branch` is the leaf-to-root sequence of sibling hashes, as
///   provided by an SV1 `mining.notify` or the TDP template equivalent.
pub fn merkle_root_from_coinbase(coinbase_hash: &[u8; 32], merkle_branch: &[[u8; 32]]) -> [u8; 32] {
    let mut current = *coinbase_hash;
    let mut buf = [0u8; 64];
    for sibling in merkle_branch {
        buf[..32].copy_from_slice(&current);
        buf[32..].copy_from_slice(sibling);
        current = sha256d(&buf);
    }
    current
}

/// The inverse: build the branch [`merkle_root_from_coinbase`] folds.
///
/// `leaves` is the block's txid list in block order, coinbase first, each in
/// internal byte order. Returns the sibling hashes from the coinbase leaf up
/// to the root — what an SV1 `mining.notify` merkle branch and an SV2
/// `merkle_path` carry. Odd levels duplicate their last entry, as consensus
/// does.
///
/// It lives HERE, beside the fold, deliberately: the two have to agree on the
/// duplicate-last rule, and the cross-check in this module's tests is what
/// establishes that they do. A second copy elsewhere would be free to drift
/// from this one with nothing failing.
pub fn coinbase_merkle_branch(leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut level = leaves.to_vec();
    let mut branch = Vec::new();
    let mut buf = [0u8; 64];
    while level.len() > 1 {
        // The coinbase is the left child at every level, so its sibling is
        // always the node at index 1.
        branch.push(level[1]);
        let half = level.len().div_ceil(2);
        let mut next = Vec::with_capacity(half);
        for idx in 0..half {
            let left = level[2 * idx];
            let right = level[std::cmp::min(2 * idx + 1, level.len() - 1)];
            buf[..32].copy_from_slice(&left);
            buf[32..].copy_from_slice(&right);
            next.push(sha256d(&buf));
        }
        level = next;
    }
    branch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_branch_returns_coinbase_hash() {
        let hash = [42u8; 32];
        assert_eq!(merkle_root_from_coinbase(&hash, &[]), hash);
    }

    #[test]
    fn single_step_matches_manual_sha256d() {
        let cb = [0x01u8; 32];
        let sib = [0x02u8; 32];
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&cb);
        buf[32..].copy_from_slice(&sib);
        let expected = sha256d(&buf);
        assert_eq!(merkle_root_from_coinbase(&cb, &[sib]), expected);
    }

    #[test]
    fn multi_step_folds_left_to_right() {
        let cb = [0x05u8; 32];
        let s1 = [0xAAu8; 32];
        let s2 = [0xBBu8; 32];
        let s3 = [0xCCu8; 32];

        // Independent reference: explicit unrolled fold.
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&cb);
        buf[32..].copy_from_slice(&s1);
        let h1 = sha256d(&buf);
        buf[..32].copy_from_slice(&h1);
        buf[32..].copy_from_slice(&s2);
        let h2 = sha256d(&buf);
        buf[..32].copy_from_slice(&h2);
        buf[32..].copy_from_slice(&s3);
        let h3 = sha256d(&buf);

        assert_eq!(merkle_root_from_coinbase(&cb, &[s1, s2, s3]), h3);
    }

    // ── Reference cross-check against a full Bitcoin merkle tree ────────
    //
    // The synthetic tests above fix the siblings by hand. This builds a
    // complete merkle tree the way Bitcoin Core does (pair + duplicate the
    // last node on an odd count), extracts the coinbase's branch, and
    // confirms `merkle_root_from_coinbase` reconstructs the same root — for
    // several leaf counts including odd ones (which exercise the
    // duplicate-last rule that an SV1 `mining.notify` branch encodes).

    /// Hash-like leaf from a seed byte (looks like a real txid).
    fn leaf(seed: u8) -> [u8; 32] {
        sha256d(&[seed; 32])
    }

    /// Bitcoin merkle root: combine pairs, duplicating the last node when a
    /// level has an odd count, until one node remains.
    fn reference_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(*level.last().unwrap());
            }
            let mut next = Vec::with_capacity(level.len() / 2);
            let mut buf = [0u8; 64];
            for pair in level.chunks(2) {
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                next.push(sha256d(&buf));
            }
            level = next;
        }
        level[0]
    }

    /// The cross-check runs against the PRODUCTION branch builder, not a
    /// test-local copy of it. `reference_root` stays hand-rolled on purpose —
    /// it is the independent second opinion the builder is measured against,
    /// and it reaches the root by a different route (pair the whole level,
    /// repeat) than the branch does (siblings on the way up).
    #[test]
    fn fold_matches_full_tree_root_for_various_tx_counts() {
        // 1 (coinbase-only), 2, 3, 4, 5, 7, 9 transactions. Odd counts force
        // the duplicate-last rule at one or more levels.
        for n in [1usize, 2, 3, 4, 5, 7, 9] {
            let leaves: Vec<[u8; 32]> = (0..n as u8).map(leaf).collect();
            let expected = reference_root(&leaves);
            let branch = coinbase_merkle_branch(&leaves);
            let got = merkle_root_from_coinbase(&leaves[0], &branch);
            assert_eq!(
                got, expected,
                "fold must reconstruct the full-tree root for {n} transactions"
            );
        }
    }

    /// A block with only the coinbase has no siblings to fold.
    #[test]
    fn a_lone_coinbase_has_an_empty_branch() {
        assert!(coinbase_merkle_branch(&[leaf(1)]).is_empty());
    }
}
