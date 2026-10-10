// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `DeclareMiningJob` → `ProvideMissingTransactions` round-trip: the JDS
//! needs every declared transaction to rebuild the block on `PushSolution`,
//! so whatever the template lacks is requested. wtxids are in wire byte order.

use std::collections::HashMap;

use bitcoin::hashes::{sha256d, Hash};

// ── DeclaredTxs ─────────────────────────────────────────────────────

/// One slot per position in the declared `wtxid_list`: the declared wtxid,
/// with the raw tx when the template has it and `None` where it must be
/// requested.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeclaredTxs(Vec<([u8; 32], Option<Vec<u8>>)>);

/// The provided list must match the request in count and order
/// (SV2 JDP/ProvideMissingTransactions.Success); a shorter list would shift
/// every later position onto the wrong transaction.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MergeError {
    #[error("expected {expected} transactions, got {got}")]
    PositionCountMismatch { expected: usize, got: usize },
    /// The bytes provided for a position are not the transaction declared
    /// there; keeping them would store a transaction nothing has checked.
    #[error(
        "the transaction provided for position {position} does not hash to its declared wtxid"
    )]
    WtxidMismatch { position: u32 },
}

impl DeclaredTxs {
    pub fn against_template(
        wtxid_list: &[[u8; 32]],
        template_txs: &HashMap<[u8; 32], Vec<u8>>,
    ) -> Self {
        Self(
            wtxid_list
                .iter()
                .map(|wtxid| (*wtxid, template_txs.get(wtxid).cloned()))
                .collect(),
        )
    }

    /// The positions to request, ascending.
    pub fn missing_positions(&self) -> Vec<u32> {
        (0u32..)
            .zip(&self.0)
            .filter_map(|(position, (_, tx))| tx.is_none().then_some(position))
            .collect()
    }

    /// The transactions the pool already has, in declaration order.
    pub fn known(&self) -> Vec<&[u8]> {
        self.0.iter().filter_map(|(_, tx)| tx.as_deref()).collect()
    }

    /// Every transaction in declaration order, or `self` back when one is missing.
    pub fn into_complete(self) -> Result<Vec<Vec<u8>>, Self> {
        if self.0.iter().any(|(_, tx)| tx.is_none()) {
            return Err(self);
        }
        Ok(self.0.into_iter().filter_map(|(_, tx)| tx).collect())
    }

    /// The complete list with `provided` filling the gaps, without copying a tx.
    pub fn completed_with<'a>(
        &'a self,
        provided: &'a [Vec<u8>],
    ) -> Result<Vec<&'a [u8]>, MergeError> {
        fill_gaps(
            self.0.iter().map(|(wtxid, tx)| (*wtxid, tx.as_deref())),
            provided.iter().map(Vec::as_slice),
        )
    }

    /// The complete list with `provided` filling the gaps.
    pub fn complete_with(self, provided: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, MergeError> {
        fill_gaps(self.0, provided)
    }
}

/// `provided` into the `None` slots, in order, each checked against the
/// wtxid declared at its position.
fn fill_gaps<T: AsRef<[u8]>>(
    slots: impl IntoIterator<Item = ([u8; 32], Option<T>)>,
    provided: impl IntoIterator<Item = T, IntoIter: ExactSizeIterator>,
) -> Result<Vec<T>, MergeError> {
    let slots: Vec<([u8; 32], Option<T>)> = slots.into_iter().collect();
    let mut provided = provided.into_iter();
    let expected = slots.iter().filter(|(_, tx)| tx.is_none()).count();
    if provided.len() != expected {
        return Err(MergeError::PositionCountMismatch {
            expected,
            got: provided.len(),
        });
    }
    (0u32..)
        .zip(slots)
        .map(|(position, (wtxid, slot))| match slot {
            Some(tx) => Ok(tx),
            None => {
                let tx = provided
                    .next()
                    .expect("one provided tx per gap, counted above");
                if sha256d::Hash::hash(tx.as_ref()).to_byte_array() != wtxid {
                    return Err(MergeError::WtxidMismatch { position });
                }
                Ok(tx)
            }
        })
        .collect()
}

/// The wtxid of a raw transaction (sha256d over its serialization), for
/// fixtures whose provided bytes must match what they declare.
#[cfg(test)]
pub(crate) fn wtxid_of(tx: &[u8]) -> [u8; 32] {
    sha256d::Hash::hash(tx).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wtxid(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    // ── against_template ───────────────────────────────────────────

    #[test]
    fn an_empty_list_is_complete() {
        let txs = DeclaredTxs::against_template(&[], &HashMap::new());
        assert!(txs.missing_positions().is_empty());
        assert_eq!(txs.into_complete(), Ok(vec![]));
    }

    #[test]
    fn a_list_the_template_covers_is_complete_in_order() {
        let mut template = HashMap::new();
        template.insert(wtxid(0x01), vec![0xAA]);
        template.insert(wtxid(0x02), vec![0xBB]);
        let txs = DeclaredTxs::against_template(&[wtxid(0x02), wtxid(0x01)], &template);
        assert!(txs.missing_positions().is_empty());
        assert_eq!(txs.into_complete(), Ok(vec![vec![0xBB], vec![0xAA]]));
    }

    #[test]
    fn unknown_wtxids_become_missing_positions() {
        let mut template = HashMap::new();
        template.insert(wtxid(0x02), vec![0xBB]);
        let list = [wtxid(0x01), wtxid(0x02), wtxid(0x03), wtxid(0x04)];
        let txs = DeclaredTxs::against_template(&list, &template);
        assert_eq!(txs.missing_positions(), vec![0, 2, 3]);
        assert_eq!(txs.known(), vec![&[0xBB][..]]);
        assert!(txs.into_complete().is_err());
    }

    #[test]
    fn a_duplicate_wtxid_fills_both_positions() {
        let mut template = HashMap::new();
        template.insert(wtxid(0x01), vec![0xAA]);
        let txs = DeclaredTxs::against_template(&[wtxid(0x01), wtxid(0x01)], &template);
        assert_eq!(txs.into_complete(), Ok(vec![vec![0xAA], vec![0xAA]]));
    }

    // ── completing ─────────────────────────────────────────────────

    /// Known 0xAA and 0xCC, gaps declared as 0xBB and 0xDD.
    fn gapped() -> DeclaredTxs {
        DeclaredTxs(vec![
            (wtxid_of(&[0xAA]), Some(vec![0xAA])),
            (wtxid_of(&[0xBB]), None),
            (wtxid_of(&[0xCC]), Some(vec![0xCC])),
            (wtxid_of(&[0xDD]), None),
        ])
    }

    #[test]
    fn provided_txs_fill_the_gaps_in_order() {
        let provided = vec![vec![0xBB], vec![0xDD]];
        let expected = vec![vec![0xAA], vec![0xBB], vec![0xCC], vec![0xDD]];
        let txs = gapped();
        let borrowed = txs.completed_with(&provided).unwrap();
        assert_eq!(
            borrowed,
            expected.iter().map(Vec::as_slice).collect::<Vec<_>>()
        );
        assert_eq!(gapped().complete_with(provided).unwrap(), expected);
    }

    #[test]
    fn a_provided_list_of_the_wrong_length_is_refused() {
        let err = MergeError::PositionCountMismatch {
            expected: 2,
            got: 3,
        };
        let provided = vec![vec![0x01], vec![0x02], vec![0x03]];
        assert_eq!(gapped().completed_with(&provided).unwrap_err(), err);
        assert_eq!(gapped().complete_with(provided).unwrap_err(), err);
        assert_eq!(
            gapped().complete_with(vec![vec![0x01]]).unwrap_err(),
            MergeError::PositionCountMismatch {
                expected: 2,
                got: 1,
            }
        );
    }

    #[test]
    fn nothing_provided_completes_a_gapless_list() {
        let txs = DeclaredTxs(vec![(wtxid_of(&[0xAA]), Some(vec![0xAA]))]);
        assert_eq!(txs.complete_with(vec![]).unwrap(), vec![vec![0xAA]]);
    }

    /// Bytes that are not the declared transaction are refused on both paths,
    /// even with the count right; the declared bytes in the same place pass.
    #[test]
    fn a_provided_tx_must_hash_to_the_declared_wtxid() {
        let swapped = vec![vec![0xBB], vec![0xEE]];
        let err = MergeError::WtxidMismatch { position: 3 };
        assert_eq!(gapped().completed_with(&swapped).unwrap_err(), err);
        assert_eq!(gapped().complete_with(swapped).unwrap_err(), err);

        let in_wrong_order = vec![vec![0xDD], vec![0xBB]];
        assert_eq!(
            gapped().complete_with(in_wrong_order).unwrap_err(),
            MergeError::WtxidMismatch { position: 1 }
        );

        let declared = vec![vec![0xBB], vec![0xDD]];
        assert!(gapped().complete_with(declared).is_ok());
    }
}
