// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure helpers for the JDP `DeclareMiningJob` → `ProvideMissingTransactions`
//! → `…Success` round-trip.
//!
//! ## What happens on `DeclareMiningJob`
//!
//! The JDS needs raw bytes for every declared wtxid to reconstruct the block
//! on `PushSolution` (SV2 JDP/PushSolution). Wtxids in the current template
//! are covered; the missing positions are requested from the JDC via
//! `ProvideMissingTransactions` ([`partition_against_template`]).
//!
//! ## Round-trip state
//!
//! Until `ProvideMissingTransactions.Success` arrives, the JDS holds a
//! [`PendingDeclaration`] (request id, requested positions, locally known
//! raw txs); [`merge_provided_with_known`] then builds the complete
//! `position → raw_tx` map.
//!
//! ## Byte order
//!
//! All wtxids here are in **wire byte order** (the natural SHA256d output);
//! callers key their template-tx maps the same way.

use std::collections::HashMap;

// ── PartitionResult ─────────────────────────────────────────────────

/// Outcome of [`partition_against_template`]. `known_raw_txs` keys
/// are wtxid-list **positions** (the index into the JDC's declared
/// `wtxid_list`), values are the raw transaction bytes pulled from
/// the JDS's local template. `missing_positions` lists the positions
/// the JDS needs from the JDC via `ProvideMissingTransactions`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartitionResult {
    pub known_raw_txs: HashMap<u32, Vec<u8>>,
    pub missing_positions: Vec<u32>,
}

impl PartitionResult {
    /// `true` when no transactions are missing, so the
    /// `ProvideMissingTransactions` step is skipped.
    pub fn fully_covered(&self) -> bool {
        self.missing_positions.is_empty()
    }
}

// ── partition_against_template ──────────────────────────────────────

/// Partition `wtxid_list` against the JDS's local `template_txs`
/// (`wtxid → raw_tx`, same byte order). Positions not in the template go
/// into the `ProvideMissingTransactions` request.
pub fn partition_against_template(
    wtxid_list: &[[u8; 32]],
    template_txs: &HashMap<[u8; 32], Vec<u8>>,
) -> PartitionResult {
    let mut known = HashMap::with_capacity(wtxid_list.len());
    let mut missing = Vec::new();
    for (idx, wtxid) in wtxid_list.iter().enumerate() {
        let position = idx as u32;
        match template_txs.get(wtxid) {
            Some(raw) => {
                known.insert(position, raw.clone());
            }
            None => missing.push(position),
        }
    }
    PartitionResult {
        known_raw_txs: known,
        missing_positions: missing,
    }
}

// ── PendingDeclaration ──────────────────────────────────────────────

/// In-flight declaration state, held on the JDP session between
/// `ProvideMissingTransactions` and its `.Success`. At most one per
/// connection: a second `DeclareMiningJob` in the meantime REPLACES it, and
/// the first `request_id` is never answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingDeclaration {
    /// `DeclareMiningJob.request_id`, echoed on the Success frame.
    pub request_id: u32,
    /// Positions requested from the JDC (`unknown_tx_position_list` in
    /// `ProvideMissingTransactions`).
    pub missing_positions: Vec<u32>,
    /// Raw txs already held locally; [`merge_provided_with_known`] folds the
    /// provided list in.
    pub known_raw_txs: HashMap<u32, Vec<u8>>,
}

// ── merge_provided_with_known ──────────────────────────────────────

/// Error from [`merge_provided_with_known`].
/// SV2 JDP/ProvideMissingTransactions.Success fixes `transaction_list` to the
/// requested transactions "in the order they were requested". The count is
/// enforced too, because a shorter list would shift every later position onto
/// the wrong transaction. The handler answers a mismatch with `missing-txs`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MergeError {
    #[error("expected {expected} transactions, got {got}")]
    PositionCountMismatch { expected: usize, got: usize },
}

/// Fold a `ProvideMissingTransactions.Success` payload into the
/// known-raw-txs map and return the complete `position → raw_tx` map.
///
/// The provided list must match `pending.missing_positions` in length and,
/// index for index, in order.
pub fn merge_provided_with_known(
    pending: PendingDeclaration,
    provided: Vec<Vec<u8>>,
) -> Result<HashMap<u32, Vec<u8>>, MergeError> {
    if provided.len() != pending.missing_positions.len() {
        return Err(MergeError::PositionCountMismatch {
            expected: pending.missing_positions.len(),
            got: provided.len(),
        });
    }
    let mut merged = pending.known_raw_txs;
    for (position, raw_tx) in pending.missing_positions.into_iter().zip(provided) {
        merged.insert(position, raw_tx);
    }
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wtxid(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    // ── partition_against_template ─────────────────────────────────

    #[test]
    fn partition_template_empty_list_is_fully_covered() {
        let result = partition_against_template(&[], &HashMap::new());
        assert!(result.fully_covered());
        assert!(result.known_raw_txs.is_empty());
        assert!(result.missing_positions.is_empty());
    }

    #[test]
    fn partition_template_all_known_yields_no_missing() {
        let mut template = HashMap::new();
        template.insert(wtxid(0x01), vec![0xAA]);
        template.insert(wtxid(0x02), vec![0xBB]);
        let list = vec![wtxid(0x01), wtxid(0x02)];
        let result = partition_against_template(&list, &template);
        assert!(result.fully_covered());
        assert_eq!(result.known_raw_txs.len(), 2);
        assert_eq!(result.known_raw_txs.get(&0), Some(&vec![0xAA]));
        assert_eq!(result.known_raw_txs.get(&1), Some(&vec![0xBB]));
    }

    #[test]
    fn partition_template_unknown_wtxids_become_missing_positions() {
        let mut template = HashMap::new();
        template.insert(wtxid(0x01), vec![0xAA]);
        // wtxid 0x02 NOT in template → missing.
        let list = vec![wtxid(0x01), wtxid(0x02), wtxid(0x03)];
        let result = partition_against_template(&list, &template);
        assert!(!result.fully_covered());
        assert_eq!(result.missing_positions, vec![1, 2]);
        assert_eq!(result.known_raw_txs.len(), 1);
        assert_eq!(result.known_raw_txs.get(&0), Some(&vec![0xAA]));
    }

    /// Positions are 0-indexed and preserve order — even when
    /// known + missing interleave.
    #[test]
    fn partition_template_preserves_position_order() {
        let mut template = HashMap::new();
        template.insert(wtxid(0x02), vec![0xBB]);
        let list = vec![wtxid(0x01), wtxid(0x02), wtxid(0x03), wtxid(0x04)];
        let result = partition_against_template(&list, &template);
        assert_eq!(result.missing_positions, vec![0, 2, 3]);
        assert_eq!(result.known_raw_txs.get(&1), Some(&vec![0xBB]));
    }

    /// Duplicate wtxids in the JDC's list → both positions get the
    /// same raw tx assigned.
    #[test]
    fn partition_template_handles_duplicate_wtxids() {
        let mut template = HashMap::new();
        template.insert(wtxid(0x01), vec![0xAA]);
        let list = vec![wtxid(0x01), wtxid(0x01)];
        let result = partition_against_template(&list, &template);
        assert_eq!(result.known_raw_txs.len(), 2);
        assert!(result.missing_positions.is_empty());
        assert_eq!(result.known_raw_txs.get(&0), Some(&vec![0xAA]));
        assert_eq!(result.known_raw_txs.get(&1), Some(&vec![0xAA]));
    }

    // ── merge_provided_with_known ──────────────────────────────────

    #[test]
    fn merge_provided_folds_into_known_map() {
        let mut known = HashMap::new();
        known.insert(0u32, vec![0xAA]);
        known.insert(2u32, vec![0xCC]);
        let pending = PendingDeclaration {
            request_id: 7,
            missing_positions: vec![1, 3],
            known_raw_txs: known,
        };
        let provided = vec![vec![0xBB], vec![0xDD]];
        let merged = merge_provided_with_known(pending, provided).unwrap();
        assert_eq!(merged.len(), 4);
        assert_eq!(merged.get(&0), Some(&vec![0xAA]));
        assert_eq!(merged.get(&1), Some(&vec![0xBB]));
        assert_eq!(merged.get(&2), Some(&vec![0xCC]));
        assert_eq!(merged.get(&3), Some(&vec![0xDD]));
    }

    #[test]
    fn merge_provided_length_mismatch_returns_error() {
        let pending = PendingDeclaration {
            request_id: 1,
            missing_positions: vec![1, 2, 3],
            known_raw_txs: HashMap::new(),
        };
        let provided = vec![vec![0xAA], vec![0xBB]]; // got 2, expected 3
        let err = merge_provided_with_known(pending, provided).unwrap_err();
        assert_eq!(
            err,
            MergeError::PositionCountMismatch {
                expected: 3,
                got: 2,
            }
        );
    }

    /// Zero missing positions + zero provided → the known map unchanged.
    #[test]
    fn merge_provided_zero_positions_is_a_noop() {
        let pending = PendingDeclaration {
            request_id: 1,
            missing_positions: vec![],
            known_raw_txs: HashMap::from([(0u32, vec![0xAA])]),
        };
        let merged = merge_provided_with_known(pending, vec![]).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged.get(&0), Some(&vec![0xAA]));
    }
}
