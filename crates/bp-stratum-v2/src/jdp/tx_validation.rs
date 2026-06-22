// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure helpers for the JDP `DeclareMiningJob` → `ProvideMissingTransactions`
//! → `…Success` round-trip.
//!
//! ## What happens on `DeclareMiningJob`
//!
//! The JDC sends a wtxid list as part of `DeclareMiningJob`. The JDS
//! needs raw transaction bytes for every wtxid so it can later
//! reconstruct the block on `PushSolution` (spec §6.4.9). Two
//! partitions drive the response:
//!
//! 1. **Mempool partition** (informational, for logging only): which
//!    wtxids does bitcoin-core's mempool already know about? Computed
//!    by [`partition_mempool_known`]. This is used for logging only;
//!    it doesn't affect what we ask the JDC.
//!
//! 2. **Template partition** (actionable): which wtxids do we have
//!    raw transaction bytes for in our current template? Computed by
//!    [`partition_against_template`]. The missing positions are
//!    requested from the JDC via `ProvideMissingTransactions`.
//!
//! ## Round-trip state
//!
//! Between sending `ProvideMissingTransactions` and receiving
//! `ProvideMissingTransactions.Success`, the JDS holds a
//! [`PendingDeclaration`] that tracks the request-id, the positions
//! we asked for, and the raw txs we already had locally. When the
//! Success frame arrives, [`merge_provided_with_known`] folds the
//! provided list into the complete `position → raw_tx` map.
//!
//! ## Byte-order convention
//!
//! All wtxids in this module are 32-byte arrays in **wire byte
//! order** (the order SV2 sends them on the wire — i.e. the natural
//! output of SHA256d). Callers are responsible for keying their
//! template-tx and mempool-wtxid maps in the same byte order.

use std::collections::{HashMap, HashSet};

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
    /// `true` when no transactions are missing — the JDS can skip
    /// the `ProvideMissingTransactions` step and call
    /// `acceptDeclaration` directly.
    pub fn fully_covered(&self) -> bool {
        self.missing_positions.is_empty()
    }
}

// ── partition_against_template ──────────────────────────────────────

/// Partition `wtxid_list` against the JDS's local
/// `template_txs` (a `wtxid → raw_tx` map keyed in the same byte
/// order as the wtxid_list entries).
///
/// Pure function — no I/O. The result drives the
/// `ProvideMissingTransactions` request: positions whose wtxids
/// aren't in the template need to be filled by the JDC.
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

// ── partition_mempool_known (informational) ─────────────────────────

/// Outcome of [`partition_mempool_known`]. Both lists hold wtxid
/// bytes (not positions) because this is used for logging
/// only — it's not actionable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MempoolPartition {
    pub known: Vec<[u8; 32]>,
    pub unknown: Vec<[u8; 32]>,
}

/// Partition `wtxid_list` against `mempool_wtxids` (what bitcoin-core
/// currently has in its mempool). Used for logging only
/// — doesn't affect what's requested via `ProvideMissingTransactions`.
///
/// **Graceful-degradation note**: On mempool-lookup failure, the
/// caller may adopt a fallback that accepts all transactions (assumes
/// everything is in mempool). This pure function just reports what the
/// caller pre-computed; error handling is the caller's responsibility.
pub fn partition_mempool_known(
    wtxid_list: &[[u8; 32]],
    mempool_wtxids: &HashSet<[u8; 32]>,
) -> MempoolPartition {
    let mut known = Vec::new();
    let mut unknown = Vec::new();
    for wtxid in wtxid_list {
        if mempool_wtxids.contains(wtxid) {
            known.push(*wtxid);
        } else {
            unknown.push(*wtxid);
        }
    }
    MempoolPartition { known, unknown }
}

// ── PendingDeclaration ──────────────────────────────────────────────

/// In-flight declaration state. Stored on the JDP-session between
/// emitting `ProvideMissingTransactions` and receiving
/// `ProvideMissingTransactions.Success`. The handler-layer holds at
/// most one of these per connection — a second `DeclareMiningJob`
/// arriving while a pending one is in-flight is a JDC bug we'd want
/// to log and drop (deferred to `jdp::client`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingDeclaration {
    /// `DeclareMiningJob.request_id` — echoed on the Success frame.
    pub request_id: u32,
    /// Positions we asked the JDC for (matches the
    /// `unknown_tx_position_list` field in
    /// `ProvideMissingTransactions`).
    pub missing_positions: Vec<u32>,
    /// Raw txs we already had locally. Caller folds the provided
    /// list in via [`merge_provided_with_known`] when the Success
    /// frame arrives.
    pub known_raw_txs: HashMap<u32, Vec<u8>>,
}

// ── merge_provided_with_known ──────────────────────────────────────

/// Error from [`merge_provided_with_known`]. The Success frame's
/// `transaction_list` MUST contain exactly one entry per requested
/// position (SV2 spec §6.4.7). A length mismatch is a JDC
/// protocol-error — the caller decides whether to silently drop or
/// reset the connection.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MergeError {
    #[error("expected {expected} transactions, got {got}")]
    PositionCountMismatch { expected: usize, got: usize },
}

/// Fold a `ProvideMissingTransactions.Success` payload into the
/// known-raw-txs map collected during partition. Returns the
/// complete `position → raw_tx` map ready for the `acceptDeclaration`
/// path.
///
/// The provided list MUST have the same length as
/// `pending.missing_positions` — order matches index-for-index.
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

    /// Positions are 0-indexed and preserve order — even when known
    /// + missing interleave.
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

    // ── partition_mempool_known ────────────────────────────────────

    #[test]
    fn partition_mempool_classifies_known_and_unknown() {
        let mut mempool = HashSet::new();
        mempool.insert(wtxid(0x01));
        mempool.insert(wtxid(0x03));
        let list = vec![wtxid(0x01), wtxid(0x02), wtxid(0x03)];
        let result = partition_mempool_known(&list, &mempool);
        assert_eq!(result.known, vec![wtxid(0x01), wtxid(0x03)]);
        assert_eq!(result.unknown, vec![wtxid(0x02)]);
    }

    #[test]
    fn partition_mempool_empty_list() {
        let result = partition_mempool_known(&[], &HashSet::new());
        assert!(result.known.is_empty());
        assert!(result.unknown.is_empty());
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

    /// Zero missing positions + zero provided → empty merge (the
    /// caller would normally skip the ProvideMissingTransactions
    /// round-trip entirely, but the function is total).
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
