// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared apply-distribution ledger primitives.
//!
//! The per-engine `apply_distribution` orchestrators (PPLNS signed
//! credit/debit, Group-Solo unsigned pending) build mode-specific audit
//! rows, but the row-type discriminator, the result counts, and the
//! error type are identical — hoisted here so the wire strings the DB
//! column + UI depend on stay one source of truth.

use bp_db::DbError;
use thiserror::Error;

/// Row-type discriminator for the payout-history tables.
///
/// Single source of truth for the wire value: the strings
/// (`coinbase` | `pending` | `dust-sweep`), the schema columns
/// are `varchar(16)`, and the UI styles + filters on the literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayoutRowType {
    /// Paid on-chain via the block's coinbase tx.
    Coinbase,
    /// Ledger change without an on-chain output (sub-dust /
    /// weight-trimmed credit, matching debit, or member-kick
    /// redistribution).
    Pending,
    /// Absorbed by the daily sweep cron after the abandonment period.
    DustSweep,
}

impl PayoutRowType {
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Coinbase => "coinbase",
            Self::Pending => "pending",
            Self::DustSweep => "dust-sweep",
        }
    }

    /// Inverse of [`Self::as_wire`]. `None` for an unrecognised string.
    /// Used when reconstructing a frozen distribution (e.g. a
    /// confirmation-gated block-found) from its serialized wire form.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "coinbase" => Some(Self::Coinbase),
            "pending" => Some(Self::Pending),
            "dust-sweep" => Some(Self::DustSweep),
            _ => None,
        }
    }
}

/// Error from an apply-distribution transaction.
#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("db: {0}")]
    Db(#[from] DbError),
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// Height `block_height` already carries payout rows that do NOT match
    /// what this apply would write — so a DIFFERENT block was booked at
    /// this height and a reorg replaced it with the one being applied now.
    ///
    /// `pplns_payout_history` has no `blockHash` column and is UNIQUE on
    /// `(blockHeight, address)`, so the ledger cannot hold both. This apply
    /// therefore books nothing, and saying so as an error is the whole
    /// point: the previous shape returned `Ok` with zero counts, which the
    /// confirmation watcher read as success — it fired the settlement,
    /// logged "payout history applied" and dropped the parked block. A
    /// block whose coinbase paid miners on-chain vanished with it.
    ///
    /// Terminal by nature: the recorded rows will not change on a retry.
    /// The caller parks the block in the unbookable store instead, where
    /// the frozen distribution survives for an operator reprocess.
    #[error(
        "block height {block_height} already carries {booked_rows} payout rows from a different \
         block; this apply would have written {incoming_rows} — the ledger keys payout history by \
         height, so it cannot hold both"
    )]
    HeightBookedByAnotherBlock {
        block_height: i32,
        booked_rows: usize,
        incoming_rows: usize,
    },
}

impl LedgerError {
    /// Would retrying this ever succeed?
    ///
    /// Only [`Self::HeightBookedByAnotherBlock`] is a verdict; the rest are
    /// infrastructure and clear on their own. Kept here rather than in each
    /// engine's `is_terminal` so the two cannot disagree about it.
    pub fn is_terminal(&self) -> bool {
        match self {
            LedgerError::HeightBookedByAnotherBlock { .. } => true,
            LedgerError::Db(_) | LedgerError::Sqlx(_) => false,
        }
    }
}

/// Row counts affected by one apply-distribution transaction.
#[derive(Clone, Debug)]
pub struct ApplyDistributionResult {
    pub history_inserted: u64,
    pub balances_affected: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payout_row_type_wire_strings_are_correct() {
        assert_eq!(PayoutRowType::Coinbase.as_wire(), "coinbase");
        assert_eq!(PayoutRowType::Pending.as_wire(), "pending");
        assert_eq!(PayoutRowType::DustSweep.as_wire(), "dust-sweep");
    }
}
