// SPDX-License-Identifier: AGPL-3.0-or-later

//! Apply-distribution primitives shared by both engines, so the row-type
//! strings the DB column and UI depend on have one source of truth.

use bp_db::DbError;
use thiserror::Error;

/// Row-type discriminator for the payout-history tables. The columns are
/// `varchar(16)` and the UI filters on the literal strings.
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
}

/// Error from an apply-distribution transaction.
#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("db: {0}")]
    Db(#[from] DbError),
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// A different block (reorged out) is already booked at this height, and
    /// history is UNIQUE on `(blockHeight, address)`. Must be an error, not a
    /// zero-count `Ok`, or the confirmation watcher would drop the parked block.
    /// Terminal: the caller parks it for an operator reprocess.
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
    /// True when a retry can never succeed. Lives here so the two engines
    /// cannot disagree about it.
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
