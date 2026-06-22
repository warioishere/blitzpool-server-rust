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
