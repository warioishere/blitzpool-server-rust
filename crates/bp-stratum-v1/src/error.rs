// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crate-level error type.

/// Failures that stop the server from running. Share rejects are not errors:
/// they are normal SV1 responses and live in the submit module's `RejectReason`.
#[derive(thiserror::Error, Debug)]
pub enum StratumV1Error {
    /// Server or port configuration failed validation.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}
