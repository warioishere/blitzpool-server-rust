// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crate-level error type. Grows as modules land.

/// Errors returned across the `bp-stratum-v1` public surface.
///
/// Per-share reject classifications (Job-Not-Found, Duplicate, Stale,
/// Low-Difficulty) are *not* errors — they're normal SV1 wire responses
/// and live in the submit module's `RejectReason` enum. This type only
/// captures failures that prevent the server / a connection from
/// functioning: config validation, IO startup, frame parsing.
#[derive(thiserror::Error, Debug)]
pub enum StratumV1Error {
    /// Server or port configuration is malformed. The string explains
    /// which field failed validation and why.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}
