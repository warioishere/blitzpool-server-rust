// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crate-level error type. Grows as modules land.
//!
//! Per Design Principle 9 (`feedback-design-principles`): narrow
//! per-module errors live with the module that produces them (e.g.
//! `config::ConfigError`); the crate-level `PplnsEngineError` here only
//! captures failures that callers need to handle at the engine
//! boundary (engine startup, distribution build, share-record, block-
//! found). Each variant carries the underlying narrow error via
//! `#[from]` so callers can `match` on the specific cause.

use crate::config::ConfigError;

/// Errors returned across the `bp-pplns-engine` public surface.
#[derive(thiserror::Error, Debug)]
pub enum PplnsEngineError {
    /// Config validation failed at engine construction.
    #[error("config validation: {0}")]
    Config(#[from] ConfigError),
}
