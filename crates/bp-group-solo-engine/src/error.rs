// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crate-level error umbrella.
//!
//! Narrow per-module errors live with the module that produces them
//! (`config::ConfigError` etc.); this enum only captures failures callers
//! handle at the engine boundary, each wrapping its narrow error via
//! `#[from]`.

use crate::config::ConfigError;

#[derive(thiserror::Error, Debug)]
pub enum GroupSoloEngineError {
    #[error("config validation: {0}")]
    Config(#[from] ConfigError),
}
