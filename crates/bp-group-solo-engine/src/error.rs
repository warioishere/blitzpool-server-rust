// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crate-level error umbrella. Grows as modules land.
//!
//! Per Design Principle 9: narrow per-module errors live with the
//! module that produces them (`config::ConfigError` etc.); this enum
//! only captures failures callers need to handle at the engine
//! boundary. Each variant carries the underlying narrow error via
//! `#[from]`.

use crate::config::ConfigError;

#[derive(thiserror::Error, Debug)]
pub enum GroupSoloEngineError {
    #[error("config validation: {0}")]
    Config(#[from] ConfigError),
}
