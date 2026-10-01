// SPDX-License-Identifier: AGPL-3.0-or-later

//! Errors at the engine boundary; narrow errors live with their module.

use crate::config::ConfigError;

#[derive(thiserror::Error, Debug)]
pub enum PplnsEngineError {
    /// Config validation failed at engine construction.
    #[error("config validation: {0}")]
    Config(#[from] ConfigError),
}
