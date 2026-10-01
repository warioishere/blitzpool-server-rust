// SPDX-License-Identifier: AGPL-3.0-or-later

//! Errors callers handle at the engine boundary; narrow errors live with the
//! module that produces them.

use crate::config::ConfigError;

#[derive(thiserror::Error, Debug)]
pub enum GroupSoloEngineError {
    #[error("config validation: {0}")]
    Config(#[from] ConfigError),
}
