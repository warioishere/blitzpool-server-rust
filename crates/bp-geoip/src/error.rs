// SPDX-License-Identifier: AGPL-3.0-or-later

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GeoIpError {
    #[error("HTTP request failed: {0}")]
    Http(String),
    #[error("response parse error: {0}")]
    Parse(String),
    #[error("invalid configuration: {0}")]
    Config(String),
}
