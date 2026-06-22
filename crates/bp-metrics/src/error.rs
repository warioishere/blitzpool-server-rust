// SPDX-License-Identifier: AGPL-3.0-or-later

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("invalid metrics configuration: {0}")]
    Config(String),
    #[error("failed to install Prometheus recorder: {0}")]
    Install(String),
}
