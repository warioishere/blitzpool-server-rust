// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exporter configuration.

use std::net::SocketAddr;

use crate::error::MetricsError;

/// Default listen address — `0.0.0.0:9000`. Production wiring picks
/// this up from the `BP_PROMETHEUS_PORT` env var.
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9000";

#[derive(Clone, Debug)]
pub struct PrometheusConfig {
    /// HTTP listener address. The exporter serves Prometheus
    /// text-format on `GET /metrics`.
    pub bind_addr: SocketAddr,
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            bind_addr: DEFAULT_BIND_ADDR
                .parse()
                .expect("DEFAULT_BIND_ADDR is hard-coded valid"),
        }
    }
}

impl PrometheusConfig {
    /// Construct with a caller-supplied bind addr. Returns a config
    /// error if the string doesn't parse as a `SocketAddr`.
    pub fn with_bind(bind: &str) -> Result<Self, MetricsError> {
        let bind_addr = bind
            .parse()
            .map_err(|e| MetricsError::Config(format!("invalid bind addr {bind:?}: {e}")))?;
        Ok(Self { bind_addr })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_well_known_prom_port() {
        let cfg = PrometheusConfig::default();
        assert_eq!(cfg.bind_addr.port(), 9000);
    }

    #[test]
    fn with_bind_parses_valid_addr() {
        let cfg = PrometheusConfig::with_bind("127.0.0.1:9100").expect("parse");
        assert_eq!(cfg.bind_addr.to_string(), "127.0.0.1:9100");
    }

    #[test]
    fn with_bind_rejects_garbage() {
        assert!(PrometheusConfig::with_bind("not a socket addr").is_err());
    }
}
