// SPDX-License-Identifier: AGPL-3.0-or-later

use std::time::Duration;

use crate::error::GeoIpError;

/// 10 minute TTL on the whole-cache wipe.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(600);

/// 2-second HTTP timeout.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// `http://ip-api.com` by default; the env var or production wiring
/// can swap in a self-hosted mirror.
pub const DEFAULT_BASE_URL: &str = "http://ip-api.com";

#[derive(Clone, Debug)]
pub struct GeoIpConfig {
    pub base_url: String,
    pub cache_ttl: Duration,
    pub request_timeout: Duration,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            cache_ttl: DEFAULT_CACHE_TTL,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }
}

impl GeoIpConfig {
    pub fn validate(&self) -> Result<(), GeoIpError> {
        if self.base_url.is_empty() {
            return Err(GeoIpError::Config("base_url must not be empty".to_string()));
        }
        if self.cache_ttl.is_zero() {
            return Err(GeoIpError::Config("cache_ttl must be > 0".to_string()));
        }
        if self.request_timeout.is_zero() {
            return Err(GeoIpError::Config(
                "request_timeout must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_validates() {
        assert!(GeoIpConfig::default().validate().is_ok());
    }

    #[test]
    fn empty_base_url_rejected() {
        let cfg = GeoIpConfig {
            base_url: String::new(),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_ttl_rejected() {
        let cfg = GeoIpConfig {
            cache_ttl: Duration::ZERO,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
