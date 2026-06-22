// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine tunables.

use std::time::Duration;

use crate::error::SessionPersistenceError;

/// Constructed once at `bin/blitzpool` startup, immutable thereafter.
#[derive(Clone, Debug)]
pub struct SessionPersistenceConfig {
    /// Max number of cached `address → CachedAddressSettings` entries.
    /// Hits a soft cap; cold-path on overflow is fine (re-reads from PG).
    /// Default 50_000 — comfortably fits ~10× active-miner count in
    /// memory (each entry is ~150 bytes).
    pub address_cache_capacity: usize,
    /// Flush interval for the buffered `client_entity` touch updates.
    /// Default 30 s.
    pub touch_flush_interval: Duration,
}

impl Default for SessionPersistenceConfig {
    fn default() -> Self {
        Self {
            address_cache_capacity: 50_000,
            touch_flush_interval: Duration::from_secs(30),
        }
    }
}

impl SessionPersistenceConfig {
    pub fn validate(&self) -> Result<(), SessionPersistenceError> {
        if self.address_cache_capacity == 0 {
            return Err(SessionPersistenceError::Config(
                "address_cache_capacity must be > 0".to_string(),
            ));
        }
        if self.touch_flush_interval.is_zero() {
            return Err(SessionPersistenceError::Config(
                "touch_flush_interval must be > 0".to_string(),
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
        assert!(SessionPersistenceConfig::default().validate().is_ok());
    }

    #[test]
    fn zero_capacity_rejected() {
        let cfg = SessionPersistenceConfig {
            address_cache_capacity: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_flush_interval_rejected() {
        let cfg = SessionPersistenceConfig {
            touch_flush_interval: Duration::ZERO,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
