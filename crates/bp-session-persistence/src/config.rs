// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine tunables.

use std::time::Duration;

use crate::error::SessionPersistenceError;

/// Constructed once at `bin/blitzpool` startup, immutable thereafter.
#[derive(Clone, Debug)]
pub struct SessionPersistenceConfig {
    /// Flush interval for the touch updates into the `client:live:*` hashes.
    pub touch_flush_interval: Duration,
    /// How long a session must survive before its `client_entity` row is
    /// written. Must stay well below the device-status gate's `online_dwell`,
    /// which treats a device without a row as absent. `ZERO` is legal.
    pub row_debounce: Duration,
    /// Flush interval for the batched row births.
    pub row_flush_interval: Duration,
    /// TTL of the `client:live:*` hashes, wired to the dead-session sweep's
    /// staleness cutoff so both clocks agree. Only the touch flush refreshes it.
    pub live_ttl: Duration,
}

impl Default for SessionPersistenceConfig {
    fn default() -> Self {
        Self {
            touch_flush_interval: Duration::from_secs(30),
            row_debounce: Duration::from_secs(15),
            row_flush_interval: Duration::from_secs(5),
            live_ttl: Duration::from_secs(5 * 60),
        }
    }
}

impl SessionPersistenceConfig {
    pub fn validate(&self) -> Result<(), SessionPersistenceError> {
        if self.touch_flush_interval.is_zero() {
            return Err(SessionPersistenceError::Config(
                "touch_flush_interval must be > 0".to_string(),
            ));
        }
        // `row_debounce` may be zero: it is an age threshold, not a timer.
        if self.row_flush_interval.is_zero() {
            return Err(SessionPersistenceError::Config(
                "row_flush_interval must be > 0".to_string(),
            ));
        }
        // Otherwise every live hash expires between two touch flushes.
        if self.live_ttl <= self.touch_flush_interval {
            return Err(SessionPersistenceError::Config(
                "live_ttl must be > touch_flush_interval".to_string(),
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
    fn zero_flush_interval_rejected() {
        let cfg = SessionPersistenceConfig {
            touch_flush_interval: Duration::ZERO,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_row_flush_interval_rejected_but_zero_debounce_allowed() {
        let cfg = SessionPersistenceConfig {
            row_flush_interval: Duration::ZERO,
            ..Default::default()
        };
        assert!(cfg.validate().is_err(), "a zero interval panics tokio");

        let cfg = SessionPersistenceConfig {
            row_debounce: Duration::ZERO,
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn live_ttl_at_or_below_flush_interval_rejected() {
        // Equal is already broken: the hash can expire just before the flush.
        let cfg = SessionPersistenceConfig {
            touch_flush_interval: Duration::from_secs(30),
            live_ttl: Duration::from_secs(30),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());

        let cfg = SessionPersistenceConfig {
            live_ttl: Duration::ZERO,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
