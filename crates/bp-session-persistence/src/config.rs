// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine tunables.

use std::time::Duration;

use crate::error::SessionPersistenceError;

/// Constructed once at `bin/blitzpool` startup, immutable thereafter.
#[derive(Clone, Debug)]
pub struct SessionPersistenceConfig {
    /// Flush interval for the buffered session-touch updates written
    /// into the `client:live:*` hashes. Default 30 s.
    pub touch_flush_interval: Duration,
    /// Sampling window for the live per-session hashrate. Each tick closes
    /// a window and writes a 2-sample moving average of the per-window
    /// share rate to the live hash's `hash_rate` field. Default 60 s — long enough
    /// that vardiff's ~10–15 shares/min keep a window well-populated (30 s
    /// is too few shares → noisy), short enough to stay "live".
    pub hashrate_sample_interval: Duration,
    /// Flush interval for the buffered per-slot max-difficulty upserts.
    /// Matches `touch_flush_interval`: both drain the same share window, and
    /// a per-slot max is not more urgent than a session touch.
    pub diff_stat_flush_interval: Duration,
    /// How long a session must survive before its `client_entity` row is
    /// written. Probe connections (measured on prod: 95 % gone within
    /// 1 s) never outlive this, so they cost no statement and leave no
    /// row. Must stay well below the device-status gate's `online_dwell`
    /// (90 s): the gate drops (address, worker) keys with no row yet, so
    /// a later birth would make it treat a connected device as absent.
    /// `ZERO` is legal — "born at the next flush tick" — and is what the
    /// integration tests use for determinism. Default 15 s.
    pub row_debounce: Duration,
    /// Flush interval for the batched row births. Together with
    /// `row_debounce` it bounds the birth latency (debounce + one tick).
    /// Default 5 s.
    pub row_flush_interval: Duration,
    /// TTL of the per-session `client:live:*` Redis hashes. Production
    /// wires this to the dead-session sweep's staleness cutoff so both
    /// clocks agree: a session's hash expires no earlier than its birth
    /// row becomes sweep-eligible. Only the touch flush refreshes it.
    /// Default 300 s.
    pub live_ttl: Duration,
}

impl Default for SessionPersistenceConfig {
    fn default() -> Self {
        Self {
            touch_flush_interval: Duration::from_secs(30),
            hashrate_sample_interval: Duration::from_secs(60),
            diff_stat_flush_interval: Duration::from_secs(30),
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
        if self.hashrate_sample_interval.is_zero() {
            return Err(SessionPersistenceError::Config(
                "hashrate_sample_interval must be > 0".to_string(),
            ));
        }
        // A zero interval is not "flush eagerly" — `tokio::time::interval`
        // panics on it, and it would take the whole engine down at spawn.
        if self.diff_stat_flush_interval.is_zero() {
            return Err(SessionPersistenceError::Config(
                "diff_stat_flush_interval must be > 0".to_string(),
            ));
        }
        // Same interval-panic guard. `row_debounce` on the other hand MAY
        // be zero — that is an age threshold, not a timer.
        if self.row_flush_interval.is_zero() {
            return Err(SessionPersistenceError::Config(
                "row_flush_interval must be > 0".to_string(),
            ));
        }
        // A TTL at or below the flush cadence can only be a mistake:
        // every live hash would expire between two touch flushes and the
        // whole pool would flicker in and out of existence.
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
    fn zero_hashrate_sample_interval_rejected() {
        let cfg = SessionPersistenceConfig {
            hashrate_sample_interval: Duration::ZERO,
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

        // Zero debounce is an age threshold ("due immediately"), not a
        // timer — it must validate.
        let cfg = SessionPersistenceConfig {
            row_debounce: Duration::ZERO,
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn live_ttl_at_or_below_flush_interval_rejected() {
        // Equal is already broken: the hash can expire in the instant
        // before the refreshing flush lands.
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
