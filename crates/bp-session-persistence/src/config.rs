// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine tunables.

use std::time::Duration;

use crate::error::SessionPersistenceError;

/// Constructed once at `bin/blitzpool` startup, immutable thereafter.
#[derive(Clone, Debug)]
pub struct SessionPersistenceConfig {
    /// Flush interval for the buffered `client_entity` touch updates.
    /// Default 30 s.
    pub touch_flush_interval: Duration,
    /// Sampling window for the live per-session hashrate. Each tick closes
    /// a window and writes a 2-sample moving average of the per-window
    /// share rate to `client_entity.hashRate`. Default 60 s — long enough
    /// that vardiff's ~10–15 shares/min keep a window well-populated (30 s
    /// is too few shares → noisy), short enough to stay "live".
    pub hashrate_sample_interval: Duration,
    /// Flush interval for the buffered per-slot max-difficulty upserts.
    /// Matches `touch_flush_interval`: both drain the same share window, and
    /// a per-slot max is not more urgent than a session touch.
    pub diff_stat_flush_interval: Duration,
    /// Whether this process zeroes stale `hashRate` at startup. Only the
    /// hashRate-writing role (Front) should set this — the sampler map is
    /// empty on boot, so leftover hashRate from the previous process would
    /// linger as a ghost until `kill_dead_clients` sweeps it. A non-writing
    /// role (api/payout/notify) must NOT, or it would wipe the values the
    /// Front is actively maintaining. Default `false`.
    pub reconcile_hashrate_on_boot: bool,
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
}

impl Default for SessionPersistenceConfig {
    fn default() -> Self {
        Self {
            touch_flush_interval: Duration::from_secs(30),
            hashrate_sample_interval: Duration::from_secs(60),
            diff_stat_flush_interval: Duration::from_secs(30),
            reconcile_hashrate_on_boot: false,
            row_debounce: Duration::from_secs(15),
            row_flush_interval: Duration::from_secs(5),
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
}
