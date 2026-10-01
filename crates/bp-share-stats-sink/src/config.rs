// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine tunables.

use std::time::Duration;

use crate::error::SinkError;

/// Constructed once at `bin/blitzpool` startup, immutable thereafter.
#[derive(Clone, Debug)]
pub struct StatsSinkConfig {
    pub flush_interval: Duration,
    /// Max rows per `client_statistics_entity` bulk upsert; larger drains
    /// are split across several calls.
    pub client_stats_batch_size: usize,
    /// Flush immediately when the 10-minute slot ends instead of waiting
    /// for the next tick.
    pub slot_aligned_flush: bool,
    /// Run `seed_if_empty` on [`crate::engine::ShareStatsEngine::spawn`].
    pub seed_on_spawn: bool,
    /// Delays the first tick so the flush does not coincide with the other
    /// 60 s loops and their PG load.
    pub startup_offset: Duration,
}

impl Default for StatsSinkConfig {
    fn default() -> Self {
        Self {
            flush_interval: Duration::from_secs(60),
            client_stats_batch_size: 1000,
            slot_aligned_flush: true,
            seed_on_spawn: true,
            startup_offset: Duration::ZERO,
        }
    }
}

impl StatsSinkConfig {
    pub fn validate(&self) -> Result<(), SinkError> {
        if self.flush_interval.is_zero() {
            return Err(SinkError::Config("flush_interval must be > 0".to_string()));
        }
        if self.client_stats_batch_size == 0 {
            return Err(SinkError::Config(
                "client_stats_batch_size must be > 0".to_string(),
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
        assert!(StatsSinkConfig::default().validate().is_ok());
    }

    #[test]
    fn zero_flush_interval_rejected() {
        let cfg = StatsSinkConfig {
            flush_interval: Duration::ZERO,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_batch_size_rejected() {
        let cfg = StatsSinkConfig {
            client_stats_batch_size: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
