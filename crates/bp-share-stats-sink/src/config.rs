// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine tunables.

use std::time::Duration;

use crate::error::SinkError;

/// Constructed once at `bin/blitzpool` startup, immutable thereafter.
#[derive(Clone, Debug)]
pub struct StatsSinkConfig {
    /// Flush cadence. 60 s in production; tests use sub-second
    /// intervals.
    pub flush_interval: Duration,
    /// Max rows per single `client_statistics_entity` bulk-upsert.
    /// Above this the coordinator batches across multiple PG calls.
    /// Each batch sends 13 arrays of length N; stays well under PG's
    /// 65 535 param limit.
    pub client_stats_batch_size: usize,
    /// Whether to fire an immediate "spot flush" the moment the
    /// current 10-minute slot ends. When disabled, residuals wait
    /// for the next cron tick (up to `flush_interval`).
    pub slot_aligned_flush: bool,
    /// Whether to run the `seedIfEmpty` bootstrap on
    /// [`crate::engine::ShareStatsEngine::spawn`]. Disabled by tests
    /// that don't want the migration overhead.
    pub seed_on_spawn: bool,
    /// Phase offset applied to the first tick of the flush loop so
    /// it doesn't fire on the same boot-relative instant as other
    /// 60 s loops (kill_dead_clients, best_difficulty cron, etc.).
    /// Default zero — set in the bin to spread PG load.
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
