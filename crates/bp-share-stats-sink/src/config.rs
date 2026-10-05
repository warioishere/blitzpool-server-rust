// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine tunables.

use std::time::Duration;

/// Constructed once at `bin/blitzpool` startup, immutable thereafter.
#[derive(Clone, Debug)]
pub struct StatsSinkConfig {
    /// Period of the flush tick, aligned to the wall clock.
    pub flush_interval: Duration,
    /// Max rows per `client_statistics_entity` bulk upsert; larger drains
    /// are split across several calls.
    pub client_stats_batch_size: usize,
    /// How far past each wall-clock period the tick fires, so this flush
    /// does not coincide with the other 60 s loops. An ended slot reaches
    /// Postgres this long after its end, which must stay inside
    /// `bp_stats::CHART_VISIBILITY_BUFFER` or charts show it empty.
    pub tick_offset: Duration,
}

impl Default for StatsSinkConfig {
    fn default() -> Self {
        Self {
            flush_interval: Duration::from_secs(60),
            client_stats_batch_size: 1000,
            tick_offset: Duration::ZERO,
        }
    }
}
