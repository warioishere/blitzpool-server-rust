// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only views consumed by `bp-api` HTTP routes.
//!
//! Endpoints:
//! - `/api/pplns/groups/:groupId/round-stats` ⇒
//!   [`ReaderView::round_stats`]
//! - `/api/pplns/groups/:groupId/best-difficulty` ⇒
//!   [`ReaderView::best_difficulty`]
//!
//! `/api/pplns/groups/:groupId/blocks` (block-history list) is
//! deferred to a consumer-driven bp-db read query; the underlying
//! `PplnsGroupBlockHistoryRow` row-struct already exists in bp-db.

use bp_db::find_group;
use bp_group_mgmt::group::PayoutMode;
use uuid::Uuid;

use crate::engine::{EngineError, GroupSoloEngine};
use crate::round::{BestShare, RoundStats};

impl GroupSoloEngine {
    pub fn reader(&self) -> ReaderView<'_> {
        ReaderView { engine: self }
    }
}

pub struct ReaderView<'a> {
    engine: &'a GroupSoloEngine,
}

/// Per-time-bucket sliding-window contribution for the timeline chart.
/// `buckets` is `(hour-bucket-id, addr → diff)` oldest→newest; empty for a
/// non-window group. `window_ms` is the window length (0 when not window).
#[derive(Clone, Debug, PartialEq)]
pub struct WindowTimeline {
    pub window_ms: i64,
    pub buckets: Vec<(i64, std::collections::HashMap<String, f64>)>,
}

impl ReaderView<'_> {
    /// Snapshot of one group's round state: per-address share contribution +
    /// totals + rejected counters. Mode-aware — a `Window`-mode group's
    /// per-address view is its trimmed sliding window, not the full history.
    pub async fn round_stats(&self, group_id: Uuid) -> Result<RoundStats, EngineError> {
        let (mode, window_ms) = match find_group(self.engine.pool(), group_id).await? {
            Some(g) => crate::engine::group_mode_from_row(&g),
            None => (PayoutMode::Prop, 0),
        };
        let now_ms = chrono::Utc::now().timestamp_millis();
        let stats = self
            .engine
            .round()
            .read_round_stats_for(&group_id.to_string(), mode, now_ms, window_ms)
            .await?;
        Ok(stats)
    }

    /// Best-difficulty share recorded in the current round. `None`
    /// if no shares yet (round just started).
    pub async fn best_difficulty(&self, group_id: Uuid) -> Result<Option<BestShare>, EngineError> {
        let best = self
            .engine
            .round()
            .read_best_share(&group_id.to_string())
            .await?;
        Ok(best)
    }

    /// Per-bucket sliding-window timeline for a `Window`-mode group (drives the
    /// window-timeline chart). Resolves the group's window length, trims, and
    /// returns per-bucket per-address contribution oldest→newest. A non-window
    /// group (or unknown id) yields an empty timeline — the caller renders
    /// nothing for it.
    pub async fn window_timeline(&self, group_id: Uuid) -> Result<WindowTimeline, EngineError> {
        let (mode, window_ms) = match find_group(self.engine.pool(), group_id).await? {
            Some(g) => crate::engine::group_mode_from_row(&g),
            None => (PayoutMode::Prop, 0),
        };
        if mode != PayoutMode::Window {
            return Ok(WindowTimeline {
                window_ms: 0,
                buckets: Vec::new(),
            });
        }
        let now_ms = chrono::Utc::now().timestamp_millis();
        let buckets = self
            .engine
            .round()
            .read_window_timeline(&group_id.to_string(), now_ms, window_ms)
            .await?;
        Ok(WindowTimeline { window_ms, buckets })
    }
}
