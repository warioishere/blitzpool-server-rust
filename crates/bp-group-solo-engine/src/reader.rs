// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only views consumed by `bp-api` HTTP routes.
//!
//! Endpoints:
//! - `/api/pplns/groups/:groupId/round-stats` ⇒
//!   [`ReaderView::round_stats`]
//! - `/api/pplns/groups/:groupId/best-difficulty` ⇒
//!   [`ReaderView::best_difficulty`]
//! - `/api/pplns/groups/:groupId/balance/:address` ⇒
//!   [`ReaderView::balance`]
//!
//! `/api/pplns/groups/:groupId/blocks` (block-history list) is
//! deferred to a consumer-driven bp-db read query; the underlying
//! `PplnsGroupBlockHistoryRow` row-struct already exists in bp-db.

use bp_common::AddressId;
use bp_db::{find_group, find_group_balance};
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

#[derive(Clone, Debug, PartialEq)]
pub struct GroupBalanceView {
    pub address: String,
    pub group_id: Uuid,
    pub pending_sats: i64,
    pub total_paid_sats: i64,
    pub last_accepted_share_at_ms: Option<i64>,
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

    /// One miner's balance + last-share state for a specific group.
    /// `Ok(None)` if the address isn't a member with an open
    /// pending balance.
    pub async fn balance(
        &self,
        group_id: Uuid,
        address: &str,
    ) -> Result<Option<GroupBalanceView>, EngineError> {
        let Ok(addr_id) = AddressId::new(address.to_string()) else {
            return Ok(None);
        };
        let row = find_group_balance(self.engine.pool(), &addr_id, group_id).await?;
        Ok(row.map(|r| GroupBalanceView {
            address: r.address.as_str().to_string(),
            group_id: r.group_id,
            pending_sats: r.pending_sats.0,
            total_paid_sats: r.total_paid_sats.0,
            last_accepted_share_at_ms: r.last_accepted_share_at,
        }))
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
