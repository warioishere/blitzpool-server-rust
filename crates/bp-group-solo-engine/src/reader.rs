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
use bp_db::find_group_balance;
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

impl ReaderView<'_> {
    /// Snapshot of one group's PROP-round state: per-address share
    /// contribution + totals + rejected counters.
    pub async fn round_stats(&self, group_id: Uuid) -> Result<RoundStats, EngineError> {
        let stats = self
            .engine
            .round()
            .read_round_stats(&group_id.to_string())
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
}
