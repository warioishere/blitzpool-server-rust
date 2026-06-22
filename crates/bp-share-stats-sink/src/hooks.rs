// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bp_share_hook` trait impls — fan a single share into the six
//! accumulators that back the 7 PG tables.
//!
//! Engines used to impl `bp_stratum_v1::hooks::AcceptedShareSink` +
//! `RejectedShareSink` directly. Both
//! per-share hooks are decoupled from the wire protocol via
//! `bp-share-hook` so this single impl serves both SV1 + SV2 servers.
//!
//! **Mode-blind**: every accepted / rejected share lands here regardless
//! of solo / PPLNS / group-solo. `bin/blitzpool` composes this sink
//! with `bp-pplns-engine`'s and `bp-group-solo-engine`'s hooks via a
//! fan-out composite so each engine sees only the shares it cares
//! about while the stats-sink sees them all.
//!
//! The `pool_mode_hashrate` table is per-mode (solo / pplns /
//! group-solo). The share carries its producer-resolved
//! [`bp_common::MiningMode`], so the sink reads `share.mode` directly —
//! no per-share mode-gate query.

use std::sync::Arc;

use async_trait::async_trait;
use bp_common::AddressId;
use bp_share_hook::{
    RejectedReason, SharedAcceptedShare, SharedAcceptedShareSink, SharedRejectedShare,
    SharedRejectedShareSink,
};
use bp_stats::{
    ClientRejectedKey, ClientStatisticsKey, ClientStatisticsRecord, TimeSlot,
    MAX_REASONABLE_DIFFICULTY,
};

use crate::flush::Accumulators;

/// `SharedAcceptedShareSink` impl that mutates the six accumulators on
/// every accepted share. Cheap to clone (single `Arc`).
pub struct ShareStatsAcceptedSink {
    accumulators: Arc<Accumulators>,
}

impl ShareStatsAcceptedSink {
    pub fn new(accumulators: Arc<Accumulators>) -> Self {
        Self { accumulators }
    }
}

#[async_trait]
impl SharedAcceptedShareSink for ShareStatsAcceptedSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        let diff = share.effective_difficulty;
        if !diff.is_finite() || diff <= 0.0 || diff > MAX_REASONABLE_DIFFICULTY {
            return;
        }
        let slot = TimeSlot::current();
        // Producer-stamped mode — no per-share gate query.
        let mode = share.mode;
        // Per-share accumulator fan-out.
        self.accumulators.pool_shares.add_accepted(slot, diff);
        self.accumulators.pool_mode_hashrate.add(slot, mode, diff);
        let address_id = match AddressId::new(share.address.to_string()) {
            Ok(a) => a,
            Err(_) => return, // pre-authorize-rejected shapes can't be keyed
        };
        let key = ClientStatisticsKey {
            address: address_id.clone(),
            client_name: share.worker.to_string(),
            session_id: share.session_id.to_string(),
            slot,
        };
        self.accumulators.client_statistics.add(
            key,
            &ClientStatisticsRecord {
                shares: diff,
                accepted_count: 1.0,
                ..Default::default()
            },
        );
        self.accumulators
            .share_totals
            .add(address_id, share.worker.to_string(), diff);
    }
}

/// `SharedRejectedShareSink` impl. Address is `Option` because some
/// reject reasons fire before authorize completes; in that case we
/// still bump the pool-wide counters but skip per-address ones.
pub struct ShareStatsRejectedSink {
    accumulators: Arc<Accumulators>,
}

impl ShareStatsRejectedSink {
    pub fn new(accumulators: Arc<Accumulators>) -> Self {
        Self { accumulators }
    }
}

#[async_trait]
impl SharedRejectedShareSink for ShareStatsRejectedSink {
    async fn record_rejected(&self, share: SharedRejectedShare<'_>) {
        let difficulty = share.difficulty;
        if !difficulty.is_finite() || difficulty <= 0.0 || difficulty > MAX_REASONABLE_DIFFICULTY {
            return;
        }
        let slot = TimeSlot::current();
        let reason = share.reason;
        // Pool-wide counters always fire. The per-reason
        // accumulator stores share-difficulty SUM rather than a
        // literal share count — that's the value the frontend
        // chart renders ("rejected difficulty per reason per slot").
        self.accumulators.pool_shares.add_rejected(slot, difficulty);
        self.accumulators
            .pool_rejected
            .add(slot, reason, difficulty);

        let Some(addr) = share.address else {
            return;
        };
        let address_id = match AddressId::new(addr.to_string()) {
            Ok(a) => a,
            Err(_) => return,
        };

        // Per-address rejected stats.
        self.accumulators.client_rejected.add(
            ClientRejectedKey {
                address: address_id.clone(),
                slot,
                reason,
            },
            1.0,
            difficulty,
        );

        let key = ClientStatisticsKey {
            address: address_id.clone(),
            client_name: share.worker.unwrap_or("").to_string(),
            session_id: share.session_id.to_string(),
            slot,
        };
        let mut delta = ClientStatisticsRecord {
            rejected_count: 1.0,
            ..Default::default()
        };
        match reason {
            // `client_statistics_entity` only has three rejected*
            // column pairs — Stale shares fold into the JobNotFound
            // bucket here so the per-session counter stays
            // wire-code-stable. The pool-wide
            // `pool_rejected_statistics_entity` keeps Stale as its
            // own row.
            RejectedReason::JobNotFound | RejectedReason::Stale => {
                delta.rejected_job_not_found_count = 1.0;
                delta.rejected_job_not_found_diff1 = difficulty;
            }
            RejectedReason::DuplicateShare => {
                delta.rejected_duplicate_share_count = 1.0;
                delta.rejected_duplicate_share_diff1 = difficulty;
            }
            RejectedReason::LowDifficulty => {
                delta.rejected_low_difficulty_share_count = 1.0;
                delta.rejected_low_difficulty_share_diff1 = difficulty;
            }
        }
        self.accumulators.client_statistics.add(key, &delta);
    }
}
