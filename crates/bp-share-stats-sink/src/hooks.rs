// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bp_share_hook` trait impls: fan a single share into the accumulators
//! that back the stats tables.
//!
//! Both per-share hooks come from `bp-share-hook`, decoupled from the wire
//! protocol, so this single impl serves both the SV1 and SV2 servers.
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

/// `SharedAcceptedShareSink` impl that mutates the accumulators on
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
        self.accumulators
            .pool_shares
            .add_accepted(slot, diff, share.submission_difficulty);
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
                max_difficulty: bp_stats::share_max(share.submission_difficulty),
                ..Default::default()
            },
        );
        // All-time best difficulty tracks the SOLVED difficulty (can exceed
        // the credited/clamped one), stamped with the miner's firmware. Folded
        // into `address_settings_entity."bestDifficulty"` at flush time via
        // GREATEST, so there is no per-share PG write.
        self.accumulators.best_difficulty.add(
            &address_id,
            share.submission_difficulty,
            share.user_agent,
        );
        self.accumulators
            .share_totals
            .add(address_id, share.worker.to_string(), diff);
    }
}

/// `SharedRejectedShareSink` impl. Address is `Option` because some
/// reject reasons fire before authorize completes; such a reject still
/// bumps the pool-wide counters but skips the per-address ones.
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
        // One column pair per reason, no folds — every arm below writes a
        // different pair, so the five counters sum to `rejected_count`. Adding
        // a `RejectedReason` variant without a pair to put it in would break
        // that sum silently; a new variant gets its own column pair.
        match reason {
            RejectedReason::JobNotFound => {
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
            // Not folded into low-difficulty: such a share's proof-of-work may
            // be perfectly good, so an operator seeing it there would read
            // normal churn where a miner is ignoring the mask it negotiated.
            RejectedReason::VersionRollingNotAllowed => {
                delta.rejected_version_rolling_count = 1.0;
                delta.rejected_version_rolling_diff1 = difficulty;
            }
            // Not folded into job-not-found: this is the ordinary tail of a
            // block transition and needs no action, that one is work the pool
            // never had. Folded together, every block change would read as a
            // fleet of broken miners.
            RejectedReason::Stale => {
                delta.rejected_stale_count = 1.0;
                delta.rejected_stale_diff1 = difficulty;
            }
        }
        self.accumulators.client_statistics.add(key, &delta);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::MiningMode;

    /// The slot maximum is the difficulty the share solved, the sums are what
    /// it was credited at. Handing the credited value to the maximum would
    /// leave it at 10 here.
    #[tokio::test]
    async fn an_accepted_share_feeds_the_solved_difficulty_into_both_slot_maxima() {
        let accs = Arc::new(Accumulators::default());
        let sink = ShareStatsAcceptedSink::new(accs.clone());
        sink.record_accepted(SharedAcceptedShare {
            address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            worker: "rig1",
            session_id: "sess0001",
            effective_difficulty: 10.0,
            submission_difficulty: 4096.0,
            user_agent: None,
            is_block_candidate: false,
            hash_rate: 0.0,
            channel_count: 1,
            ts_ms: 0,
            share_id: "",
            mode: MiningMode::Solo,
            group_id: None,
        })
        .await;

        let pool = accs.pool_shares.drain();
        let pool = pool.values().next().expect("one pool slot");
        assert_eq!((pool.accepted, pool.max_difficulty), (10.0, 4096.0));

        let clients = accs.client_statistics.drain();
        let client = clients.values().next().expect("one client row");
        assert_eq!((client.shares, client.max_difficulty), (10.0, 4096.0));
    }
}
