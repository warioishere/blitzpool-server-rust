// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bp_share_hook` impls that fan every share into the stats accumulators.
//! Mode-blind: every accepted / rejected share of every mode lands here; the
//! per-mode hashrate reads the producer-stamped `share.mode`.

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
        let mode = share.mode;
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
        // Best difficulty tracks the solved difficulty, which can exceed the
        // credited one.
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

/// A reject before authorize has neither address nor worker: it bumps only
/// the pool-wide counters.
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
        // The per-reason accumulator sums difficulty, not a share count:
        // that is what the chart renders.
        self.accumulators.pool_shares.add_rejected(slot, difficulty);
        self.accumulators
            .pool_rejected
            .add(slot, reason, difficulty);

        let (Some(addr), Some(worker)) = (share.address, share.worker) else {
            return;
        };
        let address_id = match AddressId::new(addr.to_string()) {
            Ok(a) => a,
            Err(_) => return,
        };

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
            client_name: worker.to_string(),
            session_id: share.session_id.to_string(),
            slot,
        };
        let mut delta = ClientStatisticsRecord {
            rejected_count: 1.0,
            ..Default::default()
        };
        // One column pair per reason, no folds, so the counters sum to
        // `rejected_count`; a new `RejectedReason` variant needs its own pair.
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
            // Not low-difficulty: the work may be fine, the miner is ignoring
            // the mask it negotiated.
            RejectedReason::VersionRollingNotAllowed => {
                delta.rejected_version_rolling_count = 1.0;
                delta.rejected_version_rolling_diff1 = difficulty;
            }
            // Not job-not-found: a stale share is the ordinary tail of a block
            // change; folded together, every block would look like broken miners.
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

    /// Slot maxima take the solved difficulty, sums the credited one.
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
