// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fan-out of the share hooks into the accumulators, driven through the
//! protocol-agnostic `bp_share_hook` view. No PG, no flush.

use std::sync::Arc;

use bp_share_hook::{RejectedReason, SharedRejectedShare, SharedRejectedShareSink};
use bp_share_stats_sink::flush::Accumulators;
use bp_share_stats_sink::hooks::ShareStatsRejectedSink;

fn share<'a>(
    address: Option<&'a str>,
    session_id: &'a str,
    reason: RejectedReason,
    difficulty: f64,
) -> SharedRejectedShare<'a> {
    SharedRejectedShare {
        address,
        worker: address.map(|_| "w1"),
        session_id,
        reason,
        difficulty,
        group_id: None,
    }
}

#[tokio::test]
async fn rejected_share_with_address_fans_into_four_accumulators() {
    let accs = Arc::new(Accumulators::default());
    let sink = ShareStatsRejectedSink::new(accs.clone());

    sink.record_rejected(share(
        Some("bc1qalice"),
        "sess0001",
        RejectedReason::LowDifficulty,
        25.0,
    ))
    .await;

    let snap = accs.pool_shares.take();
    assert_eq!(snap.values().next().unwrap().rejected, 25.0);
    let pr = accs.pool_rejected.take();
    // Difficulty sum per (slot, reason), not a share count: the chart
    // plots rejected diff-1 per reason.
    assert_eq!(
        pr.values().next().unwrap()[&RejectedReason::LowDifficulty],
        25.0
    );
    assert_eq!(accs.share_totals.take_workers_rejected().len(), 1);
    assert_eq!(accs.client_statistics.take().len(), 1);
}

#[tokio::test]
async fn rejected_share_without_address_skips_per_address_buckets() {
    let accs = Arc::new(Accumulators::default());
    let sink = ShareStatsRejectedSink::new(accs.clone());

    sink.record_rejected(share(None, "sess0001", RejectedReason::JobNotFound, 10.0))
        .await;

    assert_eq!(
        accs.pool_shares.take().values().next().unwrap().rejected,
        10.0
    );
    assert_eq!(accs.pool_rejected.take().len(), 1);
    assert_eq!(accs.share_totals.take_workers_rejected().len(), 0);
    assert_eq!(accs.client_statistics.take().len(), 0);
    assert_eq!(accs.share_totals.take_addresses().len(), 0);
}

#[tokio::test]
async fn rejected_share_with_invalid_address_short_circuits() {
    let accs = Arc::new(Accumulators::default());
    let sink = ShareStatsRejectedSink::new(accs.clone());

    sink.record_rejected(share(
        Some(""),
        "sess0001",
        RejectedReason::DuplicateShare,
        5.0,
    ))
    .await;

    assert_eq!(
        accs.pool_shares.take().values().next().unwrap().rejected,
        5.0
    );
    assert_eq!(accs.pool_rejected.take().len(), 1);
    assert_eq!(accs.share_totals.take_workers_rejected().len(), 0);
}

#[tokio::test]
async fn rejected_share_non_finite_difficulty_is_silently_discarded() {
    let accs = Arc::new(Accumulators::default());
    let sink = ShareStatsRejectedSink::new(accs.clone());

    for diff in [
        f64::NAN,
        f64::INFINITY,
        0.0,
        -5.0,
        bp_stats::MAX_REASONABLE_DIFFICULTY * 10.0,
    ] {
        sink.record_rejected(share(
            Some("bc1qalice"),
            "sess",
            RejectedReason::LowDifficulty,
            diff,
        ))
        .await;
    }

    assert_eq!(accs.pool_shares.take().len(), 0);
    assert_eq!(accs.pool_rejected.take().len(), 0);
    assert_eq!(accs.share_totals.take_workers_rejected().len(), 0);
}

#[tokio::test]
async fn rejected_share_classifies_jnf_dup_low_into_separate_diff1_fields() {
    let accs = Arc::new(Accumulators::default());
    let sink = ShareStatsRejectedSink::new(accs.clone());

    for (reason, diff) in [
        (RejectedReason::JobNotFound, 7.0),
        (RejectedReason::DuplicateShare, 13.0),
        (RejectedReason::LowDifficulty, 29.0),
    ] {
        sink.record_rejected(share(Some("bc1qalice"), "sess", reason, diff))
            .await;
    }

    let cs = accs.client_statistics.take();
    assert_eq!(cs.len(), 1);
    let rec = cs.values().next().unwrap();
    assert_eq!(rec.rejected_job_not_found_diff1, 7.0);
    assert_eq!(rec.rejected_duplicate_share_diff1, 13.0);
    assert_eq!(rec.rejected_low_difficulty_share_diff1, 29.0);
    let counts = rec.rejected_job_not_found_count
        + rec.rejected_duplicate_share_count
        + rec.rejected_low_difficulty_share_count;
    assert_eq!(counts, 3.0, "one count per reject, each under its reason");
}

/// The sink is the one gate for an unusable credited difficulty: nothing of
/// such a share reaches any accumulator.
#[tokio::test]
async fn accepted_share_with_unusable_difficulty_is_silently_discarded() {
    use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareSink};
    use bp_share_stats_sink::hooks::ShareStatsAcceptedSink;
    use bp_stats::MAX_REASONABLE_DIFFICULTY;

    let accs = Arc::new(Accumulators::default());
    let sink = ShareStatsAcceptedSink::new(accs.clone());
    for diff in [
        f64::NAN,
        f64::INFINITY,
        0.0,
        -5.0,
        MAX_REASONABLE_DIFFICULTY * 10.0,
    ] {
        sink.record_accepted(SharedAcceptedShare {
            address: "bc1qalice",
            worker: "w1",
            session_id: "sess",
            effective_difficulty: diff,
            submission_difficulty: diff,
            user_agent: None,
            is_block_candidate: false,
            hash_rate: 0.0,
            channel_count: 1,
            ts_ms: 0,
            share_id: "",
            mode: bp_share_hook::MiningMode::Solo,
            group_id: None,
        })
        .await;
    }

    assert!(accs.pool_shares.take().is_empty());
    assert!(accs.pool_mode_hashrate.take().is_empty());
    assert!(accs.client_statistics.take().is_empty());
    assert!(accs.share_totals.take_addresses().is_empty());
    assert!(accs.best_difficulty.take().is_empty());
}
