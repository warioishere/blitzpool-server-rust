// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit-level fan-out tests for the share-hook impls. No PG, no flush.
//!
//! The hooks impl `bp_share_hook`'s protocol-agnostic traits. SV1+SV2
//! servers project their native
//! `ShareAccept` / `ShareReject` into the shared view via adapters in
//! the respective `bp-stratum-v{1,2}::shared_adapter` modules — tests
//! here drive the shared view directly.

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

    let snap = accs.pool_shares.drain();
    assert_eq!(snap.values().next().unwrap().rejected, 25.0);
    let pr = accs.pool_rejected.drain();
    // pool_rejected stores difficulty SUM per (slot, reason), not a
    // raw share count — the frontend chart graphs "rejected diff-1
    // per reason per slot".
    assert_eq!(
        pr.values().next().unwrap()[&RejectedReason::LowDifficulty],
        25.0
    );
    assert_eq!(accs.client_rejected.drain().len(), 1);
    assert_eq!(accs.client_statistics.drain().len(), 1);
}

#[tokio::test]
async fn rejected_share_without_address_skips_per_address_buckets() {
    let accs = Arc::new(Accumulators::default());
    let sink = ShareStatsRejectedSink::new(accs.clone());

    sink.record_rejected(share(None, "sess0001", RejectedReason::JobNotFound, 10.0))
        .await;

    assert_eq!(
        accs.pool_shares.drain().values().next().unwrap().rejected,
        10.0
    );
    assert_eq!(accs.pool_rejected.drain().len(), 1);
    assert_eq!(accs.client_rejected.drain().len(), 0);
    assert_eq!(accs.client_statistics.drain().len(), 0);
    assert_eq!(accs.share_totals.drain_addresses().len(), 0);
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
        accs.pool_shares.drain().values().next().unwrap().rejected,
        5.0
    );
    assert_eq!(accs.pool_rejected.drain().len(), 1);
    assert_eq!(accs.client_rejected.drain().len(), 0);
}

#[tokio::test]
async fn rejected_share_non_finite_difficulty_is_silently_discarded() {
    let accs = Arc::new(Accumulators::default());
    let sink = ShareStatsRejectedSink::new(accs.clone());

    for diff in [f64::NAN, f64::INFINITY, 0.0, -5.0] {
        sink.record_rejected(share(
            Some("bc1qalice"),
            "sess",
            RejectedReason::LowDifficulty,
            diff,
        ))
        .await;
    }

    assert_eq!(accs.pool_shares.drain().len(), 0);
    assert_eq!(accs.pool_rejected.drain().len(), 0);
    assert_eq!(accs.client_rejected.drain().len(), 0);
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

    let cs = accs.client_statistics.drain();
    assert_eq!(cs.len(), 1);
    let rec = cs.values().next().unwrap();
    assert_eq!(rec.rejected_job_not_found_diff1, 7.0);
    assert_eq!(rec.rejected_duplicate_share_diff1, 13.0);
    assert_eq!(rec.rejected_low_difficulty_share_diff1, 29.0);
    assert_eq!(rec.rejected_count, 3.0);
}
