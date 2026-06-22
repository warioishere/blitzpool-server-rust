// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bridges the SV2-specific
//! [`AcceptedShareSink`](crate::hooks::AcceptedShareSink) trait to the
//! protocol-agnostic
//! [`SharedAcceptedShareSink`](bp_share_hook::SharedAcceptedShareSink).
//!
//! Symmetric counterpart to `bp_stratum_v1::Sv1AcceptedShareAdapter`.
//! See the `bp-share-hook` crate-level docs for the architecture.

use std::sync::Arc;

use async_trait::async_trait;
use bp_share::Difficulty;
use bp_share_hook::{
    RejectedReason, SharedAcceptedShare, SharedAcceptedShareSink, SharedRejectedShare,
    SharedRejectedShareSink, SharedSessionPersistence,
};

use crate::hooks::{AcceptedShareSink, RejectedShareSink, SessionPersistence};
use crate::mining::submit::{RejectReason, ShareAccept};

/// SV2 → shared adapter. Cheap to clone (single `Arc`).
pub struct Sv2AcceptedShareAdapter<S: SharedAcceptedShareSink + ?Sized> {
    inner: Arc<S>,
}

impl<S: SharedAcceptedShareSink + ?Sized> Sv2AcceptedShareAdapter<S> {
    pub fn new(inner: Arc<S>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<S: SharedAcceptedShareSink + ?Sized> AcceptedShareSink for Sv2AcceptedShareAdapter<S> {
    async fn record_accepted(
        &self,
        address: &str,
        worker: &str,
        session_id_hex: &str,
        user_agent: Option<&str>,
        accept: &ShareAccept,
        hash_rate: f64,
    ) {
        self.inner
            .record_accepted(SharedAcceptedShare {
                address,
                worker,
                session_id: session_id_hex,
                user_agent,
                effective_difficulty: accept.effective_difficulty.as_f64(),
                submission_difficulty: accept.submission_difficulty.as_f64(),
                is_block_candidate: accept.is_block_candidate,
                hash_rate,
                ts_ms: bp_share_hook::now_ms(),
                // Producer-assigned downstream at the single fan-out point;
                // the per-protocol adapter has no global share sequence and
                // no mode-gate, so it leaves share_id/mode/group_id blank.
                share_id: "",
                mode: bp_common::MiningMode::Solo,
                group_id: None,
            })
            .await;
    }
}

/// SV2 → shared rejected-share adapter. Maps SV2's per-protocol reject
/// reasons into the canonical 3-variant `bp_stats::RejectedReason`.
/// SV2's extra wire-codes (`bad-extranonce-size`,
/// `invalid-channel-id`, `invalid-job-id`, `stale-share`,
/// `difficulty-too-low`) are mapped/dropped here. `BadExtranonceSize`
/// never reaches this hook (it's pre-share-validation reject — see
/// `feedback-sv2-bad-extranonce-size-hard-reject`).
pub struct Sv2RejectedShareAdapter<S: SharedRejectedShareSink + ?Sized> {
    inner: Arc<S>,
}

impl<S: SharedRejectedShareSink + ?Sized> Sv2RejectedShareAdapter<S> {
    pub fn new(inner: Arc<S>) -> Self {
        Self { inner }
    }
}

fn map_sv2_reject(reason: RejectReason) -> Option<RejectedReason> {
    match reason {
        // Retired-past-grace + unknown-job-id both bucket as JobNotFound
        // — these are "the job isn't valid for crediting" failures, the
        // shared rejected-stats only has three buckets.
        RejectReason::StaleShare | RejectReason::InvalidJobId => Some(RejectedReason::JobNotFound),
        RejectReason::DuplicateShare => Some(RejectedReason::DuplicateShare),
        RejectReason::DifficultyTooLow => Some(RejectedReason::LowDifficulty),
        // Channel-id rejects + bad-extranonce-size are protocol-validity
        // failures, not share-correctness ones — they don't count toward
        // the per-address rejected-stats counters.
        RejectReason::InvalidChannelId | RejectReason::BadExtranonceSize => None,
    }
}

#[async_trait]
impl<S: SharedRejectedShareSink + ?Sized> RejectedShareSink for Sv2RejectedShareAdapter<S> {
    async fn record_rejected(
        &self,
        address: Option<&str>,
        worker: Option<&str>,
        session_id_hex: &str,
        reason: RejectReason,
        difficulty: Difficulty,
    ) {
        if let Some(mapped) = map_sv2_reject(reason) {
            self.inner
                .record_rejected(SharedRejectedShare {
                    address,
                    worker,
                    session_id: session_id_hex,
                    reason: mapped,
                    difficulty: difficulty.as_f64(),
                    // The producer (Core composite) stamps the group id from
                    // the mode gate; the protocol adapter has none.
                    group_id: None,
                })
                .await;
        }
    }
}

/// SV2 → shared session-persistence adapter. Symmetric to SV1.
pub struct Sv2SessionPersistenceAdapter<S: SharedSessionPersistence + ?Sized> {
    inner: Arc<S>,
}

impl<S: SharedSessionPersistence + ?Sized> Sv2SessionPersistenceAdapter<S> {
    pub fn new(inner: Arc<S>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<S: SharedSessionPersistence + ?Sized> SessionPersistence for Sv2SessionPersistenceAdapter<S> {
    async fn register_session(
        &self,
        session_id_hex: &str,
        address: &str,
        worker: &str,
        _channel_id: u32,
        user_agent: Option<&str>,
    ) {
        self.inner
            .register_session(session_id_hex, address, worker, user_agent)
            .await;
    }
    async fn deregister_session(&self, session_id_hex: &str) {
        self.inner.deregister_session(session_id_hex).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_jobs_lifecycle::JobClassification;
    use std::sync::Mutex;

    type SharedTuple = (String, String, String, f64, f64, bool, Option<String>);

    struct CapturingSink {
        captured: Mutex<Vec<SharedTuple>>,
    }

    #[async_trait]
    impl SharedAcceptedShareSink for CapturingSink {
        async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
            self.captured.lock().unwrap().push((
                share.address.to_string(),
                share.worker.to_string(),
                share.session_id.to_string(),
                share.effective_difficulty,
                share.submission_difficulty,
                share.is_block_candidate,
                share.user_agent.map(str::to_string),
            ));
        }
    }

    fn synthetic_accept(eff: f64, sub: f64, candidate: bool) -> ShareAccept {
        ShareAccept {
            classification: JobClassification::Active,
            effective_difficulty: Difficulty(eff),
            submission_difficulty: Difficulty(sub),
            header: [0u8; 80],
            hash: [0u8; 32],
            is_block_candidate: candidate,
            template_id: None,
            witness_coinbase: Vec::new(),
            effective_worker_name: None,
            coinbase_tx_value_remaining: 5_000_000_000,
        }
    }

    #[tokio::test]
    async fn adapter_projects_share_accept_into_shared_view() {
        let inner = Arc::new(CapturingSink {
            captured: Mutex::new(Vec::new()),
        });
        let adapter = Sv2AcceptedShareAdapter::new(inner.clone());
        let accept = synthetic_accept(512.0, 8192.0, false);
        adapter
            .record_accepted(
                "bc1qbob",
                "rig2",
                "sess-sv2-1",
                Some("antminer/sv2"),
                &accept,
                0.0,
            )
            .await;
        let cap = inner.captured.lock().unwrap();
        assert_eq!(cap.len(), 1);
        assert_eq!(cap[0].0, "bc1qbob");
        assert_eq!(cap[0].1, "rig2");
        assert_eq!(cap[0].2, "sess-sv2-1");
        assert_eq!(cap[0].3, 512.0);
        assert_eq!(cap[0].4, 8192.0);
        assert!(!cap[0].5);
        assert_eq!(cap[0].6.as_deref(), Some("antminer/sv2"));
    }

    #[tokio::test]
    async fn adapter_propagates_block_candidate_flag() {
        let inner = Arc::new(CapturingSink {
            captured: Mutex::new(Vec::new()),
        });
        let adapter = Sv2AcceptedShareAdapter::new(inner.clone());
        let accept = synthetic_accept(100.0, 1e15, true);
        adapter
            .record_accepted("a", "w", "s", None, &accept, 0.0)
            .await;
        assert!(inner.captured.lock().unwrap()[0].5);
    }

    /// The adapter is the birth point of `ts_ms` — it must stamp the
    /// Core accept time so downstream sinks (and, later, the Core→Satellite
    /// stream) carry the real share time instead of a sink-side `now()`.
    #[tokio::test]
    async fn adapter_stamps_accept_time() {
        struct TsSink {
            ts: Mutex<Option<i64>>,
        }
        #[async_trait]
        impl SharedAcceptedShareSink for TsSink {
            async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
                *self.ts.lock().unwrap() = Some(share.ts_ms);
            }
        }

        let before = bp_share_hook::now_ms();
        let inner = Arc::new(TsSink {
            ts: Mutex::new(None),
        });
        let adapter = Sv2AcceptedShareAdapter::new(inner.clone());
        let accept = synthetic_accept(512.0, 8192.0, false);
        adapter
            .record_accepted("a", "w", "s", None, &accept, 0.0)
            .await;
        let after = bp_share_hook::now_ms();

        let ts = inner.ts.lock().unwrap().expect("share recorded");
        assert!(
            ts >= before && ts <= after,
            "ts_ms must be stamped at accept time (got {ts}, window [{before}, {after}])"
        );
    }

    #[test]
    fn map_sv2_reject_distinguishes_duplicate_from_stale() {
        assert_eq!(
            map_sv2_reject(RejectReason::DuplicateShare),
            Some(RejectedReason::DuplicateShare)
        );
        assert_eq!(
            map_sv2_reject(RejectReason::StaleShare),
            Some(RejectedReason::JobNotFound)
        );
        assert_eq!(
            map_sv2_reject(RejectReason::InvalidJobId),
            Some(RejectedReason::JobNotFound)
        );
        assert_eq!(
            map_sv2_reject(RejectReason::DifficultyTooLow),
            Some(RejectedReason::LowDifficulty)
        );
        assert_eq!(map_sv2_reject(RejectReason::InvalidChannelId), None);
        assert_eq!(map_sv2_reject(RejectReason::BadExtranonceSize), None);
    }
}
