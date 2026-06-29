// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bridges the SV1-specific [`AcceptedShareSink`](crate::hooks::AcceptedShareSink)
//! trait to the protocol-agnostic
//! [`SharedAcceptedShareSink`](bp_share_hook::SharedAcceptedShareSink).
//!
//! Engines (PPLNS, group-solo, share-stats-sink, session-persistence)
//! implement `SharedAcceptedShareSink` once and the SV1 server uses
//! this adapter to project its native [`ShareAccept`](crate::ShareAccept)
//! into the shared view. The SV2 server provides a symmetric adapter
//! in `bp-stratum-v2`. See the `bp-share-hook` crate-level docs for
//! the full picture.

use std::sync::Arc;

use async_trait::async_trait;
use bp_share_hook::{
    RejectedReason, SharedAcceptedShare, SharedAcceptedShareSink, SharedRejectedShare,
    SharedRejectedShareSink, SharedSessionPersistence,
};

use crate::hooks::{AcceptedShareSink, RejectedShareSink, SessionPersistence};
use crate::{RejectReason, ShareAccept};

/// SV1 → shared adapter. Cheap to clone (single `Arc`).
pub struct Sv1AcceptedShareAdapter<S: SharedAcceptedShareSink + ?Sized> {
    inner: Arc<S>,
}

impl<S: SharedAcceptedShareSink + ?Sized> Sv1AcceptedShareAdapter<S> {
    pub fn new(inner: Arc<S>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<S: SharedAcceptedShareSink + ?Sized> AcceptedShareSink for Sv1AcceptedShareAdapter<S> {
    async fn record_accepted(
        &self,
        address: &str,
        worker: &str,
        session_id: &str,
        user_agent: Option<&str>,
        accept: &ShareAccept,
        hash_rate: f64,
    ) {
        self.inner
            .record_accepted(SharedAcceptedShare {
                address,
                worker,
                session_id,
                user_agent,
                effective_difficulty: accept.effective_difficulty,
                submission_difficulty: accept.submission_difficulty,
                is_block_candidate: accept.is_block_candidate,
                hash_rate,
                // SV1 is one device per connection — never bundled.
                channel_count: 1,
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

/// SV1 → shared rejected-share adapter. Maps SV1's 4-variant
/// `RejectReason` (Duplicate / JobNotFound / Stale / LowDifficulty)
/// into the canonical 3-variant `bp_stats::RejectedReason`. `Stale`
/// collapses into `JobNotFound` because both share the same reject
/// accumulator bucket (see `bp_share_stats_sink::hooks::map_reject_reason`
/// for the same mapping at the sink-side — adapter centralizes it here).
pub struct Sv1RejectedShareAdapter<S: SharedRejectedShareSink + ?Sized> {
    inner: Arc<S>,
}

impl<S: SharedRejectedShareSink + ?Sized> Sv1RejectedShareAdapter<S> {
    pub fn new(inner: Arc<S>) -> Self {
        Self { inner }
    }
}

fn map_sv1_reject(reason: RejectReason) -> RejectedReason {
    match reason {
        RejectReason::JobNotFound | RejectReason::Stale => RejectedReason::JobNotFound,
        RejectReason::DuplicateShare => RejectedReason::DuplicateShare,
        RejectReason::LowDifficulty => RejectedReason::LowDifficulty,
    }
}

#[async_trait]
impl<S: SharedRejectedShareSink + ?Sized> RejectedShareSink for Sv1RejectedShareAdapter<S> {
    async fn record_rejected(
        &self,
        address: Option<&str>,
        worker: Option<&str>,
        session_id: &str,
        reason: RejectReason,
        difficulty: f64,
    ) {
        self.inner
            .record_rejected(SharedRejectedShare {
                address,
                worker,
                session_id,
                reason: map_sv1_reject(reason),
                difficulty,
                // The producer (Core composite) stamps the group id from the
                // mode gate; the protocol adapter has none.
                group_id: None,
            })
            .await;
    }
}

/// SV1 → shared session-persistence adapter. Already protocol-agnostic
/// in shape — just forwards.
pub struct Sv1SessionPersistenceAdapter<S: SharedSessionPersistence + ?Sized> {
    inner: Arc<S>,
}

impl<S: SharedSessionPersistence + ?Sized> Sv1SessionPersistenceAdapter<S> {
    pub fn new(inner: Arc<S>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<S: SharedSessionPersistence + ?Sized> SessionPersistence for Sv1SessionPersistenceAdapter<S> {
    async fn register_session(
        &self,
        session_id: &str,
        address: &str,
        worker: &str,
        user_agent: Option<&str>,
    ) {
        self.inner
            .register_session(session_id, address, worker, user_agent)
            .await;
    }
    async fn deregister_session(&self, session_id: &str) {
        self.inner.deregister_session(session_id).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct CapturingSink {
        captured: Mutex<Vec<SharedTuple>>,
    }
    type SharedTuple = (String, String, String, f64, f64, bool, Option<String>);

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
        use crate::ActiveSV1Template;
        use bp_jobs_lifecycle::JobClassification;
        use bp_mining_job::{CoinbaseTemplate, PayoutEntry};

        // Minimal MiningJob via the real builder.
        let payouts = [PayoutEntry {
            address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string(),
            percent: 100.0,
        }];
        let template = CoinbaseTemplate {
            block_height: 1,
            coinbase_value_sats: 5_000_000_000,
            witness_commitment: [0u8; 32],
        };
        let job = bp_mining_job::build_mining_job(
            bitcoin::Network::Regtest,
            &payouts,
            &template,
            "test",
            bp_mining_job::EXTRANONCE_SLOT_LEN,
        )
        .expect("build job");

        ShareAccept {
            classification: JobClassification::Active,
            effective_difficulty: eff,
            submission_difficulty: sub,
            header: [0u8; 80],
            hash: [0u8; 32],
            is_block_candidate: candidate,
            mining_job: Arc::new(job),
            template: Arc::new(ActiveSV1Template {
                template_id: 1,
                version: 0x2000_0000,
                prev_hash: [0u8; 32],
                n_bits: 0x1d00_ffff,
                header_timestamp: 0,
                network_target: [0xff; 32],
                network_difficulty: 1.0,
                coinbase_prefix: vec![],
                coinbase_tx_version: 2,
                coinbase_tx_input_sequence: 0xffff_ffff,
                coinbase_tx_value_remaining: 5_000_000_000,
                coinbase_tx_outputs: vec![],
                coinbase_tx_outputs_count: 0,
                coinbase_tx_locktime: 0,
                merkle_path: vec![],
                merkle_branch_hex: vec![],
            }),
            enonce1: [0u8; 4],
            extranonce2: [0u8; 8],
        }
    }

    #[tokio::test]
    async fn adapter_projects_share_accept_into_shared_view() {
        let inner = Arc::new(CapturingSink {
            captured: Mutex::new(Vec::new()),
        });
        let adapter = Sv1AcceptedShareAdapter::new(inner.clone());
        let accept = synthetic_accept(1024.0, 2048.0, false);
        adapter
            .record_accepted(
                "bc1qalice",
                "rig1",
                "sess0001",
                Some("bitaxe/1.0"),
                &accept,
                0.0,
            )
            .await;
        let cap = inner.captured.lock().unwrap();
        assert_eq!(cap.len(), 1);
        assert_eq!(cap[0].0, "bc1qalice");
        assert_eq!(cap[0].1, "rig1");
        assert_eq!(cap[0].2, "sess0001");
        assert_eq!(cap[0].3, 1024.0);
        assert_eq!(cap[0].4, 2048.0);
        assert!(!cap[0].5);
        assert_eq!(cap[0].6.as_deref(), Some("bitaxe/1.0"));
    }

    #[tokio::test]
    async fn adapter_propagates_block_candidate_flag() {
        let inner = Arc::new(CapturingSink {
            captured: Mutex::new(Vec::new()),
        });
        let adapter = Sv1AcceptedShareAdapter::new(inner.clone());
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
        let adapter = Sv1AcceptedShareAdapter::new(inner.clone());
        let accept = synthetic_accept(1024.0, 2048.0, false);
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
}
