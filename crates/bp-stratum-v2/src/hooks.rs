// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hook boundaries of the SV2 mining server, shaped like `bp_stratum_v1::hooks`
//! with a [`NoOpHooks`] default and a [`test_support::RecordingHooks`] recorder.
//! Shares, sessions and device status go to the `bp_share_hook` traits shared
//! with SV1; only the SV2-specific hooks live here.

use std::sync::Arc;

use bp_common::{AddressId, StreamKind};
use bp_mining_job::{PayoutEntry, ResolvedPayouts};
use bp_share_hook::{
    DeviceStatusSink, NoOpSink, SharedAcceptedShareSink, SharedRejectedShareSink,
    SharedSessionPersistence,
};

use crate::mining::submit::ShareAccept;

// ── PayoutResolver ──────────────────────────────────────────────────

/// Resolve a miner address to a coinbase payout list per template broadcast,
/// feeding [`bp_mining_job::build_mining_job_from_tdp`]. Production evaluates
/// the address's mode; [`NoOpHooks`] pays 100% to the miner.
#[async_trait::async_trait]
pub trait PayoutResolver: Send + Sync {
    /// Exact output sats per entry, placed verbatim, plus the fingerprint of
    /// the distribution they came from (zeroed = books without a snapshot).
    async fn resolve_payouts(&self, miner_address: &AddressId, reward_sats: u64)
        -> ResolvedPayouts;

    /// Which TDP template stream this address mines on, resolved once at
    /// OpenChannel from the in-memory mode cache.
    fn resolve_stream(&self, _miner_address: &AddressId) -> StreamKind {
        StreamKind::Pplns
    }

    /// [`Self::resolve_stream`], with `None` for "not known yet": the mode cache
    /// learns an address from its mining session, which the JDP allocate path
    /// normally precedes.
    fn resolve_stream_known(&self, miner_address: &AddressId) -> Option<StreamKind> {
        Some(self.resolve_stream(miner_address))
    }
}

// ── BlockSubmissionSink ─────────────────────────────────────────────

/// Receives a block-candidate share. A JDC's PushSolution may reach
/// bitcoin-core in parallel via the JDP server; `submitblock` is idempotent.
#[async_trait::async_trait]
pub trait BlockSubmissionSink: Send + Sync {
    // `stream` routes the solution to the TDP handle the job was built on.
    async fn submit_block(
        &self,
        accept: &ShareAccept,
        address: &str,
        worker: &str,
        session_id_hex: &str,
        stream: StreamKind,
    );
}

// ── CustomExtranonceSource ──────────────────────────────────────────

/// Customer-pinned 4-byte extranonce prefix for `(address, worker)`, replacing
/// the pool-allocated one at channel open. Sync on purpose: it reads an
/// in-memory cache, never a per-lookup DB round-trip.
pub trait CustomExtranonceSource: Send + Sync {
    fn lookup(&self, address: &str, worker: &str) -> Option<[u8; 4]>;
}

// ── ServerHooks aggregator ──────────────────────────────────────────

/// Composite hook handle for the SV2 mining server, cloned into every
/// per-connection task.
#[derive(Clone)]
pub struct MiningServerHooks {
    pub payout_resolver: Arc<dyn PayoutResolver>,
    pub block_sink: Arc<dyn BlockSubmissionSink>,
    pub accepted_sink: Arc<dyn SharedAcceptedShareSink>,
    pub rejected_sink: Arc<dyn SharedRejectedShareSink>,
    pub session_persistence: Arc<dyn SharedSessionPersistence>,
    pub device_status_sink: Arc<dyn DeviceStatusSink>,
    pub custom_extranonce: Arc<dyn CustomExtranonceSource>,
}

impl MiningServerHooks {
    /// Every hook set to [`NoOpHooks`].
    pub fn no_op() -> Self {
        let no_op: Arc<NoOpHooks> = Arc::new(NoOpHooks);
        let shared: Arc<NoOpSink> = Arc::new(NoOpSink);
        Self {
            payout_resolver: no_op.clone(),
            block_sink: no_op.clone(),
            accepted_sink: shared.clone(),
            rejected_sink: shared.clone(),
            session_persistence: shared.clone(),
            device_status_sink: shared,
            custom_extranonce: no_op,
        }
    }
}

// ── NoOpHooks ───────────────────────────────────────────────────────

/// Ignores every event; pays 100% to the miner.
pub struct NoOpHooks;

#[async_trait::async_trait]
impl PayoutResolver for NoOpHooks {
    async fn resolve_payouts(
        &self,
        miner_address: &AddressId,
        reward_sats: u64,
    ) -> ResolvedPayouts {
        ResolvedPayouts::unsnapshotted(vec![PayoutEntry {
            address: miner_address.as_str().to_string(),
            sats: reward_sats,
        }])
    }
}

#[async_trait::async_trait]
impl BlockSubmissionSink for NoOpHooks {
    async fn submit_block(&self, _: &ShareAccept, _: &str, _: &str, _: &str, _: StreamKind) {}
}

impl CustomExtranonceSource for NoOpHooks {
    fn lookup(&self, _: &str, _: &str) -> Option<[u8; 4]> {
        None
    }
}

// ── test_support ────────────────────────────────────────────────────

/// Recording hooks for tests; public so integration tests can use them.
pub mod test_support {
    use super::*;
    use bp_share_hook::{RejectedReason, SharedAcceptedShare, SharedRejectedShare};
    use std::sync::Mutex;

    #[derive(Clone, Debug, PartialEq)]
    pub struct AcceptedRecord {
        pub address: String,
        pub worker: String,
        pub session_id_hex: String,
        pub effective_difficulty: f64,
        pub is_block_candidate: bool,
        pub channel_count: u32,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct RejectedRecord {
        pub address: Option<String>,
        pub worker: Option<String>,
        pub session_id_hex: String,
        pub reason: RejectedReason,
        pub difficulty: f64,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct RegisteredRecord {
        pub session_id_hex: String,
        pub address: String,
        pub worker: String,
    }

    /// Records every hook call; clones share the same recordings.
    #[derive(Clone, Default)]
    pub struct RecordingHooks {
        pub accepted: Arc<Mutex<Vec<AcceptedRecord>>>,
        pub rejected: Arc<Mutex<Vec<RejectedRecord>>>,
        pub blocks_submitted: Arc<Mutex<Vec<AcceptedRecord>>>,
        pub registered: Arc<Mutex<Vec<RegisteredRecord>>>,
        pub deregistered: Arc<Mutex<Vec<String>>>,
        /// (address, worker, online) per `on_device_event`.
        pub device_events: Arc<Mutex<Vec<(String, String, bool)>>>,
        /// Replaces the default 100%-to-the-miner payout list; see
        /// [`Self::with_payouts`].
        pub payouts_override: Arc<Mutex<Option<Vec<PayoutEntry>>>>,
    }

    impl RecordingHooks {
        pub fn new() -> Self {
            Self::default()
        }

        /// Override the payout list returned by [`PayoutResolver`], e.g. for
        /// a multi-output distribution.
        pub fn with_payouts(self, payouts: Vec<PayoutEntry>) -> Self {
            *self.payouts_override.lock().expect("poisoned") = Some(payouts);
            self
        }

        /// Wrap into a [`MiningServerHooks`].
        pub fn into_server_hooks(self) -> MiningServerHooks {
            let arc = Arc::new(self);
            MiningServerHooks {
                payout_resolver: arc.clone(),
                block_sink: arc.clone(),
                accepted_sink: arc.clone(),
                rejected_sink: arc.clone(),
                session_persistence: arc.clone(),
                device_status_sink: arc,
                custom_extranonce: Arc::new(NoOpHooks),
            }
        }
    }

    #[async_trait::async_trait]
    impl PayoutResolver for RecordingHooks {
        async fn resolve_payouts(
            &self,
            miner_address: &AddressId,
            reward_sats: u64,
        ) -> ResolvedPayouts {
            if let Some(ref custom) = *self.payouts_override.lock().expect("poisoned") {
                return ResolvedPayouts::unsnapshotted(custom.clone());
            }
            ResolvedPayouts::unsnapshotted(vec![PayoutEntry {
                address: miner_address.as_str().to_string(),
                sats: reward_sats,
            }])
        }
    }

    #[async_trait::async_trait]
    impl BlockSubmissionSink for RecordingHooks {
        async fn submit_block(
            &self,
            accept: &ShareAccept,
            address: &str,
            worker: &str,
            session_id_hex: &str,
            _: StreamKind,
        ) {
            self.blocks_submitted
                .lock()
                .expect("poisoned")
                .push(AcceptedRecord {
                    address: address.to_string(),
                    worker: worker.to_string(),
                    session_id_hex: session_id_hex.to_string(),
                    effective_difficulty: accept.effective_difficulty.as_f64(),
                    is_block_candidate: accept.is_block_candidate,
                    // submit_block carries no channel count; the block
                    // record only asserts the candidate path, not bundling.
                    channel_count: 1,
                });
        }
    }

    #[async_trait::async_trait]
    impl SharedAcceptedShareSink for RecordingHooks {
        async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
            self.accepted
                .lock()
                .expect("poisoned")
                .push(AcceptedRecord {
                    address: share.address.to_string(),
                    worker: share.worker.to_string(),
                    session_id_hex: share.session_id.to_string(),
                    effective_difficulty: share.effective_difficulty,
                    is_block_candidate: share.is_block_candidate,
                    channel_count: share.channel_count,
                });
        }
    }

    #[async_trait::async_trait]
    impl SharedRejectedShareSink for RecordingHooks {
        async fn record_rejected(&self, share: SharedRejectedShare<'_>) {
            self.rejected
                .lock()
                .expect("poisoned")
                .push(RejectedRecord {
                    address: share.address.map(|a| a.to_string()),
                    worker: share.worker.map(|w| w.to_string()),
                    session_id_hex: share.session_id.to_string(),
                    reason: share.reason,
                    difficulty: share.difficulty,
                });
        }
    }

    #[async_trait::async_trait]
    impl SharedSessionPersistence for RecordingHooks {
        async fn register_session(
            &self,
            session_id_hex: &str,
            address: &str,
            worker: &str,
            _user_agent: Option<&str>,
        ) {
            self.registered
                .lock()
                .expect("poisoned")
                .push(RegisteredRecord {
                    session_id_hex: session_id_hex.to_string(),
                    address: address.to_string(),
                    worker: worker.to_string(),
                });
        }

        async fn deregister_session(&self, session_id_hex: &str) {
            self.deregistered
                .lock()
                .expect("poisoned")
                .push(session_id_hex.to_string());
        }
    }

    #[async_trait::async_trait]
    impl DeviceStatusSink for RecordingHooks {
        async fn on_device_event(
            &self,
            address: &str,
            worker: &str,
            _session_id: &str,
            _user_agent: Option<&str>,
            online: bool,
        ) {
            self.device_events.lock().expect("poisoned").push((
                address.to_string(),
                worker.to_string(),
                online,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::RecordingHooks;
    use super::*;
    use crate::mining::submit::RejectReason;
    use bp_jobs_lifecycle::JobClassification;
    use bp_share::Difficulty;

    fn make_addr() -> AddressId {
        AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string()).unwrap()
    }

    fn make_accept() -> ShareAccept {
        ShareAccept {
            payouts_fingerprint: [0u8; 32],
            classification: JobClassification::Active,
            effective_difficulty: Difficulty(1024.0),
            submission_difficulty: Difficulty(2048.0),
            header: [0u8; 80],
            hash: [0u8; 32],
            is_block_candidate: false,
            template_id: None,
            jdp_claims_the_block: false,
            witness_coinbase: Vec::new(),
            effective_worker_name: None,
            coinbase_tx_value_remaining: 5_000_000_000,
        }
    }

    #[tokio::test]
    async fn no_op_hooks_default_payouts_to_self() {
        let hooks = NoOpHooks;
        let payouts = hooks.resolve_payouts(&make_addr(), 5_000_000_000).await;
        assert_eq!(payouts.entries.len(), 1);
        assert_eq!(payouts.entries[0].sats, 5_000_000_000);
        assert_eq!(payouts.payouts_fingerprint, [0u8; 32]);
    }

    #[tokio::test]
    async fn recording_hooks_capture_accepted_share() {
        let hooks = RecordingHooks::new();
        let server_hooks = hooks.clone().into_server_hooks();
        server_hooks
            .accepted_sink
            .record_accepted(crate::shared_adapter::shared_accepted(
                "addr1",
                "wrk",
                "sess-1",
                None,
                &make_accept(),
                0.0,
                1,
            ))
            .await;
        let records = hooks.accepted.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].address, "addr1");
        assert!((records[0].effective_difficulty - 1024.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn recording_hooks_capture_rejected_share() {
        let hooks = RecordingHooks::new();
        let server_hooks = hooks.clone().into_server_hooks();
        let share = crate::shared_adapter::shared_rejected(
            Some("addr1"),
            Some("worker1"),
            "sess-1",
            RejectReason::StaleShare,
            Difficulty(1024.0),
        )
        .expect("a stale share counts toward the reject stats");
        server_hooks.rejected_sink.record_rejected(share).await;
        let records = hooks.rejected.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].reason, bp_share_hook::RejectedReason::Stale);
    }

    #[tokio::test]
    async fn recording_hooks_capture_block_candidate_separately() {
        let hooks = RecordingHooks::new();
        let server_hooks = hooks.clone().into_server_hooks();
        let mut accept = make_accept();
        accept.is_block_candidate = true;
        server_hooks
            .block_sink
            .submit_block(&accept, "addr1", "wrk", "sess-1", StreamKind::Pplns)
            .await;
        let blocks = hooks.blocks_submitted.lock().unwrap();
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].is_block_candidate);
        // Each sink records only its own calls; the caller decides which to
        // drive.
        assert!(hooks.accepted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn recording_hooks_capture_session_register_and_deregister() {
        let hooks = RecordingHooks::new();
        let server_hooks = hooks.clone().into_server_hooks();
        server_hooks
            .session_persistence
            .register_session("sess-1", "addr1", "wrk", Some("ua"))
            .await;
        server_hooks
            .session_persistence
            .deregister_session("sess-1")
            .await;
        assert_eq!(hooks.registered.lock().unwrap().len(), 1);
        assert_eq!(hooks.deregistered.lock().unwrap()[0], "sess-1");
    }

    #[tokio::test]
    async fn recording_hooks_payout_override_replaces_default() {
        let hooks = RecordingHooks::new().with_payouts(vec![
            PayoutEntry {
                address: "p1".to_string(),
                sats: 1_500_000_000,
            },
            PayoutEntry {
                address: "p2".to_string(),
                sats: 3_500_000_000,
            },
        ]);
        let payouts = hooks.resolve_payouts(&make_addr(), 5_000_000_000).await;
        assert_eq!(payouts.entries.len(), 2);
        assert_eq!(payouts.entries[0].address, "p1");
    }
}
