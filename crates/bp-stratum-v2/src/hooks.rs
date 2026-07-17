// SPDX-License-Identifier: AGPL-3.0-or-later

//! Async-trait boundaries for production wiring.
//!
//! Mirrors the design of [`bp_stratum_v1::hooks`] (`Arc<dyn Trait>`-
//! dispatched aggregator + a [`NoOpHooks`] default + a
//! [`test_support::RecordingHooks`] tester) and extends it for the
//! SV2-specific extras:
//!
//! - **`PayoutResolver`** — async hook the per-connection task calls
//!   on every template broadcast to resolve the connection's miner
//!   address into a payout list. Output is fed to
//!   [`bp_mining_job::build_mining_job_from_tdp`] inside
//!   `server.rs::run_mining_connection`, then the resulting
//!   `MiningJob` flows into [`crate::mining::client::apply_template_broadcast`].
//! - **`BlockSubmissionSink`** — called on `ShareAccepted` with
//!   `is_block_candidate = true`. Hands the assembled-block bytes off
//!   to `bp_template_distribution::TdpHandle::submit_solution` in
//!   production wiring; tests use [`NoOpHooks`].
//! - **`AcceptedShareSink`** / **`RejectedShareSink`** — share fan-out
//!   for PPLNS / group-solo accumulators + reject counters.
//! - **`SessionPersistence`** — register / deregister the per-channel
//!   session in the live-clients registry on `ChannelOpened` /
//!   connection close.
//!
//! ## Why 5 traits, not 8
//!
//! The earlier skeleton listed 8 hooks (block submission, accepted /
//! rejected sinks, session persistence, block-found notification,
//! mempool validator, miner lookup, coinbase distributor). The 5
//! above cover the **mining-server** per-connection task. The
//! remaining 3 belong to a different surface:
//!
//! - `BlockFoundNotificationSink` lives in `bp_notifications`
//!   (Telegram / ntfy / push). It's downstream of the share-accept
//!   hook (the service layer composes both).
//! - `MempoolValidator` belongs to the JDP-server hook surface
//!   (`jdp_server.rs`) — it's only ever consulted on JDP frames,
//!   never on mining frames.
//! - `MinerLookup` is the bridge between JDP IP and mining
//!   miner-address; that's caller-supplied state inside
//!   `MiningServerContext`, not an async hook (it's a sync registry
//!   lookup, see [`crate::bridge::JdpDeclaredJobRegistry`]).
//!
//! Tracking those 3 under the same module would be premature — we'll
//! pull them in when their callers land.

use std::sync::Arc;

use bp_common::{AddressId, StreamKind};
use bp_mining_job::PayoutEntry;
use bp_share::Difficulty;

use crate::mining::submit::{RejectReason, ShareAccept};

// ── PayoutResolver ──────────────────────────────────────────────────

/// Resolve a miner address to a coinbase payout list. Called per
/// template broadcast inside the per-connection task; the returned
/// list is fed to [`bp_mining_job::build_mining_job_from_tdp`] to
/// produce the `MiningJob` consumed by
/// [`crate::mining::client::apply_template_broadcast`].
///
/// Production impl runs the service-layer mode-resolver
/// ([`bp_mining_mode::ModeResolver`]) + builds the per-mode
/// distribution ([`bp_pplns::build_coinbase_distribution`] /
/// [`bp_group_solo::build_group_solo_distribution`] / single-output
/// solo). Tests use [`NoOpHooks`] returning a single 100%-to-self
/// entry.
#[async_trait::async_trait]
pub trait PayoutResolver: Send + Sync {
    /// Resolve the payout list for a given connection's locked
    /// address + reward (in sats). Each entry carries its exact output
    /// sats (summing to ≤ reward); `bp_mining_job::build_mining_job_from_tdp`
    /// places them verbatim and sweeps any shortfall onto `outs[0]`.
    async fn resolve_payouts(
        &self,
        miner_address: &AddressId,
        reward_sats: u64,
    ) -> Vec<PayoutEntry>;

    /// Which TDP template stream a connection with this address mines on —
    /// resolved once at OpenChannel and fixed. Default `Default`
    /// (single-stream); the production resolver overrides it to route Solo
    /// addresses to the Solo stream. Sync (in-memory mode cache).
    fn resolve_stream(&self, _miner_address: &AddressId) -> StreamKind {
        StreamKind::Pplns
    }
}

// ── BlockSubmissionSink ─────────────────────────────────────────────

/// Receives a block-candidate share (`is_block_candidate = true` on
/// the accepted share). Production wiring forwards to
/// `bp_template_distribution::TdpHandle::submit_solution`; the JDC
/// path's PushSolution also reaches bitcoin-core in parallel via the
/// JDP-server's own block-submit hook. `submitblock` is idempotent
/// so the double-submit is safe.
#[async_trait::async_trait]
pub trait BlockSubmissionSink: Send + Sync {
    // `stream`: the template stream this job was built on — routes the
    // solution to the matching TDP handle. See [`bp_common::StreamKind`].
    async fn submit_block(
        &self,
        accept: &ShareAccept,
        address: &str,
        worker: &str,
        session_id_hex: &str,
        stream: StreamKind,
    );
}

// ── AcceptedShareSink ───────────────────────────────────────────────

/// Records an accepted share for PPLNS / group-solo / per-mode
/// accumulators + the share-totals cache.
#[async_trait::async_trait]
pub trait AcceptedShareSink: Send + Sync {
    /// `hash_rate` is the session-wide H/s snapshot the vardiff
    /// engine reports right after consuming this share — written to
    /// client_entity.hashRate by the persistence sink. `user_agent` is
    /// the vendor-derived firmware string (same source as the
    /// register / device-status path), used to stamp the all-time
    /// best-difficulty row. `channel_count` is how many mining channels
    /// the connection holds (`1` for a direct miner, `> 1` when a rental
    /// proxy bundles several same-rig devices onto one connection) —
    /// persisted to client_entity.channelCount so the UI can flag the
    /// session's difficulty as aggregated.
    #[allow(clippy::too_many_arguments)]
    async fn record_accepted(
        &self,
        address: &str,
        worker: &str,
        session_id_hex: &str,
        user_agent: Option<&str>,
        accept: &ShareAccept,
        hash_rate: f64,
        channel_count: u32,
    );
}

// ── RejectedShareSink ───────────────────────────────────────────────

/// Records a rejected share. `reason` is the typed reject; `wire_code`
/// is its serialized form (`stale-share`, `invalid-job-id`,
/// `difficulty-too-low`, `bad-extranonce-size`, ...).
#[async_trait::async_trait]
pub trait RejectedShareSink: Send + Sync {
    async fn record_rejected(
        &self,
        address: Option<&str>,
        worker: Option<&str>,
        session_id_hex: &str,
        reason: RejectReason,
        difficulty: Difficulty,
    );
}

// ── SessionPersistence ──────────────────────────────────────────────

/// Per-channel session registration. Production wiring updates the
/// `client` DB table + the live-clients in-process registry; on
/// disconnect it fires the device-offline notification.
#[async_trait::async_trait]
pub trait SessionPersistence: Send + Sync {
    async fn register_session(
        &self,
        session_id_hex: &str,
        address: &str,
        worker: &str,
        channel_id: u32,
        user_agent: Option<&str>,
    );

    async fn deregister_session(&self, session_id_hex: &str);
}

// ── DeviceStatusSink ────────────────────────────────────────────────

/// Fired on per-channel ChannelOpened (online) + ChannelClosed (offline)
/// transitions. Production wiring forwards to
/// `bp_notifications::dispatcher::NotificationDispatcher::notify_device_status`
/// so subscribers receive per-worker connect / disconnect pushes.
#[async_trait::async_trait]
pub trait DeviceStatusSink: Send + Sync {
    async fn on_device_event(
        &self,
        address: &str,
        worker: &str,
        session_id_hex: &str,
        user_agent: Option<&str>,
        is_online: bool,
    );
}

// ── CustomExtranonceSource ──────────────────────────────────────────

/// Look up a customer-set extranonce prefix for a `(address, worker)`.
///
/// Backs the custom-extranonce override: an address that proved control of
/// its key (via the ownership signature) may pin its own 4-byte prefix per
/// worker through the API. The stratum server consults this at channel-open
/// to swap the pool-allocated prefix for the customer's chosen one.
///
/// Sync on purpose — the production impl reads an in-memory cache the core
/// refreshes off PG periodically (never a per-lookup DB round-trip), mirroring
/// how the mode-gate lookup is a plain map hit. Returns `None` for the
/// overwhelming majority of workers, which have no override.
pub trait CustomExtranonceSource: Send + Sync {
    fn lookup(&self, address: &str, worker: &str) -> Option<[u8; 4]>;
}

// ── ServerHooks aggregator ──────────────────────────────────────────

/// Composite hook handle for the SV2 mining server. Cheap to clone
/// (each field is an `Arc<dyn Trait>`). Production wiring constructs
/// once at startup with concrete impls; the server clones it into
/// every per-connection task.
#[derive(Clone)]
pub struct MiningServerHooks {
    pub payout_resolver: Arc<dyn PayoutResolver>,
    pub block_sink: Arc<dyn BlockSubmissionSink>,
    pub accepted_sink: Arc<dyn AcceptedShareSink>,
    pub rejected_sink: Arc<dyn RejectedShareSink>,
    pub session_persistence: Arc<dyn SessionPersistence>,
    pub device_status_sink: Arc<dyn DeviceStatusSink>,
    /// Customer extranonce overrides. [`NoOpHooks`] returns `None` for every
    /// worker, so a deployment without the feature behaves exactly as before.
    pub custom_extranonce: Arc<dyn CustomExtranonceSource>,
}

impl MiningServerHooks {
    /// Build with every hook set to [`NoOpHooks`]. Convenience for
    /// regtest / smoke-test wiring; production fills each slot with
    /// its concrete impl.
    pub fn no_op() -> Self {
        let no_op: Arc<NoOpHooks> = Arc::new(NoOpHooks);
        Self {
            payout_resolver: no_op.clone(),
            block_sink: no_op.clone(),
            accepted_sink: no_op.clone(),
            rejected_sink: no_op.clone(),
            session_persistence: no_op.clone(),
            device_status_sink: no_op.clone(),
            custom_extranonce: no_op,
        }
    }
}

// ── NoOpHooks ───────────────────────────────────────────────────────

/// Drop-in [`MiningServerHooks`]-compatible impl that silently
/// ignores every event. Used by tests that don't care about hook
/// fan-out and by the regtest harness during the wire-roundtrip
/// portion of `tests/regtest_*.rs`.
pub struct NoOpHooks;

#[async_trait::async_trait]
impl PayoutResolver for NoOpHooks {
    async fn resolve_payouts(
        &self,
        miner_address: &AddressId,
        reward_sats: u64,
    ) -> Vec<PayoutEntry> {
        vec![PayoutEntry {
            address: miner_address.as_str().to_string(),
            sats: reward_sats,
        }]
    }
}

#[async_trait::async_trait]
impl BlockSubmissionSink for NoOpHooks {
    async fn submit_block(&self, _: &ShareAccept, _: &str, _: &str, _: &str, _: StreamKind) {}
}

#[async_trait::async_trait]
impl AcceptedShareSink for NoOpHooks {
    async fn record_accepted(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: &ShareAccept,
        _: f64,
        _: u32,
    ) {
    }
}

#[async_trait::async_trait]
impl RejectedShareSink for NoOpHooks {
    async fn record_rejected(
        &self,
        _: Option<&str>,
        _: Option<&str>,
        _: &str,
        _: RejectReason,
        _: Difficulty,
    ) {
    }
}

#[async_trait::async_trait]
impl DeviceStatusSink for NoOpHooks {
    async fn on_device_event(&self, _: &str, _: &str, _: &str, _: Option<&str>, _: bool) {}
}

#[async_trait::async_trait]
impl SessionPersistence for NoOpHooks {
    async fn register_session(&self, _: &str, _: &str, _: &str, _: u32, _: Option<&str>) {}
    async fn deregister_session(&self, _: &str) {}
}

impl CustomExtranonceSource for NoOpHooks {
    fn lookup(&self, _: &str, _: &str) -> Option<[u8; 4]> {
        None
    }
}

// ── test_support ────────────────────────────────────────────────────

/// Recording hooks for unit tests. Captures every call into thread-
/// safe `Mutex<Vec<...>>` buffers so test assertions can inspect
/// what the server fanned out.
///
/// Public under `pub mod test_support` so integration tests outside
/// this crate can use it, mirroring the SV1 pattern.
pub mod test_support {
    use super::*;
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
        pub reason: RejectReason,
        pub difficulty: f64,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct RegisteredRecord {
        pub session_id_hex: String,
        pub address: String,
        pub worker: String,
        pub channel_id: u32,
    }

    /// Records every hook call. Cheap to clone (`Arc<...>` internal
    /// buffers — multiple clones share the same recordings).
    #[derive(Clone, Default)]
    pub struct RecordingHooks {
        pub accepted: Arc<Mutex<Vec<AcceptedRecord>>>,
        pub rejected: Arc<Mutex<Vec<RejectedRecord>>>,
        pub blocks_submitted: Arc<Mutex<Vec<AcceptedRecord>>>,
        pub registered: Arc<Mutex<Vec<RegisteredRecord>>>,
        pub deregistered: Arc<Mutex<Vec<String>>>,
        /// (address, worker, online) per `on_device_event`.
        pub device_events: Arc<Mutex<Vec<(String, String, bool)>>>,
        /// Payout list returned by [`PayoutResolver::resolve_payouts`]
        /// — default is a 100%-to-the-given-address entry; tests can
        /// override via [`Self::with_payouts`].
        pub payouts_override: Arc<Mutex<Option<Vec<PayoutEntry>>>>,
    }

    impl RecordingHooks {
        pub fn new() -> Self {
            Self::default()
        }

        /// Override the payout list returned by [`PayoutResolver`].
        /// Useful for tests that want to exercise specific
        /// distribution shapes (e.g. PPLNS multi-output).
        pub fn with_payouts(self, payouts: Vec<PayoutEntry>) -> Self {
            *self.payouts_override.lock().expect("poisoned") = Some(payouts);
            self
        }

        /// Wrap into a [`MiningServerHooks`] for plugging into
        /// `StratumV2MiningServer::spawn`.
        pub fn into_server_hooks(self) -> MiningServerHooks {
            let arc = Arc::new(self);
            MiningServerHooks {
                payout_resolver: arc.clone(),
                block_sink: arc.clone(),
                accepted_sink: arc.clone(),
                rejected_sink: arc.clone(),
                session_persistence: arc.clone(),
                device_status_sink: arc,
                // RecordingHooks doesn't record EN lookups — no override in tests.
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
        ) -> Vec<PayoutEntry> {
            if let Some(ref custom) = *self.payouts_override.lock().expect("poisoned") {
                return custom.clone();
            }
            vec![PayoutEntry {
                address: miner_address.as_str().to_string(),
                sats: reward_sats,
            }]
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
    impl AcceptedShareSink for RecordingHooks {
        async fn record_accepted(
            &self,
            address: &str,
            worker: &str,
            session_id_hex: &str,
            _user_agent: Option<&str>,
            accept: &ShareAccept,
            _hash_rate: f64,
            channel_count: u32,
        ) {
            self.accepted
                .lock()
                .expect("poisoned")
                .push(AcceptedRecord {
                    address: address.to_string(),
                    worker: worker.to_string(),
                    session_id_hex: session_id_hex.to_string(),
                    effective_difficulty: accept.effective_difficulty.as_f64(),
                    is_block_candidate: accept.is_block_candidate,
                    channel_count,
                });
        }
    }

    #[async_trait::async_trait]
    impl RejectedShareSink for RecordingHooks {
        async fn record_rejected(
            &self,
            address: Option<&str>,
            worker: Option<&str>,
            session_id_hex: &str,
            reason: RejectReason,
            difficulty: Difficulty,
        ) {
            self.rejected
                .lock()
                .expect("poisoned")
                .push(RejectedRecord {
                    address: address.map(|a| a.to_string()),
                    worker: worker.map(|w| w.to_string()),
                    session_id_hex: session_id_hex.to_string(),
                    reason,
                    difficulty: difficulty.as_f64(),
                });
        }
    }

    #[async_trait::async_trait]
    impl SessionPersistence for RecordingHooks {
        async fn register_session(
            &self,
            session_id_hex: &str,
            address: &str,
            worker: &str,
            channel_id: u32,
            _user_agent: Option<&str>,
        ) {
            self.registered
                .lock()
                .expect("poisoned")
                .push(RegisteredRecord {
                    session_id_hex: session_id_hex.to_string(),
                    address: address.to_string(),
                    worker: worker.to_string(),
                    channel_id,
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

    fn make_addr() -> AddressId {
        AddressId::new("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string()).unwrap()
    }

    fn make_accept() -> ShareAccept {
        ShareAccept {
            classification: JobClassification::Active,
            effective_difficulty: Difficulty(1024.0),
            submission_difficulty: Difficulty(2048.0),
            header: [0u8; 80],
            hash: [0u8; 32],
            is_block_candidate: false,
            template_id: None,
            witness_coinbase: Vec::new(),
            effective_worker_name: None,
            coinbase_tx_value_remaining: 5_000_000_000,
        }
    }

    #[tokio::test]
    async fn no_op_hooks_default_payouts_to_self() {
        let hooks = NoOpHooks;
        let payouts = hooks.resolve_payouts(&make_addr(), 5_000_000_000).await;
        assert_eq!(payouts.len(), 1);
        assert_eq!(payouts[0].sats, 5_000_000_000);
    }

    #[tokio::test]
    async fn recording_hooks_capture_accepted_share() {
        let hooks = RecordingHooks::new();
        let server_hooks = hooks.clone().into_server_hooks();
        server_hooks
            .accepted_sink
            .record_accepted("addr1", "wrk", "sess-1", None, &make_accept(), 0.0, 1)
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
        server_hooks
            .rejected_sink
            .record_rejected(
                Some("addr1"),
                Some("worker1"),
                "sess-1",
                RejectReason::StaleShare,
                Difficulty(1024.0),
            )
            .await;
        let records = hooks.rejected.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].reason, RejectReason::StaleShare);
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
        // Not recorded in `accepted` because the fan-out chooses one
        // sink per side-effect — caller decides which to drive on
        // `is_block_candidate`.
        assert!(hooks.accepted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn recording_hooks_capture_session_register_and_deregister() {
        let hooks = RecordingHooks::new();
        let server_hooks = hooks.clone().into_server_hooks();
        server_hooks
            .session_persistence
            .register_session("sess-1", "addr1", "wrk", 7, Some("ua"))
            .await;
        server_hooks
            .session_persistence
            .deregister_session("sess-1")
            .await;
        assert_eq!(hooks.registered.lock().unwrap().len(), 1);
        assert_eq!(hooks.registered.lock().unwrap()[0].channel_id, 7);
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
        assert_eq!(payouts.len(), 2);
        assert_eq!(payouts[0].address, "p1");
    }
}
