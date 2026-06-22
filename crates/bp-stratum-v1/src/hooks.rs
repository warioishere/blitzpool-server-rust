// SPDX-License-Identifier: AGPL-3.0-or-later

//! I/O side-effect trait boundaries for the SV1 server.
//!
//! The `client.rs` pure handlers produce [`crate::client::SessionEvent`]s
//! that the server task translates into hook calls. The hooks themselves
//! are trait-objects so the production wiring can plug in:
//!
//! - **Block submission**: a `TdpHandle::submit_solution` adapter for
//!   the SV1-as-translator topology (TDP-direct, no JDP for SV1).
//! - **Accepted / rejected share stats**: `bp_stats` accumulators
//!   (`PoolShares`, `PoolModeHashrate`, `PoolRejected`,
//!   `ClientStatistics`, `ClientRejected`, `ShareTotals`).
//! - **Session persistence**: `bp-db` writer for the `client` row, plus
//!   the device-online/offline notification path.
//!
//! Trait-object dispatch is deliberate: each hook fires once per
//! event (subscribe / authorize / share / block-change) — single-digit
//! per-second on a production pool, sub-microsecond vtable cost. The
//! production wiring is genuinely heterogeneous (DB impls, notification
//! adapters, stat sinks), so per-trait `dyn` is the natural fit. See
//! `feedback-design-principles`: *"dyn nur wenn echte Heterogenität
//! nötig"*.
//!
//! All four traits have a [`NoOpHooks`] default impl exposed via
//! [`ServerHooks::no_op`] so the crate is usable end-to-end without
//! full production wiring. Tests inject recording impls to assert
//! the fan-out triggers correctly.

use std::sync::Arc;

use async_trait::async_trait;
use bp_mining_job::PayoutEntry;

use bp_common::StreamKind;

use crate::submit::{RejectReason, ShareAccept};

// ── PayoutResolver ───────────────────────────────────────────────────

/// Resolve the per-template coinbase payout list for an authorized
/// miner. Called by the IO layer at every template-broadcast +
/// post-authorize moment so the freshly-built `MiningJob` carries
/// the correct mode-aware distribution (Solo / PPLNS / Group-Solo).
///
/// Production wiring routes through the mining-mode gate to dispatch:
/// - **Solo**: single 100%-to-miner entry (or split with `dev_fee_*`
///   when the server config has one).
/// - **PPLNS**: window-distribution from `PplnsEngine::build_distribution`.
/// - **Group-Solo**: round-distribution from
///   `GroupSoloEngine::build_distribution(group_id, reward, finder_address)`.
///
/// `reward_sats` is the block-reward portion available to the
/// coinbase (= TDP template's `coinbase_tx_value_remaining`).
///
/// The default impl on [`NoOpHooks`] returns a single 100%-to-miner
/// entry — matches the pre-7.4d behaviour where every mode emitted
/// solo-output coinbase regardless of port (share crediting was
/// correct via the accept-hook fan-out, only the on-chain payout
/// shape was wrong).
#[async_trait]
pub trait PayoutResolver: Send + Sync {
    async fn resolve_payouts(&self, miner_address: &str, reward_sats: u64) -> Vec<PayoutEntry>;

    /// Which TDP template stream a connection with this address mines on —
    /// resolved once at `mining.authorize` and fixed for the session. The
    /// default is `Default` (single-stream behaviour); the production resolver
    /// overrides it to route Solo addresses to the Solo stream. Sync because
    /// the mode lookup is an in-memory cache hit.
    fn resolve_stream(&self, _miner_address: &str) -> StreamKind {
        StreamKind::Pplns
    }
}

// ── Block submission ─────────────────────────────────────────────────

/// Fires when an accepted share's `submission_difficulty` meets the
/// network difficulty. Production wiring forwards to
/// `bp_template_distribution::TdpHandle::submit_solution(template_id,
/// version, header_timestamp, header_nonce, witness_coinbase)`.
///
/// The hook gets the full [`ShareAccept`] (carries the template,
/// MiningJob, and assembled header) plus the authorized identity so the
/// adapter can stamp `blocks_entity` rows with `address` / `worker` /
/// `session_id`.
/// `stream` is the template stream this job was built on — it routes the
/// solution to the matching TDP handle (the one whose `template_id` the
/// coinbase references). See [`bp_common::StreamKind`].
#[async_trait]
pub trait BlockSubmissionSink: Send + Sync {
    async fn submit_block(
        &self,
        accept: &ShareAccept,
        address: &str,
        worker: &str,
        session_id: &str,
        stream: StreamKind,
    );
}

// ── Accepted share fan-out ───────────────────────────────────────────

/// Fires for every accepted share. Production impl fans out to:
/// - `PoolShareStatisticsService.addAcceptedShare(effective_diff)`
/// - `ClientStatisticsService.addAcceptedShare(entity, effective_diff)`
/// - `MinerActiveModeService.mark(address, effective_mode)`
/// - `PoolModeHashrateService.incrementAccepted(effective_mode,
///   effective_diff)`
/// - `ShareTotalsCacheService.increment(address, worker, effective_diff)`
/// - `ClientDifficultyStatisticsService.recordShareDifficulty(...)`
///
/// The PPLNS / group-solo `recordShare` calls live with the payout-mode
/// adapter, not this sink (different wiring, different rate-limit
/// semantics).
#[async_trait]
pub trait AcceptedShareSink: Send + Sync {
    /// `hash_rate` is the session-wide H/s snapshot the vardiff
    /// engine reports right after consuming this share — written
    /// to client_entity.hashRate by the persistence sink. `user_agent`
    /// is the miner's firmware/vendor string (same source as
    /// `register_session`), used to stamp the all-time best-difficulty row.
    async fn record_accepted(
        &self,
        address: &str,
        worker: &str,
        session_id: &str,
        user_agent: Option<&str>,
        accept: &ShareAccept,
        hash_rate: f64,
    );
}

// ── Rejected share fan-out ───────────────────────────────────────────

/// Fires for every rejected share. Forwards to the pool-wide +
/// per-client rejected-share accumulators (pool reject totals, pool
/// share stats, per-client reject totals, per-client share stats).
///
/// `address` is `None` for shares rejected before the worker authorized
/// (only possible for `Stale` / `JobNotFound` if the framing layer ever
/// lets one through — defensive).
#[async_trait]
pub trait RejectedShareSink: Send + Sync {
    async fn record_rejected(
        &self,
        address: Option<&str>,
        worker: Option<&str>,
        session_id: &str,
        reason: RejectReason,
        difficulty: f64,
    );
}

// ── Session persistence ──────────────────────────────────────────────

/// Per-session bookkeeping — `client` row insert + device-online/offline
/// notifications:
///
/// - `register_session` inserts the `client` row and fires the
///   device-online notification.
/// - `deregister_session` deletes the row and fires the device-offline
///   notification.
#[async_trait]
pub trait SessionPersistence: Send + Sync {
    async fn register_session(
        &self,
        session_id: &str,
        address: &str,
        worker: &str,
        user_agent: Option<&str>,
    );
    async fn deregister_session(&self, session_id: &str);
}

// ── Device status ────────────────────────────────────────────────────

/// Fired on per-session online (`Authorized`) + offline (`Disconnect`)
/// transitions. Production wiring forwards to
/// `bp_notifications::dispatcher::NotificationDispatcher::notify_device_status`
/// so subscribers get per-worker connect / disconnect pushes.
#[async_trait]
pub trait DeviceStatusSink: Send + Sync {
    async fn on_device_event(
        &self,
        address: &str,
        worker: &str,
        session_id: &str,
        user_agent: Option<&str>,
        is_online: bool,
    );
}

// ── ServerHooks ──────────────────────────────────────────────────────

/// Composite of all six trait boundaries. Cheap to clone (each field is
/// an `Arc`); the server task clones once per connection.
#[derive(Clone)]
pub struct ServerHooks {
    pub block_sink: Arc<dyn BlockSubmissionSink>,
    pub accepted_sink: Arc<dyn AcceptedShareSink>,
    pub rejected_sink: Arc<dyn RejectedShareSink>,
    pub session_persistence: Arc<dyn SessionPersistence>,
    pub payout_resolver: Arc<dyn PayoutResolver>,
    pub device_status_sink: Arc<dyn DeviceStatusSink>,
}

impl ServerHooks {
    /// All-noop instance. Used for tests + standalone integration without
    /// full production wiring. The server still functions end-to-end
    /// (mining works, blocks found through the SV1 → SubmitSolution path
    /// land when the block_sink is replaced); only the per-share stats /
    /// persistence side-effects are silent.
    pub fn no_op() -> Self {
        let n: Arc<NoOpHooks> = Arc::new(NoOpHooks);
        Self {
            block_sink: n.clone(),
            accepted_sink: n.clone(),
            rejected_sink: n.clone(),
            session_persistence: n.clone(),
            payout_resolver: n.clone(),
            device_status_sink: n,
        }
    }
}

// ── Default no-op impl ───────────────────────────────────────────────

/// Stub impl satisfying every hook trait. Useful as a placeholder
/// without full production wiring + for unit-testing the dispatch layer.
pub struct NoOpHooks;

#[async_trait]
impl BlockSubmissionSink for NoOpHooks {
    async fn submit_block(&self, _: &ShareAccept, _: &str, _: &str, _: &str, _: StreamKind) {}
}

#[async_trait]
impl AcceptedShareSink for NoOpHooks {
    async fn record_accepted(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: &ShareAccept,
        _: f64,
    ) {
    }
}

#[async_trait]
impl RejectedShareSink for NoOpHooks {
    async fn record_rejected(
        &self,
        _: Option<&str>,
        _: Option<&str>,
        _: &str,
        _: RejectReason,
        _: f64,
    ) {
    }
}

#[async_trait]
impl SessionPersistence for NoOpHooks {
    async fn register_session(&self, _: &str, _: &str, _: &str, _: Option<&str>) {}
    async fn deregister_session(&self, _: &str) {}
}

#[async_trait]
impl DeviceStatusSink for NoOpHooks {
    async fn on_device_event(&self, _: &str, _: &str, _: &str, _: Option<&str>, _: bool) {}
}

#[async_trait]
impl PayoutResolver for NoOpHooks {
    async fn resolve_payouts(&self, miner_address: &str, _reward_sats: u64) -> Vec<PayoutEntry> {
        vec![PayoutEntry {
            address: miner_address.to_string(),
            percent: 100.0,
        }]
    }
}

// ── Test-only recording impl ─────────────────────────────────────────
//
// Lives in a `pub(crate)` non-test module so the `server.rs` test
// module can import `RecordingHooks` directly. Keeping it ABOVE the
// in-module test fn avoids the `items-after-test-module` lint.

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::Mutex;

    /// `(address, worker, reason, difficulty)` captured per rejected share.
    type RejectedRecord = (Option<String>, Option<String>, RejectReason, f64);

    pub(crate) struct RecordingHooks {
        pub registered: Mutex<Vec<(String, String, String)>>,
        pub deregistered: Mutex<Vec<String>>,
        pub accepted: Mutex<Vec<(String, f64)>>,
        pub rejected: Mutex<Vec<RejectedRecord>>,
        pub blocks_submitted: Mutex<Vec<(String, String, u64)>>,
        /// (address, worker, online) per `on_device_event`.
        pub device_events: Mutex<Vec<(String, String, bool)>>,
    }

    impl RecordingHooks {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self {
                registered: Mutex::new(vec![]),
                deregistered: Mutex::new(vec![]),
                accepted: Mutex::new(vec![]),
                rejected: Mutex::new(vec![]),
                blocks_submitted: Mutex::new(vec![]),
                device_events: Mutex::new(vec![]),
            })
        }
        pub(crate) fn as_server_hooks(self: &Arc<Self>) -> ServerHooks {
            ServerHooks {
                block_sink: self.clone(),
                accepted_sink: self.clone(),
                rejected_sink: self.clone(),
                session_persistence: self.clone(),
                payout_resolver: self.clone(),
                device_status_sink: self.clone(),
            }
        }
    }

    #[async_trait]
    impl DeviceStatusSink for RecordingHooks {
        async fn on_device_event(
            &self,
            address: &str,
            worker: &str,
            _session_id: &str,
            _user_agent: Option<&str>,
            online: bool,
        ) {
            self.device_events.lock().unwrap().push((
                address.to_string(),
                worker.to_string(),
                online,
            ));
        }
    }

    #[async_trait]
    impl BlockSubmissionSink for RecordingHooks {
        async fn submit_block(
            &self,
            accept: &ShareAccept,
            address: &str,
            _: &str,
            session_id: &str,
            _: StreamKind,
        ) {
            self.blocks_submitted.lock().unwrap().push((
                address.to_string(),
                session_id.to_string(),
                accept.template.template_id,
            ));
        }
    }

    #[async_trait]
    impl AcceptedShareSink for RecordingHooks {
        async fn record_accepted(
            &self,
            address: &str,
            _worker: &str,
            _session_id: &str,
            _user_agent: Option<&str>,
            accept: &ShareAccept,
            _hash_rate: f64,
        ) {
            self.accepted
                .lock()
                .unwrap()
                .push((address.to_string(), accept.effective_difficulty));
        }
    }

    #[async_trait]
    impl RejectedShareSink for RecordingHooks {
        async fn record_rejected(
            &self,
            address: Option<&str>,
            worker: Option<&str>,
            _: &str,
            reason: RejectReason,
            difficulty: f64,
        ) {
            self.rejected.lock().unwrap().push((
                address.map(String::from),
                worker.map(String::from),
                reason,
                difficulty,
            ));
        }
    }

    #[async_trait]
    impl PayoutResolver for RecordingHooks {
        async fn resolve_payouts(
            &self,
            miner_address: &str,
            _reward_sats: u64,
        ) -> Vec<PayoutEntry> {
            vec![PayoutEntry {
                address: miner_address.to_string(),
                percent: 100.0,
            }]
        }
    }

    #[async_trait]
    impl SessionPersistence for RecordingHooks {
        async fn register_session(
            &self,
            session_id: &str,
            address: &str,
            worker: &str,
            _user_agent: Option<&str>,
        ) {
            self.registered.lock().unwrap().push((
                session_id.to_string(),
                address.to_string(),
                worker.to_string(),
            ));
        }
        async fn deregister_session(&self, session_id: &str) {
            self.deregistered
                .lock()
                .unwrap()
                .push(session_id.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_op_hooks_is_constructable() {
        let _hooks = ServerHooks::no_op();
        let _clone = _hooks.clone();
    }
}
