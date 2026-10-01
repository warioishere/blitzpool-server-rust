// SPDX-License-Identifier: AGPL-3.0-or-later

//! Side-effect hooks of the SV1 server: block submission and payout
//! resolution are SV1 traits; shares, sessions and device status go to the
//! `bp_share_hook` traits shared with SV2. [`ServerHooks::no_op`] makes the
//! crate usable without production wiring.

use std::sync::Arc;

use async_trait::async_trait;
use bp_mining_job::{PayoutEntry, ResolvedPayouts};

use bp_common::StreamKind;
use bp_share_hook::{
    DeviceStatusSink, NoOpSink, SharedAcceptedShareSink, SharedRejectedShareSink,
    SharedSessionPersistence,
};

use crate::submit::ShareAccept;

// ── PayoutResolver ───────────────────────────────────────────────────

/// The mode-aware coinbase payout list for an authorized miner, resolved
/// on every template broadcast and after authorize. `reward_sats` is the
/// template's `coinbase_tx_value_remaining`.
#[async_trait]
pub trait PayoutResolver: Send + Sync {
    /// Resolve the payout list plus the fingerprint of the
    /// distribution it came from (zeroed = books without a snapshot).
    async fn resolve_payouts(&self, miner_address: &str, reward_sats: u64) -> ResolvedPayouts;

    /// The template stream this address mines on, fixed at
    /// `mining.authorize`. Defaults to `StreamKind::Pplns` (single stream);
    /// sync because the mode lookup is an in-memory cache hit.
    fn resolve_stream(&self, _miner_address: &str) -> StreamKind {
        StreamKind::Pplns
    }
}

// ── Block submission ─────────────────────────────────────────────────

/// Fires when an accepted share meets the network target. `stream` is the
/// stream the job was built on and must pick the TDP handle submitting the
/// solution: `template_id`s are only meaningful on their own stream.
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

// ── ServerHooks ──────────────────────────────────────────────────────

/// Composite of every hook the server fires. Cheap to clone (each field is
/// an `Arc`); the server task clones once per connection.
#[derive(Clone)]
pub struct ServerHooks {
    pub block_sink: Arc<dyn BlockSubmissionSink>,
    pub accepted_sink: Arc<dyn SharedAcceptedShareSink>,
    pub rejected_sink: Arc<dyn SharedRejectedShareSink>,
    pub session_persistence: Arc<dyn SharedSessionPersistence>,
    pub payout_resolver: Arc<dyn PayoutResolver>,
    pub device_status_sink: Arc<dyn DeviceStatusSink>,
}

impl ServerHooks {
    /// All-noop hooks: mining still works, only the side effects are silent
    /// (and blocks land only once `block_sink` is replaced).
    pub fn no_op() -> Self {
        let n: Arc<NoOpHooks> = Arc::new(NoOpHooks);
        let shared: Arc<NoOpSink> = Arc::new(NoOpSink);
        Self {
            block_sink: n.clone(),
            accepted_sink: shared.clone(),
            rejected_sink: shared.clone(),
            session_persistence: shared.clone(),
            payout_resolver: n,
            device_status_sink: shared,
        }
    }
}

// ── Default no-op impl ───────────────────────────────────────────────

/// No-op SV1 hooks; the payout resolver pays everything to the miner.
pub(crate) struct NoOpHooks;

#[async_trait]
impl BlockSubmissionSink for NoOpHooks {
    async fn submit_block(&self, _: &ShareAccept, _: &str, _: &str, _: &str, _: StreamKind) {}
}

#[async_trait]
impl PayoutResolver for NoOpHooks {
    async fn resolve_payouts(&self, miner_address: &str, reward_sats: u64) -> ResolvedPayouts {
        ResolvedPayouts::unsnapshotted(vec![PayoutEntry {
            address: miner_address.to_string(),
            sats: reward_sats,
        }])
    }
}

// ── Test-only recording impl ─────────────────────────────────────────
// `pub(crate)` so other modules' tests can import `RecordingHooks`.

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use bp_share_hook::{RejectedReason, SharedAcceptedShare, SharedRejectedShare};
    use std::sync::Mutex;

    /// `(address, worker, reason, difficulty)` captured per rejected share.
    type RejectedRecord = (Option<String>, Option<String>, RejectedReason, f64);

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
    impl SharedAcceptedShareSink for RecordingHooks {
        async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
            self.accepted
                .lock()
                .unwrap()
                .push((share.address.to_string(), share.effective_difficulty));
        }
    }

    #[async_trait]
    impl SharedRejectedShareSink for RecordingHooks {
        async fn record_rejected(&self, share: SharedRejectedShare<'_>) {
            self.rejected.lock().unwrap().push((
                share.address.map(String::from),
                share.worker.map(String::from),
                share.reason,
                share.difficulty,
            ));
        }
    }

    #[async_trait]
    impl PayoutResolver for RecordingHooks {
        async fn resolve_payouts(&self, miner_address: &str, reward_sats: u64) -> ResolvedPayouts {
            ResolvedPayouts::unsnapshotted(vec![PayoutEntry {
                address: miner_address.to_string(),
                sats: reward_sats,
            }])
        }
    }

    #[async_trait]
    impl SharedSessionPersistence for RecordingHooks {
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
