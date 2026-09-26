// SPDX-License-Identifier: AGPL-3.0-or-later

//! I/O side-effect trait boundaries for the SV1 server.
//!
//! The `client.rs` pure handlers produce [`crate::client::SessionEvent`]s
//! that the server task translates into hook calls. The hooks themselves
//! are trait-objects so the production wiring can plug in:
//!
//! - **Block submission**: a `TdpHandle::submit_solution` adapter for
//!   the SV1-as-translator topology (TDP-direct, no JDP for SV1).
//! - **Payout resolution**: the mode-aware coinbase distribution.
//!
//! Accepted / rejected shares, session lifecycle and device status go to
//! the protocol-agnostic `bp_share_hook` traits, which SV2 shares — the
//! server projects its own types into them at the call site
//! (`crate::shared_adapter`).
//!
//! Trait-object dispatch is deliberate: each hook fires once per
//! event (subscribe / authorize / share / block-change) — single-digit
//! per-second on a production pool, sub-microsecond vtable cost. The
//! production wiring is genuinely heterogeneous (DB impls, notification
//! adapters, stat sinks), so per-trait `dyn` is the natural fit. See
//! `feedback-design-principles`: *"dyn nur wenn echte Heterogenität
//! nötig"*.
//!
//! [`ServerHooks::no_op`] fills every slot with a no-op ([`NoOpHooks`] for
//! the SV1 traits, `bp_share_hook::NoOpSink` for the shared ones) so the
//! crate is usable end-to-end without full production wiring. Tests inject recording impls to assert
//! the fan-out triggers correctly.

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
/// The default impl on `NoOpHooks` returns a single 100%-to-miner
/// entry — matches the pre-7.4d behaviour where every mode emitted
/// solo-output coinbase regardless of port (share crediting was
/// correct via the accept-hook fan-out, only the on-chain payout
/// shape was wrong).
#[async_trait]
pub trait PayoutResolver: Send + Sync {
    /// Resolve the payout list plus the fingerprint of the
    /// distribution it came from (zeroed = books without a snapshot).
    async fn resolve_payouts(&self, miner_address: &str, reward_sats: u64) -> ResolvedPayouts;

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

/// Fires when an accepted share's hash meets the network target
/// (`bp_mining_job::meets_network_target`). Production wiring forwards to
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
    /// The pool's rotating-identity intake, consulted once per
    /// `mining.authorize`. `None` in every standalone / test wiring.
    ///
    /// It rides the hook composite for the same reason
    /// [`PayoutResolver`] does: it is a capability this crate **needs but
    /// cannot provide** — building one requires `miniscript` and the
    /// operator's `[payout_identity]` config, neither of which belongs in a
    /// protocol crate. The composite is already the place an injected
    /// capability arrives; a second mechanism for the same job would be one
    /// more thing to keep in step.
    ///
    /// The `Option` is "no intake wired", not "the feature is off" — the
    /// operator flag lives inside the implementation, so with an intake
    /// installed and the flag `false` an xpub is *refused with a reason*
    /// rather than mistaken for a malformed address. See
    /// `SessionState::rotating_intake`, which the IO layer
    /// copies this onto.
    pub rotating_intake: Option<Arc<dyn bp_common::RotatingIntake>>,
}

impl ServerHooks {
    /// All-noop instance. Used for tests + standalone integration without
    /// full production wiring. The server still functions end-to-end
    /// (mining works, blocks found through the SV1 → SubmitSolution path
    /// land when the block_sink is replaced); only the per-share stats /
    /// persistence side-effects are silent.
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
            // No intake: every address on this wiring takes the static path,
            // byte for byte as before. `NoOpHooks` deliberately does NOT get a
            // `RotatingIntake` impl — a no-op one would have to answer
            // "is this an xpub?", and a stub answering `Ok(None)` is a second
            // opinion on that question.
            rotating_intake: None,
        }
    }
}

// ── Default no-op impl ───────────────────────────────────────────────

/// Stub impl of the SV1-specific hook traits. Useful as a placeholder
/// without full production wiring + for unit-testing the dispatch layer.
pub(crate) struct NoOpHooks;

#[async_trait]
impl BlockSubmissionSink for NoOpHooks {
    async fn submit_block(&self, _: &ShareAccept, _: &str, _: &str, _: &str, _: StreamKind) {}
}

#[async_trait]
impl PayoutResolver for NoOpHooks {
    async fn resolve_payouts(&self, miner_address: &str, reward_sats: u64) -> ResolvedPayouts {
        ResolvedPayouts::unsnapshotted(vec![PayoutEntry::static_address(
            miner_address.to_string(),
            reward_sats,
        )])
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
                rotating_intake: None,
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
            ResolvedPayouts::unsnapshotted(vec![PayoutEntry::static_address(
                miner_address.to_string(),
                reward_sats,
            )])
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
