// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fan-out of an SV2 ext-0x0003 §10 settlement.
//!
//! When a block is booked, every payout distribution the pool has
//! published becomes stale at once: its weights encode the ledger
//! balances as they stood BEFORE the booking, so a job-declaring client
//! still declaring against them would pay those balances a second time.
//! §10 therefore requires the acceptance window to close on a settlement
//! rather than expire on its own.
//!
//! The registry that has to hear it is
//! [`bp_stratum_v2::jdp_server::StratumV2JdpServer`]'s, and it lives on
//! the process holding the `front` role. **The booking does not.** Under
//! the role split the `payout` process drains the block-found stream and
//! applies the ledger, so the settlement happens on one process and the
//! registry sits on another.
//!
//! That is what this type exists to make un-forgettable. It used to be a
//! bare `Arc<OnceLock<DistributionInvalidationHandle>>` threaded to the
//! Stratum sinks, the confirmation watcher and the JDP sink — a handle
//! that is only ever filled by `jdp::spawn`, i.e. only on a `front`. On
//! every other process `.get()` returned `None` and the settlement was
//! silently dropped, which in the production topology is *every* Stratum
//! block: the front publishes the block-found event, the payout process
//! books it, and nothing told the front.
//!
//! So a settlement now goes two ways at once, the same shape the
//! membership caches already use ([`crate::cache_sync`]): apply to the
//! local registry if this process has one, and publish onto the
//! `cache:invalidate` stream so a registry in another process hears it.
//! A process that is both front and payout does both and settles twice —
//! harmless, the second epoch bump invalidates an already-invalid set and
//! the publisher's `Notify` coalesces the forced republish.
//!
//! There is deliberately NO periodic backstop, unlike the membership
//! rebuilds on the same stream: "settle again just in case" would bump
//! the epoch and force a republish on a timer forever. A missed event
//! instead self-heals within one `[sv2].jdp_payout_distribution_interval_secs`
//! (60 s by default), because the next scheduled publish rebuilds from
//! the post-settlement ledger anyway. §10 is about closing the window
//! immediately; the interval bounds how long it can stay open if the
//! signal is lost.

use std::sync::{Arc, OnceLock};

use bp_share_stream::{
    cache_kind, CacheInvalidation, StreamProducer, CACHE_INVALIDATION_STREAM_KEY,
};
use bp_stratum_v2::jdp_server::DistributionInvalidationHandle;
use redis::aio::ConnectionManager;
use tracing::{debug, warn};

/// Tells every published payout distribution that a block settled.
///
/// Cheap to clone: an `Arc` plus an optionally-present producer that is
/// itself `Arc`-backed.
#[derive(Clone)]
pub(crate) struct SettlementSignal {
    /// Filled by `jdp::spawn` on the process that runs the JDP server —
    /// i.e. only on a `front`. `OnceLock` because the Stratum sinks and
    /// the confirmation watcher are built BEFORE the JDP server exists.
    local: Arc<OnceLock<DistributionInvalidationHandle>>,
    /// `None` on a process with no Redis handle (tests). Present
    /// otherwise, including on a front — a second front would not hear a
    /// settlement any other way.
    remote: Option<StreamProducer<CacheInvalidation>>,
}

impl SettlementSignal {
    /// A signal with no cross-process reach — the local registry only.
    /// Tests use it to exercise the invalidation without Redis.
    #[cfg(test)]
    pub(crate) fn local_only() -> Self {
        Self {
            local: Arc::new(OnceLock::new()),
            remote: None,
        }
    }

    /// The production shape: local slot plus the `cache:invalidate`
    /// stream.
    pub(crate) fn new(redis: ConnectionManager) -> Self {
        Self {
            local: Arc::new(OnceLock::new()),
            remote: Some(StreamProducer::new(redis, CACHE_INVALIDATION_STREAM_KEY)),
        }
    }

    /// The slot `jdp::spawn` fills once the registry exists, and that
    /// [`crate::cache_sync`] reads when a settlement arrives from another
    /// process. Set-once; a second attempt is ignored.
    pub(crate) fn registry_slot(&self) -> Arc<OnceLock<DistributionInvalidationHandle>> {
        self.local.clone()
    }

    /// A block was booked. Invalidate every published distribution —
    /// here, and on whatever other process holds a registry.
    pub(crate) async fn settle(&self) {
        if let Some(handle) = self.local.get() {
            handle.settle();
            debug!("settlement: local payout distributions invalidated");
        }
        let Some(producer) = self.remote.as_ref() else {
            return;
        };
        let event = CacheInvalidation {
            kind: cache_kind::SETTLEMENT.to_string(),
        };
        // Best-effort, like every other publisher on this stream: a
        // settlement that cannot be broadcast must not fail the booking
        // that already committed. The bound on the damage is the
        // publisher's own republish interval.
        if let Err(err) = producer.publish(&event).await {
            warn!(
                %err,
                "settlement: could not broadcast the §10 invalidation — a job-declaring \
                 client may keep declaring against pre-settlement weights until the next \
                 scheduled republish"
            );
        }
    }
}
