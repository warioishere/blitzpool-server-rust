// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fan-out of an ext 0x0003/Implementation Notes settlement.
//!
//! When a block is booked, every payout distribution the pool has published
//! becomes stale at once: its weights encode the ledger balances as they stood
//! BEFORE the booking, so a job-declaring client still declaring against them
//! would pay those balances a second time. ext 0x0003/Implementation Notes
//! therefore requires the acceptance window to close on a settlement rather
//! than expire on its own.
//!
//! The registry that has to hear it
//! ([`bp_stratum_v2::jdp_server::StratumV2JdpServer`]'s) lives on the
//! `front`; **the booking does not**: the `payout` process applies the
//! ledger. So a settlement goes two ways, like the membership caches
//! ([`crate::cache_sync`]): to the local registry if this process has one,
//! and onto the `cache:invalidate` stream for a registry elsewhere. A
//! process that is both settles twice, which is harmless: the second epoch
//! bump invalidates an already-invalid set and the republish coalesces.
//!
//! Deliberately NO periodic backstop: "settle again just in case" would
//! force a republish on a timer forever. A missed event self-heals within
//! one `[sv2].jdp_payout_distribution_interval_secs` (60 s by default),
//! since the next publish rebuilds from the post-settlement ledger.

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
    /// Filled by `jdp::spawn`, so only on a `front`. `OnceLock` because the
    /// Stratum sinks and the confirmation watcher are built BEFORE the JDP
    /// server exists.
    local: Arc<OnceLock<DistributionInvalidationHandle>>,
    /// `None` only without Redis (tests).
    ///
    /// ⚠️ It does NOT reach a second front: all fronts share one consumer
    /// group ([`crate::cache_sync`]), which hands each entry to one
    /// consumer. The other front keeps its distribution until its next
    /// publish tick. See `cache_sync::GROUP`.
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
        // Best-effort: a failed broadcast must not fail the committed
        // booking; the republish interval bounds the damage.
        if let Err(err) = producer.publish(&event).await {
            warn!(
                %err,
                "settlement: could not broadcast the ext 0x0003/Implementation Notes invalidation — a job-declaring \
                 client may keep declaring against pre-settlement weights until the next \
                 scheduled republish"
            );
        }
    }
}
