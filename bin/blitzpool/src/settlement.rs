// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fan-out of an ext 0x0003/Implementation Notes settlement: after a booking,
//! every published distribution encodes balances that would pay twice. The
//! registry is on `front`, the booking on `payout`, so it goes local and onto
//! `cache:invalidate`. No backstop: the next distribution publish heals a miss.

use std::sync::{Arc, OnceLock};

use bp_share_stream::{
    cache_kind, CacheInvalidation, StreamProducer, CACHE_INVALIDATION_STREAM_KEY,
};
use bp_stratum_v2::jdp_server::DistributionInvalidationHandle;
use redis::aio::ConnectionManager;
use tracing::{debug, warn};

/// Tells every published payout distribution that a block settled.
#[derive(Clone)]
pub(crate) struct SettlementSignal {
    /// Filled by `jdp::spawn`, so only on a `front`. `OnceLock` because the
    /// Stratum sinks and the confirmation watcher are built BEFORE the JDP
    /// server exists.
    local: Arc<OnceLock<DistributionInvalidationHandle>>,
    /// `None` only without Redis (tests). ⚠️ Does NOT reach a second front:
    /// all fronts share one consumer group, see `cache_sync::GROUP`.
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
