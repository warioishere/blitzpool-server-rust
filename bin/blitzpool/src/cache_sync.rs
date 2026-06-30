// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-process routing-cache sync.
//!
//! Group-Solo + Blockparty membership lives in per-process in-memory routing
//! caches that the Stratum mode-gate reads. In the Core/Satellite split the
//! API writers and the Stratum Front are SEPARATE processes, so a membership
//! change made via the API doesn't reach the Front's cache (it's hydrated at
//! boot + on in-process changes only).
//!
//! This module closes that gap two ways:
//! - **Publish** ([`StreamCacheNotifier`]): the writer process `XADD`s a
//!   [`CacheInvalidation`] to the `cache:invalidate` stream after every
//!   membership mutation (wired via [`bp_group_mgmt_engine::MembershipChangeNotifier`]).
//! - **Consume + backstop** ([`spawn`]): the Front drains the stream (tail-start
//!   — it warmed from the DB at boot) and rebuilds the matching cache, AND
//!   rebuilds both on a periodic timer so a missed event self-heals.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bp_blockparty_engine::BlockpartyApi;
use bp_group_mgmt_engine::MembershipChangeNotifier;
use bp_share_stream::{
    cache_kind, CacheInvalidation, StreamConsumer, StreamProducer, CACHE_INVALIDATION_STREAM_KEY,
};
use redis::aio::ConnectionManager;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use bp_common::{AddressId, MiningMode};
use bp_mining_mode::MiningModeResult;

use crate::engines::BlitzpoolModeGate;
use crate::group_service::SharedGroupService;

const GROUP: &str = "cache-sync-front";
const CONSUMER: &str = "c1";
const BATCH: usize = 32;
const BLOCK_MS: usize = 1000;
const ERROR_BACKOFF: Duration = Duration::from_millis(500);
/// Full-rebuild safety net for any invalidation the stream consumer missed
/// (e.g. a brief Redis blip). Membership changes aren't latency-critical, so a
/// minute is plenty; the stream path handles the common case instantly.
const BACKSTOP_INTERVAL: Duration = Duration::from_secs(60);

/// Publishes membership-change invalidations onto the `cache:invalidate` stream.
/// Wired into the group + blockparty services on the writer process.
pub(crate) struct StreamCacheNotifier {
    producer: StreamProducer<CacheInvalidation>,
}

impl StreamCacheNotifier {
    pub(crate) fn new(redis: ConnectionManager) -> Self {
        Self {
            producer: StreamProducer::new(redis, CACHE_INVALIDATION_STREAM_KEY),
        }
    }
}

#[async_trait]
impl MembershipChangeNotifier for StreamCacheNotifier {
    async fn membership_changed(&self, kind: &str) {
        let event = CacheInvalidation {
            kind: kind.to_string(),
        };
        // Best-effort: a publish failure is caught by the Front's periodic
        // backstop rebuild, so it must never fail the mutation path.
        if let Err(err) = self.producer.publish(&event).await {
            warn!(%err, kind, "cache-sync: publish failed (front backstop will catch up)");
        }
    }
}

/// Live consumer + backstop task.
pub(crate) struct CacheSyncHandle {
    task: JoinHandle<()>,
    cancel: CancellationToken,
}

impl CacheSyncHandle {
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        if let Err(err) = self.task.await {
            warn!(%err, "cache-sync: task join failed");
        }
    }
}

/// Spawn the Front-side cache-sync consumer + periodic backstop. Drains
/// `cache:invalidate` and rebuilds the matching routing cache; on a timer,
/// rebuilds both regardless (the safety net).
pub(crate) fn spawn(
    redis: ConnectionManager,
    group: SharedGroupService,
    blockparty: Option<Arc<dyn BlockpartyApi>>,
    gate: Arc<BlitzpoolModeGate>,
) -> CacheSyncHandle {
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        let consumer: StreamConsumer<CacheInvalidation> =
            StreamConsumer::new(redis, CACHE_INVALIDATION_STREAM_KEY, GROUP, CONSUMER);
        // Tail-start: the Front already warmed both caches from the DB at boot,
        // so it only needs invalidations published AFTER that.
        if let Err(err) = consumer.ensure_group_at_tail().await {
            warn!(%err, "cache-sync: ensure_group failed; relying on periodic backstop only");
        }

        info!("cache-sync: live (stream + periodic backstop)");
        let mut backstop = tokio::time::interval(BACKSTOP_INTERVAL);
        backstop.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                biased;
                _ = task_cancel.cancelled() => break,
                _ = backstop.tick() => {
                    rebuild_group(&group, &gate).await;
                    rebuild_blockparty(blockparty.as_ref()).await;
                }
                result = consumer.read_new(BATCH, BLOCK_MS) => match result {
                    Ok(batch) => {
                        if batch.is_empty() {
                            continue;
                        }
                        let mut want_group = false;
                        let mut want_blockparty = false;
                        let mut ids = Vec::with_capacity(batch.len());
                        for entry in &batch {
                            match entry.value.kind.as_str() {
                                cache_kind::GROUP => want_group = true,
                                cache_kind::BLOCKPARTY => want_blockparty = true,
                                other => warn!(kind = other, "cache-sync: unknown invalidation kind — ignored"),
                            }
                            ids.push(entry.id.clone());
                        }
                        // Coalesce: one rebuild per kind per batch.
                        if want_group {
                            rebuild_group(&group, &gate).await;
                        }
                        if want_blockparty {
                            rebuild_blockparty(blockparty.as_ref()).await;
                        }
                        if let Err(err) = consumer.ack(&ids).await {
                            warn!(%err, "cache-sync: ack failed (will redeliver)");
                        }
                    }
                    Err(err) => {
                        warn!(%err, "cache-sync: read_new failed; backing off");
                        tokio::time::sleep(ERROR_BACKOFF).await;
                    }
                },
            }
        }
        info!("cache-sync: stopped");
    });
    CacheSyncHandle { task, cancel }
}

async fn rebuild_group(group: &SharedGroupService, gate: &Arc<BlitzpoolModeGate>) {
    match group.service.rebuild_cache().await {
        Ok(()) => info!("cache-sync: group address cache rebuilt"),
        Err(err) => {
            warn!(%err, "cache-sync: group cache rebuild failed");
            return;
        }
    }
    reconcile_gate_modes(group, gate).await;
}

/// After the address cache reflects a membership change, flip the **live** mode
/// gate for already-connected miners so their running connection's shares route
/// correctly without a reconnect:
///
/// - a `Solo`-gated miner now in an active group → `GroupSolo` (the join case:
///   a miner that solo-mined before joining keeps a self-refreshing Solo marker,
///   so its authorize-time resolution stuck on Solo — this is what makes an
///   approved join take effect from the next share),
/// - a `GroupSolo`-gated miner no longer in an active group → `Solo` (left /
///   kicked / dissolved).
///
/// Runs on every group invalidation (instant on approve) + the 60s backstop.
async fn reconcile_gate_modes(group: &SharedGroupService, gate: &Arc<BlitzpoolModeGate>) {
    let cache = group.service.address_cache();
    let (mut upgraded, mut downgraded) = (0u32, 0u32);
    for (address, current) in gate.group_transition_candidates() {
        let Ok(addr_id) = AddressId::new(address.clone()) else {
            continue;
        };
        let active_group = cache
            .get(&addr_id)
            .await
            .filter(|e| e.active)
            .map(|e| e.group_id);
        match (current.mode, active_group) {
            (MiningMode::Solo, Some(group_id)) => {
                gate.override_mode(&address, MiningModeResult::group_solo(group_id.to_string()));
                upgraded += 1;
            }
            (MiningMode::GroupSolo, None) => {
                gate.override_mode(&address, MiningModeResult::solo());
                downgraded += 1;
            }
            _ => {}
        }
    }
    if upgraded > 0 || downgraded > 0 {
        info!(
            upgraded,
            downgraded, "cache-sync: reconciled live mode gate to group membership"
        );
    }
}

async fn rebuild_blockparty(blockparty: Option<&Arc<dyn BlockpartyApi>>) {
    let Some(bp) = blockparty else {
        return;
    };
    match bp.rebuild_cache().await {
        Ok(()) => info!("cache-sync: blockparty routing cache rebuilt"),
        Err(err) => warn!(%err, "cache-sync: blockparty cache rebuild failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REDIS_URL: &str = "redis://127.0.0.1:16379";

    async fn connect_redis_or_skip(db: u8) -> Option<ConnectionManager> {
        let client = redis::Client::open(format!("{REDIS_URL}/{db}")).ok()?;
        let mut conn = tokio::time::timeout(Duration::from_secs(2), ConnectionManager::new(client))
            .await
            .ok()?
            .ok()?;
        let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await.ok()?;
        Some(conn)
    }

    /// The notifier publishes `group` + `blockparty` invalidations onto the
    /// stream, and a consumer reads them back intact — the exact path the Front
    /// drains to rebuild its routing caches.
    #[tokio::test]
    async fn notifier_publishes_invalidations_a_consumer_reads() {
        let Some(redis) = connect_redis_or_skip(12).await else {
            eprintln!("redis unreachable — skipping cache-sync test");
            return;
        };

        let notifier = StreamCacheNotifier::new(redis.clone());
        notifier.membership_changed(cache_kind::GROUP).await;
        notifier.membership_changed(cache_kind::BLOCKPARTY).await;

        let consumer: StreamConsumer<CacheInvalidation> =
            StreamConsumer::new(redis, CACHE_INVALIDATION_STREAM_KEY, "verify", "c1");
        consumer.ensure_group().await.expect("ensure_group");

        let mut kinds = Vec::new();
        for _ in 0..5 {
            let batch = consumer.read_new(16, 500).await.expect("read_new");
            for entry in batch {
                kinds.push(entry.value.kind);
            }
            if kinds.len() >= 2 {
                break;
            }
        }
        assert_eq!(kinds, vec!["group".to_string(), "blockparty".to_string()]);
    }
}
