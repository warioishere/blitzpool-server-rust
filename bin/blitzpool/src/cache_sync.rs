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
//!
//! The same stream carries [`cache_kind::SETTLEMENT`], for the same
//! reason and in the opposite direction: the SV2 ext-0x0003 payout
//! registry lives on the Front, and the process that BOOKS a block
//! (`payout`) is a different one. See [`crate::settlement`] — including
//! why that kind is deliberately absent from the periodic backstop.

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
use tracing::{debug, info, warn};

use bp_common::{AddressId, MiningMode};
use bp_mining_mode::MiningModeResult;

use crate::engines::BlitzpoolModeGate;
use crate::group_service::SharedGroupService;

/// Consumer group for the Front's invalidation drain.
///
/// **One group, shared by every front — so exactly ONE front may consume
/// it.** A Redis consumer group hands each entry to exactly one consumer,
/// so with two fronts running this code each invalidation reaches whichever
/// asked first and the other never sees it. That is survivable for the
/// membership kinds (the 60 s [`BACKSTOP_INTERVAL`] rebuild covers a miss)
/// and a real, if bounded, window for [`cache_kind::SETTLEMENT`], which
/// deliberately has no backstop — see [`crate::settlement`].
///
/// Making a settlement reach EVERY front means a group per front, not a
/// consumer name per front: distinct consumer names inside one group still
/// split the entries between them. It would need a stable per-instance
/// identifier (a fresh group per boot leaks a group and a growing PEL each
/// restart), or dropping the group entirely in favour of a plain tail
/// `XREAD`, which is the natural primitive for a broadcast and needs no
/// acks — the Front warms both caches from the DB at boot, so entries
/// missed while it was down are not needed.
///
/// Left as-is on an OPERATOR DECISION, not by omission: this pool runs one
/// front and is not going to run more (stated 2026-08-03). So the shared
/// group is correct for the deployment it has, and rebuilding it would
/// change shared stream infrastructure to serve a topology nobody wants.
///
/// What that decision buys, and therefore what it costs to reverse: the
/// settlement fan-out ([`crate::settlement`]) is allowed to assume the one
/// front hears every invalidation. A second front would silently keep a
/// pre-settlement payout distribution current for up to one publish
/// interval. `two_consumers_in_one_group_split_the_entries` pins the
/// underlying semantics so that consequence cannot be re-discovered the
/// hard way.
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
    // The Front's JDP payout registry, once `jdp::spawn` has attached it.
    // Empty on a Front without JDP enabled — a settlement then has nothing
    // to invalidate here, which is correct, not a miss.
    settle_registry: Arc<
        std::sync::OnceLock<bp_stratum_v2::jdp_server::DistributionInvalidationHandle>,
    >,
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
                        let mut want_settlement = false;
                        let mut ids = Vec::with_capacity(batch.len());
                        for entry in &batch {
                            match entry.value.kind.as_str() {
                                cache_kind::GROUP => want_group = true,
                                cache_kind::BLOCKPARTY => want_blockparty = true,
                                cache_kind::SETTLEMENT => want_settlement = true,
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
                        if want_settlement {
                            invalidate_payout_distributions(&settle_registry);
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

/// §10: a block settled on another process. Every payout distribution
/// this Front published encodes pre-settlement ledger balances, so the
/// acceptance window has to close on them now — a job-declaring client
/// still declaring against them would pay those balances a second time.
///
/// Unlike the membership rebuilds this reads no database: the registry
/// simply bumps its settlement epoch and the JDP publisher pushes a
/// fresh distribution built from the post-settlement ledger.
fn invalidate_payout_distributions(
    registry: &Arc<std::sync::OnceLock<bp_stratum_v2::jdp_server::DistributionInvalidationHandle>>,
) {
    match registry.get() {
        Some(handle) => {
            handle.settle();
            info!("cache-sync: settlement heard — published payout distributions invalidated");
        }
        // No JDP server on this process, so nothing published anything.
        None => debug!("cache-sync: settlement heard but no payout registry here — ignored"),
    }
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
        // Fold this binary's local number into its own DB range —
        // see `bp_test_support::redis_db`. Two binaries both using
        // 0..15 flush each other mid-run.
        let db =
            bp_test_support::redis_db_in_range(bp_test_support::redis_db::BLITZPOOL_BIN, db).await;
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

    /// The constraint behind [`GROUP`]: two consumers in ONE group SPLIT the
    /// entries — they do not each get a copy.
    ///
    /// Every front runs this module with the same group and the same
    /// consumer name, so a second front does not receive an invalidation the
    /// first one took. For the membership kinds the 60 s backstop rebuild
    /// covers that; [`cache_kind::SETTLEMENT`] has no backstop by design, so
    /// there the miss is a real (bounded) window in which a JDC can keep
    /// declaring against pre-settlement weights.
    ///
    /// Asserted on the TOTAL number of deliveries rather than on who got
    /// what: which consumer wins a race is not the property, "each entry is
    /// delivered once, not once per front" is.
    #[tokio::test]
    async fn two_consumers_in_one_group_split_the_entries() {
        let Some(redis) = connect_redis_or_skip(1).await else {
            eprintln!("redis unreachable — skipping consumer-group semantics test");
            return;
        };
        let notifier = StreamCacheNotifier::new(redis.clone());
        for _ in 0..4 {
            notifier.membership_changed(cache_kind::GROUP).await;
        }

        // Same group as production, two distinct consumer names — the most
        // favourable case for "both hear everything", and it still splits.
        let first: StreamConsumer<CacheInvalidation> = StreamConsumer::new(
            redis.clone(),
            CACHE_INVALIDATION_STREAM_KEY,
            GROUP,
            "front-a",
        );
        let second: StreamConsumer<CacheInvalidation> =
            StreamConsumer::new(redis, CACHE_INVALIDATION_STREAM_KEY, GROUP, "front-b");
        first.ensure_group().await.expect("ensure_group");

        // Explicit counts, so the split is deterministic rather than a race.
        let a = first.read_new(2, 500).await.expect("read a");
        let b = second.read_new(16, 500).await.expect("read b");
        assert_eq!(a.len(), 2, "the first front takes the two it asked for");
        assert_eq!(
            b.len(),
            2,
            "the second front sees only what was LEFT — not the 4 that were \
             published. A settlement the first front consumed never reaches it."
        );
        assert_eq!(
            a.len() + b.len(),
            4,
            "each entry is delivered exactly once across the group"
        );
    }

    /// MONEY / ext 0x0003 §10: a settlement must cross the process
    /// boundary. Under the role split `payout` books the block and `front`
    /// holds the payout registry, so the settling process has no local
    /// handle — `.get()` returns `None` and the invalidation was silently
    /// dropped. Every Stratum block in the production topology took that
    /// path, and a job-declaring client would have kept declaring against
    /// pre-settlement weights, paying those ledger balances twice.
    ///
    /// Both halves are real here: a settling process with NO registry
    /// publishes, and a second process with one receives and invalidates.
    #[tokio::test]
    async fn a_settlement_on_one_process_invalidates_the_registry_on_another() {
        use bp_stratum_v2::bridge::{JdpDeclaredJobRegistry, PayoutDistributionEntry};
        use bp_stratum_v2::jdp::payout_distribution::WeightedOutput;
        use bp_stratum_v2::jdp_server::{JdpServerHooks, StratumV2JdpServer};
        use bp_stratum_v2::noise::{NoiseConfig, DEFAULT_CERT_VALIDITY};

        // DB 16, and it has to be its own: DB 9 was shared with
        // `redis_backup`'s test in this same binary, which FLUSHDBs it. The
        // comment here used to blame "other crates" for the resulting
        // flakiness — per-binary ranges (`bp_test_support::redis_db`) rule
        // those out; the collision was a sibling. The publish+read below
        // still RETRIES, which costs a round on a wipe rather than a red
        // test while a broken mechanism never produces an entry.
        let Some(redis) = connect_redis_or_skip(16).await else {
            eprintln!("redis unreachable — skipping settlement cross-process test");
            return;
        };

        // ── The `front`: a JDP server with a published distribution ──
        let bridge = Arc::new(std::sync::RwLock::new(JdpDeclaredJobRegistry::new()));
        bridge
            .write()
            .unwrap()
            .publish_pool_wide(PayoutDistributionEntry {
                distribution_id: 1,
                pool_payout: WeightedOutput {
                    script_pubkey: vec![0x51],
                    weight: 1,
                },
                payouts: vec![WeightedOutput {
                    script_pubkey: vec![0x00, 0x14, 0xAA],
                    weight: 100,
                }],
                dust_limits: vec![546],
                additional_outputs: vec![],
                reference_reward_sats: 312_500_000,
                payouts_fingerprint: Some([1u8; 32]),
                bookable: true,
                owner: None,
                jdp_session_id: None,
                published_at_ms: 1_001,
            });
        let noise = NoiseConfig::parse_strings(
            "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72",
            "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n",
            DEFAULT_CERT_VALIDITY,
        )
        .expect("noise config");
        let server = StratumV2JdpServer::spawn(
            noise,
            JdpServerHooks::no_op(),
            bridge.clone(),
            Duration::from_secs(3600),
        );
        let front_registry: Arc<std::sync::OnceLock<_>> = Arc::new(std::sync::OnceLock::new());
        let _ = front_registry.set(server.distribution_handle());
        assert!(
            bridge.read().unwrap().current_pool_wide().is_some(),
            "precondition: the front has a live published distribution"
        );

        // ── The `payout` process: settles, holds NO registry ────────
        let settling = crate::settlement::SettlementSignal::new(redis.clone());
        assert!(
            settling.registry_slot().get().is_none(),
            "precondition: the settling process has no local registry — that is \
             the whole reason this has to travel"
        );
        // ── The front's consumer drains it ──────────────────────────
        let consumer: StreamConsumer<CacheInvalidation> =
            StreamConsumer::new(redis, CACHE_INVALIDATION_STREAM_KEY, "front-verify", "c1");
        consumer.ensure_group().await.expect("ensure_group");
        let mut heard = false;
        for _ in 0..5 {
            settling.settle().await;
            for entry in consumer.read_new(16, 500).await.expect("read_new") {
                if entry.value.kind == cache_kind::SETTLEMENT {
                    invalidate_payout_distributions(&front_registry);
                    heard = true;
                }
            }
            if heard {
                break;
            }
        }
        assert!(heard, "the settlement never reached the front's consumer");
        assert!(
            bridge.read().unwrap().current_pool_wide().is_none(),
            "the front must have NO current distribution left — one that survives \
             a settlement pays its pre-settlement balances a second time"
        );
        server.shutdown().await;
    }
}
