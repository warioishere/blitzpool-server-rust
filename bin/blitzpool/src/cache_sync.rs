// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-process routing-cache sync: API writers publish membership
//! invalidations to `cache:invalidate` ([`StreamCacheNotifier`]), the Front
//! rebuilds the matching cache plus a timed backstop ([`spawn`]). The stream
//! also carries [`cache_kind::SETTLEMENT`], see [`crate::settlement`].

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bp_blockparty_engine::BlockpartyService;
use bp_group_mgmt_engine::MembershipChangeNotifier;
use bp_share_hook::MinerAdmission;
use bp_share_stream::{
    cache_kind, CacheInvalidation, StreamConsumer, StreamProducer, CACHE_INVALIDATION_STREAM_KEY,
};
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use bp_common::AddressId;
use bp_mining_mode::MiningModeResult;

use crate::coinbase_tags::CoinbaseTagCache;
use crate::engines::BlitzpoolModeGate;
use crate::group_service::SharedGroupService;
use crate::membership::{membership_mode, BlockpartyAdminLookup, GroupLookup};

/// Consumer group for the Front's invalidation drain. ⚠️ Exactly ONE front
/// may consume it: a group splits entries between consumers, and a missed
/// [`cache_kind::SETTLEMENT`] (no backstop) keeps a pre-settlement payout
/// distribution current. More fronts need a group each or a plain `XREAD`.
const GROUP: &str = "cache-sync-front";
const CONSUMER: &str = "c1";
const BATCH: usize = 32;
const BLOCK_MS: usize = 1000;
const ERROR_BACKOFF: Duration = Duration::from_millis(500);
/// Full-rebuild safety net for any invalidation the consumer missed.
/// Membership changes are not latency-critical; the stream handles the
/// common case instantly.
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
    membership: &crate::membership::Membership,
    pool: PgPool,
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
    let blockparty = membership.blockparty_service();
    let coinbase_tags = membership.coinbase_tags.clone();
    let sync = MembershipSync {
        group: membership.group.clone(),
        blockparty,
        admission: membership.admission(),
        gate,
        kicks: membership.session_kicks.clone(),
    };
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
                    let fresh = rebuild_group(&sync.group).await
                        & rebuild_blockparty(sync.blockparty.as_ref()).await;
                    if fresh {
                        sync.kick_moved_sessions().await;
                    }
                    rebuild_coinbase_tags(&coinbase_tags, &pool).await;
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
                        // Coalesce: one rebuild per kind per batch, then one
                        // kick pass over the rebuilt caches.
                        let mut fresh = true;
                        if want_group {
                            fresh &= rebuild_group(&sync.group).await;
                        }
                        if want_blockparty {
                            fresh &= rebuild_blockparty(sync.blockparty.as_ref()).await;
                        }
                        if (want_group || want_blockparty) && fresh {
                            sync.kick_moved_sessions().await;
                        }
                        // Teams and Blockpartys both set a tag.
                        if want_group || want_blockparty {
                            rebuild_coinbase_tags(&coinbase_tags, &pool).await;
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

/// ext 0x0003/Implementation Notes: a block settled on another process.
/// Every distribution this Front published encodes pre-settlement balances,
/// so their acceptance window closes now; declaring against them would pay
/// those balances twice.
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

/// `false` when the rebuild failed, so no kick acts on a stale cache.
async fn rebuild_group(group: &SharedGroupService) -> bool {
    match group.service.rebuild_cache().await {
        Ok(()) => {
            info!("cache-sync: group address cache rebuilt");
            true
        }
        Err(err) => {
            warn!(%err, "cache-sync: group cache rebuild failed");
            false
        }
    }
}

/// What a rebuild and its kick pass read: the routing caches, the admission
/// and the connected sessions' modes.
struct MembershipSync {
    group: SharedGroupService,
    blockparty: Option<Arc<BlockpartyService>>,
    admission: Arc<dyn MinerAdmission>,
    gate: Arc<BlitzpoolModeGate>,
    kicks: broadcast::Sender<String>,
}

impl MembershipSync {
    async fn kick_moved_sessions(&self) {
        kick_moved_sessions(
            &self.gate,
            &*self.group.service,
            self.blockparty
                .as_deref()
                .map(|bp| bp as &dyn BlockpartyAdminLookup),
            &*self.admission,
            &self.kicks,
        )
        .await;
    }
}

/// Whether a connection mining in `current` must close because a membership
/// change moved it: `membership` is what its memberships give it now (an
/// active team, the admin of a routable party), `refused` whether admission
/// refuses it now. A port-mode connection stays only while it has neither.
fn mode_moved(
    current: MiningModeResult,
    membership: Option<MiningModeResult>,
    refused: bool,
) -> bool {
    match current {
        MiningModeResult::GroupSolo(_) | MiningModeResult::Blockparty(_) => {
            membership != Some(current)
        }
        MiningModeResult::Solo | MiningModeResult::Pplns => membership.is_some() || refused,
    }
}

/// Close every connection whose mode a membership change moved, so it
/// reconnects into its new mode and template stream together, or is refused.
async fn kick_moved_sessions(
    gate: &BlitzpoolModeGate,
    group: &dyn GroupLookup,
    blockparty: Option<&dyn BlockpartyAdminLookup>,
    admission: &dyn MinerAdmission,
    kicks: &broadcast::Sender<String>,
) {
    let mut kicked = 0u32;
    for (address, current) in gate.connected() {
        let Ok(address_id) = AddressId::new(address.clone()) else {
            continue;
        };
        let membership = membership_mode(group, blockparty, &address_id).await;
        let refused = admission.refusal(&address).await.is_some();
        if mode_moved(current, membership, refused) {
            // Errs only without a connection listening, which is fine.
            let _ = kicks.send(address);
            kicked += 1;
        }
    }
    if kicked > 0 {
        info!(kicked, "cache-sync: closed connections whose mode changed");
    }
}

async fn rebuild_coinbase_tags(tags: &CoinbaseTagCache, pool: &PgPool) {
    match tags.rebuild(pool).await {
        Ok(()) => debug!("cache-sync: coinbase tags rebuilt"),
        Err(err) => warn!(%err, "cache-sync: coinbase tag rebuild failed"),
    }
}

/// `false` when the rebuild failed, so no kick acts on a stale cache.
async fn rebuild_blockparty(blockparty: Option<&Arc<BlockpartyService>>) -> bool {
    let Some(bp) = blockparty else {
        return true;
    };
    match bp.rebuild_cache().await {
        Ok(()) => {
            info!("cache-sync: blockparty routing cache rebuilt");
            true
        }
        Err(err) => {
            warn!(%err, "cache-sync: blockparty cache rebuild failed");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bp_test_support::{connect_redis_in_range_or_skip, redis_db};

    /// A team or party connection stays only while that same membership
    /// holds; a port-mode connection stays only while it has no membership
    /// and is not refused.
    #[test]
    fn a_connection_closes_exactly_when_its_membership_moved() {
        let team = MiningModeResult::GroupSolo(uuid::Uuid::new_v4());
        let other_team = MiningModeResult::GroupSolo(uuid::Uuid::new_v4());
        let party = MiningModeResult::Blockparty(uuid::Uuid::new_v4());
        for port in [MiningModeResult::Solo, MiningModeResult::Pplns] {
            assert!(!mode_moved(port, None, false), "nothing changed");
            assert!(mode_moved(port, Some(team), false), "joined a team");
            assert!(
                mode_moved(port, Some(party), false),
                "its party became Ready"
            );
            assert!(
                mode_moved(port, None, true),
                "it now administers an unready party"
            );
        }
        assert!(!mode_moved(team, Some(team), false), "still in the team");
        assert!(mode_moved(team, None, false), "left the team");
        assert!(
            mode_moved(team, Some(other_team), false),
            "moved to another team"
        );
        assert!(
            !mode_moved(party, Some(party), false),
            "the party still routes"
        );
        assert!(mode_moved(party, None, false), "the party was dissolved");
    }

    /// Fixed memberships and refusals, standing in for the routing caches.
    struct Fixed {
        teams: std::collections::HashMap<&'static str, uuid::Uuid>,
        parties: std::collections::HashMap<&'static str, uuid::Uuid>,
        refused: Vec<&'static str>,
    }
    #[async_trait]
    impl GroupLookup for Fixed {
        async fn group_for_address(&self, address: &AddressId) -> Option<uuid::Uuid> {
            self.teams.get(address.as_str()).copied()
        }
    }
    #[async_trait]
    impl BlockpartyAdminLookup for Fixed {
        async fn routable_group_id_for_admin(&self, address: &AddressId) -> Option<uuid::Uuid> {
            self.parties.get(address.as_str()).copied()
        }
    }
    #[async_trait]
    impl MinerAdmission for Fixed {
        async fn refusal(&self, address: &str) -> Option<bp_share_hook::AdmissionRefusal> {
            self.refused
                .contains(&address)
                .then_some(bp_share_hook::AdmissionRefusal::BlockpartyNotReady)
        }
    }

    /// The kick pass reads each connected address's mode from the gate and
    /// its memberships from the caches, and kicks exactly the moved ones.
    #[tokio::test]
    async fn the_kick_pass_kicks_exactly_the_connections_whose_mode_moved() {
        const STAYS_SOLO: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        const JOINED: &str = "bcrt1qvs8k07ggszru23v9p42vpg4jxts9y2k8kkujja";
        const STAYS_TEAM: &str = "bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9t";
        const LEFT_TEAM: &str = "bcrt1qqgpqyqszqgpqyqszqgpqyqszqgpqyqszazmwwa";
        const NOW_UNREADY_ADMIN: &str = "bcrt1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcruj60yu";
        const STAYS_PARTY: &str = "bcrt1qqszqgpqyqszqgpqyqszqgpqyqszqgpqyuza2rq";
        let team = uuid::Uuid::new_v4();
        let party = uuid::Uuid::new_v4();
        let gate = BlitzpoolModeGate::new();
        gate.set_mode(STAYS_SOLO, MiningModeResult::Solo);
        gate.set_mode(JOINED, MiningModeResult::Pplns);
        gate.set_mode(STAYS_TEAM, MiningModeResult::GroupSolo(team));
        gate.set_mode(LEFT_TEAM, MiningModeResult::GroupSolo(team));
        gate.set_mode(NOW_UNREADY_ADMIN, MiningModeResult::Solo);
        gate.set_mode(STAYS_PARTY, MiningModeResult::Blockparty(party));
        let caches = Fixed {
            teams: [(JOINED, team), (STAYS_TEAM, team)].into(),
            parties: [(STAYS_PARTY, party)].into(),
            refused: vec![NOW_UNREADY_ADMIN],
        };
        for address in [
            STAYS_SOLO,
            JOINED,
            STAYS_TEAM,
            LEFT_TEAM,
            NOW_UNREADY_ADMIN,
            STAYS_PARTY,
        ] {
            assert!(
                AddressId::new(address.to_string()).is_ok(),
                "precondition: {address} parses"
            );
        }
        let (kicks, mut rx) = broadcast::channel(16);

        kick_moved_sessions(&gate, &caches, Some(&caches), &caches, &kicks).await;

        let mut kicked = Vec::new();
        while let Ok(address) = rx.try_recv() {
            kicked.push(address);
        }
        kicked.sort();
        let mut expected = vec![JOINED, LEFT_TEAM, NOW_UNREADY_ADMIN];
        expected.sort();
        assert_eq!(kicked, expected);
    }

    /// Published `group` + `blockparty` invalidations read back intact.
    #[tokio::test]
    async fn notifier_publishes_invalidations_a_consumer_reads() {
        let Some(redis) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 12).await else {
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

    /// The constraint behind [`GROUP`]: two consumers in ONE group split the entries.
    #[tokio::test]
    async fn two_consumers_in_one_group_split_the_entries() {
        let Some(redis) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 1).await else {
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

    /// MONEY: a settlement on `payout` invalidates the registry on `front`.
    #[tokio::test]
    async fn a_settlement_on_one_process_invalidates_the_registry_on_another() {
        use bp_stratum_v2::bridge::{JdpDeclaredJobRegistry, PayoutDistributionEntry};
        use bp_stratum_v2::jdp::payout_distribution::WeightedOutput;
        use bp_stratum_v2::jdp_server::{JdpServerHooks, StratumV2JdpServer};
        use bp_stratum_v2::noise::NoiseConfig;

        // DB 16 is this test's own; siblings in this binary FLUSHDB theirs.
        // The publish+read below retries, so a wipe costs a round while a
        // broken mechanism never produces an entry.
        let Some(redis) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 16).await else {
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
                built: bp_stratum_v2::bridge::BuiltPayoutDistribution {
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
                },
                accounting: bp_stratum_v2::bridge::DistributionAccounting::PoolWide,
                jdp_session_id: None,
                published_at_ms: 1_001,
            });
        let noise = NoiseConfig::new(
            "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
                .parse()
                .unwrap(),
            "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
                .parse()
                .unwrap(),
        );
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
