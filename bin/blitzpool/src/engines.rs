// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine spawning and share-sink composition on top of [`FoundationHandles`].
//! The front resolves each share's mode once through [`BlitzpoolModeGate`]
//! and stamps it onto the share ([`CompositeAcceptedShareSink`]), so the
//! Satellite sinks, which hold no gate, read it off the stream.

use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bp_blockparty_engine::{BlockpartyPayoutConfig, BlockpartyPayouts};
use bp_common::{AddressId, Sats};
use bp_config::{AppConfig, PplnsConfig as TomlPplnsConfig, Role};
use bp_group_solo_engine::config::GroupSoloEngineConfig;
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_group_solo_engine::hooks::{GroupSoloAcceptedShareSink, GroupSoloRejectedShareSink};
use bp_mining_mode::MiningModeResult;
use bp_pplns_engine::config::PplnsEngineConfig;
use bp_pplns_engine::engine::PplnsEngine;
use bp_pplns_engine::hooks::PplnsAcceptedShareSink;
use bp_pplns_engine::window::NetworkDifficulty;
use bp_session_persistence::{
    SessionPersistenceConfig, SessionPersistenceEngine, SessionPersistenceEngineHandle,
    SessionPersistenceHook,
};
use bp_share_hook::{
    ShareSequencer, SharedAcceptedShare, SharedAcceptedShareSink, SharedRejectedShare,
    SharedRejectedShareSink,
};
use bp_share_stats_sink::config::StatsSinkConfig;
use bp_share_stats_sink::engine::{ShareStatsEngine, ShareStatsEngineHandle};
use bp_share_stats_sink::hooks::{ShareStatsAcceptedSink, ShareStatsRejectedSink};
use bp_share_stream::{
    ProducingRejectedSink, ProducingSink, StreamProducer, ACCEPTED_STREAM_KEY, REJECTED_STREAM_KEY,
};
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

use crate::boot::FoundationHandles;

pub(crate) struct EngineHandles {
    pub(crate) pplns: Option<PplnsEngine>,
    pub(crate) group_solo: Option<GroupSoloEngine>,
    pub(crate) stats: ShareStatsEngineHandle,
    pub(crate) session_persistence: SessionPersistenceEngineHandle,
    pub(crate) mode_gate: Arc<BlitzpoolModeGate>,
    /// The front's sinks that stamp each share and publish it to the stream.
    /// `None` off the front, where the consumer builds its own sinks.
    pub(crate) accepted_sink: Option<Arc<CompositeAcceptedShareSink>>,
    pub(crate) rejected_sink: Option<Arc<dyn SharedRejectedShareSink>>,
    pub(crate) session_persistence_hook: SessionPersistenceHook,
    /// The DB-only Blockparty half every role may hold; `None` unless
    /// Blockparty is configured. The cache-carrying service is front/API
    /// only, see [`crate::membership::Membership`].
    pub(crate) blockparty_payouts: Option<BlockpartyPayouts>,
}

#[derive(Debug, Error)]
pub(crate) enum EngineError {
    #[error("pplns engine spawn failed: {0}")]
    Pplns(#[from] bp_pplns_engine::engine::EngineError),
    #[error("pplns config invalid: {0}")]
    PplnsConfig(#[from] bp_pplns_engine::config::ConfigError),
    #[error("group-solo engine spawn failed: {0}")]
    GroupSolo(#[from] bp_group_solo_engine::engine::EngineError),
    #[error("group-solo config invalid: {0}")]
    GroupSoloConfig(#[from] bp_group_solo_engine::config::ConfigError),
    #[error(
        "group-solo is disabled (no [group_solo] table in config) but {count} active \
         group(s) exist; their members would mine as Solo. Add an empty [group_solo] \
         table to keep them, or dissolve the groups first"
    )]
    GroupSoloDisabledWithActiveGroups { count: usize },
    #[error("group-solo: active-group check failed: {0}")]
    GroupSoloActiveGroups(#[from] bp_db::DbError),
    #[error("share-stats engine spawn failed: {0}")]
    Stats(#[from] bp_share_stats_sink::error::SinkError),
    #[error("session-persistence engine spawn failed: {0}")]
    SessionPersistence(#[from] bp_session_persistence::error::SessionPersistenceError),
    #[error("invalid bitcoin address {0:?}: {1}")]
    InvalidAddress(String, bp_common::InvalidAddressError),
    #[error("core epoch fetch (INCR core:epoch) failed: {0}")]
    CoreEpoch(#[from] redis::RedisError),
}

/// Per-boot share-id epoch, so share_ids (the dedup key, see
/// [`ShareSequencer`]) stay unique across Core restarts. A failure is fatal
/// rather than risking a silent id collision.
async fn fetch_core_epoch(redis: &redis::aio::ConnectionManager) -> Result<u64, EngineError> {
    let mut conn = redis.clone();
    let epoch: u64 = redis::cmd("INCR")
        .arg("core:epoch")
        .query_async(&mut conn)
        .await?;
    Ok(epoch)
}

/// Spawn the engines and, on the front, the producing share sinks. Only the
/// `payout` role runs ledger-mutating crons; every other process reads.
pub(crate) async fn spawn(
    cfg: &AppConfig,
    handles: &FoundationHandles,
) -> Result<EngineHandles, EngineError> {
    let read_only = !cfg.has_role(Role::Payout);
    let mode_gate = Arc::new(BlitzpoolModeGate::new());
    let pplns = spawn_pplns(cfg, handles, read_only).await?;
    let group_solo = spawn_group_solo(cfg, handles, read_only).await?;
    let stats = spawn_stats(handles).await?;
    let session_persistence = spawn_session_persistence(handles).await?;
    let blockparty_payouts = blockparty_payouts(cfg, handles)?;

    let (accepted_sink, rejected_sink) = if cfg.has_role(Role::Front) {
        let core_epoch = fetch_core_epoch(&handles.redis).await?;
        let accepted =
            build_producing_composite(mode_gate.clone(), handles.redis.clone(), core_epoch);
        let rejected = build_producing_rejected_composite(mode_gate.clone(), handles.redis.clone());
        (Some(accepted), Some(rejected))
    } else {
        (None, None)
    };
    let session_persistence_hook = session_persistence.session_persistence_hook();

    info!(
        pplns_enabled = pplns.is_some(),
        group_solo_enabled = group_solo.is_some(),
        read_only,
        roles = ?cfg.effective_roles(),
        "engines ready"
    );
    Ok(EngineHandles {
        pplns,
        group_solo,
        stats,
        session_persistence,
        mode_gate,
        accepted_sink,
        rejected_sink,
        session_persistence_hook,
        blockparty_payouts,
    })
}

// ─── PPLNS engine ────────────────────────────────────────────────

async fn spawn_pplns(
    cfg: &AppConfig,
    handles: &FoundationHandles,
    core: bool,
) -> Result<Option<PplnsEngine>, EngineError> {
    let Some(toml_cfg) = cfg.pplns.as_ref() else {
        info!("pplns: disabled (no [pplns] table in config)");
        return Ok(None);
    };
    let engine_cfg = to_pplns_engine_config(toml_cfg, cfg.network)?;
    let net_diff = bootstrap_network_difficulty(handles).await;
    info!(
        net_diff = %net_diff.get(),
        fee_percent = engine_cfg.fee_percent,
        core,
        "pplns: spawning engine"
    );
    let redis = handles.redis.clone();
    let pool = handles.db.pool().clone();
    // `spawn_core` runs no ledger-mutating crons, but the constructor's
    // one-shot window passes run in every role; `PplnsEngine::spawn_inner`
    // says why.
    let engine = if core {
        PplnsEngine::spawn_core(engine_cfg, redis, pool, net_diff).await?
    } else {
        PplnsEngine::spawn(engine_cfg, redis, pool, net_diff).await?
    };
    Ok(Some(engine))
}

/// Must be the network's real schedule: settlement refuses a coinbase paying
/// less than the block's subsidy, so a wrong interval makes regtest blocks
/// past height 150 look underpaid.
fn subsidy_halving_interval(network: bp_config::Network) -> u32 {
    match network {
        bp_config::Network::Regtest => bp_share::REGTEST_SUBSIDY_HALVING_INTERVAL,
        bp_config::Network::Mainnet
        | bp_config::Network::Testnet
        | bp_config::Network::Testnet4 => bp_share::SUBSIDY_HALVING_INTERVAL,
    }
}

fn to_pplns_engine_config(
    cfg: &TomlPplnsConfig,
    network: bp_config::Network,
) -> Result<PplnsEngineConfig, EngineError> {
    let fee_address = if cfg.fee_address.trim().is_empty() {
        None
    } else {
        Some(
            AddressId::new(cfg.fee_address.trim().to_string())
                .map_err(|e| EngineError::InvalidAddress(cfg.fee_address.clone(), e))?,
        )
    };
    let base = PplnsEngineConfig {
        fee_address,
        fee_percent: cfg.fee_percent,
        min_payout_sats: Sats(cfg.min_payout_sats),
        coinbase_weight_budget: cfg.coinbase_weight_budget,
        min_difficulty: cfg.min_difficulty,
        dust_sweep_enabled: cfg.dust_sweep_enabled,
        abandoned_balance_days: cfg.abandoned_balance_days,
        bucket_shares: cfg.bucket_shares,
        subsidy_halving_interval: subsidy_halving_interval(network),
        ..PplnsEngineConfig::default()
    };
    let validated = base.try_new()?;
    Ok(validated)
}

/// Falls back to `1.0` so the engine still spawns; the window is under-sized
/// until the payout role's refresh.
async fn bootstrap_network_difficulty(handles: &FoundationHandles) -> NetworkDifficulty {
    match handles.bitcoin_rpc.get_mining_info().await {
        Ok(info) => NetworkDifficulty::new(info.difficulty),
        Err(err) => {
            warn!(
                %err,
                "bitcoin rpc getmininginfo failed; pplns starting with net_diff = 1.0"
            );
            NetworkDifficulty::new(1.0)
        }
    }
}

// ─── Group-Solo engine ───────────────────────────────────────────

async fn spawn_group_solo(
    cfg: &AppConfig,
    handles: &FoundationHandles,
    core: bool,
) -> Result<Option<GroupSoloEngine>, EngineError> {
    let Some(gs_cfg) = cfg.group_solo.as_ref() else {
        // Switching the mode off must not silently turn existing groups'
        // members into Solo miners.
        let active = bp_db::list_active_pplns_groups(handles.db.pool()).await?;
        if !active.is_empty() {
            return Err(EngineError::GroupSoloDisabledWithActiveGroups {
                count: active.len(),
            });
        }
        info!("group-solo: disabled (no [group_solo] table in config)");
        return Ok(None);
    };
    let engine_cfg = to_group_solo_engine_config(gs_cfg, cfg.network)?;
    info!(
        fee_percent = engine_cfg.fee_percent,
        core, "group-solo: spawning engine"
    );
    let redis = handles.redis.clone();
    let pool = handles.db.pool().clone();
    let engine = if core {
        GroupSoloEngine::spawn_core(engine_cfg, redis, pool).await?
    } else {
        GroupSoloEngine::spawn(engine_cfg, redis, pool).await?
    };
    Ok(Some(engine))
}

fn to_group_solo_engine_config(
    cfg: &bp_config::GroupSoloConfig,
    network: bp_config::Network,
) -> Result<GroupSoloEngineConfig, EngineError> {
    let base = GroupSoloEngineConfig {
        fee_address: Some(mode_fee_address(&cfg.fee_address)?),
        fee_percent: cfg.fee_percent,
        // Must equal the budget boot reserves on the Group-Solo TDP stream, or
        // the coinbase outgrows Core's reservation and the block is rejected.
        coinbase_weight_budget: cfg.coinbase_weight_budget,
        subsidy_halving_interval: subsidy_halving_interval(network),
        min_payout_sats: Sats(cfg.min_payout_sats),
    };
    let validated = base.try_new()?;
    Ok(validated)
}

/// A mode section's required fee address.
fn mode_fee_address(raw: &str) -> Result<AddressId, EngineError> {
    AddressId::new(raw.trim().to_string())
        .map_err(|e| EngineError::InvalidAddress(raw.to_string(), e))
}

// ─── Blockparty payouts ──────────────────────────────────────────

fn blockparty_payouts(
    cfg: &AppConfig,
    handles: &FoundationHandles,
) -> Result<Option<BlockpartyPayouts>, EngineError> {
    let Some(bp_cfg) = cfg.blockparty.as_ref() else {
        info!("blockparty: feature disabled (no `[blockparty]` config block)");
        return Ok(None);
    };
    Ok(Some(BlockpartyPayouts::new(
        handles.db.pool().clone(),
        BlockpartyPayoutConfig {
            fee_address: Some(mode_fee_address(&bp_cfg.fee_address)?),
            fee_percent: bp_cfg.fee_percent,
            min_payout_sats: Sats(bp_cfg.min_payout_sats),
        },
    )))
}

// ─── ShareStats engine ───────────────────────────────────────────

async fn spawn_stats(handles: &FoundationHandles) -> Result<ShareStatsEngineHandle, EngineError> {
    let cfg = StatsSinkConfig {
        // Spreads the 60 s loops across the minute.
        tick_offset: crate::crons::offsets::STATS_SINK_FLUSH,
        ..StatsSinkConfig::default()
    };
    info!(
        flush_interval = ?cfg.flush_interval,
        seed_on_spawn = cfg.seed_on_spawn,
        tick_offset = ?cfg.tick_offset,
        "share-stats: spawning engine"
    );
    let handle = ShareStatsEngine::spawn(cfg, handles.db.pool().clone()).await?;
    Ok(handle)
}

// ─── Session-persistence engine ──────────────────────────────────

async fn spawn_session_persistence(
    handles: &FoundationHandles,
) -> Result<SessionPersistenceEngineHandle, EngineError> {
    let cfg = SessionPersistenceConfig {
        // Same duration as the sweep's staleness cutoff, but this TTL runs
        // from the last touch flush, the cutoff from the row's birth: the
        // key is the liveness signal, the age only a birth grace.
        live_ttl: crate::crons::STALE_CLIENT_TTL,
        ..SessionPersistenceConfig::default()
    };
    info!(
        live_ttl_secs = cfg.live_ttl.as_secs(),
        "session-persistence: spawning engine"
    );
    // Shared manager: the live-hash scripts are short and non-blocking.
    let handle = SessionPersistenceEngine::spawn(
        cfg,
        handles.db.pool().clone(),
        Some(handles.redis.clone()),
    )
    .await?;
    Ok(handle)
}

// ─── BlitzpoolModeGate (sync address→mode cache) ──

/// Address → mode, set on authorize; unknown addresses read as `Solo`.
/// Refcounted per connection so one disconnect cannot clear a mode other
/// connections of the same address rely on; the mode itself is
/// last-write-wins, so a re-authorize picks up a membership change.
pub(crate) struct BlitzpoolModeGate {
    inner: Mutex<HashMap<String, RefcountedMode>>,
}

#[derive(Debug, Clone)]
struct RefcountedMode {
    mode: MiningModeResult,
    count: usize,
}

impl BlitzpoolModeGate {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn set_mode(&self, address: &str, result: MiningModeResult) {
        let mut guard = self.inner.lock().expect("mode-gate mutex poisoned");
        guard
            .entry(address.to_string())
            .and_modify(|e| {
                e.mode = result;
                e.count += 1;
            })
            .or_insert(RefcountedMode {
                mode: result,
                count: 1,
            });
    }

    pub(crate) fn clear_mode(&self, address: &str) {
        let mut guard = self.inner.lock().expect("mode-gate mutex poisoned");
        if let Some(entry) = guard.get_mut(address) {
            if entry.count <= 1 {
                guard.remove(address);
            } else {
                entry.count -= 1;
            }
        }
    }

    /// Solo when the gate has never been told.
    pub(crate) fn lookup_mode(&self, address: &str) -> MiningModeResult {
        self.lookup_known(address).unwrap_or(MiningModeResult::Solo)
    }

    /// `None` without a live session, which differs from Solo: the port is the
    /// only Solo-vs-PPLNS declaration, so [`Self::lookup_mode`]'s default is a
    /// guess. Callers acting before the session exists (JDP allocate, which
    /// precedes the mining channel) must use this.
    pub(crate) fn lookup_known(&self, address: &str) -> Option<MiningModeResult> {
        let guard = self.inner.lock().expect("mode-gate mutex poisoned");
        guard.get(address).map(|e| e.mode)
    }

    /// Solo records no payout rows, so a Solo block without them is normal;
    /// in every other mode a missing row is a real miss.
    pub(crate) fn keeps_a_payout_ledger(&self, address: &str) -> bool {
        !matches!(self.lookup_mode(address), MiningModeResult::Solo)
    }

    /// Group-Solo `group_id` only: a Blockparty address carries one too, but
    /// it is not a Group-Solo group.
    pub(crate) fn group_for_address(&self, address: &str) -> Option<Uuid> {
        match self.lookup_mode(address) {
            MiningModeResult::GroupSolo(g) => Some(g),
            MiningModeResult::Solo | MiningModeResult::Pplns | MiningModeResult::Blockparty(_) => {
                None
            }
        }
    }

    /// Connected `Solo` / `GroupSolo` addresses: the only modes a membership
    /// change flips.
    pub(crate) fn group_transition_candidates(&self) -> Vec<(String, MiningModeResult)> {
        let guard = self.inner.lock().expect("mode-gate mutex poisoned");
        guard
            .iter()
            .filter(|(_, e)| {
                matches!(
                    e.mode,
                    MiningModeResult::Solo | MiningModeResult::GroupSolo(_)
                )
            })
            .map(|(a, e)| (a.clone(), e.mode))
            .collect()
    }

    /// Flip a connected address's mode without bumping its refcount. A no-op
    /// for an unconnected address, so a disconnected entry is never resurrected.
    pub(crate) fn override_mode(&self, address: &str, result: MiningModeResult) {
        let mut guard = self.inner.lock().expect("mode-gate mutex poisoned");
        if let Some(e) = guard.get_mut(address) {
            e.mode = result;
        }
    }
}

// ─── Composite share sinks ───────────────────────────────────────

/// Fan-out of [`SharedAcceptedShareSink`]; sequential so ordering stays
/// deterministic. The single point every share crosses, so `share_id` and
/// mode are stamped here.
pub(crate) struct CompositeAcceptedShareSink {
    /// [`ArcSwap`] so a startup [`Self::push`] needs no lock on the per-share
    /// path, and the snapshot can be held across the fan-out's `await`s.
    sinks: ArcSwap<Vec<Arc<dyn SharedAcceptedShareSink>>>,
    sequencer: ShareSequencer,
    gate: Arc<BlitzpoolModeGate>,
}

impl CompositeAcceptedShareSink {
    /// One-shot startup wiring. Copy-on-write, so readers mid-fan-out keep
    /// their own consistent snapshot.
    pub(crate) fn push(&self, sink: Arc<dyn SharedAcceptedShareSink>) {
        let mut next = Vec::clone(&self.sinks.load_full());
        next.push(sink);
        self.sinks.store(Arc::new(next));
    }
}

#[async_trait]
impl SharedAcceptedShareSink for CompositeAcceptedShareSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        let snapshot = self.sinks.load_full();
        // Stamped before any sink sees the share: dedup keys on share_id,
        // mode-gated sinks read share.mode.
        let share_id = self.sequencer.next_id();
        let resolved = self.gate.lookup_mode(share.address);
        let mut group_buf = Uuid::encode_buffer();
        let share = SharedAcceptedShare {
            share_id: &share_id,
            mode: resolved.mode(),
            group_id: resolved
                .group_id()
                .map(|g| &*g.hyphenated().encode_lower(&mut group_buf)),
            ..share
        };
        for (i, sink) in snapshot.iter().enumerate() {
            // An inline sink blocks the connection loop while it runs.
            let t0 = std::time::Instant::now();
            sink.record_accepted(share).await;
            let us = t0.elapsed().as_micros();
            if us >= 100_000 {
                tracing::warn!(sink_index = i, us, "accepted-share sink slow");
            }
        }
    }
}

pub(crate) struct CompositeRejectedShareSink {
    sinks: Vec<Arc<dyn SharedRejectedShareSink>>,
    /// Stamps `group_id` here, the only side holding the gate.
    gate: Arc<BlitzpoolModeGate>,
}

#[async_trait]
impl SharedRejectedShareSink for CompositeRejectedShareSink {
    async fn record_rejected(&self, share: SharedRejectedShare<'_>) {
        // Group-Solo only: a Blockparty reject must not reach that engine.
        let group_id = share
            .address
            .and_then(|addr| self.gate.group_for_address(addr))
            .map(|u| u.to_string());
        let share = SharedRejectedShare {
            group_id: group_id.as_deref(),
            ..share
        };
        for sink in &self.sinks {
            sink.record_rejected(share).await;
        }
    }
}

/// Accepted-share sinks split into the two consumer groups of
/// [`crate::satellite_consumer`].
pub(crate) struct AcceptedSinkSet {
    /// PPLNS + Group-Solo window writes: order-sensitive (window order is
    /// consume order), so one ordered, exactly-once consumer.
    pub(crate) money: Vec<Arc<dyn SharedAcceptedShareSink>>,
    /// Order-insensitive; a separate group so a stall never blocks money acks.
    pub(crate) aux: Vec<Arc<dyn SharedAcceptedShareSink>>,
}

pub(crate) fn build_accepted_sinks(
    pplns: Option<&PplnsEngine>,
    group_solo: Option<&GroupSoloEngine>,
    stats: &ShareStatsEngineHandle,
    session_persistence: &SessionPersistenceEngineHandle,
    redis: redis::aio::ConnectionManager,
) -> AcceptedSinkSet {
    let mut money: Vec<Arc<dyn SharedAcceptedShareSink>> = Vec::new();
    if let Some(p) = pplns {
        money.push(Arc::new(PplnsAcceptedShareSink::new(p.clone())));
    }
    if let Some(g) = group_solo {
        money.push(Arc::new(GroupSoloAcceptedShareSink::new(g.clone())));
    }

    let aux: Vec<Arc<dyn SharedAcceptedShareSink>> = vec![
        Arc::new(ShareStatsAcceptedSink::new(stats.accumulators())),
        Arc::new(session_persistence.client_row_touch_sink()),
        Arc::new(crate::live_mode_marker::LiveModeMarkerSink::new(
            redis,
            Arc::new(bp_mining_mode::MarkDebouncer::new()),
        )),
    ];
    AcceptedSinkSet { money, aux }
}

/// Front fan-out: stamp, then publish via [`ProducingSink`]; the Satellite
/// runs the engine sinks off the stream.
fn build_producing_composite(
    gate: Arc<BlitzpoolModeGate>,
    redis: redis::aio::ConnectionManager,
    core_epoch: u64,
) -> Arc<CompositeAcceptedShareSink> {
    let producing: Arc<dyn SharedAcceptedShareSink> = Arc::new(ProducingSink::new(
        StreamProducer::new(redis, ACCEPTED_STREAM_KEY),
    ));
    Arc::new(CompositeAcceptedShareSink {
        sinks: ArcSwap::new(Arc::new(vec![producing])),
        sequencer: ShareSequencer::new(core_epoch),
        gate,
    })
}

pub(crate) fn build_rejected_sinks(
    group_solo: Option<&GroupSoloEngine>,
    stats: &ShareStatsEngineHandle,
) -> Vec<Arc<dyn SharedRejectedShareSink>> {
    let mut sinks: Vec<Arc<dyn SharedRejectedShareSink>> =
        vec![Arc::new(ShareStatsRejectedSink::new(stats.accumulators()))];
    if let Some(g) = group_solo {
        sinks.push(Arc::new(GroupSoloRejectedShareSink::new(g.clone())));
    }
    sinks
}

fn build_producing_rejected_composite(
    gate: Arc<BlitzpoolModeGate>,
    redis: redis::aio::ConnectionManager,
) -> Arc<dyn SharedRejectedShareSink> {
    let producing: Arc<dyn SharedRejectedShareSink> = Arc::new(ProducingRejectedSink::new(
        StreamProducer::new(redis, REJECTED_STREAM_KEY),
    ));
    Arc::new(CompositeRejectedShareSink {
        sinks: vec![producing],
        gate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::MiningMode;
    use bp_share_stream::StreamConsumer;
    use bp_test_support::{connect_redis_in_range_or_skip, redis_db};

    /// Pins regtest's own halving schedule, without which regtest blocks past
    /// height 150 would be refused as underpaid.
    #[test]
    fn regtest_gets_its_own_halving_schedule() {
        assert_eq!(
            subsidy_halving_interval(bp_config::Network::Regtest),
            bp_share::REGTEST_SUBSIDY_HALVING_INTERVAL
        );
        for net in [
            bp_config::Network::Mainnet,
            bp_config::Network::Testnet,
            bp_config::Network::Testnet4,
        ] {
            assert_eq!(
                subsidy_halving_interval(net),
                bp_share::SUBSIDY_HALVING_INTERVAL,
                "{net:?} shares the mainnet schedule"
            );
        }
        let regtest = bp_share::block_subsidy_sats(
            500,
            subsidy_halving_interval(bp_config::Network::Regtest),
        );
        assert_eq!(regtest, 625_000_000, "3 halvings in on regtest");
        assert!(
            regtest
                < bp_share::block_subsidy_sats(
                    500,
                    subsidy_halving_interval(bp_config::Network::Mainnet)
                ),
            "the mainnet schedule would over-state it and gate the block"
        );
    }

    /// Pins that both engines default to the same halving schedule.
    #[test]
    fn both_engine_configs_default_to_the_mainnet_schedule() {
        assert_eq!(
            PplnsEngineConfig::default().subsidy_halving_interval,
            bp_share::SUBSIDY_HALVING_INTERVAL
        );
        assert_eq!(
            bp_group_solo_engine::config::GroupSoloEngineConfig::default().subsidy_halving_interval,
            bp_share::SUBSIDY_HALVING_INTERVAL
        );
    }

    /// Deliberately without `[pplns]`: that is the shape under test.
    const NO_PPLNS_CFG: &str = r#"
        network = "mainnet"
        pool_identifier = "blitzpool"

        [bitcoin_rpc]
        url = "http://127.0.0.1"
        user = "u"
        password = "p"
        port = 8332

        [tdp]
        socket_path = "/var/run/bitcoind/bp-tdp.sock"

        [database]
        host = "localhost"
        user = "postgres"
        password = "postgres"
        database = "public_pool"

        [redis]
        host = "localhost"

        [api]
        port = 3334

        [stratum]
        solo_port = 3333
        solo_start_difficulty = 5000
        solo_high_diff_port = 3339
        high_diff_start_difficulty = 1000000
        job_retention_ms = 90000
        target_shares_per_minute = 6
        high_diff_target_shares_per_minute = 6
        difficulty_check_interval_ms = 60000

        [group_solo]
        fee_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        fee_percent = 1.0
        coinbase_weight_budget = 12000
        min_payout_sats = 7000
    "#;

    /// Group-Solo takes every knob from `[group_solo]`, and a `[pplns]`
    /// section with other values changes none of them.
    #[test]
    fn group_solo_takes_its_config_from_its_own_section() {
        let cfg: bp_config::AppConfig = toml::from_str(&format!(
            "{NO_PPLNS_CFG}\n\
             [pplns]\n\
             port = 3340\n\
             high_diff_port = 3349\n\
             start_difficulty = 5000\n\
             target_shares_per_minute = 12\n\
             fee_address = \"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\"\n\
             fee_percent = 1.5\n\
             coinbase_weight_budget = 35000\n\
             min_difficulty = 500\n\
             min_payout_sats = 12345\n"
        ))
        .expect("parse config");
        let gs = cfg.group_solo.as_ref().expect("fixture enables Group-Solo");

        let built = to_group_solo_engine_config(gs, cfg.network).expect("build");
        assert_eq!(
            built.fee_address.as_ref().map(|a| a.as_str()),
            Some("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        );
        assert_eq!(built.fee_percent, 1.0);
        assert_eq!(built.coinbase_weight_budget, 12_000);
        assert_eq!(built.min_payout_sats, Sats(7_000));
    }

    // ── CompositeAcceptedShareSink: ArcSwap fan-out list ─────────────

    struct CountingSink(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    #[async_trait]
    impl SharedAcceptedShareSink for CountingSink {
        async fn record_accepted(&self, _share: SharedAcceptedShare<'_>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    struct GroupIdSink(std::sync::Mutex<Vec<(MiningMode, Option<String>)>>);

    #[async_trait]
    impl SharedAcceptedShareSink for GroupIdSink {
        async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
            let seen = (share.mode, share.group_id.map(str::to_string));
            self.0.lock().unwrap().push(seen);
        }
    }

    /// Pins the stamped `group_id` to the group's canonical string, the form
    /// the Group-Solo and Blockparty sinks parse back.
    #[tokio::test]
    async fn composite_stamps_the_group_of_both_group_modes() {
        let composite = empty_composite();
        let sink = Arc::new(GroupIdSink(std::sync::Mutex::new(Vec::new())));
        composite.push(sink.clone());
        let (gs, bp) = (Uuid::new_v4(), Uuid::new_v4());
        let addr = test_share().address;

        composite
            .gate
            .set_mode(addr, MiningModeResult::GroupSolo(gs));
        composite.record_accepted(test_share()).await;
        composite
            .gate
            .set_mode(addr, MiningModeResult::Blockparty(bp));
        composite.record_accepted(test_share()).await;
        composite.gate.set_mode(addr, MiningModeResult::Pplns);
        composite.record_accepted(test_share()).await;

        assert_eq!(
            *sink.0.lock().unwrap(),
            vec![
                (MiningMode::GroupSolo, Some(gs.to_string())),
                (MiningMode::Blockparty, Some(bp.to_string())),
                (MiningMode::Pplns, None),
            ]
        );
    }

    fn empty_composite() -> CompositeAcceptedShareSink {
        CompositeAcceptedShareSink {
            sinks: ArcSwap::new(Arc::new(Vec::new())),
            sequencer: ShareSequencer::new(0),
            gate: Arc::new(BlitzpoolModeGate::new()),
        }
    }

    fn test_share() -> SharedAcceptedShare<'static> {
        SharedAcceptedShare {
            address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
            worker: "w1",
            session_id: "sess",
            effective_difficulty: 1.0,
            submission_difficulty: 1.0,
            user_agent: None,
            is_block_candidate: false,
            hash_rate: 0.0,
            channel_count: 1,
            ts_ms: 0,
            share_id: "",
            mode: MiningMode::Solo,
            group_id: None,
        }
    }

    /// Pins that `push` is visible to later reads.
    #[tokio::test]
    async fn composite_push_is_visible_to_later_reads() {
        let composite = empty_composite();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        composite.push(Arc::new(CountingSink(hits.clone())));

        composite.record_accepted(test_share()).await;
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a sink appended via push() must receive subsequent shares"
        );
    }

    /// Pins that every pushed sink receives the share.
    #[tokio::test]
    async fn composite_fans_out_to_every_pushed_sink() {
        let composite = empty_composite();
        let a = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let b = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        composite.push(Arc::new(CountingSink(a.clone())));
        composite.push(Arc::new(CountingSink(b.clone())));

        composite.record_accepted(test_share()).await;
        assert_eq!(a.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(b.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(composite.sinks.load().len(), 2);
    }

    /// Pins that a snapshot taken before a `push` keeps its own view.
    #[test]
    fn composite_push_is_copy_on_write() {
        let composite = empty_composite();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        composite.push(Arc::new(CountingSink(hits.clone())));

        let snapshot = composite.sinks.load_full();
        assert_eq!(snapshot.len(), 1);
        composite.push(Arc::new(CountingSink(hits)));
        assert_eq!(snapshot.len(), 1, "held snapshot must not see the append");
        assert_eq!(composite.sinks.load().len(), 2, "new readers see both");
    }

    /// Pins that the stamped `share_id` and `mode` survive the stream.
    #[tokio::test]
    async fn producing_composite_stamps_and_publishes_to_stream() {
        let Some(conn) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 6).await else {
            return;
        };

        let gate = Arc::new(BlitzpoolModeGate::new());
        let addr = "bc1qproducingsink";
        gate.set_mode(addr, MiningModeResult::Pplns);

        let composite = build_producing_composite(gate, conn.clone(), 7);

        // Adapter-shaped input: the composite must overwrite both fields.
        let share = SharedAcceptedShare {
            address: addr,
            worker: "rig1",
            session_id: "sess1",
            effective_difficulty: 1024.0,
            submission_difficulty: 2048.0,
            user_agent: Some("bitaxe/1.0"),
            is_block_candidate: false,
            hash_rate: 12345.6,
            channel_count: 1,
            ts_ms: 1_700_000_000_000,
            share_id: "",
            mode: MiningMode::Solo,
            group_id: None,
        };
        composite.record_accepted(share).await;

        let consumer = StreamConsumer::accepted(conn, ACCEPTED_STREAM_KEY, "test_money", "c1");
        consumer.ensure_group().await.expect("ensure_group");
        let entries = consumer.read_new(16, 500).await.expect("read_new");
        assert_eq!(entries.len(), 1, "exactly one share published");
        let owned = &entries[0].value;
        assert_eq!(owned.address, addr);
        assert_eq!(owned.mode, MiningMode::Pplns, "mode stamped from gate");
        assert_eq!(owned.group_id, None);
        assert_eq!(owned.share_id, "7:0", "share_id stamped from sequencer");
        assert!((owned.effective_difficulty - 1024.0).abs() < 1e-9);
    }

    fn mode_of(gate: &BlitzpoolModeGate, address: &str) -> MiningMode {
        gate.lookup_mode(address).mode()
    }

    /// Pins that `lookup_known` tells an undecided address apart from Solo,
    /// asserted against `lookup_mode` so the two answers stay distinct.
    #[test]
    fn lookup_known_tells_unknown_apart_from_solo() {
        let gate = BlitzpoolModeGate::new();

        assert_eq!(
            gate.lookup_known("bc1qnobody"),
            None,
            "an address with no mining session is UNDECIDED, not Solo"
        );
        assert_eq!(
            mode_of(&gate, "bc1qnobody"),
            MiningMode::Solo,
            "precondition: the guessing accessor still guesses — otherwise this \
             test would pass with both answers collapsed"
        );

        gate.set_mode("bc1qsolo", MiningModeResult::Solo);
        assert_eq!(
            gate.lookup_known("bc1qsolo").map(|r| r.mode()),
            Some(MiningMode::Solo)
        );

        gate.set_mode("bc1qpplns", MiningModeResult::Pplns);
        assert_eq!(
            gate.lookup_known("bc1qpplns").map(|r| r.mode()),
            Some(MiningMode::Pplns)
        );

        gate.clear_mode("bc1qpplns");
        assert_eq!(gate.lookup_known("bc1qpplns"), None);
    }

    #[test]
    fn mode_gate_defaults_to_solo_for_unknown_address() {
        let gate = BlitzpoolModeGate::new();
        assert_eq!(mode_of(&gate, "bc1qunknown"), MiningMode::Solo);
        assert_eq!(gate.group_for_address("bc1qunknown"), None);
    }

    #[test]
    fn mode_gate_pplns_path() {
        let gate = BlitzpoolModeGate::new();
        gate.set_mode("bc1qpplns", MiningModeResult::Pplns);
        assert_eq!(mode_of(&gate, "bc1qpplns"), MiningMode::Pplns);
        assert_eq!(gate.group_for_address("bc1qpplns"), None);
    }

    #[test]
    fn mode_gate_group_solo_path_extracts_uuid() {
        let gate = BlitzpoolModeGate::new();
        let group_id = Uuid::new_v4();
        gate.set_mode("bc1qgs", MiningModeResult::GroupSolo(group_id));
        assert_eq!(mode_of(&gate, "bc1qgs"), MiningMode::GroupSolo);
        assert_eq!(gate.group_for_address("bc1qgs"), Some(group_id));
    }

    #[test]
    fn mode_gate_clear_drops_the_entry_when_refcount_zero() {
        let gate = BlitzpoolModeGate::new();
        gate.set_mode("bc1q", MiningModeResult::Pplns);
        assert_eq!(mode_of(&gate, "bc1q"), MiningMode::Pplns);
        gate.clear_mode("bc1q");
        assert_eq!(mode_of(&gate, "bc1q"), MiningMode::Solo);
    }

    #[test]
    fn override_mode_flips_connected_solo_to_group_without_touching_refcount() {
        let gate = BlitzpoolModeGate::new();
        gate.set_mode("bc1qsolo", MiningModeResult::Solo);
        gate.set_mode("bc1qpplns", MiningModeResult::Pplns);
        let group_id = Uuid::new_v4();

        let cands = gate.group_transition_candidates();
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].0, "bc1qsolo");
        assert_eq!(cands[0].1, MiningModeResult::Solo);

        gate.override_mode("bc1qsolo", MiningModeResult::GroupSolo(group_id));
        assert_eq!(mode_of(&gate, "bc1qsolo"), MiningMode::GroupSolo);
        assert_eq!(gate.group_for_address("bc1qsolo"), Some(group_id));

        // Refcount untouched: one disconnect still drops the entry.
        gate.clear_mode("bc1qsolo");
        assert_eq!(mode_of(&gate, "bc1qsolo"), MiningMode::Solo);

        gate.override_mode("bc1qabsent", MiningModeResult::GroupSolo(group_id));
        assert_eq!(mode_of(&gate, "bc1qabsent"), MiningMode::Solo);
    }

    #[test]
    fn mode_gate_last_write_wins_on_mode_while_refcount_increments() {
        let gate = BlitzpoolModeGate::new();
        gate.set_mode("bc1q", MiningModeResult::Pplns);
        let group_id = Uuid::new_v4();
        gate.set_mode("bc1q", MiningModeResult::GroupSolo(group_id));
        assert_eq!(mode_of(&gate, "bc1q"), MiningMode::GroupSolo);
        assert_eq!(gate.group_for_address("bc1q"), Some(group_id));
        gate.clear_mode("bc1q");
        assert_eq!(mode_of(&gate, "bc1q"), MiningMode::GroupSolo);
        gate.clear_mode("bc1q");
        assert_eq!(mode_of(&gate, "bc1q"), MiningMode::Solo);
    }

    #[test]
    fn mode_gate_clear_unknown_address_is_noop() {
        let gate = BlitzpoolModeGate::new();
        gate.clear_mode("bc1qnever_seen");
        assert_eq!(mode_of(&gate, "bc1qnever_seen"), MiningMode::Solo);
    }

    #[test]
    fn mode_gate_refcount_balances_under_parallel_connections() {
        // The first disconnect must not drop the mode the second still uses.
        let gate = BlitzpoolModeGate::new();
        gate.set_mode("bc1q", MiningModeResult::Pplns);
        gate.set_mode("bc1q", MiningModeResult::Pplns);
        gate.clear_mode("bc1q");
        assert_eq!(mode_of(&gate, "bc1q"), MiningMode::Pplns);
        gate.clear_mode("bc1q");
        assert_eq!(mode_of(&gate, "bc1q"), MiningMode::Solo);
    }
}
