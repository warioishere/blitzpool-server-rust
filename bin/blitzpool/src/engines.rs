// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine spawning + share-sink composition.
//!
//! Builds the four service-layer engines on top of [`FoundationHandles`]:
//!
//! 1. **PPLNS engine**: only when `[pplns]` is present in the config.
//! 2. **Group-Solo engine**: always; it runs in parallel with PPLNS
//!    regardless of port enablement.
//! 3. **Share-stats engine**: mode-blind accumulator coordinator; always on.
//! 4. **Session-persistence engine**: synchronous PG write-through for
//!    the client + best-difficulty tables; always on.
//!
//! Then composes them into:
//!
//! - **[`CompositeAcceptedShareSink`]** — every accepted share fans out
//!   to the PPLNS sink (mode-gated), the Group-Solo sink (mode-gated),
//!   the ShareStats sink (mode-blind), and the BestDifficulty sink
//!   (mode-blind).
//! - **[`CompositeRejectedShareSink`]** — every rejected share fans out
//!   to the Group-Solo rejected sink (mode-gated) + the ShareStats
//!   rejected sink (mode-blind).
//! - The session-persistence hook is exposed separately because it
//!   binds to a different trait (`SharedSessionPersistence`).
//!
//! ## Mode-gate wiring
//!
//! [`BlitzpoolModeGate`] is a single concrete struct holding a synchronous
//! in-memory map keyed by miner address; each entry caches the last
//! [`MiningModeResult`] resolved for that address. The Stratum-server
//! authorize path publishes `(address → mode)` via [`BlitzpoolModeGate::set_mode`],
//! and the share producer resolves it once per share via
//! [`BlitzpoolModeGate::lookup_mode`] and stamps the mode onto the share, so
//! the per-share sinks read `share.mode` rather than re-querying the gate.
//! The rejected composite likewise stamps each rejected share's Group-Solo
//! `group_id` (via [`BlitzpoolModeGate::group_for_address`]) so its sinks need
//! no gate either. Addresses absent from the cache default to `Solo`.
//!
//! ## Network difficulty bootstrap
//!
//! PPLNS needs an initial [`NetworkDifficulty`] (the `4 * net_diff`
//! window-sizing factor reads it), fetched once at boot via
//! `getmininginfo`; the payout role refreshes it afterwards
//! (`crate::network_difficulty`). On a transient failure it defaults to
//! `1.0` with a warning, and the window is under-sized until the refresh.

use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bp_common::{AddressId, MiningMode, Sats};
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

/// Long-lived engine + sink aggregate, threaded into the Stratum servers
/// and cron schedules.
pub(crate) struct EngineHandles {
    pub(crate) pplns: Option<PplnsEngine>,
    pub(crate) group_solo: GroupSoloEngine,
    pub(crate) stats: ShareStatsEngineHandle,
    pub(crate) session_persistence: SessionPersistenceEngineHandle,
    pub(crate) mode_gate: Arc<BlitzpoolModeGate>,
    /// The front's producing Stratum fan-out sinks: they stamp each share and
    /// publish it onto the Redis stream. `None` off the front, where the
    /// stream consumer builds its own sink set (`build_accepted_sinks`).
    pub(crate) accepted_sink: Option<Arc<CompositeAcceptedShareSink>>,
    pub(crate) rejected_sink: Option<Arc<dyn SharedRejectedShareSink>>,
    pub(crate) session_persistence_hook: SessionPersistenceHook,
    /// Blockparty handle, wired only when the feature is configured; `None`
    /// keeps PayoutResolver + block-sink on the Solo / PPLNS / Group-Solo paths.
    pub(crate) blockparty: Option<Arc<dyn bp_blockparty_engine::BlockpartyApi>>,
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
    #[error("share-stats engine spawn failed: {0}")]
    Stats(#[from] bp_share_stats_sink::error::SinkError),
    #[error("session-persistence engine spawn failed: {0}")]
    SessionPersistence(#[from] bp_session_persistence::error::SessionPersistenceError),
    #[error("invalid bitcoin address {0:?}: {1}")]
    InvalidAddress(String, bp_common::InvalidAddressError),
    #[error("core epoch fetch (INCR core:epoch) failed: {0}")]
    CoreEpoch(#[from] redis::RedisError),
}

/// Fetch this Core process's share-id epoch: `INCR core:epoch`. Unique per
/// boot, so producer share_ids stay globally unique across Core restarts
/// (the dedup discriminator; see [`ShareSequencer`]). A failure is fatal
/// rather than risking a silent id collision.
async fn fetch_core_epoch(redis: &redis::aio::ConnectionManager) -> Result<u64, EngineError> {
    let mut conn = redis.clone();
    let epoch: u64 = redis::cmd("INCR")
        .arg("core:epoch")
        .query_async(&mut conn)
        .await?;
    Ok(epoch)
}

/// Spawn all four engines + build the front's producing share sinks.
///
/// Role-aware (see [`Role`]):
///
/// - A **front** (`front` role) runs the accounting engines *read-only*
///   (`spawn_core`, no ledger-mutating crons) so the `PayoutResolver` can
///   build coinbase distributions. Its accepted- and rejected-share fan-outs
///   are each a single [`ProducingSink`] that publishes every stamped share
///   onto the Redis stream for the Satellite.
/// - The **back** (`payout` / `stats`) spawns the full engines; its share
///   sinks are driven by the stream consumer off `build_accepted_sinks` /
///   `build_rejected_sinks`.
pub(crate) async fn spawn(
    cfg: &AppConfig,
    handles: &FoundationHandles,
) -> Result<EngineHandles, EngineError> {
    // Read-only engines (no ledger-mutating crons) on every process without
    // the `payout` role: the front builds coinbases from them, the API
    // serves reads from them.
    let read_only = !cfg.has_role(Role::Payout);
    let mode_gate = Arc::new(BlitzpoolModeGate::new());
    let pplns = spawn_pplns(cfg, handles, read_only).await?;
    let group_solo = spawn_group_solo(cfg, handles, read_only).await?;
    let stats = spawn_stats(cfg, handles).await?;
    let session_persistence = spawn_session_persistence(handles).await?;

    // Only the front builds the Stratum fan-out sinks (and INCRs
    // `core:epoch`); it always produces to the Redis streams.
    let (accepted_sink, rejected_sink) = if cfg.has_role(Role::Front) {
        let core_epoch = fetch_core_epoch(&handles.redis).await?;
        let accepted =
            build_producing_composite(mode_gate.clone(), handles.redis.clone(), core_epoch);
        // Stamp the group_id (gate) then publish to the rejected stream; the
        // back runs the reject counters off it.
        let rejected = build_producing_rejected_composite(mode_gate.clone(), handles.redis.clone());
        (Some(accepted), Some(rejected))
    } else {
        (None, None)
    };
    let session_persistence_hook = session_persistence.session_persistence_hook();

    info!(
        pplns_enabled = pplns.is_some(),
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
        // Filled in by main.rs after `blockparty_service::spawn`, which
        // needs the GroupService built after the engines.
        blockparty: None,
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
    // Core runs read-only (no touch-flush / dust-sweep crons): it only
    // reads the window for the PayoutResolver's coinbase distributions.
    // The constructor's one-shot window passes still run in every role;
    // `PplnsEngine::spawn_inner` says why.
    let engine = if core {
        PplnsEngine::spawn_core(engine_cfg, redis, pool, net_diff).await?
    } else {
        PplnsEngine::spawn(engine_cfg, redis, pool, net_diff).await?
    };
    Ok(Some(engine))
}

/// Blocks between subsidy halvings for the configured network. The
/// settlement gate refuses to book a coinbase paying less than the
/// block's own subsidy, so this has to be the network's real schedule:
/// regtest halves every 150 blocks, and with the mainnet 210 000 every
/// regtest block past height 150 would look underpaid and not book.
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

/// Best-effort fetch of the current network difficulty for PPLNS
/// window-sizing. Falls back to `1.0` on transient failure (with a
/// `warn`), so the engine can still spawn.
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
) -> Result<GroupSoloEngine, EngineError> {
    let engine_cfg = to_group_solo_engine_config(cfg)?;
    info!(
        fee_percent = engine_cfg.fee_percent,
        core, "group-solo: spawning engine"
    );
    let redis = handles.redis.clone();
    let pool = handles.db.pool().clone();
    // Core runs read-only (no per-group round-reset cron).
    let engine = if core {
        GroupSoloEngine::spawn_core(engine_cfg, redis, pool).await?
    } else {
        GroupSoloEngine::spawn(engine_cfg, redis, pool).await?
    };
    Ok(engine)
}

fn to_group_solo_engine_config(cfg: &AppConfig) -> Result<GroupSoloEngineConfig, EngineError> {
    // Group-Solo + Blockparty share a `[group_fees]` lane independent from
    // PPLNS, falling back to `[pplns]` when it is absent.
    let (fee_address, fee_percent) = crate::blockparty_service::resolve_group_fees(cfg)
        .map_err(|(raw, err)| EngineError::InvalidAddress(raw, err))?;
    let base = GroupSoloEngineConfig {
        fee_address,
        fee_percent,
        // VALIDITY-CRITICAL: the distribution trims the coinbase to this budget,
        // and boot reserves exactly the same budget on the Group-Solo TDP stream
        // (`tdp_constraint_for_budget(cfg.group_fees.coinbase_weight_budget)`).
        // The two MUST be the same value, or the trimmer fits a coinbase larger
        // than bitcoin-core reserved and the block is rejected. Mirrors the
        // PPLNS engine↔default-stream coupling.
        coinbase_weight_budget: cfg.group_fees.coinbase_weight_budget,
        subsidy_halving_interval: subsidy_halving_interval(cfg.network),
        // The `min_payout_sats` floor is shared between PPLNS + Group-Solo:
        // `[pplns]`'s value when configured, else the engine default.
        //
        // NOT `unwrap_or_default()`: that is `Sats(0)`, which fails
        // validation, and the `..GroupSoloEngineConfig::default()` below
        // does not fill a field that is set explicitly.
        min_payout_sats: cfg.pplns.as_ref().map_or_else(
            || GroupSoloEngineConfig::default().min_payout_sats,
            |p| Sats(p.min_payout_sats),
        ),
        ..GroupSoloEngineConfig::default()
    };
    let validated = base.try_new()?;
    Ok(validated)
}

// ─── ShareStats engine ───────────────────────────────────────────

async fn spawn_stats(
    _cfg: &AppConfig,
    handles: &FoundationHandles,
) -> Result<ShareStatsEngineHandle, EngineError> {
    let cfg = StatsSinkConfig {
        // Pull the offset from the bin-level offset table so all 60 s
        // loops are spread across the minute (kill_dead_clients = 0 s,
        // stats_sink_flush = 17 s, best_difficulty = 37 s, …).
        startup_offset: crate::crons::offsets::STATS_SINK_FLUSH,
        ..StatsSinkConfig::default()
    };
    info!(
        flush_interval = ?cfg.flush_interval,
        seed_on_spawn = cfg.seed_on_spawn,
        startup_offset = ?cfg.startup_offset,
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
        // Same duration as the sweep's staleness cutoff, but NOT the same
        // instant: the cutoff runs from the row's birth (updatedAt is only
        // stamped at birth / re-register / soft-delete), while this TTL runs
        // from the last touch flush and is refreshed every 30 s. The age is
        // only a birth grace; the key is the liveness signal.
        live_ttl: crate::crons::STALE_CLIENT_TTL,
        ..SessionPersistenceConfig::default()
    };
    info!(
        live_ttl_secs = cfg.live_ttl.as_secs(),
        "session-persistence: spawning engine"
    );
    // The shared multiplexed manager: the live-hash scripts are short
    // non-blocking commands; dedicated connections are for blocking XREADs.
    let handle = SessionPersistenceEngine::spawn(
        cfg,
        handles.db.pool().clone(),
        Some(handles.redis.clone()),
    )
    .await?;
    Ok(handle)
}

// ─── BlitzpoolModeGate (sync address→mode cache) ──

/// In-memory `(address → MiningModeResult, refcount)` map. The Stratum
/// authorize path calls [`Self::set_mode`] when a miner authorizes on a port
/// (the port's marker drives the mode). Addresses absent from the map
/// default to `Solo`.
///
/// **Refcounting**: each authorize bumps the count for `address`; each
/// disconnect decrements via [`Self::clear_mode`], and the entry is dropped
/// only at zero, so one of several concurrent connections for the same
/// address cannot clear mode information the others still rely on. The mode
/// itself is last-write-wins, so a re-authorize picks up a membership change.
///
/// [`lookup_mode`](Self::lookup_mode) and
/// [`group_for_address`](Self::group_for_address) read the same map. The lock
/// is held only across a single `HashMap::get`, so per-share contention is
/// negligible.
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

    /// Called from the Stratum-server authorize path to publish the resolved
    /// mode for `address`. Increments the refcount; last-write-wins on the
    /// mode itself.
    pub(crate) fn set_mode(&self, address: &str, result: MiningModeResult) {
        let mut guard = self.inner.lock().expect("mode-gate mutex poisoned");
        guard
            .entry(address.to_string())
            .and_modify(|e| {
                e.mode = result.clone();
                e.count += 1;
            })
            .or_insert(RefcountedMode {
                mode: result,
                count: 1,
            });
    }

    /// Called from the Stratum-server disconnect path. Decrements the
    /// refcount and removes the entry at zero. A no-op for an address never
    /// `set_mode`'d.
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

    /// The mode for `address`, Solo when the gate has never been told. The
    /// full `MiningModeResult` (mode + optional group_id), for the share
    /// producer, the payout resolver and block-found.
    pub(crate) fn lookup_mode(&self, address: &str) -> MiningModeResult {
        self.lookup_known(address)
            .unwrap_or_else(MiningModeResult::solo)
    }

    /// The mode ONLY if this address has a live mining session — `None` when
    /// the gate has never been told, which is a different answer from Solo.
    ///
    /// The gate is session-scoped, and for Solo vs PPLNS there is no
    /// persistent record: the port the miner connects to IS the declaration.
    /// So an unknown address is genuinely undecided, and
    /// [`Self::lookup_mode`]'s Solo default is a guess.
    ///
    /// Routing a live connection may use the guess, since a session exists by
    /// then. A caller that acts BEFORE the session exists must not: the JDP
    /// allocate publishes a payout distribution off this answer, and a JDC
    /// allocates before its mining channel opens.
    pub(crate) fn lookup_known(&self, address: &str) -> Option<MiningModeResult> {
        let guard = self.inner.lock().expect("mode-gate mutex poisoned");
        guard.get(address).map(|e| e.mode.clone())
    }

    /// Does this address's payout mode keep a ledger the pool books into?
    ///
    /// Solo does not: it pays straight into the coinbase and records no
    /// payout rows, so a Solo block without them is normal. Every other mode
    /// books, and a missing row there is a real miss.
    pub(crate) fn keeps_a_payout_ledger(&self, address: &str) -> bool {
        !matches!(self.lookup_mode(address).mode, MiningMode::Solo)
    }

    /// Resolve an address to its **Group-Solo** `group_id` — `None` for any
    /// other mode (a Blockparty address carries a group_id too, but it is not
    /// a Group-Solo group). The rejected composite stamps from this filter.
    pub(crate) fn group_for_address(&self, address: &str) -> Option<Uuid> {
        let r = self.lookup_mode(address);
        match r.mode {
            MiningMode::GroupSolo => r.group_id.and_then(|s| Uuid::parse_str(&s).ok()),
            MiningMode::Solo | MiningMode::Pplns | MiningMode::Blockparty => None,
        }
    }

    /// Snapshot the connected addresses currently gated `Solo` or `GroupSolo`,
    /// the only modes the cache-sync reconcile flips on a group-membership
    /// change, as `(address, mode)` pairs.
    pub(crate) fn group_transition_candidates(&self) -> Vec<(String, MiningModeResult)> {
        let guard = self.inner.lock().expect("mode-gate mutex poisoned");
        guard
            .iter()
            .filter(|(_, e)| matches!(e.mode.mode, MiningMode::Solo | MiningMode::GroupSolo))
            .map(|(a, e)| (a.clone(), e.mode.clone()))
            .collect()
    }

    /// Update the cached mode for an **already-connected** address WITHOUT
    /// bumping its refcount. The cache-sync reconcile uses it to flip a live
    /// miner between Solo and Group-Solo on a membership change, without a
    /// reconnect. No-op for an address that isn't connected, so a
    /// disconnected entry is never resurrected.
    pub(crate) fn override_mode(&self, address: &str, result: MiningModeResult) {
        let mut guard = self.inner.lock().expect("mode-gate mutex poisoned");
        if let Some(e) = guard.get_mut(address) {
            e.mode = result;
        }
    }
}

// ─── Composite share sinks ───────────────────────────────────────

/// Fan-out impl of [`SharedAcceptedShareSink`]. Each contained sink
/// receives every accepted share; mode-gating happens internally per
/// sink. A sequential `await` chain keeps the ordering deterministic; the
/// sinks all log-and-continue on internal failure.
pub(crate) struct CompositeAcceptedShareSink {
    /// Copy-on-write behind an [`ArcSwap`] so a one-shot startup append (via
    /// [`Self::push`]) can extend the fan-out after the composite is already
    /// wrapped in `Arc`, **without a lock on the per-share read path**.
    ///
    /// The read path is `load_full()` (one atomic load plus a refcount bump),
    /// and the resulting `Arc` is held across the `await`s of the fan-out,
    /// where a `std` guard could not be held.
    sinks: ArcSwap<Vec<Arc<dyn SharedAcceptedShareSink>>>,
    /// Assigns the producer `share_id` to every accepted share, at the single
    /// fan-out point every share crosses regardless of protocol.
    sequencer: ShareSequencer,
    /// Resolves each share's payout mode once, here at the fan-out point,
    /// so the mode is stamped onto the share and downstream sinks (and the
    /// Satellite, which has no gate) read it instead of querying a gate.
    gate: Arc<BlitzpoolModeGate>,
}

impl CompositeAcceptedShareSink {
    /// Append an extra sink to the fan-out. Intended for one-shot startup
    /// wiring (e.g. Blockparty, constructed after the rest of the engines).
    ///
    /// Copy-on-write: builds the new list and swaps the pointer, so readers
    /// mid-fan-out keep iterating their own consistent snapshot.
    pub(crate) fn push(&self, sink: Arc<dyn SharedAcceptedShareSink>) {
        let mut next = Vec::clone(&self.sinks.load_full());
        next.push(sink);
        self.sinks.store(Arc::new(next));
    }
}

#[async_trait]
impl SharedAcceptedShareSink for CompositeAcceptedShareSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        // One atomic load + refcount bump, held across the fan-out below.
        let snapshot = self.sinks.load_full();
        // Stamp the producer fields before any sink sees the share: the
        // adapters leave them blank; idempotent sinks key their dedup on
        // share_id, mode-gated sinks read share.mode.
        let share_id = self.sequencer.next_id();
        let resolved = self.gate.lookup_mode(share.address);
        let share = SharedAcceptedShare {
            share_id: &share_id,
            mode: resolved.mode,
            group_id: resolved.group_id.as_deref(),
            ..share
        };
        for (i, sink) in snapshot.iter().enumerate() {
            // diag: per-sink timing, since an inline sink blocks the
            // connection loop while it runs.
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
    /// Stamps each rejected share's `group_id` once, here at the fan-out
    /// point (the only side holding the gate), so the Satellite reads it off
    /// the rejected stream.
    gate: Arc<BlitzpoolModeGate>,
}

#[async_trait]
impl SharedRejectedShareSink for CompositeRejectedShareSink {
    async fn record_rejected(&self, share: SharedRejectedShare<'_>) {
        // Group-Solo group ids only: a Blockparty address carries a group_id
        // too, but its reject must not be credited to the Group-Solo engine.
        // `group_for_address` applies that filter.
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

/// The accepted-share sinks split by durability class — the two consumer
/// groups the Satellite stream consumer runs (see
/// [`crate::satellite_consumer`]): order-sensitive `money` first, then
/// order-insensitive `aux`.
pub(crate) struct AcceptedSinkSet {
    /// Money: PPLNS + Group-Solo Redis-window mutations. Order-sensitive
    /// (window order = consume order) and exactly-once via the `share_id`
    /// dedup marker → driven by a single ordered consumer.
    pub(crate) money: Vec<Arc<dyn SharedAcceptedShareSink>>,
    /// Stats accumulators + session-persistence (best-diff / touch /
    /// difficulty-stats) + live-mode marker. Order-insensitive; run on a
    /// separate consumer group so a stall here never blocks money acks.
    pub(crate) aux: Vec<Arc<dyn SharedAcceptedShareSink>>,
}

/// Build the per-engine accepted-share sinks, split by durability class.
/// Driven by the Satellite stream consumer.
pub(crate) fn build_accepted_sinks(
    pplns: Option<&PplnsEngine>,
    group_solo: &GroupSoloEngine,
    stats: &ShareStatsEngineHandle,
    session_persistence: &SessionPersistenceEngineHandle,
    redis: redis::aio::ConnectionManager,
) -> AcceptedSinkSet {
    let mut money: Vec<Arc<dyn SharedAcceptedShareSink>> = Vec::new();
    if let Some(p) = pplns {
        money.push(Arc::new(PplnsAcceptedShareSink::new(p.clone())));
    }
    money.push(Arc::new(GroupSoloAcceptedShareSink::new(
        group_solo.clone(),
    )));

    let aux: Vec<Arc<dyn SharedAcceptedShareSink>> = vec![
        Arc::new(ShareStatsAcceptedSink::new(stats.accumulators())),
        Arc::new(session_persistence.client_row_touch_sink()),
        Arc::new(session_persistence.client_difficulty_statistics_sink()),
        Arc::new(crate::live_mode_marker::LiveModeMarkerSink::new(
            redis,
            Arc::new(bp_mining_mode::MarkDebouncer::new()),
        )),
    ];
    AcceptedSinkSet { money, aux }
}

/// Core-mode accepted fan-out: the composite keeps its single
/// share_id-/mode-stamping fan-out point but routes to exactly one sink —
/// the [`ProducingSink`] that publishes each share onto the Redis stream.
/// The Satellite re-runs the real engine sinks off that stream, reading
/// the stamped `share_id` + `mode` (it has no mode gate of its own).
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

/// The per-engine rejected-share sinks (Group-Solo reject counter + stats
/// reject counter). Driven by the Satellite's rejected consumer. They read
/// the (Core-stamped) `group_id` off the share — no gate.
pub(crate) fn build_rejected_sinks(
    group_solo: &GroupSoloEngine,
    stats: &ShareStatsEngineHandle,
) -> Vec<Arc<dyn SharedRejectedShareSink>> {
    vec![
        Arc::new(GroupSoloRejectedShareSink::new(group_solo.clone())),
        Arc::new(ShareStatsRejectedSink::new(stats.accumulators())),
    ]
}

/// Core-mode rejected fan-out: stamp the `group_id` (gate) at the single
/// fan-out point, then publish to the rejected stream. The Satellite re-runs
/// the real reject sinks off that stream.
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

    /// The settlement gate refuses a coinbase paying less than the block's
    /// own subsidy, and regtest halves every 150 blocks: with the mainnet
    /// 210 000 the engines would over-state the subsidy and refuse regtest
    /// blocks past that height.
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
        // The concrete consequence, at a height a regtest harness reaches.
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

    /// Both engines must carry the same schedule — a Group-Solo block
    /// and a PPLNS block on the same node cannot disagree about what
    /// their own subsidy was.
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

    /// Enough config to reach the engine builders. Deliberately WITHOUT
    /// `[pplns]` — that is the shape under test.
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

        [group_fees]
        address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        percent = 1.0
    "#;

    /// A pool that does not run PPLNS must still boot: without `[pplns]` the
    /// shared `min_payout_sats` is the Group-Solo engine default, not
    /// `Sats(0)`, which would fail validation.
    #[test]
    fn a_pool_without_pplns_still_builds_its_group_solo_config() {
        let cfg: bp_config::AppConfig =
            toml::from_str(NO_PPLNS_CFG).expect("parse config without [pplns]");
        assert!(cfg.pplns.is_none(), "the fixture must not define [pplns]");

        let built = to_group_solo_engine_config(&cfg).expect("must build without [pplns]");
        assert_eq!(
            built.min_payout_sats,
            GroupSoloEngineConfig::default().min_payout_sats,
            "the engine default applies, not Sats(0)"
        );
    }

    /// And when `[pplns]` IS configured, its value is the one that wins —
    /// the two engines share one floor.
    #[test]
    fn pplns_min_payout_is_shared_with_group_solo() {
        let cfg: bp_config::AppConfig = toml::from_str(&format!(
            "{NO_PPLNS_CFG}\n\
             [pplns]\n\
             port = 3340\n\
             high_diff_port = 3349\n\
             start_difficulty = 5000\n\
             target_shares_per_minute = 12\n\
             fee_address = \"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"\n\
             fee_percent = 1.5\n\
             coinbase_weight_budget = 35000\n\
             min_difficulty = 500\n\
             min_payout_sats = 12345\n"
        ))
        .expect("parse config with [pplns]");

        let built = to_group_solo_engine_config(&cfg).expect("build");
        assert_eq!(built.min_payout_sats, Sats(12_345));
    }

    // ── CompositeAcceptedShareSink: ArcSwap fan-out list ─────────────
    //
    // The list is appended once at startup (Blockparty) and read on EVERY
    // accepted share via `load_full()`. These tests pin its semantics.

    /// Counts how often it was invoked, so a fan-out can be observed.
    struct CountingSink(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    #[async_trait]
    impl SharedAcceptedShareSink for CountingSink {
        async fn record_accepted(&self, _share: SharedAcceptedShare<'_>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn empty_composite() -> CompositeAcceptedShareSink {
        CompositeAcceptedShareSink {
            sinks: ArcSwap::new(Arc::new(Vec::new())),
            sequencer: ShareSequencer::new(0),
            gate: Arc::new(BlitzpoolModeGate::new()),
        }
    }

    /// Minimal borrowed accepted-share; only the fan-out is under test.
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

    /// `push` must be visible to reads that happen after it (Blockparty is
    /// wired after the composite is already inside an `Arc`).
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

    /// Every sink in the list is fanned out to: `load_full()` exposes the
    /// complete list.
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

    /// Copy-on-write: a snapshot taken before a `push` keeps its own view, so
    /// a reader mid-fan-out is never mutated underneath.
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

    /// Core mode: the producing composite stamps `share_id` + `mode` at the
    /// single fan-out point and publishes the owned share onto the
    /// accepted-share stream the Satellite consumes; read back through a
    /// consumer group, the stamped fields survive.
    #[tokio::test]
    async fn producing_composite_stamps_and_publishes_to_stream() {
        let Some(conn) = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, 6).await else {
            return;
        };

        let gate = Arc::new(BlitzpoolModeGate::new());
        let addr = "bc1qproducingsink";
        gate.set_mode(addr, MiningModeResult::pplns());

        let composite = build_producing_composite(gate, conn.clone(), 7);

        // Adapter-shaped input: share_id blank + mode Solo; the composite
        // overwrites both before publishing.
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

        // Read it back through a consumer group — the Satellite's path.
        // ensure_group at "0" so the group sees the already-XADD'd entry,
        // then read never-delivered entries (`>`).
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

    /// The resolved mode via `lookup_mode`.
    fn mode_of(gate: &BlitzpoolModeGate, address: &str) -> MiningMode {
        gate.lookup_mode(address).mode
    }

    /// `lookup_known` tells an undecided address apart from Solo, where
    /// `lookup_mode` guesses Solo. The JDP allocate publishes a payout
    /// distribution before the mining channel opens, and a Solo guess there
    /// would publish a Solo plan for a PPLNS miner or a Group-Solo finder.
    /// Asserted against `lookup_mode` so the two answers stay distinct.
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

        // A real Solo miner is a different answer, and must read as one.
        gate.set_mode("bc1qsolo", MiningModeResult::solo());
        assert_eq!(
            gate.lookup_known("bc1qsolo").map(|r| r.mode),
            Some(MiningMode::Solo)
        );

        // And the mode the guess would have got wrong.
        gate.set_mode("bc1qpplns", MiningModeResult::pplns());
        assert_eq!(
            gate.lookup_known("bc1qpplns").map(|r| r.mode),
            Some(MiningMode::Pplns)
        );

        // Cleared with the session: a disconnected miner is undecided again.
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
        gate.set_mode("bc1qpplns", MiningModeResult::pplns());
        assert_eq!(mode_of(&gate, "bc1qpplns"), MiningMode::Pplns);
        assert_eq!(gate.group_for_address("bc1qpplns"), None);
    }

    #[test]
    fn mode_gate_group_solo_path_extracts_uuid() {
        let gate = BlitzpoolModeGate::new();
        let group_id = Uuid::new_v4();
        gate.set_mode("bc1qgs", MiningModeResult::group_solo(group_id.to_string()));
        assert_eq!(mode_of(&gate, "bc1qgs"), MiningMode::GroupSolo);
        assert_eq!(gate.group_for_address("bc1qgs"), Some(group_id));
    }

    #[test]
    fn mode_gate_group_solo_with_invalid_uuid_returns_none() {
        // A malformed UUID in the gate yields None from `group_for_address`
        // rather than panicking on the share path.
        let gate = BlitzpoolModeGate::new();
        gate.set_mode("bc1qgs", MiningModeResult::group_solo("not-a-uuid"));
        assert_eq!(gate.group_for_address("bc1qgs"), None);
        assert_eq!(mode_of(&gate, "bc1qgs"), MiningMode::GroupSolo);
    }

    #[test]
    fn mode_gate_clear_drops_the_entry_when_refcount_zero() {
        let gate = BlitzpoolModeGate::new();
        gate.set_mode("bc1q", MiningModeResult::pplns());
        assert_eq!(mode_of(&gate, "bc1q"), MiningMode::Pplns);
        gate.clear_mode("bc1q");
        assert_eq!(mode_of(&gate, "bc1q"), MiningMode::Solo);
    }

    #[test]
    fn override_mode_flips_connected_solo_to_group_without_touching_refcount() {
        let gate = BlitzpoolModeGate::new();
        gate.set_mode("bc1qsolo", MiningModeResult::solo());
        gate.set_mode("bc1qpplns", MiningModeResult::pplns());
        let group_id = Uuid::new_v4();

        // Only Solo / GroupSolo entries are transition candidates (PPLNS skipped).
        let cands = gate.group_transition_candidates();
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].0, "bc1qsolo");
        assert_eq!(cands[0].1.mode, MiningMode::Solo);

        // The cache-sync reconcile flips a live solo miner to group-solo so its
        // running connection's shares route to the group from the next share.
        gate.override_mode(
            "bc1qsolo",
            MiningModeResult::group_solo(group_id.to_string()),
        );
        assert_eq!(mode_of(&gate, "bc1qsolo"), MiningMode::GroupSolo);
        assert_eq!(gate.group_for_address("bc1qsolo"), Some(group_id));

        // Refcount untouched: a single disconnect still drops the entry (an
        // accidental extra bump would leave it stuck after one disconnect).
        gate.clear_mode("bc1qsolo");
        assert_eq!(mode_of(&gate, "bc1qsolo"), MiningMode::Solo);

        // Override on a disconnected (absent) address is a no-op — never resurrects.
        gate.override_mode(
            "bc1qabsent",
            MiningModeResult::group_solo(group_id.to_string()),
        );
        assert_eq!(mode_of(&gate, "bc1qabsent"), MiningMode::Solo);
    }

    #[test]
    fn mode_gate_last_write_wins_on_mode_while_refcount_increments() {
        let gate = BlitzpoolModeGate::new();
        gate.set_mode("bc1q", MiningModeResult::pplns());
        let group_id = Uuid::new_v4();
        // Second set: mode overwritten to GroupSolo, refcount now 2.
        gate.set_mode("bc1q", MiningModeResult::group_solo(group_id.to_string()));
        assert_eq!(mode_of(&gate, "bc1q"), MiningMode::GroupSolo);
        assert_eq!(gate.group_for_address("bc1q"), Some(group_id));
        // First disconnect → refcount drops to 1, entry survives.
        gate.clear_mode("bc1q");
        assert_eq!(mode_of(&gate, "bc1q"), MiningMode::GroupSolo);
        // Second disconnect → refcount returns to 0, entry dropped.
        gate.clear_mode("bc1q");
        assert_eq!(mode_of(&gate, "bc1q"), MiningMode::Solo);
    }

    #[test]
    fn mode_gate_clear_unknown_address_is_noop() {
        // Disconnect for an address that never authorized must not panic.
        let gate = BlitzpoolModeGate::new();
        gate.clear_mode("bc1qnever_seen");
        assert_eq!(mode_of(&gate, "bc1qnever_seen"), MiningMode::Solo);
    }

    #[test]
    fn mode_gate_refcount_balances_under_parallel_connections() {
        // Two parallel connections for the same address; the first
        // disconnect must NOT drop mode information the second
        // connection still relies on.
        let gate = BlitzpoolModeGate::new();
        gate.set_mode("bc1q", MiningModeResult::pplns());
        gate.set_mode("bc1q", MiningModeResult::pplns());
        gate.clear_mode("bc1q");
        // After first clear: refcount = 1, mode still cached.
        assert_eq!(mode_of(&gate, "bc1q"), MiningMode::Pplns);
        gate.clear_mode("bc1q");
        // After second clear: refcount = 0, entry gone.
        assert_eq!(mode_of(&gate, "bc1q"), MiningMode::Solo);
    }
}
