// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine spawning + share-sink composition — Phase 7.2.
//!
//! Builds the four service-layer engines on top of [`FoundationHandles`]:
//!
//! 1. **PPLNS engine** — only when `[pplns]` is present in the config.
//! 2. **Group-Solo engine** — always; Group-Solo is a first-class mode
//!    that runs in parallel with PPLNS regardless of port enablement.
//! 3. **Share-stats engine** — mode-blind accumulator coordinator; always
//!    on.
//! 4. **Session-persistence engine** — synchronous PG write-through for
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
//! window-sizing factor reads it). We boot-fetch it once via
//! `getmininginfo`; refresh is Phase 7.5's `bp-notifications`
//! network-difficulty cron's job (it already polls `mempool.space`).
//! The bitcoin RPC handle in 7.1 is liveness-pinged, so this call is
//! expected to succeed; on transient failure we default to `1.0` and
//! warn — the window degrades gracefully (slightly under-sized) until
//! the cron's first tick lands.

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
    AcceptedShareProducer, ProducingRejectedSink, ProducingSink, StreamProducer,
    ACCEPTED_STREAM_KEY, REJECTED_STREAM_KEY,
};
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

use crate::boot::FoundationHandles;

/// Long-lived engine + sink aggregate. Phase 7.4 + 7.5 thread this
/// into the Stratum servers + cron schedules.
#[allow(dead_code)]
pub(crate) struct EngineHandles {
    pub(crate) pplns: Option<PplnsEngine>,
    pub(crate) group_solo: GroupSoloEngine,
    pub(crate) stats: ShareStatsEngineHandle,
    pub(crate) session_persistence: SessionPersistenceEngineHandle,
    pub(crate) mode_gate: Arc<BlitzpoolModeGate>,
    /// The front's producing Stratum fan-out sinks — built only on the front,
    /// where Stratum feeds them; they stamp each share and publish it onto the
    /// Redis stream. `None` on the satellite: it has no Stratum listeners; its
    /// stream consumer builds its own sink set from these engines (see
    /// `build_accepted_sinks`), so building one here too would be a dead
    /// duplicate.
    pub(crate) accepted_sink: Option<Arc<CompositeAcceptedShareSink>>,
    pub(crate) rejected_sink: Option<Arc<dyn SharedRejectedShareSink>>,
    pub(crate) session_persistence_hook: SessionPersistenceHook,
    /// Optional Blockparty handle. Wired only when the feature is
    /// configured at boot; `None` keeps PayoutResolver + block-sink on
    /// the existing Solo / PPLNS / Group-Solo paths.
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
/// (the dedup discriminator — see [`ShareSequencer`]). Redis is already a
/// hard dependency at this point in boot, so a failure here is fatal and
/// surfaces as a pointed error rather than a silent collision.
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
///   (`spawn_core`, no ledger-mutating crons) — they exist only so the
///   `PayoutResolver` can build coinbase distributions. Its accepted- and
///   rejected-share fan-outs are each a single [`ProducingSink`] that
///   publishes every (already share_id-/mode-stamped) share onto the Redis
///   stream for the Satellite to consume.
/// - The **back** (`payout` / `stats`) spawns the full engines; its share
///   sinks are driven by the stream consumer off `build_accepted_sinks` /
///   `build_rejected_sinks`, so no in-process composite is built here.
pub(crate) async fn spawn(
    cfg: &AppConfig,
    handles: &FoundationHandles,
) -> Result<EngineHandles, EngineError> {
    // Read-only engines (skip the ledger-mutating crons) on every process
    // that doesn't run the payout accounting — the front builds coinbases
    // from them, the API serves reads from them. Only the `payout` role runs
    // them full (with crons).
    let read_only = !cfg.has_role(Role::Payout);
    let mode_gate = Arc::new(BlitzpoolModeGate::new());
    let pplns = spawn_pplns(cfg, handles, read_only).await?;
    let group_solo = spawn_group_solo(cfg, handles, read_only).await?;
    let stats = spawn_stats(cfg, handles).await?;
    // Only the Front role feeds + writes hashRate, so only it reconciles
    // stale hashRate on boot (see run_sample_loop); a non-writing role
    // zeroing the column would wipe the Front's live values.
    let session_persistence = spawn_session_persistence(handles, cfg.has_role(Role::Front)).await?;

    // Only the front builds the Stratum fan-out sinks, and it always produces
    // to the Redis streams (the Satellite consumes them). A pure back / api
    // process has no Stratum and consumes (or doesn't touch) the streams
    // instead, so it skips them (and the `core:epoch` INCR).
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
        // Blockparty wiring lands in a follow-up patch — needs the
        // AddressEmailService handle for invitation flow and a
        // dedicated config block. None disables the feature without
        // touching any other code path.
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
    let engine_cfg = to_pplns_engine_config(toml_cfg)?;
    let net_diff = bootstrap_network_difficulty(handles).await;
    info!(
        net_diff = %net_diff.get(),
        fee_percent = engine_cfg.fee_percent,
        core,
        "pplns: spawning engine"
    );
    let redis = handles.redis.clone();
    let pool = handles.db.pool().clone();
    // Core runs read-only (no touch-flush / dust-sweep crons) — it only
    // reads the window for the PayoutResolver's coinbase distributions.
    let engine = if core {
        PplnsEngine::spawn_core(engine_cfg, redis, pool, net_diff).await?
    } else {
        PplnsEngine::spawn(engine_cfg, redis, pool, net_diff).await?
    };
    Ok(Some(engine))
}

fn to_pplns_engine_config(cfg: &TomlPplnsConfig) -> Result<PplnsEngineConfig, EngineError> {
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
        warmup_shares: cfg.warmup_shares,
        dust_sweep_enabled: cfg.dust_sweep_enabled,
        abandoned_balance_days: cfg.abandoned_balance_days,
        bucket_shares: cfg.bucket_shares,
        ..PplnsEngineConfig::default()
    };
    let validated = base.try_new()?;
    Ok(validated)
}

/// Best-effort fetch of the current network difficulty for PPLNS
/// window-sizing. Falls back to `1.0` on transient failure (with a
/// `warn`), so the engine can still spawn — the
/// `bp-notifications::cron::network_difficulty` refresh task
/// (Phase 7.5) keeps the value fresh during runtime.
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
        dust_sweep_enabled = engine_cfg.dust_sweep_enabled,
        core,
        "group-solo: spawning engine"
    );
    let redis = handles.redis.clone();
    let pool = handles.db.pool().clone();
    // Core runs read-only (no dust-sweep / per-group round-reset crons).
    let engine = if core {
        GroupSoloEngine::spawn_core(engine_cfg, redis, pool).await?
    } else {
        GroupSoloEngine::spawn(engine_cfg, redis, pool).await?
    };
    Ok(engine)
}

fn to_group_solo_engine_config(cfg: &AppConfig) -> Result<GroupSoloEngineConfig, EngineError> {
    // Group-Solo + Blockparty share a `[group_fees]` lane independent
    // from PPLNS. Fall back to `[pplns]` for backward compatibility
    // with PPLNS-only deployments.
    let (fee_address, fee_percent) = crate::blockparty_service::resolve_group_fees(cfg)
        .map_err(|(raw, err)| EngineError::InvalidAddress(raw, err))?;
    let base = GroupSoloEngineConfig {
        fee_address,
        fee_percent,
        // VALIDITY-CRITICAL: the distribution trims the coinbase to this budget,
        // and boot reserves exactly the same budget on the Group-Solo TDP stream
        // (`tdp_constraint_for_budget(cfg.group_fees.coinbase_weight_budget)`).
        // The two MUST be the same value — otherwise the trimmer fits a coinbase
        // larger than bitcoin-core reserved and rejects the block. Mirrors the
        // PPLNS engine↔default-stream coupling.
        coinbase_weight_budget: cfg.group_fees.coinbase_weight_budget,
        dust_sweep_enabled: cfg.group_fees.dust_sweep_enabled,
        dormant_balance_days: cfg.group_fees.dormant_balance_days,
        // The `min_payout_sats` floor is shared between PPLNS + Group-
        // Solo: both engines read the same value. When `[pplns]` is
        // configured we reuse its
        // value; otherwise we fall back to the engine default.
        min_payout_sats: cfg
            .pplns
            .as_ref()
            .map(|p| Sats(p.min_payout_sats))
            .unwrap_or_default(),
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
    reconcile_hashrate_on_boot: bool,
) -> Result<SessionPersistenceEngineHandle, EngineError> {
    let cfg = SessionPersistenceConfig {
        reconcile_hashrate_on_boot,
        ..SessionPersistenceConfig::default()
    };
    info!(
        reconcile_hashrate_on_boot,
        "session-persistence: spawning engine"
    );
    let handle = SessionPersistenceEngine::spawn(cfg, handles.db.pool().clone()).await?;
    Ok(handle)
}

// ─── BlitzpoolModeGate (sync address→mode cache) ──

/// In-memory `(address → MiningModeResult, refcount)` map. Empty in
/// 7.2; Phase 7.4's Stratum-side authorize path calls
/// [`Self::set_mode`] when a miner authorizes on a port (the port's
/// marker drives the mode). Addresses absent from the map default to
/// `Solo`.
///
/// **Refcounting**: each authorize bumps the count for `address`;
/// each disconnect decrements via [`Self::clear_mode`]. Entry is
/// dropped only when the count returns to zero. This handles the
/// case where the same address has multiple concurrent connections
/// (BitAxe + cpuminer using the same payout address): one disconnect
/// must not clear mode information the other connection still relies
/// on. Mode resolution remains last-write-wins — if the operator
/// adds the miner to a group between connections, the second
/// authorize's `MiningModeResult` overwrites the cached mode while
/// keeping the refcount bumped.
///
/// [`lookup_mode`](Self::lookup_mode) (used by the share producer + the
/// payout resolver + block-found) and [`group_for_address`](Self::group_for_address)
/// (used by the rejected composite's group-id stamp) read the same map. The
/// map's lock is held only across a single `HashMap::get`, so per-share
/// contention is negligible.
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

    /// Phase 7.4 hook: called from the Stratum-server authorize path
    /// to publish the resolved mode for `address`. Increments the
    /// refcount; last-write-wins on the mode itself (a re-authorize
    /// from the same address picks up any membership change since
    /// the previous connection).
    #[allow(dead_code)]
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

    /// Phase 7.4 hook: called from the Stratum-server disconnect path.
    /// Decrements the refcount + removes the entry when the count
    /// returns to zero. Calling `clear_mode` for an address never
    /// `set_mode`'d is a no-op (defensive — a deregister event for an
    /// unauthorized session shouldn't reach here, but if it does, we
    /// just ignore it).
    #[allow(dead_code)]
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

    fn lookup(&self, address: &str) -> MiningModeResult {
        let guard = self.inner.lock().expect("mode-gate mutex poisoned");
        guard
            .get(address)
            .map(|e| e.mode.clone())
            .unwrap_or_else(MiningModeResult::solo)
    }

    /// Public alias of [`Self::lookup`] for the
    /// [`crate::payout_resolver::ProductionPayoutResolver`] — needs
    /// full `MiningModeResult` (mode + optional group_id), not just
    /// the slice the trait surfaces expose.
    pub(crate) fn lookup_mode(&self, address: &str) -> MiningModeResult {
        self.lookup(address)
    }

    /// Resolve an address to its **Group-Solo** `group_id` — `None` for any
    /// other mode (a Blockparty address carries a group_id too, but it is not
    /// a Group-Solo group). The single source of the Group-Solo group filter
    /// the rejected composite stamps from.
    pub(crate) fn group_for_address(&self, address: &str) -> Option<Uuid> {
        let r = self.lookup(address);
        if r.mode != MiningMode::GroupSolo {
            return None;
        }
        r.group_id.and_then(|s| Uuid::parse_str(&s).ok())
    }

    /// Snapshot the connected addresses currently gated `Solo` or `GroupSolo`
    /// — the only modes the cache-sync reconcile flips on a group-membership
    /// change. Returns `(address, mode)` pairs (a small clone under a brief
    /// lock); PPLNS/Blockparty addresses are never touched.
    pub(crate) fn group_transition_candidates(&self) -> Vec<(String, MiningModeResult)> {
        let guard = self.inner.lock().expect("mode-gate mutex poisoned");
        guard
            .iter()
            .filter(|(_, e)| matches!(e.mode.mode, MiningMode::Solo | MiningMode::GroupSolo))
            .map(|(a, e)| (a.clone(), e.mode.clone()))
            .collect()
    }

    /// Update the cached mode for an **already-connected** address WITHOUT
    /// bumping its refcount — used by the cache-sync reconcile to flip a live
    /// miner between Solo and Group-Solo when its group membership changes, so
    /// its running connection's shares route to the right place on the next
    /// share with no reconnect. No-op for an address that isn't connected
    /// (absent from the map) — we never resurrect a disconnected entry.
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
/// sink. Sequential `await` chain — keeps the share-path simple and
/// the ordering deterministic; concurrent fan-out via `join_all`
/// would shave latency at the cost of dropped-share-on-panic
/// semantics that we don't need (these sinks are all
/// log-and-continue on internal failure).
pub(crate) struct CompositeAcceptedShareSink {
    /// Copy-on-write behind an [`ArcSwap`] so a one-shot startup append (via
    /// [`Self::push`]) can extend the fan-out after the composite is already
    /// wrapped in `Arc`, **without putting a lock on the per-share read
    /// path**.
    ///
    /// The read path is `load_full()` — one atomic load plus a refcount bump
    /// — and the resulting `Arc` is held across the `await`s of the fan-out.
    /// This replaces a `Mutex<Vec<_>>` whose read path locked and then deep-
    /// cloned the whole `Vec` on **every accepted share**, i.e. a process-wide
    /// lock acquisition + one allocation per share, paid forever for what is
    /// only a startup-time mutation. (The `Vec` clone existed because the
    /// fan-out `await`s each sink, so a `std` guard cannot be held across it;
    /// `ArcSwap` removes both the lock and the clone.)
    sinks: ArcSwap<Vec<Arc<dyn SharedAcceptedShareSink>>>,
    /// Assigns the producer `share_id` to every accepted share. This is the
    /// single fan-out point every share crosses regardless of protocol, so
    /// it is exactly where the id is stamped today — and where the stream
    /// producer will assign it under the Core/Satellite split.
    sequencer: ShareSequencer,
    /// Resolves each share's payout mode once, here at the fan-out point,
    /// so the mode is stamped onto the share and the downstream sinks read
    /// it instead of re-querying the gate per sink. Under the split the
    /// stream producer holds the authoritative Core gate and does the same.
    gate: Arc<BlitzpoolModeGate>,
}

impl CompositeAcceptedShareSink {
    /// Append an extra sink to the fan-out. Intended for one-shot
    /// startup wiring (e.g. Blockparty, whose handle is constructed
    /// after the rest of the engines).
    ///
    /// Copy-on-write: builds the new list and swaps the pointer, so readers
    /// concurrently fanning out a share keep iterating their own consistent
    /// snapshot. Startup-only, so the clone here is not on any hot path.
    pub(crate) fn push(&self, sink: Arc<dyn SharedAcceptedShareSink>) {
        let mut next = Vec::clone(&self.sinks.load_full());
        next.push(sink);
        self.sinks.store(Arc::new(next));
    }
}

#[async_trait]
impl SharedAcceptedShareSink for CompositeAcceptedShareSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        // One atomic load + refcount bump; no lock, no `Vec` clone. Held
        // across the fan-out `await`s below.
        let snapshot = self.sinks.load_full();
        // Stamp the producer fields here — one id + one mode resolution per
        // share, assigned at the single point every share crosses, before
        // any sink sees it. The adapters left them blank; idempotent sinks
        // key their dedup on share_id, mode-gated sinks read share.mode.
        let share_id = self.sequencer.next_id();
        let resolved = self.gate.lookup_mode(share.address);
        let share = SharedAcceptedShare {
            share_id: &share_id,
            mode: resolved.mode,
            group_id: resolved.group_id.as_deref(),
            ..share
        };
        for (i, sink) in snapshot.iter().enumerate() {
            // diag: per-sink timing — one of these inline accepted-share
            // sinks occasionally blocks the connection loop for ~1s. Index
            // order = build_accepted_sinks (money: [pplns?], group-solo;
            // aux: stats, best-difficulty, touch, diff-stats, live-marker).
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
    /// Stamps each rejected share's `group_id` once, here at the single
    /// fan-out point (the only side holding the gate), so the Group-Solo
    /// reject sink reads it instead of querying a gate — and so the Satellite
    /// gets it off the rejected stream.
    gate: Arc<BlitzpoolModeGate>,
}

#[async_trait]
impl SharedRejectedShareSink for CompositeRejectedShareSink {
    async fn record_rejected(&self, share: SharedRejectedShare<'_>) {
        // Stamp the Group-Solo group id (only — a Blockparty address also
        // carries a group_id, but the rejected fan-out has no Blockparty
        // sink, and crediting its reject to the Group-Solo engine would be
        // wrong). `group_for_address` applies exactly that filter.
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
/// Driven by the Satellite stream consumer (the front produces to the stream
/// rather than fanning out in-process).
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
        AcceptedShareProducer::new(redis, ACCEPTED_STREAM_KEY),
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
    use bp_share_stream::AcceptedShareConsumer;

    // ── CompositeAcceptedShareSink: ArcSwap fan-out list ─────────────
    //
    // The list is appended exactly once at startup (Blockparty) and then
    // read on EVERY accepted share. It used to be a `Mutex<Vec<_>>` whose
    // read path locked and deep-cloned the whole `Vec` per share; it is now
    // an `ArcSwap` read via `load_full()` (atomic load + refcount bump).
    // These tests pin the semantics that change had to preserve.

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

    /// `push` must be visible to reads that happen after it — the whole
    /// point of the late-append (Blockparty is wired after the composite
    /// is already inside an `Arc`).
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

    /// Every sink in the list is fanned out to, in order — `load_full()`
    /// must expose the complete list, not a truncated snapshot.
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

    /// Copy-on-write: a snapshot taken before a `push` keeps its own view.
    /// This is what makes the lock unnecessary — a reader mid-fan-out is
    /// never mutated underneath.
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

    const REDIS_URL: &str = "redis://127.0.0.1:16379";

    /// Connect a flushed Redis logical DB, or `None` to skip (Redis
    /// unavailable / CI without services).
    async fn connect_redis_or_skip(db: u8) -> Option<redis::aio::ConnectionManager> {
        let base = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_URL.to_string());
        let client = redis::Client::open(format!("{base}/{db}")).ok()?;
        let mut conn = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            redis::aio::ConnectionManager::new(client),
        )
        .await
        {
            Ok(Ok(c)) => c,
            _ => {
                eprintln!("redis unreachable — skipping engines stream test");
                return None;
            }
        };
        if redis::cmd("FLUSHDB")
            .query_async::<()>(&mut conn)
            .await
            .is_err()
        {
            return None;
        }
        Some(conn)
    }

    /// Core mode: the producing composite stamps `share_id` + `mode` at the
    /// single fan-out point and publishes the owned share onto the shared
    /// accepted-share stream — exactly what the Satellite consumes. Proven
    /// end-to-end: build the composite, feed one borrowed share for a
    /// PPLNS-gated address, then read it back off the stream and assert the
    /// stamped fields survived.
    #[tokio::test]
    async fn producing_composite_stamps_and_publishes_to_stream() {
        let Some(conn) = connect_redis_or_skip(6).await else {
            return;
        };

        let gate = Arc::new(BlitzpoolModeGate::new());
        let addr = "bc1qproducingsink";
        gate.set_mode(addr, MiningModeResult::pplns());

        let composite = build_producing_composite(gate, conn.clone(), 7);

        // Adapter-shaped input: share_id blank + mode Solo — the composite
        // overwrites both from the gate before publishing.
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
        let consumer = AcceptedShareConsumer::new(conn, ACCEPTED_STREAM_KEY, "test_money", "c1");
        consumer.ensure_group().await.expect("ensure_group");
        let entries = consumer.read_new(16, 500).await.expect("read_new");
        assert_eq!(entries.len(), 1, "exactly one share published");
        let owned = &entries[0].share;
        assert_eq!(owned.address, addr);
        assert_eq!(owned.mode, MiningMode::Pplns, "mode stamped from gate");
        assert_eq!(owned.group_id, None);
        assert_eq!(owned.share_id, "7:0", "share_id stamped from sequencer");
        assert!((owned.effective_difficulty - 1024.0).abs() < 1e-9);
    }

    /// `is_pplns` / `mode_for` were removed with the dead gate traits; the
    /// gate's live API is `lookup_mode`. This reads the resolved mode.
    fn mode_of(gate: &BlitzpoolModeGate, address: &str) -> MiningMode {
        gate.lookup_mode(address).mode
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
        // Defence-in-depth: a malformed UUID in the gate → GroupModeGate
        // falls through to None rather than panicking on the share path.
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
        // Disconnect for an address that never authorized — defensive
        // path; must not panic.
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
