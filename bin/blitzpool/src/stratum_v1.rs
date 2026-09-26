// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV1 server composition — Phase 7.4b (per-port hooks) +
//! Phase 7.4c (listener moved to [`crate::stratum`]).
//!
//! Builds one [`StratumV1Server`] per port (solo + solo-high-diff +
//! optionally pplns + pplns-high-diff). The TCP-accept loop lives in
//! `stratum.rs` because it's now protocol-detect-multiplexed (SV1 +
//! SV2 share the same listening port and dispatch via
//! the first-byte router in `stratum.rs`). Each server has its own
//! [`ServerHooks`] clone wired to:
//!
//! - **block_sink**: [`TdpBlockSubmissionSink`] (shared across all
//!   ports — it's stateless, holds only a clone of `TdpHandle`).
//! - **accepted_sink / rejected_sink**: shared `EngineHandles`
//!   composite sinks (PPLNS + Group-Solo + ShareStats + best-diff,
//!   all mode-gated internally).
//! - **session_persistence**: a [`ModeGatePopulatingPersistence`]
//!   wrapper that publishes the resolved
//!   [`MiningModeResult`] into the
//!   shared mode-gate on `register_session`, decrements the refcount
//!   on `deregister_session`, then forwards to the engine-layer
//!   [`SessionPersistenceHook`](bp_session_persistence::SessionPersistenceHook).
//!
//! ## Why one server per port
//!
//! `StratumV1Server` captures one `ServerHooks` at spawn time and
//! clones it into every connection. Mode-gate population needs the
//! per-port `payout_mode` to know which `MiningModeResult` to publish
//! when an address isn't a group member — that's per-port state, so
//! we spawn one server per port. The cost is 4× translator tasks +
//! 4× template broadcast channels; the translator fires only on TDP
//! updates (~30 s cadence) so the overhead is negligible.
//!
//! ## Address-resolution at authorize
//!
//! When a miner authorizes, [`ModeGatePopulatingPersistence`]
//! consults the shared [`GroupLookup`] (impl'd for production by
//! `GroupService`). If the address is in an active group, the
//! published mode is `MiningModeResult::group_solo(group_id)`;
//! otherwise the port's `payout_mode` (Solo or Pplns) drives the
//! result. Group-Solo (per-address membership) preempts the port choice.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bp_common::{AddressId, MiningMode};
use bp_config::AppConfig;
use bp_group_mgmt_engine::{GroupService, GroupServiceHooks};
use bp_mining_mode::MiningModeResult;
use bp_share_hook::SharedSessionPersistence;
use bp_stratum_v1::{PortConfig, ServerConfig, ServerHooks, SharedExtranonce, StratumV1Server};
use thiserror::Error;
use tracing::warn;
use uuid::Uuid;

use crate::block_sink::TdpBlockSubmissionSink;
use crate::boot::FoundationHandles;
use crate::engines::{BlitzpoolModeGate, EngineHandles};
use crate::group_service::SharedGroupService;
use crate::payout_identities::PayoutIdentityDirectory;

/// Per-port SV1 server bundle. One entry per `[stratum]`/`[pplns]`
/// port the operator enabled. Consumed by [`crate::stratum::spawn`]
/// which binds a single shared listener per port and protocol-detects
/// the first byte to dispatch into either this `server` or the SV2
/// equivalent.
pub(crate) struct Sv1PortServer {
    pub(crate) port_config: PortConfig,
    pub(crate) server: StratumV1Server,
}

#[derive(Debug, Error)]
pub(crate) enum StratumV1SpawnError {
    #[error("stratum-v1 server config invalid: {0}")]
    ServerConfig(String),
    #[error("stratum-v1 port {port} config invalid: {source}")]
    PortConfig {
        port: u16,
        #[source]
        source: bp_stratum_v1::StratumV1Error,
    },
}

/// Build one [`StratumV1Server`] per port + its
/// [`bp_stratum_v1::ServerHooks`] clone. Returns an empty vec when
/// TDP is unavailable (`--skip-tdp`) — SV1 has no jobs to serve
/// without a template source.
///
/// The actual TCP-accept loop lives in [`crate::stratum::spawn`]; this
/// function only constructs the servers + threads them back so the
/// caller can build a per-port unified-protocol accept loop on top.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_per_port_servers(
    cfg: &AppConfig,
    foundation: &FoundationHandles,
    engines: &EngineHandles,
    group_service: &SharedGroupService,
    payout_resolver: Arc<dyn bp_stratum_v1::PayoutResolver>,
    // The pool's one rotating-identity intake, built in `crate::stratum` and
    // shared with SV2. Every port gets the same `Arc` — the verdict on an xpub
    // cannot depend on which port a miner connected to.
    rotating_intake: Arc<dyn bp_common::RotatingIntake>,
    dispatcher: Option<Arc<bp_notifications::dispatcher::NotificationDispatcher>>,
    device_status_sink: Arc<dyn bp_share_hook::DeviceStatusSink>,
    live_sessions: Arc<crate::live_sessions::LiveSessionRegistry>,
    job_cache: Arc<bp_mining_job::MiningJobCache>,
    settle: crate::settlement::SettlementSignal,
) -> Result<Vec<Sv1PortServer>, StratumV1SpawnError> {
    let Some(tdp) = foundation.tdp.as_ref() else {
        warn!("stratum-v1: TDP missing (--skip-tdp); skipping SV1 server construction");
        return Ok(vec![]);
    };

    let server_config = build_server_config(cfg);
    server_config
        .validate()
        .map_err(|e| StratumV1SpawnError::ServerConfig(e.to_string()))?;

    // Phase 7.7: block_sink fans block-found events to the per-mode
    // engine ledger (PPLNS / Group-Solo `on_block_found`) +
    // notification dispatcher, in addition to the existing TDP
    // submit_solution path.
    let block_sink = TdpBlockSubmissionSink::wired(
        tdp.clone(),
        cfg,
        foundation,
        engines,
        dispatcher.clone(),
        settle,
    )
    .into_sv1_arc();

    let port_configs = build_port_configs(cfg);
    for pc in &port_configs {
        pc.validate()
            .map_err(|source| StratumV1SpawnError::PortConfig {
                port: pc.port,
                source,
            })?;
    }

    let lookup: Arc<dyn GroupLookup> = group_service.service.clone();
    let mut out: Vec<Sv1PortServer> = Vec::with_capacity(port_configs.len());

    // One pool-wide extranonce1 allocator shared across every SV1 port, so
    // two miners can never be handed the same prefix — not even on
    // different ports. Worker 1 keeps SV1's prefixes disjoint from the SV2
    // server's worker-0 space.
    let extranonce = SharedExtranonce::new();

    for port_config in port_configs {
        let hooks = build_port_hooks(
            port_config.payout_mode,
            block_sink.clone(),
            payout_resolver.clone(),
            rotating_intake.clone(),
            engines,
            lookup.clone(),
            device_status_sink.clone(),
            Arc::clone(&live_sessions),
        );

        let templates = crate::stratum::PortTemplates::subscribe(tdp, foundation);
        let server = StratumV1Server::spawn(
            server_config.clone(),
            templates.updates_rx,
            templates.initial_snapshot,
            templates.alt_streams,
            hooks,
            extranonce.clone(),
            job_cache.clone(),
        );
        out.push(Sv1PortServer {
            port_config,
            server,
        });
    }

    Ok(out)
}

// ─── ServerConfig + PortConfig builders ──────────────────────────

pub(crate) fn build_server_config(cfg: &AppConfig) -> ServerConfig {
    let network = crate::boot::bitcoin_network(cfg.network);
    let mut sc = ServerConfig::defaults_for(network);
    sc.pool_identifier = cfg.pool_identifier.clone();
    // Solo dev-fee is applied by `ProductionPayoutResolver` (reads
    // `cfg.solo` directly); `ServerConfig` carries no fee fields.
    sc.lifecycle.retention_ms = cfg.stratum.job_retention_ms;
    sc.difficulty_check_interval_ms = cfg.stratum.difficulty_check_interval_ms;
    sc.vardiff_silence_easing = cfg.stratum.vardiff_silence_easing_enabled;
    sc.protocol_debug = cfg.debug.stratum_wire_logs;
    sc.share_logs = cfg.debug.stratum_share_logs;
    sc.log_submit_latency = cfg.debug.submit_latency;
    sc
}

/// Build the per-port configs from `[stratum]` + (optional)
/// `[pplns]`. Always at least 2 Solo entries; up to 4 when PPLNS is
/// enabled. The high-diff PPLNS port mirrors
/// `high_diff_start_difficulty` (no separate field in the
/// PPLNS config schema — kept consistent with the operator-facing
/// "high-diff" knob in `[stratum]`).
pub(crate) fn build_port_configs(cfg: &AppConfig) -> Vec<PortConfig> {
    let mut ports = Vec::with_capacity(4);

    // Solo (low-diff)
    ports.push(PortConfig {
        payout_mode: MiningMode::Solo,
        target_shares_per_minute: cfg.stratum.target_shares_per_minute as f64,
        ..PortConfig::new(
            cfg.stratum.solo_port,
            cfg.stratum.solo_start_difficulty as f64,
        )
    });

    // Solo high-diff
    ports.push(PortConfig {
        payout_mode: MiningMode::Solo,
        target_shares_per_minute: cfg.stratum.high_diff_target_shares_per_minute as f64,
        allow_suggested_difficulty: false,
        ..PortConfig::new(
            cfg.stratum.solo_high_diff_port,
            cfg.stratum.high_diff_start_difficulty as f64,
        )
    });

    if let Some(pplns) = &cfg.pplns {
        // PPLNS (low-diff)
        ports.push(PortConfig {
            payout_mode: MiningMode::Pplns,
            target_shares_per_minute: pplns.target_shares_per_minute as f64,
            minimum_difficulty: pplns.min_difficulty as f64,
            ..PortConfig::new(pplns.port, pplns.start_difficulty as f64)
        });

        // PPLNS high-diff — mirror high_diff_start_difficulty
        // (operator-facing "high-diff threshold" is one value across
        // both payout modes; the PPLNS schema doesn't carry a
        // separate one).
        ports.push(PortConfig {
            payout_mode: MiningMode::Pplns,
            target_shares_per_minute: cfg.stratum.high_diff_target_shares_per_minute as f64,
            minimum_difficulty: pplns.min_difficulty as f64,
            allow_suggested_difficulty: false,
            ..PortConfig::new(
                pplns.high_diff_port,
                cfg.stratum.high_diff_start_difficulty as f64,
            )
        });
    }

    ports
}

// ─── ServerHooks composition ──────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn build_port_hooks(
    port_payout_mode: MiningMode,
    block_sink: Arc<dyn bp_stratum_v1::BlockSubmissionSink>,
    payout_resolver: Arc<dyn bp_stratum_v1::PayoutResolver>,
    rotating_intake: Arc<dyn bp_common::RotatingIntake>,
    engines: &EngineHandles,
    group_lookup: Arc<dyn GroupLookup>,
    device_status_sink: Arc<dyn bp_share_hook::DeviceStatusSink>,
    live_sessions: Arc<crate::live_sessions::LiveSessionRegistry>,
) -> ServerHooks {
    // Front-only path: `build_per_port_servers` runs only when Stratum spawns
    // (the front), where `engines::spawn` always builds these.
    ServerHooks {
        block_sink,
        accepted_sink: engines
            .accepted_sink
            .clone()
            .expect("front mode builds the accepted composite"),
        rejected_sink: engines
            .rejected_sink
            .clone()
            .expect("front mode builds the rejected composite"),
        session_persistence: ModeGatePopulatingPersistence::for_port(
            port_payout_mode,
            engines,
            group_lookup,
            live_sessions,
        ),
        payout_resolver,
        device_status_sink,
        rotating_intake: Some(rotating_intake),
    }
}

// ─── GroupLookup trait (group_id resolution) ──────────────────────

/// Address → active-group-id lookup surface. Decouples the wrapper
/// from the heavy `GroupService<H>` generic so unit tests can inject
/// a fake without standing up a `PgPool`. The single production impl
/// is on `GroupService<H>` below.
#[async_trait]
pub(crate) trait GroupLookup: Send + Sync {
    /// Cache-only lookup. Returns `Some(group_id)` only when the
    /// address is in an **active** group; inactive groups + missing
    /// addresses both yield `None`.
    async fn group_for_address(&self, address: &AddressId) -> Option<Uuid>;
}

#[async_trait]
impl<H: GroupServiceHooks + Send + Sync + 'static> GroupLookup for GroupService<H> {
    async fn group_for_address(&self, address: &AddressId) -> Option<Uuid> {
        self.get_group_for_address(address)
            .await
            .filter(|e| e.active)
            .map(|e| e.group_id)
    }
}

// ─── BlockpartyAdminLookup trait (admin → routable-party-id) ───────

/// Narrow admin-lookup surface over the heavy `BlockpartyApi`, mirroring
/// [`GroupLookup`]. Lets `resolve_mode` ask "is this address the admin of
/// a **routable** (Ready/Active) Blockparty?" without unit tests having to
/// stand up the full service. In Blockparty only the admin address hashes;
/// members are payout recipients, so admin-keyed resolution is correct.
#[async_trait]
pub(crate) trait BlockpartyAdminLookup: Send + Sync {
    /// `Some(group_id)` only when `address` is the admin of a Ready/Active
    /// party (see `BlockpartyStatus::is_routable`); `None` otherwise.
    async fn routable_group_id_for_admin(&self, address: &AddressId) -> Option<Uuid>;
}

/// Adapter wrapping the production `Arc<dyn BlockpartyApi>` into the narrow
/// [`BlockpartyAdminLookup`] surface.
pub(crate) struct BlockpartyApiAdminLookup(pub Arc<dyn bp_blockparty_engine::BlockpartyApi>);

#[async_trait]
impl BlockpartyAdminLookup for BlockpartyApiAdminLookup {
    async fn routable_group_id_for_admin(&self, address: &AddressId) -> Option<Uuid> {
        self.0.routable_group_id_for_admin(address).await
    }
}

// ─── ModeGatePopulatingPersistence ────────────────────────────────

/// Wraps a `SharedSessionPersistence` impl and, on every
/// register/deregister, also publishes / refcounts the resolved
/// `MiningModeResult` into the shared [`BlitzpoolModeGate`].
///
/// **Per-port** — the `port_payout_mode` field captures the fallback
/// mode for addresses that aren't in any active group. Every port gets
/// its own instance per protocol, built by [`Self::for_port`]: SV1 and
/// SV2 must not share one, because `sessions` is keyed by session ids
/// each protocol mints on its own.
///
/// **session→address tracking**: the SV1
/// `SessionPersistence::deregister_session` API only carries the
/// `session_id`; the address is not re-provided. We keep a local
/// `Mutex<HashMap<SessionId, String>>` populated on register so the
/// deregister path can resolve the address back and call
/// `mode_gate.clear_mode` correctly under refcounting.
///
/// **It also releases the payout-identity directory entry**, from the same
/// resolved address and under the same refcount. That is deliberate rather than
/// convenient: this is the one place both protocols' disconnects converge, and it
/// is already the thing that knows which `payout_id` the ending session held. A
/// second release site — one per protocol, say — would be two chances for a
/// rotating miner's descriptor to outlive its connections or to be dropped while
/// a sibling rig is still mining on it.
pub(crate) struct ModeGatePopulatingPersistence {
    port_payout_mode: MiningMode,
    mode_gate: Arc<BlitzpoolModeGate>,
    /// Released in lockstep with the mode gate — see the struct doc.
    payout_identities: Arc<PayoutIdentityDirectory>,
    group_lookup: Arc<dyn GroupLookup>,
    /// Blockparty admin-lookup. `None` when the `[blockparty]` feature
    /// isn't configured — then Blockparty mode is never resolved here.
    blockparty: Option<Arc<dyn BlockpartyAdminLookup>>,
    inner: Arc<dyn SharedSessionPersistence>,
    sessions: Mutex<HashMap<String, String>>,
}

impl ModeGatePopulatingPersistence {
    /// The instance a Stratum port registers its sessions through — the one
    /// place the SV1 and SV2 port builders get it from, so the two cannot
    /// resolve a connection's mode from different inputs.
    pub(crate) fn for_port(
        port_payout_mode: MiningMode,
        engines: &EngineHandles,
        group_lookup: Arc<dyn GroupLookup>,
        live_sessions: Arc<crate::live_sessions::LiveSessionRegistry>,
    ) -> Arc<dyn SharedSessionPersistence> {
        let blockparty: Option<Arc<dyn BlockpartyAdminLookup>> = engines
            .blockparty
            .clone()
            .map(|bp| Arc::new(BlockpartyApiAdminLookup(bp)) as Arc<dyn BlockpartyAdminLookup>);
        Arc::new(Self::new(
            port_payout_mode,
            engines.mode_gate.clone(),
            engines.payout_identities.clone(),
            group_lookup,
            blockparty,
            live_sessions,
        ))
    }

    pub(crate) fn new(
        port_payout_mode: MiningMode,
        mode_gate: Arc<BlitzpoolModeGate>,
        payout_identities: Arc<PayoutIdentityDirectory>,
        group_lookup: Arc<dyn GroupLookup>,
        blockparty: Option<Arc<dyn BlockpartyAdminLookup>>,
        inner: Arc<dyn SharedSessionPersistence>,
    ) -> Self {
        Self {
            port_payout_mode,
            mode_gate,
            payout_identities,
            group_lookup,
            blockparty,
            inner,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve `address` → `MiningModeResult`. Cache-only group
    /// lookup (the `AddressCache` is rebuilt on every membership
    /// change so cache-only is the correct read path here).
    async fn resolve_mode(&self, address: &str) -> MiningModeResult {
        let address_id = match AddressId::new(address.to_string()) {
            Ok(a) => a,
            // The SV1 authorize handler already validated the address
            // shape; defensive fallthrough to the port's payout-mode
            // result rather than panic on this branch.
            Err(_) => return mode_from_port(self.port_payout_mode),
        };
        // Group-Solo membership wins (active group only).
        if let Some(group_id) = self.group_lookup.group_for_address(&address_id).await {
            return MiningModeResult::group_solo(group_id.to_string());
        }
        // Blockparty: the connecting address is the admin of a routable
        // (Ready/Active) party. Only the admin hashes; the coinbase splits
        // to the members. Resolved admin-keyed, independent of the port.
        if let Some(bp) = self.blockparty.as_ref() {
            if let Some(group_id) = bp.routable_group_id_for_admin(&address_id).await {
                return MiningModeResult::blockparty(group_id.to_string());
            }
        }
        // Otherwise the port's payout mode (Solo / Pplns).
        mode_from_port(self.port_payout_mode)
    }
}

#[async_trait]
impl SharedSessionPersistence for ModeGatePopulatingPersistence {
    async fn register_session(
        &self,
        session_id: &str,
        address: &str,
        worker: &str,
        user_agent: Option<&str>,
    ) {
        let mode = self.resolve_mode(address).await;
        self.mode_gate.set_mode(address, mode);
        {
            let mut guard = self.sessions.lock().expect("session map mutex poisoned");
            guard.insert(session_id.to_string(), address.to_string());
        }
        self.inner
            .register_session(session_id, address, worker, user_agent)
            .await;
    }

    async fn deregister_session(&self, session_id: &str) {
        let address = {
            let mut guard = self.sessions.lock().expect("session map mutex poisoned");
            guard.remove(session_id)
        };
        if let Some(address) = address {
            self.mode_gate.clear_mode(&address);
            // Same key, same refcount, same moment. `address` here is the
            // session's `payout_id` (authorize replaced the wire string with it),
            // which is what the directory is keyed on; for a static miner this is
            // a no-op, because nothing static was ever published.
            self.payout_identities.release(&address);
        }
        self.inner.deregister_session(session_id).await;
    }
}

/// Map a port's `payout_mode` enum to a `MiningModeResult`. SV1 port
/// configs only carry Solo or Pplns; a `GroupSolo` port config is a
/// configuration error (group membership is per-address, not
/// per-port) — we fall through to `solo()` defensively.
fn mode_from_port(m: MiningMode) -> MiningModeResult {
    match m {
        MiningMode::Pplns => MiningModeResult::pplns(),
        MiningMode::Solo => MiningModeResult::solo(),
        // Group-Solo and Blockparty are per-address modes, not per-port —
        // a port config naming either is a misconfiguration. Defensively
        // fall through to solo so the coinbase is at least spendable.
        MiningMode::GroupSolo | MiningMode::Blockparty => MiningModeResult::solo(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_config::{
        ApiConfig, BitcoinRpcConfig, DatabaseConfig, Network, PayoutIdentityConfig, PplnsConfig,
        RedisConfig, StratumConfig, TdpConfig as TomlTdpConfig,
    };
    use std::path::PathBuf;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::Mutex as AsyncMutex;

    fn min_cfg(pplns: Option<PplnsConfig>) -> AppConfig {
        AppConfig {
            network: Network::Regtest,
            pool_identifier: "Blitzpool-Test".into(),
            pool_base_url: None,
            roles: Vec::new(),
            // Default: rotating identities off, which is what these tests want —
            // they assert SV1's existing static-address behaviour.
            payout_identity: PayoutIdentityConfig::default(),
            bitcoin_rpc: BitcoinRpcConfig {
                url: "http://127.0.0.1".into(),
                user: "u".into(),
                password: "p".into(),
                port: 18443,
                timeout_ms: 1000,
            },
            tdp: TomlTdpConfig {
                socket_path: PathBuf::from("/tmp/bp-tdp.sock"),
                fee_threshold_sats: None,
                min_interval_secs: None,
                broadcast_capacity: None,
                staleness_threshold_secs: 120,
            },
            database: DatabaseConfig {
                host: "h".into(),
                port: 5432,
                user: "u".into(),
                password: "p".into(),
                database: "d".into(),
                ssl: false,
                pool_size: 1,
                acquire_timeout_ms: 1_000,
                idle_timeout_ms: 1_000,
            },
            redis: RedisConfig {
                host: "h".into(),
                port: 6379,
                password: None,
                db: 0,
            },
            api: ApiConfig {
                port: 3334,
                cache: Default::default(),
            },
            stratum: StratumConfig {
                solo_port: 3333,
                solo_start_difficulty: 1024,
                solo_high_diff_port: 3339,
                high_diff_start_difficulty: 1_000_000,
                job_retention_ms: 600_000,
                target_shares_per_minute: 6,
                high_diff_target_shares_per_minute: 6,
                difficulty_check_interval_ms: 60_000,
                vardiff_silence_easing_enabled: false,
            },
            sv2: Default::default(),
            debug: Default::default(),
            pplns,
            solo: Default::default(),
            group_fees: Default::default(),
            blockparty: None,
            notifications: Default::default(),
            smtp: None,
            metrics: Default::default(),
        }
    }

    fn pplns_block() -> PplnsConfig {
        PplnsConfig {
            port: 3340,
            high_diff_port: 3349,
            start_difficulty: 16_384,
            target_shares_per_minute: 8,
            fee_address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".into(),
            fee_percent: 1.5,
            coinbase_weight_budget: 100_000,
            min_difficulty: 1024,
            min_payout_sats: 100_000,
            dust_sweep_enabled: true,
            abandoned_balance_days: 90,
            confirmation_depth: 3,
            bucket_shares: 10_000,
            coinbase_autoscale: None,
        }
    }

    // ── Pure builders ─────────────────────────────────────────────

    #[test]
    fn build_port_configs_without_pplns_returns_two_solo_ports() {
        let cfg = min_cfg(None);
        let ports = build_port_configs(&cfg);
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].payout_mode, MiningMode::Solo);
        assert_eq!(ports[1].payout_mode, MiningMode::Solo);
        assert_eq!(ports[0].port, 3333);
        assert_eq!(ports[1].port, 3339);
        assert_eq!(ports[0].initial_difficulty, 1024.0);
        assert_eq!(ports[1].initial_difficulty, 1_000_000.0);
        assert!(ports[0].allow_suggested_difficulty);
        assert!(!ports[1].allow_suggested_difficulty);
    }

    #[test]
    fn build_port_configs_with_pplns_returns_four_ports_mixed_modes() {
        let cfg = min_cfg(Some(pplns_block()));
        let ports = build_port_configs(&cfg);
        assert_eq!(ports.len(), 4);
        assert_eq!(ports[0].payout_mode, MiningMode::Solo);
        assert_eq!(ports[1].payout_mode, MiningMode::Solo);
        assert_eq!(ports[2].payout_mode, MiningMode::Pplns);
        assert_eq!(ports[3].payout_mode, MiningMode::Pplns);
        assert_eq!(ports[2].port, 3340);
        assert_eq!(ports[3].port, 3349);
        assert_eq!(ports[2].minimum_difficulty, 1024.0);
        // PPLNS high-diff mirrors high_diff_start_difficulty.
        assert_eq!(ports[3].initial_difficulty, 1_000_000.0);
        assert!(ports[0].allow_suggested_difficulty);
        assert!(!ports[1].allow_suggested_difficulty);
        assert!(ports[2].allow_suggested_difficulty);
        assert!(!ports[3].allow_suggested_difficulty);
    }

    #[test]
    fn mode_from_port_maps_each_variant() {
        assert_eq!(mode_from_port(MiningMode::Solo).mode, MiningMode::Solo);
        assert_eq!(mode_from_port(MiningMode::Pplns).mode, MiningMode::Pplns);
        // GroupSolo port -> defensive solo (port configs never carry
        // GroupSolo; group membership is per-address).
        assert_eq!(mode_from_port(MiningMode::GroupSolo).mode, MiningMode::Solo);
    }

    #[test]
    fn build_server_config_carries_pool_identifier() {
        let mut cfg = min_cfg(None);
        cfg.pool_identifier = "MyPool".into();
        let sc = build_server_config(&cfg);
        assert_eq!(sc.pool_identifier, "MyPool");
        assert_eq!(sc.lifecycle.retention_ms, 600_000);
        assert_eq!(sc.network, bitcoin::Network::Regtest);
    }

    // ── ModeGatePopulatingPersistence behaviour ───────────────────

    /// Recording inner-persistence for assertions.
    struct RecordingInner {
        register_calls: AsyncMutex<Vec<(String, String, String)>>,
        deregister_calls: AsyncMutex<Vec<String>>,
    }
    impl RecordingInner {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                register_calls: AsyncMutex::new(vec![]),
                deregister_calls: AsyncMutex::new(vec![]),
            })
        }
    }
    #[async_trait]
    impl SharedSessionPersistence for RecordingInner {
        async fn register_session(
            &self,
            session_id: &str,
            address: &str,
            worker: &str,
            _user_agent: Option<&str>,
        ) {
            self.register_calls.lock().await.push((
                session_id.into(),
                address.into(),
                worker.into(),
            ));
        }
        async fn deregister_session(&self, session_id: &str) {
            self.deregister_calls.lock().await.push(session_id.into());
        }
    }

    /// Stub `GroupLookup` driven by a static address → group map.
    struct StubLookup {
        groups: StdMutex<HashMap<String, Uuid>>,
    }
    impl StubLookup {
        fn empty() -> Self {
            Self {
                groups: StdMutex::new(HashMap::new()),
            }
        }
        fn with(address: &str, group: Uuid) -> Self {
            let mut m = HashMap::new();
            m.insert(address.to_string(), group);
            Self {
                groups: StdMutex::new(m),
            }
        }
    }
    #[async_trait]
    impl GroupLookup for StubLookup {
        async fn group_for_address(&self, address: &AddressId) -> Option<Uuid> {
            self.groups
                .lock()
                .expect("stub mutex")
                .get(address.as_str())
                .copied()
        }
    }

    /// Stub `BlockpartyAdminLookup` — returns a fixed group only for one
    /// admin address (simulating a Ready/Active party), `None` otherwise.
    struct StubBlockparty {
        admin: String,
        group: Uuid,
    }
    #[async_trait]
    impl BlockpartyAdminLookup for StubBlockparty {
        async fn routable_group_id_for_admin(&self, address: &AddressId) -> Option<Uuid> {
            (address.as_str() == self.admin).then_some(self.group)
        }
    }

    #[tokio::test]
    async fn mode_gate_persistence_publishes_port_mode_for_non_group_address() {
        let gate = Arc::new(BlitzpoolModeGate::new());
        let inner = RecordingInner::new();
        let lookup: Arc<dyn GroupLookup> = Arc::new(StubLookup::empty());
        let wrapper = ModeGatePopulatingPersistence::new(
            MiningMode::Pplns,
            gate.clone(),
            Arc::new(PayoutIdentityDirectory::new()),
            lookup,
            None,
            inner.clone(),
        );
        wrapper
            .register_session("sess1", "bcrt1qabc", "w1", None)
            .await;
        // PPLNS port + non-group address → PPLNS mode published.
        assert_eq!(gate.lookup_mode("bcrt1qabc").mode, MiningMode::Pplns);
        // Inner persistence forwarded.
        let calls = inner.register_calls.lock().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], ("sess1".into(), "bcrt1qabc".into(), "w1".into()));
    }

    #[tokio::test]
    async fn mode_gate_persistence_publishes_group_solo_when_address_is_group_member() {
        let gate = Arc::new(BlitzpoolModeGate::new());
        let inner = RecordingInner::new();
        let gid = Uuid::new_v4();
        let lookup: Arc<dyn GroupLookup> = Arc::new(StubLookup::with("bcrt1qgs", gid));
        // Port is Solo, but the address is in an active group → group_solo wins.
        let wrapper = ModeGatePopulatingPersistence::new(
            MiningMode::Solo,
            gate.clone(),
            Arc::new(PayoutIdentityDirectory::new()),
            lookup,
            None,
            inner.clone(),
        );
        wrapper.register_session("s1", "bcrt1qgs", "w", None).await;
        assert_eq!(gate.group_for_address("bcrt1qgs"), Some(gid));
    }

    #[tokio::test]
    async fn mode_gate_persistence_publishes_blockparty_when_address_is_routable_admin() {
        let gate = Arc::new(BlitzpoolModeGate::new());
        let inner = RecordingInner::new();
        let gid = Uuid::new_v4();
        let lookup: Arc<dyn GroupLookup> = Arc::new(StubLookup::empty());
        let bp: Arc<dyn BlockpartyAdminLookup> = Arc::new(StubBlockparty {
            admin: "bcrt1qadmin".to_string(),
            group: gid,
        });
        // Solo port, not a group member, but IS the admin of a routable
        // party → Blockparty wins over the port's Solo default.
        let wrapper = ModeGatePopulatingPersistence::new(
            MiningMode::Solo,
            gate.clone(),
            Arc::new(PayoutIdentityDirectory::new()),
            lookup,
            Some(bp),
            inner.clone(),
        );
        wrapper
            .register_session("s1", "bcrt1qadmin", "w", None)
            .await;
        assert_eq!(gate.lookup_mode("bcrt1qadmin").mode, MiningMode::Blockparty);
        // A non-admin address falls through to the port mode (Solo).
        wrapper
            .register_session("s2", "bcrt1qother", "w", None)
            .await;
        assert_eq!(gate.lookup_mode("bcrt1qother").mode, MiningMode::Solo);
    }

    #[tokio::test]
    async fn mode_gate_persistence_refcounts_on_deregister() {
        let gate = Arc::new(BlitzpoolModeGate::new());
        let inner = RecordingInner::new();
        let lookup: Arc<dyn GroupLookup> = Arc::new(StubLookup::empty());
        let wrapper = ModeGatePopulatingPersistence::new(
            MiningMode::Pplns,
            gate.clone(),
            Arc::new(PayoutIdentityDirectory::new()),
            lookup,
            None,
            inner.clone(),
        );
        // Two parallel registers for the same address → refcount == 2.
        wrapper.register_session("s1", "bcrt1qa", "w", None).await;
        wrapper.register_session("s2", "bcrt1qa", "w", None).await;
        assert_eq!(gate.lookup_mode("bcrt1qa").mode, MiningMode::Pplns);

        // Single deregister → refcount drops to 1, mode still cached.
        wrapper.deregister_session("s1").await;
        assert_eq!(gate.lookup_mode("bcrt1qa").mode, MiningMode::Pplns);
        assert_eq!(inner.deregister_calls.lock().await.len(), 1);

        // Second deregister → refcount returns to 0, entry cleared.
        wrapper.deregister_session("s2").await;
        assert_eq!(gate.lookup_mode("bcrt1qa").mode, MiningMode::Solo);
        assert_eq!(inner.deregister_calls.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn mode_gate_persistence_deregister_unknown_session_is_noop() {
        let gate = Arc::new(BlitzpoolModeGate::new());
        let inner = RecordingInner::new();
        let lookup: Arc<dyn GroupLookup> = Arc::new(StubLookup::empty());
        let wrapper = ModeGatePopulatingPersistence::new(
            MiningMode::Pplns,
            gate.clone(),
            Arc::new(PayoutIdentityDirectory::new()),
            lookup,
            None,
            inner.clone(),
        );
        // Never registered — deregister must not panic + must still
        // forward to the inner sink so PG soft-delete attempts still
        // run (no-op on the SQL side, but the contract is fan-out).
        wrapper.deregister_session("ghost-session").await;
        assert_eq!(inner.deregister_calls.lock().await.len(), 1);
    }
}
