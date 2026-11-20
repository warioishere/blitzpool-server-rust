// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV1 server composition: one [`StratumV1Server`] per port, because a
//! server clones one [`ServerHooks`] into every connection and the fallback
//! mode for a non-group address is per-port state. Mode at authorize: a
//! Group-Solo membership wins, then Blockparty admin, else the port's mode.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bp_common::AddressId;
use bp_config::AppConfig;
use bp_mining_mode::MiningModeResult;
use bp_share_hook::SharedSessionPersistence;
use bp_stratum_v1::{
    PortConfig, PortMode, ServerConfig, ServerHooks, SharedExtranonce, StratumV1Server,
};
use bp_template_distribution::TdpHandle;
use thiserror::Error;

use crate::boot::FoundationHandles;
use crate::engines::{BlitzpoolModeGate, EngineHandles};
use crate::membership::{membership_mode, BlockpartyAdminLookup, GroupLookup, Membership};

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

/// What every SV1 port server shares: the validated [`ServerConfig`], the
/// pool-wide extranonce1 allocator and the hooks that are the same on every
/// port. [`crate::stratum::spawn`] calls [`Self::spawn_port`] once per port,
/// next to the SV2 server for the same port.
pub(crate) struct Sv1Servers<'a> {
    server_config: ServerConfig,
    extranonce: SharedExtranonce,
    tdp: &'a TdpHandle,
    foundation: &'a FoundationHandles,
    engines: &'a EngineHandles,
    membership: &'a Membership,
    block_sink: Arc<dyn bp_stratum_v1::BlockSubmissionSink>,
    payout_resolver: Arc<dyn bp_mining_job::PayoutResolver>,
    device_status_sink: Arc<dyn bp_share_hook::DeviceStatusSink>,
    live_sessions: Arc<crate::live_sessions::LiveSessionRegistry>,
    job_cache: Arc<bp_mining_job::MiningJobCache>,
}

impl<'a> Sv1Servers<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        cfg: &AppConfig,
        tdp: &'a TdpHandle,
        foundation: &'a FoundationHandles,
        engines: &'a EngineHandles,
        membership: &'a Membership,
        block_sink: Arc<dyn bp_stratum_v1::BlockSubmissionSink>,
        payout_resolver: Arc<dyn bp_mining_job::PayoutResolver>,
        device_status_sink: Arc<dyn bp_share_hook::DeviceStatusSink>,
        live_sessions: Arc<crate::live_sessions::LiveSessionRegistry>,
        job_cache: Arc<bp_mining_job::MiningJobCache>,
    ) -> Result<Self, StratumV1SpawnError> {
        let server_config = build_server_config(cfg);
        server_config
            .validate()
            .map_err(|e| StratumV1SpawnError::ServerConfig(e.to_string()))?;
        Ok(Self {
            server_config,
            // One pool-wide extranonce1 allocator across every SV1 port, so
            // no two miners share a prefix. Worker 1 keeps SV1 disjoint from
            // SV2's worker 0.
            extranonce: SharedExtranonce::new(),
            tdp,
            foundation,
            engines,
            membership,
            block_sink,
            payout_resolver,
            device_status_sink,
            live_sessions,
            job_cache,
        })
    }

    /// Spawn the SV1 server for one port.
    pub(crate) fn spawn_port(&self, port_config: &PortConfig) -> StratumV1Server {
        let hooks = build_port_hooks(
            port_config.payout_mode,
            self.block_sink.clone(),
            self.payout_resolver.clone(),
            self.engines,
            self.membership,
            self.device_status_sink.clone(),
            Arc::clone(&self.live_sessions),
        );
        let templates = crate::stratum::PortTemplates::subscribe(self.tdp, self.foundation);
        StratumV1Server::spawn(
            self.server_config.clone(),
            templates.updates_rx,
            templates.initial_snapshot,
            templates.alt_streams,
            hooks,
            self.extranonce.clone(),
            self.job_cache.clone(),
        )
    }
}

/// [`build_port_configs`], each checked with [`PortConfig::validate`]. The
/// one port list both protocols serve.
pub(crate) fn validated_port_configs(
    cfg: &AppConfig,
) -> Result<Vec<PortConfig>, StratumV1SpawnError> {
    let port_configs = build_port_configs(cfg);
    for pc in &port_configs {
        pc.validate()
            .map_err(|source| StratumV1SpawnError::PortConfig {
                port: pc.port,
                source,
            })?;
    }
    Ok(port_configs)
}

// ─── ServerConfig + PortConfig builders ──────────────────────────

pub(crate) fn build_server_config(cfg: &AppConfig) -> ServerConfig {
    let network = crate::boot::bitcoin_network(cfg.network);
    let mut sc = ServerConfig::defaults_for(network);
    sc.pool_identifier = cfg.pool_identifier.clone();
    // The Solo dev-fee is applied by `ProductionPayoutResolver` from the
    // boot-validated `EngineHandles::solo_fee`; `ServerConfig` carries no fee.
    sc.lifecycle.retention_ms = cfg.stratum.job_retention_ms;
    sc.difficulty_check_interval_ms = cfg.stratum.difficulty_check_interval_ms;
    sc.protocol_debug = cfg.debug.stratum_wire_logs;
    sc.share_logs = cfg.debug.stratum_share_logs;
    sc.log_submit_latency = cfg.debug.submit_latency;
    sc
}

/// Build the per-port configs from `[stratum]` and optional `[pplns]`:
/// 2 Solo ports, plus 2 PPLNS ports when PPLNS is enabled. The PPLNS
/// high-diff port uses `[stratum]`'s `high_diff_start_difficulty`, one
/// high-diff threshold for both modes.
fn build_port_configs(cfg: &AppConfig) -> Vec<PortConfig> {
    let mut ports = Vec::with_capacity(4);

    // Solo (low-diff)
    ports.push(PortConfig {
        payout_mode: PortMode::Solo,
        target_shares_per_minute: cfg.stratum.target_shares_per_minute as f64,
        ..PortConfig::new(
            cfg.stratum.solo_port,
            cfg.stratum.solo_start_difficulty as f64,
        )
    });

    // Solo high-diff
    ports.push(PortConfig {
        payout_mode: PortMode::Solo,
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
            payout_mode: PortMode::Pplns,
            target_shares_per_minute: pplns.target_shares_per_minute as f64,
            minimum_difficulty: pplns.min_difficulty as f64,
            ..PortConfig::new(pplns.port, pplns.start_difficulty as f64)
        });

        // PPLNS high-diff: shares `[stratum]`'s high-diff start difficulty.
        ports.push(PortConfig {
            payout_mode: PortMode::Pplns,
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
    port_payout_mode: PortMode,
    block_sink: Arc<dyn bp_stratum_v1::BlockSubmissionSink>,
    payout_resolver: Arc<dyn bp_mining_job::PayoutResolver>,
    engines: &EngineHandles,
    membership: &Membership,
    device_status_sink: Arc<dyn bp_share_hook::DeviceStatusSink>,
    live_sessions: Arc<crate::live_sessions::LiveSessionRegistry>,
) -> ServerHooks {
    // Front-only path: SV1 servers are built only when Stratum spawns (the
    // front), where `engines::spawn` always builds these.
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
            membership,
            live_sessions,
        ),
        payout_resolver,
        device_status_sink,
        admission: membership.admission(),
        session_kicks: membership.session_kicks.clone(),
    }
}

// ─── ModeGatePopulatingPersistence ────────────────────────────────

/// Publishes / refcounts the resolved `MiningModeResult` in the shared
/// [`BlitzpoolModeGate`] on every register/deregister. One instance per port
/// AND protocol: `sessions` is keyed by ids each protocol mints on its own,
/// and maps them back to the address because deregister carries only the id.
pub(crate) struct ModeGatePopulatingPersistence {
    port_payout_mode: PortMode,
    mode_gate: Arc<BlitzpoolModeGate>,
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
        port_payout_mode: PortMode,
        engines: &EngineHandles,
        membership: &Membership,
        live_sessions: Arc<crate::live_sessions::LiveSessionRegistry>,
    ) -> Arc<dyn SharedSessionPersistence> {
        let group_lookup: Arc<dyn GroupLookup> = membership.group.service.clone();
        let blockparty: Option<Arc<dyn BlockpartyAdminLookup>> = membership
            .blockparty_service()
            .map(|bp| bp as Arc<dyn BlockpartyAdminLookup>);
        Arc::new(Self::new(
            port_payout_mode,
            engines.mode_gate.clone(),
            group_lookup,
            blockparty,
            live_sessions,
        ))
    }

    pub(crate) fn new(
        port_payout_mode: PortMode,
        mode_gate: Arc<BlitzpoolModeGate>,
        group_lookup: Arc<dyn GroupLookup>,
        blockparty: Option<Arc<dyn BlockpartyAdminLookup>>,
        inner: Arc<dyn SharedSessionPersistence>,
    ) -> Self {
        Self {
            port_payout_mode,
            mode_gate,
            group_lookup,
            blockparty,
            inner,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve `address` → `MiningModeResult`. The group lookup is
    /// cache-only; the `AddressCache` is rebuilt on every membership change.
    async fn resolve_mode(&self, address: &str) -> MiningModeResult {
        let address_id = match AddressId::new(address.to_string()) {
            Ok(a) => a,
            // Authorize already validated the address; fall back to the
            // port mode rather than panic.
            Err(_) => return mode_from_port(self.port_payout_mode),
        };
        membership_mode(&*self.group_lookup, self.blockparty.as_deref(), &address_id)
            .await
            .unwrap_or_else(|| mode_from_port(self.port_payout_mode))
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
        }
        self.inner.deregister_session(session_id).await;
    }
}

/// The mode a session takes from its port.
fn mode_from_port(m: PortMode) -> MiningModeResult {
    match m {
        PortMode::Pplns => MiningModeResult::Pplns,
        PortMode::Solo => MiningModeResult::Solo,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_common::MiningMode;
    use bp_config::{
        ApiConfig, BitcoinRpcConfig, DatabaseConfig, Network, PplnsConfig, RedisConfig,
        StratumConfig, TdpConfig as TomlTdpConfig,
    };
    use std::path::PathBuf;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::Mutex as AsyncMutex;
    use uuid::Uuid;

    fn min_cfg(pplns: Option<PplnsConfig>) -> AppConfig {
        AppConfig {
            network: Network::Regtest,
            pool_identifier: "Blitzpool-Test".into(),
            pool_base_url: None,
            roles: Vec::new(),
            bitcoin_rpc: BitcoinRpcConfig {
                url: "http://127.0.0.1".into(),
                user: "u".into(),
                password: "p".into(),
                port: 18443,
                timeout_ms: 1000,
            },
            tdp: TomlTdpConfig {
                socket_path: PathBuf::from("/tmp/bp-tdp.sock"),
                bitcoin_core_version: None,
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
                address_auth: Default::default(),
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
            },
            sv2: Default::default(),
            debug: Default::default(),
            pplns,
            solo: Default::default(),
            group_solo: None,
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
        assert_eq!(ports[0].payout_mode, PortMode::Solo);
        assert_eq!(ports[1].payout_mode, PortMode::Solo);
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
        assert_eq!(ports[0].payout_mode, PortMode::Solo);
        assert_eq!(ports[1].payout_mode, PortMode::Solo);
        assert_eq!(ports[2].payout_mode, PortMode::Pplns);
        assert_eq!(ports[3].payout_mode, PortMode::Pplns);
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
        assert_eq!(mode_from_port(PortMode::Solo).mode(), MiningMode::Solo);
        assert_eq!(mode_from_port(PortMode::Pplns).mode(), MiningMode::Pplns);
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
            PortMode::Pplns,
            gate.clone(),
            lookup,
            None,
            inner.clone(),
        );
        wrapper
            .register_session("sess1", "bcrt1qabc", "w1", None)
            .await;
        // PPLNS port + non-group address → PPLNS mode published.
        assert_eq!(gate.lookup_mode("bcrt1qabc").mode(), MiningMode::Pplns);
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
        // Port is Solo, but the address is in a group → group_solo wins.
        let wrapper = ModeGatePopulatingPersistence::new(
            PortMode::Solo,
            gate.clone(),
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
            PortMode::Solo,
            gate.clone(),
            lookup,
            Some(bp),
            inner.clone(),
        );
        wrapper
            .register_session("s1", "bcrt1qadmin", "w", None)
            .await;
        assert_eq!(
            gate.lookup_mode("bcrt1qadmin").mode(),
            MiningMode::Blockparty
        );
        // A non-admin address falls through to the port mode (Solo).
        wrapper
            .register_session("s2", "bcrt1qother", "w", None)
            .await;
        assert_eq!(gate.lookup_mode("bcrt1qother").mode(), MiningMode::Solo);
    }

    #[tokio::test]
    async fn mode_gate_persistence_refcounts_on_deregister() {
        let gate = Arc::new(BlitzpoolModeGate::new());
        let inner = RecordingInner::new();
        let lookup: Arc<dyn GroupLookup> = Arc::new(StubLookup::empty());
        let wrapper = ModeGatePopulatingPersistence::new(
            PortMode::Pplns,
            gate.clone(),
            lookup,
            None,
            inner.clone(),
        );
        // Two parallel registers for the same address → refcount == 2.
        wrapper.register_session("s1", "bcrt1qa", "w", None).await;
        wrapper.register_session("s2", "bcrt1qa", "w", None).await;
        assert_eq!(gate.lookup_mode("bcrt1qa").mode(), MiningMode::Pplns);

        // Single deregister → refcount drops to 1, mode still cached.
        wrapper.deregister_session("s1").await;
        assert_eq!(gate.lookup_mode("bcrt1qa").mode(), MiningMode::Pplns);
        assert_eq!(inner.deregister_calls.lock().await.len(), 1);

        // Second deregister → refcount returns to 0, entry cleared.
        wrapper.deregister_session("s2").await;
        assert_eq!(gate.lookup_mode("bcrt1qa").mode(), MiningMode::Solo);
        assert_eq!(inner.deregister_calls.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn mode_gate_persistence_deregister_unknown_session_is_noop() {
        let gate = Arc::new(BlitzpoolModeGate::new());
        let inner = RecordingInner::new();
        let lookup: Arc<dyn GroupLookup> = Arc::new(StubLookup::empty());
        let wrapper = ModeGatePopulatingPersistence::new(
            PortMode::Pplns,
            gate.clone(),
            lookup,
            None,
            inner.clone(),
        );
        // Never registered: deregister must not panic and still forwards
        // to the inner sink.
        wrapper.deregister_session("ghost-session").await;
        assert_eq!(inner.deregister_calls.lock().await.len(), 1);
    }
}
