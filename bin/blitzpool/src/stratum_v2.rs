// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 mining-server composition — Phase 7.4c.
//!
//! Builds one [`StratumV2MiningServer`] per port (mirrors the SV1
//! per-port-server topology in [`crate::stratum_v1`]). The shared
//! `JdpDeclaredJobRegistry` bridge is constructed at the top level
//! by [`crate::stratum::spawn`] and threaded into every per-port
//! SV2 server clone so `SetCustomMiningJob` routing works across
//! ports.
//!
//! ## Scope of Phase 7.4c → 7.4d
//!
//! - [`PayoutResolver`] is supplied by the caller from
//!   [`crate::payout_resolver::ProductionPayoutResolver`] (Phase
//!   7.4d). Pre-7.4d this module shipped a solo-only stub; the
//!   production resolver now consults the mode-gate + PPLNS /
//!   Group-Solo engine round state to assemble the real per-mode
//!   coinbase distribution.
//!
//! - [`BlockSubmissionSink`] is [`crate::block_sink::TdpBlockSubmissionSink`].
//!   The SV2 `ShareAccept` carries the assembled witness coinbase, the
//!   `template_id`, and the per-job pinned `coinbase_tx_value_remaining`, so
//!   the block-found path submits the solution via TDP AND writes the per-mode
//!   engine ledger (PPLNS / Group-Solo / Blockparty) exactly like SV1.
//!
//! What this phase DOES wire:
//! - Per-port `StratumV2MiningServer` construction with TDP subscribe.
//! - `Sv2AcceptedShareAdapter` / `Sv2RejectedShareAdapter` over the
//!   shared engine sinks (mode-gated PPLNS + Group-Solo + ShareStats +
//!   BestDifficulty).
//! - `Sv2SessionPersistenceAdapter` wrapping the reused
//!   [`crate::stratum_v1::ModeGatePopulatingPersistence`] so SV2
//!   `ChannelOpened` events publish the resolved mode into the same
//!   mode-gate the SV1 path populates.

use std::sync::{Arc, RwLock};

use bitcoin::Network as BitcoinNetwork;
use bp_common::{MiningMode, StreamKind};
use bp_config::{AppConfig, Role};
use bp_share::Difficulty;
use bp_share_hook::SharedSessionPersistence;
use bp_share_stream::{StreamProducer, BLOCK_FOUND_STREAM_KEY};
use bp_stratum_v2::bridge::JdpDeclaredJobRegistry;
use bp_stratum_v2::hooks::{
    AcceptedShareSink as Sv2AcceptedSink, BlockSubmissionSink as Sv2BlockSink, MiningServerHooks,
    PayoutResolver, RejectedShareSink as Sv2RejectedSink, SessionPersistence as Sv2SessionPersist,
};
use bp_stratum_v2::mining::client::PortConfig as Sv2PortConfig;
use bp_stratum_v2::noise::{NoiseConfig, NoiseConfigError, DEFAULT_CERT_VALIDITY};
use bp_stratum_v2::server::{ServerConfig as Sv2ServerConfig, StratumV2MiningServer};
use bp_stratum_v2::shared_adapter::{
    Sv2AcceptedShareAdapter, Sv2RejectedShareAdapter, Sv2SessionPersistenceAdapter,
};
use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use thiserror::Error;
use tracing::{info, warn};

// Note: stratum-apps depends on `secp256k1` 0.28 internally, but the
// blitzpool workspace pins 0.29 elsewhere — passing raw [u8;32] via
// `secp256k1::SecretKey::from_slice` would fail-type-check across the
// version boundary. Instead we round-trip via base58check (the
// canonical wire-format `Secp256k1SecretKey::FromStr` parses).

use crate::boot::FoundationHandles;
use crate::engines::{BlitzpoolModeGate, EngineHandles};
use crate::group_service::SharedGroupService;
use crate::stratum_v1::{
    self, BlockpartyAdminLookup, BlockpartyApiAdminLookup, GroupLookup,
    ModeGatePopulatingPersistence,
};

/// Per-port SV2 mining server bundle. One entry per port (mirrors
/// [`crate::stratum_v1::Sv1PortServer`]). Carries the SV2 [`PortConfig`]
/// (different shape from SV1's) so the unified accept-loop can hand it
/// in to `accept_connection`.
pub(crate) struct Sv2PortServer {
    pub(crate) port: u16,
    pub(crate) port_config: Sv2PortConfig,
    pub(crate) server: StratumV2MiningServer,
}

#[derive(Debug, Error)]
pub(crate) enum StratumV2SpawnError {
    #[error("sv2 noise config invalid: {0}")]
    Noise(#[from] NoiseConfigError),
    #[error("sv2 authority private key hex must be exactly 64 hex chars (32 bytes): got {0}")]
    AuthorityPrivkeyHexLen(usize),
    #[error("sv2 authority private key hex didn't decode: {0}")]
    AuthorityPrivkeyHex(String),
    #[error("sv2 authority private key bytes didn't parse: {0}")]
    AuthorityPrivkey(String),
    #[error("sv2 needs [sv2].authority_privkey_hex (32-byte hex) — none configured")]
    AuthorityKeyMissing,
}

/// Construct the shared [`JdpDeclaredJobRegistry`] used by every SV2
/// mining server clone + the JDP server. The bridge stores
/// declared-job → mining-channel routing state; one instance per
/// process. Uses `std::sync::RwLock` (matches the bp-stratum-v2 crate
/// internals — no `await` is held across the lock).
pub(crate) fn build_bridge() -> Arc<RwLock<JdpDeclaredJobRegistry>> {
    Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()))
}

/// Build the pool-wide [`NoiseConfig`] from `[sv2]`. Decodes
/// `authority_privkey_hex` (raw 32-byte secp256k1 secret in hex),
/// derives the matching x-only public key, and stamps the default
/// 12-hour cert validity.
pub(crate) fn build_noise_config(cfg: &AppConfig) -> Result<NoiseConfig, StratumV2SpawnError> {
    let hex_str = cfg
        .sv2
        .authority_privkey_hex
        .as_deref()
        .ok_or(StratumV2SpawnError::AuthorityKeyMissing)?;
    if hex_str.len() != 64 {
        return Err(StratumV2SpawnError::AuthorityPrivkeyHexLen(hex_str.len()));
    }
    let raw_bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex_str[i..i + 2], 16)
                .map_err(|e| StratumV2SpawnError::AuthorityPrivkeyHex(e.to_string()))
        })
        .collect::<Result<_, _>>()?;
    // Round-trip via base58check — stratum-apps's `FromStr` parses
    // that form, which avoids depending on a specific `secp256k1`
    // version (stratum-apps pins 0.28; the workspace uses 0.29).
    let b58 = bs58::encode(&raw_bytes).with_check().into_string();
    let authority_prv: Secp256k1SecretKey =
        b58.parse().map_err(|e: stratum_apps::key_utils::Error| {
            StratumV2SpawnError::AuthorityPrivkey(format!("{e:?}"))
        })?;
    let authority_pub: Secp256k1PublicKey = authority_prv.into();
    NoiseConfig::new(authority_pub, authority_prv, DEFAULT_CERT_VALIDITY).map_err(Into::into)
}

/// Build the SV2 [`ServerConfig`](Sv2ServerConfig) from the network +
/// pool identifier in the toplevel `AppConfig`.
pub(crate) fn build_server_config(cfg: &AppConfig) -> Sv2ServerConfig {
    let network = config_network_to_bitcoin(cfg.network);
    let mut sc = Sv2ServerConfig::defaults_for(network);
    sc.pool_identifier = cfg.pool_identifier.clone();
    sc.debug_messages = cfg.debug.stratum_wire_logs;
    sc.share_logs = cfg.debug.stratum_share_logs;
    sc.log_submit_latency = cfg.debug.submit_latency;
    sc
}

fn config_network_to_bitcoin(n: bp_config::Network) -> BitcoinNetwork {
    match n {
        bp_config::Network::Mainnet => BitcoinNetwork::Bitcoin,
        // testnet4 shares the `tb` HRP + address byte set with
        // testnet3, so the bitcoin-crate's Testnet variant covers
        // both for address parsing / script generation purposes.
        // rust-bitcoin 0.32 doesn't have a dedicated Testnet4
        // variant yet.
        bp_config::Network::Testnet | bp_config::Network::Testnet4 => BitcoinNetwork::Testnet,
        bp_config::Network::Regtest => BitcoinNetwork::Regtest,
    }
}

/// Build one [`StratumV2MiningServer`] per SV1 port (so SV1 and SV2
/// share the same TCP listener — the per-port unified accept-loop in
/// [`crate::stratum`] dispatches based on the first byte). Returns an
/// empty vec when TDP is unavailable (`--skip-tdp`) — SV2 mining has
/// no jobs to serve without a template source, mirroring the SV1
/// no-op behaviour.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_per_port_servers(
    cfg: &AppConfig,
    foundation: &FoundationHandles,
    engines: &EngineHandles,
    group_service: &SharedGroupService,
    noise_config: NoiseConfig,
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    payout_resolver: Arc<dyn PayoutResolver>,
    dispatcher: Option<Arc<bp_notifications::dispatcher::NotificationDispatcher>>,
) -> Vec<Sv2PortServer> {
    let Some(tdp) = foundation.tdp.as_ref() else {
        warn!("stratum-v2: TDP missing (--skip-tdp); skipping SV2 server construction");
        return vec![];
    };

    let server_config = build_server_config(cfg);
    let network = config_network_to_bitcoin(cfg.network);
    // Use SV1's port enumeration as the canonical port list (same TCP
    // listener serves SV1 + SV2 — protocol-detect dispatches in
    // `crate::stratum`).
    let sv1_port_configs = stratum_v1::build_port_configs(cfg);
    let lookup: Arc<dyn GroupLookup> = group_service.service.clone();
    let mode_gate = engines.mode_gate.clone();
    // Phase 7.4d + 7.7: TDP submit + (engine ledger + dispatcher notification)
    // fan-out. The SV2 ShareAccept now carries the per-job pinned
    // `coinbase_tx_value_remaining`, so the engine ledger-write fires for
    // SV2-found blocks just like SV1; the dispatcher notification fires too.
    let mut sink = crate::block_sink::TdpBlockSubmissionSink::new(tdp.clone())
        .with_alt_streams(foundation.alt_tdp.clone())
        .with_fanout(
            mode_gate.clone(),
            engines.pplns.clone(),
            engines.group_solo.clone(),
            dispatcher.clone(),
            foundation.bitcoin_rpc.clone(),
        )
        .with_blockparty(engines.blockparty.clone())
        .with_pool(foundation.db.pool().clone())
        .with_redis(foundation.redis.clone());
    // The front routes block-found events to the stream — the payout Satellite
    // applies the ledger and the notify Satellite fans out the push. A front
    // always produces (front + payout can't share a process; see the boot
    // guard in main.rs), so this gates on the front role alone.
    if cfg.has_role(Role::Front) {
        sink = sink.with_block_found_producer(StreamProducer::new(
            foundation.redis.clone(),
            BLOCK_FOUND_STREAM_KEY,
        ));
    }
    let block_sink: Arc<dyn Sv2BlockSink> = sink.into_sv2_arc();

    // Phase 7.7: device-status sink. Forwards ChannelOpened / ChannelClosed.
    // With an in-process dispatcher (a front co-located with the `notify` role)
    // it fires directly; without one the front publishes to the `device:status`
    // stream so the Satellite fans it out — never a silent drop. (Stratum only
    // spawns on the front, so `None` here means "no co-located dispatcher", not
    // "notifications off".)
    let device_status_sink: Arc<dyn bp_stratum_v2::hooks::DeviceStatusSink> = match dispatcher {
        Some(d) => Arc::new(crate::device_status::DispatcherDeviceStatusSink::new(
            d,
            foundation.db.pool().clone(),
        )),
        None => Arc::new(crate::device_status::ProducingDeviceStatusSink::new(
            foundation.redis.clone(),
            foundation.db.pool().clone(),
        )),
    };

    let mut out: Vec<Sv2PortServer> = Vec::with_capacity(sv1_port_configs.len());
    for sv1_port_config in sv1_port_configs {
        let hooks = build_port_hooks(
            sv1_port_config.payout_mode,
            payout_resolver.clone(),
            block_sink.clone(),
            engines,
            lookup.clone(),
            mode_gate.clone(),
            device_status_sink.clone(),
        );

        // Subscribe + snapshot — broadcast catches future updates,
        // snapshot covers the bitcoin-core bootstrap pair the broadcast
        // typically misses (sent before this subscriber installs). See
        // memory `feedback-tdp-initial-template-drain`.
        let updates_rx = tdp.subscribe();
        let initial_snapshot = tdp.current_snapshot();
        // Every port carries ALL alt streams — mode is per-address, not
        // per-port, so a Group-Solo / Blockparty member can connect on any
        // port and must be routable onto its stream.
        let alt_streams: Vec<(StreamKind, _, _)> = foundation
            .alt_tdp
            .iter()
            .map(|(kind, handle)| (*kind, handle.subscribe(), handle.current_snapshot()))
            .collect();
        let server = StratumV2MiningServer::spawn(
            server_config.clone(),
            noise_config.clone(),
            updates_rx,
            initial_snapshot,
            alt_streams,
            hooks,
            bridge.clone(),
        );
        // Same per-port toml block drives both SV1 + SV2. start_difficulty
        // is the first SetTarget; min_difficulty is the vardiff floor (only
        // [pplns] sets it explicitly today — solo defaults to 0 which the
        // vardiff engine treats as "no floor" and falls back to a small
        // internal constant). Distinct fields so vardiff can actually
        // retarget downward instead of being stuck at start.
        // VARDIFF_DEFAULT_MIN_DIFFICULTY in bp-vardiff (default 0.00001).
        // No vardiff retarget is allowed below this; without it, mis-configured
        // ports would let vardiff march down to zero.
        let min_diff = if sv1_port_config.minimum_difficulty > 0.0 {
            sv1_port_config.minimum_difficulty
        } else {
            0.00001
        };
        let initial_diff = sv1_port_config.effective_initial_difficulty();
        let sv2_port_config = Sv2PortConfig {
            network,
            min_difficulty: Difficulty(min_diff),
            initial_difficulty: Difficulty(initial_diff),
            target_shares_per_minute: sv1_port_config.target_shares_per_minute,
            vardiff_interval_ms: cfg.stratum.difficulty_check_interval_ms,
        };
        info!(
            port = sv1_port_config.port,
            payout_mode = ?sv1_port_config.payout_mode,
            min_diff = sv2_port_config.min_difficulty.as_f64(),
            initial_diff = sv2_port_config.initial_difficulty.as_f64(),
            "stratum-v2: mining server constructed"
        );
        out.push(Sv2PortServer {
            port: sv1_port_config.port,
            port_config: sv2_port_config,
            server,
        });
    }
    out
}

// ─── MiningServerHooks composition ────────────────────────────────

fn build_port_hooks(
    port_payout_mode: MiningMode,
    payout_resolver: Arc<dyn PayoutResolver>,
    block_sink: Arc<dyn Sv2BlockSink>,
    engines: &EngineHandles,
    group_lookup: Arc<dyn GroupLookup>,
    mode_gate: Arc<BlitzpoolModeGate>,
    device_status_sink: Arc<dyn bp_stratum_v2::hooks::DeviceStatusSink>,
) -> MiningServerHooks {
    // Front-only path (Stratum spawns only on the front), where
    // `engines::spawn` always builds these composites.
    let accepted: Arc<dyn Sv2AcceptedSink> = Arc::new(Sv2AcceptedShareAdapter::new(
        engines
            .accepted_sink
            .clone()
            .expect("front mode builds the accepted composite"),
    ));
    let rejected: Arc<dyn Sv2RejectedSink> = Arc::new(Sv2RejectedShareAdapter::new(
        engines
            .rejected_sink
            .clone()
            .expect("front mode builds the rejected composite"),
    ));

    let blockparty_lookup: Option<Arc<dyn BlockpartyAdminLookup>> = engines
        .blockparty
        .clone()
        .map(|bp| Arc::new(BlockpartyApiAdminLookup(bp)) as Arc<dyn BlockpartyAdminLookup>);
    let mode_gate_persistence: Arc<dyn SharedSessionPersistence> =
        Arc::new(ModeGatePopulatingPersistence::new(
            port_payout_mode,
            mode_gate,
            group_lookup,
            blockparty_lookup,
            Arc::new(engines.session_persistence_hook.clone()),
        ));
    let session: Arc<dyn Sv2SessionPersist> =
        Arc::new(Sv2SessionPersistenceAdapter::new(mode_gate_persistence));

    MiningServerHooks {
        payout_resolver,
        block_sink,
        accepted_sink: accepted,
        rejected_sink: rejected,
        session_persistence: session,
        device_status_sink,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_config::{
        ApiConfig, BitcoinRpcConfig, DatabaseConfig, Network, PplnsConfig, RedisConfig,
        StratumConfig, Sv2Config, TdpConfig as TomlTdpConfig,
    };
    use std::path::PathBuf;

    fn min_cfg_with_sv2(privkey: Option<String>) -> AppConfig {
        AppConfig {
            network: Network::Regtest,
            pool_identifier: "Blitzpool-Test".into(),
            pool_base_url: None,
            pool_admin_email: None,
            api_secure: false,
            mode: bp_config::DeploymentMode::Satellite,
            roles: Vec::new(),
            bitcoin_rpc: BitcoinRpcConfig {
                url: "http://127.0.0.1".into(),
                user: "u".into(),
                password: "p".into(),
                port: 18443,
                timeout_ms: 1000,
            },
            bitcoin_zmq: None,
            tdp: TomlTdpConfig {
                socket_path: PathBuf::from("/tmp/bp-tdp.sock"),
                fee_threshold_sats: None,
                min_interval_secs: None,
                broadcast_capacity: None,
                staleness_threshold_secs: 120,
            },
            database: DatabaseConfig {
                driver: "postgres".into(),
                host: "h".into(),
                port: 5432,
                user: "u".into(),
                password: "p".into(),
                database: "d".into(),
                ssl: false,
                pool_size: 1,
                max_query_time_ms: 30_000,
                acquire_timeout_ms: 1_000,
                idle_timeout_ms: 1_000,
                run_migrations: false,
            },
            redis: RedisConfig {
                host: "h".into(),
                port: 6379,
                password: None,
                db: 0,
                ttl_secs: 60,
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
            },
            sv2: Sv2Config {
                authority_privkey_hex: privkey,
                ed25519_authority_seed_hex: None,
                cert_signed_part: None,
                jdp_enabled: false,
                jdp_port: None,
                jdp_orphan_submitblock: false,
            },
            debug: Default::default(),
            pplns: Some(PplnsConfig {
                port: 3340,
                high_diff_port: 3349,
                start_difficulty: 16_384,
                target_shares_per_minute: 8,
                fee_address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".into(),
                fee_percent: 1.5,
                coinbase_weight_budget: 100_000,
                min_difficulty: 1024,
                warmup_shares: 5,
                min_payout_sats: 100_000,
                dust_sweep_enabled: true,
                abandoned_balance_days: 90,
                confirmation_depth: 3,
                bucket_shares: 10_000,
                coinbase_autoscale: None,
            }),
            solo: Default::default(),
            group_fees: Default::default(),
            blockparty: None,
            notifications: Default::default(),
            smtp: None,
            capacity_alert: Default::default(),
            aggregation: Default::default(),
            metrics: Default::default(),
        }
    }

    /// SRI test private key as 32 raw bytes hex-encoded. NOT the same
    /// as the production `[sv2].authority_privkey_hex` — this one is
    /// the well-known SV2 testnet fixture (also in
    /// `bp-stratum-v2/src/noise.rs::tests`).
    const TEST_PRIVKEY_HEX: &str =
        "8d698e28310f2e60707bc4f26eebba81915dc4e2c6647e635ed452cbac49c5f6";

    #[test]
    fn build_noise_config_decodes_hex_secret() {
        let cfg = min_cfg_with_sv2(Some(TEST_PRIVKEY_HEX.to_string()));
        let noise = build_noise_config(&cfg).expect("must parse");
        assert_eq!(noise.cert_validity(), DEFAULT_CERT_VALIDITY);
        // Public key derived from secret must be non-zero.
        assert_ne!((*noise.authority_pub()).into_bytes(), [0u8; 32]);
    }

    #[test]
    fn build_noise_config_rejects_missing_privkey() {
        let cfg = min_cfg_with_sv2(None);
        assert!(matches!(
            build_noise_config(&cfg),
            Err(StratumV2SpawnError::AuthorityKeyMissing)
        ));
    }

    #[test]
    fn build_noise_config_rejects_wrong_length() {
        let cfg = min_cfg_with_sv2(Some("aa".to_string()));
        assert!(matches!(
            build_noise_config(&cfg),
            Err(StratumV2SpawnError::AuthorityPrivkeyHexLen(2))
        ));
    }

    #[test]
    fn build_noise_config_rejects_non_hex() {
        let cfg = min_cfg_with_sv2(Some("g".repeat(64)));
        assert!(matches!(
            build_noise_config(&cfg),
            Err(StratumV2SpawnError::AuthorityPrivkeyHex(_))
        ));
    }

    // Production resolver lives in `crate::payout_resolver`; its unit
    // tests cover the solo-only fallback shape.
}
