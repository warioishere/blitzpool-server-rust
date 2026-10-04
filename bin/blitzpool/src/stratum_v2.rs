// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 mining-server composition: one [`StratumV2MiningServer`] per port of
//! [`crate::stratum_v1`]'s port set, with the same resolver, block sink,
//! share sinks and mode gate as SV1. The JDP bridge is shared by every port
//! so `SetCustomMiningJob` routing works across ports.

use std::sync::{Arc, RwLock};

use bp_common::MiningMode;
use bp_config::AppConfig;
use bp_jobs_lifecycle::LifecycleConfig;
use bp_share::Difficulty;
use bp_stratum_v2::bridge::JdpDeclaredJobRegistry;
use bp_stratum_v2::extranonce::{SharedExtranonceAllocator, SV2_WORKER_ID};
use bp_stratum_v2::hooks::{
    BlockSubmissionSink as Sv2BlockSink, MiningServerHooks, PayoutResolver,
};
use bp_stratum_v2::mining::client::PortConfig as Sv2PortConfig;
use bp_stratum_v2::noise::NoiseConfig;
use bp_stratum_v2::server::{ServerConfig as Sv2ServerConfig, StratumV2MiningServer};
use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use thiserror::Error;
use tracing::{info, warn};

use crate::boot::FoundationHandles;
use crate::engines::EngineHandles;
use crate::membership::Membership;
use crate::stratum_v1::{self, ModeGatePopulatingPersistence};

/// Per-port SV2 mining server, like [`crate::stratum_v1::Sv1PortServer`].
/// Carries the SV2 `PortConfig` the unified accept loop passes to
/// `accept_connection`.
pub(crate) struct Sv2PortServer {
    pub(crate) port: u16,
    pub(crate) port_config: Sv2PortConfig,
    pub(crate) server: StratumV2MiningServer,
}

#[derive(Debug, Error)]
pub(crate) enum StratumV2SpawnError {
    #[error("sv2 authority private key hex must be exactly 64 hex chars (32 bytes): got {0}")]
    PrivkeyHexLen(usize),
    #[error("sv2 authority private key hex didn't decode: {0}")]
    PrivkeyHex(String),
    #[error("sv2 authority private key bytes didn't parse: {0}")]
    InvalidPrivkey(String),
    #[error("sv2 needs [sv2].authority_privkey_hex (32-byte hex) — none configured")]
    PrivkeyMissing,
}

/// Construct the shared [`JdpDeclaredJobRegistry`] (declared-job →
/// mining-channel routing), one per process, used by every SV2 mining
/// server and the JDP server. A `std::sync::RwLock`: no `await` is held
/// across it.
pub(crate) fn build_bridge() -> Arc<RwLock<JdpDeclaredJobRegistry>> {
    Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()))
}

/// Build the pool-wide [`NoiseConfig`] from `[sv2]`. Decodes
/// `authority_privkey_hex` (raw 32-byte secp256k1 secret in hex),
/// and derives the matching x-only public key.
pub(crate) fn build_noise_config(cfg: &AppConfig) -> Result<NoiseConfig, StratumV2SpawnError> {
    let hex_str = cfg
        .sv2
        .authority_privkey_hex
        .as_deref()
        .ok_or(StratumV2SpawnError::PrivkeyMissing)?;
    noise_config_from_hex(hex_str)
}

/// A fresh authority key as `(authority_privkey_hex, public key)`, the public
/// key in the form SV2 miners are configured with. Decoded through the same
/// path the pool takes at start, so the pair is one the pool accepts.
pub(crate) fn generate_authority_key() -> Result<(String, String), getrandom::Error> {
    loop {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret)?;
        let hex_str = hex::encode(secret);
        // Only a zero or out-of-range scalar fails; draw again.
        if let Ok(noise) = noise_config_from_hex(&hex_str) {
            return Ok((hex_str, noise.authority_pub().to_string()));
        }
    }
}

fn noise_config_from_hex(hex_str: &str) -> Result<NoiseConfig, StratumV2SpawnError> {
    if hex_str.len() != 64 {
        return Err(StratumV2SpawnError::PrivkeyHexLen(hex_str.len()));
    }
    let raw_bytes =
        hex::decode(hex_str).map_err(|e| StratumV2SpawnError::PrivkeyHex(e.to_string()))?;
    // Round-trip via base58check, the form `Secp256k1SecretKey::FromStr`
    // parses: stratum-apps pins `secp256k1` 0.28 and the workspace 0.29,
    // so raw key types do not cross the version boundary.
    let b58 = bs58::encode(&raw_bytes).with_check().into_string();
    let authority_prv: Secp256k1SecretKey =
        b58.parse().map_err(|e: stratum_apps::key_utils::Error| {
            StratumV2SpawnError::InvalidPrivkey(format!("{e:?}"))
        })?;
    let authority_pub: Secp256k1PublicKey = authority_prv.into();
    Ok(NoiseConfig::new(authority_pub, authority_prv))
}

/// Build the SV2 [`ServerConfig`](Sv2ServerConfig) from the network +
/// pool identifier in the toplevel `AppConfig`.
pub(crate) fn build_server_config(cfg: &AppConfig) -> Sv2ServerConfig {
    let network = crate::boot::bitcoin_network(cfg.network);
    let mut sc = Sv2ServerConfig::defaults_for(network);
    sc.pool_identifier = cfg.pool_identifier.clone();
    sc.debug_messages = cfg.debug.stratum_wire_logs;
    sc.share_logs = cfg.debug.stratum_share_logs;
    sc.log_submit_latency = cfg.debug.submit_latency;
    sc
}

/// Build one [`StratumV2MiningServer`] per SV1 port; both share the port's
/// listener in [`crate::stratum`]. Empty when TDP is unavailable
/// (`--skip-tdp`), like SV1.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_per_port_servers(
    cfg: &AppConfig,
    foundation: &FoundationHandles,
    engines: &EngineHandles,
    membership: &Membership,
    noise_config: NoiseConfig,
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    payout_resolver: Arc<dyn PayoutResolver>,
    custom_extranonce: Arc<dyn bp_stratum_v2::hooks::CustomExtranonceSource>,
    dispatcher: Option<Arc<bp_notifications::dispatcher::NotificationDispatcher>>,
    device_status_sink: Arc<dyn bp_share_hook::DeviceStatusSink>,
    live_sessions: Arc<crate::live_sessions::LiveSessionRegistry>,
    job_cache: Arc<bp_mining_job::MiningJobCache>,
    settle: crate::settlement::SettlementSignal,
) -> Vec<Sv2PortServer> {
    let Some(tdp) = foundation.tdp.as_ref() else {
        warn!("stratum-v2: TDP missing (--skip-tdp); skipping SV2 server construction");
        return vec![];
    };

    let server_config = build_server_config(cfg);
    let network = crate::boot::bitcoin_network(cfg.network);
    // SV1's port enumeration is the canonical port list.
    let sv1_port_configs = stratum_v1::build_port_configs(cfg);
    // TDP submit plus engine ledger and dispatcher fan-out, as for SV1.
    let block_sink: Arc<dyn Sv2BlockSink> = crate::block_sink::TdpBlockSubmissionSink::wired(
        tdp.clone(),
        cfg,
        foundation,
        engines,
        dispatcher.clone(),
        settle,
    )
    .into_sv2_arc();

    let mut out: Vec<Sv2PortServer> = Vec::with_capacity(sv1_port_configs.len());

    // One extranonce allocator across every SV2 port: separate ones would
    // start at the same prefix, and two PPLNS ports would hash the same
    // coinbase.
    let extranonce = SharedExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID);

    for sv1_port_config in sv1_port_configs {
        let hooks = build_port_hooks(
            sv1_port_config.payout_mode,
            payout_resolver.clone(),
            block_sink.clone(),
            engines,
            membership,
            device_status_sink.clone(),
            Arc::clone(&live_sessions),
            custom_extranonce.clone(),
        );

        let templates = crate::stratum::PortTemplates::subscribe(tdp, foundation);
        let server = StratumV2MiningServer::spawn(
            server_config.clone(),
            noise_config.clone(),
            templates.updates_rx,
            templates.initial_snapshot,
            templates.alt_streams,
            hooks,
            bridge.clone(),
            extranonce.clone(),
            job_cache.clone(),
        );
        // The same per-port config drives SV1 and SV2. start_difficulty is
        // the first SetTarget; min_difficulty is the vardiff floor, which
        // only [pplns] sets. Without a floor, 0.00001 (bp-vardiff's
        // default minimum) keeps vardiff from marching down to zero.
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
            vardiff_silence_easing: cfg.stratum.vardiff_silence_easing_enabled,
            job_lifecycle: LifecycleConfig {
                retention_ms: cfg.stratum.job_retention_ms,
                ..LifecycleConfig::DEFAULT
            },
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

#[allow(clippy::too_many_arguments)]
fn build_port_hooks(
    port_payout_mode: MiningMode,
    payout_resolver: Arc<dyn PayoutResolver>,
    block_sink: Arc<dyn Sv2BlockSink>,
    engines: &EngineHandles,
    membership: &Membership,
    device_status_sink: Arc<dyn bp_share_hook::DeviceStatusSink>,
    live_sessions: Arc<crate::live_sessions::LiveSessionRegistry>,
    custom_extranonce: Arc<dyn bp_stratum_v2::hooks::CustomExtranonceSource>,
) -> MiningServerHooks {
    // Front-only path (Stratum spawns only on the front), where
    // `engines::spawn` always builds these composites.
    MiningServerHooks {
        payout_resolver,
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
        device_status_sink,
        custom_extranonce,
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
            sv2: Sv2Config {
                jdp_validation_socket_path: None,
                authority_privkey_hex: privkey,
                jdp_enabled: false,
                jdp_port: None,
                jdp_orphan_submitblock: false,
                jdp_payout_distribution_interval_secs: None,
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
                min_payout_sats: 100_000,
                dust_sweep_enabled: true,
                abandoned_balance_days: 90,
                confirmation_depth: 3,
                bucket_shares: 10_000,
                coinbase_autoscale: None,
            }),
            solo: Default::default(),
            group_solo: None,
            blockparty: None,
            notifications: Default::default(),
            smtp: None,
            metrics: Default::default(),
        }
    }

    /// A well-known SV2 test private key, 32 raw bytes hex-encoded. Never a production key.
    const TEST_PRIVKEY_HEX: &str =
        "8d698e28310f2e60707bc4f26eebba81915dc4e2c6647e635ed452cbac49c5f6";

    #[test]
    fn build_noise_config_decodes_hex_secret() {
        let cfg = min_cfg_with_sv2(Some(TEST_PRIVKEY_HEX.to_string()));
        let noise = build_noise_config(&cfg).expect("must parse");
        // Public key derived from secret must be non-zero.
        assert_ne!((*noise.authority_pub()).into_bytes(), [0u8; 32]);
    }

    /// The logged public key is the base58check form SV2 miners and JD
    /// clients are configured with; the pair is the SV2 reference dev key.
    #[test]
    fn the_authority_public_key_displays_as_miners_configure_it() {
        let cfg = min_cfg_with_sv2(Some(
            "65995eb19631f478a46ffa5cf1e545091efe950eaeac7482ffdc06eb6a89f697".to_string(),
        ));
        let noise = build_noise_config(&cfg).expect("must parse");
        assert_eq!(
            noise.authority_pub().to_string(),
            "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
        );
    }

    /// `--sv2-keygen` prints a pair the pool accepts at start: the config it
    /// yields resolves to the very public key printed next to it.
    #[test]
    fn a_generated_authority_key_is_one_the_pool_starts_with() {
        let (secret_hex, public_key) = generate_authority_key().expect("randomness");
        let cfg = min_cfg_with_sv2(Some(secret_hex.clone()));
        let noise = build_noise_config(&cfg).expect("the pool accepts the generated key");
        assert_eq!(noise.authority_pub().to_string(), public_key);
        let (other, _) = generate_authority_key().expect("randomness");
        assert_ne!(other, secret_hex, "every run draws a new key");
    }

    #[test]
    fn build_noise_config_rejects_missing_privkey() {
        let cfg = min_cfg_with_sv2(None);
        assert!(matches!(
            build_noise_config(&cfg),
            Err(StratumV2SpawnError::PrivkeyMissing)
        ));
    }

    #[test]
    fn build_noise_config_rejects_wrong_length() {
        let cfg = min_cfg_with_sv2(Some("aa".to_string()));
        assert!(matches!(
            build_noise_config(&cfg),
            Err(StratumV2SpawnError::PrivkeyHexLen(2))
        ));
    }

    #[test]
    fn build_noise_config_rejects_non_hex() {
        let cfg = min_cfg_with_sv2(Some("g".repeat(64)));
        assert!(matches!(
            build_noise_config(&cfg),
            Err(StratumV2SpawnError::PrivkeyHex(_))
        ));
    }

    /// A multi-byte character in a 64-byte key is a decode error, not a panic.
    #[test]
    fn build_noise_config_rejects_non_ascii() {
        let cfg = min_cfg_with_sv2(Some(format!("€{}", "a".repeat(61))));
        assert!(matches!(
            build_noise_config(&cfg),
            Err(StratumV2SpawnError::PrivkeyHex(_))
        ));
    }
}
