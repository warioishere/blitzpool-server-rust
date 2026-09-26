// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 mining-server composition.
//!
//! Builds one [`StratumV2MiningServer`] per port (mirrors the SV1
//! per-port-server topology in [`crate::stratum_v1`]). The shared
//! `JdpDeclaredJobRegistry` bridge is constructed at the top level
//! by [`crate::stratum::spawn`] and threaded into every per-port
//! SV2 server clone so `SetCustomMiningJob` routing works across
//! ports.
//!
//! ## What the caller supplies
//!
//! - [`PayoutResolver`] is supplied by the caller from
//!   [`crate::payout_resolver::ProductionPayoutResolver`]. This module
//!   once shipped a solo-only stub instead; the
//!   production resolver now consults the mode-gate + PPLNS /
//!   Group-Solo engine round state to assemble the real per-mode
//!   coinbase distribution.
//!
//! - `BlockSubmissionSink` is [`crate::block_sink::TdpBlockSubmissionSink`].
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

// Note: stratum-apps depends on `secp256k1` 0.28 internally, but the
// blitzpool workspace pins 0.29 elsewhere — passing raw [u8;32] via
// `secp256k1::SecretKey::from_slice` would fail-type-check across the
// version boundary. Instead we round-trip via base58check (the
// canonical wire-format `Secp256k1SecretKey::FromStr` parses).

use crate::boot::FoundationHandles;
use crate::engines::EngineHandles;
use crate::group_service::SharedGroupService;
use crate::stratum_v1::{self, GroupLookup, ModeGatePopulatingPersistence};

/// Per-port SV2 mining server bundle. One entry per port (mirrors
/// [`crate::stratum_v1::Sv1PortServer`]). Carries the SV2 `PortConfig`
/// (different shape from SV1's) so the unified accept-loop can hand it
/// in to `accept_connection`.
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
/// and derives the matching x-only public key.
pub(crate) fn build_noise_config(cfg: &AppConfig) -> Result<NoiseConfig, StratumV2SpawnError> {
    let hex_str = cfg
        .sv2
        .authority_privkey_hex
        .as_deref()
        .ok_or(StratumV2SpawnError::PrivkeyMissing)?;
    if hex_str.len() != 64 {
        return Err(StratumV2SpawnError::PrivkeyHexLen(hex_str.len()));
    }
    let raw_bytes =
        hex::decode(hex_str).map_err(|e| StratumV2SpawnError::PrivkeyHex(e.to_string()))?;
    // Round-trip via base58check — stratum-apps's `FromStr` parses
    // that form, which avoids depending on a specific `secp256k1`
    // version (stratum-apps pins 0.28; the workspace uses 0.29).
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
    custom_extranonce: Arc<dyn bp_stratum_v2::hooks::CustomExtranonceSource>,
    // The pool's one rotating-identity intake — the same `Arc` SV1 gets, built
    // in `crate::stratum`. See SV1's `build_per_port_servers`.
    rotating_intake: Arc<dyn bp_common::RotatingIntake>,
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
    // Use SV1's port enumeration as the canonical port list (same TCP
    // listener serves SV1 + SV2 — protocol-detect dispatches in
    // `crate::stratum`).
    let sv1_port_configs = stratum_v1::build_port_configs(cfg);
    let lookup: Arc<dyn GroupLookup> = group_service.service.clone();
    // TDP submit + (engine ledger + dispatcher notification)
    // fan-out. The SV2 ShareAccept now carries the per-job pinned
    // `coinbase_tx_value_remaining`, so the engine ledger-write fires for
    // SV2-found blocks just like SV1; the dispatcher notification fires too.
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

    // One extranonce allocator shared across every SV2 port, as SV1 does —
    // a separate one per port starts each at the same prefix, and two PPLNS
    // ports hash the same coinbase.
    let extranonce = SharedExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID);

    for sv1_port_config in sv1_port_configs {
        let hooks = build_port_hooks(
            sv1_port_config.payout_mode,
            payout_resolver.clone(),
            rotating_intake.clone(),
            block_sink.clone(),
            engines,
            lookup.clone(),
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
    rotating_intake: Arc<dyn bp_common::RotatingIntake>,
    block_sink: Arc<dyn Sv2BlockSink>,
    engines: &EngineHandles,
    group_lookup: Arc<dyn GroupLookup>,
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
            group_lookup,
            live_sessions,
        ),
        device_status_sink,
        custom_extranonce,
        rotating_intake: Some(rotating_intake),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_config::{
        ApiConfig, BitcoinRpcConfig, DatabaseConfig, Network, PayoutIdentityConfig, PplnsConfig,
        RedisConfig, StratumConfig, Sv2Config, TdpConfig as TomlTdpConfig,
    };
    use std::path::PathBuf;

    fn min_cfg_with_sv2(privkey: Option<String>) -> AppConfig {
        AppConfig {
            network: Network::Regtest,
            pool_identifier: "Blitzpool-Test".into(),
            pool_base_url: None,
            roles: Vec::new(),
            // Default: rotating identities off — these tests assert SV2's
            // existing static-address behaviour.
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
            group_fees: Default::default(),
            blockparty: None,
            notifications: Default::default(),
            smtp: None,
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
        // Public key derived from secret must be non-zero.
        assert_ne!((*noise.authority_pub()).into_bytes(), [0u8; 32]);
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

    /// 64 bytes that are not 64 ASCII characters: a multi-byte character
    /// straddling a two-character hex pair is a decode error, not a panic.
    #[test]
    fn build_noise_config_rejects_non_ascii() {
        let cfg = min_cfg_with_sv2(Some(format!("€{}", "a".repeat(61))));
        assert!(matches!(
            build_noise_config(&cfg),
            Err(StratumV2SpawnError::PrivkeyHex(_))
        ));
    }

    // Production resolver lives in `crate::payout_resolver`; its unit
    // tests cover the solo-only fallback shape.
}
