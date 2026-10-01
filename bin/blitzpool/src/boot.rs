// SPDX-License-Identifier: AGPL-3.0-or-later

//! Foundation handles: [`boot`] builds every long-lived dependency the
//! engines need, in dependency order. Postgres, Redis, Bitcoin RPC and (front
//! role only) TDP are essential and fatal on failure, since no templates
//! means no jobs; GeoIP and Metrics are optional.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bp_bitcoin::{BitcoinRpc, BitcoinRpcConfig as BtcRpcConfig, RpcAuth};
use bp_common::StreamKind;
use bp_config::{AppConfig, BitcoinRpcConfig, DatabaseConfig, RedisConfig, Role, TdpConfig};
use bp_db::{Db, DbConfig};
use bp_geoip::{GeoIpService, ReqwestGeoIpClient};
use bp_metrics::{MetricsService, MetricsServiceHandle, PrometheusConfig};
use bp_template_distribution::{TdpCoinbaseConstraints, TdpConfig as TdpSpawnConfig, TdpHandle};
use redis::aio::ConnectionManager;
use thiserror::Error;
use tracing::{info, warn};

/// Long-lived runtime dependencies the engine wiring consumes.
// Consumers borrow the aggregate and clone individual handles.
pub(crate) struct FoundationHandles {
    pub(crate) db: Db,
    pub(crate) redis: ConnectionManager,
    pub(crate) bitcoin_rpc: BitcoinRpc,
    /// **Default** TDP stream with the PPLNS-autoscaled reservation; also
    /// feeds JDP, the bp-api block-template and the autoscaler. `None` under
    /// `--skip-tdp`, which consumers treat as "feature disabled".
    pub(crate) tdp: Option<TdpHandle>,
    /// Fixed-reservation **alt** TDP streams per [`StreamKind`], each its own
    /// IPC connection: their small reservations reclaim the PPLNS-sized block
    /// space those modes would waste. Routed per connection by
    /// [`StreamKind::for_mode`].
    pub(crate) alt_tdp: HashMap<StreamKind, TdpHandle>,
    pub(crate) geoip: Option<Arc<GeoIpService>>,
    pub(crate) metrics: Option<MetricsServiceHandle>,
}

impl FoundationHandles {
    /// A dedicated Redis [`ConnectionManager`] for a blocking stream consumer:
    /// `XREAD BLOCK` on a multiplexed connection head-of-line-blocks every
    /// command queued behind it. Falls back to the shared handle only if a
    /// fresh connection can't be opened.
    pub(crate) async fn dedicated_redis(&self, cfg: &RedisConfig, who: &str) -> ConnectionManager {
        match spawn_redis(cfg).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    consumer = who,
                    "dedicated redis connection failed; reusing the shared handle \
                     (its blocking read may stall this process's redis throughput)"
                );
                self.redis.clone()
            }
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum BootError {
    #[error("postgres connect failed: {0}")]
    Db(#[from] bp_db::DbError),
    #[error("redis connect failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("bitcoin rpc init failed: {0}")]
    BitcoinRpc(#[from] bp_bitcoin::RpcError),
    #[error("tdp spawn failed: {0}")]
    Tdp(#[from] bp_template_distribution::TdpError),
    /// Construction succeeded but the initial liveness ping failed:
    /// bitcoin-core unreachable, wrong RPC credentials or a closed port.
    #[error("bitcoin rpc liveness ping failed: {0}")]
    BitcoinRpcLiveness(bp_bitcoin::RpcError),
}

/// Boot-time flags that override the strict defaults (staging only).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BootOptions {
    /// Skip the `getnetworkinfo` liveness ping; the RPC client is still
    /// built. For staging where bitcoind is unreachable but PG, Redis and
    /// HTTP should come up.
    pub(crate) skip_bitcoin_rpc_liveness: bool,
    /// Skip TDP spawn entirely: the PPLNS network-difficulty bootstrap
    /// defaults to 1.0 and `/info/block-template` returns 503. Never in
    /// production.
    pub(crate) skip_tdp: bool,
}

/// Build every essential handle. Optional handles (GeoIP, Metrics)
/// return `None` on failure with a `warn!` line rather than aborting.
pub(crate) async fn boot(
    cfg: &AppConfig,
    opts: BootOptions,
) -> Result<FoundationHandles, BootError> {
    let db = spawn_pg(&cfg.database).await?;
    let redis = spawn_redis(&cfg.redis).await?;
    let bitcoin_rpc = spawn_bitcoin_rpc(&cfg.bitcoin_rpc, opts.skip_bitcoin_rpc_liveness).await?;
    // TDP feeds the share path and block submit, a front-only concern; a
    // process without the `front` role builds no jobs and needs no IPC
    // socket.
    let (tdp, alt_tdp) = if opts.skip_tdp || !cfg.has_role(Role::Front) {
        if opts.skip_tdp {
            warn!(
                "tdp: spawn skipped via --skip-tdp; pplns net-diff bootstrap will fall back to 1.0"
            );
        } else {
            info!(roles = ?cfg.effective_roles(), "tdp: spawn skipped (process has no front role)");
        }
        (None, HashMap::new())
    } else {
        // Default stream: PPLNS-autoscaled (or DEFAULT_COINBASE_WEIGHT_BUDGET
        // when no PPLNS). Serves PPLNS connections.
        let default_constraints = coinbase_constraints_from_pplns_budget(cfg.pplns.as_ref());
        let tdp = spawn_tdp_stream(&cfg.tdp, default_constraints, StreamKind::Pplns.as_label())?;
        // Alt streams: small FIXED reservations against the same socket, one
        // per non-PPLNS mode, each sized so its mode's coinbase never
        // overflows it. Blockparty only when `[blockparty]` is configured.
        let mut alt_specs: Vec<(StreamKind, u32)> = vec![
            (StreamKind::Solo, cfg.solo.coinbase_weight_budget),
            (StreamKind::GroupSolo, cfg.group_fees.coinbase_weight_budget),
        ];
        if let Some(bp) = cfg.blockparty.as_ref() {
            alt_specs.push((StreamKind::Blockparty, bp.coinbase_weight_budget));
        }
        let mut alt_tdp = HashMap::new();
        for (kind, budget) in alt_specs {
            alt_tdp.insert(
                kind,
                spawn_tdp_stream(&cfg.tdp, tdp_constraint_for_budget(budget), kind.as_label())?,
            );
        }
        (Some(tdp), alt_tdp)
    };
    let geoip = spawn_geoip().map(Arc::new);
    let metrics = spawn_metrics(&cfg.metrics);
    info!("foundation handles ready");
    Ok(FoundationHandles {
        db,
        redis,
        bitcoin_rpc,
        tdp,
        alt_tdp,
        geoip,
        metrics,
    })
}

// ─── Postgres ─────────────────────────────────────────────────────

pub(crate) async fn spawn_pg(cfg: &DatabaseConfig) -> Result<Db, BootError> {
    let url = build_pg_url(cfg);
    let pool_cfg = DbConfig {
        max_connections: cfg.pool_size,
        acquire_timeout: Duration::from_millis(cfg.acquire_timeout_ms),
        idle_timeout: Duration::from_millis(cfg.idle_timeout_ms),
    };
    info!(
        host = %cfg.host,
        port = cfg.port,
        db = %cfg.database,
        pool_size = cfg.pool_size,
        "postgres: connecting"
    );
    let db = Db::connect_with(&url, pool_cfg).await?;
    info!("postgres: connected");
    // Apply pending migrations before serving. Advisory-locked and
    // idempotent, so every process can run it at boot; the first applies.
    info!("postgres: applying migrations");
    db.run_migrations().await?;
    info!("postgres: migrations applied");
    Ok(db)
}

/// Build a libpq-style URL from the typed config. User and password are
/// percent-encoded (`@`, `:`, `/` would break the URL); SSL is signalled via
/// `?sslmode=require`.
fn build_pg_url(cfg: &DatabaseConfig) -> String {
    let user = encode_pg_url_component(&cfg.user);
    let password = encode_pg_url_component(&cfg.password);
    let mut url = format!(
        "postgres://{user}:{password}@{host}:{port}/{db}",
        host = cfg.host,
        port = cfg.port,
        db = cfg.database,
    );
    if cfg.ssl {
        url.push_str("?sslmode=require");
    }
    url
}

/// Minimal percent-encoder for the chars libpq treats as separators
/// in the URL form. Good enough for the values an operator types into
/// a config file; not a general-purpose encoder.
fn encode_pg_url_component(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            ':' => "%3A".to_string(),
            '@' => "%40".to_string(),
            '/' => "%2F".to_string(),
            '?' => "%3F".to_string(),
            '#' => "%23".to_string(),
            '%' => "%25".to_string(),
            c => c.to_string(),
        })
        .collect()
}

// ─── Redis ─────────────────────────────────────────────────────────

pub(crate) async fn spawn_redis(cfg: &RedisConfig) -> Result<ConnectionManager, redis::RedisError> {
    info!(
        host = %cfg.host,
        port = cfg.port,
        db = cfg.db,
        password_set = cfg.password.is_some(),
        "redis: connecting"
    );
    let client = redis::Client::open(redis_connection_info(cfg))?;
    let manager = ConnectionManager::new(client).await?;
    info!("redis: connected");
    Ok(manager)
}

/// Typed connection info, so a password needs no URL encoding. An empty
/// password means none, the same as an empty password in a `redis://` URL.
fn redis_connection_info(cfg: &RedisConfig) -> redis::ConnectionInfo {
    redis::ConnectionInfo {
        addr: redis::ConnectionAddr::Tcp(cfg.host.clone(), cfg.port),
        redis: redis::RedisConnectionInfo {
            db: i64::from(cfg.db),
            username: None,
            password: cfg.password.clone().filter(|pw| !pw.is_empty()),
            protocol: redis::ProtocolVersion::RESP2,
        },
    }
}

// ─── Bitcoin RPC ──────────────────────────────────────────────────

async fn spawn_bitcoin_rpc(
    cfg: &BitcoinRpcConfig,
    skip_liveness: bool,
) -> Result<BitcoinRpc, BootError> {
    // Append the default port when the operator-supplied URL doesn't
    // already carry one. Conservative: an explicit port in `url` wins.
    let url = if cfg.url.matches(':').count() >= 2 {
        // scheme://host:port → already has both colons; leave as-is.
        cfg.url.clone()
    } else {
        format!("{url}:{port}", url = cfg.url, port = cfg.port)
    };
    let btc_cfg = BtcRpcConfig {
        url: url.clone(),
        auth: RpcAuth::UserPassword {
            user: cfg.user.clone(),
            password: cfg.password.clone(),
        },
        timeout: Some(Duration::from_millis(cfg.timeout_ms)),
    };
    info!(url = %url, "bitcoin rpc: client init");
    let rpc = BitcoinRpc::new(btc_cfg)?;
    if skip_liveness {
        warn!("bitcoin rpc: liveness ping skipped via --skip-bitcoin-rpc-liveness");
        return Ok(rpc);
    }
    // Liveness ping with its own error variant, so an unreachable node or
    // wrong credentials fail at boot with a pointed message.
    rpc.get_network_info()
        .await
        .map_err(BootError::BitcoinRpcLiveness)?;
    info!("bitcoin rpc: ready (getnetworkinfo ok)");
    Ok(rpc)
}

// ─── TDP ──────────────────────────────────────────────────────────

/// Headroom over the byte-equivalent of `coinbase_weight_budget` (BIP-141
/// weight units; `bytes ≈ weight / 4` for non-witness outputs), so a
/// mismatch between the pre-trim weight estimate and the serialised size
/// never yields a coinbase larger than bitcoin-core reserved.
const TDP_COINBASE_SIZE_HEADROOM_BYTES: u32 = 256;

/// The `bitcoin` network a configured [`bp_config::Network`] parses and
/// builds addresses for. testnet4 shares the `tb` HRP and address bytes with
/// testnet3, and rust-bitcoin 0.32 has no Testnet4 variant, so both map to
/// `Testnet`.
pub(crate) fn bitcoin_network(n: bp_config::Network) -> bitcoin::Network {
    match n {
        bp_config::Network::Mainnet => bitcoin::Network::Bitcoin,
        bp_config::Network::Testnet | bp_config::Network::Testnet4 => bitcoin::Network::Testnet,
        bp_config::Network::Regtest => bitcoin::Network::Regtest,
    }
}

/// Derive the bitcoin-core `CoinbaseOutputConstraints` for a coinbase weight
/// budget. Boot and [`crate::coinbase_autoscaler`] both call it, so core's
/// reservation never drifts from what the trimmer fits: a coinbase larger
/// than core reserved makes core reject the block.
pub(crate) fn tdp_constraint_for_budget(weight_budget: u32) -> TdpCoinbaseConstraints {
    // Non-witness outputs weigh ~4 × bytes; ceil errs on the side of more
    // headroom.
    let bytes_strict = weight_budget.div_ceil(4);
    let max_additional_size = bytes_strict.saturating_add(TDP_COINBASE_SIZE_HEADROOM_BYTES);
    TdpCoinbaseConstraints {
        max_additional_size,
        // Pay-to-address scripts and the witness commitment OP_RETURN
        // count no sigops.
        max_additional_sigops: 0,
    }
}

/// The default stream's reservation, coupled to `pplns.coinbase_weight_budget`
/// so a TOML edit cannot move the trimmer's budget without core's reservation.
fn coinbase_constraints_from_pplns_budget(
    pplns: Option<&bp_config::PplnsConfig>,
) -> TdpCoinbaseConstraints {
    let weight_budget = pplns
        .map(|p| p.coinbase_weight_budget)
        .unwrap_or(bp_pplns::DEFAULT_COINBASE_WEIGHT_BUDGET);
    tdp_constraint_for_budget(weight_budget)
}

/// Spawn one TDP worker with a given coinbase reservation. Each reservation
/// class is a separate IPC connection to the same bitcoind; `label` tells
/// them apart in logs.
fn spawn_tdp_stream(
    cfg: &TdpConfig,
    constraints: TdpCoinbaseConstraints,
    label: &str,
) -> Result<TdpHandle, BootError> {
    let mut spawn_cfg = TdpSpawnConfig::new(&cfg.socket_path);
    if let Some(fee) = cfg.fee_threshold_sats {
        spawn_cfg = spawn_cfg.with_fee_threshold(fee);
    }
    if let Some(min_interval) = cfg.min_interval_secs {
        spawn_cfg = spawn_cfg.with_min_interval_secs(min_interval);
    }
    if let Some(cap) = cfg.broadcast_capacity {
        spawn_cfg = spawn_cfg.with_broadcast_capacity(cap);
    }
    spawn_cfg = spawn_cfg.with_coinbase_constraints(constraints);
    info!(
        stream = label,
        socket = %cfg.socket_path.display(),
        coinbase_max_additional_size = constraints.max_additional_size,
        coinbase_max_additional_sigops = constraints.max_additional_sigops,
        "tdp: spawning worker"
    );
    let handle = TdpHandle::spawn(spawn_cfg)?;
    info!(stream = label, "tdp: handle live");
    Ok(handle)
}

// ─── GeoIP (optional) ─────────────────────────────────────────────

/// The GeoIP service (`http://ip-api.com`, 10-minute cache). Fails only if
/// the HTTP client cannot be built; an unreachable upstream just caches
/// `None` for 10 min.
fn spawn_geoip() -> Option<GeoIpService> {
    match ReqwestGeoIpClient::new(bp_geoip::BASE_URL, bp_geoip::REQUEST_TIMEOUT) {
        Ok(client) => {
            info!("geoip: handle live");
            Some(GeoIpService::spawn(Arc::new(client), bp_geoip::CACHE_TTL))
        }
        Err(err) => {
            warn!(%err, "geoip: client init failed — continuing without geoip");
            None
        }
    }
}

// ─── Metrics (optional) ───────────────────────────────────────────

/// Install the global Prometheus recorder and spawn the `/metrics`
/// listener, gated on `[metrics] enabled = true` (default off). A bind
/// failure is logged and ignored: only dashboards depend on the exporter.
fn spawn_metrics(cfg: &bp_config::MetricsConfig) -> Option<MetricsServiceHandle> {
    if !cfg.enabled {
        info!("metrics: disabled ([metrics] enabled = false); set to true to expose /metrics");
        return None;
    }
    let prom_cfg = match cfg.bind.as_deref() {
        Some(bind) => match PrometheusConfig::with_bind(bind) {
            Ok(c) => c,
            Err(err) => {
                warn!(%err, bind, "metrics: [metrics].bind invalid; falling back to default");
                PrometheusConfig::default()
            }
        },
        None => PrometheusConfig::default(),
    };
    match MetricsService::spawn(prom_cfg) {
        Ok(handle) => {
            info!(bind = %handle.bind_addr, "metrics: exporter live");
            Some(handle)
        }
        Err(err) => {
            warn!(%err, "metrics: spawn failed — continuing without exporter");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_network_maps_to_bitcoin_network() {
        use bp_config::Network as Config;
        assert_eq!(bitcoin_network(Config::Mainnet), bitcoin::Network::Bitcoin);
        assert_eq!(bitcoin_network(Config::Testnet), bitcoin::Network::Testnet);
        assert_eq!(bitcoin_network(Config::Testnet4), bitcoin::Network::Testnet);
        assert_eq!(bitcoin_network(Config::Regtest), bitcoin::Network::Regtest);
    }

    #[test]
    fn pg_url_build_round_trips_simple_values() {
        let cfg = DatabaseConfig {
            host: "127.0.0.1".into(),
            port: 5432,
            user: "postgres".into(),
            password: "secret".into(),
            database: "public_pool".into(),
            ssl: false,
            pool_size: 10,
            acquire_timeout_ms: 60_000,
            idle_timeout_ms: 10_000,
        };
        let url = build_pg_url(&cfg);
        assert_eq!(url, "postgres://postgres:secret@127.0.0.1:5432/public_pool");
    }

    #[test]
    fn pg_url_build_escapes_separators_in_password() {
        let mut cfg = DatabaseConfig {
            host: "h".into(),
            port: 5432,
            user: "u".into(),
            // password contains `@` and `:` which must be percent-encoded
            password: "p@ss:word".into(),
            database: "d".into(),
            ssl: false,
            pool_size: 10,
            acquire_timeout_ms: 60_000,
            idle_timeout_ms: 10_000,
        };
        let url = build_pg_url(&cfg);
        assert_eq!(url, "postgres://u:p%40ss%3Aword@h:5432/d");
        cfg.ssl = true;
        let url = build_pg_url(&cfg);
        assert!(url.ends_with("?sslmode=require"));
    }

    /// Parses the equivalent `redis://` URL, so the typed info is checked
    /// against URL semantics.
    fn redis_info_from_url(url: &str) -> redis::ConnectionInfo {
        redis::IntoConnectionInfo::into_connection_info(url).unwrap()
    }

    fn assert_same_redis_info(a: &redis::ConnectionInfo, b: &redis::ConnectionInfo) {
        assert_eq!(a.addr, b.addr);
        assert_eq!(a.redis.db, b.redis.db);
        assert_eq!(a.redis.username, b.redis.username);
        assert_eq!(a.redis.password, b.redis.password);
        assert_eq!(a.redis.protocol, b.redis.protocol);
    }

    #[test]
    fn redis_info_omits_password_when_absent() {
        let cfg = RedisConfig {
            host: "h".into(),
            port: 6379,
            password: None,
            db: 3,
        };
        let info = redis_connection_info(&cfg);
        assert_same_redis_info(&info, &redis_info_from_url("redis://h:6379/3"));
        assert_eq!(info.redis.password, None);
    }

    #[test]
    fn redis_info_includes_password_when_present() {
        let cfg = RedisConfig {
            host: "h".into(),
            port: 6379,
            password: Some("redis".into()),
            db: 0,
        };
        let info = redis_connection_info(&cfg);
        assert_same_redis_info(&info, &redis_info_from_url("redis://:redis@h:6379/0"));
    }

    #[test]
    fn redis_info_keeps_url_separators_in_password_verbatim() {
        let cfg = RedisConfig {
            host: "h".into(),
            port: 6379,
            password: Some("p@ss:w/o?r#d%20 x".into()),
            db: 1,
        };
        let info = redis_connection_info(&cfg);
        assert_eq!(info.redis.password.as_deref(), Some("p@ss:w/o?r#d%20 x"));
        assert_same_redis_info(
            &info,
            &redis_info_from_url("redis://:p%40ss%3Aw%2Fo%3Fr%23d%2520%20x@h:6379/1"),
        );
    }

    #[test]
    fn redis_info_treats_empty_password_as_none_like_the_url_did() {
        let cfg = RedisConfig {
            host: "h".into(),
            port: 6379,
            password: Some(String::new()),
            db: 0,
        };
        let info = redis_connection_info(&cfg);
        assert_same_redis_info(&info, &redis_info_from_url("redis://:@h:6379/0"));
        assert_eq!(info.redis.password, None);
    }

    // ── TDP coinbase constraints coupling ─────────────────────────

    #[test]
    fn coinbase_constraints_uses_pplns_default_when_no_pplns_block() {
        let c = coinbase_constraints_from_pplns_budget(None);
        // 50 000 WU / 4 = 12 500 bytes; + 256 byte headroom.
        assert_eq!(c.max_additional_size, 12_500 + 256);
        assert_eq!(c.max_additional_sigops, 0);
    }

    #[test]
    fn coinbase_constraints_scales_with_configured_budget() {
        let pplns = bp_config::PplnsConfig {
            port: 3340,
            high_diff_port: 3349,
            start_difficulty: 16_384,
            target_shares_per_minute: 8,
            fee_address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".into(),
            fee_percent: 1.5,
            coinbase_weight_budget: 100_000,
            min_difficulty: 1024,
            min_payout_sats: 5_000,
            dust_sweep_enabled: true,
            abandoned_balance_days: 90,
            confirmation_depth: 3,
            bucket_shares: 10_000,
            coinbase_autoscale: None,
        };
        let c = coinbase_constraints_from_pplns_budget(Some(&pplns));
        // 100 000 WU / 4 = 25 000 bytes; + 256 byte headroom.
        assert_eq!(c.max_additional_size, 25_000 + 256);
    }

    #[test]
    fn coinbase_constraints_rounds_up_ceil_div_4() {
        // 50 003 WU / 4 = 12 501 (ceil), not 12 500 (floor).
        let pplns = bp_config::PplnsConfig {
            port: 3340,
            high_diff_port: 3349,
            start_difficulty: 16_384,
            target_shares_per_minute: 8,
            fee_address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".into(),
            fee_percent: 1.5,
            coinbase_weight_budget: 50_003,
            min_difficulty: 1024,
            min_payout_sats: 5_000,
            dust_sweep_enabled: true,
            abandoned_balance_days: 90,
            confirmation_depth: 3,
            bucket_shares: 10_000,
            coinbase_autoscale: None,
        };
        let c = coinbase_constraints_from_pplns_budget(Some(&pplns));
        assert_eq!(c.max_additional_size, 12_501 + 256);
    }
}
