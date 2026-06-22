// SPDX-License-Identifier: AGPL-3.0-or-later

//! Foundation-handle spawning — Phase 7.1.
//!
//! [`boot`] builds every long-lived dependency the Phase-7.2+ engines
//! need, in dependency order:
//!
//! 1. **Postgres pool** — `sqlx::PgPool` via `bp_db::Db::connect_with`.
//!    Essential. Connect failure → fatal.
//! 2. **Redis** — `redis::aio::ConnectionManager`. Essential (PPLNS
//!    window + group-solo round state both live there). Connect
//!    failure → fatal.
//! 3. **Bitcoin RPC** — `BitcoinRpc::new` + a single ping via
//!    `getnetworkinfo`. Connect failure → fatal.
//! 4. **TDP** — `TdpHandle::spawn` against the bitcoin-core IPC
//!    socket. Spawn failure → fatal (no templates ⇒ no jobs ⇒ no
//!    point in running).
//! 5. **GeoIP** — optional. Lookup-cache only; if `ip-api.com` is
//!    unreachable at boot the resolver still serves Stratum, just
//!    without country/city labels on peer-info responses.
//! 6. **Metrics** — optional. `/metrics` endpoint installation is a
//!    process-global recorder install; if the bind port is in use we
//!    warn-and-continue (the pool itself doesn't depend on the
//!    exporter).
//!
//! Returns a [`FoundationHandles`] aggregate cloned + threaded into
//! Phase 7.2's `run` function. Everything in `FoundationHandles` is
//! cheaply cloneable (single `Arc` under the hood).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bp_bitcoin::{BitcoinRpc, BitcoinRpcConfig as BtcRpcConfig, RpcAuth};
use bp_common::StreamKind;
use bp_config::{AppConfig, BitcoinRpcConfig, DatabaseConfig, RedisConfig, Role, TdpConfig};
use bp_db::{Db, DbConfig};
use bp_geoip::{GeoIpConfig, GeoIpService, GeoIpServiceHandle, ReqwestGeoIpClient};
use bp_metrics::{MetricsService, MetricsServiceHandle, PrometheusConfig};
use bp_template_distribution::{TdpCoinbaseConstraints, TdpConfig as TdpSpawnConfig, TdpHandle};
use redis::aio::ConnectionManager;
use thiserror::Error;
use tracing::{info, warn};

/// Long-lived runtime dependencies the engine wiring (Phase 7.2+)
/// consumes. Clone-on-share; the underlying handles all share an
/// `Arc` so duplicating this struct is cheap.
// Phase 7.2+ wires every field into the engine layer + bp-api
// AppState; consumers borrow the aggregate (`&FoundationHandles`)
// and clone individual handles internally. `FoundationHandles`
// itself is NOT `Clone` because `GeoIpServiceHandle` owns an
// exclusive shutdown `oneshot` and can't satisfy the bound.
#[allow(dead_code)]
pub(crate) struct FoundationHandles {
    pub(crate) db: Db,
    pub(crate) redis: ConnectionManager,
    pub(crate) bitcoin_rpc: BitcoinRpc,
    /// **Default** TDP stream — PPLNS-autoscaled reservation. Serves every
    /// non-Solo payout mode (PPLNS / Group-Solo / Blockparty), plus JDP, the
    /// bp-api block-template, and the coinbase-budget autoscaler.
    /// `None` when `--skip-tdp`; consumers treat the missing handle as
    /// "feature disabled" rather than fatal.
    pub(crate) tdp: Option<TdpHandle>,
    /// Fixed-reservation **alt** TDP streams keyed by [`StreamKind`] (Solo /
    /// GroupSolo / Blockparty), each a separate IPC connection against the same
    /// bitcoind. Their small fixed coinbase reservations reclaim the
    /// PPLNS-sized block space those modes' blocks would otherwise waste.
    /// Empty when `--skip-tdp`. Blockparty is present only when `[blockparty]`
    /// is configured. Routed to per-connection by [`StreamKind::for_mode`].
    pub(crate) alt_tdp: HashMap<StreamKind, TdpHandle>,
    pub(crate) geoip: Option<Arc<GeoIpServiceHandle>>,
    pub(crate) metrics: Option<MetricsServiceHandle>,
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
    /// Construction succeeded but the initial liveness ping failed.
    /// Surfaces a hint to the operator that the bitcoin-core process
    /// likely isn't reachable / RPC creds are wrong / port is closed.
    #[error("bitcoin rpc liveness ping failed: {0}")]
    BitcoinRpcLiveness(bp_bitcoin::RpcError),
}

/// Boot-time flags that override the strict defaults. Currently
/// only one knob (`skip_bitcoin_rpc_liveness`) — kept as a struct
/// so additions in later sub-phases don't churn the call signature.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BootOptions {
    /// Skip the bitcoin-rpc `getnetworkinfo` liveness ping. The RPC
    /// client itself still gets built; only the proof-of-reachability
    /// is bypassed. Useful in staging where bitcoind isn't reachable
    /// from the operator's workstation but the rest of the pool
    /// stack (PG, Redis, HTTP) should still come up.
    pub(crate) skip_bitcoin_rpc_liveness: bool,
    /// Skip TDP spawn entirely — leaves `FoundationHandles.tdp` as
    /// an unused stub. The PPLNS network-difficulty bootstrap will
    /// warn-and-default-to-1.0; bp-api `/info/block-template` will
    /// return 503. Same staging affordance as the RPC liveness skip
    /// — production should never set this.
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
    // TDP is the template source for the share path + block submit — a
    // front-only concern. Any process that doesn't run the `front` role
    // (api / payout / stats) holds no Stratum listeners and never builds
    // jobs, so it skips the TDP spawn entirely (and doesn't need the
    // bitcoin-core IPC socket). Gated on the role, NOT `cfg.mode`: a
    // role-overridden process (BLITZPOOL_ROLES) keeps `mode` at its default.
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
        // per non-PPLNS mode. Each is sized so its mode's coinbase never
        // overflows the reservation. Blockparty is only included when the
        // feature is configured — an absent `[blockparty]` table means no
        // Blockparty connections, so no stream.
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

async fn spawn_pg(cfg: &DatabaseConfig) -> Result<Db, BootError> {
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
    // Apply pending schema migrations before serving. Advisory-locked +
    // idempotent, so every process in the split can run it at boot — the
    // first wins the lock and applies, the rest see them done.
    info!("postgres: applying migrations");
    db.run_migrations().await?;
    info!("postgres: migrations applied");
    Ok(db)
}

/// Build a libpq-style URL from the typed config. We URL-encode the
/// password naively (`%`/`@`/`/` would break the URL otherwise); the
/// `urlencoding` crate isn't worth a dep just for this so we do it
/// inline. SSL is signalled via the `?sslmode=...` query parameter.
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
    let url = build_redis_url(cfg);
    info!(
        host = %cfg.host,
        port = cfg.port,
        db = cfg.db,
        password_set = cfg.password.is_some(),
        "redis: connecting"
    );
    let client = redis::Client::open(url)?;
    let manager = ConnectionManager::new(client).await?;
    info!("redis: connected");
    Ok(manager)
}

fn build_redis_url(cfg: &RedisConfig) -> String {
    match &cfg.password {
        Some(pw) => format!(
            "redis://:{password}@{host}:{port}/{db}",
            password = encode_pg_url_component(pw),
            host = cfg.host,
            port = cfg.port,
            db = cfg.db,
        ),
        None => format!(
            "redis://{host}:{port}/{db}",
            host = cfg.host,
            port = cfg.port,
            db = cfg.db,
        ),
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
    // Single liveness ping. If bitcoind isn't reachable / creds wrong
    // we surface a separate error variant so the operator sees a
    // pointed hint rather than a generic `BitcoinRpc` failure later
    // when the first share comes in.
    rpc.get_network_info()
        .await
        .map_err(BootError::BitcoinRpcLiveness)?;
    info!("bitcoin rpc: ready (getnetworkinfo ok)");
    Ok(rpc)
}

// ─── TDP ──────────────────────────────────────────────────────────

/// Headroom over the strict byte-equivalent of `coinbase_weight_budget`.
/// `coinbase_weight_budget` is in BIP-141 weight units (witness-discount
/// applied). For a coinbase whose extra outputs are all non-witness data,
/// `bytes ≈ weight / 4`. We round up + add a small constant cushion so
/// transient mismatch between our pre-trim weight estimate and the
/// post-serialisation byte count never produces a coinbase larger than
/// what bitcoin-core was told to reserve.
const TDP_COINBASE_SIZE_HEADROOM_BYTES: u32 = 256;

/// Derive [`TdpCoinbaseConstraints`] from `pplns.coinbase_weight_budget`.
///
/// **Invariant**: bitcoin-core must be told via `CoinbaseOutputConstraints`
/// IPC how much space the pool will append to coinbase outputs. If the
/// PPLNS trimmer emits more bytes than core reserved, the resulting block
/// exceeds template weight expectations and **bitcoin-core rejects it.**
/// This conversion couples the trimmer's budget to the IPC-advertised
/// constraint so the two can never drift apart through a TOML edit on one
/// side alone.
/// Derive the bitcoin-core `CoinbaseOutputConstraints` for a given coinbase
/// weight budget. **Single source of truth** for the budget→reservation
/// mapping — both the boot path and the runtime autoscaler
/// ([`crate::coinbase_autoscaler`]) call this so core's reservation can never
/// drift from what the PPLNS trimmer was told to fit.
pub(crate) fn tdp_constraint_for_budget(weight_budget: u32) -> TdpCoinbaseConstraints {
    // BIP-141 weight = (base × 3) + total. For non-witness-only coinbase
    // outputs that's ~ 4 × bytes; we use ceil to err on the side of more
    // headroom (operator never asked for less than `weight_budget` worth).
    let bytes_strict = weight_budget.div_ceil(4);
    let max_additional_size = bytes_strict.saturating_add(TDP_COINBASE_SIZE_HEADROOM_BYTES);
    TdpCoinbaseConstraints {
        max_additional_size,
        // Coinbase outputs are paid-to-address scripts (P2PKH / P2SH /
        // P2WPKH / P2WSH / P2TR + the witness commitment OP_RETURN); none
        // of these execute opcodes that count as sigops. Keep at 0.
        max_additional_sigops: 0,
    }
}

fn coinbase_constraints_from_pplns_budget(
    pplns: Option<&bp_config::PplnsConfig>,
) -> TdpCoinbaseConstraints {
    let weight_budget = pplns
        .map(|p| p.coinbase_weight_budget)
        .unwrap_or(bp_pplns::DEFAULT_COINBASE_WEIGHT_BUDGET);
    tdp_constraint_for_budget(weight_budget)
}

/// Spawn one TDP worker against the IPC socket with a given coinbase
/// reservation. The pool runs multiple streams (one per reservation class)
/// against the SAME bitcoind — each is a separate IPC connection; `label`
/// distinguishes them in logs.
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

/// Construct the GeoIP service handle. Hard-codes `http://ip-api.com`
/// and a 10-minute cache TTL (config knobs would be net-new). Failures
/// only ever come from the `validate()` step (empty base URL) — never
/// from network I/O.
/// If the upstream service is unreachable at boot, lookups during
/// the pool's runtime quietly cache `None` for 10 min.
fn spawn_geoip() -> Option<GeoIpServiceHandle> {
    let cfg = GeoIpConfig::default();
    let client = match ReqwestGeoIpClient::new(cfg.base_url.clone(), Duration::from_secs(5)) {
        Ok(c) => Arc::new(c),
        Err(err) => {
            warn!(%err, "geoip: client init failed — continuing without geoip");
            return None;
        }
    };
    match GeoIpService::spawn(cfg, client) {
        Ok(handle) => {
            info!("geoip: handle live");
            Some(handle)
        }
        Err(err) => {
            warn!(%err, "geoip: spawn failed — continuing without geoip");
            None
        }
    }
}

// ─── Metrics (optional) ───────────────────────────────────────────

/// Install the global Prometheus recorder + spawn the `/metrics`
/// HTTP listener — gated on `[metrics] enabled = true` in the TOML
/// (default off; the recorder calls aren't wired yet). If the bind
/// port is already in use (another
/// process / a previous instance that didn't release), we log and
/// continue — the pool itself doesn't depend on the exporter being
/// up; only operator dashboards do.
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
    fn pg_url_build_round_trips_simple_values() {
        let cfg = DatabaseConfig {
            driver: "postgres".into(),
            host: "127.0.0.1".into(),
            port: 5432,
            user: "postgres".into(),
            password: "secret".into(),
            database: "public_pool".into(),
            ssl: false,
            pool_size: 10,
            max_query_time_ms: 30_000,
            acquire_timeout_ms: 60_000,
            idle_timeout_ms: 10_000,
            run_migrations: false,
        };
        let url = build_pg_url(&cfg);
        assert_eq!(url, "postgres://postgres:secret@127.0.0.1:5432/public_pool");
    }

    #[test]
    fn pg_url_build_escapes_separators_in_password() {
        let mut cfg = DatabaseConfig {
            driver: "postgres".into(),
            host: "h".into(),
            port: 5432,
            user: "u".into(),
            // password contains `@` and `:` which must be percent-encoded
            password: "p@ss:word".into(),
            database: "d".into(),
            ssl: false,
            pool_size: 10,
            max_query_time_ms: 30_000,
            acquire_timeout_ms: 60_000,
            idle_timeout_ms: 10_000,
            run_migrations: false,
        };
        let url = build_pg_url(&cfg);
        assert_eq!(url, "postgres://u:p%40ss%3Aword@h:5432/d");
        cfg.ssl = true;
        let url = build_pg_url(&cfg);
        assert!(url.ends_with("?sslmode=require"));
    }

    #[test]
    fn redis_url_build_omits_password_when_absent() {
        let cfg = RedisConfig {
            host: "h".into(),
            port: 6379,
            password: None,
            db: 3,
            ttl_secs: 600,
        };
        assert_eq!(build_redis_url(&cfg), "redis://h:6379/3");
    }

    #[test]
    fn redis_url_build_includes_password_when_present() {
        let cfg = RedisConfig {
            host: "h".into(),
            port: 6379,
            password: Some("redis".into()),
            db: 0,
            ttl_secs: 600,
        };
        assert_eq!(build_redis_url(&cfg), "redis://:redis@h:6379/0");
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
            warmup_shares: 5,
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
            warmup_shares: 5,
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
