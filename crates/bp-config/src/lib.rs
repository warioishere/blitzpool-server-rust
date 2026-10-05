// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed configuration for `bin/blitzpool`, read from one TOML file.
//! No env-var overrides except `--roles` / `BLITZPOOL_ROLES`.
//! `deny_unknown_fields` everywhere so a typo is a load error, not a silent
//! default; an absent optional table (`Option<T>`) means the feature is off.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

/// Top-level config — one of these per process.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// `mainnet` / `testnet` / `regtest`. Affects address parsing
    /// network-byte expectations + which Bitcoin Core network the
    /// RPC + TDP/JDP endpoints are assumed to be on.
    pub network: Network,
    /// Human-readable pool name. Surfaced in `/api/info/pool` +
    /// Stratum subscribe-response client identifier.
    pub pool_identifier: String,
    /// Public UI base URL (no trailing slash). Used to assemble
    /// invitation + verification links in transactional emails.
    /// Required when SMTP + email features are enabled.
    #[serde(default)]
    pub pool_base_url: Option<String>,

    /// The roles this process runs — the single source of deployment topology.
    /// Required here or via `--roles` / `BLITZPOOL_ROLES`; the binary exits at
    /// boot without it.
    #[serde(default)]
    pub roles: Vec<Role>,

    pub bitcoin_rpc: BitcoinRpcConfig,
    pub tdp: TdpConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,

    pub api: ApiConfig,
    pub stratum: StratumConfig,
    #[serde(default)]
    pub sv2: Sv2Config,
    #[serde(default)]
    pub pplns: Option<PplnsConfig>,
    #[serde(default)]
    pub solo: SoloConfig,
    #[serde(default)]
    pub group_solo: Option<GroupSoloConfig>,
    #[serde(default)]
    pub blockparty: Option<BlockpartyConfig>,

    #[serde(default)]
    pub notifications: NotificationsConfig,
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
    #[serde(default)]
    pub metrics: MetricsConfig,

    #[serde(default)]
    pub debug: DebugConfig,
}

/// Protocol-level debug logging switches, all off by default because the
/// share traces are noisy under production load.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DebugConfig {
    /// Per-frame SV1/SV2 wire dumps — heavy under load. Per-share
    /// diagnostics are [`Self::stratum_share_logs`].
    #[serde(default)]
    pub stratum_wire_logs: bool,
    /// Per-share diagnostic logs for accepted shares; rejections always log
    /// at WARN regardless of this flag.
    #[serde(default)]
    pub stratum_share_logs: bool,
    /// Log the pool-internal submit→ack latency (SV1 and SV2) per share at
    /// INFO, to separate pool processing time from network/miner latency.
    #[serde(default)]
    pub submit_latency: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Mainnet,
    Testnet,
    /// Bitcoin testnet4 (BIP-94). Shares the `tb` HRP with testnet3, so
    /// address parsing uses the same `bitcoin::Network::Testnet` byte set.
    Testnet4,
    Regtest,
}

/// Deployment role; the set a process runs gates each subsystem at boot.
/// "Satellite" is any non-[`Role::Front`] process: it consumes the front's
/// Redis streams (at-least-once, dedup on `share_id`), so it can restart
/// without dropping miners.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Always-on share path: Stratum listeners + share producer + block
    /// submit + JDP + read-only coinbase engines. The `core` process.
    Front,
    /// HTTP API — serves over PG/Redis with read-only engines, no consumers.
    Api,
    /// Payout accounting: PPLNS + Group-Solo + Blockparty ledger (accepted +
    /// rejected + block-found ledger apply) + the confirmation watcher.
    Payout,
    /// Share statistics + per-session persistence (best-diff / touch / charts).
    Stats,
    /// Notifications: dispatcher, command listeners, push/digest crons and the
    /// block-found + device-status fan-out. Separate so notification changes
    /// redeploy without restarting the `payout` process.
    Notify,
}

impl std::str::FromStr for Role {
    type Err = String;

    /// Case-insensitive, so all containers can share one config and differ
    /// only by `BLITZPOOL_ROLES`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "front" => Ok(Role::Front),
            "api" => Ok(Role::Api),
            "payout" => Ok(Role::Payout),
            "stats" => Ok(Role::Stats),
            "notify" => Ok(Role::Notify),
            other => Err(format!(
                "unknown role {other:?} (expected one of: front, api, payout, stats, notify)"
            )),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinRpcConfig {
    /// Full base URL incl. scheme (`http://…`). The `port` field is
    /// appended to this if the URL doesn't already carry one.
    pub url: String,
    pub user: String,
    pub password: String,
    pub port: u16,
    #[serde(default = "default_rpc_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TdpConfig {
    /// bitcoin-core IPC socket the templates arrive over (TDP).
    pub socket_path: PathBuf,
    /// Minimum block-reward fee (sats) before a refreshed template supersedes
    /// the previous one. Lower → more template churn. Default 1_000_000.
    #[serde(default)]
    pub fee_threshold_sats: Option<u64>,
    /// Minimum interval between template refreshes (seconds).
    #[serde(default)]
    pub min_interval_secs: Option<u8>,
    /// Template broadcast channel capacity. Default 16.
    #[serde(default)]
    pub broadcast_capacity: Option<usize>,
    /// Age (seconds) past which `/api/health` reports the template stale.
    /// Generous so a brief bitcoin-core restart does not flip health, only a
    /// prolonged outage does. Default 120.
    #[serde(default = "default_tdp_staleness_threshold_secs")]
    pub staleness_threshold_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub host: String,
    #[serde(default = "default_pg_port")]
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
    #[serde(default)]
    pub ssl: bool,
    #[serde(default = "default_pg_pool_size")]
    pub pool_size: u32,
    #[serde(default = "default_pg_acquire_timeout_ms")]
    pub acquire_timeout_ms: u64,
    #[serde(default = "default_pg_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisConfig {
    pub host: String,
    #[serde(default = "default_redis_port")]
    pub port: u16,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub db: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    pub port: u16,
    /// Per-endpoint response-cache TTLs (seconds).
    #[serde(default)]
    pub cache: ApiCacheConfig,
}

/// Response-cache TTLs for the read-only API surface. Each field is
/// a TTL in seconds for the named endpoint family. Set to `0` to
/// disable caching for that family.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiCacheConfig {
    #[serde(default = "ttl_site_info")]
    pub site_info_secs: u64,
    #[serde(default = "ttl_pool_info")]
    pub pool_info_secs: u64,
    #[serde(default = "ttl_60")]
    pub core_info_secs: u64,
    #[serde(default = "ttl_60")]
    pub peer_info_secs: u64,
    #[serde(default = "ttl_60")]
    pub chart_secs: u64,
    #[serde(default = "ttl_60")]
    pub shares_secs: u64,
    #[serde(default = "ttl_60")]
    pub workers_secs: u64,
    #[serde(default = "ttl_60")]
    pub accepted_secs: u64,
    #[serde(default = "ttl_60")]
    pub rejected_secs: u64,
    #[serde(default = "ttl_60")]
    pub client_block_template_secs: u64,
    #[serde(default = "ttl_60")]
    pub client_info_secs: u64,
    #[serde(default = "ttl_60")]
    pub client_chart_secs: u64,
    #[serde(default = "ttl_60")]
    pub client_worker_shares_secs: u64,
    #[serde(default = "ttl_60")]
    pub client_workers_secs: u64,
    #[serde(default = "ttl_60")]
    pub client_accepted_secs: u64,
    #[serde(default = "ttl_60")]
    pub client_rejected_secs: u64,
    #[serde(default = "ttl_60")]
    pub client_worker_group_secs: u64,
    #[serde(default = "ttl_60")]
    pub client_worker_session_secs: u64,

    // ─── PPLNS endpoints ────────────────────────────────────────
    #[serde(default = "ttl_60")]
    pub pplns_root_secs: u64,
    #[serde(default = "ttl_60")]
    pub pplns_mode_secs: u64,
    #[serde(default = "ttl_60")]
    pub pplns_status_secs: u64,
    #[serde(default = "ttl_60")]
    pub pplns_fees_secs: u64,
    #[serde(default = "ttl_60")]
    pub pplns_distribution_secs: u64,
    #[serde(default = "ttl_60")]
    pub pplns_chart_secs: u64,
    /// Ledger is more sensitive (credits/debits) — keep TTL short.
    #[serde(default = "ttl_30")]
    pub pplns_ledger_secs: u64,
    #[serde(default = "ttl_60")]
    pub pplns_address_secs: u64,
    #[serde(default = "ttl_60")]
    pub pplns_address_history_secs: u64,

    // ─── Group endpoints ────────────────────────────────────────
    #[serde(default = "ttl_60")]
    pub group_public_list_secs: u64,
    #[serde(default = "ttl_60")]
    pub group_detail_secs: u64,
    #[serde(default = "ttl_60")]
    pub group_public_detail_secs: u64,
    #[serde(default = "ttl_60")]
    pub group_hashrate_secs: u64,
    #[serde(default = "ttl_60")]
    pub group_chart_secs: u64,
    #[serde(default = "ttl_60")]
    pub group_accepted_secs: u64,
    #[serde(default = "ttl_60")]
    pub group_rejected_secs: u64,
    #[serde(default = "ttl_60")]
    pub group_distribution_secs: u64,
    #[serde(default = "ttl_60")]
    pub group_best_difficulty_secs: u64,
    #[serde(default = "ttl_60")]
    pub group_history_secs: u64,
    /// Often mutated (accept / decline / revoke) — short TTL.
    #[serde(default = "ttl_30")]
    pub group_invitations_secs: u64,
    #[serde(default = "ttl_30")]
    pub group_join_requests_secs: u64,

    /// Total cache entries before LRU eviction; dominated by
    /// per-`(address, range)` client keys.
    #[serde(default = "default_cache_capacity")]
    pub max_entries: u64,
}

impl Default for ApiCacheConfig {
    fn default() -> Self {
        Self {
            site_info_secs: ttl_site_info(),
            pool_info_secs: ttl_pool_info(),
            core_info_secs: ttl_60(),
            peer_info_secs: ttl_60(),
            chart_secs: ttl_60(),
            shares_secs: ttl_60(),
            workers_secs: ttl_60(),
            accepted_secs: ttl_60(),
            rejected_secs: ttl_60(),
            client_block_template_secs: ttl_60(),
            client_info_secs: ttl_60(),
            client_chart_secs: ttl_60(),
            client_worker_shares_secs: ttl_60(),
            client_workers_secs: ttl_60(),
            client_accepted_secs: ttl_60(),
            client_rejected_secs: ttl_60(),
            client_worker_group_secs: ttl_60(),
            client_worker_session_secs: ttl_60(),

            pplns_root_secs: ttl_60(),
            pplns_mode_secs: ttl_60(),
            pplns_status_secs: ttl_60(),
            pplns_fees_secs: ttl_60(),
            pplns_distribution_secs: ttl_60(),
            pplns_chart_secs: ttl_60(),
            pplns_ledger_secs: ttl_30(),
            pplns_address_secs: ttl_60(),
            pplns_address_history_secs: ttl_60(),

            group_public_list_secs: ttl_60(),
            group_detail_secs: ttl_60(),
            group_public_detail_secs: ttl_60(),
            group_hashrate_secs: ttl_60(),
            group_chart_secs: ttl_60(),
            group_accepted_secs: ttl_60(),
            group_rejected_secs: ttl_60(),
            group_distribution_secs: ttl_60(),
            group_best_difficulty_secs: ttl_60(),
            group_history_secs: ttl_60(),
            group_invitations_secs: ttl_30(),
            group_join_requests_secs: ttl_30(),

            max_entries: default_cache_capacity(),
        }
    }
}

fn ttl_30() -> u64 {
    30
}
fn ttl_60() -> u64 {
    60
}
fn ttl_site_info() -> u64 {
    300
}
fn ttl_pool_info() -> u64 {
    600
}
fn default_job_retention_ms() -> u64 {
    600_000
}

fn default_cache_capacity() -> u64 {
    10_000
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StratumConfig {
    /// Solo SV1 listener port.
    pub solo_port: u16,
    pub solo_start_difficulty: u64,
    /// High-difficulty SV1 listener port.
    pub solo_high_diff_port: u16,
    pub high_diff_start_difficulty: u64,
    /// How long a retired job stays stored (SV1 and SV2); a share against a
    /// dropped job is rejected as unknown. Default 600 000 (10 min).
    #[serde(default = "default_job_retention_ms")]
    pub job_retention_ms: u64,
    pub target_shares_per_minute: u32,
    pub high_diff_target_shares_per_minute: u32,
    pub difficulty_check_interval_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sv2Config {
    /// 32-byte secp256k1 authority private key in hex (`blitzpool --sv2-keygen`).
    /// Required by the front: its Stratum and JDP servers refuse to start
    /// without it. SV2 miners pin the public key derived from it.
    #[serde(default)]
    pub authority_privkey_hex: Option<String>,
    #[serde(default)]
    pub jdp_enabled: bool,
    #[serde(default)]
    pub jdp_port: Option<u16>,
    /// Reconstruct a pushed solution and `submitblock` it: the only way to meet
    /// SV2 JDP/PushSolution (JDS MUST propagate) on Core v31, whose IPC
    /// solution submit is a stub. A "duplicate" answer is normal. `false` logs
    /// only and leaves propagation to the JDC's own node.
    #[serde(default = "default_true")]
    pub jdp_orphan_submitblock: bool,
    /// bitcoin-core IPC socket (normally the `[tdp]` one) for `checkBlock`
    /// validation of declared jobs (SV2 JDP/Job Declarator Server); unset
    /// trusts the JDC. Must be a `<dir>/<network>/node.sock` path the engine
    /// can derive, else boot refuses rather than validate against nothing.
    #[serde(default)]
    pub jdp_validation_socket_path: Option<PathBuf>,
    /// Republish cadence (seconds) for the ext 0x0003 `SetPayoutDistribution`
    /// push. Invalidation also fires it immediately; the timer only bounds
    /// staleness between blocks. Default 60.
    #[serde(default)]
    pub jdp_payout_distribution_interval_secs: Option<u64>,
}

impl Default for Sv2Config {
    /// A missing `[sv2]` section must equal an empty one. `#[derive(Default)]`
    /// would skip serde's per-field defaults and turn `jdp_orphan_submitblock`
    /// off, breaking SV2 JDP/PushSolution.
    fn default() -> Self {
        // Deserializing an empty table keeps that true for every future field.
        toml::from_str("").expect("empty [sv2] table applies every serde default")
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PplnsConfig {
    /// Standard PPLNS listener port.
    pub port: u16,
    /// High-difficulty PPLNS listener port.
    pub high_diff_port: u16,
    pub start_difficulty: u64,
    pub target_shares_per_minute: u32,
    /// Address paid the pool fee in every PPLNS coinbase; must parse for
    /// `network`.
    pub fee_address: String,
    /// Fee as percent of block reward. Trimming and dust-sweep never pad it:
    /// the fee output is exactly this percentage.
    pub fee_percent: f64,
    /// Coinbase weight budget (WU), sent to bitcoin-core over TDP. Lower →
    /// fewer recipients, more tx-fee room. Floored at
    /// `bp_pplns::MIN_COINBASE_WEIGHT_BUDGET`, below which nothing is
    /// publishable.
    pub coinbase_weight_budget: u32,
    /// VarDiff floor for the PPLNS port (sub-ASIC hardware gate).
    pub min_difficulty: u64,
    /// Minimum on-chain payout in sats; smaller amounts stay as pending
    /// ledger credit. Clamped up to the dust limit by the engine.
    pub min_payout_sats: i64,
    /// Daily PPLNS dust-sweep cron (pair-cancels abandoned credit against
    /// abandoned debit). Manual admin sweeps work regardless.
    #[serde(default = "default_true")]
    pub dust_sweep_enabled: bool,
    /// Inactivity (days) before a `pplns_balance` row is sweepable. Must be
    /// positive so freshly credited rows are never swept.
    #[serde(default = "default_abandoned_days")]
    pub abandoned_balance_days: u32,
    /// Confirmations before a found block's distribution is booked, so an
    /// orphaned block never reaches the ledger. The on-chain payment is
    /// unaffected. Default 3.
    #[serde(default = "default_confirmation_depth")]
    pub confirmation_depth: u32,
    /// Shares per window bucket. Never raise it on a live window: the bucket
    /// id comes from a never-resetting counter, so a bigger divisor puts new
    /// shares below the live window where the trim discards them. Lowering
    /// is harmless.
    #[serde(default = "default_bucket_shares")]
    pub bucket_shares: u64,
    /// Coinbase-budget autoscaler. Absent ⇒ the budget stays fixed at
    /// `coinbase_weight_budget`; present ⇒ it adjusts at runtime between that
    /// floor and `max_weight_budget`.
    #[serde(default)]
    pub coinbase_autoscale: Option<CoinbaseAutoscaleConfig>,
}

/// `[pplns.coinbase_autoscale]`: the budget steps multiplicatively between the
/// parent's `coinbase_weight_budget` (floor, boot seed) and
/// `max_weight_budget`, with hysteresis, debounce and cooldown so it never
/// flaps. See `bp_pplns_engine::autoscale`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoinbaseAutoscaleConfig {
    /// Master switch. Defaults to `true` — declaring the section implies
    /// intent to autoscale; set `false` to stage config without enabling.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Hard upper bound in WU — the budget never rises above this. Required:
    /// autoscaling without a ceiling could reserve unbounded block space.
    pub max_weight_budget: u32,
    /// Step up when utilization ≥ this fraction of the trim threshold
    /// (`0.85` = "15% before trimming"). Range `(down_threshold, 1.0]`.
    #[serde(default = "default_autoscale_up_threshold")]
    pub up_threshold: f64,
    /// Step down when utilization ≤ this fraction (`0.50`). Range `(0.0, up)`.
    #[serde(default = "default_autoscale_down_threshold")]
    pub down_threshold: f64,
    /// Multiplicative step (`1.15` → +15% up / ÷1.15 down). Must be `> 1.0`.
    #[serde(default = "default_autoscale_step_factor")]
    pub step_factor: f64,
    /// Consecutive over-threshold samples before stepping up (quick).
    #[serde(default = "default_autoscale_up_debounce")]
    pub up_debounce: u32,
    /// Consecutive under-threshold samples before stepping down (lazy).
    #[serde(default = "default_autoscale_down_debounce")]
    pub down_debounce: u32,
    /// Minimum seconds between two budget changes.
    #[serde(default = "default_autoscale_cooldown_secs")]
    pub cooldown_secs: u64,
    /// How often the driver samples utilization + evaluates (seconds).
    #[serde(default = "default_autoscale_sample_interval_secs")]
    pub sample_interval_secs: u64,
}

fn default_autoscale_up_threshold() -> f64 {
    0.85
}
fn default_autoscale_down_threshold() -> f64 {
    0.50
}
fn default_autoscale_step_factor() -> f64 {
    1.15
}
fn default_autoscale_up_debounce() -> u32 {
    3
}
fn default_autoscale_down_debounce() -> u32 {
    10
}
fn default_autoscale_cooldown_secs() -> u64 {
    300
}
fn default_autoscale_sample_interval_secs() -> u64 {
    30
}

impl CoinbaseAutoscaleConfig {
    /// Checks the section's own invariants; the floor-vs-ceiling check runs
    /// at boot, where both values are visible.
    pub fn validate(&self) -> Result<(), String> {
        if !self.up_threshold.is_finite() || !(0.0..=1.0).contains(&self.up_threshold) {
            return Err(format!(
                "coinbase_autoscale.up_threshold must be in (0,1], got {}",
                self.up_threshold
            ));
        }
        if !self.down_threshold.is_finite()
            || self.down_threshold <= 0.0
            || self.down_threshold >= self.up_threshold
        {
            return Err(format!(
                "coinbase_autoscale.down_threshold must be in (0, up_threshold={}), got {}",
                self.up_threshold, self.down_threshold
            ));
        }
        if !self.step_factor.is_finite() || self.step_factor <= 1.0 {
            return Err(format!(
                "coinbase_autoscale.step_factor must be > 1.0, got {}",
                self.step_factor
            ));
        }
        if self.up_debounce == 0 || self.down_debounce == 0 {
            return Err("coinbase_autoscale up_debounce / down_debounce must be > 0".to_string());
        }
        if self.sample_interval_secs == 0 {
            return Err("coinbase_autoscale.sample_interval_secs must be > 0".to_string());
        }
        // One up-step from the up-threshold must not land at/below the
        // down-threshold, else a single jump re-arms the reverse direction.
        if self.up_threshold / self.step_factor <= self.down_threshold {
            return Err(format!(
                "coinbase_autoscale: step too large for the deadband — up_threshold/step_factor ({:.3}) must exceed down_threshold ({:.3}) or the budget can flap",
                self.up_threshold / self.step_factor,
                self.down_threshold
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoloConfig {
    /// Optional pool fee on Solo blocks. Empty/absent = no fee output (every
    /// sat goes to the finder).
    #[serde(default)]
    pub fee_address: Option<String>,
    #[serde(default)]
    pub fee_percent: Option<f64>,
    /// Coinbase weight reservation (WU) for the Solo template stream. Solo
    /// coinbases have 1–2 outputs, so a small value leaves the block to fee
    /// transactions. Sent to core over TDP; core clamps it to at least 2000 WU.
    #[serde(default = "default_solo_coinbase_weight_budget")]
    pub coinbase_weight_budget: u32,
}

fn default_solo_coinbase_weight_budget() -> u32 {
    // Finder + dev-fee + cushion after the headroom factor.
    4_000
}

impl Default for SoloConfig {
    fn default() -> Self {
        Self {
            fee_address: None,
            fee_percent: None,
            coinbase_weight_budget: default_solo_coinbase_weight_budget(),
        }
    }
}

/// Presence enables Group-Solo.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSoloConfig {
    /// Receives the pool fee in every Group-Solo block; must parse for
    /// `network`.
    pub fee_address: String,
    pub fee_percent: f64,
    /// Coinbase weight reservation (WU) for the Group-Solo stream, default fits
    /// ~50 members. Drives both the TDP reservation and the engine's trimmer,
    /// so blocks stay valid; under-sizing rolls trimmed members' payout into
    /// the fee output, costing fairness rather than validity.
    #[serde(default = "default_group_solo_coinbase_weight_budget")]
    pub coinbase_weight_budget: u32,
    /// Smallest member output; smaller shares go to the fee output.
    #[serde(default = "default_group_solo_min_payout_sats")]
    pub min_payout_sats: i64,
}

pub fn default_group_solo_coinbase_weight_budget() -> u32 {
    // ~50 Taproot members + fee output + cushion.
    10_000
}

fn default_group_solo_min_payout_sats() -> i64 {
    5_000
}

/// Presence enables Blockparty; absence leaves every Blockparty surface on
/// its Solo fallback.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockpartyConfig {
    /// Receives the pool fee in every Blockparty block; must parse for
    /// `network`.
    pub fee_address: String,
    pub fee_percent: f64,
    /// Minimum on-chain payout per member. Sub-min splits roll into
    /// the pool-fee output. Clamped at runtime to ≥ Bitcoin dust limit.
    #[serde(default = "default_blockparty_min_payout_sats")]
    pub min_payout_sats: i64,
    /// Coinbase weight reservation (WU) for the Blockparty template stream;
    /// one output per member (~124–172 WU) plus the fee, default fits ~40.
    /// Validity-critical: a party past this reservation makes bitcoin-core
    /// reject the block, so raise it before onboarding larger parties.
    #[serde(default = "default_blockparty_coinbase_weight_budget")]
    pub coinbase_weight_budget: u32,
}

fn default_blockparty_min_payout_sats() -> i64 {
    5_000
}

fn default_blockparty_coinbase_weight_budget() -> u32 {
    // ~40 Taproot members + fee output + cushion.
    8_000
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NotificationsConfig {
    #[serde(default)]
    pub telegram: Option<TelegramConfig>,
    #[serde(default)]
    pub ntfy: Option<NtfyConfig>,
    #[serde(default)]
    pub web_push: Option<WebPushConfig>,
    #[serde(default)]
    pub fcm: Option<FcmConfig>,
    #[serde(default)]
    pub device_status: DeviceStatusConfig,
}

/// Debounce + coalescing for miner online/offline notifications, so a flaky
/// link or rotating rental rigs do not produce a push per reconnect.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceStatusConfig {
    /// How long a device must look gone before "offline" is sent; long enough
    /// to swallow a WiFi hiccup, reboot or pool restart.
    #[serde(default = "default_offline_grace_secs")]
    pub offline_grace_secs: u64,
    /// How long a device must look present before "back online" is sent.
    /// Keep it above ~20 s: the `client_entity` row appears only after the
    /// session-persistence debounce, and a device without a row counts as
    /// absent, which delays a new worker's online message by one grace.
    #[serde(default = "default_online_dwell_secs")]
    pub online_dwell_secs: u64,
    /// Hard floor on the spacing between two device messages for one
    /// address. Transitions inside the window are collected and sent
    /// together as a single summary.
    #[serde(default = "default_coalesce_window_secs")]
    pub coalesce_window_secs: u64,
    /// How often a settled device is re-checked against the database, so a
    /// wrong answer (e.g. the dead-client sweep retiring a quiet session)
    /// corrects itself instead of standing until the next reconnect.
    #[serde(default = "default_recheck_interval_secs")]
    pub recheck_interval_secs: u64,
}

fn default_offline_grace_secs() -> u64 {
    300
}

fn default_online_dwell_secs() -> u64 {
    90
}

fn default_coalesce_window_secs() -> u64 {
    300
}

fn default_recheck_interval_secs() -> u64 {
    300
}

impl Default for DeviceStatusConfig {
    fn default() -> Self {
        Self {
            offline_grace_secs: default_offline_grace_secs(),
            online_dwell_secs: default_online_dwell_secs(),
            coalesce_window_secs: default_coalesce_window_secs(),
            recheck_interval_secs: default_recheck_interval_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramConfig {
    pub bot_token: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtfyConfig {
    pub server_url: String,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub topic_prefix: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebPushConfig {
    pub vapid_public_key: String,
    pub vapid_private_key: String,
    /// e.g. `"mailto:admin@example.com"` — required by the Web-Push
    /// VAPID JWT spec for the `aud` claim.
    pub vapid_subject: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FcmConfig {
    /// Path to the Firebase Admin SDK service-account JSON. Loaded
    /// once at startup; the adapter caches the OAuth access token
    /// (60-s skew window).
    pub service_account_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    /// `true` ⇒ implicit TLS on port 465; `false` ⇒ STARTTLS on 587.
    #[serde(default)]
    pub secure: bool,
    pub user: String,
    pub pass: String,
    /// RFC 5322 mailbox — `"Display Name <addr@example.com>"`.
    pub from: String,
}

/// Prometheus `/metrics` exporter; `enabled = true` spawns the listener.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Overrides the default `0.0.0.0:9000` bind.
    #[serde(default)]
    pub bind: Option<String>,
}

// ─── defaults ─────────────────────────────────────────────────────

fn default_rpc_timeout_ms() -> u64 {
    10_000
}
fn default_pg_port() -> u16 {
    5432
}
fn default_tdp_staleness_threshold_secs() -> u64 {
    120
}
fn default_pg_pool_size() -> u32 {
    10
}
fn default_pg_acquire_timeout_ms() -> u64 {
    60_000
}
fn default_pg_idle_timeout_ms() -> u64 {
    10_000
}
fn default_redis_port() -> u16 {
    6379
}
fn default_true() -> bool {
    true
}
fn default_abandoned_days() -> u32 {
    90
}
fn default_confirmation_depth() -> u32 {
    3
}
fn default_bucket_shares() -> u64 {
    10_000
}

// ─── loader + errors ──────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse TOML at {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

impl AppConfig {
    /// The roles this process runs. Empty is fatal at boot (checked in `main`).
    pub fn effective_roles(&self) -> Vec<Role> {
        self.roles.clone()
    }

    /// Whether this process runs the given role.
    pub fn has_role(&self, role: Role) -> bool {
        self.effective_roles().contains(&role)
    }

    /// Read + parse a TOML config file; errors carry the path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str::<AppConfig>(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Parse a TOML string without touching the filesystem.
    pub fn from_toml_str(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str::<AppConfig>(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `blitzpool.example.toml` parses against the current schema and is
    /// the Solo-only pool it says it is.
    #[test]
    fn example_toml_parses() {
        let bytes = include_str!("../../../blitzpool.example.toml");
        let cfg = AppConfig::from_toml_str(bytes).expect("blitzpool.example.toml parses");
        assert_eq!(cfg.network, Network::Mainnet);
        assert_eq!(cfg.pool_identifier, "blitzpool");
        assert!(cfg.pplns.is_none() && cfg.group_solo.is_none() && cfg.blockparty.is_none());
        assert!(
            cfg.sv2.authority_privkey_hex.is_some(),
            "the front needs it to start"
        );
    }

    /// `blitzpool.full.example.toml` parses and switches every mode on.
    #[test]
    fn full_example_toml_parses() {
        let bytes = include_str!("../../../blitzpool.full.example.toml");
        let cfg = AppConfig::from_toml_str(bytes).expect("blitzpool.full.example.toml parses");
        assert!(cfg.pplns.is_some() && cfg.group_solo.is_some() && cfg.blockparty.is_some());
        assert!(cfg.smtp.is_some());
    }

    /// Minimal valid config body (top-level keys + required tables) for the
    /// role-resolution tests; a `roles` line is prepended per-case.
    const MINIMAL_CFG: &str = r#"
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
    "#;

    /// Missing or partial `device_status` keys fall back to the defaults.
    #[test]
    fn device_status_debounce_defaults_without_a_config_block() {
        let cfg: AppConfig = toml::from_str(&format!("roles = [\"notify\"]\n{MINIMAL_CFG}"))
            .expect("parse without a notifications block");
        let ds = cfg.notifications.device_status;
        assert_eq!(ds.offline_grace_secs, 300);
        assert_eq!(ds.online_dwell_secs, 90);
        assert_eq!(ds.coalesce_window_secs, 300);
        assert_eq!(ds.recheck_interval_secs, 300);

        // A partial block keeps the defaults for the keys it omits.
        let cfg: AppConfig = toml::from_str(&format!(
            "roles = [\"notify\"]\n{MINIMAL_CFG}\n\
             [notifications.device_status]\n\
             offline_grace_secs = 120\n"
        ))
        .expect("parse with a partial device_status block");
        let ds = cfg.notifications.device_status;
        assert_eq!(ds.offline_grace_secs, 120);
        assert_eq!(ds.online_dwell_secs, 90);
        assert_eq!(ds.coalesce_window_secs, 300);
        assert_eq!(ds.recheck_interval_secs, 300);
    }

    #[test]
    fn roles_select_topology() {
        // No `roles` → empty. The config still parses; the binary rejects an
        // empty role set at boot (see the roles check in `main`).
        let none: AppConfig = toml::from_str(MINIMAL_CFG).expect("parse");
        assert!(none.effective_roles().is_empty());
        assert!(!none.has_role(Role::Front) && !none.has_role(Role::Stats));

        // Explicit `roles` are the topology.
        let api_only: AppConfig =
            toml::from_str(&format!("roles = [\"api\"]\n{MINIMAL_CFG}")).expect("parse roles");
        assert_eq!(api_only.effective_roles(), vec![Role::Api]);
        assert!(api_only.has_role(Role::Api));
        assert!(!api_only.has_role(Role::Payout) && !api_only.has_role(Role::Stats));

        let payout_stats: AppConfig =
            toml::from_str(&format!("roles = [\"payout\", \"stats\"]\n{MINIMAL_CFG}"))
                .expect("parse roles");
        assert_eq!(
            payout_stats.effective_roles(),
            vec![Role::Payout, Role::Stats]
        );
        // payout,stats carries no notify role — the binary must run a separate
        // `notify` process (and warns loudly when it doesn't).
        assert!(!payout_stats.has_role(Role::Notify));

        // A dedicated notify process: only the notify role.
        let notify_only: AppConfig =
            toml::from_str(&format!("roles = [\"notify\"]\n{MINIMAL_CFG}")).expect("parse roles");
        assert_eq!(notify_only.effective_roles(), vec![Role::Notify]);
        assert!(notify_only.has_role(Role::Notify));
        assert!(!notify_only.has_role(Role::Payout) && !notify_only.has_role(Role::Front));
    }

    #[test]
    fn stray_mode_field_is_rejected() {
        // Roles are the only topology input: a `mode = "..."` key is a load
        // error (deny_unknown_fields), not silently ignored.
        let parsed = AppConfig::from_toml_str(&format!(
            "roles = [\"front\"]\nmode = \"core\"\n{MINIMAL_CFG}"
        ));
        assert!(parsed.is_err(), "a stray `mode` field must be rejected");
    }

    fn valid_autoscale() -> CoinbaseAutoscaleConfig {
        CoinbaseAutoscaleConfig {
            enabled: true,
            max_weight_budget: 400_000,
            up_threshold: default_autoscale_up_threshold(),
            down_threshold: default_autoscale_down_threshold(),
            step_factor: default_autoscale_step_factor(),
            up_debounce: default_autoscale_up_debounce(),
            down_debounce: default_autoscale_down_debounce(),
            cooldown_secs: default_autoscale_cooldown_secs(),
            sample_interval_secs: default_autoscale_sample_interval_secs(),
        }
    }

    #[test]
    fn solo_coinbase_budget_defaults_and_parses() {
        // Default applied when omitted.
        assert_eq!(SoloConfig::default().coinbase_weight_budget, 4_000);
        // Far smaller than a typical PPLNS budget — that's the whole point.
        assert!(SoloConfig::default().coinbase_weight_budget < 50_000 / 5);
        // Parses from TOML and is overridable.
        let c: SoloConfig = toml::from_str("coinbase_weight_budget = 6000").expect("parses");
        assert_eq!(c.coinbase_weight_budget, 6_000);
        // Omitted → default.
        let d: SoloConfig = toml::from_str("").expect("parses");
        assert_eq!(d.coinbase_weight_budget, 4_000);
    }

    #[test]
    fn solo_rejects_unknown_dust_sweep_keys() {
        // Sweep keys belong to [pplns]; on [solo] they MUST fail loud rather
        // than be silently ignored.
        assert!(toml::from_str::<SoloConfig>("dust_sweep_enabled = true").is_err());
        assert!(toml::from_str::<SoloConfig>("abandoned_balance_days = 90").is_err());
        assert!(toml::from_str::<SoloConfig>("dust_sweep_dormant_days = 30").is_err());
    }

    const MODE_FEE: &str =
        "fee_address = \"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"\nfee_percent = 1.5\n";

    #[test]
    fn group_solo_coinbase_budget_defaults_and_parses() {
        // Default applied when omitted (sized to ~50 members), smaller than
        // the 50 kWU PPLNS budget: the whole point of the stream.
        let d: GroupSoloConfig = toml::from_str(MODE_FEE).expect("parses");
        assert_eq!(d.coinbase_weight_budget, 10_000);
        assert_eq!(d.min_payout_sats, 5_000);
        let c: GroupSoloConfig =
            toml::from_str(&format!("{MODE_FEE}coinbase_weight_budget = 22000\n")).expect("parses");
        assert_eq!(c.coinbase_weight_budget, 22_000);
    }

    #[test]
    fn pplns_sweep_overrides_propagate_from_toml() {
        // Operator override on [pplns] must end up on the parsed config so
        // the wiring in bin/blitzpool can pass it through to PplnsEngineConfig.
        let text = r#"
            port = 3340
            high_diff_port = 3349
            start_difficulty = 1000
            target_shares_per_minute = 6
            fee_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
            fee_percent = 1.5
            coinbase_weight_budget = 50000
            min_difficulty = 500
            min_payout_sats = 5000
            dust_sweep_enabled = false
            abandoned_balance_days = 45
        "#;
        let c: PplnsConfig = toml::from_str(text).expect("parses");
        assert!(!c.dust_sweep_enabled);
        assert_eq!(c.abandoned_balance_days, 45);
    }

    /// Sweep keys on `[group_solo]` fail the load: Group-Solo has no ledger.
    #[test]
    fn group_solo_rejects_the_retired_sweep_keys() {
        for key in ["dust_sweep_enabled = false", "dormant_balance_days = 14"] {
            assert!(toml::from_str::<GroupSoloConfig>(&format!("{MODE_FEE}{key}\n")).is_err());
        }
    }

    /// `[group_solo]` switches the mode: present is on, absent is off; once
    /// present, its fee is required, with no fallback to another section.
    #[test]
    fn group_solo_is_on_only_with_its_table() {
        let off = AppConfig::from_toml_str(MINIMAL_CFG).expect("parses");
        assert!(off.group_solo.is_none());
        let on = AppConfig::from_toml_str(&format!("{MINIMAL_CFG}\n[group_solo]\n{MODE_FEE}"))
            .expect("parses");
        assert!(on.group_solo.is_some());
        assert!(
            AppConfig::from_toml_str(&format!("{MINIMAL_CFG}\n[group_solo]\n")).is_err(),
            "[group_solo] without its fee must fail the load"
        );
    }

    /// `[group_fees]` and `dev_fee_*` are not config keys: a config carrying them
    /// fails the load instead of silently dropping the fee.
    #[test]
    fn retired_fee_keys_fail_the_load() {
        assert!(AppConfig::from_toml_str(&format!(
            "{MINIMAL_CFG}\n[group_fees]\naddress = \"x\"\n"
        ))
        .is_err());
        assert!(AppConfig::from_toml_str(&format!(
            "{MINIMAL_CFG}\n[solo]\ndev_fee_percent = 1.0\n"
        ))
        .is_err());
    }

    #[test]
    fn blockparty_coinbase_budget_defaults_and_parses() {
        // Default applied when omitted (sized to ~40 members).
        let d: BlockpartyConfig = toml::from_str(MODE_FEE).expect("parses");
        assert_eq!(d.coinbase_weight_budget, 8_000);
        assert_eq!(d.min_payout_sats, default_blockparty_min_payout_sats());
        let c: BlockpartyConfig =
            toml::from_str(&format!("{MODE_FEE}coinbase_weight_budget = 16000\n")).expect("parses");
        assert_eq!(c.coinbase_weight_budget, 16_000);
        // The fee is required once Blockparty is on.
        assert!(toml::from_str::<BlockpartyConfig>("").is_err());
    }

    #[test]
    fn autoscale_defaults_validate() {
        valid_autoscale()
            .validate()
            .expect("recommended defaults are valid");
    }

    #[test]
    fn autoscale_rejects_down_above_up() {
        let mut c = valid_autoscale();
        c.down_threshold = 0.90; // > up_threshold (0.85)
        assert!(c.validate().is_err());
    }

    #[test]
    fn autoscale_rejects_step_le_one() {
        let mut c = valid_autoscale();
        c.step_factor = 1.0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn autoscale_rejects_step_too_large_for_deadband() {
        // 0.85 / 1.8 = 0.47 < down_threshold 0.50 → would flap.
        let mut c = valid_autoscale();
        c.step_factor = 1.8;
        let err = c.validate().expect_err("oversized step must be rejected");
        assert!(
            err.contains("flap"),
            "reason should mention flapping: {err}"
        );
    }

    #[test]
    fn autoscale_subsection_parses_with_defaults() {
        // Only the required ceiling given; everything else defaults.
        let text = r#"
            enabled = true
            max_weight_budget = 200000
        "#;
        let c: CoinbaseAutoscaleConfig = toml::from_str(text).expect("parses");
        assert_eq!(c.max_weight_budget, 200_000);
        assert!((c.up_threshold - 0.85).abs() < 1e-9);
        assert_eq!(c.up_debounce, 3);
        assert_eq!(c.down_debounce, 10);
        assert_eq!(c.cooldown_secs, 300);
        c.validate().expect("default-filled subsection is valid");
    }

    #[test]
    fn unknown_field_is_rejected() {
        let text = r#"
            network = "mainnet"
            pool_identifier = "blitzpool"
            stratum_garbage = 42

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
        "#;
        let err = AppConfig::from_toml_str(text).expect_err("deny_unknown_fields rejects typo");
        assert!(
            err.to_string().contains("stratum_garbage"),
            "expected unknown-field error to mention the typo: {err}"
        );
    }

    #[test]
    fn minimal_config_loads() {
        let text = r#"
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
            target_shares_per_minute = 6
            high_diff_target_shares_per_minute = 6
            difficulty_check_interval_ms = 60000
        "#;
        let cfg = AppConfig::from_toml_str(text).expect("minimal config loads");
        assert!(cfg.pplns.is_none());
        assert!(cfg.notifications.fcm.is_none());
        assert!(cfg.smtp.is_none());
        assert_eq!(cfg.solo.coinbase_weight_budget, 4_000);
        // [stratum] job_retention_ms defaults to 10 min when unset.
        assert_eq!(cfg.stratum.job_retention_ms, 600_000);
        // [tdp] staleness threshold defaults to 120s when unset.
        assert_eq!(cfg.tdp.staleness_threshold_secs, 120);
        // SV2 JDP/PushSolution: propagation is a MUST, so the default is on.
        assert!(
            cfg.sv2.jdp_orphan_submitblock,
            "pool-side block propagation must default to on"
        );
    }

    #[test]
    fn tdp_staleness_threshold_overrides_from_toml() {
        let text = r#"
            socket_path = "/var/run/bitcoind/bp-tdp.sock"
            staleness_threshold_secs = 45
        "#;
        let c: TdpConfig = toml::from_str(text).expect("parses");
        assert_eq!(c.staleness_threshold_secs, 45);
    }
}
