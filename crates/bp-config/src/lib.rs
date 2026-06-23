// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed application configuration for `bin/blitzpool`.
//!
//! The Rust pool reads a single TOML file at startup (`--config <PATH>`
//! on the binary). The schema covers the full operator-facing
//! configuration surface so a production deployment maps one-to-one.
//! Field names use `snake_case`; grouping uses TOML tables.
//!
//! ## Design choices
//!
//! - **TOML-only, no env-var override layer**. We ship a
//!   `blitzpool.example.toml` committed in the repo + an
//!   operator-managed `.local/blitzpool.toml` (or wherever the
//!   operator wants it). One source of truth.
//! - **`deny_unknown_fields` everywhere**. A typo in a key name is a
//!   load error, not a silent default. Operators see "unknown field
//!   `pplsn_fee_percent`" up-front.
//! - **Optional groups are `Option<T>`**, not "empty defaults". An
//!   absent `[notifications.fcm]` table means FCM is disabled —
//!   different from FCM enabled-but-misconfigured. The binary checks
//!   `if let Some(fcm) = &cfg.notifications.fcm { … }`.
//! - **Engine-specific tuning fields live next to their engine's
//!   config**, not under a generic `[performance]` block. The wiring
//!   code reads them by passing the sub-config to the engine's
//!   `spawn(cfg, …)` builder.

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
    /// Mailbox the capacity-alert / fail-safe ops mails go to.
    /// Without this the alert pipeline silently disables itself.
    #[serde(default)]
    pub pool_admin_email: Option<String>,
    /// `true` ⇒ the `/api` HTTP server expects to be fronted by a
    /// TLS-terminating proxy and emits `Strict-Transport-Security`
    /// + secure-cookie hints. `false` ⇒ plain HTTP.
    #[serde(default)]
    pub api_secure: bool,

    /// Deployment topology shorthand for the role set (overridden by an
    /// explicit `roles` list). `core` is the always-on front — Stratum
    /// listeners + share validation + block submit, producing accepted shares
    /// onto the Redis stream (no accounting engines / API). `satellite`
    /// (default) is the restartable back — it consumes that stream to run
    /// accounting + API + crons (no Stratum). Split so the Satellite can
    /// restart without dropping miner connections.
    #[serde(default)]
    pub mode: DeploymentMode,

    /// Fine-grained role override. When non-empty it is authoritative and
    /// `mode` is ignored for topology; when empty (the default) the role set
    /// is derived from `mode`. Use it to split the back-office into
    /// per-feature processes, e.g. `roles = ["api"]`, `roles = ["payout"]`,
    /// `roles = ["stats"]` (or `["payout", "stats"]` to keep them together).
    #[serde(default)]
    pub roles: Vec<Role>,

    pub bitcoin_rpc: BitcoinRpcConfig,
    #[serde(default)]
    pub bitcoin_zmq: Option<BitcoinZmqConfig>,
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
    /// Shared fee config for Group-Solo + Blockparty. Independent
    /// from the PPLNS lane; falls back to `[pplns].fee_*` when
    /// fields are absent so existing deployments keep working.
    #[serde(default)]
    pub group_fees: GroupFeesConfig,
    #[serde(default)]
    pub blockparty: Option<BlockpartyConfig>,

    #[serde(default)]
    pub notifications: NotificationsConfig,
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
    #[serde(default)]
    pub capacity_alert: CapacityAlertConfig,
    #[serde(default)]
    pub aggregation: AggregationConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Optional `[debug]` section. Holds the protocol-level debug
    /// switches (frame dumps, per-share traces, Noise-handshake debug).
    #[serde(default)]
    pub debug: DebugConfig,
}

/// Protocol-level debug logging switches. Both default to `false`
/// because the SV1+SV2 share traces are noisy under production load
/// — flip to `true` in staging / regtest when diagnosing a miner
/// rejection rate or a Noise handshake.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DebugConfig {
    /// `true` ⇒ protocol *frame* dumps: SV1 `📤 RX:` JSON-RPC lines and
    /// SV2 `📨 RX` / `📤 TX` wire-frame dumps (message name, type byte,
    /// payload length). One pair per frame — heavy under load. Does NOT
    /// cover per-share diagnostics (see [`Self::stratum_share_logs`]).
    #[serde(default)]
    pub stratum_wire_logs: bool,
    /// `true` ⇒ per-share diagnostic logs: SV1 `🎯 Share difficulty` +
    /// `✅ Share accepted`, and SV2 `🎯 Extended share difficulty` +
    /// `📤 SubmitSharesExtended`. One line (or two) per submitted share.
    /// Independent of share rejections, which always log at WARN
    /// regardless of this flag.
    #[serde(default)]
    pub stratum_share_logs: bool,
    /// `true` ⇒ SV2 Noise handshake byte-level logging (Act1/Act2
    /// hex dumps, first-chunk preview). Very noisy — only enable when
    /// diagnosing handshake-layer issues.
    #[serde(default)]
    pub noise_debug: bool,
    /// `true` ⇒ log the pool-internal submit→ack latency for **both**
    /// SV1 and SV2 (µs from the inbound submit line/frame being read to
    /// its response being written) at INFO, one line per share.
    /// Lightweight diagnostic to isolate pool processing time from
    /// network / miner / measurement latency — leave off normally.
    #[serde(default)]
    pub submit_latency: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Mainnet,
    Testnet,
    /// Bitcoin testnet4 (BIP-94 fork of testnet3 with shorter target
    /// recalculation + lower difficulty floor). Addresses share the
    /// `tb` HRP with testnet3 so address parsing maps to the same
    /// `bitcoin::Network::Testnet` byte set.
    Testnet4,
    Regtest,
}

/// Deployment topology — see [`AppConfig::mode`].
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    /// Always-on front: Stratum + validation + block submit + share
    /// producer. No accounting engines / API.
    Core,
    /// Restartable back: stream consumer + accounting + API + crons. No
    /// Stratum.
    #[default]
    Satellite,
}

impl DeploymentMode {
    /// Does this process hold miner connections — Stratum listeners +
    /// the share producer? (`core`.)
    pub fn is_front(self) -> bool {
        matches!(self, Self::Core)
    }

    /// Does this process run the accounting engines, API, crons, and the
    /// stream consumer? (`satellite`.)
    pub fn is_back(self) -> bool {
        matches!(self, Self::Satellite)
    }

    /// Expand the shorthand mode into its fine-grained [`Role`] set. The
    /// `satellite` back-office is `api` + `payout` + `stats` + `notify`;
    /// splitting it into separate processes is done by setting `roles`
    /// directly (see [`AppConfig::effective_roles`]).
    pub fn roles(self) -> Vec<Role> {
        match self {
            Self::Core => vec![Role::Front],
            Self::Satellite => vec![Role::Api, Role::Payout, Role::Stats, Role::Notify],
        }
    }
}

/// Fine-grained deployment role. A process runs one or more roles; which
/// roles it runs is what actually gates each subsystem at boot. `mode` is a
/// shorthand that expands to a role set, and an explicit `roles` list
/// overrides it — that's how the back-office splits into per-feature
/// processes (e.g. `roles = ["api"]` / `["payout"]` / `["stats"]`).
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
    /// Notifications: the dispatcher (FCM / Web-Push / Telegram / ntfy), the
    /// Telegram + ntfy command listeners, the push/digest crons (network- +
    /// best-difficulty, hourly stats), and the notify-only fan-out of the
    /// block-found + device-status streams. Carved out so notification feature
    /// changes redeploy without restarting the `payout` (PPLNS) process.
    Notify,
}

impl std::str::FromStr for Role {
    type Err = String;

    /// Parse a role name (case-insensitive). Lets the binary accept
    /// `--roles` / `BLITZPOOL_ROLES=api,payout` so all containers can share
    /// one config and differ only by an env var.
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
pub struct BitcoinZmqConfig {
    /// e.g. `"tcp://192.168.1.100:28332"` — matches Core's
    /// `zmqpubrawblock` socket. Optional in the Rust port (TDP is
    /// the primary template source); kept here for operators still
    /// wiring a ZMQ source during cut-over.
    pub host: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TdpConfig {
    /// Path to the bitcoin-core IPC Unix-domain socket. The Rust port
    /// uses TDP-direkt (see memory `project-tdp-direct-architecture`)
    /// instead of ZMQ + RPC `getblocktemplate`; this socket is what
    /// `bp-template-distribution::TdpHandle::spawn` connects to.
    pub socket_path: PathBuf,
    /// Minimum block-reward fee (sats) before a refreshed template
    /// supersedes the previous one. Lower → more template churn.
    /// `TdpHandle` default if absent: 1_000_000.
    #[serde(default)]
    pub fee_threshold_sats: Option<u64>,
    /// Minimum interval between template refreshes (seconds). Floor
    /// — Core may emit faster but the worker rate-limits.
    #[serde(default)]
    pub min_interval_secs: Option<u8>,
    /// `tokio::sync::broadcast` capacity for the template channel.
    /// Default if absent: 16.
    #[serde(default)]
    pub broadcast_capacity: Option<usize>,
    /// Age (seconds) past which the last-seen template/prev-hash is
    /// considered stale by `/api/health`. Deliberately generous so a
    /// brief bitcoin-core restart (the reconnect loop re-attaches in
    /// ~`reconnect_backoff`) does NOT flip the health status — only a
    /// prolonged outage where core stops feeding fresh work does.
    /// Default if absent: 120.
    #[serde(default = "default_tdp_staleness_threshold_secs")]
    pub staleness_threshold_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Currently always `"postgres"` for the Rust port. The schema
    /// uses PG-only types (BIGINT-epoch-ms etc.); SQLite is not
    /// supported.
    pub driver: String,
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
    #[serde(default = "default_pg_max_query_time_ms")]
    pub max_query_time_ms: u64,
    #[serde(default = "default_pg_acquire_timeout_ms")]
    pub acquire_timeout_ms: u64,
    #[serde(default = "default_pg_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// `true` ⇒ run pending migrations on startup. **Note**: the Rust
    /// port reads from the existing schema and doesn't ship migrations
    /// itself; this flag is honoured by the deployment stack that owns
    /// the migration set against the same DB.
    #[serde(default)]
    pub run_migrations: bool,
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
    #[serde(default = "default_redis_ttl_secs")]
    pub ttl_secs: u64,
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
    pub client_diff_scores_secs: u64,
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
    pub group_list_secs: u64,
    #[serde(default = "ttl_60")]
    pub group_public_list_secs: u64,
    #[serde(default = "ttl_60")]
    pub group_by_address_secs: u64,
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

    /// Upper bound on total cache entries before LRU eviction kicks
    /// in. Dominated by per-`(address, range)` client keys; 10k is
    /// generous for most deployments.
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
            client_diff_scores_secs: ttl_60(),
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

            group_list_secs: ttl_60(),
            group_public_list_secs: ttl_60(),
            group_by_address_secs: ttl_60(),
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
    /// How long an emitted job stays valid before the engine refuses
    /// shares against it.
    pub job_retention_ms: u64,
    pub target_shares_per_minute: u32,
    pub high_diff_target_shares_per_minute: u32,
    pub difficulty_check_interval_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Sv2Config {
    /// 32-byte secp256k1 authority private key in hex. When absent
    /// a random key is generated on every startup (operators can't
    /// pin a pool identity that way — fine for staging, not prod).
    #[serde(default)]
    pub authority_privkey_hex: Option<String>,
    /// 32-byte Ed25519 seed in hex for the SV2 certificate-signing
    /// authority key.
    #[serde(default)]
    pub ed25519_authority_seed_hex: Option<String>,
    /// SV2 certificate `signed_part` byte — operator-tunable for
    /// future cert-rotation flows.
    #[serde(default)]
    pub cert_signed_part: Option<u8>,
    #[serde(default)]
    pub jdp_enabled: bool,
    #[serde(default)]
    pub jdp_port: Option<u16>,
    /// JDP block-found orphan-protection redundancy switch.
    /// `false` (default): on `PushSolution` the pool **logs only** —
    /// JDC is responsible for propagating the block via its own
    /// `TdpHandle::submit_solution` path. SRI's reference pool does
    /// the same.
    /// `true`: pool additionally reconstructs the block + submits via
    /// `bitcoind submitblock` RPC — anti-orphan redundancy for
    /// production pools that serve
    /// commercial JDCs. Off by default because most deployments
    /// don't run JDC traffic — flip on when JDPs are in active use.
    #[serde(default)]
    pub jdp_orphan_submitblock: bool,
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
    /// On-chain bitcoin address that receives the pool fee directly
    /// in every PPLNS-coinbase. Must be parseable as the configured
    /// `network`.
    pub fee_address: String,
    /// Fee as percent of block reward (`1.5` = 1.5 %). Trimming +
    /// dust-sweep never pad this — the fee output equals exactly
    /// this percentage.
    pub fee_percent: f64,
    /// Coinbase weight budget in WU — **must match** `bitcoin.conf
    /// blockreservedweight`. Lower budget → fewer payout recipients
    /// per block but more tx-fee room.
    pub coinbase_weight_budget: u32,
    /// VarDiff floor for the PPLNS port (sub-ASIC hardware gate).
    pub min_difficulty: u64,
    /// Per-session share warmup — first N accepted shares are
    /// counted in stats but NOT recorded in the PPLNS ledger.
    pub warmup_shares: u32,
    /// Minimum on-chain payout in sats. Outputs below this stay as
    /// pending credit in the signed ledger. Always clamped upward
    /// to `DUST_LIMIT_SATS` (546) by the engine.
    pub min_payout_sats: i64,
    /// Enable the daily 03:00 UTC PPLNS dust-sweep cron (pair-cancels
    /// abandoned positive credit against abandoned debit on
    /// `pplns_balance`). Manual sweeps via admin trigger still work
    /// when false.
    #[serde(default = "default_true")]
    pub dust_sweep_enabled: bool,
    /// Inactivity cutoff (days) at which a `pplns_balance` row becomes
    /// eligible for the abandoned-pair sweep. Must be > 0 (engine
    /// rejects 0 to avoid sweeping freshly-credited rows).
    #[serde(default = "default_abandoned_days")]
    pub abandoned_balance_days: u32,
    /// Confirmations a found block must reach before its PPLNS payout
    /// distribution is written to the ledger. The distribution is frozen
    /// at block-found time and parked (Redis) until the block is this
    /// many blocks deep; a block that orphans before then is discarded so
    /// the pending-balance ledger never drifts. Default 3. The on-chain
    /// coinbase payment is unaffected — only the internal accounting is
    /// gated.
    #[serde(default = "default_confirmation_depth")]
    pub confirmation_depth: u32,
    /// Shares per count-bucket for the sliding window (default 10000). The
    /// window is stored as per-address buckets of this many shares; bigger =
    /// less Redis memory + coarser trim, smaller = more memory + finer. MUST
    /// match the TS pool's `PPLNS_BUCKET_SHARES` (they share Redis).
    #[serde(default = "default_bucket_shares")]
    pub bucket_shares: u64,
    /// Coinbase-budget autoscaler. **Absent** ⇒ the budget stays fixed at
    /// `coinbase_weight_budget` (legacy behaviour, fully back-compatible).
    /// **Present** ⇒ the budget self-adjusts at runtime within
    /// `[coinbase_weight_budget` (floor)`, max_weight_budget]` — no restart
    /// needed as the pool grows.
    #[serde(default)]
    pub coinbase_autoscale: Option<CoinbaseAutoscaleConfig>,
}

/// `[pplns.coinbase_autoscale]` — runtime self-tuning of the coinbase weight
/// budget. The parent's `coinbase_weight_budget` is the **floor** (also the
/// boot seed when no persisted value exists); `max_weight_budget` is the
/// **ceiling**. The budget steps multiplicatively within that band with
/// hysteresis + debounce + cooldown so it never flaps. See
/// `bp_pplns_engine::autoscale` for the control semantics.
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
    /// Validate internal invariants (relationships not involving the parent's
    /// floor — that `floor ≤ ceiling` / `ceiling > min_budget` check happens at
    /// boot where both values are visible). Returns a human-readable reason on
    /// failure so the operator sees a pointed config error.
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
        // Geometry guard against hopping: one up-step from the up-threshold must
        // not land at/below the down-threshold (else a single jump re-arms the
        // reverse direction). 0.85/1.15 = 0.739 > 0.50 with defaults.
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
    /// Optional solo-mining dev-fee address. Empty/absent = no
    /// dev-fee output (every sat goes to the share finder).
    #[serde(default)]
    pub dev_fee_address: Option<String>,
    #[serde(default)]
    pub dev_fee_percent: Option<f64>,
    /// Coinbase weight reservation (WU) for the **Solo** template stream.
    /// Solo coinbases are tiny (finder + optional dev-fee = 1–2 outputs), so
    /// this is small: it lets bitcoin-core fill the rest of the block with fee
    /// transactions instead of reserving PPLNS-sized space on every Solo block
    /// (Solo is the bulk of the hashrate). Maps to core's `block_reserved_weight`
    /// via the TDP IPC constraint; core min-clamps the reservation to 2000 WU.
    #[serde(default = "default_solo_coinbase_weight_budget")]
    pub coinbase_weight_budget: u32,
}

fn default_solo_coinbase_weight_budget() -> u32 {
    // ~5 kWU reserved after the headroom factor — comfortable for finder +
    // dev-fee + cushion, while reclaiming ~145 kWU/block vs the PPLNS budget.
    4_000
}

impl Default for SoloConfig {
    fn default() -> Self {
        Self {
            dev_fee_address: None,
            dev_fee_percent: None,
            coinbase_weight_budget: default_solo_coinbase_weight_budget(),
        }
    }
}

/// Optional Blockparty section. Presence enables the feature; absence
/// leaves every Blockparty surface (api routes, payout-resolver arm,
/// mode gate) on its safe Solo fallback.
///
/// **Fee config** is NOT in this section. Group-Solo + Blockparty
/// share a single `[group_fees]` lane (`group_fees.address` /
/// `group_fees.percent`) with fallback to `[pplns]` — that's the
/// production model.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockpartyConfig {
    /// Minimum on-chain payout per member. Sub-min splits roll into
    /// the pool-fee output. Clamped at runtime to ≥ Bitcoin dust limit.
    #[serde(default = "default_blockparty_min_payout_sats")]
    pub min_payout_sats: i64,
    /// Coinbase weight reservation (WU) for the **Blockparty** template stream
    /// (a small fixed reservation against the same bitcoind, separate from the
    /// PPLNS-autoscaled default). Size it to the largest party you expect:
    /// each member is one extra coinbase output (~124 WU for P2WPKH, ~172 WU
    /// for Taproot), plus one pool-fee output. The default fits ~40 members.
    ///
    /// **Validity-critical**: if a party grows past what this reserves,
    /// bitcoin-core rejects the block (the coinbase exceeds the advertised
    /// `CoinbaseOutputConstraints`). Raise it before onboarding larger parties.
    #[serde(default = "default_blockparty_coinbase_weight_budget")]
    pub coinbase_weight_budget: u32,
}

impl Default for BlockpartyConfig {
    fn default() -> Self {
        Self {
            min_payout_sats: default_blockparty_min_payout_sats(),
            coinbase_weight_budget: default_blockparty_coinbase_weight_budget(),
        }
    }
}

fn default_blockparty_min_payout_sats() -> i64 {
    5_000
}

fn default_blockparty_coinbase_weight_budget() -> u32 {
    // ~40 members × ~172 WU (Taproot) + fee output + cushion. Reclaims block
    // space vs the 50 kWU PPLNS budget while staying safe for the default max
    // party size.
    8_000
}

/// Shared `[group_fees]` lane used by both Group-Solo and Blockparty
/// (`group_fees.address` / `group_fees.percent`). Both fields are
/// optional — when absent the boot layer falls
/// back to the corresponding `[pplns]` values so existing PPLNS-only
/// deployments keep working without a config change.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupFeesConfig {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub percent: Option<f64>,
    /// Coinbase weight reservation (WU) for the **Group-Solo** template stream
    /// (a small fixed reservation against the same bitcoind, separate from the
    /// PPLNS-autoscaled default). Size it to the largest group you expect: each
    /// member is one extra coinbase output (~124 WU for P2WPKH, ~172 WU for
    /// Taproot), plus one pool-fee output. The default fits ~50 members.
    ///
    /// This value is wired into BOTH the TDP reservation AND the Group-Solo
    /// engine's distribution trimmer (they must match — boot couples them), so
    /// blocks are always valid: members beyond what the budget holds have their
    /// payout rolled into the pool-fee output rather than overflowing the
    /// reservation. Under-sizing therefore costs *fairness* (trimmed members get
    /// 0 sats), not validity — raise it before onboarding larger groups.
    #[serde(default = "default_group_solo_coinbase_weight_budget")]
    pub coinbase_weight_budget: u32,
    /// Enable the daily 03:00 UTC Group-Solo dust-sweep cron (deletes dormant
    /// `pplns_group_balance` rows below `min_payout_sats`). Manual sweeps via
    /// admin trigger still work when false.
    #[serde(default = "default_true")]
    pub dust_sweep_enabled: bool,
    /// Inactivity cutoff (days) at which a `pplns_group_balance` row becomes
    /// eligible for the dormant-row sweep.
    #[serde(default = "default_dormant_days")]
    pub dormant_balance_days: u32,
}

impl Default for GroupFeesConfig {
    fn default() -> Self {
        Self {
            address: None,
            percent: None,
            coinbase_weight_budget: default_group_solo_coinbase_weight_budget(),
            dust_sweep_enabled: true,
            dormant_balance_days: default_dormant_days(),
        }
    }
}

fn default_group_solo_coinbase_weight_budget() -> u32 {
    // ~50 members × ~172 WU (Taproot) + fee output + cushion. Reclaims block
    // space vs the 50 kWU PPLNS budget while staying safe for the default max
    // group size.
    10_000
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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramConfig {
    pub bot_token: String,
    #[serde(default)]
    pub diff_notifications: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtfyConfig {
    pub server_url: String,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub topic_prefix: Option<String>,
    #[serde(default)]
    pub diff_notifications: bool,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityAlertConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Hashrate / capacity ratio above which a warning email is sent
    /// to `pool_admin_email`.
    #[serde(default = "default_capacity_threshold")]
    pub threshold: f64,
    /// Ratio above which the alert is escalated to "urgent".
    #[serde(default = "default_capacity_urgent")]
    pub urgent_threshold: f64,
}

impl Default for CapacityAlertConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: default_capacity_threshold(),
            urgent_threshold: default_capacity_urgent(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// `pool_stats` aggregation tick (ms). Default 600 000.
    #[serde(default = "default_pool_stats_interval_ms")]
    pub pool_stats_interval_ms: u64,
    /// `chart_data` aggregation tick (ms). Default 300 000.
    #[serde(default = "default_chart_data_interval_ms")]
    pub chart_data_interval_ms: u64,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            pool_stats_interval_ms: default_pool_stats_interval_ms(),
            chart_data_interval_ms: default_chart_data_interval_ms(),
        }
    }
}

/// Prometheus `/metrics` exporter configuration.
///
/// Default `enabled = false`: the exporter is "off until somebody asks
/// for a dashboard". Flip `[metrics] enabled = true` in
/// the TOML to spawn the `:9000` HTTP listener; the actual `record_*`
/// instrumentation across the share-accept / block-found / cron-tick
/// hot paths is tracked as a follow-up — until then the exporter
/// serves an empty body but the listener is reachable.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Override the default `0.0.0.0:9000` bind. Useful when the
    /// pool runs alongside another Prometheus exporter on the same
    /// host.
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
fn default_pg_max_query_time_ms() -> u64 {
    30_000
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
fn default_redis_ttl_secs() -> u64 {
    600
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
fn default_dormant_days() -> u32 {
    30
}
fn default_capacity_threshold() -> f64 {
    0.8
}
fn default_capacity_urgent() -> f64 {
    0.95
}
fn default_pool_stats_interval_ms() -> u64 {
    600_000
}
fn default_chart_data_interval_ms() -> u64 {
    300_000
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
    /// The effective set of roles this process runs: the explicit `roles`
    /// list when given, otherwise the expansion of `mode`. This is what the
    /// binary gates every subsystem on at boot.
    pub fn effective_roles(&self) -> Vec<Role> {
        if self.roles.is_empty() {
            self.mode.roles()
        } else {
            self.roles.clone()
        }
    }

    /// Whether this process runs the given role.
    pub fn has_role(&self, role: Role) -> bool {
        self.effective_roles().contains(&role)
    }

    /// Read + parse a TOML config file. The path is captured in any
    /// error so an operator sees which file failed (matters when
    /// `--config` is used to point at a non-default location).
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

    /// Parse a TOML string directly (without touching the filesystem).
    /// Used by tests + by anyone who already has the bytes in hand.
    pub fn from_toml_str(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str::<AppConfig>(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The repo-committed `blitzpool.example.toml` MUST stay in sync
    /// with the schema — otherwise an operator copying it gets a
    /// load-time error. The path is relative to the workspace root
    /// because cargo runs tests from there.
    #[test]
    fn example_toml_parses() {
        let bytes = include_str!("../../../blitzpool.example.toml");
        let cfg = AppConfig::from_toml_str(bytes).expect("blitzpool.example.toml parses");
        assert_eq!(cfg.network, Network::Mainnet);
        assert_eq!(cfg.pool_identifier, "blitzpool");
        // `mode` is optional → an example without it defaults to satellite.
        assert_eq!(cfg.mode, DeploymentMode::Satellite);
    }

    #[test]
    fn deployment_mode_default_and_predicates() {
        assert_eq!(DeploymentMode::default(), DeploymentMode::Satellite);
        assert!(DeploymentMode::Core.is_front() && !DeploymentMode::Core.is_back());
        assert!(!DeploymentMode::Satellite.is_front() && DeploymentMode::Satellite.is_back());
    }

    #[test]
    fn deployment_mode_parses_lowercase() {
        #[derive(Deserialize)]
        struct W {
            mode: DeploymentMode,
        }
        let c: W = toml::from_str(r#"mode = "core""#).expect("parses core");
        assert_eq!(c.mode, DeploymentMode::Core);
        let s: W = toml::from_str(r#"mode = "satellite""#).expect("parses satellite");
        assert_eq!(s.mode, DeploymentMode::Satellite);
    }

    #[test]
    fn mode_expands_to_roles() {
        assert_eq!(DeploymentMode::Core.roles(), vec![Role::Front]);
        assert_eq!(
            DeploymentMode::Satellite.roles(),
            vec![Role::Api, Role::Payout, Role::Stats, Role::Notify]
        );
    }

    /// Minimal valid config body (top-level keys + required tables) for the
    /// role-resolution tests; `mode` / `roles` are prepended per-case.
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
        driver = "postgres"
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

    #[test]
    fn roles_parse_and_override_mode() {
        // No `roles` → derived from `mode` (default satellite: the back, no front).
        let sat: AppConfig = toml::from_str(MINIMAL_CFG).expect("parse");
        assert_eq!(sat.effective_roles(), DeploymentMode::Satellite.roles());
        assert!(!sat.has_role(Role::Front) && sat.has_role(Role::Stats));

        // Explicit `roles` → authoritative, `mode` ignored for topology.
        let api_only: AppConfig = toml::from_str(&format!(
            "mode = \"satellite\"\nroles = [\"api\"]\n{MINIMAL_CFG}"
        ))
        .expect("parse roles");
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

        // The default satellite back includes notify so a non-split back keeps
        // sending notifications unchanged.
        let default_back: AppConfig = toml::from_str(MINIMAL_CFG).expect("parse");
        assert!(default_back.has_role(Role::Notify));
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
        // The dust_sweep_* keys used to live on [solo] but were always
        // semantic-misnomers — abandoned_balance_days only sweeps PPLNS,
        // dormant_balance_days only sweeps Group-Solo. They moved to
        // [pplns] and [group_fees] respectively. Stale configs MUST fail
        // loud rather than silently use defaults.
        assert!(toml::from_str::<SoloConfig>("dust_sweep_enabled = true").is_err());
        assert!(toml::from_str::<SoloConfig>("abandoned_balance_days = 90").is_err());
        assert!(toml::from_str::<SoloConfig>("dust_sweep_dormant_days = 30").is_err());
    }

    #[test]
    fn group_solo_coinbase_budget_defaults_and_parses() {
        // Default applied when omitted (sized to ~50 members).
        assert_eq!(GroupFeesConfig::default().coinbase_weight_budget, 10_000);
        // Smaller than the 50 kWU PPLNS budget — the whole point of the stream.
        assert!(GroupFeesConfig::default().coinbase_weight_budget < 50_000);
        // Parses + overridable; other fields keep their defaults.
        let c: GroupFeesConfig = toml::from_str("coinbase_weight_budget = 22000").expect("parses");
        assert_eq!(c.coinbase_weight_budget, 22_000);
        assert!(c.address.is_none());
        // Omitted → default.
        let d: GroupFeesConfig = toml::from_str("percent = 1.5").expect("parses");
        assert_eq!(d.coinbase_weight_budget, 10_000);
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
            warmup_shares = 5
            min_payout_sats = 5000
            dust_sweep_enabled = false
            abandoned_balance_days = 45
        "#;
        let c: PplnsConfig = toml::from_str(text).expect("parses");
        assert!(!c.dust_sweep_enabled);
        assert_eq!(c.abandoned_balance_days, 45);
    }

    #[test]
    fn group_fees_sweep_overrides_propagate_from_toml() {
        let c: GroupFeesConfig =
            toml::from_str("dust_sweep_enabled = false\ndormant_balance_days = 14")
                .expect("parses");
        assert!(!c.dust_sweep_enabled);
        assert_eq!(c.dormant_balance_days, 14);
    }

    #[test]
    fn blockparty_coinbase_budget_defaults_and_parses() {
        // Default applied when omitted (sized to ~40 members).
        assert_eq!(BlockpartyConfig::default().coinbase_weight_budget, 8_000);
        assert!(BlockpartyConfig::default().coinbase_weight_budget < 50_000);
        // Parses + overridable alongside min_payout_sats.
        let c: BlockpartyConfig = toml::from_str("coinbase_weight_budget = 16000").expect("parses");
        assert_eq!(c.coinbase_weight_budget, 16_000);
        assert_eq!(c.min_payout_sats, default_blockparty_min_payout_sats());
        // Omitted → default.
        let d: BlockpartyConfig = toml::from_str("min_payout_sats = 6000").expect("parses");
        assert_eq!(d.coinbase_weight_budget, 8_000);
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
            api_secure = false
            stratum_garbage = 42

            [bitcoin_rpc]
            url = "http://127.0.0.1"
            user = "u"
            password = "p"
            port = 8332

            [tdp]
            socket_path = "/var/run/bitcoind/bp-tdp.sock"

            [database]
            driver = "postgres"
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
            driver = "postgres"
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
        let cfg = AppConfig::from_toml_str(text).expect("minimal config loads");
        assert!(cfg.pplns.is_none());
        assert!(cfg.notifications.fcm.is_none());
        assert!(cfg.smtp.is_none());
        assert_eq!(cfg.solo.coinbase_weight_budget, 4_000);
        // Group-Solo sweep config lives on [group_fees] now.
        assert!(cfg.group_fees.dust_sweep_enabled);
        assert_eq!(cfg.group_fees.dormant_balance_days, 30);
        assert_eq!(cfg.aggregation.pool_stats_interval_ms, 600_000);
        // [tdp] staleness threshold defaults to 120s when unset.
        assert_eq!(cfg.tdp.staleness_threshold_secs, 120);
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
