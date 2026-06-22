// SPDX-License-Identifier: AGPL-3.0-or-later

//! Application state passed to every axum handler.
//!
//! All engine + service handles are `Option<Arc<…>>` so the binary
//! can wire only the subsystems it boots with — early Phase-7 staging
//! deploys can start with just `info` + `metrics` if needed and add
//! the rest later.

use std::sync::Arc;

use bp_bitcoin::BitcoinRpc;
use bp_blockparty_engine::{BlockpartyApi, BlockpartyInvitationApi};
use bp_geoip::GeoIpServiceHandle;
use bp_group_mgmt_engine::{
    EmailHooks, GroupService, GroupServiceHooks, InvitationService, JoinRequestService,
};
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_metrics::MetricsServiceHandle;
use bp_pplns_engine::engine::PplnsEngine;
use bp_template_distribution::TdpHandle;
use chrono::{DateTime, Utc};
use redis::aio::ConnectionManager as RedisConn;
use sqlx::PgPool;

use crate::email_hooks::EmailVerificationHooks;
use crate::push_hooks::PushHooks;
use crate::response_cache::ResponseCache;

/// Inner appstate fields. Wrapped in an `Arc` for cheap cloning into
/// the axum router. We use a phantom-typed pair `<H, M>` for the
/// hook trait + email trait — concrete impl is injected at bin level.
pub struct AppState<H: GroupServiceHooks + 'static, M: EmailHooks + 'static> {
    pub pool: PgPool,
    /// Redis connection — used by the mode endpoint to read the live
    /// port-marker (`miner:{address}:mode`, 5-min TTL) as step 1 of
    /// the resolution chain.
    pub redis: Option<RedisConn>,
    pub pplns: Option<Arc<PplnsEngine>>,
    pub group_solo: Option<Arc<GroupSoloEngine>>,
    pub group_service: Option<Arc<GroupService<H>>>,
    pub invitation_service: Option<Arc<InvitationService<H, M>>>,
    pub join_request_service: Option<Arc<JoinRequestService<H, M>>>,
    /// Blockparty service handle, type-erased so the bp-api AppState
    /// doesn't need a third generic param for `BlockpartyHooks`.
    pub blockparty: Option<Arc<dyn BlockpartyApi>>,
    pub blockparty_invitations: Option<Arc<dyn BlockpartyInvitationApi>>,
    pub tdp: Option<TdpHandle>,
    /// Age (ms) past which the TDP snapshot's last template/prev-hash is
    /// reported stale by `/api/health`. Fed from `[tdp]
    /// staleness_threshold_secs`. Generous by default so a brief
    /// bitcoin-core restart (auto-reconnect re-attaches) doesn't flip
    /// health.
    pub tdp_staleness_threshold_ms: i64,
    pub bitcoin_rpc: Option<Arc<BitcoinRpc>>,
    pub geoip: Option<Arc<GeoIpServiceHandle>>,
    pub metrics: Option<MetricsServiceHandle>,
    /// `Cargo.toml` package version — `/api/info/version` reads this.
    pub pool_version: &'static str,
    /// Email-verification flow hooks (`/api/email/register` + `/verify`).
    /// Defaults to NoopVerificationHooks — bin/blitzpool wires the
    /// real SMTP-backed impl.
    pub email_verification_hooks: Arc<dyn EmailVerificationHooks>,
    /// Pool base URL for verification email links
    /// (`<base>/#/email/verify/<token>`). When `None` the /email/register
    /// path returns `config-missing`.
    pub pool_base_url: Option<String>,
    /// Whether the email-send pipeline is enabled. When `false`,
    /// /email/register short-circuits with `email-disabled`.
    pub email_enabled: bool,
    /// Push-notification side-effect hooks for `/api/push/register`
    /// and `/api/push/fcm/register`. Defaults to NoopPushHooks —
    /// bin/blitzpool wires the real FCM / Web-Push impl.
    pub push_hooks: Arc<dyn PushHooks>,
    /// Pool start time — `/api/info` returns this as the `uptime` field
    /// (ISO-8601 timestamp, set once at startup).
    pub start_time: DateTime<Utc>,
    /// Bitcoin network the pool is mining against. Drives address
    /// parsing inside the per-address block-template handler.
    pub network: bitcoin::Network,
    /// Pool identifier written into the coinbase scriptsig
    /// (`pool_identifier` toml). Carried through to the block-template
    /// preview so the UI's coinbase tile shows the same pool tag the
    /// real coinbase would carry.
    pub pool_identifier: String,
    /// Per-endpoint response cache. Handlers that opt in use
    /// `cache.get_or_fetch(...)` to skip DB / RPC work on repeat
    /// reads inside the configured TTL window.
    pub cache: ResponseCache,
}

impl<H: GroupServiceHooks + 'static, M: EmailHooks + 'static> AppState<H, M> {
    /// Construct with only the PG pool — every other dep optional.
    /// Use the builder-style `with_*` methods to add subsystems.
    pub fn new(pool: PgPool, pool_version: &'static str) -> Self {
        Self {
            pool,
            redis: None,
            pplns: None,
            group_solo: None,
            group_service: None,
            invitation_service: None,
            join_request_service: None,
            blockparty: None,
            blockparty_invitations: None,
            tdp: None,
            tdp_staleness_threshold_ms: 120_000,
            bitcoin_rpc: None,
            geoip: None,
            metrics: None,
            pool_version,
            email_verification_hooks: Arc::new(crate::email_hooks::NoopVerificationHooks),
            pool_base_url: None,
            email_enabled: false,
            push_hooks: Arc::new(crate::push_hooks::NoopPushHooks),
            start_time: Utc::now(),
            network: bitcoin::Network::Bitcoin,
            pool_identifier: String::new(),
            cache: ResponseCache::new(bp_config::ApiCacheConfig::default()),
        }
    }
}

/// Shared appstate alias — handlers consume `State<SharedState<H, M>>`.
pub type SharedState<H, M> = Arc<AppState<H, M>>;
