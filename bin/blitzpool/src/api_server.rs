// SPDX-License-Identifier: AGPL-3.0-or-later

//! bp-api HTTP listener — Phase 7.4a.
//!
//! Builds the production [`AppState`] from the live foundation +
//! engine + hook aggregates, then binds an `axum::serve` task on
//! `[api] port`. The HTTP server is the first of the three TCP
//! services the binary brings up (HTTP, SV1, SV2); Stratum binding
//! follows in Phase 7.4b/c.
//!
//! `build_app_state` plumbs each foundation / engine / hook field
//! into the corresponding `AppState` slot — see the function body
//! for the detailed mapping. `GroupService`, `InvitationService`,
//! and `JoinRequestService` are constructed here (not in
//! `engines::spawn`) because they're the bp-api-layer composition
//! of the engine hooks rather than long-lived background services.

use std::net::SocketAddr;
use std::sync::Arc;

use bp_api::{build_router, response_cache::ResponseCache, AppState};
use bp_config::AppConfig;
use bp_group_mgmt_engine::{InvitationService, JoinRequestService, JoinRequestServiceConfig};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::boot::FoundationHandles;
use crate::engines::EngineHandles;
use crate::group_service::SharedGroupService;
use crate::hooks::{ProductionGroupServiceHooks, ProductionHooks, SmtpInvitationEmailHooks};

#[derive(Debug, Error)]
pub(crate) enum ApiServerError {
    #[error("bind {addr} failed: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// Long-lived handle returned by [`spawn`] — drop to cancel the
/// listener task, or `await` the inner `JoinHandle` to surface a
/// panic from inside the server.
#[allow(dead_code)]
pub(crate) struct ApiServerHandle {
    pub(crate) addr: SocketAddr,
    pub(crate) join: JoinHandle<()>,
}

/// Bind the bp-api HTTP server on `cfg.api.port` and start serving.
/// The task lives until the listener errors out or the JoinHandle is
/// aborted. Returns immediately after the TCP listener binds — every
/// caller awaits the join handle separately.
pub(crate) async fn spawn(
    cfg: &AppConfig,
    foundation: &FoundationHandles,
    engines: &EngineHandles,
    production_hooks: &ProductionHooks,
    group_service: &SharedGroupService,
    blockparty: Option<&crate::blockparty_service::SharedBlockparty>,
) -> Result<ApiServerHandle, ApiServerError> {
    let state = build_app_state(
        cfg,
        foundation,
        engines,
        production_hooks,
        group_service,
        blockparty,
    );
    let router = build_router(state);

    let addr: SocketAddr = ([0, 0, 0, 0], cfg.api.port).into();
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| ApiServerError::Bind { addr, source })?;
    info!(%addr, "bp-api: listening");

    // Serve with per-connection peer-address info so the rate-limiter's
    // IP key extractor has a fallback when no `x-forwarded-for` /
    // `x-real-ip` / `Forwarded` header is present (direct hits, or a
    // proxy that doesn't set them). Without this, rate-limited routes
    // respond 500 `Unable To Extract Key!` instead of admitting the
    // request keyed by peer IP.
    let make_service = router.into_make_service_with_connect_info::<SocketAddr>();
    let join = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, make_service).await {
            warn!(%err, "bp-api: serve loop exited");
        } else {
            info!("bp-api: serve loop ended cleanly");
        }
    });
    Ok(ApiServerHandle { addr, join })
}

/// Construct the AppState from the live aggregates. Public for
/// `--check-api-state` flag (future) + unit tests that want to
/// inspect the produced state.
fn build_app_state(
    cfg: &AppConfig,
    foundation: &FoundationHandles,
    engines: &EngineHandles,
    production_hooks: &ProductionHooks,
    group_service: &SharedGroupService,
    blockparty: Option<&crate::blockparty_service::SharedBlockparty>,
) -> Arc<AppState<ProductionGroupServiceHooks, SmtpInvitationEmailHooks>> {
    let pool = foundation.db.pool().clone();
    let group_service = group_service.service.clone();
    let invitation_service = Arc::new(InvitationService::new(pool.clone(), group_service.clone()));
    let join_request_service = Arc::new(JoinRequestService::new(
        pool.clone(),
        group_service.clone(),
        production_hooks.invitation_email.clone(),
        JoinRequestServiceConfig {
            pool_base_url: cfg.pool_base_url.clone(),
            ..JoinRequestServiceConfig::default()
        },
    ));

    let pplns_arc = engines.pplns.clone().map(Arc::new);
    let group_solo_arc = Some(Arc::new(engines.group_solo.clone()));
    let bitcoin_rpc_arc = Some(Arc::new(foundation.bitcoin_rpc.clone()));
    let tdp_clone = foundation.tdp.clone();
    let geoip_arc = foundation.geoip.clone();
    let metrics_clone = foundation.metrics.clone();

    let state = AppState {
        pool,
        redis: Some(foundation.redis.clone()),
        pplns: pplns_arc,
        group_solo: group_solo_arc,
        group_service: Some(group_service),
        invitation_service: Some(invitation_service),
        join_request_service: Some(join_request_service),
        blockparty: blockparty.map(|bp| bp.service.clone()),
        tdp: tdp_clone,
        tdp_staleness_threshold_ms: (cfg.tdp.staleness_threshold_secs as i64) * 1000,
        bitcoin_rpc: bitcoin_rpc_arc,
        geoip: geoip_arc,
        metrics: metrics_clone,
        pool_version: env!("CARGO_PKG_VERSION"),
        email_verification_hooks: production_hooks.email_verification.clone(),
        pool_base_url: cfg.pool_base_url.clone(),
        email_enabled: cfg.smtp.is_some(),
        push_hooks: production_hooks.push.clone(),
        start_time: chrono::Utc::now(),
        network: match cfg.network {
            bp_config::Network::Mainnet => bitcoin::Network::Bitcoin,
            bp_config::Network::Testnet | bp_config::Network::Testnet4 => bitcoin::Network::Testnet,
            bp_config::Network::Regtest => bitcoin::Network::Regtest,
        },
        pool_identifier: cfg.pool_identifier.clone(),
        cache: ResponseCache::new(cfg.api.cache.clone()),
    };
    Arc::new(state)
}
