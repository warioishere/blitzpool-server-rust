// SPDX-License-Identifier: AGPL-3.0-or-later

//! bp-api HTTP listener.
//!
//! `InvitationService` and `JoinRequestService` are built here, not in
//! `engines::spawn`, because they only compose engine hooks for the API.

use std::net::SocketAddr;
use std::sync::Arc;

use bp_api::middleware::{AddressAuth, AddressTokenSecret};
use bp_api::{build_router, response_cache::ResponseCache, AppState, ModeCacheNotifier};
use bp_config::{AddressAuthConfig, AppConfig};
use bp_group_mgmt_engine::{InvitationService, JoinRequestService, JoinRequestServiceConfig};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::boot::FoundationHandles;
use crate::engines::EngineHandles;
use crate::hooks::ProductionHooks;
use crate::membership::Membership;

#[derive(Debug, Error)]
pub(crate) enum ApiServerError {
    #[error("bind {addr} failed: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("[api.address_auth] is enabled but its session_secret is empty")]
    AddressAuthSecretMissing,
}

pub(crate) struct ApiServerHandle {
    pub(crate) addr: SocketAddr,
    pub(crate) join: JoinHandle<()>,
}

/// Returns as soon as the listener binds; the caller awaits the join handle.
pub(crate) async fn spawn(
    cfg: &AppConfig,
    foundation: &FoundationHandles,
    engines: &EngineHandles,
    production_hooks: &ProductionHooks,
    membership: &Membership,
) -> Result<ApiServerHandle, ApiServerError> {
    let address_auth = address_auth(&cfg.api.address_auth)?;
    let cache = ResponseCache::new(cfg.api.cache.clone());
    wire_change_notifier(foundation, membership, &cache);
    let state = build_app_state(
        cfg,
        foundation,
        engines,
        production_hooks,
        membership,
        address_auth,
        cache,
    );
    let router = build_router(state);

    let addr: SocketAddr = ([0, 0, 0, 0], cfg.api.port).into();
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| ApiServerError::Bind { addr, source })?;
    info!(%addr, "bp-api: listening");

    // Peer-address info is the rate-limiter's key when no forwarding header
    // is present; without it rate-limited routes answer 500.
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

fn build_app_state(
    cfg: &AppConfig,
    foundation: &FoundationHandles,
    engines: &EngineHandles,
    production_hooks: &ProductionHooks,
    membership: &Membership,
    address_auth: AddressAuth,
    cache: ResponseCache,
) -> Arc<AppState> {
    let pool = foundation.db.pool().clone();
    let group_service = membership.group.service.clone();
    let invitation_service = Arc::new(InvitationService::new(pool.clone(), group_service.clone()));
    let join_request_service = Arc::new(JoinRequestService::new(
        pool.clone(),
        group_service.clone(),
        production_hooks.join_decision_email.clone(),
        Arc::new(crate::join_request_notify::StreamJoinRequestNotifier::new(
            foundation.redis.clone(),
        )),
        JoinRequestServiceConfig {
            pool_base_url: cfg.pool_base_url.clone(),
            ..JoinRequestServiceConfig::default()
        },
    ));

    let pplns_arc = engines.pplns.clone().map(Arc::new);
    let group_solo_arc = engines.group_solo.clone().map(Arc::new);
    let bitcoin_rpc_arc = Some(Arc::new(foundation.bitcoin_rpc.clone()));
    let tdp_clone = foundation.tdp.clone();
    let geoip_arc = foundation.geoip.clone();

    let state = AppState {
        pool,
        redis: Some(foundation.redis.clone()),
        pplns: pplns_arc,
        pplns_budget_autoscaled: cfg
            .pplns
            .as_ref()
            .and_then(|p| p.coinbase_autoscale.as_ref())
            .is_some_and(|a| a.enabled),
        group_solo: group_solo_arc,
        group_service: Some(group_service),
        invitation_service: Some(invitation_service),
        join_request_service: Some(join_request_service),
        blockparty: membership.blockparty_service(),
        tdp: tdp_clone,
        tdp_staleness_threshold_ms: (cfg.tdp.staleness_threshold_secs as i64) * 1000,
        bitcoin_rpc: bitcoin_rpc_arc,
        geoip: geoip_arc,
        pool_version: env!("CARGO_PKG_VERSION"),
        email_verification_hooks: production_hooks.email_verification.clone(),
        pool_base_url: cfg.pool_base_url.clone(),
        email_enabled: cfg.smtp.is_some(),
        start_time: chrono::Utc::now(),
        network: crate::boot::bitcoin_network(cfg.network),
        pool_identifier: cfg.pool_identifier.clone(),
        solo_fee: crate::payout_resolver::solo_fee_config(cfg),
        cache,
        address_auth,
    };
    Arc::new(state)
}

/// The api writes memberships: each Team or Blockparty change drops the
/// cached modes it may have made wrong and goes onto `cache:invalidate`, from
/// which the front rebuilds its routing without a restart.
fn wire_change_notifier(
    foundation: &FoundationHandles,
    membership: &Membership,
    cache: &ResponseCache,
) {
    let stream = Arc::new(crate::cache_sync::StreamCacheNotifier::new(
        foundation.redis.clone(),
    ));
    let notifier = Arc::new(ModeCacheNotifier::new(cache.clone(), stream));
    membership
        .group
        .service
        .set_change_notifier(notifier.clone());
    if let Some(blockparty) = membership.blockparty_service() {
        blockparty.set_change_notifier(notifier);
    }
}

/// `[api.address_auth] enabled = true` turns the address-token check on, and
/// then the sidecar's secret is required: without it every such route would
/// refuse every request, so the api does not start.
fn address_auth(cfg: &AddressAuthConfig) -> Result<AddressAuth, ApiServerError> {
    if !cfg.enabled {
        info!("bp-api: address-token check off");
        return Ok(AddressAuth::Off);
    }
    let secret = AddressTokenSecret::new(&cfg.session_secret)
        .ok_or(ApiServerError::AddressAuthSecretMissing)?;
    info!("bp-api: address-token check on");
    Ok(AddressAuth::Required(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool, session_secret: &str) -> AddressAuthConfig {
        AddressAuthConfig {
            enabled,
            session_secret: session_secret.to_string(),
        }
    }

    #[test]
    fn the_check_is_off_unless_enabled_even_with_a_secret() {
        assert!(matches!(
            address_auth(&cfg(false, "s")),
            Ok(AddressAuth::Off)
        ));
        assert!(matches!(
            address_auth(&cfg(false, "")),
            Ok(AddressAuth::Off)
        ));
    }

    #[test]
    fn enabled_the_check_needs_the_secret() {
        assert!(matches!(
            address_auth(&cfg(true, "s")),
            Ok(AddressAuth::Required(_))
        ));
        for blank in ["", "  \n"] {
            assert!(matches!(
                address_auth(&cfg(true, blank)),
                Err(ApiServerError::AddressAuthSecretMissing)
            ));
        }
    }
}
