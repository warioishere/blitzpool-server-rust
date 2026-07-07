// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP API for the Rust port of the Blitzpool admin/UI surface.
//!
//! Built on `axum` + a typed [`AppState`] threaded through every
//! handler. Each `controllers/<name>.rs` module owns ~10 endpoints
//! and exposes a `routes()` helper returning an axum
//! `Router<SharedState<H, M>>`.
//!
//! ## Module status
//!
//! - ✅ `controllers::info` — `/api/info/*` + `/pool` + `/network` +
//!   `/health` + `/info/block-template`. Chart / accepted / workers /
//!   rejected / shares endpoints are deferred (need new bp-db time-range
//!   readers).
//! - ✅ `controllers::pplns` — 7 reader endpoints driven by
//!   `PplnsEngine::reader()` (the `/chart` time-series endpoint is in
//!   the same deferred bucket).
//! - ✅ `controllers::groups`
//! - ✅ `controllers::client`
//! - ✅ `controllers::invitation`
//! - ✅ writers
//!
//! ## Route prefixes
//!
//! Group routes are mounted under `/api/pplns/groups/*` and invitation
//! routes under `/api/pplns/invitations/*`, matching the upstream
//! controller prefixes (`pplns/groups`, `pplns/invitations`). UI fetch
//! URLs must use these exact prefixes.

mod controllers;
pub mod email_hooks;
pub mod error;
pub mod middleware;
pub mod push_hooks;
pub mod response_cache;
pub mod state;
pub mod time_range;
pub mod utils;

pub use email_hooks::{
    BindingChangeContext, EmailVerificationHooks, NoopVerificationHooks, VerificationContext,
};
pub use error::ApiError;
pub use push_hooks::{FcmRegisterContext, NoopPushHooks, PushHooks, UnifiedPushRegisterContext};
pub use state::{AppState, SharedState};

use axum::Router;
use bp_group_mgmt_engine::{EmailHooks, GroupServiceHooks};
use tower_http::cors::CorsLayer;

/// Build the root router from a [`SharedState`]. The state is shared
/// across handlers via `Arc`.
pub fn build_router<H, M>(state: SharedState<H, M>) -> Router
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    Router::new()
        .merge(controllers::info::routes())
        .merge(controllers::pplns::routes())
        .merge(controllers::groups::routes(state.clone()))
        .merge(controllers::address_ownership::routes())
        .merge(controllers::blockparty::routes())
        .merge(controllers::client::routes())
        .merge(controllers::invitation::routes())
        .merge(controllers::external_share::routes())
        .merge(controllers::downstream_report::routes())
        .merge(controllers::email::routes())
        .merge(controllers::push::routes())
        .with_state(state)
        .layer(CorsLayer::permissive())
}
