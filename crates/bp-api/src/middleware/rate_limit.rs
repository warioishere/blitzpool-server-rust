// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-route per-IP rate-limiting middleware.
//!
//! Applied on the 8 endpoints that are rate-limited (email register
//! 5/min, invitation accept/decline 20/min each, etc.). Each call to
//! [`per_minute`] allocates its own `GovernorConfig`, so a 5/min
//! limit on `/api/email/register` and a 5/min limit on
//! `/api/groups/:id/invitations/open` count independently.
//!
//! ### Key extraction
//!
//! [`SmartIpKeyExtractor`] reads `x-forwarded-for` → `x-real-ip` →
//! `Forwarded` → peer-addr in that order. **Operator note:** in
//! production behind a reverse proxy, that proxy must set one of
//! those headers — otherwise every request shares the proxy's IP and
//! the bucket throttles the whole deployment. The peer-addr fallback
//! relies on a `ConnectInfo<SocketAddr>` request extension; the
//! production server wires it via `into_make_service_with_connect_info`
//! so direct hits (no proxy header) key on the real peer IP instead of
//! failing. Where neither a header nor `ConnectInfo` is present — e.g.
//! a tower `oneshot` test that bypasses the connection layer — the
//! extractor cannot resolve a key and the layer responds with HTTP 500
//! (see [`tower_governor::GovernorError::UnableToExtractKey`]). The
//! smoke tests therefore set `x-forwarded-for: 127.0.0.1` on any
//! request that traverses a rate-limited route.

use std::sync::Arc;
use std::time::Duration;

use governor::middleware::NoOpMiddleware;
use tower_governor::governor::{GovernorConfig, GovernorConfigBuilder};
use tower_governor::key_extractor::SmartIpKeyExtractor;
use tower_governor::GovernorLayer;

/// Per-IP rate-limit configuration: `n` requests per 60 seconds with
/// a `burst_size = n`. Uses a token-bucket that replenishes one slot
/// every `60s / n` so steady-state allowance matches a strict
/// count-per-window.
pub type LimitConfig = Arc<GovernorConfig<SmartIpKeyExtractor, NoOpMiddleware>>;

/// Build an `n`-per-60s [`LimitConfig`]. Wrap in `GovernorLayer { config }`
/// to layer onto a single axum route.
pub fn per_minute(n: u32) -> LimitConfig {
    let period = Duration::from_secs(60)
        .checked_div(n)
        .expect("rate must be > 0");
    Arc::new(
        GovernorConfigBuilder::default()
            .period(period)
            .burst_size(n)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("valid governor config"),
    )
}

/// Convenience: build the layer in one call. Equivalent to
/// `GovernorLayer { config: per_minute(n) }`.
pub fn per_minute_layer(n: u32) -> GovernorLayer<SmartIpKeyExtractor, NoOpMiddleware> {
    GovernorLayer {
        config: per_minute(n),
    }
}
