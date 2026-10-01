// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-route per-IP rate limiting; each [`per_minute`] call has its own
//! bucket. [`SmartIpKeyExtractor`] keys on the proxy headers, then the peer
//! address: a reverse proxy must set one, or the whole deployment shares one
//! bucket. With neither (e.g. a `oneshot` test) the layer answers 500.

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
