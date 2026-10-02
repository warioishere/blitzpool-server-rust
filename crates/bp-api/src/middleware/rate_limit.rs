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

/// Build an `n`-per-60s [`LimitConfig`]; [`per_minute_layer`] wraps it for a
/// single axum route.
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

/// The [`per_minute`] limit as a layer for a single axum route.
pub fn per_minute_layer(
    n: u32,
) -> GovernorLayer<SmartIpKeyExtractor, NoOpMiddleware, axum::body::Body> {
    GovernorLayer::new(per_minute(n))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn status(app: &Router, ip: &str) -> StatusCode {
        let req = Request::builder()
            .uri("/limited")
            .header("x-forwarded-for", ip)
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(req).await.unwrap().status()
    }

    /// The burst is `n` per IP; the next request is refused with 429 while a
    /// different IP still has its own bucket.
    #[tokio::test]
    async fn the_request_past_the_burst_is_refused_per_ip() {
        let app = Router::new()
            .route("/limited", get(|| async { "ok" }))
            .layer(super::per_minute_layer(2));

        assert_eq!(status(&app, "10.0.0.1").await, StatusCode::OK);
        assert_eq!(status(&app, "10.0.0.1").await, StatusCode::OK);
        assert_eq!(
            status(&app, "10.0.0.1").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(status(&app, "10.0.0.2").await, StatusCode::OK);
    }
}
