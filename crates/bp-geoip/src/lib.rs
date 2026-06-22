// SPDX-License-Identifier: AGPL-3.0-or-later

//! GeoIP lookups for per-miner geographic display.
//!
//! Wraps an HTTP-backed lookup (ip-api.com by default) with a
//! process-wide in-memory cache that gets fully cleared every
//! 10 minutes (whole-cache wipe, not per-entry TTL).
//!
//! Negative results (HTTP error, ip-api `status != "success"`, empty
//! city+country) are cached as `None` to avoid hammering the upstream
//! for unresolvable IPs.
//!
//! # Module layout
//!
//! - [`client`] — `GeoIpClient` trait + production impl backed by
//!   `reqwest`. Tests inject a recording mock.
//! - [`service`] — `GeoIpService::spawn(config, client)` → handle
//!   exposing `get_location(ip)` + a background cache-clear task.

pub mod client;
pub mod config;
pub mod error;
pub mod service;

pub use client::{GeoIpClient, ReqwestGeoIpClient};
pub use config::GeoIpConfig;
pub use error::GeoIpError;
pub use service::{GeoIpService, GeoIpServiceHandle, GeoLocation};
