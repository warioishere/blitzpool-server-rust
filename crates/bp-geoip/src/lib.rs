// SPDX-License-Identifier: AGPL-3.0-or-later

//! GeoIP lookups for per-miner display: an ip-api.com lookup ([`client`])
//! behind an in-memory cache ([`service`]) that is wiped whole every
//! 10 minutes. Failed or empty lookups are cached as `None` so
//! unresolvable IPs do not hammer the upstream.

pub mod client;
pub mod error;
pub mod service;

use std::time::Duration;

pub use client::{GeoIpClient, ReqwestGeoIpClient};
pub use error::GeoIpError;
pub use service::{GeoIpService, GeoLocation};

pub const BASE_URL: &str = "http://ip-api.com";
pub const CACHE_TTL: Duration = Duration::from_secs(600);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
