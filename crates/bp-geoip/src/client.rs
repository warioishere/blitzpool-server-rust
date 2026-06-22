// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP-level surface. Production impl talks to ip-api.com via
//! `reqwest`; tests inject a recording mock.

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use crate::error::GeoIpError;

/// Raw response shape from `http://ip-api.com/json/{ip}?fields=status,city,country`.
/// `status` is `"success"` on success and `"fail"` / `"private range"` /
/// `"reserved range"` etc. on failure.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct IpApiResponse {
    pub status: String,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
}

/// HTTP-level abstraction. Production impl wraps `reqwest`; tests use
/// a recording mock. Keeps the service free of `reqwest` so unit-tests
/// can run without a live HTTP listener.
#[async_trait]
pub trait GeoIpClient: Send + Sync + 'static {
    async fn lookup(&self, ip: &str) -> Result<IpApiResponse, GeoIpError>;
}

/// Production HTTP impl. Constructed once per `GeoIpService::spawn`.
pub struct ReqwestGeoIpClient {
    http: reqwest::Client,
    base_url: String,
}

impl ReqwestGeoIpClient {
    /// `base_url` is `http://ip-api.com` in production; tests can point
    /// it at a mock HTTP server.
    pub fn new(base_url: impl Into<String>, request_timeout: Duration) -> Result<Self, GeoIpError> {
        let http = reqwest::Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(|e| GeoIpError::Http(format!("client build: {e}")))?;
        Ok(Self {
            http,
            base_url: base_url.into(),
        })
    }
}

#[async_trait]
impl GeoIpClient for ReqwestGeoIpClient {
    async fn lookup(&self, ip: &str) -> Result<IpApiResponse, GeoIpError> {
        let url = format!("{}/json/{}", self.base_url, ip);
        let response = self
            .http
            .get(&url)
            .query(&[("fields", "status,city,country")])
            .send()
            .await
            .map_err(|e| GeoIpError::Http(format!("send: {e}")))?;
        let parsed: IpApiResponse = response
            .json()
            .await
            .map_err(|e| GeoIpError::Parse(format!("json: {e}")))?;
        Ok(parsed)
    }
}

#[cfg(test)]
pub mod test_support {
    //! Recording mock client for unit tests — public under `cfg(test)`
    //! so the integration tests in `tests/` can reuse it.

    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Returns queued responses in order. After the queue is drained,
    /// any further call panics — keeps tests honest about expected
    /// HTTP-call counts.
    pub struct ScriptedClient {
        queue: Mutex<VecDeque<Result<IpApiResponse, GeoIpError>>>,
        calls: Mutex<Vec<String>>,
    }

    impl Default for ScriptedClient {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ScriptedClient {
        pub fn new() -> Self {
            Self {
                queue: Mutex::new(VecDeque::new()),
                calls: Mutex::new(Vec::new()),
            }
        }

        pub fn enqueue_ok(&self, status: &str, city: Option<&str>, country: Option<&str>) {
            self.queue
                .lock()
                .expect("scripted client poisoned")
                .push_back(Ok(IpApiResponse {
                    status: status.to_string(),
                    city: city.map(String::from),
                    country: country.map(String::from),
                }));
        }

        pub fn enqueue_err(&self, err: GeoIpError) {
            self.queue
                .lock()
                .expect("scripted client poisoned")
                .push_back(Err(err));
        }

        pub fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("scripted client poisoned").clone()
        }
    }

    #[async_trait]
    impl GeoIpClient for ScriptedClient {
        async fn lookup(&self, ip: &str) -> Result<IpApiResponse, GeoIpError> {
            self.calls
                .lock()
                .expect("scripted client poisoned")
                .push(ip.to_string());
            self.queue
                .lock()
                .expect("scripted client poisoned")
                .pop_front()
                .expect("ScriptedClient queue is empty — test fixture mismatch")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_api_response_parses_success() {
        let json = r#"{"status":"success","city":"Berlin","country":"Germany"}"#;
        let parsed: IpApiResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.status, "success");
        assert_eq!(parsed.city.as_deref(), Some("Berlin"));
        assert_eq!(parsed.country.as_deref(), Some("Germany"));
    }

    #[test]
    fn ip_api_response_parses_failure_with_missing_fields() {
        // `status: "fail"` typically omits city/country entirely.
        let json = r#"{"status":"fail","message":"private range"}"#;
        let parsed: IpApiResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.status, "fail");
        assert!(parsed.city.is_none());
        assert!(parsed.country.is_none());
    }

    #[test]
    fn ip_api_response_parses_success_with_empty_strings() {
        // Edge case: ip-api can return status=success with empty fields
        // for IPs in unmappable ranges. Service must filter these.
        let json = r#"{"status":"success","city":"","country":""}"#;
        let parsed: IpApiResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.status, "success");
        assert_eq!(parsed.city.as_deref(), Some(""));
        assert_eq!(parsed.country.as_deref(), Some(""));
    }
}
