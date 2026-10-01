// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-process cache in front of the HTTP lookup, wiped whole every TTL
//! (not per entry) so cached failures eventually retry.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::{debug, warn};

use crate::client::GeoIpClient;

/// Resolved location for one IP; a partial result keeps the known field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoLocation {
    pub city: Option<String>,
    pub country: Option<String>,
}

impl GeoLocation {
    /// A "success" response with both city and country empty is cached as
    /// a negative hit, so an unmappable IP is not re-queried until the wipe.
    pub fn is_meaningful(&self) -> bool {
        let has_city = self.city.as_deref().is_some_and(|c| !c.is_empty());
        let has_country = self.country.as_deref().is_some_and(|c| !c.is_empty());
        has_city || has_country
    }
}

type Cache = Arc<Mutex<HashMap<String, Option<GeoLocation>>>>;

pub struct GeoIpService {
    client: Arc<dyn GeoIpClient>,
    cache: Cache,
}

impl GeoIpService {
    /// Starts the task that wipes the cache every `cache_ttl`; it lives as
    /// long as the process.
    pub fn spawn(client: Arc<dyn GeoIpClient>, cache_ttl: Duration) -> Self {
        let cache: Cache = Arc::default();
        let wiped = cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cache_ttl);
            // Skip the immediate first tick — first wipe is at t = ttl.
            interval.tick().await;
            loop {
                interval.tick().await;
                let mut guard = wiped.lock().expect("geoip cache poisoned");
                let n = guard.len();
                guard.clear();
                debug!(cleared = n, "geoip cache wiped (TTL fired)");
            }
        });
        Self { client, cache }
    }

    pub async fn get_location(&self, ip: &str) -> Option<GeoLocation> {
        if let Some(cached) = self
            .cache
            .lock()
            .expect("geoip cache poisoned")
            .get(ip)
            .cloned()
        {
            return cached;
        }

        // Failures are cached as `None` so repeats do not hammer ip-api.
        let result = match self.client.lookup(ip).await {
            Ok(resp) if resp.status == "success" => {
                let loc = GeoLocation {
                    city: resp.city,
                    country: resp.country,
                };
                if loc.is_meaningful() {
                    Some(loc)
                } else {
                    None
                }
            }
            Ok(resp) => {
                warn!(ip, status = %resp.status, "geoip non-success status");
                None
            }
            Err(e) => {
                warn!(ip, error = %e, "geoip lookup error");
                None
            }
        };

        self.cache
            .lock()
            .expect("geoip cache poisoned")
            .insert(ip.to_string(), result.clone());
        result
    }

    #[cfg(test)]
    fn cache_len(&self) -> usize {
        self.cache.lock().expect("geoip cache poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_support::ScriptedClient;
    use crate::error::GeoIpError;

    fn service_no_spawn(client: Arc<ScriptedClient>) -> GeoIpService {
        GeoIpService::spawn(client, crate::CACHE_TTL)
    }

    #[test]
    fn geolocation_is_meaningful_predicate() {
        let none = GeoLocation {
            city: None,
            country: None,
        };
        assert!(!none.is_meaningful());

        let empty_strings = GeoLocation {
            city: Some(String::new()),
            country: Some(String::new()),
        };
        assert!(!empty_strings.is_meaningful());

        let only_country = GeoLocation {
            city: None,
            country: Some("DE".to_string()),
        };
        assert!(only_country.is_meaningful());

        let only_city = GeoLocation {
            city: Some("Berlin".to_string()),
            country: None,
        };
        assert!(only_city.is_meaningful());

        let both = GeoLocation {
            city: Some("Berlin".to_string()),
            country: Some("DE".to_string()),
        };
        assert!(both.is_meaningful());
    }

    #[tokio::test]
    async fn cache_hit_avoids_second_http_call() {
        let client = Arc::new(ScriptedClient::new());
        client.enqueue_ok("success", Some("A"), Some("B"));
        let service = service_no_spawn(client.clone());

        let first = service.get_location("1.1.1.1").await;
        assert_eq!(
            first,
            Some(GeoLocation {
                city: Some("A".to_string()),
                country: Some("B".to_string()),
            })
        );
        assert_eq!(client.calls().len(), 1);

        // Second call: cache hit, no HTTP.
        let second = service.get_location("1.1.1.1").await;
        assert_eq!(second, first);
        assert_eq!(
            client.calls().len(),
            1,
            "cache hit must not trigger HTTP call"
        );
    }

    #[tokio::test]
    async fn non_success_status_caches_negative() {
        let client = Arc::new(ScriptedClient::new());
        client.enqueue_ok("fail", None, None);
        let service = service_no_spawn(client.clone());

        let r = service.get_location("10.0.0.1").await;
        assert!(r.is_none(), "non-success returns None");
        assert_eq!(service.cache_len(), 1, "negative result cached");

        // Subsequent calls — still no HTTP, still None.
        let again = service.get_location("10.0.0.1").await;
        assert!(again.is_none());
        assert_eq!(
            client.calls().len(),
            1,
            "negative cache hit must not trigger HTTP"
        );
    }

    #[tokio::test]
    async fn success_with_empty_city_and_country_caches_negative() {
        let client = Arc::new(ScriptedClient::new());
        client.enqueue_ok("success", Some(""), Some(""));
        let service = service_no_spawn(client);

        let r = service.get_location("0.0.0.0").await;
        assert!(
            r.is_none(),
            "empty city+country must filter to negative even when status=success"
        );
    }

    #[tokio::test]
    async fn success_with_only_country_returns_meaningful_location() {
        let client = Arc::new(ScriptedClient::new());
        client.enqueue_ok("success", None, Some("Germany"));
        let service = service_no_spawn(client);

        let r = service.get_location("1.2.3.4").await;
        assert_eq!(
            r,
            Some(GeoLocation {
                city: None,
                country: Some("Germany".to_string()),
            })
        );
    }

    #[tokio::test]
    async fn http_error_caches_negative() {
        let client = Arc::new(ScriptedClient::new());
        client.enqueue_err(GeoIpError::Http("timeout".to_string()));
        let service = service_no_spawn(client.clone());

        let r = service.get_location("2.3.4.5").await;
        assert!(r.is_none(), "HTTP error returns None");
        assert_eq!(service.cache_len(), 1, "error result cached as negative");

        // Cache hit on the next call.
        let again = service.get_location("2.3.4.5").await;
        assert!(again.is_none());
        assert_eq!(client.calls().len(), 1);
    }

    #[tokio::test]
    async fn distinct_ips_get_independent_cache_entries() {
        let client = Arc::new(ScriptedClient::new());
        client.enqueue_ok("success", Some("Tokyo"), Some("JP"));
        client.enqueue_ok("success", Some("Paris"), Some("FR"));
        let service = service_no_spawn(client.clone());

        let tokyo = service.get_location("203.0.113.1").await;
        let paris = service.get_location("198.51.100.1").await;
        assert_eq!(tokyo.as_ref().unwrap().city.as_deref(), Some("Tokyo"));
        assert_eq!(paris.as_ref().unwrap().city.as_deref(), Some("Paris"));
        assert_eq!(service.cache_len(), 2);
        assert_eq!(client.calls().len(), 2);
    }

    #[tokio::test]
    async fn spawn_clears_cache_on_ttl_tick() {
        let client = Arc::new(ScriptedClient::new());
        client.enqueue_ok("success", Some("A"), Some("B"));
        client.enqueue_ok("success", Some("C"), Some("D"));
        let service = GeoIpService::spawn(client.clone(), Duration::from_millis(50));

        let first = service.get_location("1.1.1.1").await;
        assert_eq!(first.unwrap().city.as_deref(), Some("A"));
        assert_eq!(service.cache_len(), 1);

        // Wait > TTL so the background tick wipes the cache.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(service.cache_len(), 0, "background task cleared cache");

        // Second call re-fetches from HTTP.
        let second = service.get_location("1.1.1.1").await;
        assert_eq!(second.unwrap().city.as_deref(), Some("C"));
        assert_eq!(client.calls().len(), 2);
    }
}
