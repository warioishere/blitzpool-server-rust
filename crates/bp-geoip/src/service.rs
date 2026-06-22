// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-process cache + background TTL refresher in front of the HTTP
//! lookup. Uses a whole-cache wipe every 10 minutes (not per-entry
//! TTL) so failed lookups eventually retry.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::client::GeoIpClient;
use crate::config::GeoIpConfig;
use crate::error::GeoIpError;

/// Resolved location for a single IP. Both fields are non-empty when
/// the lookup succeeded; partial results (e.g. country known but city
/// missing) keep the known field and leave the other as `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoLocation {
    pub city: Option<String>,
    pub country: Option<String>,
}

impl GeoLocation {
    /// Predicate used by the service to decide whether to cache the
    /// result as a positive hit (`Some(GeoLocation)`) or as a negative
    /// hit (`None`). A "success"-status response with both city +
    /// country empty is treated as a negative — caches `None` so we
    /// don't re-query the same unmappable IP for 10 minutes.
    pub fn is_meaningful(&self) -> bool {
        let has_city = self.city.as_deref().is_some_and(|c| !c.is_empty());
        let has_country = self.country.as_deref().is_some_and(|c| !c.is_empty());
        has_city || has_country
    }
}

/// Spawn-friendly service handle. Owns the cache + the periodic clear
/// task. Cheap to clone (single `Arc`).
pub struct GeoIpService<C: GeoIpClient> {
    client: Arc<C>,
    cache: Arc<Mutex<HashMap<String, Option<GeoLocation>>>>,
}

impl<C: GeoIpClient> GeoIpService<C> {
    /// Build the service WITHOUT starting the background cache-clear
    /// task. Useful for tests that drive the cache manually. Production
    /// callers go through [`Self::spawn`].
    pub fn new(_config: &GeoIpConfig, client: Arc<C>) -> Self {
        Self {
            client,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Build + spawn the periodic cache-clear task.
    pub fn spawn(config: GeoIpConfig, client: Arc<C>) -> Result<GeoIpServiceHandle, GeoIpError> {
        config.validate()?;
        let service = Self::new(&config, client);
        let cache = service.cache.clone();
        let ttl = config.cache_ttl;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let join = tokio::spawn(async move {
            let mut interval = tokio::time::interval(ttl);
            // Skip the immediate first tick — first wipe is at t = ttl.
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let mut guard = cache.lock().expect("geoip cache poisoned");
                        let n = guard.len();
                        guard.clear();
                        debug!(cleared = n, "geoip cache wiped (TTL fired)");
                    }
                    _ = &mut shutdown_rx => {
                        debug!("geoip cache-clear task received shutdown");
                        break;
                    }
                }
            }
        });

        Ok(GeoIpServiceHandle {
            inner: Arc::new(GeoIpServiceInner {
                client: service.client,
                cache: service.cache,
            }),
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
            join: Mutex::new(Some(join)),
        })
    }

    /// Direct lookup path — used by [`GeoIpServiceHandle::get_location`]
    /// in production. Exposed on `Self` so the test fixture can drive
    /// the same code path without spawning the background task.
    pub async fn get_location(&self, ip: &str) -> Option<GeoLocation> {
        // Fast path: cache hit (either positive or negative).
        if let Some(cached) = self
            .cache
            .lock()
            .expect("geoip cache poisoned")
            .get(ip)
            .cloned()
        {
            return cached;
        }

        // Cache miss — HTTP lookup. Any failure / unmeaningful payload
        // gets cached as `None` so we don't hammer ip-api on repeat
        // calls for the same address.
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

    /// Internal cache accessor for tests + the handle's read-side.
    pub fn cache_len(&self) -> usize {
        self.cache.lock().expect("geoip cache poisoned").len()
    }
}

/// Cheap-to-clone handle. `bin/blitzpool` and `bp-api` clone this into
/// the per-request task pool.
pub struct GeoIpServiceHandle {
    inner: Arc<GeoIpServiceInner>,
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
    join: Mutex<Option<JoinHandle<()>>>,
}

struct GeoIpServiceInner {
    client: Arc<dyn GeoIpClient>,
    cache: Arc<Mutex<HashMap<String, Option<GeoLocation>>>>,
}

impl GeoIpServiceHandle {
    pub async fn get_location(&self, ip: &str) -> Option<GeoLocation> {
        if let Some(cached) = self
            .inner
            .cache
            .lock()
            .expect("geoip cache poisoned")
            .get(ip)
            .cloned()
        {
            return cached;
        }

        let result = match self.inner.client.lookup(ip).await {
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

        self.inner
            .cache
            .lock()
            .expect("geoip cache poisoned")
            .insert(ip.to_string(), result.clone());
        result
    }

    pub fn cache_len(&self) -> usize {
        self.inner.cache.lock().expect("geoip cache poisoned").len()
    }

    /// Force-clear the cache. Used by admin endpoints that want to
    /// invalidate without waiting for the next TTL tick.
    pub fn clear_cache(&self) {
        self.inner
            .cache
            .lock()
            .expect("geoip cache poisoned")
            .clear();
    }

    /// Signal shutdown + await the background task. Idempotent — second
    /// call is a no-op.
    pub async fn shutdown(&self) {
        if let Some(tx) = self
            .shutdown_tx
            .lock()
            .expect("geoip shutdown_tx poisoned")
            .take()
        {
            let _ = tx.send(());
        }
        // Take the JoinHandle out of the Mutex BEFORE the .await so the
        // MutexGuard doesn't live across the await point (clippy lint:
        // `await_holding_lock`).
        let join = self.join.lock().expect("geoip join poisoned").take();
        if let Some(join) = join {
            if let Err(e) = join.await {
                warn!(error = %e, "geoip cache-clear task panicked");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_support::ScriptedClient;

    fn service_no_spawn(client: Arc<ScriptedClient>) -> GeoIpService<ScriptedClient> {
        GeoIpService::new(&GeoIpConfig::default(), client)
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
    async fn spawn_handle_clears_cache_on_ttl_tick() {
        // Tight TTL so the test runs fast. Drive the same code path
        // production uses.
        let client = Arc::new(ScriptedClient::new());
        client.enqueue_ok("success", Some("A"), Some("B"));
        client.enqueue_ok("success", Some("C"), Some("D"));
        let handle = GeoIpService::spawn(
            GeoIpConfig {
                cache_ttl: std::time::Duration::from_millis(50),
                ..GeoIpConfig::default()
            },
            client.clone(),
        )
        .expect("spawn");

        let first = handle.get_location("1.1.1.1").await;
        assert_eq!(first.unwrap().city.as_deref(), Some("A"));
        assert_eq!(handle.cache_len(), 1);

        // Wait > TTL so the background tick wipes the cache.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(handle.cache_len(), 0, "background task cleared cache");

        // Second call re-fetches from HTTP.
        let second = handle.get_location("1.1.1.1").await;
        assert_eq!(second.unwrap().city.as_deref(), Some("C"));
        assert_eq!(client.calls().len(), 2);

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn clear_cache_invalidates_immediately() {
        let client = Arc::new(ScriptedClient::new());
        client.enqueue_ok("success", Some("A"), Some("B"));
        client.enqueue_ok("success", Some("C"), Some("D"));
        let handle = GeoIpService::spawn(
            GeoIpConfig {
                cache_ttl: std::time::Duration::from_secs(3600),
                ..GeoIpConfig::default()
            },
            client.clone(),
        )
        .expect("spawn");

        let first = handle.get_location("9.9.9.9").await;
        assert_eq!(first.unwrap().city.as_deref(), Some("A"));

        handle.clear_cache();
        assert_eq!(handle.cache_len(), 0);

        // Next call re-fetches.
        let second = handle.get_location("9.9.9.9").await;
        assert_eq!(second.unwrap().city.as_deref(), Some("C"));

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let client = Arc::new(ScriptedClient::new());
        let handle = GeoIpService::spawn(GeoIpConfig::default(), client).expect("spawn");
        handle.shutdown().await;
        // Second call is a no-op.
        handle.shutdown().await;
    }

    #[test]
    fn spawn_with_invalid_config_rejects() {
        let client = Arc::new(ScriptedClient::new());
        let bad = GeoIpConfig {
            base_url: String::new(),
            ..GeoIpConfig::default()
        };
        let result = GeoIpService::spawn(bad, client);
        assert!(result.is_err());
    }
}
