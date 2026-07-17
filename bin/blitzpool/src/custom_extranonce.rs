// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-memory cache of customer extranonce overrides, read by the SV2 stratum
//! server at channel-open.
//!
//! The API process writes `pplns_custom_extranonce`; the core (this process)
//! reads it. They are separate processes, so the core can't see a write
//! instantly — it reloads the whole table on a fixed interval. The table holds
//! a handful of rows (one paying customer), so a full reload is one cheap
//! query, and a change lands on the core within one interval and applies at the
//! worker's next channel-open.
//!
//! The cache is read on the channel-open path only (once per connection), so
//! the per-lookup `String` allocation is immaterial; it is never touched on the
//! per-share or per-broadcast hot paths.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bp_stratum_v2::hooks::CustomExtranonceSource;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// How often the core reloads the override table.
const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

type OverrideMap = HashMap<(String, String), u32>;

/// `(address, worker) -> prefix` cache, refreshed off PG in the background.
pub(crate) struct CustomExtranonceCache {
    map: Arc<RwLock<OverrideMap>>,
    // Cancels the refresh task when the cache is dropped (process shutdown).
    _refresh: tokio_util::sync::DropGuard,
}

impl CustomExtranonceCache {
    /// Load the table once so the cache is warm before serving, then spawn a
    /// task that reloads every [`REFRESH_INTERVAL`]. Returns an `Arc` suitable
    /// for the [`CustomExtranonceSource`] hook slot.
    pub(crate) async fn spawn(pool: PgPool) -> Arc<Self> {
        let map = Arc::new(RwLock::new(load(&pool).await.unwrap_or_default()));
        let cancel = CancellationToken::new();
        let task_map = map.clone();
        let task_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(REFRESH_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tick.tick().await; // consume the immediate first tick — already loaded
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    _ = tick.tick() => {
                        // Only overwrite on a successful load: a transient DB
                        // error must not wipe the customer's override to empty.
                        if let Some(fresh) = load(&pool).await {
                            *task_map.write().expect("custom-en cache poisoned") = fresh;
                        }
                    }
                }
            }
        });
        Arc::new(Self {
            map,
            _refresh: cancel.drop_guard(),
        })
    }
}

impl CustomExtranonceSource for CustomExtranonceCache {
    fn lookup(&self, address: &str, worker: &str) -> Option<[u8; 4]> {
        self.map
            .read()
            .expect("custom-en cache poisoned")
            .get(&(address.to_string(), worker.to_string()))
            // Big-endian to match the allocator's `prefix_to_be_bytes`
            // convention (top byte first), so a customer prefix and an
            // allocated one share one wire encoding.
            .map(|prefix| prefix.to_be_bytes())
    }
}

/// Reload the whole override table into a fresh map. `None` on a DB error so
/// the caller keeps the previous snapshot rather than serving an empty one.
async fn load(pool: &PgPool) -> Option<OverrideMap> {
    match bp_db::all_custom_extranonces(pool).await {
        Ok(rows) => {
            let map: OverrideMap = rows
                .into_iter()
                .map(|r| ((r.address.as_str().to_string(), r.worker), r.prefix))
                .collect();
            debug!(overrides = map.len(), "custom-extranonce cache reloaded");
            Some(map)
        }
        Err(e) => {
            warn!(%e, "custom-extranonce cache reload failed; keeping previous snapshot");
            None
        }
    }
}
