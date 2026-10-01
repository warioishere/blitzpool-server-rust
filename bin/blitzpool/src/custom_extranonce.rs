// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-memory cache of customer extranonce overrides, read by the SV2 server.
//!
//! The API process writes the table, so the core reloads it on an interval; it
//! holds a handful of rows, and a change applies at the next channel-open.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bp_stratum_v2::hooks::CustomExtranonceSource;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// `address -> worker -> prefix`. Nested so `lookup` keys by `&str` at both
/// levels with no per-call allocation.
type OverrideMap = HashMap<String, HashMap<String, u32>>;

pub(crate) struct CustomExtranonceCache {
    map: Arc<RwLock<OverrideMap>>,
    _refresh: tokio_util::sync::DropGuard,
}

impl CustomExtranonceCache {
    /// Loads once before returning so the cache is warm before serving.
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
        lookup_prefix(
            &self.map.read().expect("custom-en cache poisoned"),
            address,
            worker,
        )
    }
}

/// Big-endian to match the allocator's `prefix_to_be_bytes`, so a customer
/// prefix and an allocated one share one wire encoding.
fn lookup_prefix(map: &OverrideMap, address: &str, worker: &str) -> Option<[u8; 4]> {
    map.get(address)
        .and_then(|workers| workers.get(worker))
        .map(|prefix| prefix.to_be_bytes())
}

/// `None` on a DB error, so the caller keeps the previous snapshot.
async fn load(pool: &PgPool) -> Option<OverrideMap> {
    match bp_db::all_custom_extranonces(pool).await {
        Ok(rows) => {
            let count = rows.len();
            let mut map: OverrideMap = HashMap::new();
            for r in rows {
                map.entry(r.address.as_str().to_string())
                    .or_default()
                    .insert(r.worker, r.prefix);
            }
            debug!(overrides = count, "custom-extranonce cache reloaded");
            Some(map)
        }
        Err(e) => {
            warn!(%e, "custom-extranonce cache reload failed; keeping previous snapshot");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_prefix_finds_the_right_worker_and_encodes_big_endian() {
        let mut map: OverrideMap = HashMap::new();
        map.entry("bc1qalice".to_string())
            .or_default()
            .insert("rig1".to_string(), 0xC0DE_BABE);
        map.entry("bc1qalice".to_string())
            .or_default()
            .insert("rig2".to_string(), 0x0200_0001);

        assert_eq!(
            lookup_prefix(&map, "bc1qalice", "rig1"),
            Some([0xC0, 0xDE, 0xBA, 0xBE])
        );
        assert_eq!(
            lookup_prefix(&map, "bc1qalice", "rig2"),
            Some([0x02, 0x00, 0x00, 0x01])
        );
        assert_eq!(lookup_prefix(&map, "bc1qalice", "rig3"), None);
        assert_eq!(lookup_prefix(&map, "bc1qbob", "rig1"), None);
    }
}
