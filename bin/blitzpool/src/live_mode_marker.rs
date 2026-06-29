// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-address live mode marker written to Redis on every accepted share.
//!
//! `/api/pplns/mode/:address` reads `miner:{address}:mode` as the
//! authoritative current-port marker (5-min TTL); when it's absent /
//! expired the controller falls back to retrospective state derived
//! from PPLNS window membership + group DB, which lags by hours after
//! a port switch.
//!
//! The marker is debounced by [`MarkDebouncer`] — same-mode writes
//! within 60 s are skipped, mode changes always go through (port-switch
//! detection is the whole point of the marker). The Redis SET errors are
//! best-effort: failure to write is logged but never blocks the share
//! path.

use std::sync::Arc;

use async_trait::async_trait;
use bp_common::AddressId;
use bp_mining_mode::MarkDebouncer;
use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareSink};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use tracing::warn;

/// 5 min. The marker's authority window — after this, the controller
/// falls back to the state-based mode derivation.
const MARKER_TTL_SECONDS: u64 = 5 * 60;

/// `SharedAcceptedShareSink` that writes `miner:{address}:mode` after
/// every accepted share, debounced to ≤ one write per minute per
/// (address, mode) pair.
pub(crate) struct LiveModeMarkerSink {
    /// `ConnectionManager` is already `Clone` + internally multiplexed
    /// (Arc-backed), so we clone it per write like the window stores do —
    /// no external `Mutex` serializing every marker write on the hot path.
    redis: ConnectionManager,
    debouncer: Arc<MarkDebouncer>,
}

impl LiveModeMarkerSink {
    pub(crate) fn new(redis: ConnectionManager, debouncer: Arc<MarkDebouncer>) -> Self {
        Self { redis, debouncer }
    }

    fn marker_key(address: &str) -> String {
        format!("miner:{address}:mode")
    }
}

#[async_trait]
impl SharedAcceptedShareSink for LiveModeMarkerSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        // Producer-stamped mode — no gate lookup on the consumer.
        let mode = share.mode;
        let mode_str = mode.as_str();

        let Ok(address) = AddressId::new(share.address.to_string()) else {
            return;
        };
        if !self.debouncer.try_acquire(&address, mode) {
            return;
        }

        let key = Self::marker_key(share.address);
        let mut conn = self.redis.clone();
        if let Err(err) = conn
            .set_ex::<_, _, ()>(&key, mode_str, MARKER_TTL_SECONDS)
            .await
        {
            warn!(
                %err,
                address = share.address,
                mode = mode_str,
                "LiveModeMarkerSink: SET EX failed (marker not refreshed; \
                 /api/pplns/mode falls back to state-based derivation)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_share_hook::{MiningMode, SharedAcceptedShare};

    const REDIS_DEFAULT_URL: &str = "redis://127.0.0.1:16379";

    async fn connect_or_skip() -> Option<ConnectionManager> {
        let url = std::env::var("BP_REDIS_URL").unwrap_or_else(|_| REDIS_DEFAULT_URL.to_string());
        let client = redis::Client::open(url).ok()?;
        let mgr_fut = ConnectionManager::new(client);
        match tokio::time::timeout(std::time::Duration::from_secs(2), mgr_fut).await {
            Ok(Ok(mgr)) => Some(mgr),
            _ => None,
        }
    }

    fn share<'a>(
        address: &'a str,
        worker: &'a str,
        session_id: &'a str,
        mode: MiningMode,
    ) -> SharedAcceptedShare<'a> {
        SharedAcceptedShare {
            address,
            worker,
            session_id,
            effective_difficulty: 1000.0,
            submission_difficulty: 1000.0,
            user_agent: None,
            is_block_candidate: false,
            hash_rate: 0.0,
            channel_count: 1,
            ts_ms: 0,
            share_id: "",
            mode,
            group_id: None,
        }
    }

    #[tokio::test]
    async fn writes_marker_with_ttl_after_accepted_share() {
        let Some(mut redis) = connect_or_skip().await else {
            return;
        };

        let address = "test_livemarker_addr_a";

        let sink = LiveModeMarkerSink::new(redis.clone(), Arc::new(MarkDebouncer::new()));

        // Cleanup leftover key from a prior failed run.
        let _: () = redis::cmd("DEL")
            .arg(format!("miner:{address}:mode"))
            .query_async(&mut redis)
            .await
            .unwrap_or(());

        sink.record_accepted(share(address, "wkr", "sessL01", MiningMode::Pplns))
            .await;

        let raw: Option<String> = redis
            .get(format!("miner:{address}:mode"))
            .await
            .expect("redis get");
        assert_eq!(raw.as_deref(), Some("pplns"));

        let ttl: i64 = redis::cmd("TTL")
            .arg(format!("miner:{address}:mode"))
            .query_async(&mut redis)
            .await
            .expect("redis ttl");
        assert!(
            ttl > 0 && ttl as u64 <= MARKER_TTL_SECONDS,
            "TTL must be in (0, MARKER_TTL_SECONDS] but was {ttl}"
        );

        // Cleanup.
        let _: () = redis::cmd("DEL")
            .arg(format!("miner:{address}:mode"))
            .query_async(&mut redis)
            .await
            .unwrap_or(());
    }

    #[tokio::test]
    async fn mode_change_overrides_debounce() {
        let Some(mut redis) = connect_or_skip().await else {
            return;
        };

        let address = "test_livemarker_addr_b";

        let sink = LiveModeMarkerSink::new(redis.clone(), Arc::new(MarkDebouncer::new()));

        let _: () = redis::cmd("DEL")
            .arg(format!("miner:{address}:mode"))
            .query_async(&mut redis)
            .await
            .unwrap_or(());

        // First share — writes "pplns".
        sink.record_accepted(share(address, "wkr", "sessL02", MiningMode::Pplns))
            .await;
        let v1: Option<String> = redis
            .get(format!("miner:{address}:mode"))
            .await
            .expect("get v1");
        assert_eq!(v1.as_deref(), Some("pplns"));

        // Same mode immediately — debounced, value stays "pplns".
        sink.record_accepted(share(address, "wkr", "sessL02", MiningMode::Pplns))
            .await;
        let v2: Option<String> = redis
            .get(format!("miner:{address}:mode"))
            .await
            .expect("get v2");
        assert_eq!(v2.as_deref(), Some("pplns"));

        // Mode change — must always write.
        sink.record_accepted(share(address, "wkr", "sessL02", MiningMode::Solo))
            .await;
        let v3: Option<String> = redis
            .get(format!("miner:{address}:mode"))
            .await
            .expect("get v3");
        assert_eq!(v3.as_deref(), Some("solo"));

        let _: () = redis::cmd("DEL")
            .arg(format!("miner:{address}:mode"))
            .query_async(&mut redis)
            .await
            .unwrap_or(());
    }
}
