// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-process response cache with per-endpoint TTLs and explicit
//! invalidation on mutating routes. Values are pre-serialized JSON, so a hit
//! skips both the DB query and the serialization.

use std::sync::Arc;
use std::time::Duration;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bp_config::ApiCacheConfig;
use bytes::Bytes;
use moka::future::Cache;
use serde::Serialize;

/// Wrapped moka cache + the per-endpoint TTL table. Each value carries its
/// own TTL, which `EntryTtl` hands to moka.
#[derive(Clone)]
pub struct ResponseCache {
    inner: Cache<String, (Bytes, Duration)>,
    ttls: Arc<ApiCacheConfig>,
}

struct EntryTtl;

impl moka::Expiry<String, (Bytes, Duration)> for EntryTtl {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &(Bytes, Duration),
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        Some(value.1)
    }
}

/// Identifies which configured TTL applies to a cache write.
#[derive(Copy, Clone, Debug)]
pub enum TtlKind {
    SiteInfo,
    PoolInfo,
    CoreInfo,
    PeerInfo,
    Chart,
    Shares,
    Workers,
    Accepted,
    Rejected,
    ClientBlockTemplate,
    ClientInfo,
    ClientChart,
    ClientWorkerShares,
    ClientWorkers,
    ClientAccepted,
    ClientRejected,
    ClientDiffScores,
    ClientWorkerGroup,
    ClientWorkerSession,

    PplnsRoot,
    PplnsMode,
    PplnsStatus,
    PplnsFees,
    PplnsDistribution,
    PplnsChart,
    PplnsLedger,
    PplnsAddress,
    PplnsAddressHistory,

    GroupPublicList,
    GroupByAddress,
    GroupDetail,
    GroupPublicDetail,
    GroupHashrate,
    GroupChart,
    GroupAccepted,
    GroupRejected,
    GroupDistribution,
    GroupBestDifficulty,
    GroupHistory,
    GroupInvitations,
    GroupJoinRequests,
}

impl ResponseCache {
    pub fn new(cfg: ApiCacheConfig) -> Self {
        // `support_invalidation_closures` is required for the predicate-
        // based bulk eviction `invalidate_prefix` does on POST mutations.
        let inner = Cache::builder()
            .max_capacity(cfg.max_entries)
            .support_invalidation_closures()
            .expire_after(EntryTtl)
            .build();
        Self {
            inner,
            ttls: Arc::new(cfg),
        }
    }

    fn ttl_secs(&self, kind: TtlKind) -> u64 {
        match kind {
            TtlKind::SiteInfo => self.ttls.site_info_secs,
            TtlKind::PoolInfo => self.ttls.pool_info_secs,
            TtlKind::CoreInfo => self.ttls.core_info_secs,
            TtlKind::PeerInfo => self.ttls.peer_info_secs,
            TtlKind::Chart => self.ttls.chart_secs,
            TtlKind::Shares => self.ttls.shares_secs,
            TtlKind::Workers => self.ttls.workers_secs,
            TtlKind::Accepted => self.ttls.accepted_secs,
            TtlKind::Rejected => self.ttls.rejected_secs,
            TtlKind::ClientBlockTemplate => self.ttls.client_block_template_secs,
            TtlKind::ClientInfo => self.ttls.client_info_secs,
            TtlKind::ClientChart => self.ttls.client_chart_secs,
            TtlKind::ClientWorkerShares => self.ttls.client_worker_shares_secs,
            TtlKind::ClientWorkers => self.ttls.client_workers_secs,
            TtlKind::ClientAccepted => self.ttls.client_accepted_secs,
            TtlKind::ClientRejected => self.ttls.client_rejected_secs,
            TtlKind::ClientDiffScores => self.ttls.client_diff_scores_secs,
            TtlKind::ClientWorkerGroup => self.ttls.client_worker_group_secs,
            TtlKind::ClientWorkerSession => self.ttls.client_worker_session_secs,

            TtlKind::PplnsRoot => self.ttls.pplns_root_secs,
            TtlKind::PplnsMode => self.ttls.pplns_mode_secs,
            TtlKind::PplnsStatus => self.ttls.pplns_status_secs,
            TtlKind::PplnsFees => self.ttls.pplns_fees_secs,
            TtlKind::PplnsDistribution => self.ttls.pplns_distribution_secs,
            TtlKind::PplnsChart => self.ttls.pplns_chart_secs,
            TtlKind::PplnsLedger => self.ttls.pplns_ledger_secs,
            TtlKind::PplnsAddress => self.ttls.pplns_address_secs,
            TtlKind::PplnsAddressHistory => self.ttls.pplns_address_history_secs,

            TtlKind::GroupPublicList => self.ttls.group_public_list_secs,
            TtlKind::GroupByAddress => self.ttls.group_by_address_secs,
            TtlKind::GroupDetail => self.ttls.group_detail_secs,
            TtlKind::GroupPublicDetail => self.ttls.group_public_detail_secs,
            TtlKind::GroupHashrate => self.ttls.group_hashrate_secs,
            TtlKind::GroupChart => self.ttls.group_chart_secs,
            TtlKind::GroupAccepted => self.ttls.group_accepted_secs,
            TtlKind::GroupRejected => self.ttls.group_rejected_secs,
            TtlKind::GroupDistribution => self.ttls.group_distribution_secs,
            TtlKind::GroupBestDifficulty => self.ttls.group_best_difficulty_secs,
            TtlKind::GroupHistory => self.ttls.group_history_secs,
            TtlKind::GroupInvitations => self.ttls.group_invitations_secs,
            TtlKind::GroupJoinRequests => self.ttls.group_join_requests_secs,
        }
    }

    /// Look up `key`; on miss, run `compute`, serialize the result,
    /// store it with the TTL for `kind`, and return the bytes.
    /// A `0`-TTL disables caching for that endpoint — `compute`
    /// runs every call and the result is returned without insertion.
    pub async fn get_or_fetch<T, F, E>(
        &self,
        key: String,
        kind: TtlKind,
        compute: F,
    ) -> Result<Bytes, E>
    where
        T: Serialize,
        F: std::future::Future<Output = Result<T, E>>,
    {
        self.get_or_fetch_secs(key, self.ttl_secs(kind), compute)
            .await
    }

    /// Like [`Self::get_or_fetch`] with an explicit TTL in seconds, for TTLs
    /// that vary at runtime.
    pub async fn get_or_fetch_secs<T, F, E>(
        &self,
        key: String,
        ttl_secs: u64,
        compute: F,
    ) -> Result<Bytes, E>
    where
        T: Serialize,
        F: std::future::Future<Output = Result<T, E>>,
    {
        if let Some((hit, _)) = self.inner.get(&key).await {
            return Ok(hit);
        }
        let value = compute.await?;
        let bytes = Bytes::from(serde_json::to_vec(&value).expect("serialize cached value"));
        if ttl_secs > 0 {
            let ttl = Duration::from_secs(ttl_secs);
            self.inner.insert(key, (bytes.clone(), ttl)).await;
        }
        Ok(bytes)
    }

    /// Drop a single cached entry.
    pub async fn invalidate(&self, key: &str) {
        self.inner.invalidate(key).await;
    }

    /// Drop every cached entry whose key starts with `prefix`.
    pub async fn invalidate_prefix(&self, prefix: &str) {
        let prefix = prefix.to_string();
        self.inner
            .invalidate_entries_if(move |k, _| k.starts_with(&prefix))
            .expect("predicate-invalidation enabled");
    }
}

/// Axum responder that ships cached JSON bytes with the right
/// `Content-Type`. Handlers return `Ok(JsonBytes(bytes))`.
pub struct JsonBytes(pub Bytes);

impl IntoResponse for JsonBytes {
    fn into_response(self) -> Response {
        let mut resp = (StatusCode::OK, self.0).into_response();
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn cfg(ttl: u64) -> ApiCacheConfig {
        ApiCacheConfig {
            site_info_secs: ttl,
            max_entries: 16,
            ..ApiCacheConfig::default()
        }
    }

    #[tokio::test]
    async fn caches_on_second_call() {
        let cache = ResponseCache::new(cfg(60));
        let hits = AtomicUsize::new(0);
        let key = "K".to_string();
        let _ = cache
            .get_or_fetch::<_, _, ()>(key.clone(), TtlKind::SiteInfo, async {
                hits.fetch_add(1, Ordering::SeqCst);
                Ok(42_u64)
            })
            .await
            .unwrap();
        let _ = cache
            .get_or_fetch::<_, _, ()>(key, TtlKind::SiteInfo, async {
                hits.fetch_add(1, Ordering::SeqCst);
                Ok(99_u64)
            })
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn zero_ttl_disables_cache() {
        let cache = ResponseCache::new(cfg(0));
        let hits = AtomicUsize::new(0);
        for _ in 0..3 {
            let _ = cache
                .get_or_fetch::<_, _, ()>("K".to_string(), TtlKind::SiteInfo, async {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Ok(1_u64)
                })
                .await
                .unwrap();
        }
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    /// An entry lives for its own TTL: neither an earlier entry under the same
    /// key shortens it, nor does it outlive its TTL.
    #[tokio::test]
    async fn an_entry_lives_for_its_own_ttl() {
        let cache = ResponseCache::new(cfg(60));
        let fetch = |ttl: u64, v: u64| {
            cache.get_or_fetch_secs::<_, _, ()>("K".to_string(), ttl, async move { Ok(v) })
        };
        fetch(1, 1).await.unwrap();
        cache.invalidate("K").await;
        fetch(60, 2).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert_eq!(
            &fetch(60, 3).await.unwrap()[..],
            b"2",
            "the 60 s entry was cut short"
        );

        cache.invalidate("K").await;
        fetch(1, 5).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert_eq!(
            &fetch(1, 6).await.unwrap()[..],
            b"6",
            "a 1 s entry outlived its TTL"
        );
    }

    #[tokio::test]
    async fn invalidate_prefix_drops_matching() {
        let cache = ResponseCache::new(cfg(60));
        for k in ["CLIENT_INFO_a", "CLIENT_INFO_b", "OTHER_a"] {
            let _ = cache
                .get_or_fetch::<_, _, ()>(k.to_string(), TtlKind::SiteInfo, async { Ok(1_u64) })
                .await
                .unwrap();
        }
        cache.invalidate_prefix("CLIENT_INFO_").await;
        // moka's predicate-invalidate is async — wait one tick.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        cache.inner.run_pending_tasks().await;
        assert!(cache.inner.get("CLIENT_INFO_a").await.is_none());
        assert!(cache.inner.get("CLIENT_INFO_b").await.is_none());
        assert!(cache.inner.get("OTHER_a").await.is_some());
    }
}
