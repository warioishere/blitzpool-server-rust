// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-side tx cache for JDP `DeclareMiningJob` partition.
//!
//! When a Job-Declaration-Client (JDC) sends a `DeclareMiningJob`, the
//! pool partitions the JDC's `wtxid_list` against its own template-tx
//! set (see [`crate::partition_against_template`]) — wtxids the pool
//! already knows are resolved locally, the missing ones are requested
//! via `ProvideMissingTransactions`.
//!
//! Without a local cache the partition map is empty and the JDC ends up
//! sending ALL raw tx bytes (~1–2 MB per declaration). With a cache
//! warmed from the TDP `RequestTransactionData` round-trip, the typical
//! `ProvideMissingTransactions` payload drops to <100 KB — only the
//! handful of txs the JDC has that the pool doesn't.
//!
//! ## Design
//!
//! - One [`TemplateTxCache`] per pool process. Cheap to clone (Arc).
//! - Internally a FIFO of the last `N` template_ids (default 3). Old
//!   entries fall out as new ones arrive — covers
//!   `prev_hash`/template-rolling without unbounded memory growth.
//! - Per template_id: a `HashMap<wtxid → raw_witness_tx_bytes>`. The
//!   wtxid is `sha256d(raw_witness_serialised_bytes)` — matches the
//!   key shape `partition_against_template` looks up.
//! - A background task subscribes to [`crate::TdpHandle::subscribe`]
//!   and, on each `NewTemplate`, fires
//!   [`crate::TdpHandle::request_transaction_data`] for that
//!   `template_id`. The corresponding
//!   `RequestTransactionDataSuccess` arrives over the same broadcast
//!   stream and populates the cache.
//!
//! ## Co-Pattern: subscribe-before-spawn
//!
//! [`TemplateTxCache::spawn`] calls `tdp.subscribe()` SYNCHRONOUSLY
//! before returning, so the broadcast receiver is registered before
//! the cache returns control to the caller. Without this, a
//! `tokio::spawn` of the loop could miss the first `NewTemplate` that
//! the TDP worker emits between handle-attach and task-poll. Mirrors
//! the same race fixed for SV1/SV2 regtests
//! (`memory/feedback-tdp-initial-template-drain.md`).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use bp_share::sha256d;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::handle::TdpHandle;
use crate::message::{NewTemplate, RequestTransactionDataSuccess, TemplateUpdate};

/// Default FIFO depth — enough headroom for one stale + one current +
/// one in-flight template, which covers the common case of bitcoin-core
/// emitting a `NewTemplate` while a JDC is mid-roundtrip on the previous.
pub const DEFAULT_TEMPLATE_FIFO: usize = 3;

#[derive(Clone)]
pub struct TemplateTxCache {
    inner: Arc<Mutex<TxCacheInner>>,
}

struct TxCacheInner {
    /// Newest template at the back; oldest at the front.
    entries: VecDeque<TemplateEntry>,
    capacity: usize,
}

struct TemplateEntry {
    template_id: u64,
    txs: HashMap<[u8; 32], Vec<u8>>,
}

impl TxCacheInner {
    fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
        }
    }

    fn record(&mut self, template_id: u64, raw_txs: Vec<Vec<u8>>) {
        // Replace in place if the same template_id is already cached.
        // bitcoin-core can re-issue `RequestTransactionDataSuccess`
        // (e.g. the JDC's request races with a NewTemplate broadcast)
        // and we want the second response to overwrite, not duplicate.
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|e| e.template_id == template_id)
        {
            slot.txs = build_wtxid_map(raw_txs);
            return;
        }
        self.entries.push_back(TemplateEntry {
            template_id,
            txs: build_wtxid_map(raw_txs),
        });
        while self.entries.len() > self.capacity {
            self.entries.pop_front();
        }
    }

    fn current(&self) -> Option<HashMap<[u8; 32], Vec<u8>>> {
        self.entries.back().map(|e| e.txs.clone())
    }

    fn get_by_wtxid(&self, wtxid: &[u8; 32]) -> Option<Vec<u8>> {
        for entry in self.entries.iter().rev() {
            if let Some(b) = entry.txs.get(wtxid) {
                return Some(b.clone());
            }
        }
        None
    }
}

fn build_wtxid_map(raw_txs: Vec<Vec<u8>>) -> HashMap<[u8; 32], Vec<u8>> {
    let mut out = HashMap::with_capacity(raw_txs.len());
    for raw in raw_txs {
        out.insert(sha256d(&raw), raw);
    }
    out
}

impl TemplateTxCache {
    /// Spawn the cache against a live [`TdpHandle`]. Uses
    /// [`DEFAULT_TEMPLATE_FIFO`] as the FIFO depth. Must be called
    /// inside a tokio runtime — the cache spawns a background task on
    /// the current runtime.
    pub fn spawn(tdp: &TdpHandle) -> Self {
        Self::spawn_with_capacity(tdp, DEFAULT_TEMPLATE_FIFO)
    }

    /// Spawn with an explicit FIFO depth. `capacity` is clamped to at
    /// least 1.
    pub fn spawn_with_capacity(tdp: &TdpHandle, capacity: usize) -> Self {
        // Subscribe SYNCHRONOUSLY before tokio::spawn so the loop's
        // receiver registers before the worker has a chance to emit a
        // dropped NewTemplate.
        let rx = tdp.subscribe();
        let inner = Arc::new(Mutex::new(TxCacheInner::new(capacity)));
        let tdp_clone = tdp.clone();
        let inner_clone = Arc::clone(&inner);
        tokio::spawn(run_cache_loop(rx, tdp_clone, inner_clone));
        Self { inner }
    }

    /// Snapshot of the **newest** cached template's `wtxid → raw_tx`
    /// map. Cloned out of the lock — callers can mutate freely.
    /// Returns `None` if no template has been cached yet (initial
    /// boot window).
    pub fn current_template_txs(&self) -> Option<HashMap<[u8; 32], Vec<u8>>> {
        self.inner.lock().ok()?.current()
    }

    /// Search all cached templates (newest first) for the given wtxid.
    pub fn get_tx_by_wtxid(&self, wtxid: &[u8; 32]) -> Option<Vec<u8>> {
        self.inner.lock().ok()?.get_by_wtxid(wtxid)
    }

    #[cfg(test)]
    fn empty(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TxCacheInner::new(capacity))),
        }
    }

    #[cfg(test)]
    fn record_response(&self, template_id: u64, raw_txs: Vec<Vec<u8>>) {
        if let Ok(mut g) = self.inner.lock() {
            g.record(template_id, raw_txs);
        }
    }
}

async fn run_cache_loop(
    mut rx: broadcast::Receiver<TemplateUpdate>,
    tdp: TdpHandle,
    inner: Arc<Mutex<TxCacheInner>>,
) {
    loop {
        match rx.recv().await {
            Ok(TemplateUpdate::NewTemplate(NewTemplate { template_id, .. })) => {
                if let Err(err) = tdp.request_transaction_data(template_id).await {
                    warn!(
                        ?err,
                        template_id, "tx_cache: request_transaction_data failed"
                    );
                }
            }
            Ok(TemplateUpdate::RequestTransactionDataSuccess(RequestTransactionDataSuccess {
                template_id,
                transaction_list,
                ..
            })) => {
                let tx_count = transaction_list.len();
                if let Ok(mut g) = inner.lock() {
                    g.record(template_id, transaction_list);
                }
                debug!(template_id, tx_count, "tx_cache: stored template-tx set");
            }
            Ok(_) => {
                // SetNewPrevHash + RequestTransactionDataError — cache
                // doesn't react. Templates remain valid until they age
                // out of the FIFO.
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(skipped, "tx_cache: broadcast lagged; some updates missed");
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_tx(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn empty_cache_returns_none() {
        let cache = TemplateTxCache::empty(3);
        assert!(cache.current_template_txs().is_none());
        assert!(cache.get_tx_by_wtxid(&[0u8; 32]).is_none());
    }

    #[test]
    fn record_indexes_by_wtxid_and_returns_current() {
        let cache = TemplateTxCache::empty(3);
        let tx_a = raw_tx(0xaa);
        let tx_b = raw_tx(0xbb);
        let wtxid_a = sha256d(&tx_a);
        let wtxid_b = sha256d(&tx_b);

        cache.record_response(1, vec![tx_a.clone(), tx_b.clone()]);

        let current = cache.current_template_txs().expect("populated");
        assert_eq!(current.len(), 2);
        assert_eq!(current.get(&wtxid_a), Some(&tx_a));
        assert_eq!(current.get(&wtxid_b), Some(&tx_b));
    }

    #[test]
    fn fifo_evicts_oldest_template_beyond_capacity() {
        let cache = TemplateTxCache::empty(3);
        let tx_id1 = raw_tx(1);
        let tx_id2 = raw_tx(2);
        let tx_id3 = raw_tx(3);
        let tx_id4 = raw_tx(4);
        let wtxid_id1 = sha256d(&tx_id1);
        let wtxid_id4 = sha256d(&tx_id4);

        cache.record_response(1, vec![tx_id1.clone()]);
        cache.record_response(2, vec![tx_id2]);
        cache.record_response(3, vec![tx_id3]);
        // Cache full at capacity=3; recording id=4 evicts id=1.
        cache.record_response(4, vec![tx_id4.clone()]);

        // current() = newest template (id=4) only.
        let current = cache.current_template_txs().expect("populated");
        assert_eq!(current.len(), 1);
        assert!(current.contains_key(&wtxid_id4));

        // Oldest template's wtxid no longer reachable; newest still is.
        assert!(cache.get_tx_by_wtxid(&wtxid_id1).is_none());
        assert_eq!(cache.get_tx_by_wtxid(&wtxid_id4), Some(tx_id4));
    }

    #[test]
    fn get_by_wtxid_searches_all_cached_templates() {
        let cache = TemplateTxCache::empty(3);
        let stale = raw_tx(0xee);
        let current = raw_tx(0xcc);
        let wtxid_stale = sha256d(&stale);
        let wtxid_current = sha256d(&current);

        cache.record_response(10, vec![stale.clone()]);
        cache.record_response(11, vec![current.clone()]);

        // newest first via current() — gives template 11 only.
        let top = cache.current_template_txs().unwrap();
        assert!(top.contains_key(&wtxid_current));
        assert!(!top.contains_key(&wtxid_stale));

        // But get_tx_by_wtxid spans the full FIFO.
        assert_eq!(cache.get_tx_by_wtxid(&wtxid_stale), Some(stale));
        assert_eq!(cache.get_tx_by_wtxid(&wtxid_current), Some(current));
    }

    #[test]
    fn record_replaces_in_place_for_same_template_id() {
        let cache = TemplateTxCache::empty(3);
        let v1 = raw_tx(1);
        let v2_a = raw_tx(2);
        let v2_b = raw_tx(3);
        let wtxid_v1 = sha256d(&v1);
        let wtxid_v2_a = sha256d(&v2_a);

        cache.record_response(7, vec![v1.clone()]);
        // Same template_id, fresh tx-set — must replace, not extend.
        cache.record_response(7, vec![v2_a.clone(), v2_b.clone()]);

        let current = cache.current_template_txs().unwrap();
        assert_eq!(current.len(), 2);
        assert!(current.contains_key(&wtxid_v2_a));
        // First payload's wtxid evicted by the replace.
        assert!(!current.contains_key(&wtxid_v1));
    }
}
