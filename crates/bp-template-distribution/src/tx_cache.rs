// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-side tx cache for JDP `DeclareMiningJob` partition.
//!
//! When a Job-Declaration-Client (JDC) sends a `DeclareMiningJob`, the
//! pool partitions the JDC's `wtxid_list` against its own template-tx
//! set (see `crate::partition_against_template`) — wtxids the pool
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
//! - Holds the tx set of the **latest** `RequestTransactionDataSuccess`
//!   only; each response replaces the previous one. A JDC that declared
//!   against an older template simply finds fewer of its wtxids here and
//!   sends the rest via `ProvideMissingTransactions`.
//! - The set is a `HashMap<wtxid → raw_witness_tx_bytes>`. The wtxid is
//!   `sha256d(raw_witness_serialised_bytes)` — matches the key shape
//!   `partition_against_template` looks up.
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
//! the TDP worker emits between handle-attach and task-poll.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bp_share::sha256d;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::handle::TdpHandle;
use crate::message::{NewTemplate, RequestTransactionDataSuccess, TemplateUpdate};

/// `wtxid → raw_witness_tx` of one template.
type WtxidMap = HashMap<[u8; 32], Vec<u8>>;

#[derive(Clone)]
pub struct TemplateTxCache {
    /// The newest template's map; `None` until the first response arrives.
    latest: Arc<Mutex<Option<WtxidMap>>>,
}

fn build_wtxid_map(raw_txs: Vec<Vec<u8>>) -> WtxidMap {
    let mut out = HashMap::with_capacity(raw_txs.len());
    for raw in raw_txs {
        out.insert(sha256d(&raw), raw);
    }
    out
}

impl TemplateTxCache {
    /// Spawn the cache against a live [`TdpHandle`]. Must be called
    /// inside a tokio runtime — the cache spawns a background task on
    /// the current runtime.
    pub fn spawn(tdp: &TdpHandle) -> Self {
        // Subscribe SYNCHRONOUSLY before tokio::spawn so the loop's
        // receiver registers before the worker has a chance to emit a
        // dropped NewTemplate.
        let rx = tdp.subscribe();
        let cache = Self {
            latest: Arc::new(Mutex::new(None)),
        };
        tokio::spawn(run_cache_loop(rx, tdp.clone(), cache.clone()));
        cache
    }

    /// Snapshot of the newest cached template's `wtxid → raw_tx` map.
    /// Cloned out of the lock — callers can mutate freely.
    /// Returns `None` if no template has been cached yet (initial
    /// boot window).
    pub fn current_template_txs(&self) -> Option<WtxidMap> {
        self.latest.lock().ok()?.clone()
    }

    /// Replace the cached set with `raw_txs`.
    fn record(&self, raw_txs: Vec<Vec<u8>>) {
        let map = build_wtxid_map(raw_txs);
        if let Ok(mut g) = self.latest.lock() {
            *g = Some(map);
        }
    }

    #[cfg(test)]
    fn empty() -> Self {
        Self {
            latest: Arc::new(Mutex::new(None)),
        }
    }
}

async fn run_cache_loop(
    mut rx: broadcast::Receiver<TemplateUpdate>,
    tdp: TdpHandle,
    cache: TemplateTxCache,
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
                cache.record(transaction_list);
                debug!(template_id, tx_count, "tx_cache: stored template-tx set");
            }
            Ok(_) => {
                // SetNewPrevHash + RequestTransactionDataError — cache
                // doesn't react. The held set stays until the next
                // response replaces it.
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
        let cache = TemplateTxCache::empty();
        assert!(cache.current_template_txs().is_none());
    }

    #[test]
    fn record_indexes_by_wtxid_and_returns_current() {
        let cache = TemplateTxCache::empty();
        let tx_a = raw_tx(0xaa);
        let tx_b = raw_tx(0xbb);
        let wtxid_a = sha256d(&tx_a);
        let wtxid_b = sha256d(&tx_b);

        cache.record(vec![tx_a.clone(), tx_b.clone()]);

        let current = cache.current_template_txs().expect("populated");
        assert_eq!(current.len(), 2);
        assert_eq!(current.get(&wtxid_a), Some(&tx_a));
        assert_eq!(current.get(&wtxid_b), Some(&tx_b));
    }

    #[test]
    fn a_newer_response_replaces_the_held_set() {
        let cache = TemplateTxCache::empty();
        let old = raw_tx(1);
        let new_a = raw_tx(2);
        let new_b = raw_tx(3);

        cache.record(vec![old.clone()]);
        cache.record(vec![new_a.clone(), new_b]);

        // Only the newest set is visible; the older one's wtxid is gone.
        let current = cache.current_template_txs().unwrap();
        assert_eq!(current.len(), 2);
        assert!(current.contains_key(&sha256d(&new_a)));
        assert!(!current.contains_key(&sha256d(&old)));
    }
}
