// SPDX-License-Identifier: AGPL-3.0-or-later

//! The newest template's transactions keyed by wtxid, so a JDP
//! `DeclareMiningJob` resolves known wtxids locally and only the rest travel
//! via `ProvideMissingTransactions`. Only the latest set is held: a JDC on an
//! older template just finds fewer of its wtxids here.

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
    /// Must be called inside a tokio runtime.
    pub fn spawn(tdp: &TdpHandle) -> Self {
        // Subscribe before spawning, or the first NewTemplate can be missed.
        let rx = tdp.subscribe();
        let cache = Self {
            latest: Arc::new(Mutex::new(None)),
        };
        tokio::spawn(run_cache_loop(rx, tdp.clone(), cache.clone()));
        cache
    }

    /// `None` until the first template's transactions have arrived.
    pub fn current_template_txs(&self) -> Option<WtxidMap> {
        self.latest.lock().ok()?.clone()
    }

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
                // The held set stays until the next response replaces it.
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

        let current = cache.current_template_txs().unwrap();
        assert_eq!(current.len(), 2);
        assert!(current.contains_key(&sha256d(&new_a)));
        assert!(!current.contains_key(&sha256d(&old)));
    }
}
