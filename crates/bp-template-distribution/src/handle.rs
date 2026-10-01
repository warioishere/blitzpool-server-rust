// SPDX-License-Identifier: AGPL-3.0-or-later

//! Public, `Send + Clone` handle for the TDP worker.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::config::TdpConfig;
use crate::error::TdpError;
use crate::message::{apply_to_snapshot, TdpRequest, TemplateSnapshot, TemplateUpdate};
use crate::worker::spawn_worker;

/// Dropping the last clone cancels the worker and joins its OS thread.
#[derive(Clone)]
pub struct TdpHandle {
    inner: Arc<Inner>,
}

struct Inner {
    templates_tx: broadcast::Sender<TemplateUpdate>,
    submit_tx: mpsc::Sender<TdpRequest>,
    cancel: CancellationToken,
    join: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Latest-known TDP state, kept current by an internal tap task.
    snapshot: Arc<Mutex<TemplateSnapshot>>,
}

impl TdpHandle {
    /// Returns once the worker has connected to bitcoin-core's IPC socket and
    /// sent the initial `CoinbaseOutputConstraints`.
    pub fn spawn(config: TdpConfig) -> Result<Self, TdpError> {
        let cancel = CancellationToken::new();
        let (submit_tx, submit_rx) = mpsc::channel::<TdpRequest>(config.submit_capacity);
        let (templates_tx, _) = broadcast::channel::<TemplateUpdate>(config.broadcast_capacity);

        // Subscribe before spawning the worker: broadcast does not replay the
        // startup NewTemplate + SetNewPrevHash pair.
        let snapshot: Arc<Mutex<TemplateSnapshot>> =
            Arc::new(Mutex::new(TemplateSnapshot::default()));
        let mut snapshot_rx = templates_tx.subscribe();
        let snapshot_handle = Arc::clone(&snapshot);
        tokio::spawn(async move {
            loop {
                match snapshot_rx.recv().await {
                    Ok(update) => {
                        if let Ok(mut guard) = snapshot_handle.lock() {
                            apply_to_snapshot(&mut guard, &update);
                            // RequestTransactionData replies answer the pool's own
                            // calls, not new work, so they don't reset staleness.
                            if matches!(
                                update,
                                TemplateUpdate::NewTemplate(_) | TemplateUpdate::SetNewPrevHash(_)
                            ) {
                                guard.last_update_at = Some(epoch_ms_now());
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // The next NewTemplate / SetNewPrevHash resets the slot.
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        let join = spawn_worker(config, cancel.clone(), submit_rx, templates_tx.clone())?;

        Ok(Self {
            inner: Arc::new(Inner {
                templates_tx,
                submit_tx,
                cancel,
                join: Mutex::new(Some(join)),
                snapshot,
            }),
        })
    }

    /// Latest-known TDP state. Empty until bitcoin-core's first update, so
    /// callers treat `None` fields as "not ready yet", not as an error.
    pub fn current_snapshot(&self) -> TemplateSnapshot {
        self.inner
            .snapshot
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Each subscriber sees every update from the moment it subscribed; one
    /// that falls behind the configured capacity gets `RecvError::Lagged`.
    pub fn subscribe(&self) -> broadcast::Receiver<TemplateUpdate> {
        self.inner.templates_tx.subscribe()
    }

    pub async fn submit(&self, req: TdpRequest) -> Result<(), TdpError> {
        self.inner
            .submit_tx
            .send(req)
            .await
            .map_err(|_| TdpError::WorkerChannelClosed)
    }

    pub async fn set_coinbase_constraints(
        &self,
        max_additional_size: u32,
        max_additional_sigops: u16,
    ) -> Result<(), TdpError> {
        self.submit(TdpRequest::SetCoinbaseConstraints {
            max_additional_size,
            max_additional_sigops,
        })
        .await
    }

    /// The response arrives over `subscribe()`, not as a return value.
    pub async fn request_transaction_data(&self, template_id: u64) -> Result<(), TdpError> {
        self.submit(TdpRequest::RequestTransactionData { template_id })
            .await
    }

    pub async fn submit_solution(
        &self,
        template_id: u64,
        version: u32,
        header_timestamp: u32,
        header_nonce: u32,
        coinbase_tx: Vec<u8>,
    ) -> Result<(), TdpError> {
        self.submit(TdpRequest::SubmitSolution {
            template_id,
            version,
            header_timestamp,
            header_nonce,
            coinbase_tx,
        })
        .await
    }

    /// Like dropping the last clone, but surfaces join errors to the caller.
    pub fn shutdown(&self) -> Result<(), TdpError> {
        self.inner.cancel.cancel();
        let mut guard = self
            .inner
            .join
            .lock()
            .expect("bp-tdp join-handle mutex poisoned");
        if let Some(handle) = guard.take() {
            handle
                .join()
                .map_err(|_| TdpError::WorkerStartup("worker thread panicked".into()))?;
            Ok(())
        } else {
            Err(TdpError::AlreadyShutDown)
        }
    }
}

/// A clock before UNIX_EPOCH yields 0, which health reads as stale: the safe side.
fn epoch_ms_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Ok(mut guard) = self.join.lock() {
            if let Some(handle) = guard.take() {
                if handle.join().is_err() {
                    warn!("bp-tdp worker thread panicked during shutdown");
                }
            }
        }
    }
}
