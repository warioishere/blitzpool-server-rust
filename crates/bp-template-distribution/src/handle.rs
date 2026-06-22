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

/// Cheap-to-clone handle. Internally `Arc`-wraps the shared state and the
/// thread join-handle. Dropping the **last** clone cancels the worker and
/// joins the OS thread.
#[derive(Clone)]
pub struct TdpHandle {
    inner: Arc<Inner>,
}

struct Inner {
    templates_tx: broadcast::Sender<TemplateUpdate>,
    submit_tx: mpsc::Sender<TdpRequest>,
    cancel: CancellationToken,
    join: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Latest-known TDP state, refreshed by an internal tap task that
    /// subscribes to `templates_tx` before the worker is spawned.
    /// Consumers read it via [`TdpHandle::current_snapshot`] without
    /// having to manage their own broadcast subscription.
    snapshot: Arc<Mutex<TemplateSnapshot>>,
}

impl TdpHandle {
    /// Spawn the TDP worker on a dedicated OS thread. Returns once the
    /// worker has connected to bitcoin-core's IPC socket and sent the
    /// initial `CoinbaseOutputConstraints` — i.e. when it is ready to
    /// receive subscriptions.
    pub fn spawn(config: TdpConfig) -> Result<Self, TdpError> {
        let cancel = CancellationToken::new();
        let (submit_tx, submit_rx) = mpsc::channel::<TdpRequest>(config.submit_capacity);
        let (templates_tx, _) = broadcast::channel::<TemplateUpdate>(config.broadcast_capacity);

        // Snapshot tap — subscribe BEFORE spawning the worker so we don't
        // miss the startup NewTemplate+SetNewPrevHash pair (the same
        // race that `feedback-tdp-initial-template-drain` flagged for
        // regtests). The tap task lives on the multi-thread tokio
        // runtime, not the LocalSet, and exits when `templates_tx` is
        // dropped (i.e. when the worker thread terminates).
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
                            // Stamp freshness only on the two state-bearing
                            // variants — the RequestTransactionData responses
                            // are replies to our own calls, not core pushing
                            // new work, so they don't reset the staleness clock.
                            if matches!(
                                update,
                                TemplateUpdate::NewTemplate(_) | TemplateUpdate::SetNewPrevHash(_)
                            ) {
                                guard.last_update_at = Some(epoch_ms_now());
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Slow tap (process busy on shutdown) — ignore
                        // the missed update; the next NewTemplate /
                        // SetNewPrevHash will reset the relevant slot.
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

    /// Snapshot of the latest-known TDP state. Cheap clone — the
    /// internal lock is held only for the duration of the copy. Used
    /// by the `bp-api` `/info/block-template` + per-address
    /// `/client/:address/block-template` endpoints to render the
    /// current template without standing up a broadcast subscription.
    ///
    /// Returns the empty default ([`TemplateSnapshot::default`]) for
    /// the brief window between handle creation and the first TDP
    /// update from bitcoin-core; callers should treat `None` fields
    /// as "not ready yet" rather than an error.
    pub fn current_snapshot(&self) -> TemplateSnapshot {
        self.inner
            .snapshot
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Subscribe to outbound template updates. The returned `Receiver` is
    /// independent — each subscriber sees its own copy of every update from
    /// the moment it subscribed. Slow subscribers receive
    /// `broadcast::error::RecvError::Lagged` if they fall behind the
    /// configured capacity.
    pub fn subscribe(&self) -> broadcast::Receiver<TemplateUpdate> {
        self.inner.templates_tx.subscribe()
    }

    /// Send an inbound request to the worker. Returns
    /// `TdpError::WorkerChannelClosed` if the worker has already shut down.
    pub async fn submit(&self, req: TdpRequest) -> Result<(), TdpError> {
        self.inner
            .submit_tx
            .send(req)
            .await
            .map_err(|_| TdpError::WorkerChannelClosed)
    }

    /// Convenience: re-advertise coinbase output constraints to bitcoin-core.
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

    /// Convenience: request the full transaction list of a known template.
    /// The response arrives asynchronously over the `subscribe()` channel
    /// as a `TemplateUpdate::RequestTransactionDataSuccess` or `…Error`.
    pub async fn request_transaction_data(&self, template_id: u64) -> Result<(), TdpError> {
        self.submit(TdpRequest::RequestTransactionData { template_id })
            .await
    }

    /// Convenience: submit a found block solution to bitcoin-core.
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

    /// Explicitly cancel and join the worker thread. Equivalent to dropping
    /// the last `TdpHandle` clone, but lets the caller surface join errors
    /// and wait synchronously. Idempotent.
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

/// Epoch-ms now via the system clock. Used to stamp `last_update_at`
/// on the live snapshot; a clock skew before UNIX_EPOCH falls back to
/// 0 (treated as "very stale" by health, which is the safe direction).
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
