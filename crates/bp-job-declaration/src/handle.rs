// SPDX-License-Identifier: AGPL-3.0-or-later

//! Public, `Send + Clone` handle for the JDP worker.

use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::config::JdpConfig;
use crate::error::JdpError;
use crate::message::{DeclareMiningJobResult, PushSolutionRequest};
use crate::worker::{spawn_worker, WorkerMsg};

#[derive(Clone)]
pub struct JdpHandle {
    inner: Arc<Inner>,
}

struct Inner {
    request_tx: mpsc::Sender<WorkerMsg>,
    cancel: CancellationToken,
    join: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl JdpHandle {
    /// Spawn the JDP worker on a dedicated OS thread. Returns once the
    /// worker has connected to bitcoin-core's IPC socket and finished
    /// bootstrapping its mempool mirror. During IBD this can take a
    /// long time — callers should treat the call as blocking I/O.
    pub fn spawn(config: JdpConfig) -> Result<Self, JdpError> {
        let cancel = CancellationToken::new();
        let (request_tx, request_rx) = mpsc::channel::<WorkerMsg>(config.request_capacity);
        let join = spawn_worker(config, cancel.clone(), request_rx)?;

        Ok(Self {
            inner: Arc::new(Inner {
                request_tx,
                cancel,
                join: Mutex::new(Some(join)),
            }),
        })
    }

    /// Ask bitcoin-core to validate a declared mining job. Resolves to
    /// the worker's response (`Success`, `Error`, or `MissingTransactions`).
    pub async fn declare_mining_job(
        &self,
        version: bitcoin::block::Version,
        coinbase_tx: bitcoin::Transaction,
        wtxid_list: Vec<bitcoin::Wtxid>,
        missing_txs: Vec<bitcoin::Transaction>,
    ) -> Result<DeclareMiningJobResult, JdpError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.inner
            .request_tx
            .send(WorkerMsg::Declare {
                version,
                coinbase_tx,
                wtxid_list,
                missing_txs,
                response_tx,
            })
            .await
            .map_err(|_| JdpError::WorkerChannelClosed)?;
        response_rx.await.map_err(|_| JdpError::ResponseDropped)
    }

    /// Submit a mining solution to bitcoin-core. Fire-and-forget at the
    /// JDP level — the `Ok(())` only indicates that the request was
    /// successfully enqueued, not that the block was accepted by the
    /// network. Subsequent chain-tip changes will surface block-find
    /// outcomes via the TDP path.
    pub async fn push_solution(&self, request: PushSolutionRequest) -> Result<(), JdpError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.inner
            .request_tx
            .send(WorkerMsg::Push { request, ack_tx })
            .await
            .map_err(|_| JdpError::WorkerChannelClosed)?;
        ack_rx
            .await
            .map_err(|_| JdpError::ResponseDropped)
            .and_then(|res| res)
    }

    /// Explicitly cancel and join the worker thread. Equivalent to dropping
    /// the last `JdpHandle` clone but lets the caller surface join errors.
    /// Idempotent.
    pub fn shutdown(&self) -> Result<(), JdpError> {
        self.inner.cancel.cancel();
        let mut guard = self
            .inner
            .join
            .lock()
            .expect("bp-jdp join-handle mutex poisoned");
        if let Some(handle) = guard.take() {
            handle
                .join()
                .map_err(|_| JdpError::WorkerStartup("worker thread panicked".into()))?;
            Ok(())
        } else {
            Err(JdpError::AlreadyShutDown)
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Ok(mut guard) = self.join.lock() {
            if let Some(handle) = guard.take() {
                if handle.join().is_err() {
                    warn!("bp-jdp worker thread panicked during shutdown");
                }
            }
        }
    }
}
