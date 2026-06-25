// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dedicated OS-thread that hosts `BitcoinCoreSv2JDP` inside a
//! `tokio::task::LocalSet`.
//!
//! Differences from the TDP worker:
//!
//! - JDP is purely request/response. There is **no outbound stream** from
//!   bitcoin-core to fan out — every reply rides back on the same
//!   `oneshot::Sender` that the caller embedded in the request.
//! - Only one bridge task is needed (inbound). It pulls `WorkerMsg` items
//!   from a `tokio::mpsc::Receiver`, converts them into the upstream
//!   `JdRequest`, and forwards via the `async_channel::Sender` the lib
//!   expects.
//! - `BitcoinCoreSv2JDP::new` itself takes a `tokio::oneshot::Sender<()>`
//!   it pings once it has finished bootstrapping its mempool mirror; we
//!   wait for that ping before signalling startup success to the caller.

use std::path::PathBuf;

use async_channel::Sender as AcSender;
use bitcoin_core_sv2::common::job_declaration_protocol::io::{
    JdRequest, JdResponse as UpstreamJdResponse,
};
use bitcoin_core_sv2::unix_capnp::v31x::job_declaration_protocol::BitcoinCoreSv2JDP;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::JdpConfig;
use crate::error::JdpError;
use crate::message::{DeclareMiningJobResult, PushSolutionRequest};

/// Internal message variant sent from `JdpHandle` to the worker.
pub(crate) enum WorkerMsg {
    Declare {
        version: bitcoin::block::Version,
        coinbase_tx: bitcoin::Transaction,
        wtxid_list: Vec<bitcoin::Wtxid>,
        missing_txs: Vec<bitcoin::Transaction>,
        response_tx: oneshot::Sender<DeclareMiningJobResult>,
    },
    Push {
        request: PushSolutionRequest,
        ack_tx: oneshot::Sender<Result<(), JdpError>>,
    },
}

pub(crate) fn spawn_worker(
    config: JdpConfig,
    cancel: CancellationToken,
    request_rx: mpsc::Receiver<WorkerMsg>,
) -> Result<std::thread::JoinHandle<()>, JdpError> {
    if !config.socket_path.exists() {
        return Err(JdpError::SocketPathNotFound(config.socket_path.clone()));
    }

    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);

    let join = std::thread::Builder::new()
        .name("bp-jdp-worker".into())
        .spawn(move || {
            run_thread(config, cancel, request_rx, ready_tx);
        })
        .map_err(|e| JdpError::WorkerSpawn(e.to_string()))?;

    match ready_rx.recv() {
        Ok(Ok(())) => Ok(join),
        Ok(Err(reason)) => Err(JdpError::WorkerStartup(reason)),
        Err(_) => Err(JdpError::WorkerStartup(
            "worker thread exited before signalling readiness".into(),
        )),
    }
}

fn run_thread(
    config: JdpConfig,
    cancel: CancellationToken,
    request_rx: mpsc::Receiver<WorkerMsg>,
    ready_tx: std::sync::mpsc::SyncSender<Result<(), String>>,
) {
    let socket_path: PathBuf = config.socket_path.clone();

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready_tx.send(Err(format!("tokio runtime build failed: {e}")));
            cancel.cancel();
            return;
        }
    };

    let local_set = tokio::task::LocalSet::new();

    local_set.block_on(&runtime, async move {
        // The async_channel carries upstream JdRequest payloads to the lib.
        let (into_jdp_tx, into_jdp_rx) = async_channel::unbounded::<JdRequest>();

        // Upstream lib pings us when its mempool bootstrap is complete.
        let (jdp_ready_tx, jdp_ready_rx) = oneshot::channel::<()>();

        // BitcoinCoreSv2JDP::new can block for a long time during IBD; we
        // surface that latency to the caller via the ready_tx signal it
        // sends once bootstrap is done.
        let new_fut =
            BitcoinCoreSv2JDP::new(&socket_path, into_jdp_rx, cancel.clone(), jdp_ready_tx);

        let jdp = match new_fut.await {
            Ok(jdp) => jdp,
            Err(e) => {
                let _ = ready_tx.send(Err(format!("BitcoinCoreSv2JDP::new failed: {e:?}")));
                cancel.cancel();
                return;
            }
        };

        // Wait for the upstream lib's own readiness ping. `new()` already
        // sends this internally before returning Ok, so the recv should
        // resolve immediately — but await it explicitly so the contract is
        // observable.
        if jdp_ready_rx.await.is_err() {
            let _ = ready_tx.send(Err("JDP readiness signal dropped".into()));
            cancel.cancel();
            return;
        }

        info!(
            socket = %socket_path.display(),
            "bp-jdp-worker connected to bitcoin-core IPC"
        );

        // Bridge: pool-side mpsc → upstream async_channel.
        let bridge_handle = {
            let cancel = cancel.clone();
            let into_jdp_tx = into_jdp_tx.clone();
            tokio::task::spawn_local(bridge_in(request_rx, into_jdp_tx, cancel))
        };

        let _ = ready_tx.send(Ok(()));

        // Run the JDP event loop. `run` takes &self, so no mut binding.
        jdp.run().await;

        cancel.cancel();
        let _ = bridge_handle.await;

        info!("bp-jdp-worker shut down cleanly");
    });
}

async fn bridge_in(
    mut request_rx: mpsc::Receiver<WorkerMsg>,
    into_jdp_tx: AcSender<JdRequest>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                debug!("bridge_in: cancellation triggered, exiting");
                return;
            }
            msg = request_rx.recv() => match msg {
                Some(WorkerMsg::Declare {
                    version,
                    coinbase_tx,
                    wtxid_list,
                    missing_txs,
                    response_tx,
                }) => {
                    // The upstream lib expects its own oneshot in the
                    // request payload; wrap our caller's oneshot in a
                    // mapping shim so the response is translated.
                    let (upstream_tx, upstream_rx) = oneshot::channel::<UpstreamJdResponse>();
                    let req = JdRequest::DeclareMiningJob {
                        version,
                        coinbase_tx,
                        wtxid_list,
                        missing_txs,
                        response_tx: upstream_tx,
                    };
                    if let Err(e) = into_jdp_tx.send(req).await {
                        warn!(error = %e, "bridge_in: JDP inbound channel closed");
                        return;
                    }
                    // Spawn-local so further requests aren't held up; the
                    // lib processes declarations sequentially anyway, but
                    // the response handoff is independent of next-request
                    // ingress.
                    let response_tx_fwd = response_tx;
                    tokio::task::spawn_local(async move {
                        match upstream_rx.await {
                            Ok(resp) => {
                                let _ = response_tx_fwd.send(resp.into());
                            }
                            Err(_) => {
                                debug!("bridge_in: upstream dropped DeclareMiningJob response");
                            }
                        }
                    });
                }
                Some(WorkerMsg::Push { request, ack_tx }) => {
                    match request.into_upstream() {
                        Ok(push_solution) => {
                            let req = JdRequest::PushSolution { push_solution };
                            if let Err(e) = into_jdp_tx.send(req).await {
                                warn!(error = %e, "bridge_in: JDP inbound channel closed");
                                let _ = ack_tx.send(Err(JdpError::WorkerChannelClosed));
                                return;
                            }
                            let _ = ack_tx.send(Ok(()));
                        }
                        Err(err) => {
                            error!(?err, "bridge_in: rejecting malformed PushSolution");
                            let _ = ack_tx.send(Err(err));
                        }
                    }
                }
                None => {
                    debug!("bridge_in: handle dropped, exiting");
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_rejects_missing_socket_path() {
        let cfg = JdpConfig::new("/definitely/does/not/exist/bp-jdp.sock");
        let cancel = CancellationToken::new();
        let (_req_tx, req_rx) = mpsc::channel::<WorkerMsg>(1);
        let err =
            spawn_worker(cfg, cancel, req_rx).expect_err("non-existent socket should fail fast");
        assert!(matches!(err, JdpError::SocketPathNotFound(_)));
    }
}
