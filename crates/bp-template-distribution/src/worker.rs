// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dedicated OS-thread that hosts `BitcoinCoreSv2TDP` inside a
//! `tokio::task::LocalSet` (required because the upstream type is `!Send`).
//!
//! The thread owns three pieces:
//!
//! 1. The `BitcoinCoreSv2TDP` instance itself (running its event loop).
//! 2. A **bridge_in** task that consumes a `tokio::mpsc::Receiver<TdpRequest>`
//!    coming from pool code and forwards translated `TemplateDistribution`
//!    payloads into the TDP via `async_channel::Sender`.
//! 3. A **bridge_out** task that drains the TDP's outbound
//!    `async_channel::Receiver<TemplateDistribution>` and re-broadcasts
//!    each payload as `TemplateUpdate` over a `tokio::broadcast::Sender`.
//!
//! Cancellation: a single `CancellationToken` is observed by both the TDP
//! and both bridge tasks. Dropping the public `TdpHandle` triggers cancel,
//! which makes `BitcoinCoreSv2TDP::run` return; we then join the thread.

use std::path::PathBuf;

use async_channel::{Receiver as AcReceiver, Sender as AcSender};
use bitcoin_core_sv2::unix_capnp::v31x::template_distribution_protocol::BitcoinCoreSv2TDP;
use stratum_core::{
    parsers_sv2::TemplateDistribution,
    template_distribution_sv2::{
        CoinbaseOutputConstraints, RequestTransactionData, SubmitSolution,
    },
};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::{TdpCoinbaseConstraints, TdpConfig};
use crate::error::TdpError;
use crate::message::{TdpRequest, TemplateUpdate};

/// Spawns the dedicated TDP thread. Returns once the TDP's `new()` call has
/// completed (success or failure). The thread itself keeps running until
/// the cancellation token fires.
pub(crate) fn spawn_worker(
    config: TdpConfig,
    cancel: CancellationToken,
    submit_rx: mpsc::Receiver<TdpRequest>,
    templates_tx: broadcast::Sender<TemplateUpdate>,
) -> Result<std::thread::JoinHandle<()>, TdpError> {
    if !config.socket_path.exists() {
        return Err(TdpError::SocketPathNotFound(config.socket_path.clone()));
    }

    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);

    let join = std::thread::Builder::new()
        .name("bp-tdp-worker".into())
        .spawn(move || {
            run_thread(config, cancel, submit_rx, templates_tx, ready_tx);
        })
        .map_err(|e| TdpError::WorkerSpawn(e.to_string()))?;

    match ready_rx.recv() {
        Ok(Ok(())) => Ok(join),
        Ok(Err(reason)) => Err(TdpError::WorkerStartup(reason)),
        Err(_) => Err(TdpError::WorkerStartup(
            "worker thread exited before signalling readiness".into(),
        )),
    }
}

fn run_thread(
    config: TdpConfig,
    cancel: CancellationToken,
    submit_rx: mpsc::Receiver<TdpRequest>,
    templates_tx: broadcast::Sender<TemplateUpdate>,
    ready_tx: std::sync::mpsc::SyncSender<Result<(), String>>,
) {
    let socket_path: PathBuf = config.socket_path.clone();
    let coinbase_constraints = config.coinbase_constraints;
    let fee_threshold = config.fee_threshold;
    let min_interval = config.min_interval_secs;
    let reconnect_backoff = config.reconnect_backoff;

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
        // `submit_rx` (the pool→TDP request channel) must survive across
        // reconnects, so each connection iteration borrows it via
        // `bridge_in` and hands it back on exit. `templates_tx` (the
        // TDP→pool broadcast) is cheaply cloned per iteration.
        let mut submit_rx = submit_rx;
        // `ready_tx` is a one-shot rendezvous with `spawn_worker`: signal
        // exactly once, on the FIRST connection outcome. A boot-time
        // failure is fatal (caller aborts boot); any later disconnect is
        // recoverable and must NOT re-signal (the receiver is long gone).
        let mut ready_tx = Some(ready_tx);

        loop {
            // Pool shutdown requested before (re)connecting — stop.
            if cancel.is_cancelled() {
                break;
            }

            // Per-connection child token: cancelled either by pool
            // shutdown (cascades from `cancel`) or by us after the TDP
            // run-loop returns, so the bridges for THIS connection exit
            // without tearing down the shared channels.
            let conn_cancel = cancel.child_token();

            // Channels that talk to BitcoinCoreSv2TDP directly. Re-created
            // per connection — the library takes ownership of one half.
            let (into_tdp_tx, into_tdp_rx) =
                async_channel::unbounded::<TemplateDistribution<'static>>();
            let (from_tdp_tx, from_tdp_rx) =
                async_channel::unbounded::<TemplateDistribution<'static>>();

            let tdp = match BitcoinCoreSv2TDP::new(
                &socket_path,
                fee_threshold,
                min_interval,
                into_tdp_rx,
                from_tdp_tx,
                conn_cancel.clone(),
            )
            .await
            {
                Ok(tdp) => tdp,
                Err(e) => {
                    if let Some(tx) = ready_tx.take() {
                        // First attempt failed — fatal boot error.
                        let _ = tx.send(Err(format!("BitcoinCoreSv2TDP::new failed: {e:?}")));
                        cancel.cancel();
                        return;
                    }
                    // Reconnect attempt failed — bitcoin-core still down.
                    // Back off and retry; the last template stays live for
                    // miners in the meantime.
                    warn!(
                        socket = %socket_path.display(),
                        error = ?e,
                        backoff_secs = reconnect_backoff.as_secs(),
                        "bp-tdp-worker reconnect failed; retrying"
                    );
                    if sleep_or_cancelled(reconnect_backoff, &cancel).await {
                        break;
                    }
                    continue;
                }
            };

            info!(
                socket = %socket_path.display(),
                fee_threshold,
                min_interval,
                "bp-tdp-worker connected to bitcoin-core IPC"
            );

            // Send the startup CoinbaseOutputConstraints. The TDP will not
            // distribute templates until it has seen one. On a reconnect
            // this re-arms the fresh connection identically.
            if let Err(e) = send_coinbase_constraints(&into_tdp_tx, coinbase_constraints).await {
                if let Some(tx) = ready_tx.take() {
                    let _ = tx.send(Err(format!(
                        "failed to send initial CoinbaseOutputConstraints: {e}"
                    )));
                    cancel.cancel();
                    return;
                }
                warn!(error = %e, "bp-tdp-worker: re-arming constraints after reconnect failed; retrying");
                conn_cancel.cancel();
                if sleep_or_cancelled(reconnect_backoff, &cancel).await {
                    break;
                }
                continue;
            }

            // Bridges for THIS connection. `bridge_in` takes `submit_rx`
            // by value and returns it when `conn_cancel` fires, so the
            // next iteration can reuse it.
            let bridge_out_handle = {
                let conn_cancel = conn_cancel.clone();
                let templates_tx = templates_tx.clone();
                tokio::task::spawn_local(bridge_out(from_tdp_rx, templates_tx, conn_cancel))
            };
            let bridge_in_handle = {
                let conn_cancel = conn_cancel.clone();
                let into_tdp_tx = into_tdp_tx.clone();
                tokio::task::spawn_local(bridge_in(submit_rx, into_tdp_tx, conn_cancel))
            };

            // Signal boot readiness on the first successful connection only.
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(Ok(()));
            }

            // Run the TDP event loop. Returns on IPC disconnect OR when
            // `conn_cancel` fires (pool shutdown cascading through the
            // child token).
            let mut tdp = tdp;
            tdp.run().await;

            // Tear down this connection's bridges and reclaim `submit_rx`.
            conn_cancel.cancel();
            submit_rx = match bridge_in_handle.await {
                Ok(rx) => rx,
                Err(e) => {
                    // bridge_in panicked — can't recover the channel; the
                    // pool→TDP request path is dead. Treat as fatal.
                    error!(error = %e, "bp-tdp-worker: bridge_in task panicked; aborting worker");
                    cancel.cancel();
                    return;
                }
            };
            let _ = bridge_out_handle.await;

            if cancel.is_cancelled() {
                info!("bp-tdp-worker shut down cleanly");
                break;
            }

            // Unexpected disconnect (bitcoin-core restart / IPC drop).
            warn!(
                backoff_secs = reconnect_backoff.as_secs(),
                "bp-tdp-worker: bitcoin-core IPC disconnected; reconnecting"
            );
            if sleep_or_cancelled(reconnect_backoff, &cancel).await {
                break;
            }
        }
    });
}

/// Sleep for `backoff`, but wake early if `cancel` fires. Returns `true`
/// if the wait ended because of cancellation (caller should stop the
/// reconnect loop), `false` if the full backoff elapsed.
async fn sleep_or_cancelled(backoff: std::time::Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => true,
        _ = tokio::time::sleep(backoff) => false,
    }
}

async fn send_coinbase_constraints(
    into_tdp_tx: &AcSender<TemplateDistribution<'static>>,
    constraints: TdpCoinbaseConstraints,
) -> Result<(), String> {
    let msg = TemplateDistribution::CoinbaseOutputConstraints(CoinbaseOutputConstraints {
        coinbase_output_max_additional_size: constraints.max_additional_size,
        coinbase_output_max_additional_sigops: constraints.max_additional_sigops,
    });
    into_tdp_tx.send(msg).await.map_err(|e| e.to_string())
}

async fn bridge_out(
    from_tdp_rx: AcReceiver<TemplateDistribution<'static>>,
    templates_tx: broadcast::Sender<TemplateUpdate>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                debug!("bridge_out: cancellation triggered, exiting");
                return;
            }
            recv = from_tdp_rx.recv() => match recv {
                Ok(msg) => {
                    if let Some(update) = TemplateUpdate::from_upstream(&msg) {
                        // It is fine if no subscribers exist yet — bitcoin-core
                        // keeps producing templates and we just drop them.
                        let _ = templates_tx.send(update);
                    } else {
                        debug!("bridge_out: dropping non-outbound payload variant");
                    }
                }
                Err(_) => {
                    debug!("bridge_out: TDP outbound channel closed");
                    return;
                }
            }
        }
    }
}

/// Forwards pool→TDP requests for the lifetime of ONE connection.
/// Returns `submit_rx` on exit so the reconnect loop can hand the same
/// channel to the next connection's bridge — the pool-side `submit_tx`
/// stays valid across reconnects.
async fn bridge_in(
    mut submit_rx: mpsc::Receiver<TdpRequest>,
    into_tdp_tx: AcSender<TemplateDistribution<'static>>,
    cancel: CancellationToken,
) -> mpsc::Receiver<TdpRequest> {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                debug!("bridge_in: cancellation triggered, exiting");
                return submit_rx;
            }
            req = submit_rx.recv() => match req {
                Some(req) => {
                    let msg = match req {
                        TdpRequest::SetCoinbaseConstraints {
                            max_additional_size,
                            max_additional_sigops,
                        } => TemplateDistribution::CoinbaseOutputConstraints(
                            CoinbaseOutputConstraints {
                                coinbase_output_max_additional_size: max_additional_size,
                                coinbase_output_max_additional_sigops: max_additional_sigops,
                            },
                        ),
                        TdpRequest::RequestTransactionData { template_id } => {
                            TemplateDistribution::RequestTransactionData(
                                RequestTransactionData { template_id },
                            )
                        }
                        TdpRequest::SubmitSolution {
                            template_id,
                            version,
                            header_timestamp,
                            header_nonce,
                            coinbase_tx,
                        } => match make_submit_solution(
                            template_id,
                            version,
                            header_timestamp,
                            header_nonce,
                            coinbase_tx,
                        ) {
                            Ok(m) => m,
                            Err(e) => {
                                error!(
                                    error = %e,
                                    template_id,
                                    "bridge_in: rejecting malformed SubmitSolution"
                                );
                                continue;
                            }
                        },
                    };

                    if let Err(e) = into_tdp_tx.send(msg).await {
                        warn!(error = %e, "bridge_in: TDP inbound channel closed");
                        return submit_rx;
                    }
                }
                None => {
                    debug!("bridge_in: handle dropped, exiting");
                    return submit_rx;
                }
            }
        }
    }
}

fn make_submit_solution(
    template_id: u64,
    version: u32,
    header_timestamp: u32,
    header_nonce: u32,
    coinbase_tx: Vec<u8>,
) -> Result<TemplateDistribution<'static>, String> {
    // `B064K::try_from(Vec<u8>)` enforces the upper length bound
    // (u16::MAX bytes — far above any realistic coinbase).
    let coinbase_tx = stratum_core::binary_sv2::B064K::try_from(coinbase_tx)
        .map_err(|e| format!("coinbase_tx too large for B064K: {e:?}"))?;

    Ok(TemplateDistribution::SubmitSolution(SubmitSolution {
        template_id,
        version,
        header_timestamp,
        header_nonce,
        coinbase_tx,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_rejects_missing_socket_path() {
        let cfg = TdpConfig::new("/definitely/does/not/exist/bp-tdp.sock");
        let cancel = CancellationToken::new();
        let (_submit_tx, submit_rx) = mpsc::channel(1);
        let (templates_tx, _) = broadcast::channel::<TemplateUpdate>(4);
        let err = spawn_worker(cfg, cancel, submit_rx, templates_tx)
            .expect_err("non-existent socket should fail fast");
        assert!(matches!(err, TdpError::SocketPathNotFound(_)));
    }

    #[tokio::test]
    async fn sleep_or_cancelled_returns_true_when_already_cancelled() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        // Long backoff — must return immediately because cancel is set.
        let stop = sleep_or_cancelled(std::time::Duration::from_secs(3600), &cancel).await;
        assert!(stop, "pre-cancelled token must short-circuit the backoff");
    }

    #[tokio::test]
    async fn sleep_or_cancelled_returns_false_after_full_backoff() {
        let cancel = CancellationToken::new();
        let stop = sleep_or_cancelled(std::time::Duration::from_millis(5), &cancel).await;
        assert!(!stop, "uncancelled backoff must elapse and report no-stop");
    }

    #[tokio::test]
    async fn sleep_or_cancelled_wakes_early_on_mid_wait_cancel() {
        let cancel = CancellationToken::new();
        let child = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            child.cancel();
        });
        // 60 s backoff but the spawned task cancels after 10 ms — must wake early.
        let start = std::time::Instant::now();
        let stop = sleep_or_cancelled(std::time::Duration::from_secs(60), &cancel).await;
        assert!(stop, "cancel during wait must report stop");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "must wake on cancel, not wait the full backoff"
        );
    }

    #[test]
    fn child_token_cascades_from_parent() {
        // The reconnect loop relies on this: pool shutdown cancels the
        // outer token, which must cascade to the per-connection child so
        // the in-flight TDP run loop returns.
        let parent = CancellationToken::new();
        let child = parent.child_token();
        assert!(!child.is_cancelled());
        parent.cancel();
        assert!(
            child.is_cancelled(),
            "child must cascade from parent cancel"
        );
    }
}
