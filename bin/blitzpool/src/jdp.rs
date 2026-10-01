// SPDX-License-Identifier: AGPL-3.0-or-later

//! JDP server wiring: one listener on `[sv2].jdp_port`, each socket handed to
//! [`StratumV2JdpServer::accept_connection`] (no protocol detection).
//!
//! The [`TemplateTxCache`]-backed tx provider runs only with
//! `[sv2].jdp_orphan_submitblock = true`, since only then does the pool need
//! the declared tx bytes. JDP is off unless `[sv2].jdp_enabled = true`.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bp_bitcoin::BitcoinRpc;
use bp_common::AddressId;
use bp_config::AppConfig;
use bp_stratum_v2::bridge::JdpDeclaredJobRegistry;
use bp_stratum_v2::jdp_server::StratumV2JdpServer;
use bp_template_distribution::{TdpHandle, TemplateTxCache};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::jdp_hooks::build_jdp_hooks;
use crate::payout_resolver::{ProductionDistributionSource, ProductionPayoutResolver};
use crate::stratum_v2;

/// Default `SetPayoutDistribution` republish cadence when
/// `[sv2].jdp_payout_distribution_interval_secs` is unset.
const DEFAULT_DISTRIBUTION_INTERVAL_SECS: u64 = 60;

pub(crate) struct JdpHandles {
    pub(crate) port: Option<u16>,
    listener_task: Option<JoinHandle<()>>,
    server: Option<StratumV2JdpServer>,
    cancel: CancellationToken,
}

impl JdpHandles {
    fn disabled() -> Self {
        Self {
            port: None,
            listener_task: None,
            server: None,
            cancel: CancellationToken::new(),
        }
    }

    /// [`Self::disabled`] for the `--skip-tdp` startup path; the JDP hooks need TDP.
    pub(crate) fn disabled_for_init() -> Self {
        Self::disabled()
    }

    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        if let Some(server) = &self.server {
            server.shutdown().await;
        }
        if let Some(task) = self.listener_task {
            let _ = task.await;
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum JdpSpawnError {
    #[error("[sv2] jdp_enabled = true but jdp_port is unset")]
    PortMissing,
    #[error("jdp bind {addr} failed: {source}")]
    Bind {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Sv2(#[from] stratum_v2::StratumV2SpawnError),
    /// `[sv2].jdp_validation_socket_path` is unusable or the node did not answer.
    #[error("jdp validation socket unusable: {0}")]
    ValidationSocket(String),
}

/// Spawn the JDP server when `[sv2].jdp_enabled` is true. The bridge is shared
/// with the mining servers so declared tokens resolve on `SetCustomMiningJob`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn(
    cfg: &AppConfig,
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    tdp: TdpHandle,
    bitcoin_rpc: BitcoinRpc,
    payout_resolver: Arc<ProductionPayoutResolver>,
    template_tx_cache: Option<Arc<TemplateTxCache>>,
    // Books a JDC-found block against the distribution its coinbase paid.
    ledger_booker: Arc<crate::block_sink::TdpBlockSubmissionSink>,
    // Allocates the strictly-increasing `distribution_id` (ext 0x0003/SetPayoutDistribution).
    redis: redis::aio::ConnectionManager,
    // Created by the caller so the block sinks reach the same registry.
    settle: crate::settlement::SettlementSignal,
) -> Result<JdpHandles, JdpSpawnError> {
    if !cfg.sv2.jdp_enabled {
        info!("jdp: disabled (sv2.jdp_enabled = false)");
        return Ok(JdpHandles::disabled());
    }
    let port = cfg.sv2.jdp_port.ok_or(JdpSpawnError::PortMissing)?;
    let noise = stratum_v2::build_noise_config(cfg)?;
    let network = crate::boot::bitcoin_network(cfg.network);
    // Same resolver as the allocate path, so the published distribution and
    // the pool's coinbase agree. The fee address anchors modes with no pool output.
    let fee_address = cfg
        .pplns
        .as_ref()
        .and_then(|p| AddressId::new(p.fee_address.clone()).ok());
    let distribution_source = Arc::new(ProductionDistributionSource {
        resolver: payout_resolver.clone(),
        chain: Arc::new(tdp.clone()),
        redis: Some(redis),
        network,
        fee_address,
    });

    // SV2 JDP/Job Declarator Server: unset socket means trusted; an unusable
    // one stops boot rather than claiming validation that does not happen.
    let job_validator = match cfg.sv2.jdp_validation_socket_path.clone() {
        Some(socket_path) => crate::jdp_hooks::ProductionJobValidator::connect(
            socket_path,
            cfg.network,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .map_err(JdpSpawnError::ValidationSocket)?,
        None => {
            info!(
                "jdp: declared jobs are NOT validated against bitcoin-core \
                 (set `[sv2].jdp_validation_socket_path` to enable, SV2 JDP/Job Declarator Server)"
            );
            None
        }
    };

    let hooks = build_jdp_hooks(
        tdp,
        bitcoin_rpc,
        payout_resolver,
        template_tx_cache,
        network,
        cfg.sv2.jdp_orphan_submitblock,
        ledger_booker,
        distribution_source,
        settle.clone(),
        job_validator,
    );

    let distribution_interval = Duration::from_secs(
        cfg.sv2
            .jdp_payout_distribution_interval_secs
            .unwrap_or(DEFAULT_DISTRIBUTION_INTERVAL_SECS),
    );
    let server = StratumV2JdpServer::spawn(noise, hooks, bridge, distribution_interval);
    let _ = settle.registry_slot().set(server.distribution_handle());

    let bind_addr: std::net::SocketAddr = ([0, 0, 0, 0], port).into();
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|source| JdpSpawnError::Bind {
            addr: bind_addr,
            source,
        })?;
    info!(port, "jdp: listening");

    let cancel = CancellationToken::new();
    let listener_task = tokio::spawn(jdp_accept_loop(listener, server.clone(), cancel.clone()));

    Ok(JdpHandles {
        port: Some(port),
        listener_task: Some(listener_task),
        server: Some(server),
        cancel,
    })
}

/// Like the stratum accept loop, without protocol detection.
async fn jdp_accept_loop(
    listener: TcpListener,
    server: StratumV2JdpServer,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                debug!("jdp: accept-loop cancelled");
                break;
            }
            res = listener.accept() => match res {
                Ok((socket, peer)) => {
                    debug!(?peer, "jdp: accepted");
                    server.accept_connection(socket);
                }
                Err(err) => {
                    warn!(%err, "jdp: accept failed");
                }
            }
        }
    }
}
