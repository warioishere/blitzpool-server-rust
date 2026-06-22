// SPDX-License-Identifier: AGPL-3.0-or-later

//! JDP server wiring — Phase 7.4c + 7.4d.4.
//!
//! Binds a single listener on `[sv2].jdp_port` and dispatches each
//! socket into [`StratumV2JdpServer::accept_connection`]. Unlike the
//! mining ports, JDP doesn't multiplex with anything else — Job
//! Declaration Clients (JDCs) speak the JDP sub-protocol straight
//! after the Noise handshake.
//!
//! Phase 7.4d.4 replaced [`JdpServerHooks::no_op`] with
//! [`crate::jdp_hooks::build_jdp_hooks`] — full production
//! `AllocateResolver` (PayoutResolver-backed), `CurrentPrevHashProvider`
//! (TDP snapshot), and `JdpBlockSubmissionSink` (`submitblock` RPC for
//! orphan-protection redundancy). Phase 7.4d.5.a adds the
//! [`TemplateTxCache`]-backed `TemplateTxProvider`, gated on
//! `[sv2].jdp_orphan_submitblock = true`: when the pool resubmits
//! blocks itself, the cache cuts JDC-side `ProvideMissingTransactions`
//! payloads from ~1 MB to the handful of txs the JDC has and the pool
//! doesn't. In default mode (orphan-resubmit off) the cache is not
//! spawned — pool ignores the declared tx-bytes anyway.
//!
//! ## When JDP is disabled
//!
//! If `[sv2].jdp_enabled = false` or `jdp_port` is absent, this
//! module's `spawn` returns an empty handle with a single `info!`
//! log. JDP is off by default; operators flip it on deliberately.

use std::sync::{Arc, RwLock};

use bitcoin::Network as BitcoinNetwork;
use bp_bitcoin::BitcoinRpc;
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
use crate::payout_resolver::ProductionPayoutResolver;
use crate::stratum_v2;

#[allow(dead_code)]
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

    /// Public variant of [`Self::disabled`] for the `--skip-tdp`
    /// startup-path in main.rs (TDP is required to spawn the JDP
    /// hooks — production `JdpAllocateResolver` reads the latest
    /// template's `coinbase_tx_value_remaining`, and the block-submit
    /// path needs TDP to relate prev_hashes).
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
}

/// Spawn the JDP server when `[sv2].jdp_enabled` is true. The bridge
/// is shared with the SV2 mining servers via [`stratum_v2::build_bridge`]
/// so `DeclareMiningJob`-issued tokens route to the correct mining
/// channel on `SetCustomMiningJob`.
pub(crate) async fn spawn(
    cfg: &AppConfig,
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    tdp: TdpHandle,
    bitcoin_rpc: BitcoinRpc,
    payout_resolver: Arc<ProductionPayoutResolver>,
    template_tx_cache: Option<Arc<TemplateTxCache>>,
) -> Result<JdpHandles, JdpSpawnError> {
    if !cfg.sv2.jdp_enabled {
        info!("jdp: disabled (sv2.jdp_enabled = false)");
        return Ok(JdpHandles::disabled());
    }
    let port = cfg.sv2.jdp_port.ok_or(JdpSpawnError::PortMissing)?;
    let noise = stratum_v2::build_noise_config(cfg)?;
    let server_cfg = stratum_v2::build_server_config(cfg);
    let network = match cfg.network {
        bp_config::Network::Mainnet => BitcoinNetwork::Bitcoin,
        // testnet4 shares the `tb` HRP with testnet3 — rust-bitcoin
        // 0.32's Testnet variant covers both.
        bp_config::Network::Testnet | bp_config::Network::Testnet4 => BitcoinNetwork::Testnet,
        bp_config::Network::Regtest => BitcoinNetwork::Regtest,
    };
    let hooks = build_jdp_hooks(
        tdp,
        bitcoin_rpc,
        payout_resolver,
        template_tx_cache,
        network,
        cfg.sv2.jdp_orphan_submitblock,
    );

    let server = StratumV2JdpServer::spawn(server_cfg, noise, hooks, bridge);

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

/// Used the same shape as the stratum accept-loop but without
/// protocol-detect — JDP is single-protocol per its port.
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
                    server.accept_connection(socket, peer.to_string());
                }
                Err(err) => {
                    warn!(%err, "jdp: accept failed");
                }
            }
        }
    }
}
