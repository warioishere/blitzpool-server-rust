// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unified SV1+SV2 listener coordinator — Phase 7.4c.
//!
//! Owns one TCP listener per configured port (solo + solo-high-diff +
//! optionally pplns + pplns-high-diff). For each connection: peek the
//! first byte, classify via [`bp_protocol_detect::detect`], dispatch
//! to either the SV1 server's `accept_connection` (existing SV1
//! handshake) or the SV2 server's `accept_connection` (Noise XK
//! handshake). HTTP requests on a stratum port get closed with a
//! `WARN` (HTTP→bp-api proxy fallback is a deferred polish item);
//! TLS ClientHello gets closed silently to keep probe noise out of
//! the connection logs.
//!
//! One "Unified Stratum server (V1 + V2)" per port fronts both
//! protocols on the same TCP address.
//!
//! ## Why per-port unified listener (not separate ports)
//!
//! Operators have BitAxes / NerdQAxes pointed at the existing
//! `[stratum]` ports. Migrating to a separate SV2 port would force
//! every miner to re-configure. Serving both protocols on the same
//! port keeps the deploy story "swap the binary; nothing else changes".
//!
//! ## Architecture
//!
//! 1. [`crate::stratum_v1::build_per_port_servers`] returns one
//!    `Sv1PortServer` per port (no listener bound).
//! 2. [`crate::stratum_v2::build_per_port_servers`] returns one
//!    `Sv2PortServer` per port (no listener bound) — same port set.
//! 3. For each port: bind a single `TcpListener`, spawn an
//!    [`accept_loop`] that peeks → dispatches → hands the socket to
//!    the matching server.
//! 4. Shutdown: cancel the shared token + drive each per-port server's
//!    own shutdown to completion.

use std::sync::Arc;

use bp_config::AppConfig;
use bp_notifications::dispatcher::NotificationDispatcher;
use bp_protocol_detect::{detect, Detected};
use bp_stratum_v1::{PortConfig as Sv1PortConfig, StratumV1Server};
use bp_stratum_v2::server::StratumV2MiningServer;
use socket2::{SockRef, TcpKeepalive};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::boot::FoundationHandles;
use crate::engines::EngineHandles;
use crate::group_service::SharedGroupService;
use crate::stratum_v1::{self, StratumV1SpawnError};
use crate::stratum_v2::{self, StratumV2SpawnError};

/// Long-lived stratum (SV1 + SV2) handle aggregate. Drop or call
/// [`Self::shutdown`] to cancel every accept-loop + every
/// per-connection task across both protocols.
#[allow(dead_code)]
pub(crate) struct StratumHandles {
    pub(crate) ports: Vec<u16>,
    listener_tasks: Vec<JoinHandle<()>>,
    sv1_servers: Vec<StratumV1Server>,
    sv2_servers: Vec<StratumV2MiningServer>,
    cancel: CancellationToken,
}

impl StratumHandles {
    fn empty() -> Self {
        Self {
            ports: vec![],
            listener_tasks: vec![],
            sv1_servers: vec![],
            sv2_servers: vec![],
            cancel: CancellationToken::new(),
        }
    }

    /// Cancel every accept-loop, then drive each server's internal
    /// cancellation (translator tasks + per-connection tasks) to
    /// completion. Idempotent — second call is a no-op.
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        for server in &self.sv1_servers {
            server.shutdown().await;
        }
        for server in &self.sv2_servers {
            server.shutdown().await;
        }
        for task in self.listener_tasks {
            let _ = task.await;
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum StratumSpawnError {
    #[error(transparent)]
    Sv1(#[from] StratumV1SpawnError),
    #[error(transparent)]
    Sv2(#[from] StratumV2SpawnError),
    #[error("stratum bind {addr} failed: {source}")]
    Bind {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// Spawn the unified SV1+SV2 stratum listeners. Returns an empty
/// handle when TDP is unavailable (`--skip-tdp`) — both protocols
/// fail open with warns, the listener bind would be pointless.
pub(crate) async fn spawn(
    cfg: &AppConfig,
    foundation: &FoundationHandles,
    engines: &EngineHandles,
    group_service: &SharedGroupService,
    dispatcher: Option<Arc<NotificationDispatcher>>,
) -> Result<StratumHandles, StratumSpawnError> {
    if foundation.tdp.is_none() {
        warn!("stratum: TDP missing (--skip-tdp); skipping unified SV1+SV2 listener bind");
        return Ok(StratumHandles::empty());
    }

    // Single production resolver, fanned out to both protocols. Lives
    // here because it's the join point where the SV1 + SV2 hook
    // builders both need an `Arc<dyn PayoutResolver>` (each in its
    // own trait shape; same concrete impl).
    let production_resolver = Arc::new(crate::payout_resolver::ProductionPayoutResolver::new(
        engines.mode_gate.clone(),
        engines.pplns.clone(),
        engines.group_solo.clone(),
        crate::payout_resolver::SoloFeeConfig {
            dev_fee_address: cfg.solo.dev_fee_address.clone(),
            dev_fee_percent: cfg.solo.dev_fee_percent.unwrap_or(0.0),
        },
        engines.blockparty.clone(),
    ));
    let sv1_resolver: Arc<dyn bp_stratum_v1::PayoutResolver> = production_resolver.clone();
    let sv2_resolver: Arc<dyn bp_stratum_v2::hooks::PayoutResolver> = production_resolver;

    // ONE pool-wide MiningJob cache shared across every SV1 AND SV2
    // port server. All of them ride the same TDP streams, and the
    // cache key is content-based, so an SV1 PPLNS build and an SV2
    // Standard-channel build for the same template are literally the
    // same entry.
    let job_cache = Arc::new(bp_mining_job::MiningJobCache::new());

    let sv1_servers = stratum_v1::build_per_port_servers(
        cfg,
        foundation,
        engines,
        group_service,
        sv1_resolver,
        dispatcher.clone(),
        job_cache.clone(),
    )?;
    let noise_config = stratum_v2::build_noise_config(cfg)?;
    let bridge = stratum_v2::build_bridge();
    // Warm the customer-extranonce cache before the servers start serving, then
    // it self-refreshes off PG. Shared across every SV2 port.
    let custom_extranonce: Arc<dyn bp_stratum_v2::hooks::CustomExtranonceSource> =
        crate::custom_extranonce::CustomExtranonceCache::spawn(foundation.db.pool().clone()).await;
    let sv2_servers = stratum_v2::build_per_port_servers(
        cfg,
        foundation,
        engines,
        group_service,
        noise_config,
        bridge,
        sv2_resolver,
        custom_extranonce,
        dispatcher,
        job_cache,
    );

    // Pair SV1 + SV2 servers by port. Both builders enumerate ports
    // identically (SV1's `build_port_configs`); guard with an assert
    // so future divergence trips a CI failure rather than silently
    // mis-dispatching.
    assert_eq!(
        sv1_servers.len(),
        sv2_servers.len(),
        "sv1 + sv2 must enumerate the same port set"
    );

    let cancel = CancellationToken::new();
    let mut listener_tasks: Vec<JoinHandle<()>> = Vec::with_capacity(sv1_servers.len());
    let mut ports: Vec<u16> = Vec::with_capacity(sv1_servers.len());
    let mut sv1_server_handles: Vec<StratumV1Server> = Vec::with_capacity(sv1_servers.len());
    let mut sv2_server_handles: Vec<StratumV2MiningServer> = Vec::with_capacity(sv2_servers.len());

    for (sv1, sv2) in sv1_servers.into_iter().zip(sv2_servers) {
        assert_eq!(
            sv1.port_config.port, sv2.port,
            "sv1 + sv2 port enumeration drift at index"
        );

        let bind_addr: std::net::SocketAddr = ([0, 0, 0, 0], sv1.port_config.port).into();
        let listener =
            TcpListener::bind(bind_addr)
                .await
                .map_err(|source| StratumSpawnError::Bind {
                    addr: bind_addr,
                    source,
                })?;
        info!(
            port = sv1.port_config.port,
            payout_mode = ?sv1.port_config.payout_mode,
            "stratum: unified SV1+SV2 listener bound"
        );

        let dispatch = PortDispatch {
            sv1_server: sv1.server.clone(),
            sv1_port_config: sv1.port_config.clone(),
            sv2_server: sv2.server.clone(),
            sv2_port_config: sv2.port_config,
        };
        let task = tokio::spawn(accept_loop(listener, dispatch, cancel.clone()));
        listener_tasks.push(task);
        ports.push(sv1.port_config.port);
        sv1_server_handles.push(sv1.server);
        sv2_server_handles.push(sv2.server);
    }

    Ok(StratumHandles {
        ports,
        listener_tasks,
        sv1_servers: sv1_server_handles,
        sv2_servers: sv2_server_handles,
        cancel,
    })
}

/// Per-port dispatch context. Cheap to clone (the server handles are
/// internally `Arc`).
#[derive(Clone)]
struct PortDispatch {
    sv1_server: StratumV1Server,
    sv1_port_config: Sv1PortConfig,
    sv2_server: StratumV2MiningServer,
    sv2_port_config: bp_stratum_v2::mining::client::PortConfig,
}

/// TCP accept-loop with first-byte protocol-detect dispatch.
async fn accept_loop(listener: TcpListener, dispatch: PortDispatch, cancel: CancellationToken) {
    let port = dispatch.sv1_port_config.port;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                debug!(port, "stratum: accept-loop cancelled");
                break;
            }
            res = listener.accept() => match res {
                Ok((socket, peer)) => {
                    // Each connection spawns its own task — peeking +
                    // dispatching MUST NOT block subsequent accepts.
                    let dispatch = dispatch.clone();
                    tokio::spawn(async move {
                        dispatch_connection(socket, peer, dispatch).await;
                    });
                }
                Err(err) => {
                    warn!(%err, port, "stratum: accept failed");
                }
            }
        }
    }
}

/// Peek 1 byte from `socket` and dispatch to the right server. Closes
/// the socket if no byte arrives within 30 s. The peek is non-consuming
/// — the downstream server reads from byte 0 of the same socket (SV1
/// starts JSON parsing, SV2 starts Noise handshake). Any read failure
/// before dispatch closes the socket silently.
async fn dispatch_connection(
    socket: TcpStream,
    peer: std::net::SocketAddr,
    dispatch: PortDispatch,
) {
    let port = dispatch.sv1_port_config.port;
    // Disable Nagle's algorithm: stratum is latency-sensitive small-frame
    // request/response. With Nagle on, the Nagle + delayed-ACK interaction
    // adds ~40 ms per round-trip (most visible on SV2 share acks). Set it
    // once here so both SV1 and SV2 connections inherit it.
    if let Err(err) = socket.set_nodelay(true) {
        warn!(%err, ?peer, port, "stratum: set_nodelay(true) failed (continuing)");
    }
    // Enable TCP keepalive so long-lived but quiet miner connections (idle
    // between shares / new templates) don't get silently evicted from an
    // upstream NAT/firewall state table, and dead peers are detected: start
    // probing after 60 s idle, then every 20 s, drop after 4 missed probes
    // (~140 s). The per-socket SO_KEEPALIVE opt-in is required — the
    // net.ipv4.tcp_keepalive_* sysctls only tune the timing once it's on.
    let keepalive = TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(60))
        .with_interval(std::time::Duration::from_secs(20))
        .with_retries(4);
    if let Err(err) = SockRef::from(&socket).set_tcp_keepalive(&keepalive) {
        warn!(%err, ?peer, port, "stratum: set_tcp_keepalive(60s) failed (continuing)");
    }
    let detected = match timeout(std::time::Duration::from_secs(30), peek_first_byte(&socket)).await
    {
        Err(_) => {
            debug!(?peer, port, "stratum: detection timeout; closing");
            return;
        }
        Ok(Ok(Some(b))) => detect(b),
        Ok(Ok(None)) => {
            debug!(?peer, port, "stratum: empty first read; closing");
            return;
        }
        Ok(Err(err)) => {
            debug!(%err, ?peer, port, "stratum: peek failed; closing");
            return;
        }
    };

    match detected {
        Detected::Sv1 => {
            debug!(?peer, port, "stratum: SV1 detected, dispatching");
            dispatch
                .sv1_server
                .accept_connection(socket, dispatch.sv1_port_config);
        }
        Detected::Sv2 => {
            debug!(?peer, port, "stratum: SV2 detected, dispatching");
            dispatch
                .sv2_server
                .accept_connection(socket, dispatch.sv2_port_config);
        }
        Detected::Http => {
            warn!(
                ?peer,
                port, "stratum: HTTP on stratum port; closing (bp-api proxy fallback deferred)"
            );
        }
        Detected::Tls => {
            debug!(?peer, port, "stratum: TLS probe; closing silently");
        }
    }
}

/// Peek the first byte from `socket` without consuming it. Returns
/// `Ok(None)` when the peer closed the connection before sending
/// anything; `Err(_)` for any I/O error.
async fn peek_first_byte(socket: &TcpStream) -> std::io::Result<Option<u8>> {
    // `TcpStream::peek` yields until at least one byte is available or
    // the peer closes the connection. Returns 0 on peer-close, n>0
    // otherwise.
    let mut buf = [0u8; 1];
    match socket.peek(&mut buf).await? {
        0 => Ok(None),
        _ => Ok(Some(buf[0])),
    }
}

// Silence the `Arc` import warning when no other module needs it.
#[allow(dead_code)]
fn _silence_arc<T>(_: Arc<T>) {}

#[cfg(test)]
mod tests {
    use super::*;

    // Detection routing is exercised end-to-end against the actual
    // `bp_protocol_detect::detect` table; the pure-classification
    // logic itself is tested inside that crate. Here we just confirm
    // the mapping we rely on in `dispatch_connection` hasn't shifted.

    #[test]
    fn detect_table_pins_expected_mappings() {
        assert_eq!(detect(b'{'), Detected::Sv1);
        assert_eq!(detect(b' '), Detected::Sv1);
        assert_eq!(detect(b'\n'), Detected::Sv1);
        assert_eq!(detect(b'\r'), Detected::Sv1);
        assert_eq!(detect(b'G'), Detected::Http);
        assert_eq!(detect(b'P'), Detected::Http);
        assert_eq!(detect(0x16), Detected::Tls);
        // SV2's Noise handshake first byte is typically 0x00..0x40 but
        // any non-classified byte falls into SV2.
        assert_eq!(detect(0x00), Detected::Sv2);
        assert_eq!(detect(0xFF), Detected::Sv2);
    }
}
