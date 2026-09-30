// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unified SV1+SV2 listeners: one TCP listener per configured port serves
//! both protocols, so miners keep their configured `[stratum]` ports.
//!
//! [`crate::stratum_v1::build_per_port_servers`] and
//! [`crate::stratum_v2::build_per_port_servers`] build one server each per
//! port (same port set, no listener). Each port's [`accept_loop`] peeks the
//! first byte, classifies it via [`detect`] and hands the socket to the SV1
//! server or the SV2 one (Noise XK). HTTP is closed with a `WARN`; a TLS
//! ClientHello is closed silently to keep probe noise out of the logs.

use std::sync::{Arc, RwLock};

use bp_config::AppConfig;
use bp_notifications::dispatcher::NotificationDispatcher;
use bp_stratum_v1::{PortConfig as Sv1PortConfig, StratumV1Server};
use bp_stratum_v2::bridge::JdpDeclaredJobRegistry;
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
pub(crate) struct StratumHandles {
    pub(crate) ports: Vec<u16>,
    listener_tasks: Vec<JoinHandle<()>>,
    sv1_servers: Vec<StratumV1Server>,
    sv2_servers: Vec<StratumV2MiningServer>,
    cancel: CancellationToken,
    /// Republishes this front's live-session set. Only the front has one.
    live_sessions: Option<crate::live_sessions::LiveSessionPublisherHandle>,
}

impl StratumHandles {
    fn empty() -> Self {
        Self {
            ports: vec![],
            listener_tasks: vec![],
            sv1_servers: vec![],
            sv2_servers: vec![],
            cancel: CancellationToken::new(),
            live_sessions: None,
        }
    }

    /// Cancel every accept-loop, then drive each server's internal
    /// cancellation (translator tasks + per-connection tasks) to
    /// completion. Idempotent — second call is a no-op.
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        if let Some(live) = self.live_sessions {
            live.shutdown().await;
        }
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

/// Spawn the unified SV1+SV2 stratum listeners. Returns an empty handle
/// when TDP is unavailable (`--skip-tdp`): without templates there are no
/// jobs to serve.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn(
    cfg: &AppConfig,
    foundation: &FoundationHandles,
    engines: &EngineHandles,
    group_service: &SharedGroupService,
    dispatcher: Option<Arc<NotificationDispatcher>>,
    gate: Option<(
        Arc<crate::device_status_gate::Gate>,
        crate::device_status_gate::SubscribedAddresses,
    )>,
    // ext 0x0003 §10: a block booked through a Stratum sink's immediate
    // apply must invalidate the published payout distributions exactly
    // like a JDP-declared one. Filled once the JDP server exists.
    settle: crate::settlement::SettlementSignal,
    // THE JDP bridge: the same `Arc` the JDP server registers into. The JDP
    // server writes declared jobs and allocations, `SetCustomMiningJob`
    // here reads them; a second instance would fail every custom job with
    // `invalid-mining-job-token`.
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
) -> Result<StratumHandles, StratumSpawnError> {
    if foundation.tdp.is_none() {
        warn!("stratum: TDP missing (--skip-tdp); skipping unified SV1+SV2 listener bind");
        return Ok(StratumHandles::empty());
    }

    // One resolver for both protocols; each takes it as its own
    // `PayoutResolver` trait.
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

    // ONE pool-wide MiningJob cache for every SV1 and SV2 port server: they
    // share the TDP streams and the key is content-based, so identical
    // builds are one entry.
    let job_cache = Arc::new(bp_mining_job::MiningJobCache::new());

    // Only the front knows first-hand which devices are connected; publish
    // that set so the notify side need not infer it from share activity.
    // One registry per process, wrapping the shared persistence hook so
    // both protocols feed it.
    let live_sessions = Arc::new(crate::live_sessions::LiveSessionRegistry::new(
        Arc::new(engines.session_persistence_hook.clone()),
        foundation.redis.clone(),
        &uuid::Uuid::new_v4().to_string(),
    ));
    let live_publisher = crate::live_sessions::spawn_publisher(Arc::clone(&live_sessions));

    let device_status = crate::device_status::stratum_sinks(gate, foundation.redis.clone());

    let sv1_servers = stratum_v1::build_per_port_servers(
        cfg,
        foundation,
        engines,
        group_service,
        sv1_resolver,
        dispatcher.clone(),
        Arc::clone(&device_status),
        Arc::clone(&live_sessions),
        job_cache.clone(),
        settle.clone(),
    )?;
    let noise_config = stratum_v2::build_noise_config(cfg)?;
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
        device_status,
        Arc::clone(&live_sessions),
        job_cache,
        settle,
    );

    // Pair SV1 + SV2 servers by port. Both enumerate ports via SV1's
    // `build_port_configs`; the asserts fail loudly on divergence instead
    // of mis-dispatching.
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
        live_sessions: Some(live_publisher),
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

/// How long sent data may stay unacknowledged before the kernel drops the
/// connection. A miner that vanished without closing still gets jobs, so
/// keepalive never runs, and without this Linux retransmits for
/// `tcp_retries2` rounds before giving up.
#[cfg(target_os = "linux")]
const STRATUM_USER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(150);

/// Socket options every accepted stratum connection gets, SV1 and SV2
/// alike. Failures are logged and the connection is served anyway.
fn tune_stratum_socket(socket: &TcpStream, peer: std::net::SocketAddr, port: u16) {
    // No Nagle: small latency-sensitive frames, and Nagle plus delayed ACK
    // adds ~40 ms per round-trip.
    if let Err(err) = socket.set_nodelay(true) {
        warn!(%err, ?peer, port, "stratum: set_nodelay(true) failed (continuing)");
    }
    // Keepalive keeps quiet connections in NAT/firewall tables and detects
    // a dead peer on an idle connection: probe after 60 s idle, every 20 s,
    // drop after 4 misses. It only probes a connection with nothing in
    // flight; the user timeout below covers the rest. The per-socket opt-in
    // is required; the sysctls only tune the timing.
    let keepalive = TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(60))
        .with_interval(std::time::Duration::from_secs(20))
        .with_retries(4);
    if let Err(err) = SockRef::from(socket).set_tcp_keepalive(&keepalive) {
        warn!(%err, ?peer, port, "stratum: set_tcp_keepalive(60s) failed (continuing)");
    }
    // Linux only (TCP_USER_TIMEOUT). With it set, the kernel also uses it
    // to close a connection whose keepalive probes go unanswered.
    #[cfg(target_os = "linux")]
    if let Err(err) = SockRef::from(socket).set_tcp_user_timeout(Some(STRATUM_USER_TIMEOUT)) {
        warn!(%err, ?peer, port, "stratum: set_tcp_user_timeout failed (continuing)");
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
    tune_stratum_socket(&socket, peer, port);
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

/// What the first byte of an accepted connection says it speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Detected {
    /// SV1 JSON-RPC: `'{'`, or one of the pre-JSON whitespace bytes
    /// `' '` / `'\n'` / `'\r'` some SV1 implementations lead with.
    Sv1,
    /// SV2 binary protocol (Noise handshake). Every byte the other
    /// variants don't claim lands here.
    Sv2,
    /// HTTP request: `'G'` (GET) or `'P'` (POST/PUT/PATCH). Not served on
    /// a stratum port — [`dispatch_connection`] logs a warning and closes.
    Http,
    /// TLS ClientHello (`0x16`). Closed right away, so a TLS probe never
    /// reaches the SV2 handshake machinery.
    Tls,
}

/// Classify a connection by its first byte.
///
/// Pre-JSON whitespace (`' '`, `'\n'`, `'\r'`) counts as SV1: the SV1
/// spec opens with `{`, but some implementations lead with whitespace.
/// The byte is only peeked, so the SV1 parser still sees it and trims it.
fn detect(first_byte: u8) -> Detected {
    match first_byte {
        // HTTP — GET (0x47) or POST/PUT/PATCH (0x50).
        b'G' | b'P' => Detected::Http,
        // SV1 — '{' (0x7B) or leading whitespace before the JSON body.
        b'{' | b' ' | b'\n' | b'\r' => Detected::Sv1,
        // TLS ClientHello — not a stratum protocol.
        0x16 => Detected::Tls,
        // Anything else: assume SV2 binary (Noise handshake).
        _ => Detected::Sv2,
    }
}

/// Peek the first byte from `socket` without consuming it. Returns
/// `Ok(None)` when the peer closed the connection before sending
/// anything; `Err(_)` for any I/O error.
async fn peek_first_byte(socket: &TcpStream) -> std::io::Result<Option<u8>> {
    // `peek` returns 0 on peer-close.
    let mut buf = [0u8; 1];
    match socket.peek(&mut buf).await? {
        0 => Ok(None),
        _ => Ok(Some(buf[0])),
    }
}

/// One Stratum port's template subscriptions: the default stream plus every
/// alt stream, each with the snapshot that covers what the broadcast missed.
/// SV1 and SV2 build their per-port servers from the same set.
pub(crate) struct PortTemplates {
    pub(crate) updates_rx:
        tokio::sync::broadcast::Receiver<bp_template_distribution::TemplateUpdate>,
    pub(crate) initial_snapshot: bp_template_distribution::TemplateSnapshot,
    pub(crate) alt_streams: Vec<(
        bp_common::StreamKind,
        tokio::sync::broadcast::Receiver<bp_template_distribution::TemplateUpdate>,
        bp_template_distribution::TemplateSnapshot,
    )>,
}

impl PortTemplates {
    /// Subscribe BEFORE snapshotting: anything broadcast between the two ends
    /// up in both, and the assembler dedupes on template_id. The snapshot
    /// covers the bootstrap pair (NewTemplate + SetNewPrevHash) broadcast
    /// before a per-port subscriber exists.
    ///
    /// Every port carries ALL alt streams: mode is per-address, so a
    /// Group-Solo / Blockparty member on any port must be routable onto its
    /// stream.
    pub(crate) fn subscribe(
        tdp: &bp_template_distribution::TdpHandle,
        foundation: &FoundationHandles,
    ) -> Self {
        let updates_rx = tdp.subscribe();
        let initial_snapshot = tdp.current_snapshot();
        let alt_streams = foundation
            .alt_tdp
            .iter()
            .map(|(kind, handle)| (*kind, handle.subscribe(), handle.current_snapshot()))
            .collect();
        Self {
            updates_rx,
            initial_snapshot,
            alt_streams,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── socket options ──────────────────────────────────────────────

    /// An accepted stratum socket gives up on a peer that stops
    /// acknowledging after 150 s, and keeps its keepalive and no-delay.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn accepted_sockets_get_the_user_timeout_keepalive_and_nodelay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).await.unwrap();
        let (socket, peer) = listener.accept().await.unwrap();

        let sock = SockRef::from(&socket);
        assert_eq!(
            sock.tcp_user_timeout().unwrap(),
            None,
            "precondition: unset by default"
        );

        tune_stratum_socket(&socket, peer, addr.port());
        assert_eq!(sock.tcp_user_timeout().unwrap(), Some(STRATUM_USER_TIMEOUT));
        assert_eq!(STRATUM_USER_TIMEOUT, std::time::Duration::from_secs(150));
        assert!(sock.keepalive().unwrap());
        assert_eq!(
            sock.tcp_keepalive_time().unwrap(),
            std::time::Duration::from_secs(60)
        );
        assert!(socket.nodelay().unwrap());
    }

    // ── first-byte detection ─────────────────────────────────────────

    #[test]
    fn http_method_initials_route_to_http() {
        // GET (0x47); POST / PUT / PATCH all start with 0x50.
        assert_eq!(detect(b'G'), Detected::Http);
        assert_eq!(detect(b'P'), Detected::Http);
    }

    #[test]
    fn open_brace_and_leading_whitespace_are_sv1() {
        // Some non-strict SV1 implementations lead with whitespace.
        for b in [b'{', b' ', b'\n', b'\r'] {
            assert_eq!(detect(b), Detected::Sv1, "byte 0x{b:02x}");
        }
    }

    #[test]
    fn tls_client_hello_is_its_own_variant() {
        // TLS ClientHello typically starts 0x16 0x03 0x01 (handshake, TLS 1.0).
        assert_eq!(detect(0x16), Detected::Tls);
    }

    #[test]
    fn unclaimed_bytes_fall_through_to_sv2() {
        // A Noise XK first message starts with the ephemeral public key, so
        // the leading byte is whatever the curve produced.
        for b in [0x00, 0x01, 0x42, 0x80, 0xab, 0xfe, 0xff] {
            assert_eq!(detect(b), Detected::Sv2, "byte 0x{b:02x}");
        }
        // Letters other than the HTTP method initials are not HTTP.
        for b in [b'A', b'B', b'H', b'O', b'T', b'X', b'Z'] {
            assert_eq!(detect(b), Detected::Sv2, "letter '{}'", b as char);
        }
    }
}
