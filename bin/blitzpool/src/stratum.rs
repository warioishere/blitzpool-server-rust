// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unified SV1+SV2 listeners: one TCP listener per `[stratum]` port serves
//! both protocols. Each accepted connection's opening bytes are peeked,
//! classified via [`detect`] and the socket handed to the SV1 or SV2
//! server; HTTP is closed with a `WARN`, TLS probes silently.

use std::sync::{Arc, RwLock};
use std::time::Duration;

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
use crate::membership::Membership;
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
    membership: &Membership,
    dispatcher: Option<Arc<NotificationDispatcher>>,
    gate: Option<(
        Arc<crate::device_status_gate::Gate>,
        crate::device_status_gate::SubscribedAddresses,
    )>,
    // ext 0x0003/Implementation Notes: a block booked through a Stratum
    // sink's immediate apply must invalidate the published payout
    // distributions exactly like a JDP-declared one.
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
        crate::payout_resolver::solo_fee_config(cfg),
        membership.blockparty_service(),
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
        membership,
        sv1_resolver,
        dispatcher.clone(),
        Arc::clone(&device_status),
        Arc::clone(&live_sessions),
        job_cache.clone(),
        settle.clone(),
    )?;
    let noise_config = stratum_v2::build_noise_config(cfg)?;
    // SV2 miners and JD clients pin this key; this line is where an operator
    // reads it.
    info!(
        authority_pubkey = %noise_config.authority_pub(),
        "stratum-v2: authority public key"
    );
    // Warm the customer-extranonce cache before the servers start serving, then
    // it self-refreshes off PG. Shared across every SV2 port.
    let custom_extranonce: Arc<dyn bp_stratum_v2::hooks::CustomExtranonceSource> =
        crate::custom_extranonce::CustomExtranonceCache::spawn(foundation.db.pool().clone()).await;
    let sv2_servers = stratum_v2::build_per_port_servers(
        cfg,
        foundation,
        engines,
        membership,
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
        let task = tokio::spawn(accept_loop(
            listener,
            "stratum",
            sv1.port_config.port,
            cancel.clone(),
            move |socket, peer| {
                // Peeking and dispatching must not block subsequent accepts.
                let dispatch = dispatch.clone();
                tokio::spawn(async move {
                    dispatch_connection(socket, peer, dispatch).await;
                });
            },
        ));
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

/// The accept loop of every pool listener, stratum ports and JDP alike:
/// accepts until `cancel`, sets each socket's options with
/// [`tune_accepted_socket`] and hands it to `on_accept`, which must not block.
pub(crate) async fn accept_loop(
    listener: TcpListener,
    label: &'static str,
    port: u16,
    cancel: CancellationToken,
    mut on_accept: impl FnMut(TcpStream, std::net::SocketAddr),
) {
    // The wait after the last failed accept; see `accept_error_pause`.
    let mut pause: Option<Duration> = None;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                debug!(label, port, "accept-loop cancelled");
                break;
            }
            res = listener.accept() => match res {
                Ok((socket, peer)) => {
                    debug!(label, ?peer, port, "accepted");
                    tune_accepted_socket(&socket, peer, port);
                    on_accept(socket, peer);
                }
                Err(err) => {
                    pause = accept_error_pause(&err, pause);
                    warn!(%err, label, port, ?pause, "accept failed");
                    if let Some(pause) = pause {
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = tokio::time::sleep(pause) => {}
                        }
                    }
                    continue;
                }
            }
        }
        pause = None;
    }
}

/// First and longest wait of [`accept_error_pause`].
const ACCEPT_PAUSE_MIN: Duration = Duration::from_millis(5);
const ACCEPT_PAUSE_MAX: Duration = Duration::from_secs(1);

/// How long an accept loop waits after `err` before calling `accept()` again,
/// given the wait after the previous consecutive failure. Out of file
/// descriptors or kernel buffers, the pending connection stays queued and an
/// immediate retry fails the same way, spinning a core and the log; those
/// wait, doubling from [`ACCEPT_PAUSE_MIN`] to [`ACCEPT_PAUSE_MAX`]. Any other
/// error belongs to one connection and is retried at once (`None`).
fn accept_error_pause(err: &std::io::Error, previous: Option<Duration>) -> Option<Duration> {
    match err.raw_os_error() {
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM) => Some(
            previous
                .map_or(ACCEPT_PAUSE_MIN, |p| p.saturating_mul(2))
                .min(ACCEPT_PAUSE_MAX),
        ),
        _ => None,
    }
}

/// How long sent data may stay unacknowledged before the kernel drops the
/// connection. A peer that vanished without closing still gets jobs or
/// distributions, so keepalive never runs, and without this Linux
/// retransmits for `tcp_retries2` rounds before giving up.
#[cfg(target_os = "linux")]
const ACCEPTED_SOCKET_USER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(150);

/// Socket options every accepted connection gets, SV1, SV2 and JDP alike.
/// Failures are logged and the connection is served anyway.
fn tune_accepted_socket(socket: &TcpStream, peer: std::net::SocketAddr, port: u16) {
    // No Nagle: small latency-sensitive frames, and Nagle plus delayed ACK
    // adds ~40 ms per round-trip.
    if let Err(err) = socket.set_nodelay(true) {
        warn!(%err, ?peer, port, "set_nodelay(true) failed (continuing)");
    }
    // Keepalive keeps quiet connections in NAT/firewall tables and detects a
    // dead idle peer; it only probes a connection with nothing in flight, the
    // user timeout below covers the rest. The per-socket opt-in is required,
    // the sysctls only tune the timing.
    let keepalive = TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(60))
        .with_interval(std::time::Duration::from_secs(20))
        .with_retries(4);
    if let Err(err) = SockRef::from(socket).set_tcp_keepalive(&keepalive) {
        warn!(%err, ?peer, port, "set_tcp_keepalive(60s) failed (continuing)");
    }
    // Linux only (TCP_USER_TIMEOUT). With it set, the kernel also uses it
    // to close a connection whose keepalive probes go unanswered.
    #[cfg(target_os = "linux")]
    if let Err(err) = SockRef::from(socket).set_tcp_user_timeout(Some(ACCEPTED_SOCKET_USER_TIMEOUT))
    {
        warn!(%err, ?peer, port, "set_tcp_user_timeout failed (continuing)");
    }
}

/// Peek the opening bytes of `socket` and dispatch to the right server.
/// Closes the socket if detection does not finish within 30 s. The peek is
/// non-consuming: the server reads from byte 0 of the same socket. Any read
/// failure before dispatch closes the socket.
async fn dispatch_connection(
    socket: TcpStream,
    peer: std::net::SocketAddr,
    dispatch: PortDispatch,
) {
    let port = dispatch.sv1_port_config.port;
    let detected = match timeout(std::time::Duration::from_secs(30), peek_protocol(&socket)).await {
        Err(_) => {
            debug!(?peer, port, "stratum: detection timeout; closing");
            return;
        }
        Ok(Ok(Some(detected))) => detected,
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

/// What the opening bytes of an accepted connection say it speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Detected {
    /// SV1 JSON-RPC: a JSON object with string keys, optionally after
    /// whitespace.
    Sv1,
    /// SV2 (Noise handshake): everything the other variants don't claim.
    Sv2,
    /// HTTP request (`GET `, `POST`, `PUT `, `PATCH`). Not served on a
    /// stratum port; [`dispatch_connection`] logs a warning and closes.
    Http,
    /// TLS ClientHello (`0x16 0x03`). Closed right away.
    Tls,
}

/// Classify a connection by its opening bytes, `None` while undecided. An
/// SV2 connection opens with a pseudo-random EllSwift key (SV2 Protocol
/// Security) whose first byte can look like anything, so SV1, HTTP and TLS
/// are matched on a multi-byte opening and everything else is SV2.
fn detect(prefix: &[u8]) -> Option<Detected> {
    match *prefix.first()? {
        0x16 => Some(if *prefix.get(1)? == 0x03 {
            Detected::Tls
        } else {
            Detected::Sv2
        }),
        b'G' | b'P' => Some(
            if starts_with_any(prefix, &[b"GET ", b"POST", b"PUT ", b"PATCH"])? {
                Detected::Http
            } else {
                Detected::Sv2
            },
        ),
        b if is_json_whitespace(b) || b == b'{' => sv1_or_sv2(prefix),
        _ => Some(Detected::Sv2),
    }
}

fn is_json_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// SV1 messages are JSON objects with string keys: optional whitespace,
/// `{`, optional whitespace, `"`.
fn sv1_or_sv2(prefix: &[u8]) -> Option<Detected> {
    let mut bytes = prefix
        .iter()
        .copied()
        .skip_while(|b| is_json_whitespace(*b));
    if bytes.next()? != b'{' {
        return Some(Detected::Sv2);
    }
    Some(if bytes.find(|b| !is_json_whitespace(*b))? == b'"' {
        Detected::Sv1
    } else {
        Detected::Sv2
    })
}

/// `Some(true)` when `prefix` starts with one of `openings`, `Some(false)`
/// when it cannot, `None` while it is still a proper prefix of one.
fn starts_with_any(prefix: &[u8], openings: &[&[u8]]) -> Option<bool> {
    let mut undecided = false;
    for opening in openings {
        let n = prefix.len().min(opening.len());
        if prefix[..n] == opening[..n] {
            if prefix.len() >= opening.len() {
                return Some(true);
            }
            undecided = true;
        }
    }
    if undecided {
        None
    } else {
        Some(false)
    }
}

/// How many bytes detection may look at: one SV2 handshake opening.
const DETECT_PEEK_BYTES: usize = 64;

/// Peek at the opening bytes of `socket` until [`detect`] decides, without
/// consuming them. `Ok(None)` when the peer closed before sending anything.
async fn peek_protocol(socket: &TcpStream) -> std::io::Result<Option<Detected>> {
    let mut buf = [0u8; DETECT_PEEK_BYTES];
    loop {
        let n = socket.peek(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        if let Some(detected) = detect(&buf[..n]) {
            return Ok(Some(detected));
        }
        if n == buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "opening bytes match no protocol",
            ));
        }
        // `peek` returns at once while bytes are buffered, so wait before
        // looking again for the rest of the opening.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
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
    /// Subscribe BEFORE snapshotting: anything broadcast in between lands in
    /// both and the assembler dedupes on template_id. Every port carries ALL
    /// alt streams, because mode is per-address and a Group-Solo / Blockparty
    /// member on any port must be routable onto its stream.
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

    // ── accept backoff ──────────────────────────────────────────────

    /// Running out of descriptors or buffers waits, doubling up to the cap;
    /// an error that belongs to one connection is retried at once.
    #[test]
    fn accept_backs_off_only_on_resource_exhaustion() {
        let os = std::io::Error::from_raw_os_error;
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            let mut pause = None;
            let mut seen = Vec::new();
            for _ in 0..12 {
                pause = accept_error_pause(&os(errno), pause);
                seen.push(pause.expect("resource exhaustion must wait"));
            }
            assert_eq!(seen[0], ACCEPT_PAUSE_MIN, "errno {errno}");
            assert_eq!(seen[1], ACCEPT_PAUSE_MIN * 2, "errno {errno}");
            assert!(seen.windows(2).all(|w| w[0] <= w[1]), "errno {errno}");
            assert_eq!(*seen.last().unwrap(), ACCEPT_PAUSE_MAX, "errno {errno}");
        }
        for errno in [libc::ECONNABORTED, libc::EPROTO, libc::EPERM] {
            assert_eq!(
                accept_error_pause(&os(errno), Some(ACCEPT_PAUSE_MAX)),
                None,
                "errno {errno} is per-connection"
            );
        }
    }

    // ── socket options ──────────────────────────────────────────────

    /// A socket out of [`accept_loop`], the loop every listener runs, gives
    /// up on a peer that stops acknowledging after 150 s and has keepalive
    /// and no-delay. A socket accepted without it has none of them.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn accepted_sockets_get_the_user_timeout_keepalive_and_nodelay() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _raw_client = TcpStream::connect(addr).await.unwrap();
        let (raw, _) = listener.accept().await.unwrap();
        let raw = SockRef::from(&raw);
        assert_eq!(
            raw.tcp_user_timeout().unwrap(),
            None,
            "control: unset by default"
        );
        assert!(!raw.keepalive().unwrap(), "control: unset by default");

        let cancel = CancellationToken::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(accept_loop(
            listener,
            "test",
            addr.port(),
            cancel.clone(),
            move |socket, _| {
                let _ = tx.send(socket);
            },
        ));
        let _client = TcpStream::connect(addr).await.unwrap();
        let socket = rx.recv().await.unwrap();
        cancel.cancel();
        task.await.unwrap();

        let sock = SockRef::from(&socket);
        assert_eq!(
            sock.tcp_user_timeout().unwrap(),
            Some(ACCEPTED_SOCKET_USER_TIMEOUT)
        );
        assert_eq!(
            ACCEPTED_SOCKET_USER_TIMEOUT,
            std::time::Duration::from_secs(150)
        );
        assert!(sock.keepalive().unwrap());
        assert_eq!(
            sock.tcp_keepalive_time().unwrap(),
            std::time::Duration::from_secs(60)
        );
        assert!(socket.nodelay().unwrap());
    }

    // ── protocol detection ───────────────────────────────────────────

    #[test]
    fn sv1_openings_are_sv1() {
        for line in [
            &b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n"[..],
            b"{ \"id\": 1}",
            b"\n{\"id\":1}",
            b"\r\n {\"method\":\"mining.configure\"}",
        ] {
            assert_eq!(detect(line), Some(Detected::Sv1), "{line:?}");
        }
    }

    #[test]
    fn http_requests_are_http() {
        for req in [
            &b"GET / HTTP/1.1\r\n"[..],
            b"POST /api HTTP/1.1",
            b"PUT /x HTTP/1.1",
            b"PATCH /x HTTP/1.1",
        ] {
            assert_eq!(detect(req), Some(Detected::Http), "{req:?}");
        }
    }

    #[test]
    fn a_tls_client_hello_is_tls() {
        assert_eq!(detect(&[0x16, 0x03, 0x01, 0x02, 0x00]), Some(Detected::Tls));
    }

    /// A pseudo-random SV2 key whose first byte looks like SV1, HTTP or TLS is still SV2.
    #[test]
    fn an_sv2_key_starting_like_another_protocol_is_sv2() {
        for first in [b'{', b' ', b'\n', b'\r', b'G', b'P', 0x16] {
            let mut key = [0xa5u8; 64];
            key[0] = first;
            assert_eq!(
                detect(&key),
                Some(Detected::Sv2),
                "first byte 0x{first:02x}"
            );
        }
    }

    #[test]
    fn any_other_first_byte_is_sv2() {
        for first in [
            0x00, 0x01, 0x42, 0x80, 0xab, 0xfe, 0xff, b'A', b'H', b'T', b'Z',
        ] {
            let mut key = [0x5au8; 64];
            key[0] = first;
            assert_eq!(
                detect(&key),
                Some(Detected::Sv2),
                "first byte 0x{first:02x}"
            );
        }
    }

    /// Accept one connection on a local listener and run `peek_protocol` on
    /// it while `send` writes from the client side.
    async fn peek_over_tcp<F, Fut>(send: F) -> std::io::Result<Option<Detected>>
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client =
            tokio::spawn(async move { send(TcpStream::connect(addr).await.unwrap()).await });
        let (server, _) = listener.accept().await.unwrap();
        let detected =
            tokio::time::timeout(std::time::Duration::from_secs(5), peek_protocol(&server))
                .await
                .expect("detection finishes");
        client.await.unwrap();
        detected
    }

    /// Detection waits for the rest of an opening that arrives in pieces,
    /// and the peeked bytes stay unread for the server.
    #[tokio::test]
    async fn an_opening_split_across_writes_is_detected_once_complete() {
        use tokio::io::AsyncWriteExt;
        let detected = peek_over_tcp(|mut c| async move {
            c.write_all(b"{").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            c.write_all(b"\"id\":1}\n").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        })
        .await
        .unwrap();
        assert_eq!(detected, Some(Detected::Sv1));
    }

    #[tokio::test]
    async fn peek_protocol_ends_on_every_kind_of_opening() {
        use tokio::io::AsyncWriteExt;
        let mut key = [0xa5u8; 64];
        key[0] = b'{';
        let sv2 = peek_over_tcp(move |mut c| async move {
            c.write_all(&key).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        })
        .await
        .unwrap();
        assert_eq!(sv2, Some(Detected::Sv2));

        let closed = peek_over_tcp(|c| async move { drop(c) }).await.unwrap();
        assert_eq!(closed, None);

        let undecidable = peek_over_tcp(|mut c| async move {
            c.write_all(&[b' '; DETECT_PEEK_BYTES]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        })
        .await;
        assert!(undecidable.is_err(), "got {undecidable:?}");
    }

    /// A prefix that could still become SV1, HTTP or TLS waits for more bytes.
    #[test]
    fn an_undecided_prefix_asks_for_more() {
        for prefix in [
            &b""[..],
            b"{",
            b" ",
            b"\r\n",
            b"{ ",
            b"G",
            b"GE",
            b"GET",
            b"P",
            b"PO",
            b"PU",
            &[0x16],
        ] {
            assert_eq!(detect(prefix), None, "{prefix:?}");
        }
    }
}
