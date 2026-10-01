// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: the SV1 server driven by real TDP traffic completes subscribe,
//! authorize, notify and an accepted submit over a real socket, then shuts
//! down cleanly. Skipped when `bitcoin-node` is not installed.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::Network;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_stratum_v1::{
    PortConfig, ServerConfig, ServerHooks, SharedExtranonce, StratumV1Server,
    DEFAULT_POOL_IDENTIFIER,
};
use bp_template_distribution::{TdpConfig, TdpHandle};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// A valid regtest address for the fake miner's `mining.authorize`.
const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv1_server_end_to_end_against_regtest() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!("skipping SV1 e2e — {}", cfg.unavailable_reason());
        return;
    }

    // ── Bring up bitcoin-core + mine past IBD ─────────────────────────
    // 101 blocks: exit IBD and mature a coinbase.
    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 blocks for IBD-exit + coinbase maturity");

    // ── Spawn TDP, subscribe FIRST, then force a template emission ────
    // The broadcast does not replay to late receivers, so subscribing after
    // the template-forcing block would leave the server without a template.
    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn against regtest IPC");
    let updates_rx = tdp.subscribe();

    node.generate_to_self(1)
        .await
        .expect("mine 1 more to force TDP emit");
    let mut server_config = ServerConfig::defaults_for(Network::Regtest);
    server_config.difficulty_check_interval_ms = 200;
    assert_eq!(server_config.pool_identifier, DEFAULT_POOL_IDENTIFIER);
    let server = StratumV1Server::spawn(
        server_config,
        updates_rx,
        bp_template_distribution::TemplateSnapshot::default(),
        Vec::new(),
        ServerHooks::no_op(),
        SharedExtranonce::new(),
        std::sync::Arc::new(bp_mining_job::MiningJobCache::new()),
    );

    wait_until(Duration::from_secs(5), || {
        server.current_template().is_some()
    })
    .await;
    assert!(
        server.current_template().is_some(),
        "translator must have an active template before we accept the miner connection",
    );

    // ── Bind a TCP port + accept loop on a dedicated task ─────────────
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local_addr");

    // Difficulty 1e-18 saturates the target, so a fixed nonce is accepted.
    let port_config = PortConfig {
        target_shares_per_minute: 6.0,
        ..PortConfig::new(addr.port(), 1.0e-18)
    };

    // Accept exactly one connection; the server's cancel token cleans up
    // the connection task on shutdown.
    let server_clone = server.clone();
    let port_config_clone = port_config.clone();
    let accept_handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        socket.set_nodelay(true).ok();
        server_clone.accept_connection(socket, port_config_clone);
    });

    // ── Fake miner: SV1 handshake + submit ────────────────────────────
    let miner = TcpStream::connect(addr).await.expect("connect to server");
    miner.set_nodelay(true).ok();
    let (read, mut write) = miner.into_split();
    let mut reader = BufReader::new(read);

    // Step 1: subscribe.
    write
        .write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"fake-miner/1.0\"]}\n")
        .await
        .expect("write subscribe");
    let subscribe_resp = read_frame(&mut reader).await;
    assert!(
        subscribe_resp.get("error").is_some_and(|v| v.is_null()),
        "subscribe response must have null error: {subscribe_resp}"
    );
    let result = subscribe_resp
        .get("result")
        .and_then(|v| v.as_array())
        .expect("subscribe result must be a 3-tuple");
    let extranonce1_hex = result[1].as_str().expect("extranonce1 hex").to_string();
    assert_eq!(result[2].as_u64(), Some(8), "extranonce2_size must be 8");

    // Step 2: authorize.
    write
        .write_all(
            format!(
                "{{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"{REGTEST_ADDR}.fake\",\"x\"]}}\n"
            )
            .as_bytes(),
        )
        .await
        .expect("write authorize");

    // Step 3: drain until both the authorize response and a notify are in;
    // the notify may arrive before the response.
    let mut notify_frame: Option<Value> = None;
    let mut authorize_resp: Option<Value> = None;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = read_frame(&mut reader).await;
            match frame.get("method").and_then(|m| m.as_str()) {
                Some("mining.notify") => notify_frame = Some(frame),
                Some("mining.set_difficulty") => continue, // not needed for the test
                _ => {
                    if frame.get("id").and_then(|v| v.as_u64()) == Some(2) {
                        authorize_resp = Some(frame);
                    }
                }
            }
            if authorize_resp.is_some() && notify_frame.is_some() {
                return;
            }
        }
    })
    .await;

    let authorize_resp = authorize_resp.expect("authorize response within 5s");
    assert!(
        authorize_resp.get("error").is_some_and(|v| v.is_null()),
        "authorize must not error: {authorize_resp}"
    );
    assert_eq!(
        authorize_resp.get("result").and_then(|v| v.as_bool()),
        Some(true),
        "authorize result must be true: {authorize_resp}"
    );

    let notify = notify_frame.expect("mining.notify within 5s");
    let params = notify
        .get("params")
        .and_then(|v| v.as_array())
        .expect("notify params");
    assert_eq!(params.len(), 9, "mining.notify params must be 9 elements");
    let job_id_hex = params[0].as_str().expect("jobId hex").to_string();
    let ntime_hex = params[7].as_str().expect("ntime hex").to_string();

    // Step 4: submit a fixed nonce without version rolling.
    let submit_line = format!(
        "{{\"id\":3,\"method\":\"mining.submit\",\"params\":[\"{REGTEST_ADDR}.fake\",\"{job_id_hex}\",\"0000000000000000\",\"{ntime_hex}\",\"01020304\",\"00000000\"]}}\n"
    );
    write
        .write_all(submit_line.as_bytes())
        .await
        .expect("write submit");

    // Step 5: read until the submit response, skipping interleaved frames.
    let mut submit_resp: Option<Value> = None;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = read_frame(&mut reader).await;
            if frame.get("id").and_then(|v| v.as_u64()) == Some(3) {
                submit_resp = Some(frame);
                return;
            }
        }
    })
    .await;

    let submit_resp = submit_resp.expect("submit response within 5s");
    assert!(
        submit_resp.get("error").is_some_and(|v| v.is_null()),
        "submit must not error: {submit_resp}\n\
         (notify jobid=`{job_id_hex}`, ntime=`{ntime_hex}`, extranonce1=`{extranonce1_hex}`)"
    );
    assert_eq!(
        submit_resp.get("result").and_then(|v| v.as_bool()),
        Some(true),
        "submit must succeed at trivial difficulty: {submit_resp}"
    );

    // ── Clean teardown ────────────────────────────────────────────────
    // Drop the miner first so the connection task sees EOF.
    drop(write);
    drop(reader);
    server.shutdown().await;
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");

    let _ = accept_handle.await;

    let registry = server.job_registry().clone();
    assert!(registry.template_count() >= 1, "expected ≥ 1 template");
    assert!(registry.job_count() >= 1, "expected ≥ 1 job");
    let _ = Arc::strong_count(&registry); // keep the import alive
}

/// Spin-wait until `cond` returns true OR the `timeout` elapses.
async fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut cond: F) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Read one `\n`-terminated JSON-RPC frame from the miner-side reader.
async fn read_frame<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Value {
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .await
        .expect("read_line from server");
    assert!(n > 0, "server closed connection before sending frame");
    serde_json::from_str(line.trim())
        .unwrap_or_else(|e| panic!("server emitted non-JSON frame: `{}` ({})", line.trim(), e))
}
