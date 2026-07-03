// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end regtest test for the SV1 server.
//!
//! Spawns a real `bitcoin-node v31` via `bp_regtest_harness`, attaches
//! `bp_template_distribution::TdpHandle` to its IPC socket, runs an
//! [`bp_stratum_v1::StratumV1Server`] driven by the TDP broadcast, and
//! exercises the full SV1 handshake + share-submission path against a
//! fake miner connected over a real `TcpStream`.
//!
//! Covers (in one test):
//!   1. Translator pairs `NewTemplate` + `SetNewPrevHash` from real
//!      bitcoin-core IPC traffic into an `ActiveSV1Template`.
//!   2. `accept_connection` boots the per-connection task; subscribe +
//!      authorize cycle works end-to-end on a real socket.
//!   3. A `mining.notify` frame arrives within the handshake window.
//!   4. A `mining.submit` against a deliberately-trivial session
//!      difficulty produces a `result: true` success reply (the entire
//!      header-assembly / hash / target-check / `effective_job_difficulty`
//!      clamp / dedup-set path fires).
//!   5. `shutdown()` cleanly cancels the translator + the connection task.
//!
//! Skipped (with a printed warning) when `bitcoin-node` is not installed
//! at the host's default location or via `BITCOIN_NODE_PATH`.

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

/// Regtest bech32 address — `address_to_script(Network::Regtest, …)`
/// accepts this. Used by the fake miner's `mining.authorize` call.
const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv1_server_end_to_end_against_regtest() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping SV1 e2e — bitcoin-node not found at {} (set BITCOIN_NODE_PATH \
             to override)",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    // ── Bring up bitcoin-core + mine past IBD ─────────────────────────
    //
    // 101 blocks: exits IBD AND matures the genesis-coinbase so the
    // wallet can produce more blocks without "Spending genesis is not
    // allowed". Same boot sequence the TDP / JDP e2e tests use.
    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 blocks for IBD-exit + coinbase maturity");

    // ── Spawn TDP, subscribe FIRST, then force a template emission ────
    //
    // `tokio::sync::broadcast` does not replay messages sent before
    // any receiver existed. Subscribe BEFORE mining the template-forcing
    // block, otherwise the `TemplateUpdate` can be dropped on the floor
    // before our `subscribe()` call wires a receiver, leaving the server
    // with no template and the test hanging until timeout. Mirror the
    // ordering used in `bp-mining-job/tests/regtest_e2e.rs`.
    //
    // Low fee threshold + 1s interval makes regtest's empty mempool emit
    // a fresh NewTemplate roughly every block change.
    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn against regtest IPC");
    let updates_rx = tdp.subscribe();

    // Mine one more block to force a NewTemplate + SetNewPrevHash pair
    // through the broadcast — the assembler then pairs them as soon as
    // the server starts, so the first miner's `subscribe` lands a
    // `mining.notify` immediately.
    node.generate_to_self(1)
        .await
        .expect("mine 1 more to force TDP emit");
    let mut server_config = ServerConfig::defaults_for(Network::Regtest);
    // Lower the difficulty-check interval so the test can observe the
    // pipeline without waiting for the production 60 s timer.
    server_config.difficulty_check_interval_ms = 200;
    assert_eq!(server_config.pool_identifier, DEFAULT_POOL_IDENTIFIER);
    let server = StratumV1Server::spawn(
        server_config,
        updates_rx,
        bp_template_distribution::TemplateSnapshot::default(),
        // No alt streams — this test exercises the default-stream lifecycle only.
        Vec::new(),
        ServerHooks::no_op(),
        SharedExtranonce::new(),
    );

    // Wait until the translator has paired its first template. 5 s is
    // generous — the broadcast already has the messages queued from the
    // mine-1 call above.
    wait_until(Duration::from_secs(5), || {
        server.current_template().is_some()
    })
    .await;
    assert!(
        server.current_template().is_some(),
        "translator must have an active template before we accept the miner connection",
    );

    // ── Bind a TCP port + accept loop on a dedicated task ─────────────
    //
    // Bind to port 0 so the OS picks a free one — avoids collisions on
    // CI runners.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local_addr");

    // Deliberately-trivial port: initial_difficulty = 1e-18 → vardiff
    // target saturates to all-FFs in `bp_share::difficulty_to_target`, so
    // any submission hash trivially meets it. Lets us submit a fixed
    // nonce and assert acceptance without brute-forcing.
    let port_config = PortConfig {
        target_shares_per_minute: 6.0,
        ..PortConfig::new(addr.port(), 1.0e-18)
    };

    // Accept exactly one connection then return. The SV1 server's
    // accept_connection consumes the socket; we discard the resulting
    // JoinHandle (the cancel token attached to the server cleans it up
    // on shutdown).
    let server_clone = server.clone();
    let port_config_clone = port_config.clone();
    let accept_handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        // Disable Nagle so test frames don't sit in TCP buffers.
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

    // Step 2: authorize. Since we connected AFTER mining-1, the server
    // already has a template; this authorize MAY also produce an
    // immediate fresh notify per the "send fresh notify after authorize
    // if stratum is initialized" path. We read frames opportunistically.
    write
        .write_all(
            format!(
                "{{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"{REGTEST_ADDR}.fake\",\"x\"]}}\n"
            )
            .as_bytes(),
        )
        .await
        .expect("write authorize");

    // Step 3: drain frames until we have both the authorize response AND
    // a mining.notify in hand. The order isn't fixed: the server may
    // emit set_difficulty + mining.notify (init-flush after subscribe)
    // BEFORE the authorize response. Budget 5 s.
    let mut notify_frame: Option<Value> = None;
    let mut authorize_resp: Option<Value> = None;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = read_frame(&mut reader).await;
            match frame.get("method").and_then(|m| m.as_str()) {
                Some("mining.notify") => notify_frame = Some(frame),
                Some("mining.set_difficulty") => continue, // not needed for the test
                _ => {
                    // Has `id` and `result`/`error` → it's a response.
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

    // Step 4: submit. Fixed nonce / extranonce2 — diff is 1e-18 so any
    // hash will hit. version_mask = "00000000" (no version-rolling).
    let submit_line = format!(
        "{{\"id\":3,\"method\":\"mining.submit\",\"params\":[\"{REGTEST_ADDR}.fake\",\"{job_id_hex}\",\"0000000000000000\",\"{ntime_hex}\",\"01020304\",\"00000000\"]}}\n"
    );
    write
        .write_all(submit_line.as_bytes())
        .await
        .expect("write submit");

    // Step 5: read frames until we see the submit response (id=3) OR a
    // mining.notify that interleaves. Budget 5 s.
    let mut submit_resp: Option<Value> = None;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = read_frame(&mut reader).await;
            if frame.get("id").and_then(|v| v.as_u64()) == Some(3) {
                submit_resp = Some(frame);
                return;
            }
            // Otherwise ignore (could be another mining.notify if the
            // chain advanced again, or a set_difficulty from vardiff).
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
    //
    // 1. Drop the miner side first so the server's connection task gets
    //    EOF and exits its read loop.
    drop(write);
    drop(reader);
    // 2. Cancel + join translator.
    server.shutdown().await;
    // 3. Drop TDP worker.
    tdp.shutdown().expect("TDP clean shutdown");
    // 4. Stop bitcoin-node.
    node.shutdown().await.expect("regtest clean shutdown");

    // Sanity: the accept-loop task should have exited by now.
    let _ = accept_handle.await;

    // Sanity: the registry held at least one template + one job from
    // the handshake.
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
