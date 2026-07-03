// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end regtest for the SV1 job/template lifecycle wiring.
//!
//! The translator drives `JobRegistry::cleanup_for_tip` on every
//! broadcast it emits. This test proves, against a real `bitcoin-node`
//! chain tip, that the wiring produces the full ckpool-style lifecycle
//! a real miner observes:
//!
//!   1. A share on the CURRENT job is accepted (`Active`).
//!   2. After an on-chain block, a prompt share on the PREVIOUS job is
//!      still accepted (`StaleCreditable` — inside the grace window).
//!   3. Past the grace window the same job is rejected as stale
//!      (wire code 21, reason "stale") — NOT silently credited.
//!   4. A share on the current-tip job keeps working regardless.
//!   5. Retired entries age out of the registry after retention — the
//!      maps stay bounded across block changes instead of growing
//!      monotonically (the memory leak this wiring fixes).
//!
//! Grace/retention are shortened (1.5s / 3s) so the test observes the
//! transitions without production-scale waits.
//!
//! Skipped (with a printed warning) when `bitcoin-node` is not installed
//! at the host's default location or via `BITCOIN_NODE_PATH`.

use std::time::Duration;

use bitcoin::Network;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_stratum_v1::{PortConfig, ServerConfig, ServerHooks, SharedExtranonce, StratumV1Server};
use bp_template_distribution::{TdpConfig, TdpHandle};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// Shortened lifecycle knobs — long enough to be race-proof on a slow
/// CI host, short enough to observe grace-expiry + aging in-test.
const GRACE_MS: u64 = 1_500;
const RETENTION_MS: u64 = 3_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv1_job_lifecycle_stale_and_pruning_against_regtest() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping SV1 job-lifecycle regtest — bitcoin-node not found at {} \
             (set BITCOIN_NODE_PATH to override)",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    // ── bitcoin-core + TDP boot (same sequence as regtest_lifecycle) ──
    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    let mut height = node
        .generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + coinbase maturity");

    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn against regtest IPC");
    let updates_rx = tdp.subscribe();

    height = generate_and_assert_height(&node, height).await;

    let mut server_config = ServerConfig::defaults_for(Network::Regtest);
    server_config.stale_grace_ms = GRACE_MS;
    server_config.job_retention_ms = RETENTION_MS;
    let server = StratumV1Server::spawn(
        server_config,
        updates_rx,
        bp_template_distribution::TemplateSnapshot::default(),
        Vec::new(),
        ServerHooks::no_op(),
        SharedExtranonce::new(),
    );

    wait_until(Duration::from_secs(5), || {
        server.current_template().is_some()
    })
    .await;
    assert!(server.current_template().is_some(), "no template within 5s");

    // ── miner connection (trivial difficulty → every submit passes) ──
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let port_config = PortConfig {
        target_shares_per_minute: 6.0,
        ..PortConfig::new(addr.port(), 1.0e-18)
    };
    let server_clone = server.clone();
    let pc = port_config.clone();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        socket.set_nodelay(true).ok();
        server_clone.accept_connection(socket, pc);
    });

    let miner = TcpStream::connect(addr).await.expect("connect");
    miner.set_nodelay(true).ok();
    let (read, mut write) = miner.into_split();
    let mut reader = BufReader::new(read);

    write
        .write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"lifecycle-miner/1.0\"]}\n")
        .await
        .expect("write subscribe");
    let _ = read_frame(&mut reader).await;
    write
        .write_all(
            format!(
                "{{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"{REGTEST_ADDR}.x\",\"x\"]}}\n"
            )
            .as_bytes(),
        )
        .await
        .expect("write authorize");

    // First job after the handshake.
    let (job1, ntime1) = wait_for_notify(&mut reader, false).await;

    // ── 1. Active: share on the current job is accepted ──────────────
    let resp = submit(&mut write, &mut reader, 3, &job1, &ntime1, "01020304").await;
    assert_eq!(
        resp.get("result").and_then(|v| v.as_bool()),
        Some(true),
        "active-job share must be accepted: {resp}"
    );

    // ── new on-chain block → clean-jobs notify → job1 is retired ─────
    height = generate_and_assert_height(&node, height).await;
    let (job2, ntime2) = wait_for_notify(&mut reader, true).await;
    assert_ne!(job1, job2, "block change must issue a fresh job id");

    // ── 2. StaleCreditable: prompt share on the OLD job still counts ──
    let resp = submit(&mut write, &mut reader, 4, &job1, &ntime1, "01020305").await;
    assert_eq!(
        resp.get("result").and_then(|v| v.as_bool()),
        Some(true),
        "old-tip share inside the grace window must be credited: {resp}"
    );

    // ── 3. StaleRejected: past grace the old job is refused ──────────
    tokio::time::sleep(Duration::from_millis(GRACE_MS + 700)).await;
    let resp = submit(&mut write, &mut reader, 5, &job1, &ntime1, "01020306").await;
    assert_ne!(
        resp.get("result").and_then(|v| v.as_bool()),
        Some(true),
        "old-tip share past grace must be rejected: {resp}"
    );
    let err = resp.get("error").expect("stale reject carries an error");
    assert!(!err.is_null(), "stale reject error must be non-null: {resp}");
    assert_eq!(
        err.get(0).and_then(|v| v.as_i64()),
        Some(21),
        "stale uses wire code 21: {resp}"
    );
    assert!(
        err.to_string().contains("stale"),
        "reject reason must be the distinct stale marker: {resp}"
    );

    // ── 4. The current-tip job keeps working ─────────────────────────
    let resp = submit(&mut write, &mut reader, 6, &job2, &ntime2, "01020307").await;
    assert_eq!(
        resp.get("result").and_then(|v| v.as_bool()),
        Some(true),
        "current-tip share must still be accepted: {resp}"
    );

    // ── 5. Aging bounds the registry across block changes ────────────
    // Three more blocks → three more clean-jobs notifies (each registers
    // a job + template row and retires the previous tip's).
    for _ in 0..3 {
        height = generate_and_assert_height(&node, height).await;
        let _ = wait_for_notify(&mut reader, true).await;
    }
    let registry = server.job_registry();
    let peak_jobs = registry.job_count();
    let peak_templates = registry.template_count();
    assert!(peak_jobs >= 4, "expected several jobs registered by now");

    // Let the earlier retirements pass retention, then one more block —
    // its broadcast runs the aging pass.
    tokio::time::sleep(Duration::from_millis(RETENTION_MS + 700)).await;
    let _final_height = generate_and_assert_height(&node, height).await;
    let _ = wait_for_notify(&mut reader, true).await;

    let final_jobs = registry.job_count();
    let final_templates = registry.template_count();
    assert!(
        final_jobs < peak_jobs,
        "aging must shrink the job map (peak {peak_jobs} → {final_jobs})"
    );
    assert!(
        final_templates < peak_templates,
        "aging must shrink the template map (peak {peak_templates} → {final_templates})"
    );
    assert!(
        final_jobs <= 6,
        "job map must stay bounded near the min-retained floor, got {final_jobs}"
    );

    eprintln!(
        "[job-lifecycle] jobs {peak_jobs}→{final_jobs}, templates \
         {peak_templates}→{final_templates}, height {_final_height}"
    );

    // ── teardown ──────────────────────────────────────────────────────
    drop(write);
    drop(reader);
    server.shutdown().await;
    tdp.shutdown().expect("TDP clean shutdown");
    node.shutdown().await.expect("regtest clean shutdown");
}

/// Mine one block and assert bitcoin-core's tip actually advanced —
/// every lifecycle transition in this test is anchored to a real
/// on-chain block, not a simulated broadcast.
async fn generate_and_assert_height(node: &RegtestNode, before: u32) -> u32 {
    let after = node.generate_to_self(1).await.expect("generate 1 block");
    assert_eq!(after, before + 1, "chain tip must advance by one");
    after
}

/// Read frames until a `mining.notify` arrives; when `require_clean` is
/// set, skip refresh notifies until one with `clean_jobs = true` (a real
/// block change) shows up. Returns `(job_id, ntime)`.
async fn wait_for_notify(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    require_clean: bool,
) -> (String, String) {
    let mut out = None;
    let _ = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let f = read_frame(reader).await;
            if f.get("method").and_then(|m| m.as_str()) == Some("mining.notify") {
                let params = f.get("params").and_then(|v| v.as_array()).expect("params");
                let clean = params[8].as_bool().unwrap_or(false);
                if !require_clean || clean {
                    out = Some((
                        params[0].as_str().expect("jobId").to_string(),
                        params[7].as_str().expect("ntime").to_string(),
                    ));
                    return;
                }
            }
        }
    })
    .await;
    out.expect("mining.notify within 8s")
}

/// Send a `mining.submit` and read frames until its response (matched by
/// id) arrives — interleaved notifies/set_difficulty are skipped.
async fn submit(
    write: &mut tokio::net::tcp::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    id: u64,
    job_id: &str,
    ntime: &str,
    nonce: &str,
) -> Value {
    let line = format!(
        "{{\"id\":{id},\"method\":\"mining.submit\",\"params\":[\"{REGTEST_ADDR}.x\",\"{job_id}\",\"0000000000000000\",\"{ntime}\",\"{nonce}\",\"00000000\"]}}\n"
    );
    write.write_all(line.as_bytes()).await.expect("write submit");
    let mut resp = None;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let f = read_frame(reader).await;
            if f.get("id").and_then(|v| v.as_u64()) == Some(id) {
                resp = Some(f);
                return;
            }
        }
    })
    .await;
    resp.unwrap_or_else(|| panic!("no response for submit id={id} within 5s"))
}

async fn wait_until<F: Fn() -> bool>(budget: Duration, cond: F) {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn read_frame(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Value {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await.expect("read line");
    assert!(n > 0, "server closed connection unexpectedly");
    serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("parse frame `{line}`: {e}"))
}
