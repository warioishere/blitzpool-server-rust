// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: SV1 per-mode stream routing (Phase 1).
//!
//! Proves the validity-critical behaviour that unit tests can't: a connection
//! whose address resolves to **Solo** is routed onto the dedicated Solo
//! template stream (small fixed reservation) by `run_connection`, and a block
//! it finds is submitted through the **Solo TDP handle** and accepted by
//! bitcoin-core.
//!
//! Two independent guards make the proof tight:
//!   1. A recording block-sink captures the `StreamKind` of every block-submit.
//!      `Solo` proves `run_connection` switched (`state.stream`); had the swap
//!      not fired it would record `Default` and the test fails.
//!   2. The recording sink submits to the handle the stream names; the chain
//!      advancing proves the Solo handle actually knew the job's `template_id`
//!      (template_ids collide across streams, so a mis-routed submit would be
//!      rejected and the height would not move).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::Network;
use bp_common::StreamKind;
use bp_mining_job::PayoutEntry;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_stratum_v1::{
    BlockSubmissionSink, PayoutResolver, PortConfig, ServerConfig, ServerHooks, ShareAccept,
    SharedExtranonce, StratumV1Server,
};
use bp_template_distribution::{TdpCoinbaseConstraints, TdpConfig, TdpHandle};
use bp_test_support::poll_for_height;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// Resolver that classifies every address as Solo — so the connection must be
/// routed to the Solo stream — and pays the whole reward to that address
/// (a 1-output coinbase, which always fits the tiny Solo reservation).
struct SoloResolver;

#[async_trait]
impl PayoutResolver for SoloResolver {
    async fn resolve_payouts(&self, miner_address: &str, reward_sats: u64) -> Vec<PayoutEntry> {
        vec![PayoutEntry {
            address: miner_address.to_string(),
            sats: reward_sats,
        }]
    }

    fn resolve_stream(&self, _miner_address: &str) -> StreamKind {
        StreamKind::Solo
    }
}

/// Block-sink that records the routed stream and submits the solution through
/// the matching TDP handle (mirrors the production `select_handle`).
struct RecordingSoloSink {
    tdp: TdpHandle,
    tdp_solo: TdpHandle,
    recorded: Arc<Mutex<Vec<StreamKind>>>,
}

#[async_trait]
impl BlockSubmissionSink for RecordingSoloSink {
    async fn submit_block(
        &self,
        accept: &ShareAccept,
        _address: &str,
        _worker: &str,
        _session_id: &str,
        stream: StreamKind,
    ) {
        self.recorded.lock().unwrap().push(stream);
        let handle = if stream == StreamKind::Solo {
            &self.tdp_solo
        } else {
            &self.tdp
        };
        let header = &accept.header;
        let version = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let header_timestamp = u32::from_le_bytes([header[68], header[69], header[70], header[71]]);
        let header_nonce = u32::from_le_bytes([header[76], header[77], header[78], header[79]]);
        let coinbase_tx = accept
            .mining_job
            .witness_coinbase_with_extranonce(&accept.enonce1, &accept.extranonce2);
        let _ = handle
            .submit_solution(
                accept.template.template_id,
                version,
                header_timestamp,
                header_nonce,
                coinbase_tx,
            )
            .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv1_solo_connection_routes_to_solo_stream_and_block_accepted() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping SV1 solo-stream regtest — bitcoin-node not found at {}",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    let node = RegtestNode::start_with(RegtestConfig::default())
        .await
        .expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + maturity");

    // Two TDP streams against the same node: Solo (tiny reservation) + default.
    let tdp_default = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1)
            .with_coinbase_constraints(TdpCoinbaseConstraints {
                max_additional_size: 50_000,
                max_additional_sigops: 0,
            }),
    )
    .expect("spawn default TDP");
    let tdp_solo = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1)
            .with_coinbase_constraints(TdpCoinbaseConstraints {
                max_additional_size: 1_000, // tiny — Solo coinbase only
                max_additional_sigops: 0,
            }),
    )
    .expect("spawn solo TDP");

    let updates_rx = tdp_default.subscribe();
    let solo_updates_rx = tdp_solo.subscribe();
    // Force a fresh template pair on both streams.
    node.generate_to_self(1)
        .await
        .expect("mine 1 for templates");

    let recorded: Arc<Mutex<Vec<StreamKind>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = RecordingSoloSink {
        tdp: tdp_default.clone(),
        tdp_solo: tdp_solo.clone(),
        recorded: recorded.clone(),
    };
    let hooks = ServerHooks {
        block_sink: Arc::new(sink),
        payout_resolver: Arc::new(SoloResolver),
        ..ServerHooks::no_op()
    };

    let server = StratumV1Server::spawn(
        ServerConfig::defaults_for(Network::Regtest),
        updates_rx,
        tdp_default.current_snapshot(),
        vec![(
            StreamKind::Solo,
            solo_updates_rx,
            tdp_solo.current_snapshot(),
        )],
        hooks,
        SharedExtranonce::new(),
        std::sync::Arc::new(bp_mining_job::MiningJobCache::new()),
    );

    // Wait until the Solo stream has paired a template (that's the one the
    // connection switches onto).
    wait_until(Duration::from_secs(8), || {
        server.current_template().is_some()
    })
    .await;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    // Trivial session difficulty → every submit is an accepted share; ~50% of
    // nonces also clear the (easy) regtest network target → block candidates.
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

    // subscribe
    write
        .write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"solo-miner/1.0\"]}\n")
        .await
        .expect("write subscribe");
    let sub_resp = read_frame(&mut reader).await;
    // The extranonce1 (result[1]) the pool hands the miner must come from
    // the pool-wide collision-free allocator's SV1 partition (worker 1 →
    // top byte 0x01), NOT from the random session id. The block that lands
    // below is reconstructed from this exact extranonce1, so its acceptance
    // by bitcoin-core proves the allocated-prefix path yields valid blocks.
    let en1 = sub_resp["result"][1]
        .as_str()
        .expect("extranonce1 in subscribe response");
    assert_eq!(en1.len(), 8, "extranonce1 is 4 bytes / 8 hex chars: {en1}");
    assert!(
        en1.starts_with("01"),
        "SV1 extranonce1 must be allocated from worker 1 (0x01…), got {en1}"
    );

    // authorize as the Solo address → run_connection resolves Solo + swaps stream.
    write
        .write_all(
            format!(
                "{{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"{REGTEST_ADDR}.x\",\"x\"]}}\n"
            )
            .as_bytes(),
        )
        .await
        .expect("write authorize");

    // Grab the first mining.notify (built from the Solo template post-switch).
    let mut notify: Option<Value> = None;
    let _ = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let f = read_frame(&mut reader).await;
            if f.get("method").and_then(|m| m.as_str()) == Some("mining.notify") {
                notify = Some(f);
                return;
            }
        }
    })
    .await;
    let notify = notify.expect("mining.notify within 8s");
    let params = notify
        .get("params")
        .and_then(|v| v.as_array())
        .expect("params");
    let job_id_hex = params[0].as_str().expect("jobId").to_string();
    let ntime_hex = params[7].as_str().expect("ntime").to_string();

    // Submit nonces until the chain advances (a block landed via the Solo
    // handle) or we exhaust the budget. ~50% of nonces are block candidates on
    // regtest, so this lands within a few iterations.
    let before = node.current_height().await.expect("height");
    let mut landed = None;
    for nonce in 0u32..64 {
        let line = format!(
            "{{\"id\":{},\"method\":\"mining.submit\",\"params\":[\"{REGTEST_ADDR}.x\",\"{job_id_hex}\",\"0000000000000000\",\"{ntime_hex}\",\"{nonce:08x}\",\"00000000\"]}}\n",
            100 + nonce
        );
        write
            .write_all(line.as_bytes())
            .await
            .expect("write submit");
        // Drain the submit response (id 100+nonce). Best-effort.
        let _ = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut reader)).await;
        if let Some(h) = poll_for_height(&node, before + 1, Duration::from_secs(2)).await {
            landed = Some(h);
            break;
        }
    }

    drop(write);
    drop(reader);
    server.shutdown().await;
    tdp_default.shutdown().ok();
    tdp_solo.shutdown().ok();
    let after = landed.unwrap_or(before);
    let recorded = recorded.lock().unwrap().clone();
    node.shutdown().await.ok();

    eprintln!("[solo-stream] recorded streams = {recorded:?}, height {before} → {after}");
    assert!(
        recorded.contains(&StreamKind::Solo),
        "block-submit must be routed via the Solo stream (run_connection swap); recorded {recorded:?}"
    );
    assert!(
        recorded.iter().all(|s| *s == StreamKind::Solo),
        "a Solo connection must never submit via the Default stream; recorded {recorded:?}"
    );
    assert!(
        after > before,
        "bitcoin-core must accept the Solo-stream block via the Solo handle (height {before} → {after})"
    );
}

// ── helpers (mirrors regtest_lifecycle.rs) ──────────────────────────────

async fn read_frame(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read line");
    serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("parse frame `{line}`: {e}"))
}

async fn wait_until<F: Fn() -> bool>(budget: Duration, cond: F) {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
