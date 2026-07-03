// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: SV1 per-mode stream routing — Group-Solo (Phase 2).
//!
//! The Group-Solo counterpart of `regtest_solo_stream.rs`. Two tests share one
//! `run_scenario` driver. The routing test uses a 1-output coinbase and proves a
//! connection whose address resolves to GroupSolo is routed onto the dedicated
//! Group-Solo template stream by `run_connection`, and a block it finds is
//! submitted through the Group-Solo TDP handle and accepted by bitcoin-core. The
//! max-size test builds a realistic ~50-member multi-output coinbase (P2TR
//! outputs, the worst-case 172-WU output type) against the production Group-Solo
//! reservation (10 000 WU), proving the default `[group_fees].coinbase_weight_budget`
//! holds a max-size group as a VALID block bitcoin-core accepts — validating the
//! sizing end-to-end, not just routing.
//!
//! Both guard with a recording block-sink that captures the `StreamKind` of every
//! block-submit (`GroupSolo` proves the swap fired) plus the chain advancing
//! (proves the Group-Solo handle knew the job's `template_id`; template_ids
//! collide across streams, so a mis-routed submit would be rejected).

#![allow(clippy::print_stderr)]

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
/// ≈ tdp_constraint_for_budget(10_000 WU): 10_000/4 + 256. The production
/// Group-Solo reservation. Holds ~50 P2TR member outputs (50 × 43 B = 2150 B).
const GROUP_SOLO_RESERVATION_BYTES: u32 = 2_756;

/// Resolver that classifies every address as Group-Solo (so the connection must
/// be routed to the Group-Solo stream) and returns a fixed payout list — one
/// output (100% to the miner) for the routing test, or a multi-output split for
/// the max-size test.
struct GroupSoloResolver {
    payouts: Vec<PayoutEntry>,
}

#[async_trait]
impl PayoutResolver for GroupSoloResolver {
    async fn resolve_payouts(&self, _miner_address: &str, _reward_sats: u64) -> Vec<PayoutEntry> {
        self.payouts.clone()
    }

    fn resolve_stream(&self, _miner_address: &str) -> StreamKind {
        StreamKind::GroupSolo
    }
}

/// Block-sink that records the routed stream and submits the solution through
/// the matching TDP handle (mirrors the production `select_handle`).
struct RecordingAltSink {
    tdp: TdpHandle,
    tdp_alt: TdpHandle,
    recorded: Arc<Mutex<Vec<StreamKind>>>,
}

#[async_trait]
impl BlockSubmissionSink for RecordingAltSink {
    async fn submit_block(
        &self,
        accept: &ShareAccept,
        _address: &str,
        _worker: &str,
        _session_id: &str,
        stream: StreamKind,
    ) {
        self.recorded.lock().unwrap().push(stream);
        let handle = if stream == StreamKind::GroupSolo {
            &self.tdp_alt
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
async fn sv1_group_solo_connection_routes_to_group_solo_stream_and_block_accepted() {
    let Some(node) = start_node_or_skip("group-solo routing").await else {
        return;
    };
    // 1-output coinbase: full reward to the miner address.
    let payouts = vec![PayoutEntry {
        address: REGTEST_ADDR.to_string(),
        sats: 5_000_000_000,
    }];
    let (recorded, before, after) =
        run_scenario(&node, payouts, GROUP_SOLO_RESERVATION_BYTES).await;
    node.shutdown().await.ok();
    assert_routed_group_solo_and_landed(&recorded, before, after);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv1_group_solo_max_size_multi_output_coinbase_accepted() {
    let Some(node) = start_node_or_skip("group-solo max-size multi-output").await else {
        return;
    };
    // ~50 distinct P2TR (bech32m) members — the worst-case 172-WU output type —
    // each an equal split. 50 × 43 B = 2150 B of coinbase outputs, which must
    // fit the production 10 000-WU reservation (2756 B). This is the validity
    // proof for the documented "~50 members" capacity.
    const MEMBERS: usize = 50;
    let mut payouts = Vec::with_capacity(MEMBERS);
    for _ in 0..MEMBERS {
        let addr = node
            .new_address("bech32m")
            .await
            .expect("mint bech32m member address");
        payouts.push(PayoutEntry {
            address: addr,
            sats: 5_000_000_000 / MEMBERS as u64,
        });
    }
    let (recorded, before, after) =
        run_scenario(&node, payouts, GROUP_SOLO_RESERVATION_BYTES).await;
    node.shutdown().await.ok();
    eprintln!("[group-solo-multi] {MEMBERS}-output coinbase accepted: height {before} → {after}");
    assert_routed_group_solo_and_landed(&recorded, before, after);
}

/// Start a regtest node + mine 101 for IBD-exit + maturity, or return `None`
/// (and print a skip line) when bitcoin-node isn't installed.
async fn start_node_or_skip(label: &str) -> Option<RegtestNode> {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping SV1 {label} regtest — bitcoin-node not found at {}",
            cfg.bitcoin_node_path.display()
        );
        return None;
    }
    let node = RegtestNode::start_with(RegtestConfig::default())
        .await
        .expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + maturity");
    Some(node)
}

fn assert_routed_group_solo_and_landed(recorded: &[StreamKind], before: u32, after: u32) {
    eprintln!("[group-solo-stream] recorded streams = {recorded:?}, height {before} → {after}");
    assert!(
        recorded.contains(&StreamKind::GroupSolo),
        "block-submit must be routed via the Group-Solo stream (run_connection swap); recorded {recorded:?}"
    );
    assert!(
        recorded.iter().all(|s| *s == StreamKind::GroupSolo),
        "a Group-Solo connection must never submit via the Default stream; recorded {recorded:?}"
    );
    assert!(
        after > before,
        "bitcoin-core must accept the Group-Solo-stream block via the Group-Solo handle (height {before} → {after})"
    );
}

/// Spin up the two TDP streams (default + a Group-Solo stream reserved at
/// `alt_reservation_bytes`), the SV1 server with a `GroupSoloResolver(payouts)`
/// plus a recording sink, drive one miner through subscribe/authorize/submit
/// until a block lands, and return `(recorded streams, height before, after)`.
async fn run_scenario(
    node: &RegtestNode,
    payouts: Vec<PayoutEntry>,
    alt_reservation_bytes: u32,
) -> (Vec<StreamKind>, u32, u32) {
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
    let tdp_alt = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1)
            .with_coinbase_constraints(TdpCoinbaseConstraints {
                max_additional_size: alt_reservation_bytes,
                max_additional_sigops: 0,
            }),
    )
    .expect("spawn group-solo TDP");

    let updates_rx = tdp_default.subscribe();
    let alt_updates_rx = tdp_alt.subscribe();
    // Force a fresh template pair on both streams.
    node.generate_to_self(1)
        .await
        .expect("mine 1 for templates");

    let recorded: Arc<Mutex<Vec<StreamKind>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = RecordingAltSink {
        tdp: tdp_default.clone(),
        tdp_alt: tdp_alt.clone(),
        recorded: recorded.clone(),
    };
    let hooks = ServerHooks {
        block_sink: Arc::new(sink),
        payout_resolver: Arc::new(GroupSoloResolver { payouts }),
        ..ServerHooks::no_op()
    };

    let server = StratumV1Server::spawn(
        ServerConfig::defaults_for(Network::Regtest),
        updates_rx,
        tdp_default.current_snapshot(),
        vec![(
            StreamKind::GroupSolo,
            alt_updates_rx,
            tdp_alt.current_snapshot(),
        )],
        hooks,
        SharedExtranonce::new(),
        std::sync::Arc::new(bp_mining_job::MiningJobCache::new()),
    );

    // Wait until the Group-Solo stream has paired a template.
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
        .write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"gs-miner/1.0\"]}\n")
        .await
        .expect("write subscribe");
    let _ = read_frame(&mut reader).await;

    // authorize as the Group-Solo address → run_connection resolves GroupSolo +
    // swaps the stream.
    write
        .write_all(
            format!(
                "{{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"{REGTEST_ADDR}.x\",\"x\"]}}\n"
            )
            .as_bytes(),
        )
        .await
        .expect("write authorize");

    // Grab the first mining.notify (built from the Group-Solo template post-swap).
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

    // Submit nonces until the chain advances (a block landed via the Group-Solo
    // handle) or we exhaust the budget.
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
        let _ = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut reader)).await;
        if let Some(h) = poll_for_height(node, before + 1, Duration::from_secs(2)).await {
            landed = Some(h);
            break;
        }
    }

    drop(write);
    drop(reader);
    server.shutdown().await;
    tdp_default.shutdown().ok();
    tdp_alt.shutdown().ok();
    let after = landed.unwrap_or(before);
    let recorded = recorded.lock().unwrap().clone();
    (recorded, before, after)
}

// ── helpers (mirror regtest_solo_stream.rs) ──────────────────────────────

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
