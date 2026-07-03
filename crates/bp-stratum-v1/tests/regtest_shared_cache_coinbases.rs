// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: pool-wide MiningJob cache — per-finder coinbase distinctness
//! end-to-end.
//!
//! Three concurrent connections on ONE server (= one shared
//! `MiningJobCache`):
//!
//!   - miner A (address A) and miner B (address B) have DISTINCT payout
//!     sets — each `mining.notify` coinbase MUST pay its own finder. A
//!     cache-key regression (e.g. a field dropped from the job-key
//!     tuple) would serve miner B the job built for miner A, paying the
//!     wrong finder on a found block; this test is the end-to-end guard
//!     the in-crate unit tests can't provide.
//!   - miner C authorizes with miner A's address — its coinbase must be
//!     BYTE-IDENTICAL to A's (the shared build), proving the memoization
//!     actually engages through the full server path while job ids stay
//!     per-connection.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::consensus::Decodable;
use bitcoin::Network;
use bp_common::StreamKind;
use bp_mining_job::{address_to_script, MiningJobCache, PayoutEntry, EXTRANONCE_SLOT_LEN};
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_stratum_v1::{
    PayoutResolver, PortConfig, ServerConfig, ServerHooks, SharedExtranonce, StratumV1Server,
};
use bp_template_distribution::{TdpCoinbaseConstraints, TdpConfig, TdpHandle};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const ADDR_A: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const ADDR_B: &str = "bcrt1qyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zs4w3j0";

/// Pays 100% to the connecting address (per-finder distinct payout sets,
/// the Solo coinbase shape) while keeping every connection on the boot
/// (PPLNS) stream so all three ride the SAME template.
struct PayToSelfResolver;

#[async_trait]
impl PayoutResolver for PayToSelfResolver {
    async fn resolve_payouts(&self, miner_address: &str, reward_sats: u64) -> Vec<PayoutEntry> {
        vec![PayoutEntry {
            address: miner_address.to_string(),
            sats: reward_sats,
        }]
    }

    fn resolve_stream(&self, _miner_address: &str) -> StreamKind {
        StreamKind::Pplns
    }
}

struct Miner {
    write: tokio::net::tcp::OwnedWriteHalf,
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
}

impl Miner {
    async fn connect(addr: std::net::SocketAddr) -> Self {
        let socket = TcpStream::connect(addr).await.expect("connect");
        socket.set_nodelay(true).ok();
        let (read, write) = socket.into_split();
        Self {
            write,
            reader: BufReader::new(read),
        }
    }

    /// subscribe + authorize, then return (extranonce1, first notify).
    async fn handshake(&mut self, id_base: u64, address: &str) -> ([u8; 4], Value) {
        self.write
            .write_all(
                format!(
                    "{{\"id\":{id_base},\"method\":\"mining.subscribe\",\"params\":[\"cache-test/1.0\"]}}\n"
                )
                .as_bytes(),
            )
            .await
            .expect("write subscribe");
        let sub_resp = read_frame(&mut self.reader).await;
        let en1_hex = sub_resp["result"][1]
            .as_str()
            .expect("extranonce1 in subscribe response");
        let mut en1 = [0u8; 4];
        for (i, byte) in en1.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&en1_hex[i * 2..i * 2 + 2], 16).expect("hex extranonce1");
        }

        self.write
            .write_all(
                format!(
                    "{{\"id\":{},\"method\":\"mining.authorize\",\"params\":[\"{address}.x\",\"x\"]}}\n",
                    id_base + 1
                )
                .as_bytes(),
            )
            .await
            .expect("write authorize");

        let mut notify: Option<Value> = None;
        let _ = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let f = read_frame(&mut self.reader).await;
                if f.get("method").and_then(|m| m.as_str()) == Some("mining.notify") {
                    notify = Some(f);
                    return;
                }
            }
        })
        .await;
        (en1, notify.expect("mining.notify within 8s"))
    }
}

/// (job_id, coinb1 hex, coinb2 hex) from a mining.notify frame.
fn notify_coinbase_parts(notify: &Value) -> (String, String, String) {
    let params = notify
        .get("params")
        .and_then(|v| v.as_array())
        .expect("notify params");
    (
        params[0].as_str().expect("jobId").to_string(),
        params[2].as_str().expect("coinb1").to_string(),
        params[3].as_str().expect("coinb2").to_string(),
    )
}

/// Reassemble the full non-witness coinbase the miner would hash:
/// coinb1 + extranonce1 + extranonce2(zeros) + coinb2.
fn assemble_coinbase(coinb1: &str, en1: &[u8; 4], coinb2: &str) -> Vec<u8> {
    let mut full = hex::decode(coinb1).expect("coinb1 hex");
    full.extend_from_slice(en1);
    full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN - 4]);
    full.extend_from_slice(&hex::decode(coinb2).expect("coinb2 hex"));
    full
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv1_shared_cache_keeps_per_finder_coinbases_distinct() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping shared-cache regtest — bitcoin-node not found at {}",
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

    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1)
            .with_coinbase_constraints(TdpCoinbaseConstraints {
                max_additional_size: 50_000,
                max_additional_sigops: 0,
            }),
    )
    .expect("spawn TDP");
    let updates_rx = tdp.subscribe();
    node.generate_to_self(1).await.expect("mine 1 for template");

    let hooks = ServerHooks {
        payout_resolver: Arc::new(PayToSelfResolver),
        ..ServerHooks::no_op()
    };
    let job_cache = Arc::new(MiningJobCache::new());
    let server = StratumV1Server::spawn(
        ServerConfig::defaults_for(Network::Regtest),
        updates_rx,
        tdp.current_snapshot(),
        Vec::new(),
        hooks,
        SharedExtranonce::new(),
        job_cache.clone(),
    );
    wait_until(Duration::from_secs(8), || {
        server.current_template().is_some()
    })
    .await;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let port_config = PortConfig::new(addr.port(), 1.0);

    let server_clone = server.clone();
    let pc = port_config.clone();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            socket.set_nodelay(true).ok();
            server_clone.accept_connection(socket, pc.clone());
        }
    });

    let mut miner_a = Miner::connect(addr).await;
    let mut miner_b = Miner::connect(addr).await;
    let mut miner_c = Miner::connect(addr).await;
    let (en1_a, notify_a) = miner_a.handshake(10, ADDR_A).await;
    let (_en1_b, notify_b) = miner_b.handshake(20, ADDR_B).await;
    let (_en1_c, notify_c) = miner_c.handshake(30, ADDR_A).await;

    let (job_a, coinb1_a, coinb2_a) = notify_coinbase_parts(&notify_a);
    let (job_b, coinb1_b, coinb2_b) = notify_coinbase_parts(&notify_b);
    let (job_c, coinb1_c, coinb2_c) = notify_coinbase_parts(&notify_c);

    server.shutdown().await;
    tdp.shutdown().ok();
    node.shutdown().await.ok();

    // ── Distinctness: A and B have different payout sets — each
    // coinbase must pay ITS OWN finder. ──
    for (name, notify_addr, en1, coinb1, coinb2) in [
        ("A", ADDR_A, &en1_a, &coinb1_a, &coinb2_a),
        ("B", ADDR_B, &en1_a, &coinb1_b, &coinb2_b),
    ] {
        let full = assemble_coinbase(coinb1, en1, coinb2);
        let tx = bitcoin::Transaction::consensus_decode(&mut full.as_slice())
            .unwrap_or_else(|e| panic!("miner {name} coinbase must decode: {e}"));
        let expected = address_to_script(Network::Regtest, notify_addr)
            .expect("payout address parses")
            .into_bytes();
        assert_eq!(
            tx.output[0].script_pubkey.to_bytes(),
            expected,
            "miner {name}'s coinbase output must pay {notify_addr} — a shared-cache \
             key regression would pay the OTHER finder here"
        );
    }
    assert_ne!(
        coinb2_a, coinb2_b,
        "distinct payout sets must never share coinbase bytes"
    );

    // ── Sharing: C authorizes with A's address — same payout set, same
    // template → byte-identical coinbase from the shared cache, under a
    // per-connection job id. ──
    assert_eq!(
        (coinb1_a.as_str(), coinb2_a.as_str()),
        (coinb1_c.as_str(), coinb2_c.as_str()),
        "same payout set + template must produce the identical (memoized) coinbase"
    );
    assert_ne!(job_a, job_c, "job ids stay per-connection");
    assert_ne!(job_a, job_b);

    let stats = job_cache.stats();
    eprintln!(
        "[shared-cache] jobs_built={} job_hits={} outputs_built={} (jobs A={job_a} B={job_b} C={job_c})",
        stats.jobs_built, stats.job_hits, stats.outputs_built
    );
    assert!(
        stats.job_hits >= 1,
        "miner C's notify must be served from the cache (job_hits {})",
        stats.job_hits
    );
}

// ── helpers (mirrors regtest_solo_stream.rs) ────────────────────────

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
