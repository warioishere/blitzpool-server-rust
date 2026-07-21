// SPDX-License-Identifier: AGPL-3.0-or-later

//! Load test — measures **Segment 2** of the stratum-race latency: from a new
//! block (`SetNewPrevHash`) to `mining.notify` delivered to N connected miners.
//!
//! Not a pass/fail correctness test — it prints a latency distribution so we can
//! see whether the fan-out serialises (last miner much later than the first) or
//! stays flat as N grows. Run it directly:
//!
//! ```text
//! cargo test -p bp-stratum-v1 --test regtest_notify_fanout_loadtest -- --nocapture --test-threads=1
//! LOADTEST_SIZES=100,500,1000 cargo test ... --nocapture   # custom N set
//! ```
//!
//! The absolute numbers include the block-mine RPC + Core→TDP IPC hop (shared
//! across all miners); the **spread** (max − min) isolates the per-connection
//! broadcast cost, which is what a lean C connector (ckpool) would beat us on.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bitcoin::Network;
use bp_common::StreamKind;
use bp_mining_job::PayoutEntry;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_stratum_v1::{
    PayoutResolver, PortConfig, ServerConfig, ServerHooks, SharedExtranonce, StratumV1Server,
};
use bp_template_distribution::{TdpCoinbaseConstraints, TdpConfig, TdpHandle};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// Routes every connection onto the Solo stream, 1-output coinbase.
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

async fn read_frame(reader: &mut BufReader<OwnedReadHalf>) -> Option<Value> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await.ok()?;
    if n == 0 {
        return None; // EOF
    }
    serde_json::from_str::<Value>(&line).ok()
}

fn prevhash_of_notify(f: &Value) -> Option<String> {
    if f.get("method").and_then(|m| m.as_str()) != Some("mining.notify") {
        return None;
    }
    f.get("params")?
        .as_array()?
        .get(1)?
        .as_str()
        .map(String::from)
}

/// Connect `n` miners, get each to a baseline `mining.notify`, then mine one
/// block and record — per miner — the elapsed from the block trigger to the
/// first `mining.notify` carrying a *new* prev-hash. Returns (connected, samples_us).
async fn measure(node: &RegtestNode, addr: SocketAddr, n: usize) -> (usize, Vec<u128>) {
    // Set once, immediately before the block trigger; read by each miner task.
    let t0: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let (sample_tx, mut sample_rx) = mpsc::channel::<Option<u128>>(n.max(1));
    let (ready_tx, mut ready_rx) = mpsc::channel::<()>(n.max(1));

    for i in 0..n {
        let sample_tx = sample_tx.clone();
        let ready_tx = ready_tx.clone();
        let t0 = t0.clone();
        tokio::spawn(async move {
            let stream = match TcpStream::connect(addr).await {
                Ok(s) => s,
                Err(_) => {
                    let _ = sample_tx.send(None).await;
                    return;
                }
            };
            stream.set_nodelay(true).ok();
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);

            if write
                .write_all(
                    format!(
                        "{{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"load/{i}\"]}}\n"
                    )
                    .as_bytes(),
                )
                .await
                .is_err()
            {
                let _ = sample_tx.send(None).await;
                return;
            }
            let _ = read_frame(&mut reader).await; // subscribe response
            let _ = write
                .write_all(
                    format!(
                        "{{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"{REGTEST_ADDR}.{i}\",\"x\"]}}\n"
                    )
                    .as_bytes(),
                )
                .await;

            // Baseline: read until the first notify → remember its prev-hash.
            let baseline = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    match read_frame(&mut reader).await {
                        Some(f) => {
                            if let Some(ph) = prevhash_of_notify(&f) {
                                return Some(ph);
                            }
                        }
                        None => return None,
                    }
                }
            })
            .await;
            let baseline_prev = match baseline {
                Ok(Some(ph)) => ph,
                _ => {
                    let _ = sample_tx.send(None).await;
                    return;
                }
            };
            let _ = ready_tx.send(()).await;

            // Wait for a notify with a *different* prev-hash (the new block).
            // Mempool refreshes keep the same prev-hash → correctly ignored.
            let got = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    match read_frame(&mut reader).await {
                        Some(f) => {
                            if let Some(ph) = prevhash_of_notify(&f) {
                                if ph != baseline_prev {
                                    let started = *t0.lock().unwrap();
                                    return started.map(|s| s.elapsed().as_micros());
                                }
                            }
                        }
                        None => return None,
                    }
                }
            })
            .await;
            let _ = sample_tx.send(got.ok().flatten()).await;
        });
    }
    drop(sample_tx);
    drop(ready_tx);

    // Wait until every miner has its baseline (or the channel drains).
    let mut connected = 0usize;
    while connected < n {
        match tokio::time::timeout(Duration::from_secs(60), ready_rx.recv()).await {
            Ok(Some(())) => connected += 1,
            _ => break,
        }
    }
    // Let the connections settle so the block-notify isn't racing a mid-connect.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Trigger: capture the origin, then mine one block.
    *t0.lock().unwrap() = Some(Instant::now());
    node.generate_to_self(1)
        .await
        .expect("mine block for fan-out");

    // Collect one result per spawned miner task.
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        // A failed / timed-out miner yields no sample and is simply excluded
        // from the distribution (the `connected` count reports the shortfall).
        if let Ok(Some(Some(us))) =
            tokio::time::timeout(Duration::from_secs(60), sample_rx.recv()).await
        {
            samples.push(us);
        }
    }
    (connected, samples)
}

fn pct(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[allow(clippy::print_stderr)]
async fn notify_fanout_latency_under_load() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping notify-fanout load test — bitcoin-node not found at {}",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    let sizes: Vec<usize> = std::env::var("LOADTEST_SIZES")
        .ok()
        .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .filter(|v: &Vec<usize>| !v.is_empty())
        .unwrap_or_else(|| vec![50, 250, 500]);

    let node = RegtestNode::start_with(RegtestConfig::default())
        .await
        .expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + maturity");

    // Default stream (boot) + Solo stream (small reservation) against one node —
    // mirrors production; connections resolve to Solo and ride that stream.
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
                max_additional_size: 1_000,
                max_additional_sigops: 0,
            }),
    )
    .expect("spawn solo TDP");

    let updates_rx = tdp_default.subscribe();
    let solo_updates_rx = tdp_solo.subscribe();
    node.generate_to_self(1)
        .await
        .expect("mine 1 to pair templates");

    let hooks = ServerHooks {
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
        Arc::new(bp_mining_job::MiningJobCache::new()),
    );

    // Wait for the Solo stream to have paired a template.
    for _ in 0..100 {
        if server.current_template().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let port_config = PortConfig {
        target_shares_per_minute: 6.0,
        ..PortConfig::new(addr.port(), 1.0e-18)
    };

    // One accept loop serves every connection across all N-iterations.
    {
        let server_accept = server.clone();
        let pc = port_config.clone();
        tokio::spawn(async move {
            // Exits on the first accept error — the listener is dropped at
            // test teardown, which is what ends this loop.
            while let Ok((socket, _)) = listener.accept().await {
                socket.set_nodelay(true).ok();
                server_accept.accept_connection(socket, pc.clone());
            }
        });
    }

    eprintln!("\n========= notify fan-out load test (Block → mining.notify) =========");
    eprintln!(
        "{:>6}  {:>6}  {:>8}  {:>8}  {:>8}  {:>8}  {:>10}",
        "miners", "recv", "min_ms", "p50_ms", "p95_ms", "max_ms", "spread_ms"
    );
    for &n in &sizes {
        let (connected, mut samples) = measure(&node, addr, n).await;
        samples.sort_unstable();
        let ms = |us: u128| us as f64 / 1000.0;
        let (min, max) = (
            samples.first().copied().unwrap_or(0),
            samples.last().copied().unwrap_or(0),
        );
        eprintln!(
            "{:>6}  {:>6}  {:>8.2}  {:>8.2}  {:>8.2}  {:>8.2}  {:>10.2}",
            n,
            samples.len(),
            ms(min),
            ms(pct(&samples, 0.50)),
            ms(pct(&samples, 0.95)),
            ms(max),
            ms(max.saturating_sub(min)),
        );
        assert!(
            !samples.is_empty(),
            "no miner received a new-block notify at N={n} (connected={connected})"
        );
        // Let sockets from this round close before the next.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    eprintln!("spread = max−min = pure per-connection fan-out serialisation cost");
    eprintln!("====================================================================\n");

    server.shutdown().await;
    tdp_default.shutdown().ok();
    tdp_solo.shutdown().ok();
}
