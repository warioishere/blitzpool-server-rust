// SPDX-License-Identifier: AGPL-3.0-or-later

//! Load test: prints the trigger to `mining.notify` latency across N miners,
//! for a new block and for a fee refresh, and asserts that every miner gets
//! both, a block within half of `REFRESH_SPREAD` and a refresh spread over
//! `REFRESH_SPREAD`. The spread (max − min) of a block is the per-connection
//! fan-out cost; the histogram shows how evenly a refresh is spread. The
//! absolute numbers include the shared RPC + IPC hop. Run with `--nocapture`;
//! `LOADTEST_SIZES=100,500` picks N.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bitcoin::Network;
use bp_common::StreamKind;
use bp_mining_job::{PayoutEntry, ResolvedPayouts};
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_stratum_v1::{
    PayoutResolver, PortConfig, ServerConfig, ServerHooks, SharedExtranonce, StratumV1Server,
};
use bp_template_distribution::{TdpCoinbaseConstraints, TdpConfig, TdpHandle, REFRESH_SPREAD};
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
    async fn resolve_payouts(&self, miner_address: &str, reward_sats: u64) -> ResolvedPayouts {
        ResolvedPayouts::unsnapshotted(vec![PayoutEntry {
            address: miner_address.to_string(),
            sats: reward_sats,
        }])
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

/// What a measurement triggers, and which notify answers it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Trigger {
    /// Mine a block: the first notify with a new prev-hash.
    Block,
    /// Send a transaction: the first notify on the same prev-hash with
    /// `clean_jobs=false`.
    Refresh,
}

impl Trigger {
    fn answers(self, f: &Value, baseline_prev: &str) -> bool {
        let Some(ph) = prevhash_of_notify(f) else {
            return false;
        };
        let clean = f["params"].get(8).and_then(Value::as_bool);
        match self {
            Self::Block => ph != baseline_prev,
            Self::Refresh => ph == baseline_prev && clean == Some(false),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Refresh => "refresh",
        }
    }
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

/// Connect `n` miners, fire `trigger`, and return `(connected, samples_us)`:
/// per miner, the time from the trigger to the first notify answering it.
async fn measure(
    node: &RegtestNode,
    addr: SocketAddr,
    n: usize,
    trigger: Trigger,
) -> (usize, Vec<u128>) {
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

            let got = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    match read_frame(&mut reader).await {
                        Some(f) => {
                            let started = *t0.lock().unwrap();
                            // Frames before the trigger cannot answer it.
                            if let Some(s) = started {
                                if trigger.answers(&f, &baseline_prev) {
                                    return Some(s.elapsed().as_micros());
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

    *t0.lock().unwrap() = Some(Instant::now());
    match trigger {
        Trigger::Block => {
            node.generate_to_self(1)
                .await
                .expect("mine block for fan-out");
        }
        Trigger::Refresh => {
            let dest = node.new_address("bech32").await.expect("new address");
            node.wallet_call("sendtoaddress", serde_json::json!([dest, 0.01]))
                .await
                .expect("sendtoaddress for a fee refresh");
        }
    }

    // Collect one result per spawned miner task.
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        // A failed miner yields no sample; `connected` reports the shortfall.
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
            "skipping notify-fanout load test — {}",
            cfg.unavailable_reason()
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
            // Ends on the first accept error, i.e. at teardown.
            while let Ok((socket, _)) = listener.accept().await {
                socket.set_nodelay(true).ok();
                server_accept.accept_connection(socket, pc.clone());
            }
        });
    }

    eprintln!("\n========= notify fan-out load test (trigger → mining.notify) =========");
    eprintln!(
        "{:>6}  {:>7}  {:>6}  {:>8}  {:>8}  {:>8}  {:>8}  {:>10}",
        "miners", "trigger", "recv", "min_ms", "p50_ms", "p95_ms", "max_ms", "spread_ms"
    );
    let spread_ms = REFRESH_SPREAD.as_millis();
    for &n in &sizes {
        for trigger in [Trigger::Block, Trigger::Refresh] {
            let (connected, mut samples) = measure(&node, addr, n, trigger).await;
            samples.sort_unstable();
            let ms = |us: u128| us as f64 / 1000.0;
            let (min, max) = (
                samples.first().copied().unwrap_or(0),
                samples.last().copied().unwrap_or(0),
            );
            let spread = max.saturating_sub(min) / 1000;
            eprintln!(
                "{:>6}  {:>7}  {:>6}  {:>8.2}  {:>8.2}  {:>8.2}  {:>8.2}  {:>10.2}",
                n,
                trigger.label(),
                samples.len(),
                ms(min),
                ms(pct(&samples, 0.50)),
                ms(pct(&samples, 0.95)),
                ms(max),
                ms(max.saturating_sub(min)),
            );
            assert_eq!(
                samples.len(),
                connected,
                "every connected miner answers the {} at N={n}",
                trigger.label()
            );
            match trigger {
                // A block is never held back.
                Trigger::Block => assert!(
                    spread < spread_ms / 2,
                    "a block reaches every miner at once, spread {spread} ms at N={n}"
                ),
                Trigger::Refresh => {
                    let tolerance_ms = 250;
                    assert!(
                        spread <= spread_ms + tolerance_ms,
                        "every miner gets the refresh within the window, spread {spread} ms at N={n}"
                    );
                    // Miners per 100 ms slice after the first arrival.
                    let mut slices = vec![0usize; ((spread_ms + tolerance_ms) / 100) as usize + 1];
                    for us in &samples {
                        slices[(((us - min) / 1000) / 100) as usize] += 1;
                    }
                    eprintln!("{:>15}  per 100 ms: {slices:?}", "");
                    if n >= 50 {
                        assert!(
                            spread >= spread_ms / 2,
                            "the refresh is spread out, spread {spread} ms at N={n}"
                        );
                    }
                }
            }
            // Let sockets from this round close before the next.
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    eprintln!(
        "block spread = per-connection fan-out cost; refresh spread = REFRESH_SPREAD by design"
    );
    eprintln!("=======================================================================\n");

    server.shutdown().await;
    tdp_default.shutdown().ok();
    tdp_solo.shutdown().ok();
}
