// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: SV1 per-mode stream routing — Solo, Group-Solo and Blockparty
//! through ONE driver.
//!
//! Proves the validity-critical behaviour unit tests can't: a connection whose
//! address resolves to a mode is routed onto that mode's dedicated template
//! stream by `run_connection` (on `mining.authorize`), and a block it finds is
//! submitted through that mode's TDP handle and accepted by bitcoin-core.
//!
//! Two independent guards make each proof tight:
//!   1. A recording block-sink captures the `StreamKind` of every block-submit.
//!      The mode's own kind proves `run_connection` switched (`state.stream`);
//!      had the swap not fired it would record `Pplns` — the stream every
//!      connection boots on before its mode is resolved — and the test fails.
//!   2. The chain advancing proves the mode's handle actually knew the job's
//!      `template_id` — template_ids collide across streams, so a mis-routed
//!      submit would be rejected and the height would not move.
//!
//! The three modes differ only in the reservation their stream advertises and
//! in how many outputs the coinbase carries, so they share [`run_scenario`]:
//!
//!   * **Solo** pays one output, against a tiny fixed reservation.
//!   * **Group-Solo** additionally proves a ~50-member P2TR coinbase fits the
//!     production 10 000-WU reservation.
//!   * **Blockparty** does the same at 40 members / 8 000 WU — but for a
//!     different reason: Blockparty has no member cap at all.
//!
//! One driver is the point, not a convenience. These were three files with
//! three copies of the same miner loop, and `e1d3614` fixed two of them:
//! Solo and Blockparty learned to classify each submit's own response and to
//! follow a `mining.notify` arriving mid-run, Group-Solo did not — so a
//! Group-Solo run slow enough to cross a template change kept mining a job the
//! pool had already replaced, and the failure surfaced only as "height did not
//! rise". Sharing the loop is what keeps the three from drifting again.
//!
//! The SV2 counterpart is `bp-stratum-v2/tests/regtest_stream_routing.rs`:
//! same scenario, but the swap is triggered by `OpenStandardMiningChannel` in
//! `run_mining_connection`. The protocol side is the reason both exist.
//!
//! Skipped (with a printed warning) when `bitcoin-node` is not installed.

#![allow(clippy::print_stderr)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::Network;
use bp_common::StreamKind;
use bp_mining_job::{PayoutEntry, ResolvedPayouts};
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

/// The per-mode inputs of one scenario. Everything else in [`run_scenario`] is
/// identical across the three, which is why they share it.
#[derive(Clone, Copy)]
struct ModeCase {
    /// The stream the connection must be routed onto.
    stream: StreamKind,
    /// `max_additional_size` advertised on that stream's TDP handle.
    reservation_bytes: u32,
    /// Log prefix + skip-message label.
    label: &'static str,
}

/// Solo pays a single output, so a tiny reservation is all it needs.
const SOLO: ModeCase = ModeCase {
    stream: StreamKind::Solo,
    reservation_bytes: 1_000,
    label: "solo",
};

/// ≈ `tdp_constraint_for_budget(10_000 WU)`: 10_000/4 + 256. The production
/// Group-Solo reservation. Holds ~50 P2TR member outputs (50 × 43 B = 2150 B).
const GROUP_SOLO: ModeCase = ModeCase {
    stream: StreamKind::GroupSolo,
    reservation_bytes: 2_756,
    label: "group-solo",
};

/// ≈ `tdp_constraint_for_budget(8_000 WU)`: 8_000/4 + 256. The production
/// Blockparty reservation. Holds ~40 P2TR member outputs (40 × 43 B = 1720 B).
const BLOCKPARTY: ModeCase = ModeCase {
    stream: StreamKind::Blockparty,
    reservation_bytes: 2_256,
    label: "blockparty",
};

/// Routes every address to `stream` and splits the block's OWN revenue across
/// `addresses`, so the payout vector consumes the template value exactly
/// whatever the subsidy and fees happen to be.
struct FixedResolver {
    stream: StreamKind,
    addresses: Vec<String>,
}

#[async_trait]
impl PayoutResolver for FixedResolver {
    async fn resolve_payouts(&self, _miner_address: &str, reward_sats: u64) -> ResolvedPayouts {
        ResolvedPayouts::unsnapshotted(split_reward(&self.addresses, reward_sats))
    }

    fn resolve_stream(&self, _miner_address: &str) -> StreamKind {
        self.stream
    }
}

/// Split `reward_sats` evenly across `addresses`, the remainder onto the first.
/// The sum is `reward_sats` exactly — anything else is `bad-cb-amount`.
fn split_reward(addresses: &[String], reward_sats: u64) -> Vec<PayoutEntry> {
    let n = addresses.len() as u64;
    let each = reward_sats / n;
    let remainder = reward_sats - each * n;
    addresses
        .iter()
        .enumerate()
        .map(|(i, address)| {
            let sats = if i == 0 { each + remainder } else { each };
            PayoutEntry::static_address(address.clone(), sats)
        })
        .collect()
}

/// Records the routed stream and submits the solution through the handle that
/// stream owns — the test-side mirror of production's `select_handle`.
struct RecordingSink {
    tdp_default: TdpHandle,
    tdp_alt: TdpHandle,
    /// The one stream this scenario gave a dedicated handle to. Held as a
    /// value and compared, not matched as a mode: a fourth `StreamKind` cannot
    /// silently fall through to the default handle here.
    alt: StreamKind,
    recorded: Arc<Mutex<Vec<StreamKind>>>,
}

#[async_trait]
impl BlockSubmissionSink for RecordingSink {
    async fn submit_block(
        &self,
        accept: &ShareAccept,
        _address: &str,
        _worker: &str,
        _session_id: &str,
        stream: StreamKind,
    ) {
        self.recorded.lock().unwrap().push(stream);
        let handle = if stream == self.alt {
            &self.tdp_alt
        } else {
            &self.tdp_default
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

// ── the three modes ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv1_solo_connection_routes_to_solo_stream_and_block_accepted() {
    let Some(node) = start_node_or_skip(SOLO, "routing").await else {
        return;
    };
    let outcome = run_scenario(&node, SOLO, vec![REGTEST_ADDR.to_string()]).await;
    node.shutdown().await.ok();
    assert_routed_and_landed(SOLO, &outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv1_group_solo_connection_routes_to_group_solo_stream_and_block_accepted() {
    let Some(node) = start_node_or_skip(GROUP_SOLO, "routing").await else {
        return;
    };
    let outcome = run_scenario(&node, GROUP_SOLO, vec![REGTEST_ADDR.to_string()]).await;
    node.shutdown().await.ok();
    assert_routed_and_landed(GROUP_SOLO, &outcome);
}

/// ~50 distinct P2TR (bech32m) members — the worst-case 172-WU output type.
/// 50 × 43 B = 2150 B of coinbase outputs, which must fit the production
/// 10 000-WU reservation (2756 B). The validity proof for the documented
/// "~50 members" capacity of `[group_fees].coinbase_weight_budget`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv1_group_solo_max_size_multi_output_coinbase_accepted() {
    let Some(node) = start_node_or_skip(GROUP_SOLO, "max-size multi-output").await else {
        return;
    };
    const MEMBERS: usize = 50;
    let members = mint_p2tr_members(&node, MEMBERS).await;
    let outcome = run_scenario(&node, GROUP_SOLO, members).await;
    node.shutdown().await.ok();
    eprintln!(
        "[sv1-group-solo] {MEMBERS}-output coinbase accepted: height {} → {}",
        outcome.before, outcome.after
    );
    assert_routed_and_landed(GROUP_SOLO, &outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv1_blockparty_connection_routes_to_blockparty_stream_and_block_accepted() {
    let Some(node) = start_node_or_skip(BLOCKPARTY, "routing").await else {
        return;
    };
    let outcome = run_scenario(&node, BLOCKPARTY, vec![REGTEST_ADDR.to_string()]).await;
    node.shutdown().await.ok();
    assert_routed_and_landed(BLOCKPARTY, &outcome);
}

/// 40 distinct P2TR members against the production 8 000-WU reservation.
///
/// Unlike Group-Solo, Blockparty enforces no member cap: `add_member` never
/// counts, and `CoinbaseReservation::ensure_capacity_for_members` instead
/// RAISES the reservation as a party grows (high-water, floored at
/// `[blockparty].coinbase_weight_budget`, capped at 50 000 WU ≈ 285 members).
/// So the reservation is a floor with headroom, not a ceiling.
///
/// That raise reaches bitcoin-core's templates only after ~one TDP cycle, so
/// what has to hold is that a realistic party never needs it. The floor sizes
/// to `328 + 188 + (n+1)·172 + 200` WU, i.e. 41 members at 8 000 WU — this
/// test sits just under that and proves the common case is covered by the
/// floor alone, with no (lagging) raise in the path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv1_blockparty_max_size_multi_output_coinbase_accepted() {
    let Some(node) = start_node_or_skip(BLOCKPARTY, "max-size multi-output").await else {
        return;
    };
    const MEMBERS: usize = 40;
    let members = mint_p2tr_members(&node, MEMBERS).await;
    let outcome = run_scenario(&node, BLOCKPARTY, members).await;
    node.shutdown().await.ok();
    eprintln!(
        "[sv1-blockparty] {MEMBERS}-output coinbase accepted: height {} → {}",
        outcome.before, outcome.after
    );
    assert_routed_and_landed(BLOCKPARTY, &outcome);
}

// ── driver ──────────────────────────────────────────────────────────────

/// What one scenario observed. The submit tallies are carried out so a failing
/// assertion can say *why* no block landed instead of only that none did.
struct Outcome {
    recorded: Vec<StreamKind>,
    before: u32,
    after: u32,
    accepted: usize,
    rejected: Vec<String>,
    renotified: usize,
}

/// Start a regtest node + mine 101 for IBD-exit + maturity, or return `None`
/// (and print a skip line) when bitcoin-node isn't installed.
async fn start_node_or_skip(case: ModeCase, what: &str) -> Option<RegtestNode> {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping SV1 {} {what} regtest — {}",
            case.label,
            cfg.unavailable_reason()
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

/// Mint `n` distinct P2TR (bech32m) addresses from the node's wallet.
async fn mint_p2tr_members(node: &RegtestNode, n: usize) -> Vec<String> {
    let mut members = Vec::with_capacity(n);
    for _ in 0..n {
        members.push(
            node.new_address("bech32m")
                .await
                .expect("mint bech32m member address"),
        );
    }
    members
}

fn assert_routed_and_landed(case: ModeCase, outcome: &Outcome) {
    let Outcome {
        recorded,
        before,
        after,
        accepted,
        rejected,
        renotified,
    } = outcome;
    let want = case.stream;
    let label = case.label;
    eprintln!(
        "[sv1-{label}] recorded streams = {recorded:?}, height {before} → {after}, \
         submits accepted={accepted} rejected={} job-refreshes={renotified}",
        rejected.len()
    );
    if !rejected.is_empty() {
        eprintln!("[sv1-{label}] rejection reasons = {rejected:?}");
    }
    assert!(
        recorded.contains(&want),
        "block-submit must be routed via the {want:?} stream (run_connection swap); \
         recorded {recorded:?}"
    );
    assert!(
        recorded.iter().all(|s| *s == want),
        "a {want:?} connection must never submit via the boot (Pplns) stream; \
         recorded {recorded:?}"
    );
    assert!(
        after > before,
        "bitcoin-core must accept the {want:?}-stream block via the {want:?} handle \
         (height {before} → {after}; submits accepted={accepted} rejected={} \
         job-refreshes={renotified}; rejections={rejected:?})",
        rejected.len()
    );
}

/// Spin up two TDP streams (default + `case.stream` at its own reservation),
/// the SV1 server with a `FixedResolver` plus a recording sink, and drive one
/// miner through subscribe / authorize / submit until a block lands.
async fn run_scenario(node: &RegtestNode, case: ModeCase, addresses: Vec<String>) -> Outcome {
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
                max_additional_size: case.reservation_bytes,
                max_additional_sigops: 0,
            }),
    )
    .expect("spawn per-mode TDP");

    let updates_rx = tdp_default.subscribe();
    let alt_updates_rx = tdp_alt.subscribe();
    // Force a fresh template pair on both streams.
    node.generate_to_self(1)
        .await
        .expect("mine 1 for templates");

    let recorded: Arc<Mutex<Vec<StreamKind>>> = Arc::new(Mutex::new(Vec::new()));
    let hooks = ServerHooks {
        block_sink: Arc::new(RecordingSink {
            tdp_default: tdp_default.clone(),
            tdp_alt: tdp_alt.clone(),
            alt: case.stream,
            recorded: recorded.clone(),
        }),
        payout_resolver: Arc::new(FixedResolver {
            stream: case.stream,
            addresses,
        }),
        ..ServerHooks::no_op()
    };

    let server = StratumV1Server::spawn(
        ServerConfig::defaults_for(Network::Regtest),
        updates_rx,
        tdp_default.current_snapshot(),
        vec![(case.stream, alt_updates_rx, tdp_alt.current_snapshot())],
        hooks,
        SharedExtranonce::new(),
        std::sync::Arc::new(bp_mining_job::MiningJobCache::new()),
    );

    // Wait until the dedicated stream has paired a template (that's the one the
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
        .write_all(
            format!(
                "{{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"{}-miner/1.0\"]}}\n",
                case.label
            )
            .as_bytes(),
        )
        .await
        .expect("write subscribe");
    let sub_resp = read_frame(&mut reader).await;
    // The extranonce1 (result[1]) the pool hands the miner must come from the
    // pool-wide collision-free allocator's SV1 partition (worker 1 → top byte
    // 0x01), NOT from the random session id. The block that lands below is
    // reconstructed from this exact extranonce1, so its acceptance by
    // bitcoin-core proves the allocated-prefix path yields valid blocks.
    let en1 = sub_resp["result"][1]
        .as_str()
        .expect("extranonce1 in subscribe response");
    assert_eq!(en1.len(), 8, "extranonce1 is 4 bytes / 8 hex chars: {en1}");
    assert!(
        en1.starts_with("01"),
        "SV1 extranonce1 must be allocated from worker 1 (0x01…), got {en1}"
    );

    // authorize as the mode's address → run_connection resolves the mode and
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

    // Grab the first mining.notify (built from the mode's template post-swap).
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
    let mut job_id_hex = params[0].as_str().expect("jobId").to_string();
    let mut ntime_hex = params[7].as_str().expect("ntime").to_string();

    // Submit nonces until the chain advances (a block landed via the mode's
    // handle) or we exhaust the budget. ~50% of nonces are block candidates on
    // regtest, so this lands within a few iterations.
    //
    // The submit responses are classified rather than dropped, and a
    // `mining.notify` arriving mid-run replaces the job being mined. Both matter
    // under load: a run that takes long enough to cross a template change was
    // otherwise still submitting against the first job, every submit came back
    // `job not found`, and the failure surfaced only as "height did not rise"
    // with no indication why.
    let before = node.current_height().await.expect("height");
    let mut landed = None;
    let mut accepted = 0usize;
    let mut rejected: Vec<String> = Vec::new();
    let mut renotified = 0usize;
    for nonce in 0u32..64 {
        let line = format!(
            "{{\"id\":{},\"method\":\"mining.submit\",\"params\":[\"{REGTEST_ADDR}.x\",\"{job_id_hex}\",\"0000000000000000\",\"{ntime_hex}\",\"{nonce:08x}\",\"00000000\"]}}\n",
            100 + nonce
        );
        write
            .write_all(line.as_bytes())
            .await
            .expect("write submit");
        // Read until this submit's own response shows up, taking any job
        // refresh that overtakes it on the way.
        let want_id = 100 + nonce as u64;
        let _ = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let f = read_frame(&mut reader).await;
                if f.get("method").and_then(|m| m.as_str()) == Some("mining.notify") {
                    if let Some(p) = f.get("params").and_then(|v| v.as_array()) {
                        if let (Some(j), Some(t)) = (p[0].as_str(), p[7].as_str()) {
                            job_id_hex = j.to_string();
                            ntime_hex = t.to_string();
                            renotified += 1;
                        }
                    }
                    continue;
                }
                if f.get("id").and_then(|i| i.as_u64()) == Some(want_id) {
                    if f.get("result").and_then(|r| r.as_bool()) == Some(true) {
                        accepted += 1;
                    } else {
                        rejected.push(f.get("error").map(|e| e.to_string()).unwrap_or_else(|| {
                            format!("result={}", f.get("result").unwrap_or(&Value::Null))
                        }));
                    }
                    return;
                }
            }
        })
        .await;
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
    Outcome {
        recorded,
        before,
        after,
        accepted,
        rejected,
        renotified,
    }
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
