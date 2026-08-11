// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: SV2 per-mode stream routing — Solo, Group-Solo and Blockparty
//! through ONE driver.
//!
//! The SV2 counterpart of `bp-stratum-v1/tests/regtest_stream_routing.rs`.
//! Same scenario, different protocol side, and the protocol side is the whole
//! reason both exist: here the stream swap is triggered by
//! `OpenStandardMiningChannel` in `run_mining_connection` (over a Noise-XK
//! session), not by `mining.authorize` in `run_connection`.
//!
//! Two independent guards make each proof tight:
//!   1. A recording block-sink captures the `StreamKind` of every block-submit.
//!      The mode's own kind proves the OpenChannel swap fired; had it not, the
//!      sink would record `Pplns` — the stream every connection boots on
//!      before its mode is resolved — and the test fails.
//!   2. The chain advancing proves the mode's handle actually knew the job's
//!      `template_id` — template_ids collide across streams, so a mis-routed
//!      submit would be rejected and the height would not move.
//!
//! The three modes differ only in the reservation their stream advertises and
//! in how many outputs the coinbase carries, so they share [`run_scenario`]:
//!
//!   * **Solo** pays one output, against a tiny fixed reservation.
//!   * **Group-Solo** additionally proves a ~50-member P2TR coinbase fits the
//!     production 10 000-WU reservation through the SV2 coinbase builder.
//!   * **Blockparty** routes at the production 8 000-WU reservation.
//!
//! Sharing the loop is deliberate: as three files these carried three copies of
//! the same miner loop, and the copies had already begun to diverge — only Solo
//! and Blockparty classified each `SubmitShares*` response, so a Group-Solo run
//! that failed reported "height did not rise" with nothing to say why. The one
//! driver here classifies for all three.
//!
//! Skipped (with a printed warning) when `bitcoin-node` is not installed.

#![allow(clippy::print_stderr)]

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::Network;
use bp_common::{AddressId, StreamKind};
use bp_mining_job::{PayoutEntry, ResolvedPayouts};
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Difficulty;
use bp_stratum_v2::bridge::JdpDeclaredJobRegistry;
use bp_stratum_v2::hooks::{BlockSubmissionSink, MiningServerHooks, PayoutResolver};
use bp_stratum_v2::mining::client::{PortConfig, FLAG_REQUIRES_VERSION_ROLLING};
use bp_stratum_v2::mining::submit::ShareAccept;
use bp_stratum_v2::noise::{NoiseConfig, DEFAULT_CERT_VALIDITY};
use bp_stratum_v2::server::{ServerConfig, StratumV2MiningServer};
use bp_stratum_v2::server_codec::{decode_mining_inbound, encode_mining_outbound};
use bp_template_distribution::{TdpCoinbaseConstraints, TdpConfig, TdpHandle};
use bp_test_support::poll_for_height;
use stratum_apps::key_utils::Secp256k1PublicKey;
use stratum_apps::network_helpers::connect_with_noise;
use stratum_core::codec_sv2::StandardSv2Frame;
use stratum_core::common_messages_sv2::{Protocol, SetupConnection};
use stratum_core::framing_sv2::framing::Frame;
use stratum_core::mining_sv2::{OpenStandardMiningChannel, SubmitSharesStandard};
use stratum_core::parsers_sv2::{
    parse_message_frame_with_tlvs, AnyMessage, CommonMessages, Mining,
};
use tokio::net::{TcpListener, TcpStream};

const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const SRI_TEST_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const SRI_TEST_PRV: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

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
/// Blockparty reservation.
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
    async fn resolve_payouts(
        &self,
        _miner_address: &AddressId,
        reward_sats: u64,
    ) -> ResolvedPayouts {
        ResolvedPayouts::unsnapshotted(split_reward(&self.addresses, reward_sats))
    }

    fn resolve_stream(&self, _miner_address: &AddressId) -> StreamKind {
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
        .map(|(i, address)| PayoutEntry {
            address: address.clone(),
            sats: if i == 0 { each + remainder } else { each },
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
        _session_id_hex: &str,
        stream: StreamKind,
    ) {
        self.recorded.lock().unwrap().push(stream);
        if accept.witness_coinbase.is_empty() || accept.template_id.is_none() {
            return;
        }
        let handle = if stream == self.alt {
            &self.tdp_alt
        } else {
            &self.tdp_default
        };
        let h = &accept.header;
        let version = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let ts = u32::from_le_bytes([h[68], h[69], h[70], h[71]]);
        let nonce = u32::from_le_bytes([h[76], h[77], h[78], h[79]]);
        let _ = handle
            .submit_solution(
                accept.template_id.expect("checked above"),
                version,
                ts,
                nonce,
                accept.witness_coinbase.clone(),
            )
            .await;
    }
}

// ── the three modes ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv2_solo_connection_routes_to_solo_stream_and_block_accepted() {
    let Some(node) = start_node_or_skip(SOLO, "routing").await else {
        return;
    };
    let outcome = run_scenario(&node, SOLO, vec![REGTEST_ADDR.to_string()]).await;
    node.shutdown().await.ok();
    assert_routed_and_landed(SOLO, &outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv2_group_solo_connection_routes_to_group_solo_stream_and_block_accepted() {
    let Some(node) = start_node_or_skip(GROUP_SOLO, "routing").await else {
        return;
    };
    let outcome = run_scenario(&node, GROUP_SOLO, vec![REGTEST_ADDR.to_string()]).await;
    node.shutdown().await.ok();
    assert_routed_and_landed(GROUP_SOLO, &outcome);
}

/// ~50 distinct P2TR (bech32m) members — the worst-case 172-WU output type.
/// 50 × 43 B = 2150 B of coinbase outputs, which must fit the production
/// 10 000-WU reservation (2756 B). Validity proof for the documented
/// "~50 members" capacity over the SV2 coinbase builder.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv2_group_solo_max_size_multi_output_coinbase_accepted() {
    let Some(node) = start_node_or_skip(GROUP_SOLO, "max-size multi-output").await else {
        return;
    };
    const MEMBERS: usize = 50;
    let members = mint_p2tr_members(&node, MEMBERS).await;
    let outcome = run_scenario(&node, GROUP_SOLO, members).await;
    node.shutdown().await.ok();
    eprintln!(
        "[sv2-group-solo] {MEMBERS}-output coinbase accepted: height {} → {}",
        outcome.before, outcome.after
    );
    assert_routed_and_landed(GROUP_SOLO, &outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv2_blockparty_connection_routes_to_blockparty_stream_and_block_accepted() {
    let Some(node) = start_node_or_skip(BLOCKPARTY, "routing").await else {
        return;
    };
    let outcome = run_scenario(&node, BLOCKPARTY, vec![REGTEST_ADDR.to_string()]).await;
    node.shutdown().await.ok();
    assert_routed_and_landed(BLOCKPARTY, &outcome);
}

// ── driver ──────────────────────────────────────────────────────────────

/// What one scenario observed. The submit tallies are carried out so a failing
/// assertion can say *why* no block landed instead of only that none did.
struct Outcome {
    recorded: Vec<StreamKind>,
    before: u32,
    after: u32,
    successes: u32,
    errors: Vec<String>,
}

/// Start a regtest node + mine 101 for IBD-exit + maturity, or return `None`
/// (and print a skip line) when bitcoin-node isn't installed.
async fn start_node_or_skip(case: ModeCase, what: &str) -> Option<RegtestNode> {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping SV2 {} {what} regtest — {}",
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
        successes,
        errors,
    } = outcome;
    let want = case.stream;
    let label = case.label;
    eprintln!(
        "[sv2-{label}] recorded streams = {recorded:?}, height {before} → {after}, \
         submits {successes} success, errors={errors:?}"
    );
    assert!(
        recorded.contains(&want),
        "block-submit must be routed via the {want:?} stream (OpenChannel swap); \
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
         (height {before} → {after}; submits {successes} success, errors={errors:?})"
    );
}

/// Spin up two TDP streams (default + `case.stream` at its own reservation),
/// the SV2 server with a `FixedResolver` plus a recording sink, and drive one
/// Noise miner through SetupConnection / OpenStandardMiningChannel / submit
/// until a block lands.
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
    node.generate_to_self(1)
        .await
        .expect("mine 1 for templates");

    let recorded: Arc<Mutex<Vec<StreamKind>>> = Arc::new(Mutex::new(Vec::new()));
    let hooks = MiningServerHooks {
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
        ..MiningServerHooks::no_op()
    };
    let noise_config =
        NoiseConfig::parse_strings(SRI_TEST_PUB, SRI_TEST_PRV, DEFAULT_CERT_VALIDITY)
            .expect("noise config");
    let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
    let server = StratumV2MiningServer::spawn(
        ServerConfig::defaults_for(Network::Regtest),
        noise_config,
        updates_rx,
        tdp_default.current_snapshot(),
        vec![(case.stream, alt_updates_rx, tdp_alt.current_snapshot())],
        hooks,
        bridge,
        std::sync::Arc::new(bp_mining_job::MiningJobCache::new()),
    );
    wait_until(Duration::from_secs(8), || {
        server.current_template().is_some()
    })
    .await;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let port_config = PortConfig {
        network: Network::Regtest,
        min_difficulty: Difficulty(1.0e-18),
        initial_difficulty: Difficulty(1.0e-18),
        target_shares_per_minute: 6.0,
        vardiff_interval_ms: 200,
        vardiff_silence_easing: false,
    };
    let server_clone = server.clone();
    let accept_handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        socket.set_nodelay(true).ok();
        server_clone.accept_connection(socket, port_config);
    });

    let miner_socket = TcpStream::connect(addr).await.expect("connect");
    miner_socket.set_nodelay(true).ok();
    let pub_key: Secp256k1PublicKey = SRI_TEST_PUB.parse().expect("parse pub key");
    let noise = connect_with_noise::<AnyMessage<'static>>(miner_socket, Some(pub_key))
        .await
        .expect("noise handshake");
    let (mut reader, mut writer) = noise.into_split();

    write_any_message(
        &mut writer,
        AnyMessage::Common(CommonMessages::SetupConnection(
            SetupConnection {
                protocol: Protocol::MiningProtocol,
                min_version: 2,
                max_version: 2,
                flags: FLAG_REQUIRES_VERSION_ROLLING,
                endpoint_host: "127.0.0.1".to_string().try_into().unwrap(),
                endpoint_port: addr.port(),
                vendor: "regtest-miner".to_string().try_into().unwrap(),
                hardware_version: "v1".to_string().try_into().unwrap(),
                firmware: "0.1".to_string().try_into().unwrap(),
                device_id: "test".to_string().try_into().unwrap(),
            }
            .into_static(),
        )),
    )
    .await;
    let _ = read_any_message(&mut reader).await; // SetupConnectionSuccess

    // OpenStandardMiningChannel with the mode's address → triggers the swap.
    write_any_message(
        &mut writer,
        AnyMessage::Mining(Mining::OpenStandardMiningChannel(
            OpenStandardMiningChannel {
                request_id: 1u32,
                user_identity: format!("{REGTEST_ADDR}.w1").try_into().unwrap(),
                // 0 H/s → assigned `min_difficulty` (1e-18) → trivial target →
                // every submit accepted, ~every accepted share a block candidate.
                nominal_hash_rate: 0.0,
                max_target: [0xFFu8; 32].into(),
            }
            .into_static(),
        )),
    )
    .await;

    // Capture the first NewMiningJob (built from the mode's template post-swap):
    // it carries channel_id + job_id + version + min_ntime we need to submit.
    let mut job: Option<(u32, u32, u32)> = None;
    let mut ntime: Option<u32> = None;
    let _ = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            match read_any_message(&mut reader).await {
                AnyMessage::Mining(Mining::NewMiningJob(j)) => {
                    if let Some(t) = j.min_ntime.clone().into_inner() {
                        ntime = Some(t);
                    }
                    job = Some((j.channel_id, j.job_id, j.version));
                }
                // A future job carries an empty min_ntime; the activating
                // SetNewPrevHash supplies it.
                AnyMessage::Mining(Mining::SetNewPrevHash(p)) => {
                    ntime = Some(p.min_ntime);
                }
                _ => {}
            }
            if job.is_some() && ntime.is_some() {
                return;
            }
        }
    })
    .await;
    let (channel_id, job_id, version) = job.expect("NewMiningJob within 8s");
    let ntime = ntime.expect("min_ntime via job or SetNewPrevHash");
    eprintln!(
        "[sv2-{}] captured job: channel_id={channel_id} job_id={job_id} \
         version={version:#x} ntime={ntime}",
        case.label
    );

    // Submit nonces until the chain advances (a block landed via the mode's
    // handle). ~50% of nonces clear the regtest target → lands within a few.
    let before = node.current_height().await.expect("height");
    let mut landed = None;
    let mut successes = 0u32;
    let mut errors: Vec<String> = Vec::new();
    let mut latest_job = (channel_id, job_id, version, ntime);
    for nonce in 0u32..24 {
        let (cid, jid, ver, nt) = latest_job;
        write_any_message(
            &mut writer,
            AnyMessage::Mining(Mining::SubmitSharesStandard(SubmitSharesStandard {
                channel_id: cid,
                sequence_number: nonce,
                job_id: jid,
                nonce,
                ntime: nt,
                version: ver,
            })),
        )
        .await;
        // Drain the server's responses for a short window, classifying each.
        let _ = tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                match read_any_message(&mut reader).await {
                    AnyMessage::Mining(Mining::SubmitSharesError(e)) => {
                        errors.push(String::from_utf8_lossy(e.error_code.as_bytes()).to_string());
                    }
                    AnyMessage::Mining(Mining::SubmitSharesSuccess(_)) => successes += 1,
                    // Track job refresh so we don't submit against a stale id.
                    // A future job keeps the previous ntime until its
                    // SetNewPrevHash arrives (handled below).
                    AnyMessage::Mining(Mining::NewMiningJob(j)) => {
                        let nt = j.min_ntime.clone().into_inner().unwrap_or(nt);
                        latest_job = (j.channel_id, j.job_id, j.version, nt);
                    }
                    // Future-job activation supplies the ntime for the
                    // just-received job.
                    AnyMessage::Mining(Mining::SetNewPrevHash(p)) => {
                        let (cid, jid, ver, _) = latest_job;
                        latest_job = (cid, jid, ver, p.min_ntime);
                    }
                    _ => {}
                }
            }
        })
        .await;
        if let Some(h) = poll_for_height(node, before + 1, Duration::from_millis(400)).await {
            landed = Some(h);
            break;
        }
    }

    drop(writer);
    drop(reader);
    server.shutdown().await;
    tdp_default.shutdown().ok();
    tdp_alt.shutdown().ok();
    let after = landed.unwrap_or(before);
    let recorded = recorded.lock().unwrap().clone();
    let _ = accept_handle.await;
    Outcome {
        recorded,
        before,
        after,
        successes,
        errors,
    }
}

// ── helpers (mirror regtest_standard.rs) ────────────────────────────────

async fn write_any_message(
    writer: &mut stratum_apps::network_helpers::noise_stream::NoiseTcpWriteHalf<
        AnyMessage<'static>,
    >,
    msg: AnyMessage<'static>,
) {
    let sv2_frame: StandardSv2Frame<AnyMessage<'static>> =
        msg.try_into().expect("AnyMessage → StandardSv2Frame");
    writer
        .write_frame(Frame::Sv2(sv2_frame))
        .await
        .expect("write_frame");
}

async fn read_any_message(
    reader: &mut stratum_apps::network_helpers::noise_stream::NoiseTcpReadHalf<AnyMessage<'static>>,
) -> AnyMessage<'static> {
    let frame = reader.read_frame().await.expect("read_frame");
    let mut sv2_frame = match frame {
        Frame::Sv2(f) => f,
        Frame::HandShake(_) => panic!("unexpected handshake frame post-handshake"),
    };
    let header = sv2_frame.get_header().expect("frame header");
    let (msg, _tlvs) = parse_message_frame_with_tlvs(header, sv2_frame.payload(), &[])
        .expect("parse_message_frame_with_tlvs");
    let _ = decode_mining_inbound(msg.clone());
    let _ = encode_mining_outbound;
    msg
}

async fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut cond: F) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
