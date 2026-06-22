// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: SV2 per-mode stream routing — Group-Solo (Phase 2/3).
//!
//! The SV2 counterpart of `bp-stratum-v1/tests/regtest_group_solo_stream.rs`.
//! Two tests share one `run_scenario` driver. The routing test uses a 1-output
//! coinbase and proves a connection whose `OpenStandardMiningChannel` address
//! resolves to GroupSolo is routed onto the dedicated Group-Solo template
//! stream by `run_mining_connection`, and a block it finds is submitted through
//! the Group-Solo TDP handle and accepted by bitcoin-core. The max-size test
//! builds a realistic ~50-member multi-output coinbase (P2TR outputs, the
//! worst-case 172-WU output type) against the production Group-Solo reservation
//! (10 000 WU), proving the SV2 coinbase builder produces a VALID multi-output
//! block bitcoin-core accepts via the dedicated stream.
//!
//! Both guard with a recording block-sink that captures the `StreamKind` of
//! every block-submit (`GroupSolo` proves the OpenChannel swap fired) plus the
//! chain advancing (proves the Group-Solo handle knew the job's `template_id`;
//! template_ids collide across streams, so a mis-routed submit would be
//! rejected).

#![allow(clippy::print_stderr)]

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::Network;
use bp_common::{AddressId, StreamKind};
use bp_mining_job::PayoutEntry;
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
/// ≈ tdp_constraint_for_budget(10_000 WU): 10_000/4 + 256. The production
/// Group-Solo reservation. Holds ~50 P2TR member outputs (50 × 43 B = 2150 B).
const GROUP_SOLO_RESERVATION_BYTES: u32 = 2_756;

/// Resolver that classifies every address as Group-Solo (so the connection must
/// be routed to the Group-Solo stream) and returns a fixed payout list — one
/// output for the routing test, or a multi-output split for the max-size test.
struct GroupSoloResolver {
    payouts: Vec<PayoutEntry>,
}

#[async_trait]
impl PayoutResolver for GroupSoloResolver {
    async fn resolve_payouts(
        &self,
        _miner_address: &AddressId,
        _reward_sats: u64,
    ) -> Vec<PayoutEntry> {
        self.payouts.clone()
    }

    fn resolve_stream(&self, _miner_address: &AddressId) -> StreamKind {
        StreamKind::GroupSolo
    }
}

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
        _session_id_hex: &str,
        stream: StreamKind,
    ) {
        self.recorded.lock().unwrap().push(stream);
        if accept.witness_coinbase.is_empty() || accept.template_id.is_none() {
            return;
        }
        let handle = if stream == StreamKind::GroupSolo {
            &self.tdp_alt
        } else {
            &self.tdp
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv2_group_solo_connection_routes_to_group_solo_stream_and_block_accepted() {
    let Some(node) = start_node_or_skip("group-solo routing").await else {
        return;
    };
    // 1-output coinbase: full reward to the miner address.
    let payouts = vec![PayoutEntry {
        address: REGTEST_ADDR.to_string(),
        percent: 100.0,
    }];
    let (recorded, before, after) =
        run_scenario(&node, payouts, GROUP_SOLO_RESERVATION_BYTES).await;
    node.shutdown().await.ok();
    assert_routed_group_solo_and_landed(&recorded, before, after);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv2_group_solo_max_size_multi_output_coinbase_accepted() {
    let Some(node) = start_node_or_skip("group-solo max-size multi-output").await else {
        return;
    };
    // ~50 distinct P2TR (bech32m) members — the worst-case 172-WU output type —
    // each an equal split. 50 × 43 B = 2150 B of coinbase outputs, which must
    // fit the production 10 000-WU reservation (2756 B). Validity proof for the
    // documented "~50 members" capacity over the SV2 coinbase builder.
    const MEMBERS: usize = 50;
    let mut payouts = Vec::with_capacity(MEMBERS);
    for _ in 0..MEMBERS {
        let addr = node
            .new_address("bech32m")
            .await
            .expect("mint bech32m member address");
        payouts.push(PayoutEntry {
            address: addr,
            percent: 100.0 / MEMBERS as f64,
        });
    }
    let (recorded, before, after) =
        run_scenario(&node, payouts, GROUP_SOLO_RESERVATION_BYTES).await;
    node.shutdown().await.ok();
    eprintln!(
        "[sv2-group-solo-multi] {MEMBERS}-output coinbase accepted: height {before} → {after}"
    );
    assert_routed_group_solo_and_landed(&recorded, before, after);
}

async fn start_node_or_skip(label: &str) -> Option<RegtestNode> {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping SV2 {label} regtest — bitcoin-node not found at {}",
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
    eprintln!("[sv2-group-solo] recorded streams = {recorded:?}, height {before} → {after}");
    assert!(
        recorded.contains(&StreamKind::GroupSolo),
        "block-submit must be routed via the Group-Solo stream (OpenChannel swap); recorded {recorded:?}"
    );
    assert!(
        recorded.iter().all(|s| *s == StreamKind::GroupSolo),
        "a Group-Solo connection must never submit via the Default stream; recorded {recorded:?}"
    );
    assert!(
        after > before,
        "bitcoin-core must accept the Group-Solo-stream block via the Group-Solo handle ({before} → {after})"
    );
}

/// Spin up the two TDP streams (default + a Group-Solo stream reserved at
/// `alt_reservation_bytes`), the SV2 server with a `GroupSoloResolver(payouts)`
/// plus a recording sink, drive one Noise miner through SetupConnection /
/// OpenStandardMiningChannel / submit until a block lands, and return
/// `(recorded streams, height before, after)`.
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
    node.generate_to_self(1)
        .await
        .expect("mine 1 for templates");

    let recorded: Arc<Mutex<Vec<StreamKind>>> = Arc::new(Mutex::new(Vec::new()));
    let hooks = MiningServerHooks {
        block_sink: Arc::new(RecordingAltSink {
            tdp: tdp_default.clone(),
            tdp_alt: tdp_alt.clone(),
            recorded: recorded.clone(),
        }),
        payout_resolver: Arc::new(GroupSoloResolver { payouts }),
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
        vec![(
            StreamKind::GroupSolo,
            alt_updates_rx,
            tdp_alt.current_snapshot(),
        )],
        hooks,
        bridge,
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

    // OpenStandardMiningChannel with the Group-Solo address → triggers the swap.
    write_any_message(
        &mut writer,
        AnyMessage::Mining(Mining::OpenStandardMiningChannel(
            OpenStandardMiningChannel {
                request_id: 1u32.into(),
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

    // Capture the first NewMiningJob (built from the Group-Solo template post-swap).
    let mut job: Option<(u32, u32, u32, u32)> = None;
    let _ = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let AnyMessage::Mining(Mining::NewMiningJob(j)) = read_any_message(&mut reader).await
            {
                let ntime = j.min_ntime.clone().into_inner().unwrap_or(0);
                job = Some((j.channel_id, j.job_id, j.version, ntime));
                return;
            }
        }
    })
    .await;
    let (channel_id, job_id, version, ntime) = job.expect("NewMiningJob within 8s");

    let before = node.current_height().await.expect("height");
    let mut landed = None;
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
        let _ = tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                if let AnyMessage::Mining(Mining::NewMiningJob(j)) =
                    read_any_message(&mut reader).await
                {
                    let nt = j.min_ntime.clone().into_inner().unwrap_or(nt);
                    latest_job = (j.channel_id, j.job_id, j.version, nt);
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
    (recorded, before, after)
}

// ── helpers (mirror regtest_solo_stream.rs) ─────────────────────────────

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
