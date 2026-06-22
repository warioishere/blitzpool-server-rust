// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: SV2 per-mode stream routing (Phase 1).
//!
//! The SV2 counterpart of `bp-stratum-v1/tests/regtest_solo_stream.rs`. Proves
//! that a connection whose `OpenStandardMiningChannel` address resolves to
//! **Solo** is routed onto the dedicated Solo template stream by
//! `run_mining_connection`, and a block it finds is submitted through the
//! **Solo TDP handle** and accepted by bitcoin-core.
//!
//! Guards: a recording block-sink captures the `StreamKind` of every
//! block-submit (`Solo` proves the OpenChannel swap fired), and the chain
//! advancing proves the Solo handle knew the job's `template_id` (template_ids
//! collide across streams — a mis-routed submit would be rejected).

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

struct SoloResolver;

#[async_trait]
impl PayoutResolver for SoloResolver {
    async fn resolve_payouts(
        &self,
        miner_address: &AddressId,
        _reward_sats: u64,
    ) -> Vec<PayoutEntry> {
        vec![PayoutEntry {
            address: miner_address.as_str().to_string(),
            percent: 100.0,
        }]
    }

    fn resolve_stream(&self, _miner_address: &AddressId) -> StreamKind {
        StreamKind::Solo
    }
}

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
        _session_id_hex: &str,
        stream: StreamKind,
    ) {
        self.recorded.lock().unwrap().push(stream);
        if accept.witness_coinbase.is_empty() || accept.template_id.is_none() {
            return;
        }
        let handle = if stream == StreamKind::Solo {
            &self.tdp_solo
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
#[allow(clippy::print_stderr)]
async fn sv2_solo_connection_routes_to_solo_stream_and_block_accepted() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping SV2 solo-stream regtest — bitcoin-node not found at {}",
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
        .expect("mine 1 for templates");

    let recorded: Arc<Mutex<Vec<StreamKind>>> = Arc::new(Mutex::new(Vec::new()));
    let hooks = MiningServerHooks {
        block_sink: Arc::new(RecordingSoloSink {
            tdp: tdp_default.clone(),
            tdp_solo: tdp_solo.clone(),
            recorded: recorded.clone(),
        }),
        payout_resolver: Arc::new(SoloResolver),
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
            StreamKind::Solo,
            solo_updates_rx,
            tdp_solo.current_snapshot(),
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
    // Trivial difficulty → every submit is accepted; ~50% of nonces also clear
    // the easy regtest network target → block candidates.
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

    // SetupConnection → success.
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

    // OpenStandardMiningChannel with the Solo address → triggers the swap.
    write_any_message(
        &mut writer,
        AnyMessage::Mining(Mining::OpenStandardMiningChannel(
            OpenStandardMiningChannel {
                request_id: 1u32.into(),
                user_identity: format!("{REGTEST_ADDR}.w1").try_into().unwrap(),
                // 0 H/s → the server assigns `min_difficulty` (1e-18 here) →
                // trivial session target → every submit is accepted, and on
                // regtest's tiny network difficulty ~every accepted share is a
                // block candidate (so block_sink.submit_block fires).
                nominal_hash_rate: 0.0,
                max_target: [0xFFu8; 32].into(),
            }
            .into_static(),
        )),
    )
    .await;

    // Capture the first NewMiningJob (built from the Solo template post-swap):
    // it carries channel_id + job_id + version + min_ntime we need to submit.
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

    // Submit nonces until the chain advances (a block landed via the Solo
    // handle). ~50% of nonces clear the regtest target → lands within a few.
    eprintln!("[sv2-solo] captured job: channel_id={channel_id} job_id={job_id} version={version:#x} ntime={ntime}");
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
                        errors
                            .push(String::from_utf8_lossy(e.error_code.inner_as_ref()).to_string());
                    }
                    AnyMessage::Mining(Mining::SubmitSharesSuccess(_)) => successes += 1,
                    // Track job refresh so we don't submit against a stale id.
                    AnyMessage::Mining(Mining::NewMiningJob(j)) => {
                        let nt = j.min_ntime.clone().into_inner().unwrap_or(nt);
                        latest_job = (j.channel_id, j.job_id, j.version, nt);
                    }
                    _ => {}
                }
            }
        })
        .await;
        if let Some(h) = poll_for_height(&node, before + 1, Duration::from_millis(400)).await {
            landed = Some(h);
            break;
        }
    }
    eprintln!("[sv2-solo] submits: {successes} success, errors={errors:?}");

    drop(writer);
    drop(reader);
    server.shutdown().await;
    tdp_default.shutdown().ok();
    tdp_solo.shutdown().ok();
    let after = landed.unwrap_or(before);
    let recorded = recorded.lock().unwrap().clone();
    node.shutdown().await.ok();
    let _ = accept_handle.await;

    eprintln!("[sv2-solo] recorded streams = {recorded:?}, height {before} → {after}");
    assert!(
        recorded.contains(&StreamKind::Solo),
        "block-submit must be routed via the Solo stream (OpenChannel swap); recorded {recorded:?}"
    );
    assert!(
        recorded.iter().all(|s| *s == StreamKind::Solo),
        "a Solo connection must never submit via the Default stream; recorded {recorded:?}"
    );
    assert!(
        after > before,
        "bitcoin-core must accept the Solo-stream block via the Solo handle ({before} → {after})"
    );
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
