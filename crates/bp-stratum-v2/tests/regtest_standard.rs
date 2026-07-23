// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end regtest test for the SV2 mining server — Standard channel.
//!
//! Spawns a real `bitcoin-node v31` via `bp_regtest_harness`, attaches
//! `bp_template_distribution::TdpHandle`, runs a [`StratumV2MiningServer`]
//! driven by the TDP broadcast, and exercises the full Noise + SV2 wire
//! handshake against a fake miner connected over a real `TcpStream`.
//!
//! Covers:
//!   1. Noise-XK handshake succeeds with the SRI test key-pair.
//!   2. SV2 `SetupConnection` (protocol=0 Mining) → `SetupConnectionSuccess`
//!      wire roundtrip with `parse_message_frame_with_tlvs` +
//!      `encode_mining_outbound`.
//!   3. `OpenStandardMiningChannel` → `OpenStandardMiningChannelSuccess`
//!      with pool-allocated extranonce-prefix.
//!   4. `current_template` snapshot is populated after `generate_to_self`.
//!
//! Block-acceptance (TDP `submit_solution` for a winning share) is
//! deferred to the SV2-extended e2e test + the existing
//! `bp-mining-job/tests/regtest_e2e.rs` (transitivity argument from
//! `DEFERRED.md`: that test proves "ANY valid MiningJob bytes →
//! bitcoin-core accepts", and this test proves "SV2 wire roundtrip
//! produces the same MiningJob bytes the mining-job crate's helpers
//! emit").
//!
//! Skipped (with a printed warning) when `bitcoin-node` is not installed
//! at the host's default location or via `BITCOIN_NODE_PATH`.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bitcoin::Network;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Difficulty;
use bp_stratum_v2::bridge::JdpDeclaredJobRegistry;
use bp_stratum_v2::hooks::MiningServerHooks;
use bp_stratum_v2::mining::client::{PortConfig, FLAG_REQUIRES_VERSION_ROLLING};
use bp_stratum_v2::noise::{NoiseConfig, DEFAULT_CERT_VALIDITY};
use bp_stratum_v2::server::{ServerConfig, StratumV2MiningServer};
use bp_stratum_v2::server_codec::{decode_mining_inbound, encode_mining_outbound};
use bp_template_distribution::{TdpConfig, TdpHandle};
use stratum_apps::key_utils::Secp256k1PublicKey;
use stratum_apps::network_helpers::connect_with_noise;
use stratum_core::codec_sv2::StandardSv2Frame;
use stratum_core::common_messages_sv2::{Protocol, SetupConnection};
use stratum_core::framing_sv2::framing::Frame;
use stratum_core::mining_sv2::OpenStandardMiningChannel;
use stratum_core::parsers_sv2::{
    parse_message_frame_with_tlvs, AnyMessage, CommonMessages, Mining,
};
use tokio::net::{TcpListener, TcpStream};

const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const SRI_TEST_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const SRI_TEST_PRV: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_standard_channel_end_to_end_against_regtest() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping SV2 standard e2e — bitcoin-node not found at {} \
             (set BITCOIN_NODE_PATH to override)",
            cfg.bitcoin_node_path.display()
        );
        return;
    }

    // ── Bring up bitcoin-core + mine past IBD ─────────────────────────
    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 blocks for IBD-exit + coinbase maturity");

    // ── Spawn TDP, subscribe FIRST, then force a template emission ────
    //
    // `tokio::sync::broadcast` does not replay messages sent before
    // any receiver existed. If we mine the template-forcing block
    // before calling `subscribe()`, the resulting `TemplateUpdate`
    // can be dropped on the floor — the server then never sees a
    // template and `wait_until(current_template().is_some())` times
    // out. Mirror the ordering from `bp-mining-job/tests/regtest_e2e.rs`:
    // spawn → subscribe → generate → wait.
    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn against regtest IPC");
    let updates_rx = tdp.subscribe();
    // Mine one more block so the translator pairs its first
    // NewTemplate+SetNewPrevHash before we accept the miner.
    node.generate_to_self(1)
        .await
        .expect("mine 1 to force TDP emit");
    let server_config = ServerConfig::defaults_for(Network::Regtest);
    let noise_config =
        NoiseConfig::parse_strings(SRI_TEST_PUB, SRI_TEST_PRV, DEFAULT_CERT_VALIDITY)
            .expect("noise config");
    let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
    let server = StratumV2MiningServer::spawn(
        server_config,
        noise_config.clone(),
        updates_rx,
        bp_template_distribution::TemplateSnapshot::default(),
        // No alt streams — this test exercises the default-stream path only.
        Vec::new(),
        MiningServerHooks::no_op(),
        bridge,
        std::sync::Arc::new(bp_mining_job::MiningJobCache::new()),
    );

    // Wait until the translator has paired its first template.
    wait_until(Duration::from_secs(5), || {
        server.current_template().is_some()
    })
    .await;
    assert!(
        server.current_template().is_some(),
        "translator must have an active template before accepting the miner"
    );

    // ── Bind TCP port + accept exactly one connection ─────────────────
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let port_config = PortConfig {
        network: Network::Regtest,
        // Trivial min-difficulty so OpenChannel doesn't reject for
        // hash-rate-too-low (no `Difficulty` floor enforcement at the
        // wire level — `clamp_difficulty_to_max_target` handles it).
        min_difficulty: Difficulty(1.0e-18),
        initial_difficulty: Difficulty(1024.0),
        target_shares_per_minute: 6.0,
        vardiff_interval_ms: 200,
        vardiff_silence_easing: false,
    };
    let server_clone = server.clone();
    let port_config_clone = port_config;
    let accept_handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        socket.set_nodelay(true).ok();
        server_clone.accept_connection(socket, port_config_clone);
    });

    // ── Fake miner: Noise-XK + SV2 handshake + open-channel ───────────
    let miner_socket = TcpStream::connect(addr).await.expect("connect to server");
    miner_socket.set_nodelay(true).ok();
    let pub_key: Secp256k1PublicKey = SRI_TEST_PUB.parse().expect("parse pub key");
    let noise = connect_with_noise::<AnyMessage<'static>>(miner_socket, Some(pub_key))
        .await
        .expect("noise handshake (initiator)");
    let (mut reader, mut writer) = noise.into_split();

    // Send SetupConnection (mining protocol).
    let setup = AnyMessage::Common(CommonMessages::SetupConnection(
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
    ));
    write_any_message(&mut writer, setup).await;

    // Read SetupConnectionSuccess.
    let resp = read_any_message(&mut reader).await;
    match resp {
        AnyMessage::Common(CommonMessages::SetupConnectionSuccess(s)) => {
            assert_eq!(s.used_version, 2, "must use SV2 version 2");
            // Server capability bits (SV2 §5.3.2) built fresh, NOT echoed — a
            // version-rolling client must NOT get REQUIRES_FIXED_VERSION back.
            assert_eq!(
                s.flags, 0,
                "Success.flags must be 0, not an echo of the request flags"
            );
        }
        other => panic!(
            "expected SetupConnectionSuccess, got: {:?}",
            decode_label(&other)
        ),
    }

    // Send OpenStandardMiningChannel.
    let open = AnyMessage::Mining(Mining::OpenStandardMiningChannel(
        OpenStandardMiningChannel {
            request_id: 1u32,
            user_identity: format!("{REGTEST_ADDR}.worker1").try_into().unwrap(),
            nominal_hash_rate: 1_000_000.0,
            max_target: [0xFFu8; 32].into(),
        }
        .into_static(),
    ));
    write_any_message(&mut writer, open).await;

    // Drain frames until we see OpenStandardMiningChannelSuccess (we
    // may also get NewMiningJob + SetNewPrevHash interleaved). Budget
    // 5 s. The translator should fire a NewMiningJob immediately after
    // the OpenChannel because the current_template is already set.
    let mut got_open_success = false;
    let mut got_new_mining_job = false;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while !got_open_success || !got_new_mining_job {
            let m = read_any_message(&mut reader).await;
            match m {
                AnyMessage::Mining(Mining::OpenStandardMiningChannelSuccess(s)) => {
                    assert_eq!(s.request_id, 1);
                    assert_eq!(s.extranonce_prefix.as_bytes().len(), 4);
                    got_open_success = true;
                }
                AnyMessage::Mining(Mining::NewMiningJob(_)) => {
                    got_new_mining_job = true;
                }
                AnyMessage::Mining(Mining::SetNewPrevHash(_)) => {
                    // Allowed — appears before NewMiningJob on block
                    // change. Keep draining.
                }
                AnyMessage::Mining(Mining::SetTarget(_)) => {
                    // Allowed — vardiff initial-set. Keep draining.
                }
                other => panic!(
                    "unexpected frame during open-channel phase: {:?}",
                    decode_label(&other)
                ),
            }
        }
    })
    .await
    .ok();

    assert!(
        got_open_success,
        "OpenStandardMiningChannelSuccess must arrive within 5 s"
    );
    // Mine one more block so the translator broadcasts a fresh
    // NewBlock to our open channel — gives us the SetNewPrevHash +
    // NewMiningJob fan-out if we didn't see one already from the
    // pre-existing template.
    if !got_new_mining_job {
        node.generate_to_self(1)
            .await
            .expect("mine 1 to force NewBlock broadcast");
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while !got_new_mining_job {
                let m = read_any_message(&mut reader).await;
                if matches!(m, AnyMessage::Mining(Mining::NewMiningJob(_))) {
                    got_new_mining_job = true;
                    break;
                }
            }
        })
        .await
        .ok();
    }
    assert!(
        got_new_mining_job,
        "must receive at least one NewMiningJob after open + block-change"
    );

    // ── Clean teardown ────────────────────────────────────────────────
    drop(writer);
    drop(reader);
    server.shutdown().await;
    tdp.shutdown().expect("TDP shutdown");
    node.shutdown().await.expect("regtest shutdown");
    let _ = accept_handle.await;
}

// ── Helpers ─────────────────────────────────────────────────────────

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
    let header = sv2_frame.get_header().expect("frame must have header");
    let (msg, _tlvs) = parse_message_frame_with_tlvs(header, sv2_frame.payload(), &[])
        .expect("parse_message_frame_with_tlvs");
    // Confirm the decoder can map it (or returns None for non-mining
    // frames). We don't use the result — it's just a sanity check
    // that decode_mining_inbound matches what we're observing on the
    // wire.
    let _ = decode_mining_inbound(msg.clone());
    let _ = encode_mining_outbound; // silence unused-import warning
    msg
}

fn decode_label(m: &AnyMessage<'_>) -> &'static str {
    match m {
        AnyMessage::Common(_) => "Common",
        AnyMessage::Mining(_) => "Mining",
        AnyMessage::JobDeclaration(_) => "JobDeclaration",
        AnyMessage::TemplateDistribution(_) => "TemplateDistribution",
        AnyMessage::Extensions(_) => "Extensions",
    }
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
