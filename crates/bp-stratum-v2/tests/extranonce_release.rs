// SPDX-License-Identifier: AGPL-3.0-or-later

//! Extranonce-prefix release paths on the SV2 mining server.
//!
//! A prefix is taken out of the pool-wide allocator when a channel opens
//! and must go back when the channel goes away — otherwise the allocator's
//! `used` set only ever grows and prefixes are stranded until the process
//! restarts.
//!
//! `CloseChannel` covers the graceful case. This file pins the one that
//! isn't graceful: a miner that drops its TCP connection (power-cut, crash,
//! network blip) never sends `CloseChannel`, so the release has to happen on
//! connection teardown.
//!
//! Needs no bitcoin-core: a channel allocates its prefix at open time,
//! independent of whether a template ever arrives, so the server runs here
//! on an empty template snapshot.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bitcoin::Network;
use bp_share::Difficulty;
use bp_stratum_v2::bridge::JdpDeclaredJobRegistry;
use bp_stratum_v2::hooks::MiningServerHooks;
use bp_stratum_v2::mining::client::{PortConfig, FLAG_REQUIRES_VERSION_ROLLING};
use bp_stratum_v2::noise::{NoiseConfig, DEFAULT_CERT_VALIDITY};
use bp_stratum_v2::server::{ServerConfig, StratumV2MiningServer};
use bp_template_distribution::TemplateUpdate;
use stratum_apps::key_utils::Secp256k1PublicKey;
use stratum_apps::network_helpers::connect_with_noise;
use stratum_core::codec_sv2::StandardSv2Frame;
use stratum_core::common_messages_sv2::{Protocol, SetupConnection};
use stratum_core::framing_sv2::framing::Frame;
use stratum_core::mining_sv2::OpenExtendedMiningChannel;
use stratum_core::parsers_sv2::{
    parse_message_frame_with_tlvs, AnyMessage, CommonMessages, Mining,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const SRI_TEST_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const SRI_TEST_PRV: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

/// An Extended channel whose connection dies without `CloseChannel` gives its
/// prefix back. Regression pin: the teardown release used to be missing
/// entirely, so an ungracefully-dropped miner stranded its prefix for the
/// lifetime of the process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ungraceful_disconnect_releases_extranonce_prefix() {
    let (_updates_tx, updates_rx) = broadcast::channel::<TemplateUpdate>(8);
    let noise_config =
        NoiseConfig::parse_strings(SRI_TEST_PUB, SRI_TEST_PRV, DEFAULT_CERT_VALIDITY)
            .expect("noise config");
    let server = StratumV2MiningServer::spawn(
        ServerConfig::defaults_for(Network::Regtest),
        noise_config,
        updates_rx,
        bp_template_distribution::TemplateSnapshot::default(),
        Vec::new(),
        MiningServerHooks::no_op(),
        Arc::new(RwLock::new(JdpDeclaredJobRegistry::new())),
        Arc::new(bp_mining_job::MiningJobCache::new()),
    );

    assert_eq!(
        server.allocated_prefix_count(),
        0,
        "fresh server must hold no prefixes"
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let port_config = PortConfig {
        network: Network::Regtest,
        min_difficulty: Difficulty(1.0e-18),
        initial_difficulty: Difficulty(1024.0),
        target_shares_per_minute: 6.0,
        vardiff_interval_ms: 200,
        vardiff_silence_easing: false,
    };
    let server_clone = server.clone();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        socket.set_nodelay(true).ok();
        server_clone.accept_connection(socket, port_config);
    });

    // ── Miner: Noise-XK → SetupConnection → OpenExtendedMiningChannel ──
    let miner_socket = TcpStream::connect(addr).await.expect("connect to server");
    miner_socket.set_nodelay(true).ok();
    let pub_key: Secp256k1PublicKey = SRI_TEST_PUB.parse().expect("parse pub key");
    let noise = connect_with_noise::<AnyMessage<'static>>(miner_socket, Some(pub_key))
        .await
        .expect("noise handshake (initiator)");
    let (mut reader, mut writer) = noise.into_split();

    let setup = AnyMessage::Common(CommonMessages::SetupConnection(
        SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            endpoint_host: "127.0.0.1".to_string().try_into().unwrap(),
            endpoint_port: addr.port(),
            vendor: "release-test".to_string().try_into().unwrap(),
            hardware_version: "v1".to_string().try_into().unwrap(),
            firmware: "0.1".to_string().try_into().unwrap(),
            device_id: "test-release".to_string().try_into().unwrap(),
        }
        .into_static(),
    ));
    write_any_message(&mut writer, setup).await;
    match read_any_message(&mut reader).await {
        AnyMessage::Common(CommonMessages::SetupConnectionSuccess(_)) => {}
        other => panic!("expected SetupConnectionSuccess, got {}", label(&other)),
    }

    let open = AnyMessage::Mining(Mining::OpenExtendedMiningChannel(
        OpenExtendedMiningChannel {
            request_id: 1,
            user_identity: format!("{REGTEST_ADDR}.worker-release").try_into().unwrap(),
            nominal_hash_rate: 5.0e12,
            max_target: [0xFFu8; 32].into(),
            min_extranonce_size: 8,
        }
        .into_static(),
    ));
    write_any_message(&mut writer, open).await;

    // Drain until the channel is open — SetTarget and friends may interleave.
    let mut prefix_len = None;
    for _ in 0..16 {
        if let AnyMessage::Mining(Mining::OpenExtendedMiningChannelSuccess(s)) =
            read_any_message(&mut reader).await
        {
            prefix_len = Some(s.extranonce_prefix.as_ref().len());
            break;
        }
    }
    let prefix_len = prefix_len.expect("OpenExtendedMiningChannelSuccess within 16 frames");
    assert_eq!(prefix_len, 4, "pool hands out a 4-byte prefix");

    wait_until(Duration::from_secs(5), || {
        server.allocated_prefix_count() == 1
    })
    .await;
    assert_eq!(
        server.allocated_prefix_count(),
        1,
        "open Extended channel must hold exactly one prefix"
    );

    // ── The point of the test: drop the socket. No CloseChannel, no ──
    // ── shutdown handshake — exactly what a power-cut miner does.   ──
    drop(reader);
    drop(writer);

    wait_until(Duration::from_secs(5), || {
        server.allocated_prefix_count() == 0
    })
    .await;
    assert_eq!(
        server.allocated_prefix_count(),
        0,
        "prefix must return to the allocator when the connection dies without \
         CloseChannel — otherwise it is stranded until the process restarts"
    );

    server.shutdown().await;
}

// ── Helpers (mirrors of the ones in regtest_extended.rs) ─────────────

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
    msg
}

fn label(m: &AnyMessage<'_>) -> &'static str {
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
