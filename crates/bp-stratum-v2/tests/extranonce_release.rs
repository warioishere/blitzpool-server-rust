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
use bp_stratum_v2::extranonce::SharedExtranonceAllocator;
use bp_stratum_v2::hooks::MiningServerHooks;
use bp_stratum_v2::mining::client::{PortConfig, FLAG_REQUIRES_VERSION_ROLLING};
use bp_stratum_v2::noise::NoiseConfig;
use bp_stratum_v2::server::{ServerConfig, StratumV2MiningServer};
use bp_template_distribution::TemplateUpdate;
use stratum_apps::key_utils::Secp256k1PublicKey;
use stratum_apps::network_helpers::connect_with_noise;
use stratum_apps::network_helpers::noise_stream::{NoiseTcpReadHalf, NoiseTcpWriteHalf};
use stratum_core::common_messages_sv2::{Protocol, SetupConnectionOwned};
use stratum_core::mining_sv2::OpenExtendedMiningChannelOwned;
use stratum_core::parsers_sv2::{AnyMessageOwned, CommonMessagesOwned, MiningOwned};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

mod common;
use common::{
    decode_label, read_any_message, sv2_extranonce, wait_until, write_any_message, REGTEST_ADDR,
};

const SRI_TEST_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const SRI_TEST_PRV: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

/// An Extended channel whose connection dies without `CloseChannel` gives its
/// prefix back on connection teardown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ungraceful_disconnect_releases_extranonce_prefix() {
    let (server, _updates_tx) = spawn_server(sv2_extranonce());

    assert_eq!(
        server.allocated_prefix_count(),
        0,
        "fresh server must hold no prefixes"
    );

    let (prefix, reader, writer) = open_extended_channel(&server).await;
    assert_eq!(prefix.len(), 4, "pool hands out a 4-byte prefix");

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

/// The binary builds one SV2 server per port, all on one allocator. Their
/// first channels must get distinct prefixes: two PPLNS ports hash the same
/// coinbase, so a shared prefix there means two miners searching the same
/// space.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_ports_hand_out_distinct_prefixes() {
    let extranonce = sv2_extranonce();
    let (port_a, _updates_a) = spawn_server(extranonce.clone());
    let (port_b, _updates_b) = spawn_server(extranonce);

    let (prefix_a, _reader_a, _writer_a) = open_extended_channel(&port_a).await;
    let (prefix_b, _reader_b, _writer_b) = open_extended_channel(&port_b).await;

    assert_eq!(
        prefix_a.len(),
        4,
        "precondition: a real prefix was allocated"
    );
    assert_ne!(
        prefix_a, prefix_b,
        "channels on two ports of one pool must never share an extranonce prefix"
    );

    port_a.shutdown().await;
    port_b.shutdown().await;
}

/// Spawn a server on `extranonce` with an empty template snapshot. The
/// template sender is handed back so the caller keeps it alive for the whole
/// test.
fn spawn_server(
    extranonce: SharedExtranonceAllocator,
) -> (StratumV2MiningServer, broadcast::Sender<TemplateUpdate>) {
    let (updates_tx, updates_rx) = broadcast::channel::<TemplateUpdate>(8);
    let noise_config =
        NoiseConfig::new(SRI_TEST_PUB.parse().unwrap(), SRI_TEST_PRV.parse().unwrap());
    let server = StratumV2MiningServer::spawn(
        ServerConfig::defaults_for(Network::Regtest),
        noise_config,
        updates_rx,
        bp_template_distribution::TemplateSnapshot::default(),
        Vec::new(),
        MiningServerHooks::no_op(),
        Arc::new(RwLock::new(JdpDeclaredJobRegistry::new())),
        extranonce,
        Arc::new(bp_mining_job::MiningJobCache::new()),
    );
    (server, updates_tx)
}

/// Connect a miner to `server` and open one Extended channel. Returns the
/// prefix the pool assigned plus both socket halves, which the caller keeps
/// alive for as long as the channel should stay open.
async fn open_extended_channel(
    server: &StratumV2MiningServer,
) -> (Vec<u8>, NoiseTcpReadHalf, NoiseTcpWriteHalf) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let port_config = PortConfig {
        network: Network::Regtest,
        min_difficulty: Difficulty(1.0e-18),
        initial_difficulty: Difficulty(1024.0),
        target_shares_per_minute: 6.0,
        vardiff_interval_ms: 200,
        vardiff_silence_easing: false,
        job_lifecycle: bp_jobs_lifecycle::LifecycleConfig::DEFAULT,
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
    let noise = connect_with_noise(miner_socket, Some(pub_key))
        .await
        .expect("noise handshake (initiator)");
    let (mut reader, mut writer) = noise.into_split();

    let setup =
        AnyMessageOwned::Common(CommonMessagesOwned::SetupConnection(SetupConnectionOwned {
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
        }));
    write_any_message(&mut writer, setup).await;
    match read_any_message(&mut reader).await {
        AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionSuccess(_)) => {}
        other => panic!(
            "expected SetupConnectionSuccess, got {}",
            decode_label(&other)
        ),
    }

    let open = AnyMessageOwned::Mining(MiningOwned::OpenExtendedMiningChannel(
        OpenExtendedMiningChannelOwned {
            request_id: 1,
            user_identity: format!("{REGTEST_ADDR}.worker-release").try_into().unwrap(),
            nominal_hash_rate: 5.0e12,
            max_target: [0xFFu8; 32].into(),
            min_extranonce_size: 8,
        },
    ));
    write_any_message(&mut writer, open).await;

    // Drain until the channel is open — SetTarget and friends may interleave.
    for _ in 0..16 {
        if let AnyMessageOwned::Mining(MiningOwned::OpenExtendedMiningChannelSuccess(s)) =
            read_any_message(&mut reader).await
        {
            return (s.extranonce_prefix.as_ref().to_vec(), reader, writer);
        }
    }
    panic!("OpenExtendedMiningChannelSuccess within 16 frames");
}
