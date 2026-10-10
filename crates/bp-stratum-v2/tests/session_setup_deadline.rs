// SPDX-License-Identifier: AGPL-3.0-or-later

//! A connection that finishes Noise but never completes `SetupConnection` is
//! closed after `bp_common::SESSION_SETUP_DEADLINE`; one that completed it may
//! idle without a channel, as a JD-Client does until a miner attaches below it.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bitcoin::Network;
use bp_share::Difficulty;
use bp_stratum_v2::bridge::JdpDeclaredJobRegistry;
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
use common::{decode_label, read_any_message, sv2_extranonce, write_any_message, REGTEST_ADDR};

const SRI_TEST_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const SRI_TEST_PRV: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

/// Past the deadline, plus slack for scheduling.
const PAST_DEADLINE: Duration = Duration::from_secs(12);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_without_setup_is_closed_and_one_after_setup_may_idle() {
    assert!(PAST_DEADLINE > bp_common::SESSION_SETUP_DEADLINE);
    let (updates_tx, updates_rx) = broadcast::channel::<TemplateUpdate>(8);
    let server = StratumV2MiningServer::spawn(
        ServerConfig::defaults_for(Network::Regtest),
        NoiseConfig::new(SRI_TEST_PUB.parse().unwrap(), SRI_TEST_PRV.parse().unwrap()),
        updates_rx,
        bp_template_distribution::TemplateSnapshot::default(),
        Vec::new(),
        MiningServerHooks::no_op(),
        Arc::new(RwLock::new(JdpDeclaredJobRegistry::new())),
        sv2_extranonce(),
        Arc::new(bp_mining_job::MiningJobCache::new()),
    );

    let (mut silent_reader, _silent_writer, _) = connect(&server).await;
    let (mut idle_reader, mut idle_writer, port) = connect(&server).await;
    setup_connection(&mut idle_reader, &mut idle_writer, port).await;

    // The silent one is closed within the window.
    let closed = tokio::time::timeout(PAST_DEADLINE, silent_reader.read_frame()).await;
    assert!(
        matches!(closed, Ok(Err(_))),
        "a session with no SetupConnection must be closed by the deadline"
    );

    // The idle one is still served: it opens a channel after the deadline.
    let open = AnyMessageOwned::Mining(MiningOwned::OpenExtendedMiningChannel(
        OpenExtendedMiningChannelOwned {
            request_id: 1,
            user_identity: format!("{REGTEST_ADDR}.idle").try_into().unwrap(),
            nominal_hash_rate: 5.0e12,
            max_target: [0xFFu8; 32].into(),
            min_extranonce_size: 8,
        },
    ));
    write_any_message(&mut idle_writer, open).await;
    let mut opened = false;
    for _ in 0..16 {
        if let AnyMessageOwned::Mining(MiningOwned::OpenExtendedMiningChannelSuccess(_)) =
            read_any_message(&mut idle_reader).await
        {
            opened = true;
            break;
        }
    }
    assert!(
        opened,
        "a set-up session idling past the deadline must stay open"
    );

    drop(updates_tx);
    server.shutdown().await;
}

/// TCP plus Noise to a fresh port of `server`; nothing else is sent.
async fn connect(server: &StratumV2MiningServer) -> (NoiseTcpReadHalf, NoiseTcpWriteHalf, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let port_config = PortConfig {
        network: Network::Regtest,
        min_difficulty: Difficulty(1.0e-18),
        initial_difficulty: Difficulty(1024.0),
        target_shares_per_minute: 6.0,
        vardiff_interval_ms: 200,
        job_lifecycle: bp_jobs_lifecycle::LifecycleConfig::DEFAULT,
    };
    let server = server.clone();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        socket.set_nodelay(true).ok();
        server.accept_connection(socket, port_config);
    });
    let socket = TcpStream::connect(addr).await.expect("connect");
    socket.set_nodelay(true).ok();
    let pub_key: Secp256k1PublicKey = SRI_TEST_PUB.parse().expect("parse pub key");
    let noise = connect_with_noise(socket, Some(pub_key))
        .await
        .expect("noise handshake (initiator)");
    let (reader, writer) = noise.into_split();
    (reader, writer, addr.port())
}

async fn setup_connection(
    reader: &mut NoiseTcpReadHalf,
    writer: &mut NoiseTcpWriteHalf,
    port: u16,
) {
    let setup =
        AnyMessageOwned::Common(CommonMessagesOwned::SetupConnection(SetupConnectionOwned {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            endpoint_host: "127.0.0.1".to_string().try_into().unwrap(),
            endpoint_port: port,
            vendor: "deadline-test".to_string().try_into().unwrap(),
            hardware_version: "v1".to_string().try_into().unwrap(),
            firmware: "0.1".to_string().try_into().unwrap(),
            device_id: "deadline".to_string().try_into().unwrap(),
        }));
    write_any_message(writer, setup).await;
    match read_any_message(reader).await {
        AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionSuccess(_)) => {}
        other => panic!(
            "expected SetupConnectionSuccess, got {}",
            decode_label(&other)
        ),
    }
}
