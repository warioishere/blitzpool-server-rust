// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest e2e for a Standard channel: Noise-XK + `SetupConnection` +
//! `OpenStandardMiningChannel` over a real socket against a real
//! `bitcoin-node`, through to the first `NewMiningJob`. Block acceptance is
//! covered by `regtest_stream_routing.rs`; skipped without `bitcoin-node`.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bitcoin::Network;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Difficulty;
use bp_stratum_v2::bridge::JdpDeclaredJobRegistry;
use bp_stratum_v2::hooks::MiningServerHooks;
use bp_stratum_v2::mining::client::{PortConfig, FLAG_REQUIRES_VERSION_ROLLING};
use bp_stratum_v2::noise::NoiseConfig;
use bp_stratum_v2::server::{ServerConfig, StratumV2MiningServer};
use bp_template_distribution::{TdpConfig, TdpHandle};
use stratum_apps::key_utils::Secp256k1PublicKey;
use stratum_apps::network_helpers::connect_with_noise;
use stratum_core::common_messages_sv2::{Protocol, SetupConnectionOwned};
use stratum_core::mining_sv2::OpenStandardMiningChannelOwned;
use stratum_core::parsers_sv2::{AnyMessageOwned, CommonMessagesOwned, MiningOwned};
use tokio::net::{TcpListener, TcpStream};

mod common;
use common::{decode_label, read_any_message, wait_until, write_any_message, REGTEST_ADDR};

const SRI_TEST_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const SRI_TEST_PRV: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_standard_channel_end_to_end_against_regtest() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!("skipping SV2 standard e2e — {}", cfg.unavailable_reason());
        return;
    }

    // ── Bring up bitcoin-core + mine past IBD ─────────────────────────
    let node = RegtestNode::start_with(cfg).await.expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 blocks for IBD-exit + coinbase maturity");

    // ── Spawn TDP, subscribe FIRST, then force a template emission ────
    // `broadcast` does not replay to late receivers, so a template forced
    // before `subscribe()` would be lost.
    let tdp = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1),
    )
    .expect("TdpHandle::spawn against regtest IPC");
    let updates_rx = tdp.subscribe();
    // Mine one more block so the translator pairs its first
    // NewTemplate+SetNewPrevHash before the miner connects.
    node.generate_to_self(1)
        .await
        .expect("mine 1 to force TDP emit");
    let server_config = ServerConfig::defaults_for(Network::Regtest);
    let noise_config =
        NoiseConfig::new(SRI_TEST_PUB.parse().unwrap(), SRI_TEST_PRV.parse().unwrap());
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
        common::sv2_extranonce(),
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
        job_lifecycle: bp_jobs_lifecycle::LifecycleConfig::DEFAULT,
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
    let noise = connect_with_noise(miner_socket, Some(pub_key))
        .await
        .expect("noise handshake (initiator)");
    let (mut reader, mut writer) = noise.into_split();

    // Send SetupConnection (mining protocol).
    let setup =
        AnyMessageOwned::Common(CommonMessagesOwned::SetupConnection(SetupConnectionOwned {
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
        }));
    write_any_message(&mut writer, setup).await;

    // Read SetupConnectionSuccess.
    let resp = read_any_message(&mut reader).await;
    match resp {
        AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionSuccess(s)) => {
            assert_eq!(s.used_version, 2, "must use SV2 version 2");
            // Server capability bits
            // (SV2 Mining/SetupConnection Flags for Mining Protocol) built
            // fresh, NOT echoed — a version-rolling client must NOT get
            // REQUIRES_FIXED_VERSION back.
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
    let open = AnyMessageOwned::Mining(MiningOwned::OpenStandardMiningChannel(
        OpenStandardMiningChannelOwned {
            request_id: 1u32,
            user_identity: format!("{REGTEST_ADDR}.worker1").try_into().unwrap(),
            nominal_hash_rate: 1_000_000.0,
            max_target: [0xFFu8; 32].into(),
        },
    ));
    write_any_message(&mut writer, open).await;

    // Drain frames until OpenStandardMiningChannelSuccess and a
    // NewMiningJob arrive (SetNewPrevHash / SetTarget may interleave).
    // Budget 5 s; the job follows the open because a template is set.
    let mut got_open_success = false;
    let mut got_new_mining_job = false;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while !got_open_success || !got_new_mining_job {
            let m = read_any_message(&mut reader).await;
            match m {
                AnyMessageOwned::Mining(MiningOwned::OpenStandardMiningChannelSuccess(s)) => {
                    assert_eq!(s.request_id, 1);
                    assert_eq!(s.extranonce_prefix.as_bytes().len(), 4);
                    got_open_success = true;
                }
                AnyMessageOwned::Mining(MiningOwned::NewMiningJob(_)) => {
                    got_new_mining_job = true;
                }
                AnyMessageOwned::Mining(MiningOwned::SetNewPrevHash(_)) => {
                    // Allowed — appears before NewMiningJob on block
                    // change. Keep draining.
                }
                AnyMessageOwned::Mining(MiningOwned::SetTarget(_)) => {
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
    // No job yet: mine one more block to force a fresh
    // SetNewPrevHash + NewMiningJob fan-out to the open channel.
    if !got_new_mining_job {
        node.generate_to_self(1)
            .await
            .expect("mine 1 to force NewBlock broadcast");
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while !got_new_mining_job {
                let m = read_any_message(&mut reader).await;
                if matches!(m, AnyMessageOwned::Mining(MiningOwned::NewMiningJob(_))) {
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
