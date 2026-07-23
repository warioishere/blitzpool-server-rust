// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end regtest test for the SV2 mining server — Extended channel.
//!
//! Sibling of `regtest_standard.rs`: same Noise + TDP + server topology,
//! but exercises the Extended-channel path. Extended channels differ
//! from Standard in three ways the test pins:
//!
//! 1. **OpenExtendedMiningChannel** carries `min_extranonce_size: u16`;
//!    the success response carries the actual `extranonce_size` (pool-
//!    side allocated) + the `extranonce_prefix` bytes.
//! 2. **NewExtendedMiningJob** carries `version_rolling_allowed: bool`,
//!    a `merkle_path: Seq0255<U256>`, and the coinbase split as
//!    `coinbase_tx_prefix` + `coinbase_tx_suffix` (so the miner can
//!    roll their portion of the extranonce locally without a pool
//!    round-trip).
//! 3. **Shares** can be rolled by the miner — but block-acceptance is
//!    transitive via `bp-mining-job/tests/regtest_e2e.rs` (DEFERRED.md
//!    transitivity argument), so we don't drive a SubmitSharesExtended
//!    here.
//!
//! Skipped (with a printed warning) when `bitcoin-node` isn't installed.

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
use bp_template_distribution::{TdpConfig, TdpHandle};
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

const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const SRI_TEST_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const SRI_TEST_PRV: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_extended_channel_end_to_end_against_regtest() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping SV2 extended e2e — bitcoin-node not found at {} \
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

    wait_until(Duration::from_secs(5), || {
        server.current_template().is_some()
    })
    .await;
    assert!(
        server.current_template().is_some(),
        "translator must have an active template before accepting the miner"
    );

    // ── Bind TCP + accept exactly one connection ──────────────────────
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
    let accept_handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        socket.set_nodelay(true).ok();
        server_clone.accept_connection(socket, port_config);
    });

    // ── Fake miner: Noise-XK + SV2 handshake + open-extended-channel ──
    let miner_socket = TcpStream::connect(addr).await.expect("connect to server");
    miner_socket.set_nodelay(true).ok();
    let pub_key: Secp256k1PublicKey = SRI_TEST_PUB.parse().expect("parse pub key");
    let noise = connect_with_noise::<AnyMessage<'static>>(miner_socket, Some(pub_key))
        .await
        .expect("noise handshake (initiator)");
    let (mut reader, mut writer) = noise.into_split();

    // SetupConnection (mining-protocol, version-rolling flag).
    let setup = AnyMessage::Common(CommonMessages::SetupConnection(
        SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            endpoint_host: "127.0.0.1".to_string().try_into().unwrap(),
            endpoint_port: addr.port(),
            vendor: "regtest-miner-ext".to_string().try_into().unwrap(),
            hardware_version: "v1".to_string().try_into().unwrap(),
            firmware: "0.1".to_string().try_into().unwrap(),
            device_id: "test-ext".to_string().try_into().unwrap(),
        }
        .into_static(),
    ));
    write_any_message(&mut writer, setup).await;

    let resp = read_any_message(&mut reader).await;
    match resp {
        AnyMessage::Common(CommonMessages::SetupConnectionSuccess(s)) => {
            assert_eq!(s.used_version, 2);
            // Server capability bits (SV2 §5.3.2) are built fresh, NOT echoed:
            // a version-rolling client must NOT get REQUIRES_FIXED_VERSION back.
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

    // OpenExtendedMiningChannel: request 10 rollable bytes — ABOVE the old
    // 8-byte cap. This exercises that the pool now HONORS a >8 request exactly
    // (an aggregating proxy needs this) instead of silently under-granting.
    let open = AnyMessage::Mining(Mining::OpenExtendedMiningChannel(
        OpenExtendedMiningChannel {
            request_id: 7,
            user_identity: format!("{REGTEST_ADDR}.worker-ext").try_into().unwrap(),
            nominal_hash_rate: 5.0e12,
            max_target: [0xFFu8; 32].into(),
            min_extranonce_size: 10,
        }
        .into_static(),
    ));
    write_any_message(&mut writer, open).await;

    // Drain frames until we see OpenExtendedMiningChannelSuccess +
    // NewExtendedMiningJob. SetNewPrevHash / SetTarget may interleave.
    let mut got_open_success = false;
    let mut got_new_ext_job = false;
    let mut seen_extranonce_size: Option<u16> = None;
    let mut seen_extranonce_prefix_len: Option<usize> = None;
    let mut seen_version_rolling_allowed: Option<bool> = None;
    let mut seen_merkle_path_len: Option<usize> = None;
    let mut seen_coinbase_prefix_len: Option<usize> = None;
    let mut seen_coinbase_suffix_len: Option<usize> = None;

    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while !got_open_success || !got_new_ext_job {
            let m = read_any_message(&mut reader).await;
            match m {
                AnyMessage::Mining(Mining::OpenExtendedMiningChannelSuccess(s)) => {
                    assert_eq!(s.request_id, 7);
                    seen_extranonce_size = Some(s.extranonce_size);
                    seen_extranonce_prefix_len = Some(s.extranonce_prefix.as_bytes().len());
                    got_open_success = true;
                }
                AnyMessage::Mining(Mining::NewExtendedMiningJob(j)) => {
                    seen_version_rolling_allowed = Some(j.version_rolling_allowed);
                    seen_merkle_path_len = Some(j.merkle_path.as_slice().len());
                    seen_coinbase_prefix_len = Some(j.coinbase_tx_prefix.as_bytes().len());
                    seen_coinbase_suffix_len = Some(j.coinbase_tx_suffix.as_bytes().len());
                    got_new_ext_job = true;
                }
                AnyMessage::Mining(Mining::SetNewPrevHash(_)) => {}
                AnyMessage::Mining(Mining::SetTarget(_)) => {}
                AnyMessage::Mining(Mining::NewMiningJob(_)) => {
                    panic!("Extended channel must not receive NewMiningJob (Standard-only frame)");
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
        "OpenExtendedMiningChannelSuccess must arrive within 5 s"
    );

    // Force a NewBlock fan-out if the broadcast didn't already
    // produce a NewExtendedMiningJob (some templates emit it only on
    // the next NewBlock).
    if !got_new_ext_job {
        node.generate_to_self(1)
            .await
            .expect("mine 1 to force NewBlock broadcast");
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while !got_new_ext_job {
                let m = read_any_message(&mut reader).await;
                if let AnyMessage::Mining(Mining::NewExtendedMiningJob(j)) = m {
                    seen_version_rolling_allowed = Some(j.version_rolling_allowed);
                    seen_merkle_path_len = Some(j.merkle_path.as_slice().len());
                    seen_coinbase_prefix_len = Some(j.coinbase_tx_prefix.as_bytes().len());
                    seen_coinbase_suffix_len = Some(j.coinbase_tx_suffix.as_bytes().len());
                    got_new_ext_job = true;
                    break;
                }
            }
        })
        .await
        .ok();
    }
    assert!(
        got_new_ext_job,
        "must receive at least one NewExtendedMiningJob"
    );

    // ── Assertions on Extended-channel fields ─────────────────────────
    //
    // The pool's ExtranonceAllocator emits 4-byte prefixes by default. The
    // granted extranonce_size must EXACTLY honor the requested
    // min_extranonce_size (10) — the pool no longer caps it at 8.
    let extranonce_size = seen_extranonce_size.expect("Success captured");
    let extranonce_prefix_len = seen_extranonce_prefix_len.expect("Success captured");
    assert_eq!(
        extranonce_prefix_len, 4,
        "pool allocates 4-byte extranonce_prefix by default"
    );
    assert_eq!(
        extranonce_size, 10,
        "pool must honor the requested min_extranonce_size (10) exactly, not cap it"
    );

    // NewExtendedMiningJob carries the version-rolling-allowed flag
    // we set in the SetupConnection (FLAG_REQUIRES_VERSION_ROLLING).
    assert_eq!(
        seen_version_rolling_allowed,
        Some(true),
        "version_rolling_allowed must reflect the negotiated SetupConnection flag"
    );
    // Merkle path is non-empty for any non-genesis template (the
    // regtest chain has at least one in-block tx by the time we
    // generate_to_self).
    let merkle_path_len = seen_merkle_path_len.expect("NewExtendedMiningJob captured");
    // Note: regtest may emit empty merkle paths for empty-mempool
    // blocks. Just sanity-check the value is observed (not the count).
    let _ = merkle_path_len;
    // Coinbase split must be non-empty on both sides.
    let coinbase_prefix_len = seen_coinbase_prefix_len.expect("captured");
    let coinbase_suffix_len = seen_coinbase_suffix_len.expect("captured");
    assert!(
        coinbase_prefix_len > 0,
        "coinbase_tx_prefix must carry the pool-side coinbase bytes"
    );
    assert!(
        coinbase_suffix_len > 0,
        "coinbase_tx_suffix must carry the sequence + outputs + locktime"
    );

    // ── Oversize extranonce request → OpenMiningChannelError (not a
    //    silently-smaller grant). SV2 §5.3.2: grant >= requested min or reject.
    //    17 > the pool's 16-byte rollable cap.
    let oversize = AnyMessage::Mining(Mining::OpenExtendedMiningChannel(
        OpenExtendedMiningChannel {
            request_id: 8,
            user_identity: format!("{REGTEST_ADDR}.worker-ext").try_into().unwrap(),
            nominal_hash_rate: 5.0e12,
            max_target: [0xFFu8; 32].into(),
            min_extranonce_size: 17,
        }
        .into_static(),
    ));
    write_any_message(&mut writer, oversize).await;
    let mut got_reject = false;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while !got_reject {
            match read_any_message(&mut reader).await {
                AnyMessage::Mining(Mining::OpenMiningChannelError(e)) => {
                    assert_eq!(e.request_id, 8);
                    assert_eq!(
                        std::str::from_utf8(e.error_code.as_ref()).unwrap(),
                        "min-extranonce-size-too-large"
                    );
                    got_reject = true;
                }
                // Broadcast job / prev-hash / target frames for the already-open
                // channel may interleave — ignore them while awaiting the reject.
                AnyMessage::Mining(_) => {}
                other => panic!(
                    "unexpected frame while awaiting oversize reject: {:?}",
                    decode_label(&other)
                ),
            }
        }
    })
    .await
    .ok();
    assert!(
        got_reject,
        "oversize min_extranonce_size must be rejected with OpenMiningChannelError"
    );

    // ── Clean teardown ────────────────────────────────────────────────
    drop(writer);
    drop(reader);
    server.shutdown().await;
    tdp.shutdown().expect("TDP shutdown");
    node.shutdown().await.expect("regtest shutdown");
    let _ = accept_handle.await;
}

// ── Helpers (identical to regtest_standard.rs) ──────────────────────

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
