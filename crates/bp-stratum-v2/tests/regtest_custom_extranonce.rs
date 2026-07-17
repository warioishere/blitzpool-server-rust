// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: the custom-extranonce override applied at channel-open (stage 1).
//!
//! Two Extended miners connect to the same Solo-routed server:
//!   - one whose `(address, worker)` has an override → must receive a
//!     `SetExtranoncePrefix(custom)` BEFORE its first `NewExtendedMiningJob`,
//!     so it switches prefix and then gets a job built with it;
//!   - one whose worker has NO override → must receive its
//!     `OpenExtendedMiningChannelSuccess` + `NewExtendedMiningJob` with NO
//!     `SetExtranoncePrefix` at all.
//!
//! The second miner is the isolation proof for stage 1: a connection without an
//! override sees exactly the frames it would without the feature.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::Network;
use bp_common::{AddressId, StreamKind};
use bp_mining_job::PayoutEntry;
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Difficulty;
use bp_stratum_v2::bridge::JdpDeclaredJobRegistry;
use bp_stratum_v2::hooks::{CustomExtranonceSource, MiningServerHooks, PayoutResolver};
use bp_stratum_v2::mining::client::{PortConfig, FLAG_REQUIRES_VERSION_ROLLING};
use bp_stratum_v2::noise::{NoiseConfig, DEFAULT_CERT_VALIDITY};
use bp_stratum_v2::server::{ServerConfig, StratumV2MiningServer};
use bp_template_distribution::{TdpCoinbaseConstraints, TdpConfig, TdpHandle};
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

const CUSTOM_WORKER: &str = "custom";
const NORMAL_WORKER: &str = "normal";
const CUSTOM_PREFIX: [u8; 4] = [0xC0, 0xDE, 0xBA, 0xBE];

struct SoloResolver;

#[async_trait]
impl PayoutResolver for SoloResolver {
    async fn resolve_payouts(
        &self,
        miner_address: &AddressId,
        reward_sats: u64,
    ) -> Vec<PayoutEntry> {
        vec![PayoutEntry {
            address: miner_address.as_str().to_string(),
            sats: reward_sats,
        }]
    }
    fn resolve_stream(&self, _miner_address: &AddressId) -> StreamKind {
        StreamKind::Solo
    }
}

/// Override present only for `(REGTEST_ADDR, CUSTOM_WORKER)`.
struct FixedCustomSource;

impl CustomExtranonceSource for FixedCustomSource {
    fn lookup(&self, address: &str, worker: &str) -> Option<[u8; 4]> {
        (address == REGTEST_ADDR && worker == CUSTOM_WORKER).then_some(CUSTOM_PREFIX)
    }
}

/// What a miner saw between OpenExtendedMiningChannel and its first job.
struct OpenObservation {
    /// The prefix in `OpenExtendedMiningChannelSuccess` (pool-allocated).
    success_prefix: Vec<u8>,
    /// The prefix in a `SetExtranoncePrefix`, if one arrived before the job.
    set_extranonce_prefix: Option<Vec<u8>>,
    got_job: bool,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_custom_extranonce_applies_at_open_and_leaves_others_untouched() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping SV2 custom-extranonce regtest — bitcoin-node not found at {}",
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

    let hooks = MiningServerHooks {
        payout_resolver: Arc::new(SoloResolver),
        custom_extranonce: Arc::new(FixedCustomSource),
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
        Arc::new(bp_mining_job::MiningJobCache::new()),
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
        while let Ok((socket, _)) = listener.accept().await {
            socket.set_nodelay(true).ok();
            server_clone.accept_connection(socket, port_config);
        }
    });

    // Miner with an override.
    let custom = open_extended(addr, CUSTOM_WORKER).await;
    // Miner without one.
    let normal = open_extended(addr, NORMAL_WORKER).await;

    server.shutdown().await;
    tdp_default.shutdown().ok();
    tdp_solo.shutdown().ok();
    node.shutdown().await.ok();
    accept_handle.abort();

    eprintln!(
        "[custom-en] custom: success_prefix={:02x?} set_extranonce={:02x?} job={}",
        custom.success_prefix, custom.set_extranonce_prefix, custom.got_job
    );
    eprintln!(
        "[custom-en] normal: success_prefix={:02x?} set_extranonce={:02x?} job={}",
        normal.success_prefix, normal.set_extranonce_prefix, normal.got_job
    );

    // The pool allocates from worker 0 (`0x00…`) for both.
    assert_eq!(custom.success_prefix.first(), Some(&0x00));
    assert_eq!(normal.success_prefix.first(), Some(&0x00));

    // Custom miner: a SetExtranoncePrefix with the customer's value arrives
    // before the first job.
    assert_eq!(
        custom.set_extranonce_prefix.as_deref(),
        Some(CUSTOM_PREFIX.as_slice()),
        "custom miner must receive SetExtranoncePrefix with its override before the job"
    );
    assert!(custom.got_job, "custom miner must receive a job");

    // Normal miner: no SetExtranoncePrefix at all — byte-for-byte the frames it
    // would see without the feature.
    assert!(
        normal.set_extranonce_prefix.is_none(),
        "a miner without an override must never receive SetExtranoncePrefix; got {:02x?}",
        normal.set_extranonce_prefix
    );
    assert!(normal.got_job, "normal miner must receive a job");
}

/// Connect, handshake, open an Extended channel for `worker`, and drain frames
/// until the first `NewExtendedMiningJob` (or timeout), recording whether a
/// `SetExtranoncePrefix` arrived first and the success/set prefixes.
async fn open_extended(server_addr: std::net::SocketAddr, worker: &str) -> OpenObservation {
    let socket = TcpStream::connect(server_addr).await.expect("connect");
    socket.set_nodelay(true).ok();
    let pub_key: Secp256k1PublicKey = SRI_TEST_PUB.parse().expect("parse pub key");
    let noise = connect_with_noise::<AnyMessage<'static>>(socket, Some(pub_key))
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
                endpoint_port: server_addr.port(),
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

    write_any_message(
        &mut writer,
        AnyMessage::Mining(Mining::OpenExtendedMiningChannel(
            OpenExtendedMiningChannel {
                request_id: 1,
                user_identity: format!("{REGTEST_ADDR}.{worker}").try_into().unwrap(),
                nominal_hash_rate: 0.0,
                max_target: [0xFFu8; 32].into(),
                min_extranonce_size: 8,
            }
            .into_static(),
        )),
    )
    .await;

    let mut success_prefix: Option<Vec<u8>> = None;
    let mut set_extranonce_prefix: Option<Vec<u8>> = None;
    let mut got_job = false;
    let _ = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            match read_any_message(&mut reader).await {
                AnyMessage::Mining(Mining::OpenExtendedMiningChannelSuccess(s)) => {
                    success_prefix = Some(s.extranonce_prefix.as_ref().to_vec());
                }
                AnyMessage::Mining(Mining::SetExtranoncePrefix(s)) => {
                    set_extranonce_prefix = Some(s.extranonce_prefix.as_ref().to_vec());
                }
                AnyMessage::Mining(Mining::NewExtendedMiningJob(_)) => {
                    got_job = true;
                    return; // first job — we've seen the full open sequence
                }
                _ => {}
            }
        }
    })
    .await;

    drop(writer);
    drop(reader);
    OpenObservation {
        success_prefix: success_prefix.unwrap_or_default(),
        set_extranonce_prefix,
        got_job,
    }
}

// ── helpers (mirror the sibling regtests) ───────────────────────────────

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
