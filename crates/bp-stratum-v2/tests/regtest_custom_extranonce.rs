// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: the custom-extranonce override, at channel-open AND live.
//!
//! Two Extended miners stay connected to the same Solo-routed server:
//!   - one whose `(address, worker)` has an override;
//!   - one whose worker has none.
//!
//! Stage 1 (channel-open): the override miner receives `SetExtranoncePrefix`
//! before its first job; the other receives none.
//!
//! Stage 2 (live change, no reconnect): the override value is changed and a new
//! template is triggered (mining a block). The override miner receives a
//! `SetExtranoncePrefix` with the NEW value plus a fresh job — without
//! reconnecting. The other miner, across every broadcast in that window,
//! receives its normal jobs and NEVER a `SetExtranoncePrefix`. That second
//! miner is the isolation proof: the live path leaves non-customers untouched.

use std::sync::{Arc, Mutex, RwLock};
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
use stratum_apps::network_helpers::noise_stream::{NoiseTcpReadHalf, NoiseTcpWriteHalf};
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
const PREFIX_1: [u8; 4] = [0xC0, 0xDE, 0xBA, 0xBE];
const PREFIX_2: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

type Reader = NoiseTcpReadHalf<AnyMessage<'static>>;
type Writer = NoiseTcpWriteHalf<AnyMessage<'static>>;

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

/// Override for `(REGTEST_ADDR, CUSTOM_WORKER)` that the test can change live.
struct MutableCustomSource {
    prefix: Mutex<Option<[u8; 4]>>,
}

impl CustomExtranonceSource for MutableCustomSource {
    fn lookup(&self, address: &str, worker: &str) -> Option<[u8; 4]> {
        if address == REGTEST_ADDR && worker == CUSTOM_WORKER {
            *self.prefix.lock().unwrap()
        } else {
            None
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn sv2_custom_extranonce_applies_at_open_and_live_and_leaves_others_untouched() {
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

    let tdp_default = spawn_tdp(&node, 50_000);
    let tdp_solo = spawn_tdp(&node, 1_000);
    let updates_rx = tdp_default.subscribe();
    let solo_updates_rx = tdp_solo.subscribe();
    node.generate_to_self(1)
        .await
        .expect("mine 1 for templates");

    let source = Arc::new(MutableCustomSource {
        prefix: Mutex::new(Some(PREFIX_1)),
    });
    let hooks = MiningServerHooks {
        payout_resolver: Arc::new(SoloResolver),
        custom_extranonce: source.clone(),
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

    // ── Stage 1: open both channels, keep them connected ──
    let (mut c_reader, _c_writer) = connect_and_open(addr, CUSTOM_WORKER).await;
    let c_open = drain_until_first_job(&mut c_reader).await;
    let (mut n_reader, _n_writer) = connect_and_open(addr, NORMAL_WORKER).await;
    let n_open = drain_until_first_job(&mut n_reader).await;

    eprintln!("[custom-en] open custom: set={:02x?}", c_open.set_prefix);
    eprintln!("[custom-en] open normal: set={:02x?}", n_open.set_prefix);
    assert_eq!(
        c_open.set_prefix.as_deref(),
        Some(PREFIX_1.as_slice()),
        "override miner must get SetExtranoncePrefix(PREFIX_1) at open"
    );
    assert!(
        n_open.set_prefix.is_none(),
        "normal miner must get none at open"
    );

    // ── Stage 2: change the override live, trigger a template ──
    *source.prefix.lock().unwrap() = Some(PREFIX_2);
    node.generate_to_self(1)
        .await
        .expect("mine 1 to trigger a template");

    // Drain a window on each connection (no reconnect). Collect every
    // SetExtranoncePrefix seen + whether a fresh job arrived.
    let c_live = drain_window(&mut c_reader, Duration::from_secs(8)).await;
    let n_live = drain_window(&mut n_reader, Duration::from_secs(6)).await;

    server.shutdown().await;
    tdp_default.shutdown().ok();
    tdp_solo.shutdown().ok();
    node.shutdown().await.ok();
    accept_handle.abort();

    eprintln!(
        "[custom-en] live custom: set_prefixes={:02x?} job={}",
        c_live.set_prefixes, c_live.got_job
    );
    eprintln!(
        "[custom-en] live normal: set_prefixes={:02x?} job={}",
        n_live.set_prefixes, n_live.got_job
    );

    // Override miner switched to the new value live, without reconnecting.
    assert!(
        c_live.set_prefixes.iter().any(|p| p.as_slice() == PREFIX_2),
        "override miner must receive SetExtranoncePrefix(PREFIX_2) live; got {:02x?}",
        c_live.set_prefixes
    );
    assert!(c_live.got_job, "override miner must receive a fresh job");

    // Normal miner: fresh jobs, but NEVER a SetExtranoncePrefix — the isolation
    // proof for the live path.
    assert!(
        n_live.set_prefixes.is_empty(),
        "normal miner must never receive SetExtranoncePrefix; got {:02x?}",
        n_live.set_prefixes
    );
    assert!(n_live.got_job, "normal miner must keep receiving jobs");
}

// ── observation types ───────────────────────────────────────────────────

struct OpenObs {
    set_prefix: Option<Vec<u8>>,
}

struct WindowObs {
    set_prefixes: Vec<Vec<u8>>,
    got_job: bool,
}

// ── helpers ──────────────────────────────────────────────────────────────

fn spawn_tdp(node: &RegtestNode, max_additional_size: u32) -> TdpHandle {
    TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1)
            .with_coinbase_constraints(TdpCoinbaseConstraints {
                max_additional_size,
                max_additional_sigops: 0,
            }),
    )
    .expect("spawn TDP")
}

/// Noise handshake + SetupConnection + OpenExtendedMiningChannel for `worker`.
/// Returns the split halves; the caller drains the response.
async fn connect_and_open(server_addr: std::net::SocketAddr, worker: &str) -> (Reader, Writer) {
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
    (reader, writer)
}

/// Drain until the first `NewExtendedMiningJob`, recording any
/// `SetExtranoncePrefix` seen before it (the channel-open apply).
async fn drain_until_first_job(reader: &mut Reader) -> OpenObs {
    let mut set_prefix = None;
    let _ = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            match read_any_message(reader).await {
                AnyMessage::Mining(Mining::SetExtranoncePrefix(s)) => {
                    set_prefix = Some(s.extranonce_prefix.as_ref().to_vec());
                }
                AnyMessage::Mining(Mining::NewExtendedMiningJob(_)) => return,
                _ => {}
            }
        }
    })
    .await;
    OpenObs { set_prefix }
}

/// Drain for `window`, collecting every `SetExtranoncePrefix` prefix and
/// whether at least one fresh job arrived.
async fn drain_window(reader: &mut Reader, window: Duration) -> WindowObs {
    let mut set_prefixes = Vec::new();
    let mut got_job = false;
    let _ = tokio::time::timeout(window, async {
        loop {
            match read_any_message(reader).await {
                AnyMessage::Mining(Mining::SetExtranoncePrefix(s)) => {
                    set_prefixes.push(s.extranonce_prefix.as_ref().to_vec());
                }
                AnyMessage::Mining(Mining::NewExtendedMiningJob(_)) => {
                    got_job = true;
                }
                _ => {}
            }
        }
    })
    .await;
    WindowObs {
        set_prefixes,
        got_job,
    }
}

async fn write_any_message(writer: &mut Writer, msg: AnyMessage<'static>) {
    let sv2_frame: StandardSv2Frame<AnyMessage<'static>> =
        msg.try_into().expect("AnyMessage → StandardSv2Frame");
    writer
        .write_frame(Frame::Sv2(sv2_frame))
        .await
        .expect("write_frame");
}

async fn read_any_message(reader: &mut Reader) -> AnyMessage<'static> {
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
