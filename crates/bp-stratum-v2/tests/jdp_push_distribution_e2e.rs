// SPDX-License-Identifier: AGPL-3.0-or-later

//! Socket-level end-to-end test for the ext 0x0003 push model on the
//! JDP server — a minimal Job-Declaration-Client over a real Noise
//! connection.
//!
//! What the wire choreography pins (SV2 ext 0x0003):
//!
//! 1. **§3.1 first-message guarantee** — after `RequestExtensions.Success`
//!    negotiating 0x0003, the very NEXT frame is `SetPayoutDistribution`
//!    (raw ext-0x0003 frame), carrying the §3.1 weight distribution.
//! 2. **§2 empty allocate** — with 0x0003 negotiated,
//!    `AllocateMiningJobToken.Success.coinbase_tx_outputs` is empty.
//! 3. **§4/§7.1 declare** — a coinbase whose suffix outputs are the §4
//!    recompute of the published distribution, referenced via the §6
//!    `distribution_id` TLV (LE), is accepted positionally.
//! 4. **Booking** — `PushSolution` hands the block-submission sink a
//!    `PayoutBooking` naming exactly the validated distribution.
//! 5. **§7.2 grace window** — after the pool-wide distribution slides
//!    twice, the k-2 id is rejected `stale-payout-distribution` while
//!    k-1 is still accepted.
//! 6. **§2 negotiation gate** — a `distribution_id` TLV on a connection
//!    that never negotiated 0x0003 is rejected
//!    `invalid-payout-distribution` (the IO layer must surface the TLV
//!    despite the extension being un-negotiated).
//!
//! Needs no bitcoin-node / TDP / PG — declare-time validation runs
//! entirely against the published distribution.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use bp_common::AddressId;
use bp_stratum_v2::bridge::{JdpDeclaredJobRegistry, PayoutDistributionEntry};
use bp_stratum_v2::extensions::{
    encode_distribution_id_tlv, SetPayoutDistribution, SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS,
};
use bp_stratum_v2::jdp::client::{
    ERR_INVALID_PAYOUT_DISTRIBUTION, ERR_STALE_PAYOUT_DISTRIBUTION, FLAG_DECLARE_TX_DATA,
};
use bp_stratum_v2::jdp::dynamic_outputs::PayoutBooking;
use bp_stratum_v2::jdp::payout_distribution::{compute_payout_vector, WeightedOutput};
use bp_stratum_v2::jdp_server::{
    BuiltPayoutDistribution, CurrentPrevHashProvider, JdpBlockSubmissionSink, JdpServerHooks,
    PayoutDistributionSource, StratumV2JdpServer, TailoredDistribution,
};
use bp_stratum_v2::jdp_server_codec::EXT_0X0003_MSG_TYPE_SET_PAYOUT_DISTRIBUTION;
use bp_stratum_v2::noise::{NoiseConfig, DEFAULT_CERT_VALIDITY};
use bp_stratum_v2::tokens::Token;
use stratum_apps::key_utils::Secp256k1PublicKey;
use stratum_apps::network_helpers::connect_with_noise;
use stratum_apps::network_helpers::noise_stream::{NoiseTcpReadHalf, NoiseTcpWriteHalf};
use stratum_core::codec_sv2::StandardSv2Frame;
use stratum_core::common_messages_sv2::{Protocol, SetupConnection};
use stratum_core::extensions_sv2::extensions_negotiation::RequestExtensions;
use stratum_core::framing_sv2::framing::Frame;
use stratum_core::job_declaration_sv2::{AllocateMiningJobToken, DeclareMiningJob, PushSolution};
use stratum_core::parsers_sv2::{
    parse_message_frame_with_tlvs, AnyMessage, CommonMessages, Extensions, ExtensionsNegotiation,
    JobDeclaration,
};
use tokio::net::{TcpListener, TcpStream};

const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const TEST_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const TEST_PRV: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

/// The tip every declaration is accepted under and every solution names.
const PREV_HASH: [u8; 32] = [0xAB; 32];
/// The first id the test source hands the publisher.
const FIRST_ID: u64 = 41;
const REFERENCE_REWARD: u64 = 312_500_000;
const FINGERPRINT: [u8; 32] = [0x11; 32];

// ── Test hooks ──────────────────────────────────────────────────────

fn pool_slot() -> WeightedOutput {
    WeightedOutput {
        script_pubkey: vec![0x51],
        weight: 100,
    }
}

fn miner_slots() -> Vec<WeightedOutput> {
    let p2wpkh = |fill: u8| {
        let mut s = vec![0x00, 0x14];
        s.extend_from_slice(&[fill; 20]);
        s
    };
    vec![
        WeightedOutput {
            script_pubkey: p2wpkh(0xAA),
            weight: 600,
        },
        WeightedOutput {
            script_pubkey: p2wpkh(0xBB),
            weight: 300,
        },
    ]
}

fn dust_limits() -> Vec<u32> {
    vec![546, 546]
}

/// Fixed-weight distribution source: same §3.1 shape every build, ids
/// strictly increasing from [`FIRST_ID`].
struct FixedSource {
    next_id: AtomicU64,
}

#[async_trait]
impl PayoutDistributionSource for FixedSource {
    async fn build_pool_wide(&self) -> Option<BuiltPayoutDistribution> {
        Some(BuiltPayoutDistribution {
            pool_payout: pool_slot(),
            payouts: miner_slots(),
            dust_limits: dust_limits(),
            additional_outputs: Vec::new(),
            reference_reward_sats: REFERENCE_REWARD,
            payouts_fingerprint: Some(FINGERPRINT),
            bookable: true,
        })
    }

    async fn build_for_miner(&self, _miner_address: &AddressId) -> TailoredDistribution {
        TailoredDistribution::PoolWide
    }

    async fn next_distribution_id(&self) -> Option<u64> {
        Some(self.next_id.fetch_add(1, Ordering::SeqCst))
    }
}

struct FixedPrevHash;

#[async_trait]
impl CurrentPrevHashProvider for FixedPrevHash {
    async fn current_prev_hash(&self) -> Option<[u8; 32]> {
        Some(PREV_HASH)
    }
}

#[derive(Debug)]
struct RecordedCandidate {
    miner_address: String,
    booking: Option<PayoutBooking>,
    coinbase_raw: Vec<u8>,
    prev_hash: [u8; 32],
}

#[derive(Default)]
struct RecordingSink {
    candidates: Mutex<Vec<RecordedCandidate>>,
}

#[async_trait]
impl JdpBlockSubmissionSink for RecordingSink {
    #[allow(clippy::too_many_arguments)]
    async fn submit_block_candidate(
        &self,
        miner_address: AddressId,
        _new_token: Token,
        booking: Option<PayoutBooking>,
        coinbase_raw: Vec<u8>,
        _transactions: Vec<Vec<u8>>,
        prev_hash: [u8; 32],
        _version: u32,
        _ntime: u32,
        _nonce: u32,
        _n_bits: u32,
    ) {
        self.candidates.lock().unwrap().push(RecordedCandidate {
            miner_address: miner_address.as_str().to_string(),
            booking,
            coinbase_raw,
            prev_hash,
        });
    }
}

// ── The test ────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jdp_push_distribution_end_to_end() {
    let noise_config = NoiseConfig::parse_strings(TEST_PUB, TEST_PRV, DEFAULT_CERT_VALIDITY)
        .expect("noise config");
    let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
    let sink = Arc::new(RecordingSink::default());

    let mut hooks = JdpServerHooks::no_op();
    hooks.distribution_source = Arc::new(FixedSource {
        next_id: AtomicU64::new(FIRST_ID),
    });
    hooks.prev_hash_provider = Arc::new(FixedPrevHash);
    hooks.block_submission_sink = sink.clone();

    let server = StratumV2JdpServer::spawn(
        noise_config,
        hooks,
        bridge.clone(),
        // Long interval: only the startup publish fires during the test.
        Duration::from_secs(3600),
    );

    // The publisher's first tick publishes the initial distribution;
    // negotiation only offers 0x0003 once one is available.
    wait_until(Duration::from_secs(5), || {
        bridge.read().unwrap().current_pool_wide().is_some()
    })
    .await;
    let published = bridge
        .read()
        .unwrap()
        .current_pool_wide()
        .expect("startup publish");
    assert_eq!(published.distribution_id, FIRST_ID);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let server_accept = server.clone();
    let accept_handle = tokio::spawn(async move {
        loop {
            let Ok((socket, peer)) = listener.accept().await else {
                break;
            };
            socket.set_nodelay(true).ok();
            server_accept.accept_connection(socket, peer.to_string());
        }
    });

    // ── Connection 1: the negotiated JDC ──────────────────────────────
    let (mut reader, mut writer) = connect_jdc(addr).await;

    write_msg(&mut writer, setup_connection(addr.port())).await;
    expect_setup_success(read_jdc(&mut reader).await);

    // Negotiate 0x0003.
    write_msg(
        &mut writer,
        AnyMessage::Extensions(Extensions::ExtensionsNegotiation(
            ExtensionsNegotiation::RequestExtensions(
                RequestExtensions {
                    request_id: 1,
                    requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS]
                        .try_into()
                        .unwrap(),
                }
                .into_static(),
            ),
        )),
    )
    .await;
    match read_jdc(&mut reader).await {
        JdcInbound::Message(AnyMessage::Extensions(Extensions::ExtensionsNegotiation(
            ExtensionsNegotiation::RequestExtensionsSuccess(s),
        ))) => {
            assert!(s
                .supported_extensions
                .clone()
                .into_inner()
                .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS));
        }
        other => panic!("expected RequestExtensionsSuccess, got {other:?}"),
    }

    // §3.1: the very next frame MUST be SetPayoutDistribution.
    let distribution = match read_jdc(&mut reader).await {
        JdcInbound::PayoutDistribution(d) => d,
        other => panic!("§3.1 violated — expected SetPayoutDistribution next, got {other:?}"),
    };
    assert_eq!(distribution.distribution_id, FIRST_ID);
    assert_eq!(distribution.dust_limits, dust_limits());
    assert!(distribution.additional_outputs.is_empty());
    // The weights ride in the consensus TxOut amount fields (§3.1).
    let pool_out: bitcoin::TxOut =
        bitcoin::consensus::deserialize(&distribution.pool_payout).expect("pool_payout TxOut");
    assert_eq!(pool_out.value.to_sat(), pool_slot().weight);
    assert_eq!(
        pool_out.script_pubkey.as_bytes(),
        &pool_slot().script_pubkey
    );
    let wire_payouts: Vec<WeightedOutput> = distribution
        .payouts
        .iter()
        .map(|b| {
            let out: bitcoin::TxOut = bitcoin::consensus::deserialize(b).expect("payout TxOut");
            WeightedOutput {
                script_pubkey: out.script_pubkey.to_bytes(),
                weight: out.value.to_sat(),
            }
        })
        .collect();
    assert_eq!(wire_payouts, miner_slots());

    // §2: allocate returns EMPTY coinbase outputs when 0x0003 is on.
    write_msg(
        &mut writer,
        AnyMessage::JobDeclaration(JobDeclaration::AllocateMiningJobToken(
            AllocateMiningJobToken {
                request_id: 2,
                user_identifier: REGTEST_ADDR.to_string().try_into().unwrap(),
            }
            .into_static(),
        )),
    )
    .await;
    let token = match read_jdc(&mut reader).await {
        JdcInbound::Message(AnyMessage::JobDeclaration(
            JobDeclaration::AllocateMiningJobTokenSuccess(s),
        )) => {
            assert_eq!(s.request_id, 2);
            assert!(
                s.coinbase_outputs.as_bytes().is_empty(),
                "§2: coinbase_outputs MUST be empty when 0x0003 is negotiated"
            );
            s.mining_job_token.as_bytes().to_vec()
        }
        other => panic!("expected AllocateMiningJobTokenSuccess, got {other:?}"),
    };

    // The JDC computes the §4 output vector from the RECEIVED wire
    // distribution at its own template revenue and builds the coinbase.
    let suffix = conformant_suffix(&pool_out, &wire_payouts, &distribution.dust_limits);

    // Declare #9: negotiated but NO TLV → invalid (§6 mandatory).
    write_declare(&mut writer, 9, &token, &suffix, None).await;
    expect_declare_error(
        read_jdc(&mut reader).await,
        9,
        ERR_INVALID_PAYOUT_DISTRIBUTION,
    );

    // An ACCEPTED declaration issues its job token through the shared
    // per-connection TokenStore, which rate-limits to 1/s (spec §6.4.2)
    // and silently drops the declaration when exceeded — space the
    // token-allocating declares out accordingly.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Declare #10: conformant coinbase + TLV(FIRST_ID) → accepted.
    write_declare(&mut writer, 10, &token, &suffix, Some(FIRST_ID)).await;
    expect_declare_success(read_jdc(&mut reader).await, 10);

    // PushSolution on the declared tip → the sink receives the booking
    // of the validated distribution.
    let extranonce = vec![0xEE; 8];
    write_msg(
        &mut writer,
        AnyMessage::JobDeclaration(JobDeclaration::PushSolution(
            PushSolution {
                extranonce: extranonce.clone().try_into().unwrap(),
                prev_hash: PREV_HASH.into(),
                ntime: 0x6500_0001,
                nonce: 0x1234_5678,
                nbits: 0x1d00_ffff,
                version: 0x2000_0000,
            }
            .into_static(),
        )),
    )
    .await;
    wait_until(Duration::from_secs(5), || {
        !sink.candidates.lock().unwrap().is_empty()
    })
    .await;
    {
        let candidates = sink.candidates.lock().unwrap();
        assert_eq!(candidates.len(), 1, "exactly one block candidate");
        let c = &candidates[0];
        assert_eq!(c.miner_address, REGTEST_ADDR);
        assert_eq!(c.prev_hash, PREV_HASH);
        assert_eq!(
            c.booking,
            Some(PayoutBooking {
                distribution_id: FIRST_ID,
                payouts_fingerprint: FINGERPRINT,
                reference_reward_sats: REFERENCE_REWARD,
            }),
            "the booking must name exactly the validated distribution"
        );
        // coinbase = prefix + extranonce + suffix, assembled server-side.
        let raw = &c.coinbase_raw;
        assert_eq!(&raw[..COINBASE_PREFIX.len()], COINBASE_PREFIX);
        assert_eq!(
            &raw[COINBASE_PREFIX.len()..COINBASE_PREFIX.len() + extranonce.len()],
            &extranonce[..]
        );
        assert_eq!(
            &raw[COINBASE_PREFIX.len() + extranonce.len()..],
            &suffix[..]
        );
    }

    // ── §7.2 grace window: slide the pool-wide distribution twice ─────
    // (Direct registry publishes — the same slot the publisher writes.)
    for id in [FIRST_ID + 1, FIRST_ID + 2] {
        bridge.write().unwrap().publish_pool_wide(entry_with_id(id));
    }

    // Declare #12 referencing k-2 → stale.
    write_declare(&mut writer, 12, &token, &suffix, Some(FIRST_ID)).await;
    expect_declare_error(
        read_jdc(&mut reader).await,
        12,
        ERR_STALE_PAYOUT_DISTRIBUTION,
    );

    // Declare #13 referencing k-1 (the grace slot) → still accepted.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    write_declare(&mut writer, 13, &token, &suffix, Some(FIRST_ID + 1)).await;
    expect_declare_success(read_jdc(&mut reader).await, 13);

    // ── Connection 2: TLV without negotiation → rejected (§2) ─────────
    let (mut reader2, mut writer2) = connect_jdc(addr).await;
    write_msg(&mut writer2, setup_connection(addr.port())).await;
    expect_setup_success(read_jdc(&mut reader2).await);
    write_msg(
        &mut writer2,
        AnyMessage::JobDeclaration(JobDeclaration::AllocateMiningJobToken(
            AllocateMiningJobToken {
                request_id: 2,
                user_identifier: REGTEST_ADDR.to_string().try_into().unwrap(),
            }
            .into_static(),
        )),
    )
    .await;
    let token2 = match read_jdc(&mut reader2).await {
        JdcInbound::Message(AnyMessage::JobDeclaration(
            JobDeclaration::AllocateMiningJobTokenSuccess(s),
        )) => {
            assert!(
                !s.coinbase_outputs.as_bytes().is_empty(),
                "base path keeps its allocate outputs"
            );
            s.mining_job_token.as_bytes().to_vec()
        }
        other => panic!("expected AllocateMiningJobTokenSuccess, got {other:?}"),
    };
    write_declare(&mut writer2, 20, &token2, &suffix, Some(FIRST_ID + 2)).await;
    expect_declare_error(
        read_jdc(&mut reader2).await,
        20,
        ERR_INVALID_PAYOUT_DISTRIBUTION,
    );

    // ── Teardown ──────────────────────────────────────────────────────
    drop(writer);
    drop(reader);
    drop(writer2);
    drop(reader2);
    server.shutdown().await;
    accept_handle.abort();
}

// ── JDC-side fixtures ───────────────────────────────────────────────

const COINBASE_PREFIX: &[u8] = b"cb-prefix";

fn setup_connection(port: u16) -> AnyMessage<'static> {
    AnyMessage::Common(CommonMessages::SetupConnection(
        SetupConnection {
            protocol: Protocol::JobDeclarationProtocol,
            min_version: 2,
            max_version: 2,
            flags: FLAG_DECLARE_TX_DATA,
            endpoint_host: "127.0.0.1".to_string().try_into().unwrap(),
            endpoint_port: port,
            vendor: "test-jdc".to_string().try_into().unwrap(),
            hardware_version: "rev1".to_string().try_into().unwrap(),
            firmware: "0.1".to_string().try_into().unwrap(),
            device_id: "jdc-e2e".to_string().try_into().unwrap(),
        }
        .into_static(),
    ))
}

/// A coinbase suffix whose outputs are the §4 recompute at the JDC's
/// own template revenue: `[sequence][outputs][locktime]`.
fn conformant_suffix(pool: &bitcoin::TxOut, payouts: &[WeightedOutput], dust: &[u32]) -> Vec<u8> {
    let pool_slot = WeightedOutput {
        script_pubkey: pool.script_pubkey.to_bytes(),
        weight: pool.value.to_sat(),
    };
    let outputs = compute_payout_vector(&pool_slot, payouts, dust, &[], REFERENCE_REWARD)
        .expect("§4 compute");
    let mut suffix = 0xFFFF_FFFFu32.to_le_bytes().to_vec();
    suffix.extend_from_slice(&bitcoin::consensus::serialize(&outputs));
    suffix.extend_from_slice(&0u32.to_le_bytes());
    suffix
}

/// A registry entry with the fixed test weights under a new id, as the
/// publisher would produce on a later tick.
fn entry_with_id(id: u64) -> PayoutDistributionEntry {
    PayoutDistributionEntry {
        distribution_id: id,
        pool_payout: pool_slot(),
        payouts: miner_slots(),
        dust_limits: dust_limits(),
        additional_outputs: Vec::new(),
        reference_reward_sats: REFERENCE_REWARD,
        payouts_fingerprint: Some(FINGERPRINT),
        bookable: true,
        owner: None,
        jdp_session_id: None,
        published_at_ms: 2_000,
    }
}

// ── Wire helpers ────────────────────────────────────────────────────

type Reader = NoiseTcpReadHalf<AnyMessage<'static>>;
type Writer = NoiseTcpWriteHalf<AnyMessage<'static>>;

async fn connect_jdc(addr: std::net::SocketAddr) -> (Reader, Writer) {
    let socket = TcpStream::connect(addr).await.expect("connect");
    socket.set_nodelay(true).ok();
    let pub_key: Secp256k1PublicKey = TEST_PUB.parse().expect("pub key");
    let noise = connect_with_noise::<AnyMessage<'static>>(socket, Some(pub_key))
        .await
        .expect("noise handshake");
    noise.into_split()
}

#[derive(Debug)]
enum JdcInbound {
    Message(AnyMessage<'static>),
    PayoutDistribution(SetPayoutDistribution),
}

async fn read_jdc(reader: &mut Reader) -> JdcInbound {
    let frame = tokio::time::timeout(Duration::from_secs(5), reader.read_frame())
        .await
        .expect("read timeout")
        .expect("read_frame");
    let mut sv2_frame = match frame {
        Frame::Sv2(f) => f,
        Frame::HandShake(_) => panic!("unexpected handshake frame"),
    };
    let header = sv2_frame.get_header().expect("header");
    if header.ext_type_without_channel_msg() == SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS {
        assert_eq!(
            header.msg_type(),
            EXT_0X0003_MSG_TYPE_SET_PAYOUT_DISTRIBUTION
        );
        let payload = sv2_frame.payload();
        return JdcInbound::PayoutDistribution(
            SetPayoutDistribution::deserialize(payload).expect("SetPayoutDistribution"),
        );
    }
    let (msg, _tlvs) =
        parse_message_frame_with_tlvs(header, sv2_frame.payload(), &[]).expect("parse");
    JdcInbound::Message(msg)
}

async fn write_msg(writer: &mut Writer, msg: AnyMessage<'static>) {
    let frame: StandardSv2Frame<AnyMessage<'static>> = msg.try_into().expect("frame");
    writer.write_frame(Frame::Sv2(frame)).await.expect("write");
}

/// Write a `DeclareMiningJob`, optionally with the §6 `distribution_id`
/// TLV appended to the frame tail (LE, per §3.4.3 data types). The
/// frame header's msg_length is patched to cover the tail.
async fn write_declare(
    writer: &mut Writer,
    request_id: u32,
    token: &[u8],
    suffix: &[u8],
    distribution_id: Option<u64>,
) {
    let msg = AnyMessage::JobDeclaration(JobDeclaration::DeclareMiningJob(
        DeclareMiningJob {
            request_id,
            mining_job_token: token.to_vec().try_into().unwrap(),
            version: 0x2000_0000,
            coinbase_tx_prefix: COINBASE_PREFIX.to_vec().try_into().unwrap(),
            coinbase_tx_suffix: suffix.to_vec().try_into().unwrap(),
            wtxid_list: Vec::new().try_into().unwrap(),
            excess_data: Vec::new().try_into().unwrap(),
        }
        .into_static(),
    ));
    let frame: StandardSv2Frame<AnyMessage<'static>> = msg.try_into().expect("frame");
    let Some(id) = distribution_id else {
        writer.write_frame(Frame::Sv2(frame)).await.expect("write");
        return;
    };
    // Serialize the frame, append the TLV tail, patch msg_length (u24
    // LE at header bytes 3..6), re-wrap as raw bytes.
    let mut bytes = vec![0u8; frame.encoded_length()];
    frame.serialize(&mut bytes).expect("serialize");
    bytes.extend_from_slice(&encode_distribution_id_tlv(id));
    let payload_len = (bytes.len() - 6) as u32;
    bytes[3] = (payload_len & 0xFF) as u8;
    bytes[4] = ((payload_len >> 8) & 0xFF) as u8;
    bytes[5] = ((payload_len >> 16) & 0xFF) as u8;
    let raw: StandardSv2Frame<AnyMessage<'static>> =
        StandardSv2Frame::from_bytes_unchecked(bytes.into());
    writer.write_frame(Frame::Sv2(raw)).await.expect("write");
}

fn expect_setup_success(inbound: JdcInbound) {
    match inbound {
        JdcInbound::Message(AnyMessage::Common(CommonMessages::SetupConnectionSuccess(_))) => {}
        other => panic!("expected SetupConnectionSuccess, got {other:?}"),
    }
}

fn expect_declare_success(inbound: JdcInbound, request_id: u32) {
    match inbound {
        JdcInbound::Message(AnyMessage::JobDeclaration(
            JobDeclaration::DeclareMiningJobSuccess(s),
        )) => {
            assert_eq!(s.request_id, request_id);
        }
        other => panic!("expected DeclareMiningJobSuccess #{request_id}, got {other:?}"),
    }
}

fn expect_declare_error(inbound: JdcInbound, request_id: u32, code: &str) {
    match inbound {
        JdcInbound::Message(AnyMessage::JobDeclaration(JobDeclaration::DeclareMiningJobError(
            e,
        ))) => {
            assert_eq!(e.request_id, request_id);
            assert_eq!(
                std::str::from_utf8(e.error_code.as_ref()).unwrap(),
                code,
                "declare #{request_id} must fail with `{code}`"
            );
        }
        other => panic!("expected DeclareMiningJobError #{request_id}, got {other:?}"),
    }
}

async fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut cond: F) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
