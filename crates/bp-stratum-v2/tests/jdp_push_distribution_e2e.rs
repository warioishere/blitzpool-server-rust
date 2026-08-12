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
//! 7. **The JDP → Mining seam** — an accepted declaration is resolvable
//!    in the bridge under its issued token, carrying the binding, the
//!    declared tip and the §6 `distribution_id`. That is everything the
//!    mining connection judges a Full-Template `SetCustomMiningJob`
//!    against, and it was previously untested: removing the
//!    registration call left the whole suite green.
//! 8. **§6.4.3 base protocol** — a connection that never negotiates
//!    0x0003 is answered with exactly ONE designated payout output at 0
//!    sats paying the miner itself, and that token reaches the bridge as
//!    an allocation. Coinbase-only mode never declares (§6.3.1), so this
//!    allocate is the only record the mining side will have of it.
//!
//! Needs no bitcoin-node / TDP / PG — declare-time validation runs
//! entirely against the published distribution.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use bp_common::{AddressId, Sats, StreamKind};
use bp_stratum_v2::bridge::{JdpDeclaredJobRegistry, PayoutDistributionEntry};
use bp_stratum_v2::extensions::{
    encode_distribution_id_tlv, SetPayoutDistribution, SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS,
};
use bp_stratum_v2::jdp::client::{
    parse_user_identifier_as_address, AllocateTokenContext, ERR_INVALID_PAYOUT_DISTRIBUTION,
    ERR_STALE_PAYOUT_DISTRIBUTION, FLAG_DECLARE_TX_DATA,
};
use bp_stratum_v2::jdp::dynamic_outputs::{
    encode_coinbase_outputs, CandidateBacking, DynamicOutput, PayoutBooking,
};
use bp_stratum_v2::jdp::payout_distribution::{compute_payout_vector, WeightedOutput};
use bp_stratum_v2::jdp_server::{
    AllocateOutcome, BuiltPayoutDistribution, CurrentPrevHashProvider, JdpAllocateResolver,
    JdpBlockSubmissionSink, JdpServerHooks, PayoutDistributionSource, StratumV2JdpServer,
    TailoredDistribution,
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

    async fn current_mode(&self, _miner_address: &AddressId) -> Option<StreamKind> {
        // Consistent with `build_for_miner` above: everyone rides the
        // pool-wide plan here, so nobody's mode ever moves.
        Some(StreamKind::Pplns)
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

/// Allocate resolver mirroring what production answers, on both paths:
/// empty outputs once ext 0x0003 is negotiated (§2), and otherwise the one
/// §6.4.3 designated payout output at 0 sats paying the miner itself.
///
/// It has to be spelled out here rather than borrowed from
/// [`JdpServerHooks::no_op`], whose base-path answer is an EMPTY output
/// vector. That designates nothing, so the base-protocol allocation would
/// register nothing in the bridge and the assertions below would pass
/// against a pool that serves no Coinbase-only JDC at all.
struct BaseModeAllocateResolver;

#[async_trait]
impl JdpAllocateResolver for BaseModeAllocateResolver {
    async fn resolve_allocate_context(
        &self,
        user_identifier: &str,
        _remote_addr: &str,
        payout_distribution_negotiated: bool,
    ) -> AllocateOutcome {
        let Some(miner_address) = parse_user_identifier_as_address(user_identifier) else {
            return AllocateOutcome::Ignored;
        };
        let coinbase_outputs = if payout_distribution_negotiated {
            Vec::new()
        } else {
            match encode_coinbase_outputs(
                bitcoin::Network::Regtest,
                &[DynamicOutput {
                    address: miner_address.clone(),
                    sats: Sats(0),
                }],
            ) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return AllocateOutcome::Refused {
                        reason: "fixture address does not encode",
                    }
                }
            }
        };
        AllocateOutcome::Granted(AllocateTokenContext {
            miner_address,
            coinbase_outputs,
        })
    }
}

#[derive(Debug)]
struct RecordedCandidate {
    miner_address: String,
    backing: CandidateBacking,
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
        backing: CandidateBacking,
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
            backing,
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
    hooks.allocate_resolver = Arc::new(BaseModeAllocateResolver);

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
    let declared_token = expect_declare_success(read_jdc(&mut reader).await, 10);

    // ── The JDP → Mining seam ─────────────────────────────────────────
    //
    // An accepted declaration has to become resolvable on the OTHER
    // connection: the JDC opens a separate mining socket and presents
    // this token in `SetCustomMiningJob`. Everything that job is judged
    // against lives in the bridge entry — the declaration binding, the
    // tip it was accepted under, and the §6 `distribution_id`, which in
    // Full-Template mode rides on `DeclareMiningJob` and is therefore
    // never seen on the mining wire at all.
    //
    // No race: the registration happens BEFORE the Success frame is
    // written (see `run_jdp_connection`), so holding the frame means the
    // entry is already there.
    //
    // This seam had no coverage. Disabling the registration call
    // outright left all 447 unit tests and every integration test green,
    // while every real Full-Template JDC would have been answered
    // `invalid-mining-job-token` — fatal for an SRI jd-client.
    let declared_token =
        Token(<[u8; 16]>::try_from(declared_token.as_slice()).expect("16-byte job token"));
    let job_ref = bridge
        .read()
        .unwrap()
        .job_ref(&declared_token)
        .expect("an accepted declaration MUST be resolvable by the mining side");
    assert_eq!(job_ref.miner_address.as_str(), REGTEST_ADDR);
    assert_eq!(
        job_ref.declared_prev_hash,
        Some(PREV_HASH),
        "the mining side rejects a custom job that does not build on this tip"
    );
    assert_eq!(
        job_ref.distribution_id,
        Some(FIRST_ID),
        "§6 puts the TLV on DeclareMiningJob in Full-Template mode — the mining \
         side can only inherit the reference from here"
    );
    // Presence is not enough: a stub entry would satisfy the lookup and
    // still fail every `SetCustomMiningJob`. Pin what the binding says.
    let binding = job_ref
        .binding
        .expect("the declared coinbase must project, or the custom job is refused");
    assert_eq!(binding.coinbase_script_sig_prefix, SCRIPT_SIG_HEAD);
    assert_eq!(binding.extranonce_slot, EXTRANONCE_LEN);
    assert_eq!(binding.version, 0x2000_0000);

    // Negative control, in the same test so the block above cannot pass
    // on a lookup that answers `Some` for anything: a token this JDC
    // never declared resolves to nothing.
    assert!(
        bridge.read().unwrap().job_ref(&Token([0x77; 16])).is_none(),
        "an undeclared token must not resolve — otherwise the assertions \
         above prove nothing"
    );

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
            c.backing,
            CandidateBacking::Bookable(PayoutBooking {
                distribution_id: FIRST_ID,
                payouts_fingerprint: FINGERPRINT,
                reference_reward_sats: REFERENCE_REWARD,
            }),
            "the booking must name exactly the validated distribution"
        );
        // coinbase = prefix + extranonce + suffix, assembled server-side.
        let raw = &c.coinbase_raw;
        let plen = coinbase_prefix().len();
        assert_eq!(&raw[..plen], &coinbase_prefix()[..]);
        assert_eq!(&raw[plen..plen + extranonce.len()], &extranonce[..]);
        assert_eq!(&raw[plen + extranonce.len()..], &suffix[..]);
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
            // §6.4.3 on the wire: exactly one designated payout output,
            // sent with a 0 amount, paying this miner. The 0 is what lets a
            // conformant JD-client write its whole template revenue into
            // it; a second valued output here would make its coinbase
            // overspend the block.
            let outputs: Vec<bitcoin::TxOut> =
                bitcoin::consensus::deserialize(s.coinbase_outputs.as_bytes())
                    .expect("allocate outputs must decode");
            assert_eq!(outputs.len(), 1, "§6.4.3 designates ONE payout output");
            assert_eq!(outputs[0].value, bitcoin::Amount::ZERO);
            assert_eq!(
                outputs[0].script_pubkey,
                bp_mining_job::address_to_script(bitcoin::Network::Regtest, REGTEST_ADDR).unwrap(),
                "the designated output must pay the miner itself"
            );
            s.mining_job_token.as_bytes().to_vec()
        }
        other => panic!("expected AllocateMiningJobTokenSuccess, got {other:?}"),
    };

    // This connection is FULL-TEMPLATE (it set `DECLARE_TX_DATA`), so its
    // allocate token must NOT be resolvable on its own: that mode owes a
    // `DeclareMiningJob`, which is where bitcoin-core validates its
    // transaction set (§6.1). Registering it would let the JDC skip the
    // declaration and mine a job no node ever saw.
    //
    // Connection 1's token must not resolve either, for a different reason:
    // it negotiated 0x0003, so §2 left it no designated output and its jobs
    // are judged by the §7.1 recompute. Two ways to be absent, both checked
    // — the positive case is connection 4 below.
    {
        let reg = bridge.read().unwrap();
        let full_template_token =
            Token(<[u8; 16]>::try_from(token2.as_slice()).expect("16-byte allocate token"));
        assert!(
            reg.allocation_ref(&full_template_token, 0).is_none(),
            "a Full-Template allocate must not be usable without declaring"
        );
        let negotiated_token =
            Token(<[u8; 16]>::try_from(token.as_slice()).expect("16-byte allocate token"));
        assert!(
            reg.allocation_ref(&negotiated_token, 0).is_none(),
            "an ext 0x0003 allocate must register no base-protocol allocation"
        );
    }
    write_declare(&mut writer2, 20, &token2, &suffix, Some(FIRST_ID + 2)).await;
    expect_declare_error(
        read_jdc(&mut reader2).await,
        20,
        ERR_INVALID_PAYOUT_DISTRIBUTION,
    );

    // ── Connection 3: a refused setup is answered, then closed ────────
    //
    // SV2 §3.6.3: `SetupConnection.Error` is sent "prior to closing the
    // connection". Both halves matter and are asserted here: the client
    // must LEARN why (the error frame arrives), and the socket must then
    // go (the next read ends). Without the close the pool holds an FD for
    // a session that can do nothing — there is no idle timeout on this
    // path.
    let (mut reader3, mut writer3) = connect_jdc(addr).await;
    write_msg(&mut writer3, setup_connection_wrong_protocol(addr.port())).await;
    match read_jdc(&mut reader3).await {
        JdcInbound::Message(AnyMessage::Common(CommonMessages::SetupConnectionError(e))) => {
            assert_eq!(
                std::str::from_utf8(e.error_code.as_ref()).unwrap(),
                "unsupported-protocol"
            );
        }
        other => panic!("expected SetupConnectionError, got {other:?}"),
    }
    // The server closes: reading again ends rather than hanging. A
    // timeout here means the connection stayed open — the bug this
    // asserts against.
    let after = tokio::time::timeout(Duration::from_secs(5), reader3.read_frame()).await;
    match after {
        Ok(Err(_)) => {}
        Ok(Ok(f)) => panic!("expected the server to close, got another frame: {f:?}"),
        Err(_) => panic!("the server left a refused connection open"),
    }

    // ── Connection 4: a real Coinbase-only JDC (the base path) ────────
    //
    // No `DECLARE_TX_DATA`, no 0x0003. §6.3.1: "the `DeclareMiningJob`
    // message is never used" in this mode, so the allocate is the pool's
    // ONLY record of the token — the mining connection resolves it here and
    // holds the custom job's coinbase to the script registered with it.
    // Without the entry this JDC is answered `invalid-mining-job-token` on
    // every job it ever builds, which an SRI jd-client treats as fatal.
    let (mut reader4, mut writer4) = connect_jdc(addr).await;
    write_msg(&mut writer4, setup_connection_coinbase_only(addr.port())).await;
    expect_setup_success(read_jdc(&mut reader4).await);
    write_msg(
        &mut writer4,
        AnyMessage::JobDeclaration(JobDeclaration::AllocateMiningJobToken(
            AllocateMiningJobToken {
                request_id: 4,
                user_identifier: REGTEST_ADDR.to_string().try_into().unwrap(),
            }
            .into_static(),
        )),
    )
    .await;
    let token4 = match read_jdc(&mut reader4).await {
        JdcInbound::Message(AnyMessage::JobDeclaration(
            JobDeclaration::AllocateMiningJobTokenSuccess(s),
        )) => {
            // §6.4.3 on the wire: exactly ONE designated payout output, sent
            // with a 0 amount. The 0 is what lets a conformant JD-client
            // write its whole template revenue into it; a second VALUED
            // output would make its coinbase overspend the block.
            let outputs: Vec<bitcoin::TxOut> =
                bitcoin::consensus::deserialize(s.coinbase_outputs.as_bytes())
                    .expect("allocate outputs must decode");
            assert_eq!(outputs.len(), 1, "§6.4.3 designates ONE payout output");
            assert_eq!(outputs[0].value, bitcoin::Amount::ZERO);
            s.mining_job_token.as_bytes().to_vec()
        }
        other => panic!("expected AllocateMiningJobTokenSuccess, got {other:?}"),
    };
    {
        let reg = bridge.read().unwrap();
        let coinbase_only_token =
            Token(<[u8; 16]>::try_from(token4.as_slice()).expect("16-byte allocate token"));
        let allocation = reg
            .allocation_ref(&coinbase_only_token, 0)
            .expect("a Coinbase-only allocate must reach the mining side");
        assert_eq!(allocation.miner_address.as_str(), REGTEST_ADDR);
        assert!(
            matches!(
                &allocation.kind,
                bp_stratum_v2::bridge::AllocationKind::DesignatedOutput(s) if !s.is_empty()
            ),
            "the registered script is what the custom job's coinbase is held to"
        );
        // The token's own hour-long TTL travels with it, so the map cannot
        // grow for the life of a connection.
        assert!(
            allocation.expires_at_ms > 0,
            "the allocation must carry its token's expiry"
        );
        assert!(
            reg.allocation_ref(&coinbase_only_token, u64::MAX).is_none(),
            "an expired allocation must stop authorising jobs"
        );
    }

    // ── Teardown ──────────────────────────────────────────────────────
    drop(writer);
    drop(reader);
    drop(writer2);
    drop(reader2);
    drop(writer3);
    drop(reader3);
    drop(writer4);
    drop(reader4);
    server.shutdown().await;
    accept_handle.abort();
}

// ── JDC-side fixtures ───────────────────────────────────────────────

/// Bytes of extranonce the declared prefix reserves — must match the
/// extranonce this JDC fixture actually submits.
const EXTRANONCE_LEN: usize = 8;

/// The scriptSig bytes the declared coinbase commits to before the
/// extranonce slot (a BIP-34 height push). The mining side compares
/// against exactly these via the bridge projection.
const SCRIPT_SIG_HEAD: [u8; 3] = [0x03, 0xC8, 0x00];

/// A declared `coinbase_tx_prefix` that is a real coinbase header: version,
/// one input, the null outpoint, the scriptSig length, then a BIP-34 height
/// push. It stops where the extranonce slot begins.
///
/// This used to be `b"cb-prefix"`. The declare-time validation now rebuilds the
/// whole transaction from prefix + zeroed slot + suffix (the slot width comes
/// out of the prefix's scriptSig length), so a placeholder no longer parses.
fn coinbase_prefix() -> Vec<u8> {
    use bitcoin::consensus::Encodable;
    let mut p = Vec::new();
    p.extend_from_slice(&2u32.to_le_bytes());
    p.push(0x01);
    p.extend_from_slice(&[0u8; 32]);
    p.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    bitcoin::VarInt((SCRIPT_SIG_HEAD.len() + EXTRANONCE_LEN) as u64)
        .consensus_encode(&mut p)
        .unwrap();
    p.extend_from_slice(&SCRIPT_SIG_HEAD);
    p
}

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
        accounting: bp_stratum_v2::bridge::DistributionAccounting::PoolWide,
        jdp_session_id: None,
        published_at_ms: 2_000,
    }
}

// ── Wire helpers ────────────────────────────────────────────────────

type Reader = NoiseTcpReadHalf<AnyMessage<'static>>;
type Writer = NoiseTcpWriteHalf<AnyMessage<'static>>;

/// A Coinbase-only `SetupConnection`: `DECLARE_TX_DATA` clear, so the JDC
/// never declares and takes its allocate token straight to the mining
/// connection (§6.3.1).
fn setup_connection_coinbase_only(port: u16) -> AnyMessage<'static> {
    AnyMessage::Common(CommonMessages::SetupConnection(
        SetupConnection {
            protocol: Protocol::JobDeclarationProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: "127.0.0.1".to_string().try_into().unwrap(),
            endpoint_port: port,
            vendor: "test-jdc".to_string().try_into().unwrap(),
            hardware_version: "rev1".to_string().try_into().unwrap(),
            firmware: "0.1".to_string().try_into().unwrap(),
            device_id: "jdc-coinbase-only".to_string().try_into().unwrap(),
        }
        .into_static(),
    ))
}

/// A `SetupConnection` the JDP server must refuse: the Mining
/// sub-protocol on the job-declaration port.
fn setup_connection_wrong_protocol(port: u16) -> AnyMessage<'static> {
    AnyMessage::Common(CommonMessages::SetupConnection(
        SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: FLAG_DECLARE_TX_DATA,
            endpoint_host: "127.0.0.1".to_string().try_into().unwrap(),
            endpoint_port: port,
            vendor: "test-jdc".to_string().try_into().unwrap(),
            hardware_version: "rev1".to_string().try_into().unwrap(),
            firmware: "0.1".to_string().try_into().unwrap(),
            device_id: "jdc-wrong-protocol".to_string().try_into().unwrap(),
        }
        .into_static(),
    ))
}

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
            coinbase_tx_prefix: coinbase_prefix().try_into().unwrap(),
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

/// Returns the `new_mining_job_token` the JDS issued — the key the
/// mining connection later presents in `SetCustomMiningJob`.
fn expect_declare_success(inbound: JdcInbound, request_id: u32) -> Vec<u8> {
    match inbound {
        JdcInbound::Message(AnyMessage::JobDeclaration(
            JobDeclaration::DeclareMiningJobSuccess(s),
        )) => {
            assert_eq!(s.request_id, request_id);
            s.new_mining_job_token.as_bytes().to_vec()
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

/// A distribution source that only knows the miner's mode once the test says
/// so — standing in for the mode gate, which learns an address when its
/// mining session registers.
struct ModeGatedSource {
    known: AtomicBool,
    next_id: AtomicU64,
    miner: AddressId,
}

#[async_trait]
impl PayoutDistributionSource for ModeGatedSource {
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
        if !self.known.load(Ordering::SeqCst) {
            return TailoredDistribution::ModeUnknown;
        }
        TailoredDistribution::Built {
            accounting: bp_stratum_v2::bridge::DistributionAccounting::Solo(self.miner.clone()),
            built: Box::new(BuiltPayoutDistribution {
                pool_payout: pool_slot(),
                payouts: miner_slots(),
                dust_limits: dust_limits(),
                additional_outputs: Vec::new(),
                reference_reward_sats: REFERENCE_REWARD,
                payouts_fingerprint: Some(FINGERPRINT),
                bookable: true,
            }),
        }
    }

    /// Off the same flag as `build_for_miner`: unknown until the test says the
    /// mining session registered, Solo after.
    async fn current_mode(&self, _miner_address: &AddressId) -> Option<StreamKind> {
        self.known
            .load(Ordering::SeqCst)
            .then_some(StreamKind::Solo)
    }

    async fn next_distribution_id(&self) -> Option<u64> {
        Some(self.next_id.fetch_add(1, Ordering::SeqCst))
    }
}

/// Read a frame, or `None` if none arrives within `within`. `read_jdc` panics
/// on timeout, which is the right default everywhere else — here the absence
/// of a frame is the assertion.
async fn try_read_jdc(reader: &mut Reader, within: Duration) -> Option<JdcInbound> {
    match tokio::time::timeout(within, reader.read_frame()).await {
        Err(_) => None,
        Ok(frame) => {
            let mut sv2_frame = match frame.expect("read_frame") {
                Frame::Sv2(f) => f,
                Frame::HandShake(_) => panic!("unexpected handshake frame"),
            };
            let header = sv2_frame.get_header().expect("header");
            if header.ext_type_without_channel_msg() == SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS {
                let payload = sv2_frame.payload();
                return Some(JdcInbound::PayoutDistribution(
                    SetPayoutDistribution::deserialize(payload).expect("SetPayoutDistribution"),
                ));
            }
            let (msg, _tlvs) =
                parse_message_frame_with_tlvs(header, sv2_frame.payload(), &[]).expect("parse");
            Some(JdcInbound::Message(msg))
        }
    }
}

/// The session loop must publish NOTHING while the miner's mode is unknown,
/// and publish as soon as it becomes known — driven by the next inbound frame,
/// not by a timer.
///
/// This is the state machine itself, over a real Noise connection, because
/// that is the part the pure decision tests cannot reach: `build_for_miner`
/// answering `ModeUnknown` is one thing, the loop then holding back the push,
/// keeping pool-wide denied and retrying on the next frame is another.
///
/// ⭐ The publisher interval here is **one hour**. So the distribution that
/// arrives in the second half cannot have come from the publisher's tick —
/// only the per-frame retry can have produced it. That is the whole point of
/// the mechanism: on the tick alone a JDC would sit for up to a minute with no
/// distribution, declare without one, and a PPLNS address would be refused
/// `custom-jobs-require-solo` — a wrong distribution traded for a fatal one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_is_served_nothing_until_its_mode_is_known() {
    let noise_config = NoiseConfig::parse_strings(TEST_PUB, TEST_PRV, DEFAULT_CERT_VALIDITY)
        .expect("noise config");
    let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
    let source = Arc::new(ModeGatedSource {
        known: AtomicBool::new(false),
        next_id: AtomicU64::new(FIRST_ID),
        miner: AddressId::new(REGTEST_ADDR.to_string()).expect("miner address"),
    });

    let mut hooks = JdpServerHooks::no_op();
    hooks.distribution_source = source.clone();
    hooks.prev_hash_provider = Arc::new(FixedPrevHash);
    hooks.allocate_resolver = Arc::new(BaseModeAllocateResolver);

    let server = StratumV2JdpServer::spawn(
        noise_config,
        hooks,
        bridge.clone(),
        // One hour: nothing in this test can come from the publisher's tick.
        Duration::from_secs(3600),
    );
    wait_until(Duration::from_secs(5), || {
        bridge.read().unwrap().current_pool_wide().is_some()
    })
    .await;

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

    let (mut reader, mut writer) = connect_jdc(addr).await;
    write_msg(&mut writer, setup_connection(addr.port())).await;
    expect_setup_success(read_jdc(&mut reader).await);

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
        JdcInbound::Message(AnyMessage::Extensions(_)) => {}
        other => panic!("expected RequestExtensionsSuccess, got {other:?}"),
    }
    // Before any allocate the pool does not know WHO this is, so the pool-wide
    // push is all it can offer and §3.1 requires it right here.
    match read_jdc(&mut reader).await {
        JdcInbound::PayoutDistribution(d) => assert_eq!(d.distribution_id, FIRST_ID),
        other => panic!("§3.1: expected the pool-wide distribution, got {other:?}"),
    }

    // ── Identity known, mode NOT known ────────────────────────────────
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
    match read_jdc(&mut reader).await {
        JdcInbound::Message(AnyMessage::JobDeclaration(
            JobDeclaration::AllocateMiningJobTokenSuccess(_),
        )) => {}
        other => panic!("expected AllocateMiningJobTokenSuccess, got {other:?}"),
    }
    assert!(
        try_read_jdc(&mut reader, Duration::from_millis(400))
            .await
            .is_none(),
        "the pool must publish NOTHING while the mode is unknown — guessing costs \
         money in either direction, so there is no safe default to fall back on"
    );

    // ── The miner connects: the port has spoken ───────────────────────
    source.known.store(true, Ordering::SeqCst);

    // Any inbound frame is the trigger. A second allocate is the one a real
    // JDC sends anyway, on its next tip change.
    write_msg(
        &mut writer,
        AnyMessage::JobDeclaration(JobDeclaration::AllocateMiningJobToken(
            AllocateMiningJobToken {
                request_id: 3,
                user_identifier: REGTEST_ADDR.to_string().try_into().unwrap(),
            }
            .into_static(),
        )),
    )
    .await;

    let mut tailored = None;
    for _ in 0..3 {
        match try_read_jdc(&mut reader, Duration::from_secs(3)).await {
            Some(JdcInbound::PayoutDistribution(d)) => {
                tailored = Some(d);
                break;
            }
            Some(_) => continue,
            None => break,
        }
    }
    let tailored = tailored.expect(
        "once the mode is known the session must be served — and with the publisher \
         on a one-hour interval, only the per-frame retry can have produced this",
    );
    assert!(
        tailored.distribution_id > FIRST_ID,
        "the tailored distribution must be a fresh id, got {}",
        tailored.distribution_id
    );

    accept_handle.abort();
    server.shutdown().await;
}

/// What the mode gate answers for this session's miner, switchable mid-test.
///
/// Three answers because the transitions between them are the thing under
/// test: a session starts not knowing, and the answer it eventually gets can
/// be either a tailored plan or "you are on the pool-wide one".
#[derive(Clone, Copy, PartialEq, Eq)]
enum GateAnswer {
    Unknown,
    Solo,
    /// The same address on a tailored plan that pays a GROUP. Distinct from
    /// [`GateAnswer::Solo`] because the two are the mid-session flip
    /// `cache_sync` performs on a group join, and they are indistinguishable
    /// by owner address — only by accounting.
    GroupSolo,
    PoolWide,
}

struct FlippableSource {
    answer: std::sync::Mutex<GateAnswer>,
    next_id: AtomicU64,
    /// Bumped to make the pool-wide fingerprint change, which is the ONLY
    /// thing that makes the publisher publish again. Left alone, the publisher
    /// goes quiet — the state a real pool is in whenever its window is quiet,
    /// and the state that makes "the session catches itself up" testable at
    /// all: with the publisher still pushing, a missing catch-up would be
    /// papered over by the next tick.
    generation: AtomicU64,
    miner: AddressId,
}

impl FlippableSource {
    fn set(&self, answer: GateAnswer) {
        *self.answer.lock().unwrap() = answer;
    }

    fn built(&self) -> BuiltPayoutDistribution {
        let mut fingerprint = FINGERPRINT;
        fingerprint[0] = self.generation.load(Ordering::SeqCst) as u8;
        BuiltPayoutDistribution {
            pool_payout: pool_slot(),
            payouts: miner_slots(),
            dust_limits: dust_limits(),
            additional_outputs: Vec::new(),
            reference_reward_sats: REFERENCE_REWARD,
            payouts_fingerprint: Some(fingerprint),
            bookable: true,
        }
    }
}

#[async_trait]
impl PayoutDistributionSource for FlippableSource {
    async fn build_pool_wide(&self) -> Option<BuiltPayoutDistribution> {
        Some(self.built())
    }

    async fn build_for_miner(&self, _miner_address: &AddressId) -> TailoredDistribution {
        match *self.answer.lock().unwrap() {
            GateAnswer::Unknown => TailoredDistribution::ModeUnknown,
            GateAnswer::PoolWide => TailoredDistribution::PoolWide,
            GateAnswer::Solo => TailoredDistribution::Built {
                accounting: bp_stratum_v2::bridge::DistributionAccounting::Solo(self.miner.clone()),
                built: Box::new(self.built()),
            },
            GateAnswer::GroupSolo => TailoredDistribution::Built {
                accounting: bp_stratum_v2::bridge::DistributionAccounting::GroupSolo(
                    self.miner.clone(),
                ),
                built: Box::new(self.built()),
            },
        }
    }

    /// The SAME field `build_for_miner` reads, mapped to a stream — the
    /// production source reads one gate for both, and a double that could
    /// disagree with itself would prove nothing about a fix whose whole
    /// subject is the two answers agreeing.
    async fn current_mode(&self, _miner_address: &AddressId) -> Option<StreamKind> {
        match *self.answer.lock().unwrap() {
            GateAnswer::Unknown => None,
            GateAnswer::PoolWide => Some(StreamKind::Pplns),
            GateAnswer::Solo => Some(StreamKind::Solo),
            GateAnswer::GroupSolo => Some(StreamKind::GroupSolo),
        }
    }

    async fn next_distribution_id(&self) -> Option<u64> {
        Some(self.next_id.fetch_add(1, Ordering::SeqCst))
    }
}

/// Bring a JDC up to the point where it has negotiated 0x0003 and consumed the
/// §3.1 initial pool-wide push. Returns the id it saw.
async fn negotiated_jdc(addr: std::net::SocketAddr) -> (Reader, Writer, u64) {
    let (mut reader, mut writer) = connect_jdc(addr).await;
    write_msg(&mut writer, setup_connection(addr.port())).await;
    expect_setup_success(read_jdc(&mut reader).await);
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
        JdcInbound::Message(AnyMessage::Extensions(_)) => {}
        other => panic!("expected RequestExtensionsSuccess, got {other:?}"),
    }
    let first = match read_jdc(&mut reader).await {
        JdcInbound::PayoutDistribution(d) => d.distribution_id,
        other => panic!("§3.1: expected the pool-wide distribution, got {other:?}"),
    };
    (reader, writer, first)
}

async fn allocate(reader: &mut Reader, writer: &mut Writer, request_id: u32) -> Vec<u8> {
    write_msg(
        writer,
        AnyMessage::JobDeclaration(JobDeclaration::AllocateMiningJobToken(
            AllocateMiningJobToken {
                request_id,
                user_identifier: REGTEST_ADDR.to_string().try_into().unwrap(),
            }
            .into_static(),
        )),
    )
    .await;
    match read_jdc(reader).await {
        JdcInbound::Message(AnyMessage::JobDeclaration(
            JobDeclaration::AllocateMiningJobTokenSuccess(s),
        )) => s.mining_job_token.as_bytes().to_vec(),
        other => panic!("expected AllocateMiningJobTokenSuccess #{request_id}, got {other:?}"),
    }
}

/// Read frames until a `SetPayoutDistribution` shows up, or give up.
async fn next_distribution(reader: &mut Reader, within: Duration) -> Option<u64> {
    for _ in 0..4 {
        match try_read_jdc(reader, within).await {
            Some(JdcInbound::PayoutDistribution(d)) => return Some(d.distribution_id),
            Some(_) => continue,
            None => return None,
        }
    }
    None
}

fn spawn_jdp_server(
    source: Arc<FlippableSource>,
    bridge: Arc<RwLock<JdpDeclaredJobRegistry>>,
    interval: Duration,
) -> StratumV2JdpServer {
    let noise_config = NoiseConfig::parse_strings(TEST_PUB, TEST_PRV, DEFAULT_CERT_VALIDITY)
        .expect("noise config");
    let mut hooks = JdpServerHooks::no_op();
    hooks.distribution_source = source;
    hooks.prev_hash_provider = Arc::new(FixedPrevHash);
    hooks.allocate_resolver = Arc::new(BaseModeAllocateResolver);
    StratumV2JdpServer::spawn(noise_config, hooks, bridge, interval)
}

async fn accept_loop(
    server: StratumV2JdpServer,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((socket, peer)) = listener.accept().await else {
                break;
            };
            socket.set_nodelay(true).ok();
            server.accept_connection(socket, peer.to_string());
        }
    });
    (addr, handle)
}

/// The coinbase suffix that conforms to the fixed test weights — every
/// distribution in these tests carries the same ones.
fn suffix_for_test_weights() -> Vec<u8> {
    let pool = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(pool_slot().weight),
        script_pubkey: bitcoin::ScriptBuf::from_bytes(pool_slot().script_pubkey),
    };
    conformant_suffix(&pool, &miner_slots(), &dust_limits())
}

/// §6.4.2 rate-limits token issuance to 1/s per connection, and an over-limit
/// request is dropped in silence. Everything that takes a token — an allocate,
/// and an accepted declare — has to be spaced out or the test reads the NEXT
/// frame as the answer to a request that was never answered.
async fn respect_token_rate_limit() {
    tokio::time::sleep(Duration::from_millis(1100)).await;
}

/// A session that waited out its mode and turns out to be PPLNS must be caught
/// up on the CURRENT pool-wide distribution, not merely un-denied.
///
/// While it waited it was excluded from the pool-wide pushes — correctly, the
/// pool did not know they were its. So the last id it holds is whatever was
/// current when it connected, and by the time the mode arrives that id has
/// fallen out of the §7.2 window. Lifting the denial alone leaves it declaring
/// against a stale id and answered `stale-payout-distribution`, which is not a
/// benign error: `stale-chain-tip` is the only code an SRI jd-client retries,
/// every other one sends it off the pool into solo fallback.
///
/// The publisher goes quiet before the flip (an unchanged fingerprint is not
/// republished), so the frame the client receives cannot have come from a tick.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_that_waited_out_its_mode_is_caught_up_on_the_pool_wide_distribution() {
    let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
    let source = Arc::new(FlippableSource {
        answer: std::sync::Mutex::new(GateAnswer::Unknown),
        next_id: AtomicU64::new(FIRST_ID),
        generation: AtomicU64::new(0),
        miner: AddressId::new(REGTEST_ADDR.to_string()).expect("miner address"),
    });
    let server = spawn_jdp_server(source.clone(), bridge.clone(), Duration::from_millis(200));
    wait_until(Duration::from_secs(5), || {
        bridge.read().unwrap().current_pool_wide().is_some()
    })
    .await;
    let (addr, accept_handle) = accept_loop(server.clone()).await;

    let (mut reader, mut writer, first_seen) = negotiated_jdc(addr).await;
    allocate(&mut reader, &mut writer, 2).await;
    assert!(
        try_read_jdc(&mut reader, Duration::from_millis(300))
            .await
            .is_none(),
        "nothing may be published while the mode is unknown"
    );

    // The window moves on without it. This is the gap the catch-up exists for:
    // the id the client holds stops being current, and it has no way to learn
    // that on its own.
    source.generation.store(1, Ordering::SeqCst);
    wait_until(Duration::from_secs(5), || {
        bridge
            .read()
            .unwrap()
            .current_pool_wide()
            .map(|e| e.distribution_id)
            > Some(first_seen)
    })
    .await;
    let current = bridge
        .read()
        .unwrap()
        .current_pool_wide()
        .expect("a pool-wide distribution")
        .distribution_id;
    assert!(current > first_seen, "the window must have moved on");
    assert!(
        try_read_jdc(&mut reader, Duration::from_millis(300))
            .await
            .is_none(),
        "an undecided session must not receive the pool-wide pushes either"
    );

    // ── The miner connects, on the PPLNS port ─────────────────────────
    source.set(GateAnswer::PoolWide);
    respect_token_rate_limit().await;
    let token = allocate(&mut reader, &mut writer, 3).await;
    assert_eq!(
        next_distribution(&mut reader, Duration::from_secs(3)).await,
        Some(current),
        "the session must be handed the CURRENT pool-wide distribution — the publisher \
         is quiet, so nothing else is going to hand it one"
    );

    // And it must be usable, which is the point of pushing it: the denial is
    // lifted and the id resolves for this session.
    respect_token_rate_limit().await;
    write_declare(
        &mut writer,
        10,
        &token,
        &suffix_for_test_weights(),
        Some(current),
    )
    .await;
    expect_declare_success(read_jdc(&mut reader).await, 10);

    accept_handle.abort();
    server.shutdown().await;
}

/// Bring a session to: served the Solo plan its address was on, gate then
/// flipped to Group-Solo, nothing sent since the flip.
///
/// The prologue of every mode-move test, and shared because each of them
/// stands up a real JDP server on a real socket — duplicated, a change to the
/// harness has to be made twice or one test silently stops testing the flip it
/// names.
async fn served_solo_then_joined_a_group(
    source: &Arc<FlippableSource>,
    bridge: &Arc<RwLock<JdpDeclaredJobRegistry>>,
    addr: std::net::SocketAddr,
) -> (Reader, Writer, Vec<u8>, u64) {
    wait_until(Duration::from_secs(5), || {
        bridge.read().unwrap().current_pool_wide().is_some()
    })
    .await;
    let (mut reader, mut writer, _) = negotiated_jdc(addr).await;
    let token = allocate(&mut reader, &mut writer, 2).await;
    let solo_id = next_distribution(&mut reader, Duration::from_secs(3))
        .await
        .expect("a Solo miner must be served a tailored distribution");

    // Nothing else is going to wake this session: no settlement is fired, and
    // the publisher has nothing new to say (an unchanged fingerprint is not
    // republished). Whatever arrives after the flip came from the session's
    // own traffic.
    assert!(
        try_read_jdc(&mut reader, Duration::from_millis(300))
            .await
            .is_none(),
        "the publisher must be quiet, or a push after the flip proves nothing"
    );

    source.set(GateAnswer::GroupSolo);
    (reader, writer, token, solo_id)
}

fn flippable_source() -> Arc<FlippableSource> {
    Arc::new(FlippableSource {
        answer: std::sync::Mutex::new(GateAnswer::Solo),
        next_id: AtomicU64::new(FIRST_ID),
        generation: AtomicU64::new(0),
        miner: AddressId::new(REGTEST_ADDR.to_string()).expect("miner address"),
    })
}

/// The plan built for the mode that moved is DROPPED, not merely superseded —
/// and on BOTH paths that republish one.
///
/// §7.2 keeps the immediately-previous entry of a slot acceptable, so
/// republishing over a stale plan leaves it declarable for one more
/// distribution. The declare-time mode check hides that almost everywhere —
/// almost, because it can only refuse when the pool HAS an answer, and "no
/// live mining session for this address" is not an answer. A miner going
/// offline is not exotic; it is a rig rebooting.
///
/// ⚠️ Both drivers, and the ALLOCATE one is the reason this test is a loop.
/// The allocate arm republishes the tailored plan on every token request and
/// knew nothing about modes moving, while the re-ask arm that did know then
/// found nothing left to do — an SRI jd-client allocates before nearly every
/// declare, so in production the flip was almost always observed there. The
/// drop lives in `republish_tailored` for exactly that reason: one place, all
/// three callers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_plan_for_a_mode_that_moved_is_dropped_not_superseded() {
    for drive_with_allocate in [false, true] {
        let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
        let source = flippable_source();
        let server = spawn_jdp_server(source.clone(), bridge.clone(), Duration::from_millis(200));
        let (addr, accept_handle) = accept_loop(server.clone()).await;
        let (mut reader, mut writer, token, solo_id) =
            served_solo_then_joined_a_group(&source, &bridge, addr).await;

        // The session's own next frame is what makes the pool re-ask.
        respect_token_rate_limit().await;
        let token = if drive_with_allocate {
            allocate(&mut reader, &mut writer, 3).await
        } else {
            write_declare(
                &mut writer,
                10,
                &token,
                &suffix_for_test_weights(),
                Some(solo_id),
            )
            .await;
            read_jdc(&mut reader).await; // the refusal — asserted below
            token
        };
        let group_id = next_distribution(&mut reader, Duration::from_secs(3))
            .await
            .expect("the moved mode must be answered with a fresh plan");
        assert!(
            group_id > solo_id,
            "allocate={drive_with_allocate}: the group plan must be a NEW distribution"
        );

        // ── The rig reboots: the gate forgets the address ─────────────
        // The declare check has nothing to judge by now, so the drop is the
        // only thing left between the old plan and a blessed coinbase.
        source.set(GateAnswer::Unknown);
        respect_token_rate_limit().await;
        write_declare(
            &mut writer,
            11,
            &token,
            &suffix_for_test_weights(),
            Some(solo_id),
        )
        .await;
        match read_jdc(&mut reader).await {
            JdcInbound::Message(AnyMessage::JobDeclaration(
                JobDeclaration::DeclareMiningJobError(e),
            )) => assert_eq!(
                e.error_code.as_utf8_or_hex(),
                "stale-payout-distribution",
                "allocate={drive_with_allocate}: the pre-join plan must be gone, not sitting \
                 in the grace window"
            ),
            other => panic!(
                "allocate={drive_with_allocate}: the pre-join plan must not be declarable, \
                 got {other:?}"
            ),
        }

        accept_handle.abort();
        server.shutdown().await;
    }
}

/// A session already being served re-asks its mode, and a group join mid-flight
/// is answered with a new plan — not left on the one built for the mode before.
///
/// This is the production path `cache_sync::reconcile_gate_modes` walks: it
/// flips a live address from Solo to Group-Solo the moment a join is approved,
/// deliberately WITHOUT a reconnect. Until this existed the JDP side never
/// asked again, so the session kept being served the Solo plan and the mining
/// side refused every custom job built on it — fatal for an SRI jd-client,
/// which treats every code but `stale-chain-tip` as a reason to leave the pool.
///
/// Driven by a DECLARE and deliberately not by an allocate: an allocate
/// rebuilds the tailored plan unconditionally, so a test driven by one would
/// pass with the re-ask removed and prove nothing. A declare is also the frame
/// that matters — it is where a coinbase gets blessed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_served_session_is_handed_a_new_plan_when_its_mode_moves() {
    let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
    let source = flippable_source();
    let server = spawn_jdp_server(source.clone(), bridge.clone(), Duration::from_millis(200));
    let (addr, accept_handle) = accept_loop(server.clone()).await;
    let (mut reader, mut writer, token, solo_id) =
        served_solo_then_joined_a_group(&source, &bridge, addr).await;

    respect_token_rate_limit().await;
    write_declare(
        &mut writer,
        10,
        &token,
        &suffix_for_test_weights(),
        Some(solo_id),
    )
    .await;
    match read_jdc(&mut reader).await {
        JdcInbound::Message(AnyMessage::JobDeclaration(JobDeclaration::DeclareMiningJobError(
            e,
        ))) => assert_eq!(
            e.error_code.as_utf8_or_hex(),
            "stale-payout-distribution",
            "a coinbase paying the plan for the old mode must not be blessed"
        ),
        other => panic!("the plan for the old mode must be refused, got {other:?}"),
    }

    // …and the same frame makes the pool re-ask, so the client is handed the
    // plan its new mode calls for instead of being left to hang until a
    // settlement or a reconnect.
    let group_id = next_distribution(&mut reader, Duration::from_secs(3))
        .await
        .expect("the moved mode must be answered with a fresh plan");
    assert!(group_id > solo_id);

    // …and the session is not merely broken: the plan it was just handed
    // works, which is the whole difference from hanging until a reconnect.
    // Same token — a refused declare must not burn one, or the recovery would
    // cost a round-trip the §6.4.2 rate limit charges a second for.
    respect_token_rate_limit().await;
    write_declare(
        &mut writer,
        11,
        &token,
        &suffix_for_test_weights(),
        Some(group_id),
    )
    .await;
    expect_declare_success(read_jdc(&mut reader).await, 11);

    accept_handle.abort();
    server.shutdown().await;
}

/// A miner that ends up on the PPLNS window loses its tailored slot — clearing
/// the denial is not enough.
///
/// `distribution_acceptance` under `JdpSession` scope PREFERS a session's
/// tailored slot whenever it has one, and does so without looking at the
/// settlement epoch. A slot left behind therefore answers for every pool-wide
/// id the session is pushed afterwards, and answers `Stale` to all of them:
/// the session is refused for the life of the connection while the pool
/// believes it is serving it correctly.
///
/// Reached here through a §10 settlement, which is what invalidates a tailored
/// slot and makes the session re-ask what it should be served — by which time
/// the answer has changed.
///
/// The declare at the end is what pins it: the id the pool has just pushed,
/// against the coinbase the pool published, must be accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tailored_session_that_becomes_pplns_drops_its_tailored_slot() {
    let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
    let source = Arc::new(FlippableSource {
        answer: std::sync::Mutex::new(GateAnswer::Solo),
        next_id: AtomicU64::new(FIRST_ID),
        generation: AtomicU64::new(0),
        miner: AddressId::new(REGTEST_ADDR.to_string()).expect("miner address"),
    });
    let server = spawn_jdp_server(source.clone(), bridge.clone(), Duration::from_millis(200));
    wait_until(Duration::from_secs(5), || {
        bridge.read().unwrap().current_pool_wide().is_some()
    })
    .await;
    let (addr, accept_handle) = accept_loop(server.clone()).await;

    let (mut reader, mut writer, pool_wide_id) = negotiated_jdc(addr).await;
    let token = allocate(&mut reader, &mut writer, 2).await;
    let tailored_id = next_distribution(&mut reader, Duration::from_secs(3))
        .await
        .expect("a Solo miner must be served a tailored distribution");
    assert!(tailored_id > pool_wide_id);

    // ── The miner is PPLNS by the time the settlement lands ───────────
    source.set(GateAnswer::PoolWide);
    server.distribution_handle().settle();

    let served = next_distribution(&mut reader, Duration::from_secs(5))
        .await
        .expect("the settlement must leave the session with a distribution again");
    let current = bridge
        .read()
        .unwrap()
        .current_pool_wide()
        .expect("the settlement forces a fresh publish")
        .distribution_id;
    assert_eq!(
        served, current,
        "the session must be moved onto the pool-wide distribution"
    );

    respect_token_rate_limit().await;
    write_declare(
        &mut writer,
        10,
        &token,
        &suffix_for_test_weights(),
        Some(current),
    )
    .await;
    expect_declare_success(read_jdc(&mut reader).await, 10);

    accept_handle.abort();
    server.shutdown().await;
}
