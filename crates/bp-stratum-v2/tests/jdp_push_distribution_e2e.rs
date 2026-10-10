// SPDX-License-Identifier: AGPL-3.0-or-later

//! Socket-level e2e of the ext 0x0003 push model on the JDP server with a
//! minimal JDC over real Noise: first-message distribution, empty allocate,
//! conformant declare, booking, grace window, negotiation gate, the JDP →
//! Mining bridge seam and the base-protocol allocate. Needs no node or PG.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use bp_common::{AddressId, StreamKind};
use bp_stratum_v2::bridge::{
    BuiltPayoutDistribution, JdpDeclaredJobRegistry, PayoutDistributionEntry,
};
use bp_stratum_v2::extensions::{
    encode_distribution_id_tlv, SetPayoutDistribution, SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS,
};
use bp_stratum_v2::jdp::client::{
    parse_user_identifier_as_address, AllocateTokenContext, DeclarationRef, SolutionHeader,
    ERR_INVALID_MINING_JOB_TOKEN, ERR_INVALID_PAYOUT_DISTRIBUTION, ERR_STALE_PAYOUT_DISTRIBUTION,
    FLAG_DECLARE_TX_DATA,
};
use bp_stratum_v2::jdp::dynamic_outputs::{
    designated_output_blob, CandidateBacking, PayoutBooking,
};
use bp_stratum_v2::jdp::payout_distribution::{compute_payout_vector, WeightedOutput};
use bp_stratum_v2::jdp_server::{
    AllocateOutcome, ChainTipProvider, DeclaredJobToValidate, DeclaredJobValidator,
    JdpAllocateResolver, JdpBlockSubmissionSink, JdpServerHooks, JobVerdict,
    PayoutDistributionSource, StratumV2JdpServer, TailoredDistribution,
};
use bp_stratum_v2::jdp_server_codec::EXT_0X0003_MSG_TYPE_SET_PAYOUT_DISTRIBUTION;
use bp_stratum_v2::noise::NoiseConfig;
use bp_stratum_v2::tokens::Token;
use stratum_apps::key_utils::Secp256k1PublicKey;
use stratum_apps::network_helpers::connect_with_noise;
use stratum_apps::network_helpers::noise_stream::{NoiseTcpReadHalf, NoiseTcpWriteHalf};
use stratum_core::codec_sv2::{EncodableFrame, MessageFrame};
use stratum_core::common_messages_sv2::{Protocol, SetupConnectionOwned};
use stratum_core::extensions_sv2::extensions_negotiation::RequestExtensionsOwned;
use stratum_core::framing_sv2::framing::SerializedFrame;
use stratum_core::job_declaration_sv2::{
    AllocateMiningJobTokenOwned, DeclareMiningJobOwned, PushSolutionOwned,
};
use stratum_core::parsers_sv2::{
    parse_message_frame_with_tlvs, AnyMessageOwned, CommonMessagesOwned,
    ExtensionsNegotiationOwned, ExtensionsOwned, JobDeclarationOwned,
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

/// Fixed-weight distribution source: same ext 0x0003/SetPayoutDistribution
/// shape every build, ids strictly increasing from [`FIRST_ID`].
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
impl ChainTipProvider for FixedPrevHash {
    async fn current_prev_hash(&self) -> Option<[u8; 32]> {
        Some(PREV_HASH)
    }

    async fn current_target(&self) -> Option<[u8; 32]> {
        None
    }
}

/// Production's allocate answers: empty outputs with ext 0x0003, otherwise one
/// 0-sat designated output paying the miner. Not [`JdpServerHooks::no_op`],
/// whose empty base-path answer registers nothing and would make the
/// base-protocol assertions prove nothing.
struct BaseModeAllocateResolver;

#[async_trait]
impl JdpAllocateResolver for BaseModeAllocateResolver {
    async fn resolve_allocate_context(
        &self,
        user_identifier: &str,
        payout_distribution_negotiated: bool,
    ) -> AllocateOutcome {
        let Some(miner_address) = parse_user_identifier_as_address(user_identifier) else {
            return AllocateOutcome::Ignored;
        };
        let coinbase_outputs = if payout_distribution_negotiated {
            Vec::new()
        } else {
            match bp_mining_job::address_to_script(
                bitcoin::Network::Regtest,
                miner_address.as_str(),
            ) {
                Ok(script) => designated_output_blob(&script),
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
    async fn submit_block_candidate(
        &self,
        miner_address: AddressId,
        _declaration: DeclarationRef,
        backing: CandidateBacking,
        coinbase_raw: Vec<u8>,
        _transactions: Vec<Vec<u8>>,
        header: SolutionHeader,
    ) {
        self.candidates.lock().unwrap().push(RecordedCandidate {
            miner_address: miner_address.as_str().to_string(),
            backing,
            coinbase_raw,
            prev_hash: header.prev_hash,
        });
    }
}

// ── The test ────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jdp_push_distribution_end_to_end() {
    let noise_config = NoiseConfig::new(TEST_PUB.parse().unwrap(), TEST_PRV.parse().unwrap());
    let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
    let sink = Arc::new(RecordingSink::default());

    let mut hooks = JdpServerHooks::no_op();
    hooks.distribution_source = Arc::new(FixedSource {
        next_id: AtomicU64::new(FIRST_ID),
    });
    hooks.chain_tip = Arc::new(FixedPrevHash);
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
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            socket.set_nodelay(true).ok();
            server_accept.accept_connection(socket);
        }
    });

    // ── Connection 1: the negotiated JDC ──────────────────────────────
    let (mut reader, mut writer) = connect_jdc(addr).await;

    write_msg(&mut writer, setup_connection(addr.port())).await;
    expect_setup_success(read_jdc(&mut reader).await);

    // Negotiate 0x0003.
    write_msg(
        &mut writer,
        AnyMessageOwned::Extensions(ExtensionsOwned::ExtensionsNegotiation(
            ExtensionsNegotiationOwned::RequestExtensions(RequestExtensionsOwned {
                request_id: 1,
                requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS]
                    .try_into()
                    .unwrap(),
            }),
        )),
    )
    .await;
    match read_jdc(&mut reader).await {
        JdcInbound::Message(AnyMessageOwned::Extensions(
            ExtensionsOwned::ExtensionsNegotiation(
                ExtensionsNegotiationOwned::RequestExtensionsSuccess(s),
            ),
        )) => {
            assert!(s
                .supported_extensions
                .clone()
                .into_inner()
                .contains(&SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS));
        }
        other => panic!("expected RequestExtensionsSuccess, got {other:?}"),
    }

    // ext 0x0003/SetPayoutDistribution: the very next frame MUST be
    // SetPayoutDistribution.
    let distribution = match read_jdc(&mut reader).await {
        JdcInbound::PayoutDistribution(d) => d,
        other => panic!("ext 0x0003/SetPayoutDistribution violated — expected SetPayoutDistribution next, got {other:?}"),
    };
    assert_eq!(distribution.distribution_id, FIRST_ID);
    assert_eq!(distribution.dust_limits, dust_limits());
    assert!(distribution.additional_outputs.is_empty());
    // The weights ride in the consensus TxOut amount fields
    // (ext 0x0003/SetPayoutDistribution).
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

    // ext 0x0003/Negotiation: allocate returns EMPTY coinbase outputs when
    // 0x0003 is on.
    write_msg(
        &mut writer,
        AnyMessageOwned::JobDeclaration(JobDeclarationOwned::AllocateMiningJobToken(
            AllocateMiningJobTokenOwned {
                request_id: 2,
                user_identifier: REGTEST_ADDR.to_string().try_into().unwrap(),
            },
        )),
    )
    .await;
    let token = match read_jdc(&mut reader).await {
        JdcInbound::Message(AnyMessageOwned::JobDeclaration(
            JobDeclarationOwned::AllocateMiningJobTokenSuccess(s),
        )) => {
            assert_eq!(s.request_id, 2);
            assert!(
                s.coinbase_outputs.as_bytes().is_empty(),
                "ext 0x0003/Negotiation: coinbase_outputs MUST be empty when 0x0003 is negotiated"
            );
            s.mining_job_token.as_bytes().to_vec()
        }
        other => panic!("expected AllocateMiningJobTokenSuccess, got {other:?}"),
    };

    // ext 0x0003/Payout Computation from the RECEIVED wire distribution.
    let suffix = conformant_suffix(&pool_out, &wire_payouts, &distribution.dust_limits);

    // Declare #9: negotiated but NO TLV → invalid
    // (ext 0x0003/distribution_id TLV Field mandatory).
    write_declare(&mut writer, 9, &token, &suffix, None).await;
    expect_declare_error(
        read_jdc(&mut reader).await,
        9,
        ERR_INVALID_PAYOUT_DISTRIBUTION,
    );

    // Declare #9 spent its token even though it was refused. Declare #10
    // brings its own.
    let token = next_token(&mut reader, &mut writer, 3).await;

    // Declare #10: conformant coinbase + TLV(FIRST_ID) → accepted.
    write_declare(&mut writer, 10, &token, &suffix, Some(FIRST_ID)).await;
    let declared_token = expect_declare_success(read_declare_answer(&mut reader).await, 10);

    // ── The JDP → Mining seam ─────────────────────────────────────────
    // The mining connection judges `SetCustomMiningJob` against this bridge
    // entry; without it a Full-Template JDC gets the fatal
    // `invalid-mining-job-token`. Registered before the Success frame, so no race.
    let declared_token =
        Token(<[u8; 16]>::try_from(declared_token.as_slice()).expect("16-byte job token"));
    let job_ref = bridge
        .read()
        .unwrap()
        .job_ref(&declared_token)
        .expect("an accepted declaration MUST be resolvable by the mining side");
    assert_eq!(job_ref.miner_address.as_str(), REGTEST_ADDR);
    assert_eq!(
        job_ref.declared_prev_hash, PREV_HASH,
        "the mining side rejects a custom job that does not build on this tip"
    );
    assert_eq!(
        job_ref.distribution_id,
        Some(FIRST_ID),
        "ext 0x0003/distribution_id TLV Field puts the TLV on DeclareMiningJob in Full-Template mode — the mining \
         side can only inherit the reference from here"
    );
    // Presence is not enough: a stub entry would still fail every custom job.
    let binding = job_ref
        .binding
        .expect("the declared coinbase must project, or the custom job is refused");
    assert_eq!(binding.coinbase_script_sig_prefix, SCRIPT_SIG_HEAD);
    assert_eq!(binding.extranonce_slot, EXTRANONCE_LEN);
    assert_eq!(binding.version, 0x2000_0000);

    // Negative control: an undeclared token resolves to nothing.
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
        AnyMessageOwned::JobDeclaration(JobDeclarationOwned::PushSolution(PushSolutionOwned {
            extranonce: extranonce.clone().try_into().unwrap(),
            prev_hash: PREV_HASH.into(),
            ntime: 0x6500_0001,
            nonce: 0x1234_5678,
            nbits: 0x1d00_ffff,
            version: 0x2000_0000,
        })),
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

    // ── ext 0x0003/Grace Window: slide the pool-wide distribution twice ───
    for id in [FIRST_ID + 1, FIRST_ID + 2] {
        bridge.write().unwrap().publish_pool_wide(entry_with_id(id));
    }

    // Declare #12 referencing k-2 → stale. The allocate that pays for it
    // republishes the plan that just slid; drain that push so it is not
    // mistaken for the answer.
    let token = next_token(&mut reader, &mut writer, 4).await;
    write_declare(&mut writer, 12, &token, &suffix, Some(FIRST_ID)).await;
    expect_declare_error(
        read_declare_answer(&mut reader).await,
        12,
        ERR_STALE_PAYOUT_DISTRIBUTION,
    );

    // Declare #13 referencing k-1 (the grace slot) → still accepted.
    let token = next_token(&mut reader, &mut writer, 5).await;
    write_declare(&mut writer, 13, &token, &suffix, Some(FIRST_ID + 1)).await;
    expect_declare_success(read_declare_answer(&mut reader).await, 13);

    // ── Connection 2: TLV without negotiation → rejected (ext 0x0003/Negotiation) ───
    let (mut reader2, mut writer2) = connect_jdc(addr).await;
    write_msg(&mut writer2, setup_connection(addr.port())).await;
    expect_setup_success(read_jdc(&mut reader2).await);
    write_msg(
        &mut writer2,
        AnyMessageOwned::JobDeclaration(JobDeclarationOwned::AllocateMiningJobToken(
            AllocateMiningJobTokenOwned {
                request_id: 2,
                user_identifier: REGTEST_ADDR.to_string().try_into().unwrap(),
            },
        )),
    )
    .await;
    let token2 = match read_jdc(&mut reader2).await {
        JdcInbound::Message(AnyMessageOwned::JobDeclaration(
            JobDeclarationOwned::AllocateMiningJobTokenSuccess(s),
        )) => {
            // SV2 JDP/AllocateMiningJobToken.Success: one 0-sat designated
            // output paying this miner; a valued output would make the JDC's
            // coinbase overspend the block.
            let outputs: Vec<bitcoin::TxOut> =
                bitcoin::consensus::deserialize(s.coinbase_outputs.as_bytes())
                    .expect("allocate outputs must decode");
            assert_eq!(
                outputs.len(),
                1,
                "SV2 JDP/AllocateMiningJobToken.Success designates ONE payout output"
            );
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

    // A Full-Template allocate must not resolve, or the JDC could skip the
    // declaration its tx set is validated in (SV2 JDP/Job Declarator Server).
    // Connection 1's ext 0x0003 token has no designated output to register.
    // The positive case is connection 4.
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
    // SV2 Overview/SetupConnection.Error: the error frame arrives "prior to
    // closing the connection"; without the close the FD leaks (no idle timeout).
    let (mut reader3, mut writer3) = connect_jdc(addr).await;
    write_msg(&mut writer3, setup_connection_wrong_protocol(addr.port())).await;
    match read_jdc(&mut reader3).await {
        JdcInbound::Message(AnyMessageOwned::Common(
            CommonMessagesOwned::SetupConnectionError(e),
        )) => {
            assert_eq!(
                std::str::from_utf8(e.error_code.as_ref()).unwrap(),
                "unsupported-protocol"
            );
        }
        other => panic!("expected SetupConnectionError, got {other:?}"),
    }
    let after = tokio::time::timeout(Duration::from_secs(5), reader3.read_frame()).await;
    match after {
        Ok(Err(_)) => {}
        Ok(Ok(f)) => panic!("expected the server to close, got another frame: {f:?}"),
        Err(_) => panic!("the server left a refused connection open"),
    }

    // ── Connection 4: a real Coinbase-only JDC (the base path) ────────
    // SV2 JDP/Coinbase-only Mode never declares, so the allocate is the only
    // record of the token; without it every job gets the fatal
    // `invalid-mining-job-token`.
    let (mut reader4, mut writer4) = connect_jdc(addr).await;
    write_msg(&mut writer4, setup_connection_coinbase_only(addr.port())).await;
    expect_setup_success(read_jdc(&mut reader4).await);
    write_msg(
        &mut writer4,
        AnyMessageOwned::JobDeclaration(JobDeclarationOwned::AllocateMiningJobToken(
            AllocateMiningJobTokenOwned {
                request_id: 4,
                user_identifier: REGTEST_ADDR.to_string().try_into().unwrap(),
            },
        )),
    )
    .await;
    let token4 = match read_jdc(&mut reader4).await {
        JdcInbound::Message(AnyMessageOwned::JobDeclaration(
            JobDeclarationOwned::AllocateMiningJobTokenSuccess(s),
        )) => {
            // SV2 JDP/AllocateMiningJobToken.Success: one 0-sat designated output.
            let outputs: Vec<bitcoin::TxOut> =
                bitcoin::consensus::deserialize(s.coinbase_outputs.as_bytes())
                    .expect("allocate outputs must decode");
            assert_eq!(
                outputs.len(),
                1,
                "SV2 JDP/AllocateMiningJobToken.Success designates ONE payout output"
            );
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
        // The token's TTL travels with it, so the map cannot grow unbounded.
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

/// The BIP-34 height push before the extranonce slot; the mining side
/// compares against exactly these via the bridge projection.
const SCRIPT_SIG_HEAD: [u8; 3] = [0x03, 0xC8, 0x00];

/// A real coinbase header up to the extranonce slot. It has to parse:
/// declare-time validation rebuilds the transaction from it and takes the
/// slot width from its scriptSig length.
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

fn setup_connection(port: u16) -> AnyMessageOwned {
    AnyMessageOwned::Common(CommonMessagesOwned::SetupConnection(SetupConnectionOwned {
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
    }))
}

/// A coinbase suffix whose outputs are the ext 0x0003/Payout Computation
/// recompute at the JDC's own template revenue:
/// `[sequence][outputs][locktime]`.
fn conformant_suffix(pool: &bitcoin::TxOut, payouts: &[WeightedOutput], dust: &[u32]) -> Vec<u8> {
    let pool_slot = WeightedOutput {
        script_pubkey: pool.script_pubkey.to_bytes(),
        weight: pool.value.to_sat(),
    };
    let outputs = compute_payout_vector(&pool_slot, payouts, dust, &[], REFERENCE_REWARD)
        .expect("ext 0x0003/Payout Computation compute");
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
        built: BuiltPayoutDistribution {
            pool_payout: pool_slot(),
            payouts: miner_slots(),
            dust_limits: dust_limits(),
            additional_outputs: Vec::new(),
            reference_reward_sats: REFERENCE_REWARD,
            payouts_fingerprint: Some(FINGERPRINT),
            bookable: true,
        },
        accounting: bp_stratum_v2::bridge::DistributionAccounting::PoolWide,
        jdp_session_id: None,
        published_at_ms: 2_000,
    }
}

// ── Wire helpers ────────────────────────────────────────────────────

type Reader = NoiseTcpReadHalf;
type Writer = NoiseTcpWriteHalf;

/// A Coinbase-only `SetupConnection`: `DECLARE_TX_DATA` clear, so the JDC
/// never declares and takes its allocate token straight to the mining
/// connection (SV2 JDP/Coinbase-only Mode).
fn setup_connection_coinbase_only(port: u16) -> AnyMessageOwned {
    AnyMessageOwned::Common(CommonMessagesOwned::SetupConnection(SetupConnectionOwned {
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
    }))
}

/// A `SetupConnection` the JDP server must refuse: the Mining
/// sub-protocol on the job-declaration port.
fn setup_connection_wrong_protocol(port: u16) -> AnyMessageOwned {
    AnyMessageOwned::Common(CommonMessagesOwned::SetupConnection(SetupConnectionOwned {
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
    }))
}

async fn connect_jdc(addr: std::net::SocketAddr) -> (Reader, Writer) {
    let socket = TcpStream::connect(addr).await.expect("connect");
    socket.set_nodelay(true).ok();
    let pub_key: Secp256k1PublicKey = TEST_PUB.parse().expect("pub key");
    let noise = connect_with_noise(socket, Some(pub_key))
        .await
        .expect("noise handshake");
    noise.into_split()
}

#[derive(Debug)]
enum JdcInbound {
    Message(AnyMessageOwned),
    PayoutDistribution(SetPayoutDistribution),
}

async fn read_jdc(reader: &mut Reader) -> JdcInbound {
    let frame = tokio::time::timeout(Duration::from_secs(5), reader.read_frame())
        .await
        .expect("read timeout")
        .expect("read_frame");
    let mut sv2_frame = frame;
    let header = sv2_frame.header();
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
    JdcInbound::Message(msg.into_owned())
}

async fn write_msg(writer: &mut Writer, msg: AnyMessageOwned) {
    let frame: MessageFrame<AnyMessageOwned> = msg.try_into().expect("frame");
    writer.write_frame(frame).await.expect("write");
}

/// Write a `DeclareMiningJob`, optionally with the ext 0x0003/distribution_id
/// TLV Field appended and the header's msg_length patched to cover it.
async fn write_declare(
    writer: &mut Writer,
    request_id: u32,
    token: &[u8],
    suffix: &[u8],
    distribution_id: Option<u64>,
) {
    let msg = AnyMessageOwned::JobDeclaration(JobDeclarationOwned::DeclareMiningJob(
        DeclareMiningJobOwned {
            request_id,
            mining_job_token: token.to_vec().try_into().unwrap(),
            version: 0x2000_0000,
            coinbase_tx_prefix: coinbase_prefix().try_into().unwrap(),
            coinbase_tx_suffix: suffix.to_vec().try_into().unwrap(),
            wtxid_list: Vec::new().try_into().unwrap(),
            excess_data: Vec::new().try_into().unwrap(),
        },
    ));
    let frame: MessageFrame<AnyMessageOwned> = msg.try_into().expect("frame");
    let Some(id) = distribution_id else {
        writer.write_frame(frame).await.expect("write");
        return;
    };
    // Serialize the frame, append the TLV tail, patch msg_length (u24
    // LE at header bytes 3..6), re-wrap as raw bytes.
    let mut bytes = vec![0u8; frame.encoded_length()];
    frame.encode_into(&mut bytes).expect("serialize");
    bytes.extend_from_slice(&encode_distribution_id_tlv(id));
    let payload_len = (bytes.len() - 6) as u32;
    bytes[3] = (payload_len & 0xFF) as u8;
    bytes[4] = ((payload_len >> 8) & 0xFF) as u8;
    bytes[5] = ((payload_len >> 16) & 0xFF) as u8;
    let raw = SerializedFrame::from_bytes(bytes).expect("patched frame header");
    writer.write_frame(raw).await.expect("write");
}

fn expect_setup_success(inbound: JdcInbound) {
    match inbound {
        JdcInbound::Message(AnyMessageOwned::Common(
            CommonMessagesOwned::SetupConnectionSuccess(_),
        )) => {}
        other => panic!("expected SetupConnectionSuccess, got {other:?}"),
    }
}

/// Returns the `new_mining_job_token` the JDS issued — the key the
/// mining connection later presents in `SetCustomMiningJob`.
fn expect_declare_success(inbound: JdcInbound, request_id: u32) -> Vec<u8> {
    match inbound {
        JdcInbound::Message(AnyMessageOwned::JobDeclaration(
            JobDeclarationOwned::DeclareMiningJobSuccess(s),
        )) => {
            assert_eq!(s.request_id, request_id);
            s.new_mining_job_token.as_bytes().to_vec()
        }
        other => panic!("expected DeclareMiningJobSuccess #{request_id}, got {other:?}"),
    }
}

fn expect_declare_error(inbound: JdcInbound, request_id: u32, code: &str) {
    match inbound {
        JdcInbound::Message(AnyMessageOwned::JobDeclaration(
            JobDeclarationOwned::DeclareMiningJobError(e),
        )) => {
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

/// Stands in for the mode gate: the miner's mode is unknown until the test
/// says its mining session registered.
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

    /// Off the same flag as `build_for_miner`, so the two cannot disagree.
    async fn current_mode(&self, _miner_address: &AddressId) -> Option<StreamKind> {
        self.known
            .load(Ordering::SeqCst)
            .then_some(StreamKind::Solo)
    }

    async fn next_distribution_id(&self) -> Option<u64> {
        Some(self.next_id.fetch_add(1, Ordering::SeqCst))
    }
}

/// Read a frame, or `None` if none arrives within `within`, for tests where
/// the absence of a frame is the assertion.
async fn try_read_jdc(reader: &mut Reader, within: Duration) -> Option<JdcInbound> {
    match tokio::time::timeout(within, reader.read_frame()).await {
        Err(_) => None,
        Ok(frame) => {
            let mut sv2_frame = frame.expect("read_frame");
            let header = sv2_frame.header();
            if header.ext_type_without_channel_msg() == SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS {
                let payload = sv2_frame.payload();
                return Some(JdcInbound::PayoutDistribution(
                    SetPayoutDistribution::deserialize(payload).expect("SetPayoutDistribution"),
                ));
            }
            let (msg, _tlvs) =
                parse_message_frame_with_tlvs(header, sv2_frame.payload(), &[]).expect("parse");
            Some(JdcInbound::Message(msg.into_owned()))
        }
    }
}

/// Nothing is published while the mode is unknown, and the next inbound frame
/// (not the one-hour publisher tick) publishes once it is known.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_is_served_nothing_until_its_mode_is_known() {
    let noise_config = NoiseConfig::new(TEST_PUB.parse().unwrap(), TEST_PRV.parse().unwrap());
    let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
    let source = Arc::new(ModeGatedSource {
        known: AtomicBool::new(false),
        next_id: AtomicU64::new(FIRST_ID),
        miner: AddressId::new(REGTEST_ADDR.to_string()).expect("miner address"),
    });

    let mut hooks = JdpServerHooks::no_op();
    hooks.distribution_source = source.clone();
    hooks.chain_tip = Arc::new(FixedPrevHash);
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
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            socket.set_nodelay(true).ok();
            server_accept.accept_connection(socket);
        }
    });

    let (mut reader, mut writer) = connect_jdc(addr).await;
    write_msg(&mut writer, setup_connection(addr.port())).await;
    expect_setup_success(read_jdc(&mut reader).await);

    write_msg(
        &mut writer,
        AnyMessageOwned::Extensions(ExtensionsOwned::ExtensionsNegotiation(
            ExtensionsNegotiationOwned::RequestExtensions(RequestExtensionsOwned {
                request_id: 1,
                requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS]
                    .try_into()
                    .unwrap(),
            }),
        )),
    )
    .await;
    match read_jdc(&mut reader).await {
        JdcInbound::Message(AnyMessageOwned::Extensions(_)) => {}
        other => panic!("expected RequestExtensionsSuccess, got {other:?}"),
    }
    // Before any allocate the pool does not know who this is, so
    // ext 0x0003/SetPayoutDistribution gets the pool-wide plan.
    match read_jdc(&mut reader).await {
        JdcInbound::PayoutDistribution(d) => assert_eq!(d.distribution_id, FIRST_ID),
        other => panic!(
            "ext 0x0003/SetPayoutDistribution: expected the pool-wide distribution, got {other:?}"
        ),
    }

    // ── Identity known, mode NOT known ────────────────────────────────
    write_msg(
        &mut writer,
        AnyMessageOwned::JobDeclaration(JobDeclarationOwned::AllocateMiningJobToken(
            AllocateMiningJobTokenOwned {
                request_id: 2,
                user_identifier: REGTEST_ADDR.to_string().try_into().unwrap(),
            },
        )),
    )
    .await;
    match read_jdc(&mut reader).await {
        JdcInbound::Message(AnyMessageOwned::JobDeclaration(
            JobDeclarationOwned::AllocateMiningJobTokenSuccess(_),
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

    // Any inbound frame is the trigger.
    write_msg(
        &mut writer,
        AnyMessageOwned::JobDeclaration(JobDeclarationOwned::AllocateMiningJobToken(
            AllocateMiningJobTokenOwned {
                request_id: 3,
                user_identifier: REGTEST_ADDR.to_string().try_into().unwrap(),
            },
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
#[derive(Clone, Copy, PartialEq, Eq)]
enum GateAnswer {
    Unknown,
    Solo,
    /// A tailored plan paying a group; only the accounting tells it from
    /// [`GateAnswer::Solo`], and a group join flips between them mid-session.
    GroupSolo,
    PoolWide,
}

struct FlippableSource {
    answer: std::sync::Mutex<GateAnswer>,
    next_id: AtomicU64,
    /// Bumped to change the fingerprint, the only thing that makes the
    /// publisher publish again; left alone it goes quiet, so a session
    /// catch-up is not masked by the next tick.
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

    /// The same field `build_for_miner` reads, as production reads one gate for both.
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

/// A JDC that negotiated 0x0003 and consumed the initial pool-wide push,
/// returned with that push's id.
async fn negotiated_jdc(addr: std::net::SocketAddr) -> (Reader, Writer, u64) {
    let (mut reader, mut writer) = connect_jdc(addr).await;
    write_msg(&mut writer, setup_connection(addr.port())).await;
    expect_setup_success(read_jdc(&mut reader).await);
    write_msg(
        &mut writer,
        AnyMessageOwned::Extensions(ExtensionsOwned::ExtensionsNegotiation(
            ExtensionsNegotiationOwned::RequestExtensions(RequestExtensionsOwned {
                request_id: 1,
                requested_extensions: vec![SV2_EXTENSION_TYPE_NON_CUSTODIAL_PAYOUTS]
                    .try_into()
                    .unwrap(),
            }),
        )),
    )
    .await;
    match read_jdc(&mut reader).await {
        JdcInbound::Message(AnyMessageOwned::Extensions(_)) => {}
        other => panic!("expected RequestExtensionsSuccess, got {other:?}"),
    }
    let first = match read_jdc(&mut reader).await {
        JdcInbound::PayoutDistribution(d) => d.distribution_id,
        other => panic!(
            "ext 0x0003/SetPayoutDistribution: expected the pool-wide distribution, got {other:?}"
        ),
    };
    (reader, writer, first)
}

async fn allocate(reader: &mut Reader, writer: &mut Writer, request_id: u32) -> Vec<u8> {
    write_msg(
        writer,
        AnyMessageOwned::JobDeclaration(JobDeclarationOwned::AllocateMiningJobToken(
            AllocateMiningJobTokenOwned {
                request_id,
                user_identifier: REGTEST_ADDR.to_string().try_into().unwrap(),
            },
        )),
    )
    .await;
    match read_jdc(reader).await {
        JdcInbound::Message(AnyMessageOwned::JobDeclaration(
            JobDeclarationOwned::AllocateMiningJobTokenSuccess(s),
        )) => s.mining_job_token.as_bytes().to_vec(),
        other => panic!("expected AllocateMiningJobTokenSuccess #{request_id}, got {other:?}"),
    }
}

/// Read to the declaration's answer, skipping distribution pushes, which are
/// not ordered against it. A timed drain instead would race and swallow
/// misdelivered frames.
async fn read_declare_answer(reader: &mut Reader) -> JdcInbound {
    for _ in 0..4 {
        match read_jdc(reader).await {
            JdcInbound::PayoutDistribution(_) => continue,
            other => return other,
        }
    }
    panic!("no answer to the declaration arrived");
}

/// A fresh allocate token, spaced out for the SV2 JDP/AllocateMiningJobToken
/// rate limit. Every declaration spends its token, whichever way it ends.
async fn next_token(reader: &mut Reader, writer: &mut Writer, request_id: u32) -> Vec<u8> {
    respect_token_rate_limit().await;
    allocate(reader, writer, request_id).await
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
    let noise_config = NoiseConfig::new(TEST_PUB.parse().unwrap(), TEST_PRV.parse().unwrap());
    let mut hooks = JdpServerHooks::no_op();
    hooks.distribution_source = source;
    hooks.chain_tip = Arc::new(FixedPrevHash);
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
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            socket.set_nodelay(true).ok();
            server.accept_connection(socket);
        }
    });
    (addr, handle)
}

/// The coinbase suffix conforming to the fixed weights every test distribution carries.
fn suffix_for_test_weights() -> Vec<u8> {
    let pool = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(pool_slot().weight),
        script_pubkey: bitcoin::ScriptBuf::from_bytes(pool_slot().script_pubkey),
    };
    conformant_suffix(&pool, &miner_slots(), &dust_limits())
}

/// SV2 JDP/AllocateMiningJobToken issues at most 1 token/s per connection and
/// silently drops the rest, so anything taking a token is spaced out or the
/// test reads the next frame as an answer that never came.
async fn respect_token_rate_limit() {
    tokio::time::sleep(Duration::from_millis(1100)).await;
}

/// A session that waited out its mode and is PPLNS is pushed the CURRENT
/// pool-wide distribution: its held id may have left the ext 0x0003/Grace
/// Window, and `stale-payout-distribution` is not retried by clients.
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

    // The window moves on without it: the id the client holds stops being
    // current, and it cannot learn that on its own.
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

    // And the pushed id resolves for this session.
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

/// Shared prologue of the mode-move tests: a session served its Solo plan, then
/// the gate flipped to Group-Solo with nothing sent since.
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

    // No settlement and an unchanged fingerprint: whatever arrives after the
    // flip came from the session's own traffic.
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

/// The plan for a mode that moved is dropped, not superseded, on both the
/// declare and the allocate path: ext 0x0003/Grace Window would keep a
/// superseded plan declarable, and after a rig reboot the mode check has
/// nothing to judge by.
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
            Some(allocate(&mut reader, &mut writer, 3).await)
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
                                         // The replacement token comes after the plan
                                         // push, so this leg stays declare-driven.
            None
        };
        let group_id = next_distribution(&mut reader, Duration::from_secs(3))
            .await
            .expect("the moved mode must be answered with a fresh plan");
        assert!(
            group_id > solo_id,
            "allocate={drive_with_allocate}: the group plan must be a NEW distribution"
        );
        let token = match token {
            Some(token) => token,
            None => next_token(&mut reader, &mut writer, 6).await,
        };

        // ── The rig reboots: the gate forgets the address ─────────────
        // Now only the drop stands between the old plan and a blessed coinbase.
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
        match read_declare_answer(&mut reader).await {
            JdcInbound::Message(AnyMessageOwned::JobDeclaration(
                JobDeclarationOwned::DeclareMiningJobError(e),
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

/// A served session re-asks its mode on a declare, and a mid-session group
/// join is answered with a new plan. Driven by a declare because an allocate
/// rebuilds the plan unconditionally and would pass without the re-ask.
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
        JdcInbound::Message(AnyMessageOwned::JobDeclaration(
            JobDeclarationOwned::DeclareMiningJobError(e),
        )) => assert_eq!(
            e.error_code.as_utf8_or_hex(),
            "stale-payout-distribution",
            "a coinbase paying the plan for the old mode must not be blessed"
        ),
        other => panic!("the plan for the old mode must be refused, got {other:?}"),
    }

    // The same frame makes the pool re-ask and push the new mode's plan.
    let group_id = next_distribution(&mut reader, Duration::from_secs(3))
        .await
        .expect("the moved mode must be answered with a fresh plan");
    assert!(group_id > solo_id);

    // The new plan works, on a fresh token since the refused declare spent its own.
    let token = next_token(&mut reader, &mut writer, 6).await;
    // The allocate may republish the plan; the declare must name what the
    // pool holds now.
    let group_id = next_distribution(&mut reader, Duration::from_millis(500))
        .await
        .unwrap_or(group_id);
    write_declare(
        &mut writer,
        11,
        &token,
        &suffix_for_test_weights(),
        Some(group_id),
    )
    .await;
    expect_declare_success(read_declare_answer(&mut reader).await, 11);

    accept_handle.abort();
    server.shutdown().await;
}

/// An allocate token authorises one declaration (SV2 JDP/Full-Template Mode);
/// spending it keeps the allocate rate limit the bound on declarations.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_declaration_on_the_same_token_is_refused() {
    let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
    let source = flippable_source();
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

    let suffix = suffix_for_test_weights();
    write_declare(&mut writer, 10, &token, &suffix, Some(tailored_id)).await;
    expect_declare_success(read_jdc(&mut reader).await, 10);

    // The same declaration on the same token; only the request_id differs.
    write_declare(&mut writer, 11, &token, &suffix, Some(tailored_id)).await;
    expect_declare_error(
        read_jdc(&mut reader).await,
        11,
        ERR_INVALID_MINING_JOB_TOKEN,
    );

    // A fresh token makes the same declaration work again.
    let token = next_token(&mut reader, &mut writer, 3).await;
    write_declare(&mut writer, 12, &token, &suffix, Some(tailored_id)).await;
    expect_declare_success(read_declare_answer(&mut reader).await, 12);

    accept_handle.abort();
    server.shutdown().await;
}

/// The token a declaration is answered with cannot authorise another, or
/// declarations could chain without allocate or rate limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_declaration_token_cannot_itself_authorise_a_declaration() {
    let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
    let source = flippable_source();
    let server = spawn_jdp_server(source.clone(), bridge.clone(), Duration::from_millis(200));
    wait_until(Duration::from_secs(5), || {
        bridge.read().unwrap().current_pool_wide().is_some()
    })
    .await;
    let (addr, accept_handle) = accept_loop(server.clone()).await;

    let (mut reader, mut writer, _) = negotiated_jdc(addr).await;
    let token = allocate(&mut reader, &mut writer, 2).await;
    let tailored_id = next_distribution(&mut reader, Duration::from_secs(3))
        .await
        .expect("a Solo miner must be served a tailored distribution");

    let suffix = suffix_for_test_weights();
    write_declare(&mut writer, 10, &token, &suffix, Some(tailored_id)).await;
    let declaration_token = expect_declare_success(read_jdc(&mut reader).await, 10);
    assert_ne!(
        declaration_token, token,
        "precondition: the pool answers with a token of its own"
    );

    write_declare(
        &mut writer,
        11,
        &declaration_token,
        &suffix,
        Some(tailored_id),
    )
    .await;
    expect_declare_error(
        read_jdc(&mut reader).await,
        11,
        ERR_INVALID_MINING_JOB_TOKEN,
    );

    accept_handle.abort();
    server.shutdown().await;
}

/// A tailored session that becomes PPLNS at a settlement loses its tailored
/// slot, which `JdpSession` scope would otherwise prefer and answer `Stale`
/// for every later pool-wide id.
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

/// Records which sessions it was told are closed; accepts every declaration.
#[derive(Default)]
struct ClosedSessions {
    closed: Mutex<Vec<u32>>,
}

#[async_trait]
impl DeclaredJobValidator for ClosedSessions {
    async fn validate_declaration(&self, _job: DeclaredJobToValidate<'_>) -> JobVerdict {
        JobVerdict::Accepted
    }

    fn session_closed(&self, session_id: u32) {
        self.closed.lock().unwrap().push(session_id);
    }
}

/// A closed JDP connection is released exactly once by the validator, an open one never.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closed_connection_is_released_by_the_validator() {
    let validator = Arc::new(ClosedSessions::default());
    let noise_config = NoiseConfig::new(TEST_PUB.parse().unwrap(), TEST_PRV.parse().unwrap());
    let mut hooks = JdpServerHooks::no_op();
    hooks.job_validator = Some(validator.clone() as Arc<dyn DeclaredJobValidator>);
    let server = StratumV2JdpServer::spawn(
        noise_config,
        hooks,
        Arc::new(RwLock::new(JdpDeclaredJobRegistry::new())),
        Duration::from_secs(60),
    );
    let (addr, accept_handle) = accept_loop(server.clone()).await;

    let (mut reader, mut writer) = connect_jdc(addr).await;
    write_msg(&mut writer, setup_connection(addr.port())).await;
    expect_setup_success(read_jdc(&mut reader).await);
    assert!(
        validator.closed.lock().unwrap().is_empty(),
        "an open connection must not be released"
    );

    drop(reader);
    drop(writer);
    wait_until(Duration::from_secs(5), || {
        !validator.closed.lock().unwrap().is_empty()
    })
    .await;
    assert_eq!(
        validator.closed.lock().unwrap().len(),
        1,
        "the closed connection must be released exactly once"
    );

    accept_handle.abort();
    server.shutdown().await;
}
