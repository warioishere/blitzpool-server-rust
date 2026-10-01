// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regtest: SV2 per-mode stream routing (Solo, Group-Solo, Blockparty) through
//! one driver, [`run_scenario`]. The recorded `StreamKind` proves the
//! OpenChannel swap fired (else `Pplns`); the chain advancing proves the mode's
//! handle knew the `template_id`, since template ids collide across streams.

#![allow(clippy::print_stderr)]

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::Network;
use bp_common::{AddressId, StreamKind};
use bp_mining_job::{PayoutEntry, ResolvedPayouts};
use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_share::Difficulty;
use bp_stratum_v2::bridge::JdpDeclaredJobRegistry;
use bp_stratum_v2::hooks::{BlockSubmissionSink, MiningServerHooks, PayoutResolver};
use bp_stratum_v2::mining::client::{PortConfig, FLAG_REQUIRES_VERSION_ROLLING};
use bp_stratum_v2::mining::submit::ShareAccept;
use bp_stratum_v2::noise::NoiseConfig;
use bp_stratum_v2::server::{ServerConfig, StratumV2MiningServer};
use bp_template_distribution::{TdpCoinbaseConstraints, TdpConfig, TdpHandle};
use bp_test_support::poll_for_height;
use stratum_apps::key_utils::Secp256k1PublicKey;
use stratum_apps::network_helpers::connect_with_noise;
use stratum_core::common_messages_sv2::{Protocol, SetupConnectionOwned};
use stratum_core::mining_sv2::{OpenStandardMiningChannelOwned, SubmitSharesStandardOwned};
use stratum_core::parsers_sv2::{AnyMessageOwned, CommonMessagesOwned, MiningOwned};
use tokio::net::{TcpListener, TcpStream};

mod common;
use common::{read_any_message, wait_until, write_any_message, REGTEST_ADDR};

const SRI_TEST_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const SRI_TEST_PRV: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

/// The per-mode inputs of one scenario.
#[derive(Clone, Copy)]
struct ModeCase {
    /// The stream the connection must be routed onto.
    stream: StreamKind,
    /// `max_additional_size` advertised on that stream's TDP handle.
    reservation_bytes: u32,
    /// Log prefix + skip-message label.
    label: &'static str,
}

const SOLO: ModeCase = ModeCase {
    stream: StreamKind::Solo,
    reservation_bytes: 1_000,
    label: "solo",
};

/// The production Group-Solo reservation, `tdp_constraint_for_budget(10_000 WU)`.
const GROUP_SOLO: ModeCase = ModeCase {
    stream: StreamKind::GroupSolo,
    reservation_bytes: 2_756,
    label: "group-solo",
};

/// The production Blockparty reservation, `tdp_constraint_for_budget(8_000 WU)`.
const BLOCKPARTY: ModeCase = ModeCase {
    stream: StreamKind::Blockparty,
    reservation_bytes: 2_256,
    label: "blockparty",
};

/// Routes every address to `stream` and splits the block's OWN revenue, so the
/// payouts consume the template value exactly.
struct FixedResolver {
    stream: StreamKind,
    addresses: Vec<String>,
}

#[async_trait]
impl PayoutResolver for FixedResolver {
    async fn resolve_payouts(
        &self,
        _miner_address: &AddressId,
        reward_sats: u64,
    ) -> ResolvedPayouts {
        ResolvedPayouts::unsnapshotted(split_reward(&self.addresses, reward_sats))
    }

    fn resolve_stream(&self, _miner_address: &AddressId) -> StreamKind {
        self.stream
    }
}

/// Even split, remainder onto the first; any other sum is `bad-cb-amount`.
fn split_reward(addresses: &[String], reward_sats: u64) -> Vec<PayoutEntry> {
    let n = addresses.len() as u64;
    let each = reward_sats / n;
    let remainder = reward_sats - each * n;
    addresses
        .iter()
        .enumerate()
        .map(|(i, address)| PayoutEntry {
            address: address.clone(),
            sats: if i == 0 { each + remainder } else { each },
        })
        .collect()
}

/// Records the routed stream and submits through that stream's handle.
struct RecordingSink {
    tdp_default: TdpHandle,
    tdp_alt: TdpHandle,
    /// The one stream with a dedicated handle, compared rather than matched so
    /// a new `StreamKind` cannot silently fall through to the default handle.
    alt: StreamKind,
    recorded: Arc<Mutex<Vec<StreamKind>>>,
}

#[async_trait]
impl BlockSubmissionSink for RecordingSink {
    async fn submit_block(
        &self,
        accept: &ShareAccept,
        _address: &str,
        _worker: &str,
        _session_id_hex: &str,
        stream: StreamKind,
    ) {
        self.recorded.lock().unwrap().push(stream);
        if accept.witness_coinbase.is_empty() || accept.template_id.is_none() {
            return;
        }
        let handle = if stream == self.alt {
            &self.tdp_alt
        } else {
            &self.tdp_default
        };
        let h = &accept.header;
        let version = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let ts = u32::from_le_bytes([h[68], h[69], h[70], h[71]]);
        let nonce = u32::from_le_bytes([h[76], h[77], h[78], h[79]]);
        let _ = handle
            .submit_solution(
                accept.template_id.expect("checked above"),
                version,
                ts,
                nonce,
                accept.witness_coinbase.clone(),
            )
            .await;
    }
}

// ── the three modes ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv2_solo_connection_routes_to_solo_stream_and_block_accepted() {
    let Some(node) = start_node_or_skip(SOLO, "routing").await else {
        return;
    };
    let outcome = run_scenario(&node, SOLO, vec![REGTEST_ADDR.to_string()]).await;
    node.shutdown().await.ok();
    assert_routed_and_landed(SOLO, &outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv2_group_solo_connection_routes_to_group_solo_stream_and_block_accepted() {
    let Some(node) = start_node_or_skip(GROUP_SOLO, "routing").await else {
        return;
    };
    let outcome = run_scenario(&node, GROUP_SOLO, vec![REGTEST_ADDR.to_string()]).await;
    node.shutdown().await.ok();
    assert_routed_and_landed(GROUP_SOLO, &outcome);
}

/// 50 P2TR members, the worst-case output type, fit the production Group-Solo
/// reservation through the SV2 coinbase builder.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv2_group_solo_max_size_multi_output_coinbase_accepted() {
    let Some(node) = start_node_or_skip(GROUP_SOLO, "max-size multi-output").await else {
        return;
    };
    const MEMBERS: usize = 50;
    let members = mint_p2tr_members(&node, MEMBERS).await;
    let outcome = run_scenario(&node, GROUP_SOLO, members).await;
    node.shutdown().await.ok();
    eprintln!(
        "[sv2-group-solo] {MEMBERS}-output coinbase accepted: height {} → {}",
        outcome.before, outcome.after
    );
    assert_routed_and_landed(GROUP_SOLO, &outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv2_blockparty_connection_routes_to_blockparty_stream_and_block_accepted() {
    let Some(node) = start_node_or_skip(BLOCKPARTY, "routing").await else {
        return;
    };
    let outcome = run_scenario(&node, BLOCKPARTY, vec![REGTEST_ADDR.to_string()]).await;
    node.shutdown().await.ok();
    assert_routed_and_landed(BLOCKPARTY, &outcome);
}

// ── driver ──────────────────────────────────────────────────────────────

/// What one scenario observed; the submit tallies say why no block landed.
struct Outcome {
    recorded: Vec<StreamKind>,
    before: u32,
    after: u32,
    successes: u32,
    errors: Vec<String>,
}

/// Start a regtest node past IBD, or `None` when bitcoin-node isn't installed.
async fn start_node_or_skip(case: ModeCase, what: &str) -> Option<RegtestNode> {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping SV2 {} {what} regtest — {}",
            case.label,
            cfg.unavailable_reason()
        );
        return None;
    }
    let node = RegtestNode::start_with(RegtestConfig::default())
        .await
        .expect("regtest start");
    node.generate_to_self(101)
        .await
        .expect("mine 101 for IBD-exit + maturity");
    Some(node)
}

async fn mint_p2tr_members(node: &RegtestNode, n: usize) -> Vec<String> {
    let mut members = Vec::with_capacity(n);
    for _ in 0..n {
        members.push(
            node.new_address("bech32m")
                .await
                .expect("mint bech32m member address"),
        );
    }
    members
}

fn assert_routed_and_landed(case: ModeCase, outcome: &Outcome) {
    let Outcome {
        recorded,
        before,
        after,
        successes,
        errors,
    } = outcome;
    let want = case.stream;
    let label = case.label;
    eprintln!(
        "[sv2-{label}] recorded streams = {recorded:?}, height {before} → {after}, \
         submits {successes} success, errors={errors:?}"
    );
    assert!(
        recorded.contains(&want),
        "block-submit must be routed via the {want:?} stream (OpenChannel swap); \
         recorded {recorded:?}"
    );
    assert!(
        recorded.iter().all(|s| *s == want),
        "a {want:?} connection must never submit via the boot (Pplns) stream; \
         recorded {recorded:?}"
    );
    assert!(
        after > before,
        "bitcoin-core must accept the {want:?}-stream block via the {want:?} handle \
         (height {before} → {after}; submits {successes} success, errors={errors:?})"
    );
}

/// Two TDP streams (default + `case.stream`), the SV2 server, and one Noise
/// miner submitting until a block lands.
async fn run_scenario(node: &RegtestNode, case: ModeCase, addresses: Vec<String>) -> Outcome {
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
    let tdp_alt = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1)
            .with_coinbase_constraints(TdpCoinbaseConstraints {
                max_additional_size: case.reservation_bytes,
                max_additional_sigops: 0,
            }),
    )
    .expect("spawn per-mode TDP");

    let updates_rx = tdp_default.subscribe();
    let alt_updates_rx = tdp_alt.subscribe();
    node.generate_to_self(1)
        .await
        .expect("mine 1 for templates");

    let recorded: Arc<Mutex<Vec<StreamKind>>> = Arc::new(Mutex::new(Vec::new()));
    let hooks = MiningServerHooks {
        block_sink: Arc::new(RecordingSink {
            tdp_default: tdp_default.clone(),
            tdp_alt: tdp_alt.clone(),
            alt: case.stream,
            recorded: recorded.clone(),
        }),
        payout_resolver: Arc::new(FixedResolver {
            stream: case.stream,
            addresses,
        }),
        ..MiningServerHooks::no_op()
    };
    let noise_config =
        NoiseConfig::new(SRI_TEST_PUB.parse().unwrap(), SRI_TEST_PRV.parse().unwrap());
    let bridge = Arc::new(RwLock::new(JdpDeclaredJobRegistry::new()));
    let server = StratumV2MiningServer::spawn(
        ServerConfig::defaults_for(Network::Regtest),
        noise_config,
        updates_rx,
        tdp_default.current_snapshot(),
        vec![(case.stream, alt_updates_rx, tdp_alt.current_snapshot())],
        hooks,
        bridge,
        common::sv2_extranonce(),
        std::sync::Arc::new(bp_mining_job::MiningJobCache::new()),
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
        vardiff_silence_easing: false,
        job_lifecycle: bp_jobs_lifecycle::LifecycleConfig::DEFAULT,
    };
    let server_clone = server.clone();
    let accept_handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        socket.set_nodelay(true).ok();
        server_clone.accept_connection(socket, port_config);
    });

    let miner_socket = TcpStream::connect(addr).await.expect("connect");
    miner_socket.set_nodelay(true).ok();
    let pub_key: Secp256k1PublicKey = SRI_TEST_PUB.parse().expect("parse pub key");
    let noise = connect_with_noise(miner_socket, Some(pub_key))
        .await
        .expect("noise handshake");
    let (mut reader, mut writer) = noise.into_split();

    write_any_message(
        &mut writer,
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
        })),
    )
    .await;
    let _ = read_any_message(&mut reader).await; // SetupConnectionSuccess

    // OpenStandardMiningChannel with the mode's address → triggers the swap.
    write_any_message(
        &mut writer,
        AnyMessageOwned::Mining(MiningOwned::OpenStandardMiningChannel(
            OpenStandardMiningChannelOwned {
                request_id: 1u32,
                user_identity: format!("{REGTEST_ADDR}.w1").try_into().unwrap(),
                // 0 H/s → assigned `min_difficulty` (1e-18) → trivial target →
                // every submit accepted, ~every accepted share a block candidate.
                nominal_hash_rate: 0.0,
                max_target: [0xFFu8; 32].into(),
            },
        )),
    )
    .await;

    // Capture the first NewMiningJob (built from the mode's template post-swap):
    // it carries the channel_id, job_id, version and min_ntime to submit with.
    let mut job: Option<(u32, u32, u32)> = None;
    let mut ntime: Option<u32> = None;
    let _ = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            match read_any_message(&mut reader).await {
                AnyMessageOwned::Mining(MiningOwned::NewMiningJob(j)) => {
                    if let Some(t) = j.min_ntime.clone().into_inner() {
                        ntime = Some(t);
                    }
                    job = Some((j.channel_id, j.job_id, j.version));
                }
                // A future job carries an empty min_ntime; the activating
                // SetNewPrevHash supplies it.
                AnyMessageOwned::Mining(MiningOwned::SetNewPrevHash(p)) => {
                    ntime = Some(p.min_ntime);
                }
                _ => {}
            }
            if job.is_some() && ntime.is_some() {
                return;
            }
        }
    })
    .await;
    let (channel_id, job_id, version) = job.expect("NewMiningJob within 8s");
    let ntime = ntime.expect("min_ntime via job or SetNewPrevHash");
    eprintln!(
        "[sv2-{}] captured job: channel_id={channel_id} job_id={job_id} \
         version={version:#x} ntime={ntime}",
        case.label
    );

    // Submit nonces until the chain advances (a block landed via the mode's
    // handle). ~50% of nonces clear the regtest target → lands within a few.
    let before = node.current_height().await.expect("height");
    let mut landed = None;
    let mut successes = 0u32;
    let mut errors: Vec<String> = Vec::new();
    let mut latest_job = (channel_id, job_id, version, ntime);
    for nonce in 0u32..24 {
        let (cid, jid, ver, nt) = latest_job;
        write_any_message(
            &mut writer,
            AnyMessageOwned::Mining(MiningOwned::SubmitSharesStandard(
                SubmitSharesStandardOwned {
                    channel_id: cid,
                    sequence_number: nonce,
                    job_id: jid,
                    nonce,
                    ntime: nt,
                    version: ver,
                },
            )),
        )
        .await;
        // Drain the server's responses for a short window, classifying each.
        let _ = tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                match read_any_message(&mut reader).await {
                    AnyMessageOwned::Mining(MiningOwned::SubmitSharesError(e)) => {
                        errors.push(String::from_utf8_lossy(e.error_code.as_bytes()).to_string());
                    }
                    AnyMessageOwned::Mining(MiningOwned::SubmitSharesSuccess(_)) => successes += 1,
                    // A future job keeps the previous ntime until its
                    // SetNewPrevHash arrives.
                    AnyMessageOwned::Mining(MiningOwned::NewMiningJob(j)) => {
                        let nt = j.min_ntime.clone().into_inner().unwrap_or(nt);
                        latest_job = (j.channel_id, j.job_id, j.version, nt);
                    }
                    AnyMessageOwned::Mining(MiningOwned::SetNewPrevHash(p)) => {
                        let (cid, jid, ver, _) = latest_job;
                        latest_job = (cid, jid, ver, p.min_ntime);
                    }
                    _ => {}
                }
            }
        })
        .await;
        if let Some(h) = poll_for_height(node, before + 1, Duration::from_millis(400)).await {
            landed = Some(h);
            break;
        }
    }

    drop(writer);
    drop(reader);
    server.shutdown().await;
    tdp_default.shutdown().ok();
    tdp_alt.shutdown().ok();
    let after = landed.unwrap_or(before);
    let recorded = recorded.lock().unwrap().clone();
    let _ = accept_handle.await;
    Outcome {
        recorded,
        before,
        after,
        successes,
        errors,
    }
}
