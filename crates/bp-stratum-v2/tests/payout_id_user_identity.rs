// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 twin of bp-stratum-v1's `payout_id_username`: a channel whose user
//! identity is a payout id is admitted only if the server awaited
//! `RotatingIntake::warm` before the pure open handler ran. Rented hashrate
//! names an xpub miner this way, and the pool's intake is synchronous.
//!
//! No bitcoin node: the channel open is answered without a template.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bitcoin::Network;
use bp_common::{IdentityRefused, PayoutIdentity, RotatingIntake};
use bp_share::Difficulty;
use bp_stratum_v2::bridge::JdpDeclaredJobRegistry;
use bp_stratum_v2::hooks::MiningServerHooks;
use bp_stratum_v2::mining::client::{PortConfig, FLAG_REQUIRES_VERSION_ROLLING};
use bp_stratum_v2::noise::NoiseConfig;
use bp_stratum_v2::server::{ServerConfig, StratumV2MiningServer};
use stratum_apps::key_utils::Secp256k1PublicKey;
use stratum_apps::network_helpers::connect_with_noise;
use stratum_core::common_messages_sv2::{Protocol, SetupConnectionOwned};
use stratum_core::mining_sv2::OpenStandardMiningChannelOwned;
use stratum_core::parsers_sv2::{AnyMessageOwned, CommonMessagesOwned, MiningOwned};
use tokio::net::{TcpListener, TcpStream};

mod common;
use common::{decode_label, read_any_message, write_any_message, REGTEST_ADDR};

const SRI_TEST_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const SRI_TEST_PRV: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";
const KNOWN_ID: &str = "xpbAWfNYjeatqcoRWdHy8n1Fh51mqndHVh3kZEu6tf5PifG";
const UNKNOWN_ID: &str = "xpbGde6AcmBoPFVk7mbMgRXUshU81Q7vkEb95vk51jQu1vb";

/// Admits `KNOWN_ID` only after `warm` was called for it. A static stand-in
/// identity, because this crate cannot build a rotating one; the ordering is
/// what is under test.
#[derive(Default)]
struct WarmFirstIntake {
    warmed: Mutex<HashSet<String>>,
}

impl RotatingIntake for WarmFirstIntake {
    fn intake(&self, payout_part: &str) -> Result<Option<PayoutIdentity>, IdentityRefused> {
        if !payout_part.starts_with("xpb") {
            return Ok(None);
        }
        if self.warmed.lock().unwrap().contains(payout_part) {
            Ok(Some(PayoutIdentity::static_address(REGTEST_ADDR)))
        } else {
            Err(IdentityRefused)
        }
    }

    fn warm<'a>(&'a self, payout_part: &'a str) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if payout_part == KNOWN_ID {
                self.warmed.lock().unwrap().insert(payout_part.to_string());
            }
        })
    }
}

/// Noise + SetupConnection + OpenStandardMiningChannel as `<identity>`; the
/// server's first answer to the open.
async fn open_channel(addr: std::net::SocketAddr, identity: &str) -> AnyMessageOwned {
    let socket = TcpStream::connect(addr).await.expect("connect");
    socket.set_nodelay(true).ok();
    let pub_key: Secp256k1PublicKey = SRI_TEST_PUB.parse().expect("pub key");
    let noise = connect_with_noise(socket, Some(pub_key))
        .await
        .expect("noise handshake");
    let (mut reader, mut writer) = noise.into_split();
    let setup =
        AnyMessageOwned::Common(CommonMessagesOwned::SetupConnection(SetupConnectionOwned {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: FLAG_REQUIRES_VERSION_ROLLING,
            endpoint_host: "127.0.0.1".try_into().unwrap(),
            endpoint_port: addr.port(),
            vendor: "test".try_into().unwrap(),
            hardware_version: "v1".try_into().unwrap(),
            firmware: "0.1".try_into().unwrap(),
            device_id: "test".try_into().unwrap(),
        }));
    write_any_message(&mut writer, setup).await;
    let setup_resp = read_any_message(&mut reader).await;
    assert!(
        matches!(
            setup_resp,
            AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionSuccess(_))
        ),
        "expected SetupConnectionSuccess, got {}",
        decode_label(&setup_resp)
    );
    let open = AnyMessageOwned::Mining(MiningOwned::OpenStandardMiningChannel(
        OpenStandardMiningChannelOwned {
            request_id: 1u32,
            user_identity: format!("{identity}.mrr").try_into().unwrap(),
            nominal_hash_rate: 1_000_000.0,
            max_target: [0xFFu8; 32].into(),
        },
    ));
    write_any_message(&mut writer, open).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let m = read_any_message(&mut reader).await;
            match m {
                AnyMessageOwned::Mining(MiningOwned::OpenStandardMiningChannelSuccess(_))
                | AnyMessageOwned::Mining(MiningOwned::OpenMiningChannelError(_)) => return m,
                _ => continue,
            }
        }
    })
    .await
    .expect("an answer to the channel open within 5 s")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_payout_id_user_identity_is_admitted_because_the_server_warms_first() {
    let (_tx, updates_rx) = tokio::sync::broadcast::channel(8);
    let hooks = MiningServerHooks {
        rotating_intake: Some(Arc::new(WarmFirstIntake::default())),
        ..MiningServerHooks::no_op()
    };
    let server = StratumV2MiningServer::spawn(
        ServerConfig::defaults_for(Network::Regtest),
        NoiseConfig::new(SRI_TEST_PUB.parse().unwrap(), SRI_TEST_PRV.parse().unwrap()),
        updates_rx,
        bp_template_distribution::TemplateSnapshot::default(),
        Vec::new(),
        hooks,
        Arc::new(RwLock::new(JdpDeclaredJobRegistry::new())),
        common::sv2_extranonce(),
        Arc::new(bp_mining_job::MiningJobCache::new()),
    );
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
        loop {
            let (socket, _) = listener.accept().await.expect("accept");
            socket.set_nodelay(true).ok();
            server_clone.accept_connection(socket, port_config);
        }
    });

    let admitted = open_channel(addr, KNOWN_ID).await;
    assert!(
        matches!(
            admitted,
            AnyMessageOwned::Mining(MiningOwned::OpenStandardMiningChannelSuccess(_))
        ),
        "the id the intake was warmed for must get a channel, got {}",
        decode_label(&admitted)
    );

    // Control on the same server: an id `warm` does not load is refused, so
    // the channel above came from the warm and not from a lenient intake.
    let refused = open_channel(addr, UNKNOWN_ID).await;
    assert!(
        matches!(
            refused,
            AnyMessageOwned::Mining(MiningOwned::OpenMiningChannelError(_))
        ),
        "an id the intake holds nothing for must be refused, got {}",
        decode_label(&refused)
    );
}
