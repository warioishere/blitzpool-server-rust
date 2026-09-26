// SPDX-License-Identifier: AGPL-3.0-or-later

//! A miner may name a rotating identity by its payout id instead of its xpub.
//! Rented hashrate does: MRR, Braiins and the marketplace are configured from
//! the dashboard key. The pool's intake can only admit an id whose descriptor
//! it has loaded, and it is synchronous, so the server has to await
//! `RotatingIntake::warm` before the pure authorize handler runs.
//!
//! No bitcoin node: authorize needs no template, and a template channel that
//! never emits is enough to run the server.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::Network;
use bp_common::{IdentityRefused, PayoutIdentity, RotatingIntake};
use bp_stratum_v1::{PortConfig, ServerConfig, ServerHooks, SharedExtranonce, StratumV1Server};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// A payable regtest address the stand-in identity resolves to.
const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
/// Shaped like a payout id; the stand-in intake decides what it means.
const KNOWN_ID: &str = "xpbAWfNYjeatqcoRWdHy8n1Fh51mqndHVh3kZEu6tf5PifG";
const UNKNOWN_ID: &str = "xpbGde6AcmBoPFVk7mbMgRXUshU81Q7vkEb95vk51jQu1vb";

/// Stands in for the pool's intake, which lives in `bin/blitzpool` and needs a
/// database. It admits `KNOWN_ID` **only after `warm` was called for it**, so
/// an authorize that succeeds is proof the server warmed first. It answers
/// with a static identity because this crate cannot build a rotating one; the
/// ordering is what is under test, not the identity kind.
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

async fn read_frame<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read line");
    serde_json::from_str(&line).unwrap_or(Value::Null)
}

/// Subscribe + authorize as `<username>`, return the authorize response.
async fn authorize(addr: std::net::SocketAddr, username: &str) -> Value {
    let miner = TcpStream::connect(addr).await.expect("connect");
    miner.set_nodelay(true).ok();
    let (read, mut write) = miner.into_split();
    let mut reader = BufReader::new(read);
    write
        .write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"test/1.0\"]}\n")
        .await
        .expect("write subscribe");
    write
        .write_all(
            format!(
                "{{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"{username}\",\"x\"]}}\n"
            )
            .as_bytes(),
        )
        .await
        .expect("write authorize");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = read_frame(&mut reader).await;
            if frame.is_null() {
                return frame;
            }
            if frame.get("id").and_then(|v| v.as_u64()) == Some(2) {
                return frame;
            }
        }
    })
    .await
    .expect("an authorize response within 5 s")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_payout_id_username_is_admitted_because_the_server_warms_first() {
    let (_tx, updates_rx) = tokio::sync::broadcast::channel(8);
    let hooks = ServerHooks {
        rotating_intake: Some(Arc::new(WarmFirstIntake::default())),
        ..ServerHooks::no_op()
    };
    let server = StratumV1Server::spawn(
        ServerConfig::defaults_for(Network::Regtest),
        updates_rx,
        bp_template_distribution::TemplateSnapshot::default(),
        Vec::new(),
        hooks,
        SharedExtranonce::new(),
        Arc::new(bp_mining_job::MiningJobCache::new()),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let port_config = PortConfig::new(addr.port(), 1.0);
    let server_clone = server.clone();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.expect("accept");
            socket.set_nodelay(true).ok();
            server_clone.accept_connection(socket, port_config.clone());
        }
    });

    let admitted = authorize(addr, &format!("{KNOWN_ID}.mrr")).await;
    assert_eq!(
        admitted.get("result"),
        Some(&Value::Bool(true)),
        "the id the intake was warmed for must be admitted: {admitted}"
    );

    // Control on the same server: an id `warm` does not load stays refused,
    // so the admission above came from the warm and not from a lenient intake.
    let refused = authorize(addr, &format!("{UNKNOWN_ID}.mrr")).await;
    assert!(
        refused.get("error").is_some_and(|e| !e.is_null()),
        "an id the intake holds nothing for must be refused: {refused}"
    );
}
