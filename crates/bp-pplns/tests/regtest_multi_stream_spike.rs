// SPDX-License-Identifier: AGPL-3.0-or-later

//! SPIKE: can TWO concurrent TDP/IPC connections to ONE bitcoind each hold
//! their own template (with their own `block_reserved_weight`)?
//!
//! This is the make-or-break assumption for the per-mode multi-stream coinbase
//! reservation: the sv2-apps `BitcoinCoreSv2TDP` keeps exactly one template
//! client per connection, so N reservations means N TDP connections to the same
//! node. If bitcoin-core's IPC can't serve two concurrent template clients, the
//! whole approach is dead and we rethink. This test proves it can.

use std::time::Duration;

use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_template_distribution::{
    NewTemplate, SetNewPrevHash, TdpCoinbaseConstraints, TdpConfig, TdpHandle, TemplateUpdate,
};
use tokio::sync::broadcast;

/// Folds one TDP connection's `TemplateUpdate` stream into its most recent
/// complete (`NewTemplate`, `SetNewPrevHash`) pair, matched on
/// `template_id` — same pairing rule the `bp_test_support` waiters use.
#[derive(Default)]
struct PairAcc {
    template: Option<NewTemplate>,
    prev_hash: Option<SetNewPrevHash>,
    latest: Option<(NewTemplate, SetNewPrevHash)>,
}

impl PairAcc {
    fn feed(&mut self, update: TemplateUpdate) {
        match update {
            TemplateUpdate::NewTemplate(t) => self.template = Some(t),
            TemplateUpdate::SetNewPrevHash(p) => self.prev_hash = Some(p),
            _ => return,
        }
        if let (Some(t), Some(p)) = (&self.template, &self.prev_hash) {
            if t.template_id == p.template_id {
                self.latest = Some((t.clone(), p.clone()));
            }
        }
    }

    fn tip(&self) -> Option<&SetNewPrevHash> {
        self.latest.as_ref().map(|(_, p)| p)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn two_concurrent_tdp_connections_both_get_templates() {
    let cfg = RegtestConfig::default();
    if !cfg.is_available() {
        eprintln!(
            "skipping multi-stream spike — bitcoin-node not found at {}",
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

    // Two independent TDP connections to the SAME IPC socket, each with its own
    // coinbase-output reservation (tiny "solo" vs large "pplns").
    let tdp_solo = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1)
            .with_coinbase_constraints(TdpCoinbaseConstraints {
                max_additional_size: 256, // ~tiny solo coinbase
                max_additional_sigops: 0,
            }),
    )
    .expect("spawn solo TDP");
    let tdp_pplns = TdpHandle::spawn(
        TdpConfig::new(node.ipc_socket_path())
            .with_fee_threshold(1)
            .with_min_interval_secs(1)
            .with_coinbase_constraints(TdpCoinbaseConstraints {
                max_additional_size: 50_000, // ~large PPLNS coinbase
                max_additional_sigops: 0,
            }),
    )
    .expect("spawn pplns TDP");

    let mut rx_solo = tdp_solo.subscribe();
    let mut rx_pplns = tdp_pplns.subscribe();

    let mut acc_solo = PairAcc::default();
    let mut acc_pplns = PairAcc::default();

    // Each connection emits a startup pair for the PRE-generate tip as soon as
    // it attaches. Taking exactly one pair per connection after mining is what
    // made this test flaky: whether that startup pair lands before or after
    // `subscribe()` is a scheduler race, and when it landed after, one side
    // reported the stale startup template (id 0, old tip) while the other was
    // already on the freshly mined one.
    //
    // Collect it up front instead, so the skip path below is exercised on
    // every run rather than only under unlucky timing. Bounded: if a pair was
    // emitted before `subscribe()` it is simply gone, and nothing here depends
    // on having seen it.
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                r = rx_solo.recv() => { if let Ok(u) = r { acc_solo.feed(u) } }
                r = rx_pplns.recv() => { if let Ok(u) = r { acc_pplns.feed(u) } }
            }
            if acc_solo.tip().is_some() && acc_pplns.tip().is_some() {
                return;
            }
        }
    })
    .await;
    let startup_tip: Option<[u8; 32]> = acc_solo.tip().or(acc_pplns.tip()).map(|p| p.prev_hash);

    // A fresh block nudges both connections to emit a paired template.
    node.generate_to_self(1)
        .await
        .expect("mine 1 for fresh template");

    // Read from both until they agree on a tip that is NOT the startup one.
    // The chain is static after the generate, so both converge on the
    // post-generate tip and any stale startup pair is passed over.
    let converged = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let (Some(a), Some(b)) = (acc_solo.tip(), acc_pplns.tip()) {
                if a.prev_hash == b.prev_hash && startup_tip != Some(a.prev_hash) {
                    return;
                }
            }
            tokio::select! {
                r = rx_solo.recv() => match r {
                    Ok(u) => acc_solo.feed(u),
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                r = rx_pplns.recv() => match r {
                    Ok(u) => acc_pplns.feed(u),
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                },
            }
        }
    })
    .await;
    assert!(
        converged.is_ok(),
        "both TDP connections must converge on the post-generate chain tip \
         within 20s — last solo tid {:?}, last pplns tid {:?}, startup tip seen: {}",
        acc_solo.tip().map(|p| p.template_id),
        acc_pplns.tip().map(|p| p.template_id),
        startup_tip.is_some(),
    );

    // The startup pair really was collected and then skipped — otherwise this
    // run did not exercise the path the fix is about.
    assert!(
        startup_tip.is_some(),
        "expected to observe the startup template pair before mining"
    );

    let (t_solo, p_solo) = acc_solo
        .latest
        .expect("solo TDP produced no paired template");
    let (t_pplns, p_pplns) = acc_pplns
        .latest
        .expect("pplns TDP produced no paired template");

    eprintln!(
        "[spike] solo template_id={} (prev tid {}), pplns template_id={} (prev tid {})",
        t_solo.template_id, p_solo.template_id, t_pplns.template_id, p_pplns.template_id
    );

    // Both connections produced a usable template concurrently → bitcoin-core
    // IPC serves multiple template clients. Both must build on the same tip.
    assert_eq!(
        p_solo.prev_hash, p_pplns.prev_hash,
        "both streams must build on the same chain tip"
    );
    assert!(t_solo.coinbase_tx_value_remaining > 0);
    assert!(t_pplns.coinbase_tx_value_remaining > 0);

    tdp_solo.shutdown().ok();
    tdp_pplns.shutdown().ok();
    node.shutdown().await.ok();
}
