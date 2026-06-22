// SPDX-License-Identifier: AGPL-3.0-or-later

//! SPIKE: can TWO concurrent TDP/IPC connections to ONE bitcoind each hold
//! their own template (with their own `block_reserved_weight`)?
//!
//! This is the make-or-break assumption for the per-mode multi-stream coinbase
//! reservation: the sv2-apps `BitcoinCoreSv2TDP` keeps exactly one template
//! client per connection, so N reservations means N TDP connections to the same
//! node. If bitcoin-core's IPC can't serve two concurrent template clients, the
//! whole approach is dead and we rethink. This test proves it can.

use bp_regtest_harness::{RegtestConfig, RegtestNode};
use bp_template_distribution::{TdpCoinbaseConstraints, TdpConfig, TdpHandle};
use bp_test_support::wait_for_any_paired_template as wait_for_paired_template;

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

    // A fresh block nudges both connections to emit a paired template.
    node.generate_to_self(1)
        .await
        .expect("mine 1 for fresh template");

    let (t_solo, p_solo) = wait_for_paired_template(&mut rx_solo).await;
    let (t_pplns, p_pplns) = wait_for_paired_template(&mut rx_pplns).await;

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
