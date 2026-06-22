// SPDX-License-Identifier: AGPL-3.0-or-later

//! Confirmation watcher for confirmation-gated block-founds (PPLNS + Group-Solo).
//!
//! A found block parks its frozen payout in the Redis pending-store
//! ([`crate::pending_blocks`] for PPLNS, [`crate::pending_group_solo_blocks`]
//! for Group-Solo) instead of writing the ledger immediately. This task waits
//! for each parked block to reach `confirmation_depth` confirmations, then
//! applies it; a block that orphaned (or a non-chain-extending candidate, which
//! never confirms) is discarded so the internal ledger never drifts. The
//! on-chain coinbase payment is unaffected — only the internal accounting is
//! gated. Blockparty is exempt: its payouts are fixed per-member percentages
//! recomputed from the DB, so a replay/orphan can't drift anything.
//!
//! The per-block confirmation decision ([`classify_block`]) + the generic
//! load/classify/discard pass ([`collect_confirmed`]) are shared across both
//! modes; only the thin engine-specific apply loop differs.
//!
//! Trigger: the TDP `SetNewPrevHash` broadcast (a new chain tip → time to
//! re-check confirmations) plus a slow fallback timer in case the TDP stream
//! is quiet. The authoritative per-block status comes from a single
//! `getblockheader <hash>` RPC.

use std::time::Duration;

use bp_bitcoin::{BitcoinRpc, RpcError};
use bp_common::AddressId;
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_pplns_engine::engine::PplnsEngine;
use bp_template_distribution::{TdpHandle, TemplateUpdate};
use redis::aio::ConnectionManager;
use serde::de::DeserializeOwned;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::pending_blocks::{remove_pending_block, PENDING_KEY};
use crate::pending_group_solo_blocks::{remove_pending_group_solo_block, GS_PENDING_KEY};
use crate::pending_store::{load_pending, remove_pending, PendingBlockRef};

/// Fallback re-check cadence when the TDP stream is quiet. New blocks normally
/// drive the watcher via `SetNewPrevHash`; this just bounds the worst-case
/// latency if that stream stalls.
const FALLBACK_POLL: Duration = Duration::from_secs(120);

/// Live confirmation-watcher task + its cancel token. [`Self::shutdown`]
/// cancels and joins it as part of the graceful shutdown sequence.
pub(crate) struct BlockConfirmationHandle {
    task: JoinHandle<()>,
    cancel: CancellationToken,
}

impl BlockConfirmationHandle {
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        if let Err(err) = self.task.await {
            warn!(%err, "block-confirmation: watcher join failed");
        }
    }
}

/// Spawn the confirmation watcher. Owns clones of every handle it needs (all
/// cheap / `Arc`-backed). Reconciles whichever engines are present (PPLNS
/// and/or Group-Solo).
///
/// `tdp` is optional: with a TDP feed (monolith / core-side template source)
/// the `SetNewPrevHash` broadcast wakes the watcher promptly on a new tip. The
/// Satellite has none, so it passes `None` and relies solely on the fallback
/// timer + `getblockheader` RPC — correct, just coarser-grained.
pub(crate) fn spawn(
    tdp: Option<TdpHandle>,
    bitcoin_rpc: BitcoinRpc,
    redis: ConnectionManager,
    pplns: Option<PplnsEngine>,
    group_solo: Option<GroupSoloEngine>,
    confirmation_depth: u32,
) -> BlockConfirmationHandle {
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        let cancel = task_cancel;
        let mut rx = tdp.map(|t| t.subscribe());
        let mut tick = tokio::time::interval(FALLBACK_POLL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await; // consume the immediate first tick

        info!(
            confirmation_depth,
            tdp_driven = rx.is_some(),
            pplns = pplns.is_some(),
            group_solo = group_solo.is_some(),
            "block-confirmation: watcher started"
        );

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = tick.tick() => {
                    reconcile(&bitcoin_rpc, &redis, pplns.as_ref(), group_solo.as_ref(), confirmation_depth).await;
                }
                ev = next_tip_signal(&mut rx) => match ev {
                    // A new chain tip — re-check every parked block's depth.
                    Ok(TemplateUpdate::SetNewPrevHash(_)) => {
                        reconcile(&bitcoin_rpc, &redis, pplns.as_ref(), group_solo.as_ref(), confirmation_depth).await;
                    }
                    // NewTemplate / tx-data responses aren't new-block ticks.
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => continue,
                    // Sender gone (the watcher's own TdpHandle clone normally
                    // outlives it, so this is rare). Drop the stream and keep
                    // running on the fallback timer rather than stopping — parked
                    // blocks must still reconcile.
                    Err(RecvError::Closed) => {
                        rx = None;
                    }
                },
            }
        }
        info!("block-confirmation: watcher stopped");
    });
    BlockConfirmationHandle { task, cancel }
}

/// Await the next TDP tip signal, or pend forever when there's no TDP feed
/// (Satellite) — so the watcher's `select!` falls through to the fallback timer
/// as its only trigger.
async fn next_tip_signal(
    rx: &mut Option<broadcast::Receiver<TemplateUpdate>>,
) -> Result<TemplateUpdate, RecvError> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Per-block confirmation verdict from a single `getblockheader`.
enum BlockStatus {
    /// `confirmations >= depth` — safe to apply.
    Confirmed,
    /// Header known but off the active chain (`confirmations < 0`) or unknown
    /// to the node (`-5`) — no on-chain payment happened; discard.
    Orphaned,
    /// `0 <= confirmations < depth` — still maturing; leave parked.
    Maturing,
    /// RPC error — transient; leave parked and retry next tick.
    Unknown,
}

/// Classify a parked block by its header. Shared by both modes.
async fn classify_block(bitcoin_rpc: &BitcoinRpc, block_hash: &str, depth: i64) -> BlockStatus {
    match bitcoin_rpc.get_block_header(block_hash).await {
        Ok(h) if h.confirmations >= depth => BlockStatus::Confirmed,
        Ok(h) if h.confirmations < 0 => BlockStatus::Orphaned,
        Ok(_) => BlockStatus::Maturing,
        // `Block not found` (-5): the node can't place the hash on any chain it
        // knows → treat as gone, same as orphaned.
        Err(RpcError::BitcoinCore(d)) if d.code == -5 => BlockStatus::Orphaned,
        Err(_) => BlockStatus::Unknown,
    }
}

/// Load every parked entry under `key`, prune unparsable ones, discard
/// orphaned/gone ones, and return the CONFIRMED entries ready to apply (left in
/// the store — the caller removes each after a successful apply, so a failed
/// apply is retried next tick). The generic, engine-agnostic half of the pass.
async fn collect_confirmed<T: DeserializeOwned + PendingBlockRef>(
    bitcoin_rpc: &BitcoinRpc,
    conn: &mut ConnectionManager,
    key: &str,
    depth: i64,
    label: &str,
) -> Vec<T> {
    let (pending, unparsable) = match load_pending::<T>(conn, key).await {
        Ok(v) => v,
        Err(err) => {
            warn!(%err, label, "block-confirmation: load pending failed; retry next tick");
            return Vec::new();
        }
    };
    for hash in unparsable {
        warn!(label, block_hash = %hash, "block-confirmation: pruning unparsable pending entry");
        let _ = remove_pending(conn, key, &hash).await;
    }

    let mut confirmed = Vec::new();
    for pb in pending {
        match classify_block(bitcoin_rpc, pb.block_hash(), depth).await {
            BlockStatus::Confirmed => confirmed.push(pb),
            BlockStatus::Orphaned => {
                warn!(
                    label,
                    block_hash = %pb.block_hash(),
                    height = pb.block_height(),
                    "block-confirmation: block orphaned / not on active chain — discarding frozen \
                     distribution (no on-chain payment occurred)"
                );
                let _ = remove_pending(conn, key, pb.block_hash()).await;
            }
            BlockStatus::Maturing => {}
            BlockStatus::Unknown => warn!(
                label,
                block_hash = %pb.block_hash(),
                "block-confirmation: getblockheader failed; will retry next tick"
            ),
        }
    }
    confirmed
}

/// One reconciliation pass over both stores.
async fn reconcile(
    bitcoin_rpc: &BitcoinRpc,
    redis: &ConnectionManager,
    pplns: Option<&PplnsEngine>,
    group_solo: Option<&GroupSoloEngine>,
    confirmation_depth: u32,
) {
    let depth = i64::from(confirmation_depth);

    if let Some(pplns) = pplns {
        let mut conn = redis.clone();
        let confirmed = collect_confirmed::<crate::pending_blocks::PendingBlock>(
            bitcoin_rpc,
            &mut conn,
            PENDING_KEY,
            depth,
            "PPLNS",
        )
        .await;
        for pb in confirmed {
            match pplns.apply_prepared(&pb.prepared).await {
                Ok(outcome) => {
                    info!(
                        block_hash = %pb.block_hash,
                        height = pb.prepared.block_height,
                        history_inserted = outcome.history_inserted,
                        balances_affected = outcome.balances_affected,
                        "block-confirmation: confirmed → PPLNS ledger applied"
                    );
                    let _ = remove_pending_block(&mut conn, &pb.block_hash).await;
                }
                Err(err) => warn!(
                    %err,
                    block_hash = %pb.block_hash,
                    "block-confirmation: PPLNS apply_prepared failed; will retry next tick"
                ),
            }
        }
    }

    if let Some(group_solo) = group_solo {
        let mut conn = redis.clone();
        let confirmed =
            collect_confirmed::<crate::pending_group_solo_blocks::PendingGroupSoloBlock>(
                bitcoin_rpc,
                &mut conn,
                GS_PENDING_KEY,
                depth,
                "Group-Solo",
            )
            .await;
        for pb in confirmed {
            let group_uuid = match uuid::Uuid::parse_str(&pb.group_id) {
                Ok(u) => u,
                Err(err) => {
                    warn!(%err, block_hash = %pb.block_hash, group_id = %pb.group_id,
                        "block-confirmation: Group-Solo group_id not a UUID — discarding");
                    let _ = remove_pending_group_solo_block(&mut conn, &pb.block_hash).await;
                    continue;
                }
            };
            let finder = match AddressId::new(pb.finder.clone()) {
                Ok(a) => a,
                Err(err) => {
                    warn!(%err, block_hash = %pb.block_hash, finder = %pb.finder,
                        "block-confirmation: Group-Solo finder not a valid address — discarding");
                    let _ = remove_pending_group_solo_block(&mut conn, &pb.block_hash).await;
                    continue;
                }
            };
            match group_solo
                .on_block_found_with_snapshot(
                    group_uuid,
                    pb.block_height,
                    pb.block_reward_sats,
                    &finder,
                    pb.snapshot.clone().into(),
                )
                .await
            {
                Ok(outcome) => {
                    info!(
                        block_hash = %pb.block_hash,
                        height = pb.block_height,
                        group_id = %pb.group_id,
                        history_inserted = outcome.history_inserted,
                        balances_affected = outcome.balances_affected,
                        "block-confirmation: confirmed → Group-Solo ledger applied"
                    );
                    let _ = remove_pending_group_solo_block(&mut conn, &pb.block_hash).await;
                }
                Err(err) => warn!(
                    %err,
                    block_hash = %pb.block_hash,
                    "block-confirmation: Group-Solo apply failed; will retry next tick"
                ),
            }
        }
    }
}
