// SPDX-License-Identifier: AGPL-3.0-or-later

//! Confirmation watcher for confirmation-gated block-founds (PPLNS + Group-Solo).
//!
//! A found block parks its frozen payout in the Redis pending-store
//! ([`crate::pending_blocks`] — one shape for both modes) instead of writing
//! the ledger immediately. This task waits
//! for each parked block to reach `confirmation_depth` confirmations, then
//! applies it; a block that orphaned (or a non-chain-extending candidate, which
//! never confirms) is discarded so the internal ledger never drifts. The
//! on-chain coinbase payment is unaffected — only the internal accounting is
//! gated. Blockparty is exempt: its payouts are fixed per-member percentages
//! recomputed from the DB, so a replay/orphan can't drift anything.
//!
//! The per-block confirmation decision ([`classify_block`]) + the
//! load/classify/discard pass ([`collect_confirmed`]) run once for both
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
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::pending_blocks::{
    load_pending_blocks, put_pending_at, remove_pending_at, remove_pending_block, PendingBlock,
    PENDING_KEY, UNBOOKABLE_KEY,
};

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
/// `tdp` is optional: with a TDP feed (the front's template source) the
/// `SetNewPrevHash` broadcast wakes the watcher promptly on a new tip. The
/// Satellite has none, so it passes `None` and relies solely on the fallback
/// timer + `getblockheader` RPC — correct, just coarser-grained.
pub(crate) fn spawn(
    tdp: Option<TdpHandle>,
    bitcoin_rpc: BitcoinRpc,
    redis: ConnectionManager,
    pplns: Option<PplnsEngine>,
    group_solo: Option<GroupSoloEngine>,
    confirmation_depth: u32,
    // ext 0x0003 §10 settlement fan-out — a gated apply IS a settlement,
    // so the published payout distributions must be invalidated with it
    // or a JDC keeps mining pre-settlement weights. This watcher runs on
    // the `payout` role and the registry lives on `front`, which is
    // exactly why it takes the signal and not a bare in-process handle.
    settle: Option<crate::settlement::SettlementSignal>,
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
                    reconcile(&bitcoin_rpc, &redis, pplns.as_ref(), group_solo.as_ref(), confirmation_depth, settle.as_ref()).await;
                }
                ev = next_tip_signal(&mut rx) => match ev {
                    // A new chain tip — re-check every parked block's depth.
                    Ok(TemplateUpdate::SetNewPrevHash(_)) => {
                        reconcile(&bitcoin_rpc, &redis, pplns.as_ref(), group_solo.as_ref(), confirmation_depth, settle.as_ref()).await;
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
/// apply is retried next tick). The engine-agnostic half of the pass.
async fn collect_confirmed(
    bitcoin_rpc: &BitcoinRpc,
    conn: &mut ConnectionManager,
    key: &str,
    depth: i64,
    label: &str,
) -> Vec<PendingBlock> {
    let (pending, unparsable) = match load_pending_blocks(conn, key).await {
        Ok(v) => v,
        Err(err) => {
            warn!(%err, label, "block-confirmation: load pending failed; retry next tick");
            return Vec::new();
        }
    };
    for hash in unparsable {
        warn!(label, block_hash = %hash, "block-confirmation: pruning unparsable pending entry");
        let _ = remove_pending_at(conn, key, &hash).await;
    }

    let mut confirmed = Vec::new();
    for pb in pending {
        match classify_block(bitcoin_rpc, &pb.block_hash, depth).await {
            BlockStatus::Confirmed => confirmed.push(pb),
            BlockStatus::Orphaned => {
                warn!(
                    label,
                    block_hash = %pb.block_hash,
                    height = pb.block_height,
                    "block-confirmation: block orphaned / not on active chain — discarding frozen \
                     distribution (no on-chain payment occurred)"
                );
                let _ = remove_pending_at(conn, key, &pb.block_hash).await;
            }
            BlockStatus::Maturing => {}
            BlockStatus::Unknown => warn!(
                label,
                block_hash = %pb.block_hash,
                "block-confirmation: getblockheader failed; will retry next tick"
            ),
        }
    }
    confirmed
}

/// One reconciliation pass over the pending store.
///
/// One loop for both modes: the parked blob carries the settlement
/// inputs either way, and `group` decides which engine settles them.
async fn reconcile(
    bitcoin_rpc: &BitcoinRpc,
    redis: &ConnectionManager,
    pplns: Option<&PplnsEngine>,
    group_solo: Option<&GroupSoloEngine>,
    confirmation_depth: u32,
    // See `spawn`: a gated apply IS a §10 settlement event.
    settle: Option<&crate::settlement::SettlementSignal>,
) {
    let depth = i64::from(confirmation_depth);
    let mut conn = redis.clone();
    let confirmed = collect_confirmed(bitcoin_rpc, &mut conn, PENDING_KEY, depth, "pool").await;

    for pb in confirmed {
        // Settlement is `claim − paid` against the block's OWN coinbase,
        // so its payments are not optional: without them there is
        // nothing to settle against and the block is an operator
        // reprocess.
        let Some(actual) = pb.actual_coinbase.clone() else {
            error!(
                block_hash = %pb.block_hash,
                height = pb.block_height,
                "block-confirmation: parked block carries no parsed coinbase — discarding, \
                 reprocess from the block's own coinbase"
            );
            let _ = remove_pending_block(&mut conn, &pb.block_hash).await;
            continue;
        };

        let applied = match (&pb.group, pplns, group_solo) {
            (Some(group), _, Some(engine)) => {
                let (Ok(group_uuid), Ok(finder)) = (
                    uuid::Uuid::parse_str(&group.group_id),
                    AddressId::new(group.finder.clone()),
                ) else {
                    error!(
                        block_hash = %pb.block_hash,
                        group_id = %group.group_id,
                        "block-confirmation: parked Group-Solo block has an unusable group id \
                         or finder — discarding"
                    );
                    let _ = remove_pending_block(&mut conn, &pb.block_hash).await;
                    continue;
                };
                engine
                    .on_block_found(
                        group_uuid,
                        pb.block_height,
                        &actual,
                        &finder,
                        pb.weight_snapshot.clone(),
                        pb.payouts_fingerprint,
                    )
                    .await
                    .map_err(SettleError::GroupSolo)
            }
            (None, Some(engine), _) => engine
                .on_block_found(
                    pb.block_height,
                    &actual,
                    pb.weight_snapshot.clone(),
                    pb.payouts_fingerprint,
                )
                .await
                .map_err(SettleError::Pplns),
            // The engine this block belongs to is not wired on this
            // process. Leave it parked — another process may own it.
            _ => continue,
        };

        match applied {
            Ok(outcome) => {
                if let Some(signal) = settle {
                    signal.settle().await;
                }
                info!(
                    block_hash = %pb.block_hash,
                    height = pb.block_height,
                    group = pb.group.as_ref().map(|g| g.group_id.as_str()).unwrap_or("-"),
                    history_inserted = outcome.history_inserted,
                    "block-confirmation: confirmed → payout history applied"
                );
                let _ = remove_pending_block(&mut conn, &pb.block_hash).await;
            }
            Err(err) if err.is_terminal() => {
                // Park, don't destroy: the frozen blob is the only record
                // of what this block paid every miner.
                let parked = put_pending_at(&mut conn, UNBOOKABLE_KEY, &pb).await.is_ok();
                error!(
                    %err,
                    block_hash = %pb.block_hash,
                    height = pb.block_height,
                    parked,
                    unbookable_key = UNBOOKABLE_KEY,
                    "block-confirmation: block cannot be booked automatically — moved to the \
                     unbookable store instead of retrying forever; the miners it paid are owed \
                     their ledger entry and the frozen distribution is preserved there"
                );
                if parked {
                    let _ = remove_pending_block(&mut conn, &pb.block_hash).await;
                }
            }
            Err(err) => warn!(
                %err,
                block_hash = %pb.block_hash,
                "block-confirmation: apply failed; will retry next tick"
            ),
        }
    }
}

/// The two engines' errors, so one loop can treat them alike.
#[derive(Debug, thiserror::Error)]
enum SettleError {
    #[error(transparent)]
    Pplns(bp_pplns_engine::engine::EngineError),
    #[error(transparent)]
    GroupSolo(bp_group_solo_engine::engine::EngineError),
}

impl SettleError {
    fn is_terminal(&self) -> bool {
        match self {
            SettleError::Pplns(e) => e.is_terminal(),
            SettleError::GroupSolo(e) => e.is_terminal(),
        }
    }
}
