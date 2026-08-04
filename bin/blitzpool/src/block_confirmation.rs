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
    count_pending_at, load_pending_blocks, put_pending_at, remove_pending_at, remove_pending_block,
    PendingBlock, PENDING_KEY, UNBOOKABLE_KEY,
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

        // Last reported unbookable depth, so a standing non-zero count is
        // logged on change instead of every pass.
        let mut last_unbookable: Option<u64> = None;

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
                    reconcile(&bitcoin_rpc, &redis, pplns.as_ref(), group_solo.as_ref(), confirmation_depth, settle.as_ref(), &mut last_unbookable).await;
                }
                ev = next_tip_signal(&mut rx) => match ev {
                    // A new chain tip — re-check every parked block's depth.
                    Ok(TemplateUpdate::SetNewPrevHash(_)) => {
                        reconcile(&bitcoin_rpc, &redis, pplns.as_ref(), group_solo.as_ref(), confirmation_depth, settle.as_ref(), &mut last_unbookable).await;
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
/// Publish how deep the two parking stores are, and say so in the log when
/// the unbookable one CHANGES.
///
/// The gauge is the standing signal — `pool:unbookable_blocks` had no
/// reader of any kind, so a block whose miners are owed a ledger entry left
/// exactly one log line behind and then nothing. Logging only on a change
/// keeps a standing non-zero count from becoming a line every pass, which
/// is how a real one gets ignored.
async fn report_parked_depths(conn: &mut ConnectionManager, last_unbookable: &mut Option<u64>) {
    let pending = count_pending_at(conn, PENDING_KEY).await;
    let unbookable = count_pending_at(conn, UNBOOKABLE_KEY).await;
    let (Ok(pending), Ok(unbookable)) = (pending, unbookable) else {
        // A Redis blip here costs one sample. Leave the last-reported
        // value alone so the next successful pass still logs a change.
        return;
    };
    bp_metrics::recorder::set_parked_block_counts(pending, unbookable);
    if *last_unbookable != Some(unbookable) {
        if unbookable > 0 {
            error!(
                unbookable,
                pending,
                unbookable_key = UNBOOKABLE_KEY,
                "block-confirmation: blocks nothing can book automatically are parked — their \
                 coinbases already paid miners on-chain and those miners have no ledger entry. \
                 Each entry holds the frozen distribution needed to reprocess it."
            );
        } else if last_unbookable.is_some_and(|prev| prev > 0) {
            info!("block-confirmation: the unbookable store is empty again");
        }
        *last_unbookable = Some(unbookable);
    }
}

async fn reconcile(
    bitcoin_rpc: &BitcoinRpc,
    redis: &ConnectionManager,
    pplns: Option<&PplnsEngine>,
    group_solo: Option<&GroupSoloEngine>,
    confirmation_depth: u32,
    // See `spawn`: a gated apply IS a §10 settlement event.
    settle: Option<&crate::settlement::SettlementSignal>,
    last_unbookable: &mut Option<u64>,
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

    // After the pass, not before: a block parked into the unbookable store
    // by the loop above must show up in the same tick that put it there.
    report_parked_depths(&mut conn, last_unbookable).await;
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

// ── Regtest: a declared block books what its coinbase actually paid ──
//
// The one seam nothing covered. Two halves were each tested and never met:
//
// - `bp-stratum-v2`'s `jdp_push_distribution_e2e` drives the real 0x0003 wire
//   to a `PayoutBooking` — but hands it to a recording fake, no ledger.
// - `bp-pplns-engine`'s `ledger_books_exactly_what_the_accepted_coinbase_paid`
//   books a real accepted coinbase into the ledger — but calls
//   `PplnsEngine::on_block_found` directly, bypassing this file entirely.
//
// Neither crate can see the other (no dependency either way — the hook traits
// are the seam on purpose), so the join is only reachable inside this binary,
// where the JDP sink, the engines and the confirmation watcher meet.
// `book_declared_block_found`, the `emit_block_found` fan-out below it and
// `reconcile` had NO caller in any test.
//
// It drives the PRODUCTION path, not the fallback: with Redis wired a
// block-found FREEZES the distribution and parks it — the ledger stays empty
// until the block is `confirmation_depth` deep and `reconcile` applies it. An
// earlier draft asserted rows right after booking and failed, which is what the
// log said all along ("distribution frozen, awaiting confirmations").
#[cfg(test)]
mod declared_block_booking_regtest {
    use crate::block_sink::TdpBlockSubmissionSink;
    use std::sync::Arc;
    use std::time::Duration;

    use bitcoin::consensus::Decodable;
    use bitcoin::Network;
    use bp_common::{AddressId, Sats};
    use bp_mining_job::{
        build_mining_job_from_tdp, merkle_root_from_coinbase, PayoutEntry, TdpCoinbaseTemplate,
        EXTRANONCE_SLOT_LEN,
    };
    use bp_pplns::DEFAULT_MIN_PAYOUT_SATS;
    use bp_pplns_engine::config::PplnsEngineConfig;
    use bp_pplns_engine::engine::PplnsEngine;
    use bp_pplns_engine::window::NetworkDifficulty;
    use bp_regtest_harness::{RegtestConfig, RegtestNode};
    use bp_share::Target;
    use bp_template_distribution::{NewTemplate, TdpConfig, TdpHandle};
    use bp_test_support::{
        brute_force_nonce, connect_pg_or_skip, connect_redis_in_range_or_skip, poll_for_height,
        redis_db, wait_for_paired_template,
    };

    /// One logical DB per test inside this binary's range; 0..=16 are taken by
    /// the sibling in-source tests. Each `connect_*` FLUSHDBs, so sharing one
    /// would have the tests wipe each other mid-run.
    const DB_BOOKS_THE_COINBASE: u8 = 17;
    const DB_NO_DOUBLE_BOOK: u8 = 18;
    const DB_REFUSES_WITHOUT_COINBASE: u8 = 19;
    const DB_HEIGHT_CONFLICT: u8 = 20;

    /// The production default of `[pplns] confirmation_depth`.
    const DEPTH: u32 = 3;
    /// Sats moved between two miners so the mined coinbase DIVERGES from what
    /// the distribution intended. Without a divergence the central assertion
    /// cannot fail: booking derives from the actual coinbase, so comparing the
    /// ledger against that same coinbase would be a tautology.
    const SHIFT_SATS: u64 = 1_000;

    fn engine_config(fee_addr: &str) -> PplnsEngineConfig {
        PplnsEngineConfig {
            dust_sweep_enabled: false,
            touch_flush_interval_secs: 3_600,
            fee_address: Some(AddressId::new(fee_addr.to_string()).expect("fee addr")),
            fee_percent: 1.5,
            min_payout_sats: Sats(DEFAULT_MIN_PAYOUT_SATS as i64),
            ..PplnsEngineConfig::default()
        }
    }

    fn coinbase_template_from(t: &NewTemplate) -> TdpCoinbaseTemplate<'_> {
        TdpCoinbaseTemplate {
            coinbase_prefix: &t.coinbase_prefix,
            coinbase_tx_version: t.coinbase_tx_version,
            coinbase_tx_input_sequence: t.coinbase_tx_input_sequence,
            coinbase_tx_value_remaining: t.coinbase_tx_value_remaining,
            coinbase_tx_outputs: &t.coinbase_tx_outputs,
            coinbase_tx_outputs_count: t.coinbase_tx_outputs_count,
            coinbase_tx_locktime: t.coinbase_tx_locktime,
        }
    }

    /// A real regtest chain with an accepted block whose coinbase pays a real
    /// PPLNS distribution — everything up to, but not including, the booking.
    struct Chain {
        node: RegtestNode,
        tdp: TdpHandle,
        pplns: PplnsEngine,
        group_solo: bp_group_solo_engine::engine::GroupSoloEngine,
        gate: Arc<crate::engines::BlitzpoolModeGate>,
        pg: sqlx::PgPool,
        redis: redis::aio::ConnectionManager,
        miners: [String; 3],
        fee_addr: String,
        fingerprint: [u8; 32],
        /// What the distribution INTENDED to pay.
        intended: Vec<PayoutEntry>,
        height: u32,
        block_hash: String,
        block_hex: String,
        coinbase_tx: bitcoin::Transaction,
        actual: bp_coinbase_snapshot::ActualCoinbase,
    }

    impl Chain {
        /// `None` ⇒ the caller must return (bitcoin-node / Redis / PG missing).
        async fn setup(redis_db: u8) -> Option<Self> {
            let _ = tracing_subscriber::fmt()
                .with_env_filter("blitzpool=debug,bp_pplns_engine=debug")
                .with_test_writer()
                .try_init();
            let regtest_cfg = RegtestConfig::default();
            if !regtest_cfg.is_available() {
                eprintln!("skipping declared-block booking regtest — bitcoin-node not found");
                return None;
            }
            let redis = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, redis_db).await?;
            let pg = connect_pg_or_skip().await?;

            // Per-test addresses: two tests sharing them would delete each
            // other's rows in the pre-clean below.
            let tag = 0x50 + redis_db;
            let miners = [
                bp_test_support::deterministic_p2wpkh_regtest([tag; 32]),
                bp_test_support::deterministic_p2wpkh_regtest([tag.wrapping_add(0x40); 32]),
                bp_test_support::deterministic_p2wpkh_regtest([tag.wrapping_add(0x80); 32]),
            ];
            let fee_addr =
                bp_test_support::deterministic_p2wpkh_regtest([tag.wrapping_add(0xC0); 32]);

            // A run that panics before its own cleanup leaves rows behind, and
            // the regtest chain restarts at the same height every time — the next
            // run would then trip on "the ledger must still be empty". Clear by
            // ADDRESS so nothing outside this test is touched.
            Self::purge(&pg, &miners, &fee_addr).await;

            let pplns = PplnsEngine::spawn(
                engine_config(&fee_addr),
                redis.clone(),
                pg.clone(),
                NetworkDifficulty::new(1_000.0),
            )
            .await
            .expect("PplnsEngine::spawn");
            let now_ms = chrono::Utc::now().timestamp_millis() as u64;
            for (addr, weight) in [
                (&miners[0], 100.0),
                (&miners[1], 200.0),
                (&miners[2], 300.0),
            ] {
                pplns
                    .record_share(None, addr, weight, now_ms)
                    .await
                    .expect("seed share");
            }

            // The fan-out needs a Group-Solo engine too (not optional), even
            // though this block is a PPLNS one — it is the dispatch target for
            // the OTHER mode and must exist for the sink to be constructible.
            let group_solo = bp_group_solo_engine::engine::GroupSoloEngine::spawn(
                bp_group_solo_engine::config::GroupSoloEngineConfig {
                    fee_address: Some(AddressId::new(fee_addr.clone()).expect("fee addr")),
                    ..Default::default()
                }
                .try_new()
                .expect("group-solo config"),
                redis.clone(),
                pg.clone(),
            )
            .await
            .expect("GroupSoloEngine::spawn");

            // The gate decides which engine books. Its default for an unknown
            // address is SOLO, which books nothing — so forgetting this line
            // makes the assertions fail rather than pass silently.
            let gate = Arc::new(crate::engines::BlitzpoolModeGate::new());
            gate.set_mode(&miners[0], bp_mining_mode::MiningModeResult::pplns());

            let node = RegtestNode::start_with(regtest_cfg)
                .await
                .expect("regtest start");
            // Each test needs its own HEIGHT, not just its own addresses. The
            // ledger keys payout history by height alone — `apply_distribution`
            // asks `pplns_booked_value_rows_at_height`, with no address filter —
            // so two tests whose blocks land at the same height in this shared PG
            // make each other's apply fail with `HeightBookedByAnotherBlock`.
            // That is the production code behaving correctly; the collision is
            // the test's fault. Spread them 10 apart so it cannot happen, in
            // parallel runs either.
            let spread = u32::from(redis_db - DB_BOOKS_THE_COINBASE) * 10;
            node.generate_to_self(101 + spread)
                .await
                .expect("mine for IBD-exit + coinbase maturity");
            let tdp =
                TdpHandle::spawn(TdpConfig::new(node.ipc_socket_path()).with_fee_threshold(1))
                    .expect("TdpHandle::spawn");
            let mut rx = tdp.subscribe();
            let _ = tokio::time::timeout(Duration::from_millis(500), async {
                loop {
                    if rx.recv().await.is_err() {
                        break;
                    }
                }
            })
            .await;
            node.generate_to_self(1)
                .await
                .expect("mine 1 for a fresh NewTemplate");
            let (template, prev_hash) = wait_for_paired_template(&mut rx).await;

            let reward_sats = template.coinbase_tx_value_remaining;
            let dist = pplns
                .build_distribution(reward_sats)
                .await
                .expect("build_distribution");
            let fingerprint = dist.payouts_fingerprint();
            let intended: Vec<PayoutEntry> = dist
                .distribution
                .payout_entries_at(reward_sats)
                .expect("§4 payout vector")
                .iter()
                .map(|(a, s)| PayoutEntry {
                    address: a.as_str().to_string(),
                    sats: *s,
                })
                .collect();

            // Precondition against the trap in the repo's CLAUDE.md: an address
            // `bitcoin::Address` cannot parse is DROPPED, leaving an empty
            // distribution whose miners then surface as 0-sat "late arriver"
            // rows — every assertion downstream would hold while proving
            // nothing.
            assert!(
                intended.len() >= 4,
                "expected the three seeded miners plus the pool output, got {intended:?}"
            );
            for m in &miners {
                assert!(
                    intended.iter().any(|p| p.address == *m && p.sats > 0),
                    "miner {m} must hold a non-zero payout — otherwise this test \
                     books an empty distribution and asserts nothing"
                );
            }

            // In production the divergence is not synthetic: a JD-client builds
            // its coinbase from its OWN template, so its revenue differs from
            // the reference the distribution was built at.
            let mined = Self::shift(&intended, &miners[1], &miners[2]);
            assert_eq!(
                mined.iter().map(|p| p.sats).sum::<u64>(),
                intended.iter().map(|p| p.sats).sum::<u64>(),
                "the shift must keep the coinbase total — else the chain rejects it"
            );

            let (height, witness_coinbase) =
                Self::mine(&node, &tdp, &template, &prev_hash, &mined, fingerprint).await;
            let block_hash: String = node
                .rpc_call("getblockhash", serde_json::json!([height]))
                .await
                .expect("getblockhash")
                .as_str()
                .expect("hash string")
                .to_string();
            let block_hex: String = node
                .rpc_call("getblock", serde_json::json!([block_hash, 0]))
                .await
                .expect("getblock")
                .as_str()
                .expect("hex string")
                .to_string();
            let coinbase_tx =
                bitcoin::Transaction::consensus_decode(&mut witness_coinbase.as_slice())
                    .expect("submitted coinbase must decode");
            let actual =
                bp_coinbase_snapshot::ActualCoinbase::from_coinbase(&coinbase_tx, Network::Regtest);
            assert_eq!(actual.total_value_sats, reward_sats);

            Some(Self {
                node,
                tdp,
                pplns,
                group_solo,
                gate,
                pg,
                redis,
                miners,
                fee_addr,
                fingerprint,
                intended,
                height,
                block_hash,
                block_hex,
                coinbase_tx,
                actual,
            })
        }

        fn shift(from: &[PayoutEntry], minus: &str, plus: &str) -> Vec<PayoutEntry> {
            from.iter()
                .map(|p| PayoutEntry {
                    address: p.address.clone(),
                    sats: if p.address == *minus {
                        assert!(
                            p.sats > SHIFT_SATS,
                            "the shift must not drive an output under the dust floor"
                        );
                        p.sats - SHIFT_SATS
                    } else if p.address == *plus {
                        p.sats + SHIFT_SATS
                    } else {
                        p.sats
                    },
                })
                .collect()
        }

        async fn mine(
            node: &RegtestNode,
            tdp: &TdpHandle,
            template: &NewTemplate,
            prev_hash: &bp_template_distribution::SetNewPrevHash,
            payouts: &[PayoutEntry],
            fingerprint: [u8; 32],
        ) -> (u32, Vec<u8>) {
            let job = build_mining_job_from_tdp(
                Network::Regtest,
                payouts,
                &coinbase_template_from(template),
                "jdp-booking-regtest",
                EXTRANONCE_SLOT_LEN,
                fingerprint,
            )
            .expect("build_mining_job_from_tdp");
            let (en1, en2) = ([0u8; 4], [0u8; 8]);
            let merkle_root = merkle_root_from_coinbase(
                &job.coinbase_txid_with_extranonce(&en1, &en2),
                &template.merkle_path,
            );
            let nonce = brute_force_nonce(
                template.version,
                &prev_hash.prev_hash,
                &merkle_root,
                prev_hash.header_timestamp,
                prev_hash.n_bits,
                &Target::from_le_bytes(prev_hash.target),
            )
            .expect("regtest-target nonce within 1M tries");
            let witness_coinbase = job.witness_coinbase_with_extranonce(&en1, &en2);
            let before = node.current_height().await.expect("current_height");
            tdp.submit_solution(
                template.template_id,
                template.version,
                prev_hash.header_timestamp,
                nonce,
                witness_coinbase.clone(),
            )
            .await
            .expect("submit_solution");
            let height = poll_for_height(node, before + 1, Duration::from_secs(20))
                .await
                .expect("bitcoin-core must accept the block");
            (height, witness_coinbase)
        }

        fn sink(&self) -> TdpBlockSubmissionSink {
            TdpBlockSubmissionSink::new(self.tdp.clone())
                .with_network(Network::Regtest)
                .with_fanout(
                    self.gate.clone(),
                    Some(self.pplns.clone()),
                    self.group_solo.clone(),
                    None,
                    self.node.bitcoin_rpc().expect("regtest BitcoinRpc"),
                )
                .with_pool(self.pg.clone())
                .with_redis(self.redis.clone())
        }

        /// Book through the JDP door. `actual = None` models a block whose
        /// coinbase could not be parsed.
        async fn book(
            &self,
            actual: Option<bp_coinbase_snapshot::ActualCoinbase>,
            block_hash: &str,
        ) -> bool {
            self.sink()
                .book_declared_block_found(
                    self.miners[0].clone(),
                    "a1b2c3d4".to_string(), // blocks_entity."sessionId" is varchar(8)
                    self.actual.total_value_sats,
                    block_hash.to_string(),
                    self.block_hex.clone(),
                    self.fingerprint,
                    actual,
                )
                .await
        }

        async fn reconcile_once(&self) {
            let mut last_unbookable = None;
            super::reconcile(
                &self.node.bitcoin_rpc().expect("regtest BitcoinRpc"),
                &self.redis,
                Some(&self.pplns),
                Some(&self.group_solo),
                DEPTH,
                None,
                &mut last_unbookable,
            )
            .await;
        }

        /// Scoped to THIS test's miners, not just the height. All four tests
        /// start their own regtest chain, so they all find their block at the
        /// same height — a height-only query reads a sibling's leftovers after a
        /// panic, and the sibling's rows are not ours to purge. Cost me three
        /// phantom failures before I looked.
        async fn coinbase_rows(&self) -> Vec<(String, i64)> {
            sqlx::query_as(
                r#"SELECT address, "paidSats" FROM pplns_payout_history
                   WHERE "blockHeight" = $1 AND "rowType" = 'coinbase'
                     AND address = ANY($2)
                   ORDER BY address"#,
            )
            .bind(self.height as i32)
            .bind(&self.miners[..])
            .fetch_all(&self.pg)
            .await
            .expect("read audit rows")
        }

        fn amount_of(&self, rows: &[(String, i64)], miner: &str) -> u64 {
            rows.iter()
                .find(|(a, _)| a == miner)
                .map(|(_, s)| *s as u64)
                .unwrap_or_else(|| panic!("no booked row for {miner} — {rows:?}"))
        }

        fn intended_of(&self, miner: &str) -> u64 {
            self.intended
                .iter()
                .find(|p| p.address == *miner)
                .map(|p| p.sats)
                .expect("miner in the distribution")
        }

        async fn unbookable_count(&self) -> u64 {
            let mut conn = self.redis.clone();
            crate::pending_blocks::count_pending_at(
                &mut conn,
                crate::pending_blocks::UNBOOKABLE_KEY,
            )
            .await
            .unwrap_or(0)
        }

        async fn purge(pg: &sqlx::PgPool, miners: &[String; 3], fee_addr: &str) {
            for m in miners.iter().chain(std::iter::once(&fee_addr.to_string())) {
                let _ = sqlx::query(r#"DELETE FROM pplns_payout_history WHERE address = $1"#)
                    .bind(m)
                    .execute(pg)
                    .await;
                let _ = sqlx::query("DELETE FROM pplns_balance WHERE address = $1")
                    .bind(m)
                    .execute(pg)
                    .await;
                // `blocks_entity` too, and this one is not cosmetic: `/api/pool`
                // renders the found-block log inline and `bp-api`'s smoke test
                // caps the body at 1024 bytes, so leaking a row per run grows
                // that list until an UNRELATED test fails. It did, after eight
                // runs.
                let _ = sqlx::query(r#"DELETE FROM blocks_entity WHERE "minerAddress" = $1"#)
                    .bind(m)
                    .execute(pg)
                    .await;
            }
        }

        async fn teardown(self) {
            Self::purge(&self.pg, &self.miners, &self.fee_addr).await;
            self.pplns.shutdown();
            self.tdp.shutdown().expect("TDP clean shutdown");
            self.node.shutdown().await.expect("regtest clean shutdown");
        }
    }

    /// The chain's own coinbase decides the booking — not the list the pool
    /// intended to pay. Mutation-checked: booking from `intended` instead of the
    /// mined coinbase flips both amounts and fails with the exact 1000-sat delta.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_declared_block_books_exactly_what_its_coinbase_paid() {
        let Some(c) = Chain::setup(DB_BOOKS_THE_COINBASE).await else {
            return;
        };

        assert!(
            c.book(Some(c.actual.clone()), &c.block_hash).await,
            "book_declared_block_found must report the booking reached the \
             fan-out — a false means the JD-client's retry is the only \
             remaining chance to book this block"
        );

        // Gated, not immediate: with Redis wired the block is PARKED and the
        // ledger stays empty until it is confirmation-deep. An earlier draft
        // asserted rows here and failed, which the log had said all along.
        assert!(
            c.coinbase_rows().await.is_empty(),
            "with Redis wired the apply MUST wait for confirmations"
        );

        c.node
            .generate_to_self(DEPTH)
            .await
            .expect("bury to confirmation depth");
        c.reconcile_once().await;

        let rows = c.coinbase_rows().await;
        // Exactly the three seeded miners. The pool output is paid on-chain but
        // books no audit row, so 3 (not 4) is the correct shape — pinning it
        // stops a silently-empty or doubled booking sliding through the loop.
        assert_eq!(
            rows.len(),
            3,
            "one coinbase row per seeded miner, got {rows:?}"
        );

        // THE claim: miner[1] was paid SHIFT_SATS LESS on-chain than intended,
        // miner[2] that much more. The booked rows must say so.
        assert_eq!(
            c.amount_of(&rows, &c.miners[1]),
            c.intended_of(&c.miners[1]) - SHIFT_SATS,
            "must book what the COINBASE paid, not what the distribution intended"
        );
        assert_eq!(
            c.amount_of(&rows, &c.miners[2]),
            c.intended_of(&c.miners[2]) + SHIFT_SATS,
            "must book what the COINBASE paid, not what the distribution intended"
        );

        for (address, paid_sats) in &rows {
            assert!(*paid_sats > 0, "a 0-sat row proves no payout: {address}");
            let script = bp_mining_job::address_to_script(Network::Regtest, address)
                .expect("audit-row address must be payable");
            assert!(
                c.coinbase_tx.output.iter().any(|o| {
                    o.script_pubkey.as_bytes() == script.as_bytes()
                        && o.value.to_sat() == *paid_sats as u64
                }),
                "ledger claims {address} was paid {paid_sats} sat, but the accepted \
                 coinbase has no such output"
            );
        }

        c.teardown().await;
    }

    /// A re-parked block must not be booked twice. The confirmation watcher
    /// produces exactly this: its post-apply `remove_pending_block` error is
    /// deliberately ignored, so a failure there leaves the block parked and the
    /// next tick applies it again. The balance write is ABSOLUTE, so a second
    /// apply doubles a credit — measured once at 2999 → 5998 sat.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_second_apply_of_the_same_block_books_nothing_more() {
        let Some(c) = Chain::setup(DB_NO_DOUBLE_BOOK).await else {
            return;
        };
        c.book(Some(c.actual.clone()), &c.block_hash).await;
        c.node
            .generate_to_self(DEPTH)
            .await
            .expect("bury to confirmation depth");
        c.reconcile_once().await;
        let first = c.coinbase_rows().await;
        assert_eq!(first.len(), 3, "precondition: the first apply booked");
        let balances_before: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT address, "balanceSats" FROM pplns_balance
               WHERE address = ANY($1) ORDER BY address"#,
        )
        .bind(&c.miners[..])
        .fetch_all(&c.pg)
        .await
        .expect("read balances");

        // Re-park the identical block and run the watcher again.
        c.book(Some(c.actual.clone()), &c.block_hash).await;
        c.reconcile_once().await;

        assert_eq!(
            c.coinbase_rows().await,
            first,
            "a replay must leave the audit rows byte-identical"
        );
        let balances_after: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT address, "balanceSats" FROM pplns_balance
               WHERE address = ANY($1) ORDER BY address"#,
        )
        .bind(&c.miners[..])
        .fetch_all(&c.pg)
        .await
        .expect("read balances");
        assert_eq!(
            balances_after, balances_before,
            "the balance write is absolute — a replay must not move it"
        );

        c.teardown().await;
    }

    /// A block whose coinbase could not be parsed must be REFUSED, never booked
    /// from the list the pool intended to pay. This is the case that makes the
    /// byte-for-byte assertion in the first test load-bearing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_block_without_a_parsed_coinbase_is_refused_not_booked_from_intent() {
        let Some(c) = Chain::setup(DB_REFUSES_WITHOUT_COINBASE).await else {
            return;
        };
        c.book(None, &c.block_hash).await;
        c.node
            .generate_to_self(DEPTH)
            .await
            .expect("bury to confirmation depth");
        c.reconcile_once().await;

        let rows = c.coinbase_rows().await;
        assert!(
            rows.is_empty(),
            "without its own coinbase the block must not book at all — got {rows:?}, \
             which means the intended distribution was booked instead"
        );
        c.teardown().await;
    }

    /// Two different blocks at one height: `pplns_payout_history` has no
    /// `blockHash` column, so height is the only identity a booked block has.
    /// A DIFFERENT block there must be a terminal error that parks, never a
    /// silent success that lets the watcher drop it as handled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_different_block_at_a_booked_height_is_terminal_not_silent() {
        let Some(c) = Chain::setup(DB_HEIGHT_CONFLICT).await else {
            return;
        };
        c.book(Some(c.actual.clone()), &c.block_hash).await;
        c.node
            .generate_to_self(DEPTH)
            .await
            .expect("bury to confirmation depth");
        c.reconcile_once().await;
        let booked = c.coinbase_rows().await;
        assert_eq!(booked.len(), 3, "precondition: the first block booked");
        let unbookable_before = c.unbookable_count().await;

        // Same height, DIFFERENT payments. The hash cannot be fabricated —
        // `reconcile` asks the node via `classify_block`, so an unknown hash
        // would be dropped as orphaned and the test would pass for the wrong
        // reason. Model the other block the way the gate actually sees one: it
        // has no `blockHash` column to compare, it compares the value-bearing
        // ROWS. So re-park the same hash carrying a coinbase that pays
        // differently — here the shift reversed, i.e. what the pool intended.
        let mut other_tx = c.coinbase_tx.clone();
        let script_of =
            |m: &str| bp_mining_job::address_to_script(Network::Regtest, m).expect("payable");
        let (s1, s2) = (script_of(&c.miners[1]), script_of(&c.miners[2]));
        for o in other_tx.output.iter_mut() {
            if o.script_pubkey.as_bytes() == s1.as_bytes() {
                o.value = bitcoin::Amount::from_sat(o.value.to_sat() + SHIFT_SATS);
            } else if o.script_pubkey.as_bytes() == s2.as_bytes() {
                o.value = bitcoin::Amount::from_sat(o.value.to_sat() - SHIFT_SATS);
            }
        }
        let other_actual =
            bp_coinbase_snapshot::ActualCoinbase::from_coinbase(&other_tx, Network::Regtest);
        assert_eq!(
            other_actual.total_value_sats, c.actual.total_value_sats,
            "the competing coinbase must pay the same TOTAL — only the split differs"
        );
        assert_ne!(
            other_actual.paid_by_address, c.actual.paid_by_address,
            "precondition: the two coinbases must actually disagree"
        );

        c.book(Some(other_actual), &c.block_hash).await;
        c.reconcile_once().await;

        assert_eq!(
            c.coinbase_rows().await,
            booked,
            "the already-booked rows must survive untouched — overwriting them \
             would pay the second split on top of the first"
        );
        assert!(
            c.unbookable_count().await > unbookable_before,
            "the conflict must PARK as unbookable, not report success — a silent \
             Ok lets the watcher drop a block whose miners were paid on-chain"
        );

        c.teardown().await;
    }
}
