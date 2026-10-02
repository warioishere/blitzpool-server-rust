// SPDX-License-Identifier: AGPL-3.0-or-later

//! Confirmation watcher: applies a block parked in [`crate::pending_blocks`]
//! (every booking mode) once it is `confirmation_depth` deep and discards an
//! orphan, so no mode books a block the chain dropped.

use std::time::Duration;

use bp_bitcoin::{BitcoinRpc, RpcError};
use bp_blockparty_engine::BlockpartyPayouts;
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
    count_pending_at, load_pending_blocks, park_unbookable_block, remove_pending_block,
    PendingBlock, SettlementMode, PENDING_KEY, UNBOOKABLE_KEY,
};

/// Fallback re-check cadence; bounds the latency when the TDP stream stalls.
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

/// Spawn the confirmation watcher for whichever engines are present. A TDP
/// `SetNewPrevHash` wakes it on a new tip; without a feed (Satellite) the
/// fallback timer alone drives it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn(
    tdp: Option<TdpHandle>,
    bitcoin_rpc: BitcoinRpc,
    redis: ConnectionManager,
    pplns: Option<PplnsEngine>,
    group_solo: Option<GroupSoloEngine>,
    blockparty: Option<BlockpartyPayouts>,
    confirmation_depth: u32,
    // ext 0x0003/Implementation Notes settlement: a gated apply IS a
    // settlement, so the published distributions must be invalidated with it
    // or a JDC keeps mining pre-settlement weights. The watcher runs on the
    // `payout` role and the registry on `front`, hence a signal, not a handle.
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
            blockparty = blockparty.is_some(),
            "block-confirmation: watcher started"
        );
        let settlers = Settlers {
            pplns: pplns.as_ref(),
            group_solo: group_solo.as_ref(),
            blockparty: blockparty.as_ref(),
        };

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = tick.tick() => {
                    reconcile(&bitcoin_rpc, &redis, &settlers, confirmation_depth, settle.as_ref(), &mut last_unbookable).await;
                }
                ev = next_tip_signal(&mut rx) => match ev {
                    // A new chain tip — re-check every parked block's depth.
                    Ok(TemplateUpdate::SetNewPrevHash(_)) => {
                        reconcile(&bitcoin_rpc, &redis, &settlers, confirmation_depth, settle.as_ref(), &mut last_unbookable).await;
                    }
                    // NewTemplate / tx-data responses aren't new-block ticks.
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => continue,
                    // Sender gone: keep running on the fallback timer, since
                    // parked blocks must still reconcile.
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

/// Classify a parked block by its header. Shared by every mode.
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

/// Load every entry in the pending store, prune unparsable ones, discard
/// orphaned ones, and return the CONFIRMED entries. They stay in the store
/// until the caller applies them, so a failed apply is retried next tick.
async fn collect_confirmed(
    bitcoin_rpc: &BitcoinRpc,
    conn: &mut ConnectionManager,
    depth: i64,
) -> Vec<PendingBlock> {
    let (pending, unparsable) = match load_pending_blocks(conn).await {
        Ok(v) => v,
        Err(err) => {
            warn!(%err, "block-confirmation: load pending failed; retry next tick");
            return Vec::new();
        }
    };
    for hash in unparsable {
        warn!(block_hash = %hash, "block-confirmation: pruning unparsable pending entry");
        let _ = remove_pending_block(conn, &hash).await;
    }

    let mut confirmed = Vec::new();
    for pb in pending {
        match classify_block(bitcoin_rpc, &pb.block_hash, depth).await {
            BlockStatus::Confirmed => confirmed.push(pb),
            BlockStatus::Orphaned => {
                warn!(
                    block_hash = %pb.block_hash,
                    height = pb.block_height,
                    "block-confirmation: block orphaned / not on active chain — discarding frozen \
                     distribution (no on-chain payment occurred)"
                );
                let _ = remove_pending_block(conn, &pb.block_hash).await;
            }
            BlockStatus::Maturing => {}
            BlockStatus::Unknown => warn!(
                block_hash = %pb.block_hash,
                "block-confirmation: getblockheader failed; will retry next tick"
            ),
        }
    }
    confirmed
}

/// Publish how deep the two parking stores are, and log when the unbookable
/// one CHANGES: a standing non-zero count logged every pass gets ignored.
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

/// One reconciliation pass over the pending store, one loop for every mode:
/// the parked blob carries the settlement inputs either way, and `group`
/// decides which engine settles them.
async fn reconcile(
    bitcoin_rpc: &BitcoinRpc,
    redis: &ConnectionManager,
    settlers: &Settlers<'_>,
    confirmation_depth: u32,
    // See `spawn`: a gated apply IS a settlement event.
    settle: Option<&crate::settlement::SettlementSignal>,
    last_unbookable: &mut Option<u64>,
) {
    let depth = i64::from(confirmation_depth);
    let mut conn = redis.clone();
    let confirmed = collect_confirmed(bitcoin_rpc, &mut conn, depth).await;

    for pb in confirmed {
        // Settlement is `claim − paid` against the block's OWN coinbase;
        // without its payments there is nothing to settle against.
        let Some(actual) = pb.actual_coinbase.clone() else {
            // Park, don't destroy: the blob is the only record of this block.
            let parked = park_unbookable_block(&mut conn, &pb).await.is_ok();
            error!(
                block_hash = %pb.block_hash,
                height = pb.block_height,
                parked,
                unbookable_key = UNBOOKABLE_KEY,
                "block-confirmation: parked block carries no parsed coinbase — moved to the \
                 unbookable store; reprocess it from the block's own coinbase"
            );
            if parked {
                let _ = remove_pending_block(&mut conn, &pb.block_hash).await;
            }
            continue;
        };

        let applied = settle_block(settlers, &pb, &actual).await;

        match applied {
            Ok(history_inserted) => {
                if let Some(signal) = settle {
                    signal.settle().await;
                }
                info!(
                    block_hash = %pb.block_hash,
                    height = pb.block_height,
                    group = pb.group.as_ref().map(|g| g.group_id.as_str()).unwrap_or("-"),
                    history_inserted,
                    "block-confirmation: confirmed → payout history applied"
                );
                let _ = remove_pending_block(&mut conn, &pb.block_hash).await;
            }
            // No engine for this block's mode here; another process may own it.
            Err(SettleFailure::NoEngine) => continue,
            Err(err) if err.is_terminal() => {
                // Park, don't destroy: the frozen blob is the only record
                // of what this block paid every miner.
                let parked = park_unbookable_block(&mut conn, &pb).await.is_ok();
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

/// The engines a process can settle with; `None` where this process does not
/// book that mode.
pub(crate) struct Settlers<'a> {
    pub(crate) pplns: Option<&'a PplnsEngine>,
    pub(crate) group_solo: Option<&'a GroupSoloEngine>,
    pub(crate) blockparty: Option<&'a BlockpartyPayouts>,
}

/// Book one parked block into its mode's engine. Both the watcher and the
/// immediate apply ([`crate::block_sink`]) run this one settlement. Returns
/// the engine's `history_inserted`; handling a failure is the caller's call,
/// since only the watcher has a parked entry to leave in place.
pub(crate) async fn settle_block(
    settlers: &Settlers<'_>,
    pb: &PendingBlock,
    actual: &bp_coinbase_snapshot::ActualCoinbase,
) -> Result<u64, SettleFailure> {
    let height = pb.block_height;
    match pb.mode() {
        SettlementMode::GroupSolo(group) => {
            let engine = settlers.group_solo.ok_or(SettleFailure::NoEngine)?;
            let Ok(group_uuid) = uuid::Uuid::parse_str(&group.group_id) else {
                return Err(SettleFailure::UnusableGroup);
            };
            // Books from the coinbase alone; the snapshot inputs are PPLNS's.
            engine
                .on_block_found(group_uuid, height, actual)
                .await
                .map(|o| o.history_inserted)
                .map_err(|e| SettleFailure::Engine(SettleError::GroupSolo(e)))
        }
        SettlementMode::Blockparty(group) => {
            let payouts = settlers.blockparty.ok_or(SettleFailure::NoEngine)?;
            let Ok(group_uuid) = uuid::Uuid::parse_str(&group.group_id) else {
                return Err(SettleFailure::UnusableGroup);
            };
            // The split is recomputed from the roster, which cannot change
            // while the party is routable, so it is the one the coinbase paid.
            let reward = bp_common::Sats(actual.total_value_sats as i64);
            let blockparty_err = |e| SettleFailure::Engine(SettleError::Blockparty(e));
            let dist = payouts
                .build_payouts(group_uuid, reward)
                .await
                .map_err(blockparty_err)?
                .ok_or(SettleFailure::UnusableGroup)?;
            payouts
                .on_block_found(
                    group_uuid,
                    height,
                    &pb.block_hash,
                    reward,
                    dist.pool_fee_sats,
                    &dist.splits,
                    Some(pb.found_at_ms),
                )
                .await
                .map(|row| u64::from(row.is_some()))
                .map_err(blockparty_err)
        }
        SettlementMode::Pplns => settlers
            .pplns
            .ok_or(SettleFailure::NoEngine)?
            .on_block_found(
                height,
                actual,
                pb.weight_snapshot.clone(),
                pb.payouts_fingerprint,
            )
            .await
            .map(|o| o.history_inserted)
            .map_err(|e| SettleFailure::Engine(SettleError::Pplns(e))),
    }
}

/// Why [`settle_block`] booked nothing.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SettleFailure {
    /// This process has no engine for the block's mode.
    #[error("no engine wired for this block's mode")]
    NoEngine,
    /// A group-mode block whose group id does not parse, or a Blockparty
    /// whose group no longer exists.
    #[error("unusable group id")]
    UnusableGroup,
    #[error(transparent)]
    Engine(SettleError),
}

impl SettleFailure {
    /// Will a retry fail the same way? An unparsable group id stays
    /// unparsable, so it is terminal like the engines' own verdicts. A
    /// missing engine is not: another process may own the block.
    pub(crate) fn is_terminal(&self) -> bool {
        match self {
            SettleFailure::NoEngine => false,
            SettleFailure::UnusableGroup => true,
            SettleFailure::Engine(e) => e.is_terminal(),
        }
    }
}

/// The engines' errors, so one loop can treat them alike.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SettleError {
    #[error(transparent)]
    Pplns(bp_pplns_engine::engine::EngineError),
    #[error(transparent)]
    GroupSolo(bp_group_solo_engine::engine::EngineError),
    #[error(transparent)]
    Blockparty(bp_blockparty_engine::BlockpartyServiceError),
}

impl SettleError {
    fn is_terminal(&self) -> bool {
        match self {
            SettleError::Pplns(e) => e.is_terminal(),
            SettleError::GroupSolo(e) => e.is_terminal(),
            // The payout half only reads and inserts rows: a database error,
            // which the next tick may not repeat.
            SettleError::Blockparty(_) => false,
        }
    }
}

// ── Regtest: a declared block books what its coinbase actually paid ──
// The JDP sink, the engines and the watcher only meet in this binary, so
// `book_declared_block_found`, `emit_block_found` and `reconcile` are driven
// together here, on the production park-then-confirm path.
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
    const DB_GROUP_BOOKS_THE_COINBASE: u8 = 21;
    const DB_GROUP_NO_OVERWRITE: u8 = 22;
    const DB_GROUP_REFUSES_WITHOUT_COINBASE: u8 = 23;
    const DB_UNUSABLE_GROUP: u8 = 30;
    const DB_NO_PARSED_COINBASE: u8 = 31;
    const DB_LOST_SUBMIT: u8 = 0;

    /// The production default of `[pplns] confirmation_depth`.
    const DEPTH: u32 = 3;
    /// Sats moved between two miners so the mined coinbase DIVERGES from what
    /// the distribution intended; without a divergence, comparing the ledger
    /// against the coinbase could not tell the two sources apart.
    const SHIFT_SATS: u64 = 1_000;

    fn engine_config(fee_addr: &str) -> PplnsEngineConfig {
        PplnsEngineConfig {
            dust_sweep_enabled: false,
            touch_flush_interval_secs: 3_600,
            fee_address: Some(AddressId::new(fee_addr.to_string()).expect("fee addr")),
            fee_percent: 1.5,
            min_payout_sats: Sats(DEFAULT_MIN_PAYOUT_SATS as i64),
            // Regtest halves every 150 blocks. At the mainnet default the
            // engine expects 50 BTC past height 150 where regtest pays 25, and
            // its "coinbase pays less than the subsidy" guard refuses to book.
            subsidy_halving_interval: bp_share::REGTEST_SUBSIDY_HALVING_INTERVAL,
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
                // Keep in step with `GroupChain::setup` below: the skip
                // reason comes from `unavailable_reason()`, since a node can
                // be unavailable for several reasons besides a missing file.
                eprintln!(
                    "skipping declared-block booking regtest — {}",
                    regtest_cfg.unavailable_reason()
                );
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

            // A panicked run leaves rows behind at the same height the next run
            // reaches. Clear by ADDRESS so nothing outside this test is touched.
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

            // The sink is not constructible without a Group-Solo engine, even
            // for a PPLNS block: it is the dispatch target for the other mode.
            let group_solo = bp_group_solo_engine::engine::GroupSoloEngine::spawn(
                bp_group_solo_engine::config::GroupSoloEngineConfig {
                    fee_address: Some(AddressId::new(fee_addr.clone()).expect("fee addr")),
                    // Regtest halves every 150 blocks — see `engine_config`.
                    subsidy_halving_interval: bp_share::REGTEST_SUBSIDY_HALVING_INTERVAL,
                    ..Default::default()
                }
                .try_new()
                .expect("group-solo config"),
                redis.clone(),
                pg.clone(),
            )
            .await
            .expect("GroupSoloEngine::spawn");

            // The gate decides which engine books; its default for an unknown
            // address is SOLO, which books nothing.
            let gate = Arc::new(crate::engines::BlitzpoolModeGate::new());
            gate.set_mode(&miners[0], bp_mining_mode::MiningModeResult::Pplns);

            let node = RegtestNode::start_with(regtest_cfg)
                .await
                .expect("regtest start");
            // Each test needs its own HEIGHT: the ledger keys payout history by
            // height alone, so two tests booking the same height in this shared
            // PG fail each other with `HeightBookedByAnotherBlock`. Spread them
            // 10 apart; DB 0 gets a slot none of the others uses.
            let slot = match redis_db {
                DB_LOST_SUBMIT => 16,
                n => n - DB_BOOKS_THE_COINBASE,
            };
            let spread = u32::from(slot) * 10;
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

            // Precondition: an address `bitcoin::Address` cannot parse is
            // DROPPED, leaving an empty distribution whose miners surface as
            // 0-sat rows, and every assertion downstream would hold vacuously.
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
            TdpBlockSubmissionSink::new(
                self.tdp.clone(),
                self.gate.clone(),
                self.node.bitcoin_rpc().expect("regtest BitcoinRpc"),
                self.pg.clone(),
            )
            .with_network(Network::Regtest)
            .with_fanout(Some(self.pplns.clone()), self.group_solo.clone(), None)
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
                    crate::block_sink::FoundBlockRecord {
                        miner_address: self.miners[0].clone(),
                        // blocks_entity."sessionId" is varchar(8)
                        session_id: "a1b2c3d4".to_string(),
                        block_hash: block_hash.to_string(),
                        block_data: self.block_hex.clone(),
                    },
                    self.actual.total_value_sats,
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
                &super::Settlers {
                    pplns: Some(&self.pplns),
                    group_solo: Some(&self.group_solo),
                    blockparty: None,
                },
                DEPTH,
                None,
                &mut last_unbookable,
            )
            .await;
        }

        /// Scoped to THIS test's miners, not just the height: a height-only
        /// query can read a sibling test's leftovers after a panic.
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
                // `blocks_entity` too: `/api/pool` renders the found-block log
                // inline and `bp-api`'s smoke test caps the body at 1024 bytes,
                // so a leaked row per run eventually fails an unrelated test.
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

    /// The chain's own coinbase decides the booking, not the list the pool
    /// intended to pay; booking from `intended` fails with the SHIFT_SATS delta.
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
        // ledger stays empty until it is confirmation-deep.
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
        // Exactly the three seeded miners: the pool output is paid on-chain but
        // books no audit row. Pinning 3 catches an empty or doubled booking.
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

    /// A re-parked block must not be booked twice. The watcher ignores a
    /// post-apply `remove_pending_block` error, so a failure there leaves the
    /// block parked for the next tick; the balance write is ABSOLUTE, so a
    /// second apply would double a credit.
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
    /// from the list the pool intended to pay.
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

        // Same height, DIFFERENT payments. The hash cannot be fabricated,
        // since `classify_block` would drop an unknown hash as orphaned. The
        // gate compares value-bearing ROWS, not hashes, so re-park the same
        // hash with a coinbase that pays differently (the shift reversed).
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

    /// A parked Group-Solo block whose group id does not parse can be booked
    /// by nothing, but its blob is the only record of what the coinbase paid,
    /// so it moves to the unbookable store instead of being deleted. Only the
    /// unbookable count tells a park from a discard.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_group_block_with_an_unusable_group_id_parks_as_unbookable() {
        let Some(c) = Chain::setup(DB_UNUSABLE_GROUP).await else {
            return;
        };
        c.node
            .generate_to_self(DEPTH)
            .await
            .expect("bury to confirmation depth");
        let mut conn = c.redis.clone();
        crate::pending_blocks::put_pending_block(
            &mut conn,
            &crate::pending_blocks::PendingBlock {
                block_hash: c.block_hash.clone(),
                found_at_ms: 0,
                block_height: c.height as i32,
                weight_snapshot: None,
                actual_coinbase: Some(c.actual.clone()),
                payouts_fingerprint: Some(c.fingerprint),
                group: Some(crate::pending_blocks::PendingGroup {
                    group_id: "not-a-uuid".to_string(),
                    kind: crate::pending_blocks::GroupKind::GroupSolo,
                }),
            },
        )
        .await
        .expect("park the block");
        let unbookable_before = c.unbookable_count().await;

        c.reconcile_once().await;

        let still_pending =
            crate::pending_blocks::count_pending_at(&mut conn, crate::pending_blocks::PENDING_KEY)
                .await
                .expect("count pending");
        assert_eq!(
            still_pending, 0,
            "precondition: the watcher must have confirmed and handled the block"
        );
        assert!(
            c.unbookable_count().await > unbookable_before,
            "a block nothing can book must PARK as unbookable — deleting it throws \
             away the only record of what its coinbase paid"
        );

        c.teardown().await;
    }

    /// A parked block without a parsed coinbase can be settled by nothing
    /// either. Same rule as the unusable group id above: it moves to the
    /// unbookable store instead of being deleted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_block_without_a_parsed_coinbase_parks_as_unbookable() {
        let Some(c) = Chain::setup(DB_NO_PARSED_COINBASE).await else {
            return;
        };
        c.node
            .generate_to_self(DEPTH)
            .await
            .expect("bury to confirmation depth");
        let mut conn = c.redis.clone();
        crate::pending_blocks::put_pending_block(
            &mut conn,
            &crate::pending_blocks::PendingBlock {
                block_hash: c.block_hash.clone(),
                found_at_ms: 0,
                block_height: c.height as i32,
                weight_snapshot: None,
                actual_coinbase: None,
                payouts_fingerprint: Some(c.fingerprint),
                group: None,
            },
        )
        .await
        .expect("park the block");
        let unbookable_before = c.unbookable_count().await;

        c.reconcile_once().await;

        let still_pending =
            crate::pending_blocks::count_pending_at(&mut conn, crate::pending_blocks::PENDING_KEY)
                .await
                .expect("count pending");
        assert_eq!(
            still_pending, 0,
            "precondition: the watcher must have confirmed and handled the block"
        );
        assert!(
            c.unbookable_count().await > unbookable_before,
            "a block without a parsed coinbase must PARK as unbookable, not be discarded"
        );

        c.teardown().await;
    }

    /// A solution that never reached bitcoin-core (TDP worker gone) is not a
    /// found block: no park, no row, no push. Negative control first: with the
    /// worker alive the same call parks the block.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_solution_that_never_reached_core_is_not_reported_found() {
        let Some(c) = Chain::setup(DB_LOST_SUBMIT).await else {
            return;
        };
        let block_bytes = hex::decode(&c.block_hex).expect("block hex");
        let header: [u8; 80] = block_bytes[..80].try_into().expect("80-byte header");
        let coinbase_tx = bitcoin::consensus::serialize(&c.coinbase_tx);
        let submit = |sink: TdpBlockSubmissionSink| {
            let coinbase_tx = coinbase_tx.clone();
            let miner = c.miners[0].clone();
            let fingerprint = c.fingerprint;
            async move {
                sink.submit_and_emit(
                    crate::block_sink::PoolBuiltSolution {
                        protocol: "SV1",
                        template_id: 0,
                        header: &header,
                        coinbase_tx,
                        reward_sats: 5_000_000_000,
                        payouts_fingerprint: fingerprint,
                    },
                    &miner,
                    "rig1",
                    "a1b2c3d4",
                    bp_common::StreamKind::Pplns,
                )
                .await;
            }
        };
        let mut conn = c.redis.clone();
        let pending = |mut conn: redis::aio::ConnectionManager| async move {
            crate::pending_blocks::count_pending_at(&mut conn, crate::pending_blocks::PENDING_KEY)
                .await
                .expect("count pending")
        };

        let before = pending(conn.clone()).await;
        submit(c.sink()).await;
        let after_live = pending(conn.clone()).await;
        assert_eq!(
            after_live,
            before + 1,
            "precondition: with the TDP worker alive the block is parked for booking"
        );
        let _ = crate::pending_blocks::remove_pending_block(&mut conn, &c.block_hash).await;

        c.tdp.shutdown().expect("stop the TDP worker");
        submit(c.sink()).await;
        assert_eq!(
            pending(conn.clone()).await,
            before,
            "a solution that never reached bitcoin-core must not be reported as found"
        );

        // `teardown` would stop the TDP worker a second time.
        Chain::purge(&c.pg, &c.miners, &c.fee_addr).await;
        c.pplns.shutdown();
        c.node.shutdown().await.expect("regtest clean shutdown");
    }

    // ── Group-Solo: the same door, a different ledger ────────────────
    // Same `book_declared_block_found`, own fixture: it needs a group in PG, a
    // `group_solo` gate answer, and it writes `pplns_group_block_history` with
    // no ledger and no balances.

    /// A real regtest chain with an accepted block whose coinbase pays a real
    /// Group-Solo distribution — everything up to, but not including, the
    /// booking.
    struct GroupChain {
        node: RegtestNode,
        tdp: TdpHandle,
        pplns: PplnsEngine,
        group_solo: bp_group_solo_engine::engine::GroupSoloEngine,
        gate: Arc<crate::engines::BlitzpoolModeGate>,
        pg: sqlx::PgPool,
        redis: redis::aio::ConnectionManager,
        group_id: uuid::Uuid,
        /// `[0]` is the finder — the address the block is booked under.
        members: [String; 3],
        fee_addr: String,
        fingerprint: [u8; 32],
        intended: Vec<PayoutEntry>,
        height: u32,
        block_hash: String,
        block_hex: String,
        coinbase_tx: bitcoin::Transaction,
        actual: bp_coinbase_snapshot::ActualCoinbase,
    }

    impl GroupChain {
        /// `None` ⇒ the caller must return (bitcoin-node / Redis / PG missing).
        async fn setup(redis_db: u8) -> Option<Self> {
            let _ = tracing_subscriber::fmt()
                .with_env_filter("blitzpool=debug,bp_group_solo_engine=debug")
                .with_test_writer()
                .try_init();
            let regtest_cfg = RegtestConfig::default();
            if !regtest_cfg.is_available() {
                eprintln!(
                    "skipping declared-block booking regtest — {}",
                    regtest_cfg.unavailable_reason()
                );
                return None;
            }
            let redis = connect_redis_in_range_or_skip(redis_db::BLITZPOOL_BIN, redis_db).await?;
            let pg = connect_pg_or_skip().await?;

            let tag = 0x50 + redis_db;
            let members = [
                bp_test_support::deterministic_p2wpkh_regtest([tag; 32]),
                bp_test_support::deterministic_p2wpkh_regtest([tag.wrapping_add(0x40); 32]),
                bp_test_support::deterministic_p2wpkh_regtest([tag.wrapping_add(0x80); 32]),
            ];
            let fee_addr =
                bp_test_support::deterministic_p2wpkh_regtest([tag.wrapping_add(0xC0); 32]);
            let group_id = uuid::Uuid::from_u128(
                0x6720_0000_0000_0000_0000_0000_0000_0000u128 + u128::from(redis_db),
            );

            Self::purge(&pg, group_id, &members).await;

            // `pplns_group_member.address` is UNIQUE across the whole table, so
            // the purge above must run before the seed.
            sqlx::query(
                r#"INSERT INTO pplns_group
                     (id, name, "creatorAddress", "adminTokenHash", active,
                      "createdAt", "updatedAt", "isPublic", "finderBonusPpm",
                      "resetRoundOnBlock")
                   VALUES ($1, $2, $3, $4, true, 0, 0, false, NULL, true)"#,
            )
            .bind(group_id)
            .bind(format!("jdp-booking-grp-{group_id}"))
            .bind(&members[0])
            .bind(format!("hash-{group_id}"))
            .execute(&pg)
            .await
            .expect("seed group");
            for m in &members {
                sqlx::query(
                    r#"INSERT INTO pplns_group_member ("groupId", address, role)
                       VALUES ($1, $2, 'member')"#,
                )
                .bind(group_id)
                .bind(m)
                .execute(&pg)
                .await
                .expect("seed group member");
            }

            // Wired but unused by this block: the fan-out takes both engines,
            // and the sink is not constructible without the PPLNS one.
            let pplns = PplnsEngine::spawn(
                engine_config(&fee_addr),
                redis.clone(),
                pg.clone(),
                NetworkDifficulty::new(1_000.0),
            )
            .await
            .expect("PplnsEngine::spawn");
            let group_solo = bp_group_solo_engine::engine::GroupSoloEngine::spawn(
                bp_group_solo_engine::config::GroupSoloEngineConfig {
                    fee_address: Some(AddressId::new(fee_addr.clone()).expect("fee addr")),
                    // Regtest halves every 150 blocks — see `engine_config`.
                    subsidy_halving_interval: bp_share::REGTEST_SUBSIDY_HALVING_INTERVAL,
                    ..Default::default()
                }
                .try_new()
                .expect("group-solo config"),
                redis.clone(),
                pg.clone(),
            )
            .await
            .expect("GroupSoloEngine::spawn");

            // ⚠️ Membership alone earns NOTHING. Group-Solo splits by shares in
            // the round, so a group seeded with members but no shares produces a
            // two-entry distribution (the pool output and one address holding
            // the entire subsidy), and the assertions below would test nothing.
            let now_ms = chrono::Utc::now().timestamp_millis();
            for (addr, difficulty) in [
                (&members[0], 100.0),
                (&members[1], 200.0),
                (&members[2], 300.0),
            ] {
                group_solo
                    .record_share(None, group_id, addr, difficulty, now_ms)
                    .await
                    .expect("seed group share");
            }

            // Without this the gate answers Solo, which books nothing.
            let gate = Arc::new(crate::engines::BlitzpoolModeGate::new());
            gate.set_mode(
                &members[0],
                bp_mining_mode::MiningModeResult::GroupSolo(group_id),
            );

            let node = RegtestNode::start_with(regtest_cfg)
                .await
                .expect("regtest start");
            // Same height-spreading rule as the PPLNS fixture, and against the
            // same shared PG — the group history is keyed
            // (groupId, blockHeight, address), so a collision here would be a
            // silent DO NOTHING instead of a failure.
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
            let finder = AddressId::new(members[0].clone()).expect("finder addr");
            let dist = group_solo
                .build_distribution(group_id, reward_sats, &finder)
                .await
                .expect("group-solo build_distribution");
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

            // Same precondition as the PPLNS fixture: an unparsable address is
            // DROPPED from the distribution.
            assert!(
                intended.len() >= 4,
                "expected the three seeded members plus the pool output, got {intended:?}"
            );
            for m in &members {
                assert!(
                    intended.iter().any(|p| p.address == *m && p.sats > 0),
                    "member {m} must hold a non-zero payout — otherwise this test \
                     books an empty distribution and asserts nothing"
                );
            }

            let mined = Chain::shift(&intended, &members[1], &members[2]);
            assert_eq!(
                mined.iter().map(|p| p.sats).sum::<u64>(),
                intended.iter().map(|p| p.sats).sum::<u64>(),
                "the shift must keep the coinbase total — else the chain rejects it"
            );

            let (height, witness_coinbase) =
                Chain::mine(&node, &tdp, &template, &prev_hash, &mined, fingerprint).await;
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
                group_id,
                members,
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

        fn sink(&self) -> TdpBlockSubmissionSink {
            TdpBlockSubmissionSink::new(
                self.tdp.clone(),
                self.gate.clone(),
                self.node.bitcoin_rpc().expect("regtest BitcoinRpc"),
                self.pg.clone(),
            )
            .with_network(Network::Regtest)
            .with_fanout(Some(self.pplns.clone()), self.group_solo.clone(), None)
            .with_redis(self.redis.clone())
        }

        async fn book(
            &self,
            actual: Option<bp_coinbase_snapshot::ActualCoinbase>,
            block_hash: &str,
        ) -> bool {
            self.book_paying(actual, block_hash, self.fingerprint).await
        }

        /// [`Self::book`] under a chosen payout fingerprint.
        async fn book_paying(
            &self,
            actual: Option<bp_coinbase_snapshot::ActualCoinbase>,
            block_hash: &str,
            fingerprint: [u8; 32],
        ) -> bool {
            self.sink()
                .book_declared_block_found(
                    crate::block_sink::FoundBlockRecord {
                        miner_address: self.members[0].clone(),
                        // blocks_entity."sessionId" is varchar(8)
                        session_id: "b1c2d3e4".to_string(),
                        block_hash: block_hash.to_string(),
                        block_data: self.block_hex.clone(),
                    },
                    self.actual.total_value_sats,
                    fingerprint,
                    actual,
                )
                .await
        }

        async fn reconcile_once(&self) {
            let mut last_unbookable = None;
            super::reconcile(
                &self.node.bitcoin_rpc().expect("regtest BitcoinRpc"),
                &self.redis,
                &super::Settlers {
                    pplns: Some(&self.pplns),
                    group_solo: Some(&self.group_solo),
                    blockparty: None,
                },
                DEPTH,
                None,
                &mut last_unbookable,
            )
            .await;
        }

        /// Scoped to THIS group, for the same reason the PPLNS reader is scoped
        /// to its miners: every test starts its own chain at the same height.
        async fn history_rows(&self) -> Vec<(String, i64)> {
            sqlx::query_as(
                r#"SELECT address, "paidSats" FROM pplns_group_block_history
                   WHERE "groupId" = $1 AND "blockHeight" = $2 AND "rowType" = 'coinbase'
                   ORDER BY address"#,
            )
            .bind(self.group_id)
            .bind(self.height as i32)
            .fetch_all(&self.pg)
            .await
            .expect("read group history rows")
        }

        fn amount_of(&self, rows: &[(String, i64)], member: &str) -> u64 {
            rows.iter()
                .find(|(a, _)| a == member)
                .map(|(_, s)| *s as u64)
                .unwrap_or_else(|| panic!("no history row for {member} in {rows:?}"))
        }

        fn intended_of(&self, member: &str) -> u64 {
            self.intended
                .iter()
                .find(|p| p.address == *member)
                .map(|p| p.sats)
                .expect("member in the distribution")
        }

        /// Group-Solo keeps NO ledger; asserted in every Group-Solo test.
        async fn assert_no_ledger_rows(&self) {
            for m in &self.members {
                let balances: i64 =
                    sqlx::query_scalar("SELECT count(*) FROM pplns_balance WHERE address = $1")
                        .bind(m)
                        .fetch_one(&self.pg)
                        .await
                        .expect("count balances");
                assert_eq!(
                    balances, 0,
                    "Group-Solo must write no PPLNS balance row ({m})"
                );
            }
        }

        async fn purge(pg: &sqlx::PgPool, group_id: uuid::Uuid, members: &[String; 3]) {
            // ON DELETE CASCADE takes the member and history rows with it.
            let _ = sqlx::query("DELETE FROM pplns_group WHERE id = $1")
                .bind(group_id)
                .execute(pg)
                .await;
            for m in members {
                // A membership left behind by a panicked run would collide with
                // the UNIQUE on `address` at seed time.
                let _ = sqlx::query("DELETE FROM pplns_group_member WHERE address = $1")
                    .bind(m)
                    .execute(pg)
                    .await;
                let _ = sqlx::query(r#"DELETE FROM blocks_entity WHERE "minerAddress" = $1"#)
                    .bind(m)
                    .execute(pg)
                    .await;
            }
        }

        async fn teardown(self) {
            Self::purge(&self.pg, self.group_id, &self.members).await;
            self.pplns.shutdown();
            self.group_solo.shutdown();
            self.tdp.shutdown().expect("TDP clean shutdown");
            self.node.shutdown().await.expect("regtest clean shutdown");
        }
    }

    /// The chain's own coinbase decides the Group-Solo booking too — not the
    /// list the pool intended to pay. Only a coinbase the pool built is booked:
    /// the same block under a zeroed fingerprint parks nothing and leaves the
    /// round standing, then books once the real fingerprint arrives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_declared_group_block_books_exactly_what_its_coinbase_paid() {
        let Some(c) = GroupChain::setup(DB_GROUP_BOOKS_THE_COINBASE).await else {
            return;
        };

        let round_before = c
            .group_solo
            .reader()
            .round_stats(c.group_id)
            .await
            .expect("round stats")
            .total_shares;
        assert!(
            round_before > 0.0,
            "precondition: the seeded round holds shares"
        );
        assert!(
            c.book_paying(Some(c.actual.clone()), &c.block_hash, [0u8; 32])
                .await
        );
        let mut conn = c.redis.clone();
        assert_eq!(
            crate::pending_blocks::count_pending_at(&mut conn, crate::pending_blocks::PENDING_KEY)
                .await
                .expect("pending count"),
            0,
            "a coinbase the pool did not build must not be parked for booking"
        );
        c.reconcile_once().await;
        assert!(c.history_rows().await.is_empty(), "nothing booked");
        let round_after = c
            .group_solo
            .reader()
            .round_stats(c.group_id)
            .await
            .expect("round stats")
            .total_shares;
        assert_eq!(
            round_after, round_before,
            "the round must not be reset for a block nobody booked"
        );

        assert!(
            c.book(Some(c.actual.clone()), &c.block_hash).await,
            "book_declared_block_found must report the booking reached the fan-out"
        );
        assert!(
            c.history_rows().await.is_empty(),
            "with Redis wired the apply MUST wait for confirmations"
        );

        c.node
            .generate_to_self(DEPTH)
            .await
            .expect("bury to confirmation depth");
        c.reconcile_once().await;

        let rows = c.history_rows().await;
        assert_eq!(
            rows.len(),
            3,
            "one coinbase row per seeded member, got {rows:?}"
        );
        // THE claim: member[1] was paid SHIFT_SATS LESS on-chain than intended,
        // member[2] that much more. The booked rows must say so.
        assert_eq!(
            c.amount_of(&rows, &c.members[1]),
            c.intended_of(&c.members[1]) - SHIFT_SATS,
            "must book what the COINBASE paid, not what the distribution intended"
        );
        assert_eq!(
            c.amount_of(&rows, &c.members[2]),
            c.intended_of(&c.members[2]) + SHIFT_SATS,
            "must book what the COINBASE paid, not what the distribution intended"
        );
        for (address, paid_sats) in &rows {
            assert!(*paid_sats > 0, "a 0-sat row proves no payout: {address}");
            let script = bp_mining_job::address_to_script(Network::Regtest, address)
                .expect("history-row address must be payable");
            assert!(
                c.coinbase_tx.output.iter().any(|o| {
                    o.script_pubkey.as_bytes() == script.as_bytes()
                        && o.value.to_sat() == *paid_sats as u64
                }),
                "every booked row must correspond to a real coinbase output: {address}"
            );
        }

        // The pool's own output is paid ON-CHAIN but books no history row,
        // which is why 3 is the right count. Asserted from both sides.
        let fee_script = bp_mining_job::address_to_script(Network::Regtest, &c.fee_addr)
            .expect("fee address must be payable");
        assert!(
            c.coinbase_tx
                .output
                .iter()
                .any(|o| o.script_pubkey.as_bytes() == fee_script.as_bytes()),
            "the coinbase must actually pay the pool output"
        );
        assert!(
            !rows.iter().any(|(a, _)| *a == c.fee_addr),
            "the pool output must book no member history row"
        );
        c.assert_no_ledger_rows().await;

        c.teardown().await;
    }

    /// Replay safety: a second apply never adds, removes or moves a booked row.
    /// Pins the outcome, not the mechanism, with a different coinbase so an
    /// overwrite would be visible.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_second_apply_of_the_same_group_block_cannot_overwrite_it() {
        let Some(c) = GroupChain::setup(DB_GROUP_NO_OVERWRITE).await else {
            return;
        };

        assert!(c.book(Some(c.actual.clone()), &c.block_hash).await);
        c.node
            .generate_to_self(DEPTH)
            .await
            .expect("bury to confirmation depth");
        c.reconcile_once().await;

        let first = c.history_rows().await;
        assert_eq!(first.len(), 3, "precondition: the first apply booked");

        // A second coinbase for the same block, shifted the OTHER way, so a
        // missing replay guard shows up as moved amounts, not just extra rows.
        let mut divergent = c.actual.clone();
        let m1 = c.members[1].clone();
        let m2 = c.members[2].clone();
        if let Some(v) = divergent.paid_by_address.get_mut(&m1) {
            *v += SHIFT_SATS;
        }
        if let Some(v) = divergent.paid_by_address.get_mut(&m2) {
            *v -= SHIFT_SATS;
        }
        assert_ne!(
            divergent.paid_by_address.get(&m1),
            c.actual.paid_by_address.get(&m1),
            "the replay must carry a genuinely different coinbase, or it proves nothing"
        );

        assert!(c.book(Some(divergent), &c.block_hash).await);
        c.reconcile_once().await;

        let second = c.history_rows().await;
        assert_eq!(
            second, first,
            "a replay must not add, remove or move a single booked row"
        );
        c.assert_no_ledger_rows().await;

        c.teardown().await;
    }

    /// Without a parsed coinbase there is nothing to settle against, and the
    /// booking must REFUSE rather than fall back to what the pool intended.
    /// Same rule as PPLNS, on the mode that keeps no ledger to correct it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_group_block_without_a_parsed_coinbase_is_refused_not_booked_from_intent() {
        let Some(c) = GroupChain::setup(DB_GROUP_REFUSES_WITHOUT_COINBASE).await else {
            return;
        };

        assert!(c.book(None, &c.block_hash).await);
        c.node
            .generate_to_self(DEPTH)
            .await
            .expect("bury to confirmation depth");
        c.reconcile_once().await;

        assert!(
            c.history_rows().await.is_empty(),
            "a block whose coinbase could not be parsed must book NOTHING — \
             booking from the intended distribution would pay out what the \
             chain never paid"
        );
        c.assert_no_ledger_rows().await;

        c.teardown().await;
    }
}

#[cfg(test)]
mod blockparty_settlement {
    use std::collections::HashMap;

    use bp_blockparty_engine::{BlockpartyPayoutConfig, BlockpartyPayouts};
    use bp_coinbase_snapshot::ActualCoinbase;
    use bp_common::{AddressId, Sats};

    use super::{settle_block, SettleFailure, Settlers};
    use crate::pending_blocks::{GroupKind, PendingBlock, PendingGroup};

    const REWARD: u64 = 312_500_000;
    const FOUND_AT_MS: i64 = 1_700_000_000_123;

    /// A parked Blockparty block settles through the shared watcher path: one
    /// history row with the roster's split, keyed and timestamped by the
    /// parked blob, and nothing more on replay. A process without the
    /// Blockparty payouts leaves it parked (negative control).
    #[tokio::test]
    async fn a_parked_blockparty_block_books_once_from_its_blob() {
        let Some(pg) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let admin = bp_test_support::deterministic_p2wpkh_regtest([0xB1; 32]);
        let member = bp_test_support::deterministic_p2wpkh_regtest([0xB2; 32]);
        let fee = bp_test_support::deterministic_p2wpkh_regtest([0xB3; 32]);
        bp_test_support::cleanup_blockparty_rows(&pg, &[&admin, &member]).await;

        let group_id = uuid::Uuid::new_v4();
        let admin_id = AddressId::new(admin.clone()).unwrap();
        bp_db::insert_blockparty_group(
            &pg,
            group_id,
            &format!("bp-settle-{group_id}"),
            &admin_id,
            "hash",
            "active",
            1,
        )
        .await
        .expect("insert group");
        for (addr, bp, role) in [(&admin, 6_000, "admin"), (&member, 4_000, "member")] {
            let id = AddressId::new(addr.clone()).unwrap();
            bp_db::insert_blockparty_member(&pg, group_id, &id, "", bp, role, Some(1), 1)
                .await
                .expect("insert member");
        }

        let payouts = BlockpartyPayouts::new(
            pg.clone(),
            BlockpartyPayoutConfig {
                fee_address: Some(AddressId::new(fee).unwrap()),
                fee_percent: 2.0,
                min_payout_sats: Sats(5_000),
            },
        );
        let actual = ActualCoinbase {
            paid_by_address: HashMap::new(),
            pool_paid_sats: 0,
            total_value_sats: REWARD,
        };
        let pb = PendingBlock {
            block_hash: format!("{:064x}", group_id.as_u128()),
            found_at_ms: FOUND_AT_MS,
            block_height: 900_000,
            weight_snapshot: None,
            actual_coinbase: Some(actual.clone()),
            payouts_fingerprint: None,
            group: Some(PendingGroup {
                group_id: group_id.to_string(),
                kind: GroupKind::Blockparty,
            }),
        };

        let without = Settlers {
            pplns: None,
            group_solo: None,
            blockparty: None,
        };
        let refused = settle_block(&without, &pb, &actual).await;
        assert!(
            matches!(refused, Err(SettleFailure::NoEngine)),
            "{refused:?}"
        );

        let with = Settlers {
            pplns: None,
            group_solo: None,
            blockparty: Some(&payouts),
        };
        assert_eq!(settle_block(&with, &pb, &actual).await.expect("settle"), 1);

        let rows = bp_db::list_blockparty_block_history(&pg, group_id)
            .await
            .expect("history");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.block_hash, pb.block_hash);
        assert_eq!(
            row.found_at, FOUND_AT_MS,
            "found_at comes from the parked blob"
        );
        assert_eq!(row.coinbase_value_sats, Sats(REWARD as i64));
        // 2 % base fee, then 60/40 of the miners' cut.
        let cut = REWARD as i64 - REWARD as i64 * 2 / 100;
        let paid: HashMap<&str, i64> = row
            .splits
            .0
            .iter()
            .map(|s| (s.address.as_str(), s.sats))
            .collect();
        assert_eq!(paid[admin.as_str()], cut * 6_000 / 10_000);
        assert_eq!(paid[member.as_str()], cut * 4_000 / 10_000);
        assert_eq!(
            row.pool_fee_sats.0 + paid.values().sum::<i64>(),
            REWARD as i64
        );

        assert_eq!(
            settle_block(&with, &pb, &actual).await.expect("replay"),
            0,
            "a replay must not insert a second row"
        );

        bp_test_support::cleanup_blockparty_rows(&pg, &[&admin, &member]).await;
    }
}
