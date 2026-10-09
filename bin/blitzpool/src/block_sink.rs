// SPDX-License-Identifier: AGPL-3.0-or-later

//! Block submission: [`TdpBlockSubmissionSink`] forwards a block-candidate
//! share to Core via TDP `SubmitSolution` and emits the block-found event.
//! SV1 and SV2 differ only in where the coinbase bytes come from; submit and
//! emission are one path, [`TdpBlockSubmissionSink::submit_and_emit`].

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bp_bitcoin::BitcoinRpc;
use bp_coinbase_snapshot::ActualCoinbase;
use bp_common::{AddressId, MiningMode, StreamKind};
use bp_config::{AppConfig, Role};
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_mining_mode::MiningModeResult;
use bp_notifications::dispatcher::NotificationDispatcher;
use bp_pplns_engine::engine::PplnsEngine;
use bp_share_stream::{StreamProducer, BLOCK_FOUND_STREAM_KEY};
use bp_stratum_v1::{BlockSubmissionSink as Sv1BlockSubmissionSink, ShareAccept as Sv1ShareAccept};
use bp_stratum_v2::hooks::BlockSubmissionSink as Sv2BlockSubmissionSink;
use bp_stratum_v2::mining::submit::ShareAccept as Sv2ShareAccept;
use bp_template_distribution::TdpHandle;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tracing::{error, info, warn};

use crate::block_confirmation::{settle_block, SettleFailure};
use crate::boot::FoundationHandles;
use crate::engines::{BlitzpoolModeGate, EngineHandles};
use crate::pending_blocks::{put_pending_block, PendingBlock, PendingSettlement};

/// The Core→Satellite block-found event: the front submits and records the
/// block, the payout Satellite applies the ledger from this. Producer and
/// consumer run the same version: a release that changes this format deploys
/// with the block-found stream fully acked.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct BlockFoundEvent {
    /// Miner-authorized payout address.
    pub address: String,
    pub worker: String,
    pub session_id: String,
    /// What the apply side does with the ledger.
    pub booking: Booking,
    /// Big-endian block-hash hex: the idempotent history-row key and the
    /// confirmation-gating key.
    pub block_hash: String,
    /// 80-byte header hex (LE), stored in `blocks_entity.blockData`.
    pub block_data: String,
    /// Resolved on the Core, the only side holding the mode gate.
    pub mode: MiningMode,
    /// Group for `GroupSolo` / `Blockparty`, else `None`.
    pub group_id: Option<uuid::Uuid>,
    /// Derived on the Core right after submit: the chain may have advanced by
    /// the time a Satellite consumes the event.
    pub height: i32,
    /// PPLNS settlement inputs of the winning job's distribution, resolved at
    /// the block-found instant: the Redis keys they come from are overwritten
    /// or expire before the apply side runs.
    pub weight_snapshot: Option<bp_pplns_engine::window::snapshot::StoredWeightSnapshot>,
    /// Identity of the payout list the winning job's coinbase pays, so what is
    /// booked is what the coinbase paid. `None` when the pool did not build the
    /// coinbase.
    pub payouts_fingerprint: Option<[u8; 32]>,
    /// What the found block's coinbase actually paid, decoded on the Core;
    /// settlement books `claim − paid` from it. `None` (undecodable, or
    /// [`Booking::RecordOnly`]) makes every mode book nothing.
    pub actual_coinbase: Option<ActualCoinbase>,
}

/// Whether a found block goes into its mode's ledger, or is only recorded
/// (`blocks_entity` row + notification).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Booking {
    /// `reward_sats` is what the coinbase claims. Settlement only logs it and
    /// books from the block's own coinbase.
    Book { reward_sats: u64 },
    /// For a block whose distribution was never bookable, or whose pool-built
    /// SV2 custom-job coinbase did not decode.
    RecordOnly,
}

/// What identifies a JDC-found block in `blocks_entity`. `session_id` lands in
/// `varchar(8)`, and Postgres errors instead of truncating.
#[derive(Clone, Debug)]
pub(crate) struct FoundBlockRecord {
    pub(crate) miner_address: String,
    pub(crate) session_id: String,
    /// Block hash, display form.
    pub(crate) block_hash: String,
    /// The 80-byte header as hex.
    pub(crate) block_data: String,
}

/// The caller-supplied half of [`BlockFoundEvent`]; the rest is resolved on
/// the Core by [`TdpBlockSubmissionSink::emit_block_found`]. Named fields keep
/// the same-typed strings visible at the call site.
struct BlockFoundInputs {
    /// Also what the mode gate is asked: a wrong value books the block
    /// against another mode, or Solo, which writes no ledger at all.
    address: String,
    worker: String,
    /// Lands in `varchar(8)`; Postgres errors instead of truncating.
    session_id: String,
    booking: Booking,
    /// Big-endian block-hash hex.
    block_hash: String,
    /// The 80-byte header as hex (LE), for `blocks_entity.blockData`.
    block_data: String,
    payouts_fingerprint: Option<[u8; 32]>,
    actual_coinbase: Option<ActualCoinbase>,
}

/// `BlockSubmissionSink` for SV1 and SV2: submits every block candidate to
/// Core via TDP and fans the block-found out to the per-mode ledger and the
/// [`NotificationDispatcher`]. The TDP submit is the authoritative path; a
/// missing engine or dispatcher only skips its step.
pub(crate) struct TdpBlockSubmissionSink {
    /// PPLNS stream handle, and the fallback when an alt stream isn't wired.
    tdp: TdpHandle,
    /// Solo / GroupSolo / Blockparty stream handles. A solution must go to
    /// the handle that issued its template_id.
    alt: HashMap<StreamKind, TdpHandle>,
    mode_gate: Arc<BlitzpoolModeGate>,
    bitcoin_rpc: BitcoinRpc,
    pool: PgPool,
    /// Runs the same apply in-process on the Core or on a Satellite.
    applier: BlockFoundApplier,
    /// Publishes block-found events for the Satellites; on a publish failure
    /// the front applies in-process. `None` without a front role.
    block_found_producer: Option<StreamProducer<BlockFoundEvent>>,
    /// For decoding the submitted coinbase into [`ActualCoinbase`].
    network: bitcoin::Network,
}

/// The relocatable half of block-found handling: per-mode ledger writes,
/// the PPLNS pending store and notifications. Reads only the Core-stamped
/// [`BlockFoundEvent`], so it runs identically on the Core and on a Satellite.
#[derive(Default, Clone)]
pub(crate) struct BlockFoundApplier {
    pplns: Option<PplnsEngine>,
    group_solo: Option<GroupSoloEngine>,
    blockparty: Option<bp_blockparty_engine::BlockpartyPayouts>,
    dispatcher: Option<Arc<NotificationDispatcher>>,
    /// Pending-block store: a block is parked here by hash and settled by the
    /// confirmation watcher at `confirmation_depth`.
    redis: Option<ConnectionManager>,
    /// ext 0x0003/Implementation Notes: any settlement invalidates every
    /// published distribution, whose weights encode pre-settlement balances a
    /// JDC would otherwise pay twice. See [`crate::settlement`].
    settle: Option<crate::settlement::SettlementSignal>,
}

impl TdpBlockSubmissionSink {
    pub(crate) fn new(
        tdp: TdpHandle,
        mode_gate: Arc<BlitzpoolModeGate>,
        bitcoin_rpc: BitcoinRpc,
        pool: PgPool,
    ) -> Self {
        Self {
            tdp,
            alt: HashMap::new(),
            mode_gate,
            bitcoin_rpc,
            pool,
            applier: BlockFoundApplier::default(),
            block_found_producer: None,
            network: bitcoin::Network::Bitcoin,
        }
    }

    /// The one way SV1, SV2 and the JDP booker build their sink, so a block
    /// books the same way whichever found it. A front always produces onto the
    /// block-found stream: front and payout never share a process.
    pub(crate) fn wired(
        tdp: TdpHandle,
        cfg: &AppConfig,
        foundation: &FoundationHandles,
        engines: &EngineHandles,
        dispatcher: Option<Arc<NotificationDispatcher>>,
        settle: crate::settlement::SettlementSignal,
    ) -> Self {
        let sink = Self::new(
            tdp,
            engines.mode_gate.clone(),
            foundation.bitcoin_rpc.clone(),
            foundation.db.pool().clone(),
        )
        .with_network(crate::boot::bitcoin_network(cfg.network))
        .with_alt_streams(foundation.alt_tdp.clone())
        .with_fanout(
            engines.pplns.clone(),
            engines.group_solo.clone(),
            dispatcher,
        )
        .with_blockparty(engines.blockparty_payouts.clone())
        .with_redis(foundation.redis.clone())
        .with_settle_handle(settle);
        if cfg.has_role(Role::Front) {
            sink.with_block_found_producer(StreamProducer::new(
                foundation.redis.clone(),
                BLOCK_FOUND_STREAM_KEY,
            ))
        } else {
            sink
        }
    }

    /// ext 0x0003/Implementation Notes: a Stratum-path block invalidates the
    /// published distributions exactly like a JDP-declared one.
    pub(crate) fn with_settle_handle(
        mut self,
        signal: crate::settlement::SettlementSignal,
    ) -> Self {
        self.applier.settle = Some(signal);
        self
    }

    pub(crate) fn with_network(mut self, network: bitcoin::Network) -> Self {
        self.network = network;
        self
    }

    pub(crate) fn with_block_found_producer(
        mut self,
        producer: StreamProducer<BlockFoundEvent>,
    ) -> Self {
        self.block_found_producer = Some(producer);
        self
    }

    pub(crate) fn with_redis(mut self, redis: ConnectionManager) -> Self {
        self.applier.redis = Some(redis);
        self
    }

    /// template_ids are per-connection and collide across streams, so a
    /// solution must go back through the handle its job came from.
    pub(crate) fn with_alt_streams(mut self, alt: HashMap<StreamKind, TdpHandle>) -> Self {
        self.alt = alt;
        self
    }

    /// A missing alt handle falls back to the default one loudly: the submit
    /// then fails on the template_id instead of landing an invalid block.
    fn select_handle(&self, stream: StreamKind) -> &TdpHandle {
        if stream.is_pplns() {
            return &self.tdp;
        }
        match self.alt.get(&stream) {
            Some(h) => h,
            None => {
                warn!(
                    stream = stream.as_label(),
                    "block-found: alt-stream job but no matching TDP handle wired; \
                     falling back to default handle (submit will likely fail)"
                );
                &self.tdp
            }
        }
    }

    pub(crate) fn with_blockparty(
        mut self,
        blockparty: Option<bp_blockparty_engine::BlockpartyPayouts>,
    ) -> Self {
        self.applier.blockparty = blockparty;
        self
    }

    pub(crate) fn with_fanout(
        mut self,
        pplns: Option<PplnsEngine>,
        group_solo: Option<GroupSoloEngine>,
        dispatcher: Option<Arc<NotificationDispatcher>>,
    ) -> Self {
        self.applier.pplns = pplns;
        self.applier.group_solo = group_solo;
        self.applier.dispatcher = dispatcher;
        self
    }

    /// Book a JDC-declared block: the declare-time check proved its coinbase
    /// carries the payout set `payouts_fingerprint` names, so the ledger books
    /// what the block actually paid, not a rebuilt guess.
    pub(crate) async fn book_declared_block_found(
        &self,
        record: FoundBlockRecord,
        reward_sats: u64,
        payouts_fingerprint: [u8; 32],
        actual_coinbase: Option<ActualCoinbase>,
    ) -> bool {
        self.emit_block_found(BlockFoundInputs {
            address: record.miner_address,
            worker: "jdp".to_string(),
            session_id: record.session_id,
            booking: Booking::Book { reward_sats },
            block_hash: record.block_hash,
            block_data: record.block_data,
            payouts_fingerprint: Some(payouts_fingerprint),
            actual_coinbase,
        })
        .await
    }

    /// Record a declared block without booking it, when its settlement snapshot
    /// did not land and nothing can compute `claim − paid`. The block still
    /// gets its history row and notification; nothing is settled from a guess.
    pub(crate) async fn record_declared_block_without_booking(
        &self,
        record: FoundBlockRecord,
    ) -> bool {
        self.emit_block_found(BlockFoundInputs {
            address: record.miner_address,
            worker: "jdp".to_string(),
            session_id: record.session_id,
            booking: Booking::RecordOnly,
            block_hash: record.block_hash,
            block_data: record.block_data,
            payouts_fingerprint: None,
            actual_coinbase: None,
        })
        .await
    }

    pub(crate) fn into_sv1_arc(self) -> Arc<dyn Sv1BlockSubmissionSink> {
        Arc::new(self)
    }

    pub(crate) fn into_sv2_arc(self) -> Arc<dyn Sv2BlockSubmissionSink> {
        Arc::new(self)
    }

    /// Parent height + 1, not `tip + 1`: `submit_solution` may already have
    /// connected the block, making the tip one too high. The tip is only the
    /// fallback, so a height hiccup never drops the block-found.
    async fn derive_block_height(&self, rpc: &BitcoinRpc, header_hex: &str) -> Option<i32> {
        if let Some(prev_hash) = prev_hash_display_from_header(header_hex) {
            match rpc.get_block_header(&prev_hash).await {
                Ok(h) => match h.height {
                    Some(parent_height) => return Some((parent_height + 1) as i32),
                    None => warn!(
                        prev_hash,
                        "block-found: parent header has no height; falling back to get_block_count"
                    ),
                },
                Err(err) => warn!(
                    %err, prev_hash,
                    "block-found: get_block_header(parent) failed; falling back to get_block_count"
                ),
            }
        }
        match rpc.get_block_count().await {
            Ok(tip) => Some(tip.saturating_add(1) as i32),
            Err(err) => {
                warn!(%err, "block-found: get_block_count fallback failed");
                None
            }
        }
    }

    /// Front-side block-found: resolves mode and height, writes `blocks_entity`
    /// and publishes the [`BlockFoundEvent`]. `false` means nothing at all was
    /// written, so a deduping caller must not mark the block handled; past the
    /// fan-out every step is PG-idempotent and a redelivery finishes the job.
    async fn emit_block_found(&self, found: BlockFoundInputs) -> bool {
        let BlockFoundInputs {
            address,
            worker,
            session_id,
            booking,
            block_hash,
            block_data,
            payouts_fingerprint,
            actual_coinbase,
        } = found;
        let resolved = self.mode_gate.lookup_mode(&address);

        let Some(height) = self
            .derive_block_height(&self.bitcoin_rpc, &block_data)
            .await
        else {
            warn!(
                address = %address,
                "block-found: could not derive block height — skipping fan-out"
            );
            return false;
        };

        // The Redis-independent record the ledger can be reconciled against.
        // Best-effort: a failure must not abort the apply below.
        if let Err(err) = bp_db::insert_found_block(
            &self.pool,
            height as i64,
            &address,
            &worker,
            &session_id,
            &block_data,
        )
        .await
        {
            warn!(%err, address = %address, height, "block-found: blocks_entity insert failed");
        }

        let weight_snapshot = self
            .resolve_weight_snapshot(resolved, &address, payouts_fingerprint, height)
            .await;

        let event = BlockFoundEvent {
            address,
            worker,
            session_id,
            payouts_fingerprint,
            booking,
            block_hash,
            block_data,
            mode: resolved.mode(),
            group_id: resolved.group_id(),
            height,
            weight_snapshot,
            actual_coinbase,
        };

        // On a publish failure apply in-process, so a Redis blip never drops
        // the ledger write; the apply is PG-idempotent.
        match self.block_found_producer.as_ref() {
            Some(producer) => match producer.publish(&event).await {
                Ok(id) => info!(
                    address = %event.address,
                    height = event.height,
                    entry_id = %id,
                    "block-found: published to stream for Satellite apply"
                ),
                Err(err) => {
                    warn!(
                        %err,
                        address = %event.address,
                        height = event.height,
                        "block-found: stream publish failed — applying in-process as fallback"
                    );
                    self.applier.apply_block_found(&event).await;
                }
            },
            None => self.applier.apply_block_found(&event).await,
        }
        true
    }

    /// Resolve PPLNS's settlement inputs at the block-found instant: the
    /// snapshot key is alive now, not at apply time, and is their only store.
    /// Every mode is decided by the exhaustive `match`. A coinbase the pool
    /// did not build has no snapshot; the apply side refuses to book it.
    async fn resolve_weight_snapshot(
        &self,
        mode: MiningModeResult,
        address: &str,
        payouts_fingerprint: Option<[u8; 32]>,
        height: i32,
    ) -> Option<bp_pplns_engine::window::snapshot::StoredWeightSnapshot> {
        match mode {
            // Solo writes no ledger, Blockparty recomputes its fixed shares
            // from the DB, Group-Solo books from the coinbase alone. None of
            // them has a snapshot to carry.
            MiningModeResult::Solo
            | MiningModeResult::Blockparty(_)
            | MiningModeResult::GroupSolo(_) => None,
            MiningModeResult::Pplns => {
                let engine = self.applier.pplns.as_ref().or_else(|| {
                    warn!(
                        address,
                        height, "block-found: PPLNS mode but the engine is not configured"
                    );
                    None
                })?;
                let fingerprint = pool_built(payouts_fingerprint)?;
                match engine.weight_snapshot_for_block_found(&fingerprint).await {
                    Ok(Some(snap)) => Some(snap),
                    Ok(None) => {
                        error!(
                            address,
                            height,
                            fingerprint = %hex::encode(fingerprint),
                            "block-found: no PPLNS snapshot under the winning job's \
                             fingerprint — the block will park as unbookable once confirmed"
                        );
                        None
                    }
                    Err(err) => {
                        error!(
                            %err,
                            address,
                            height,
                            fingerprint = %hex::encode(fingerprint),
                            "block-found: PPLNS snapshot read failed — the block will park as \
                             unbookable once confirmed"
                        );
                        None
                    }
                }
            }
        }
    }
}

/// The payout list a found block's coinbase pays, or `None` when the pool did
/// not build that coinbase: a zeroed fingerprint marks a `SetCustomMiningJob`,
/// which has no pool distribution behind it.
fn pool_built(fingerprint: Option<[u8; 32]>) -> Option<[u8; 32]> {
    fingerprint.filter(|fp| fp != &[0u8; 32])
}

impl BlockFoundApplier {
    /// `settle` is an argument, not a builder step, so no applier can book a
    /// block without invalidating the published distributions.
    pub(crate) fn new(
        pplns: Option<PplnsEngine>,
        group_solo: Option<GroupSoloEngine>,
        blockparty: Option<bp_blockparty_engine::BlockpartyPayouts>,
        dispatcher: Option<Arc<NotificationDispatcher>>,
        redis: Option<ConnectionManager>,
        settle: Option<crate::settlement::SettlementSignal>,
    ) -> Self {
        Self {
            pplns,
            group_solo,
            blockparty,
            dispatcher,
            redis,
            settle,
        }
    }

    /// ext 0x0003/Implementation Notes: after a settlement, force a fresh
    /// publish so no JDC keeps declaring against weights already settled.
    async fn settle_distributions(&self) {
        if let Some(signal) = self.settle.as_ref() {
            signal.settle().await;
        }
    }

    /// Park the settlement inputs until `confirmation_depth` so an orphan
    /// never books, else apply immediately. Parking inputs, not results, lets
    /// several blocks pend at once. Never substitute another
    /// `weight_snapshot`: that books what the chain didn't pay.
    #[allow(clippy::too_many_arguments)]
    async fn gate_or_apply(
        &self,
        address_str: &str,
        height: i32,
        reward: u64,
        block_hash: &str,
        actual: Option<&bp_coinbase_snapshot::ActualCoinbase>,
        payouts_fingerprint: Option<[u8; 32]>,
        settlement: PendingSettlement,
    ) {
        let mode = settlement.label();
        // Only a coinbase the pool built pays the mode's distribution; booking
        // any other would settle, or reset a round, for a block that did not
        // pay it.
        if settlement.needs_pool_distribution() && pool_built(payouts_fingerprint).is_none() {
            error!(
                address = address_str,
                height,
                mode,
                "block-found: block on a coinbase the pool did not build — NOT booked"
            );
            return;
        }
        // Settlement is `claim − paid` against the block's own coinbase.
        let Some(actual) = actual else {
            error!(
                address = address_str,
                height,
                mode,
                "block-found: event carries no parsed coinbase — NOT booked, reprocess from \
                 the block's own coinbase"
            );
            return;
        };
        let pending = PendingBlock {
            block_hash: block_hash.to_string(),
            found_at_ms: chrono::Utc::now().timestamp_millis(),
            block_height: height,
            actual_coinbase: actual.clone(),
            settlement,
        };

        match self.redis.as_ref() {
            Some(redis) => {
                let mut conn = redis.clone();
                match put_pending_block(&mut conn, &pending).await {
                    Ok(()) => {
                        info!(
                            address = address_str,
                            height,
                            block_hash,
                            mode,
                            "block-found: distribution frozen, awaiting confirmations before apply"
                        );
                        return;
                    }
                    Err(err) => warn!(
                        %err, address = address_str, height, mode,
                        "block-found: pending-store write failed; applying immediately as fallback"
                    ),
                }
            }
            None => warn!(
                address = address_str,
                height,
                mode,
                "block-found: confirmation-gating unavailable (no Redis); applying immediately"
            ),
        }

        self.apply_now(address_str, reward, &pending).await;
    }

    /// Fallback of [`Self::gate_or_apply`]; the same settlement the
    /// confirmation watcher runs, on the same blob it would have parked.
    async fn apply_now(&self, address_str: &str, reward: u64, pending: &PendingBlock) {
        let height = pending.block_height;
        let label = pending.settlement.label();
        let settlers = crate::block_confirmation::Settlers {
            pplns: self.pplns.as_ref(),
            group_solo: self.group_solo.as_ref(),
            blockparty: self.blockparty.as_ref(),
        };
        let applied = settle_block(&settlers, pending).await;
        match applied {
            Ok(history_inserted) => {
                self.settle_distributions().await;
                info!(
                    address = address_str,
                    height,
                    reward_sats = reward,
                    mode = label,
                    history_inserted,
                    "block-found: payout history applied (immediate)"
                );
            }
            Err(SettleFailure::NoEngine) => warn!(
                address = address_str,
                height,
                mode = label,
                "block-found: no engine wired for this block — NOT booked"
            ),
            Err(SettleFailure::UnusableGroup) => warn!(
                address = address_str,
                group_id = ?pending.settlement.group_id(),
                height,
                mode = label,
                "block-found: group gone — NOT booked"
            ),
            Err(SettleFailure::SnapshotMissing) => warn!(
                address = address_str,
                height,
                mode = label,
                "block-found: settlement inputs not resolved at found-time — NOT booked"
            ),
            Err(SettleFailure::Engine(err)) => warn!(
                %err, address = address_str, height,
                "block-found: immediate apply failed"
            ),
        }
    }

    /// Apply a block-found event to the per-mode ledger, then notify.
    /// [`Booking::RecordOnly`] skips only the ledger. Best-effort: a failed
    /// step is logged and the others continue.
    pub(crate) async fn apply_block_found(&self, event: &BlockFoundEvent) {
        let address_str = event.address.as_str();
        let block_hash = event.block_hash.as_str();
        let height = event.height;

        if let Err(err) = AddressId::new(address_str.to_string()) {
            warn!(
                %err,
                address = address_str,
                "block-found apply: invalid AddressId shape — skipping"
            );
            return;
        }

        match (event.mode, event.booking) {
            (MiningMode::Solo, _) => {
                info!(
                    address = address_str,
                    height,
                    "block-found: solo mode — no engine ledger-write needed (single-payout coinbase)"
                );
            }
            (_, Booking::RecordOnly) => {
                warn!(
                    address = address_str,
                    height,
                    mode = ?event.mode,
                    "block-found: recorded without booking — engine ledger-write skipped"
                );
            }
            (
                MiningMode::Pplns,
                Booking::Book {
                    reward_sats: reward,
                },
            ) => match self.pplns.as_ref() {
                Some(_) => {
                    self.gate_or_apply(
                        address_str,
                        height,
                        reward,
                        block_hash,
                        event.actual_coinbase.as_ref(),
                        event.payouts_fingerprint,
                        PendingSettlement::Pplns {
                            weight_snapshot: event.weight_snapshot.clone(),
                        },
                    )
                    .await
                }
                None => warn!(
                    address = address_str,
                    height, "block-found: PPLNS mode but engine not configured"
                ),
            },
            (
                MiningMode::Blockparty,
                Booking::Book {
                    reward_sats: reward,
                },
            ) => match (event.group_id, self.blockparty.as_ref()) {
                (Some(group_id), Some(_payouts)) => {
                    self.gate_or_apply(
                        address_str,
                        height,
                        reward,
                        block_hash,
                        event.actual_coinbase.as_ref(),
                        event.payouts_fingerprint,
                        PendingSettlement::Blockparty { group_id },
                    )
                    .await;
                }
                (None, _) => warn!(
                    address = address_str,
                    height, "block-found: Blockparty mode published WITHOUT a group_id — skipping"
                ),
                (Some(_), None) => warn!(
                    address = address_str,
                    height, "block-found: Blockparty mode but payouts not configured — skipping history-row write"
                ),
            },
            (
                MiningMode::GroupSolo,
                Booking::Book {
                    reward_sats: reward,
                },
            ) => {
                match (event.group_id, self.group_solo.as_ref()) {
                    (Some(group_id), Some(_engine)) => {
                        self.gate_or_apply(
                            address_str,
                            height,
                            reward,
                            block_hash,
                            event.actual_coinbase.as_ref(),
                            event.payouts_fingerprint,
                            PendingSettlement::GroupSolo { group_id },
                        )
                        .await;
                    }
                    (None, _) => warn!(
                        address = address_str,
                        height, "block-found: Group-Solo mode but mode-gate returned no group_id"
                    ),
                    (Some(_), None) => warn!(
                        address = address_str,
                        height, "block-found: Group-Solo mode but engine not configured"
                    ),
                }
            }
        }

        self.notify_block_found(event).await;
    }

    /// Notification only: the tail of [`Self::apply_block_found`] and the entry
    /// point of the `notify` Satellite. A no-op without a dispatcher.
    pub(crate) async fn notify_block_found(&self, event: &BlockFoundEvent) {
        let Some(dispatcher) = self.dispatcher.as_ref() else {
            return;
        };
        let address_str = event.address.as_str();
        let address = match AddressId::new(address_str.to_string()) {
            Ok(a) => a,
            Err(err) => {
                warn!(
                    %err,
                    address = address_str,
                    "block-found notify: invalid AddressId shape — skipping"
                );
                return;
            }
        };
        let height = event.height;
        let message = format!("Block {height} found");
        dispatcher
            .notify_block_found(&address, height as u64, &message)
            .await;
        info!(
            address = address_str,
            height, "block-found: notifications fanned out"
        );
    }
}

#[async_trait]
impl Sv1BlockSubmissionSink for TdpBlockSubmissionSink {
    async fn submit_block(
        &self,
        accept: &Sv1ShareAccept,
        address: &str,
        worker: &str,
        session_id: &str,
        stream: StreamKind,
    ) {
        let coinbase_tx = accept
            .mining_job
            .witness_coinbase_with_extranonce(&accept.enonce1, &accept.extranonce2);
        self.submit_and_emit(
            PoolBuiltSolution {
                protocol: "sv1",
                template_id: accept.template.template_id,
                header: &accept.header,
                coinbase_tx,
                reward_sats: accept.template.coinbase_tx_value_remaining,
                payouts_fingerprint: *accept.mining_job.payouts_fingerprint(),
            },
            address,
            worker,
            session_id,
            stream,
        )
        .await;
    }
}

/// A solution on a job whose coinbase the pool built.
pub(crate) struct PoolBuiltSolution<'a> {
    /// Log label only.
    pub(crate) protocol: &'static str,
    pub(crate) template_id: u64,
    pub(crate) header: &'a [u8; 80],
    /// Witness-form coinbase of the winning job.
    pub(crate) coinbase_tx: Vec<u8>,
    /// What the job's coinbase claims, pinned at job send time.
    pub(crate) reward_sats: u64,
    pub(crate) payouts_fingerprint: [u8; 32],
}

/// `(version, header_timestamp, header_nonce)` from an assembled header. The
/// version is read back because the miner may have rolled it.
fn header_fields(header: &[u8; 80]) -> (u32, u32, u32) {
    let version = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let header_timestamp = u32::from_le_bytes([header[68], header[69], header[70], header[71]]);
    let header_nonce = u32::from_le_bytes([header[76], header[77], header[78], header[79]]);
    (version, header_timestamp, header_nonce)
}

impl TdpBlockSubmissionSink {
    /// Submit a pool-built solution, then emit the block-found. The one path
    /// SV1 and SV2 share.
    pub(crate) async fn submit_and_emit(
        &self,
        solution: PoolBuiltSolution<'_>,
        address: &str,
        worker: &str,
        session_id: &str,
        stream: StreamKind,
    ) {
        let PoolBuiltSolution {
            protocol,
            template_id,
            header,
            coinbase_tx,
            reward_sats,
            payouts_fingerprint,
        } = solution;
        let (version, header_timestamp, header_nonce) = header_fields(header);
        // Decoded before the bytes move into the submit.
        let actual = decode_actual_coinbase(&coinbase_tx, self.network);

        info!(
            protocol,
            template_id,
            version,
            header_timestamp,
            header_nonce,
            address,
            worker,
            session_id,
            ?stream,
            coinbase_tx_len = coinbase_tx.len(),
            "block-found: submitting solution via TDP"
        );

        // A failed submit means the TDP worker is gone and the block never
        // reached Core: reporting it would park a booking that cannot confirm.
        if let Err(err) = self
            .select_handle(stream)
            .submit_solution(
                template_id,
                version,
                header_timestamp,
                header_nonce,
                coinbase_tx,
            )
            .await
        {
            error!(
                %err,
                protocol,
                template_id,
                address,
                worker,
                session_id,
                "block-found: TDP submit_solution failed — the block did NOT reach \
                 bitcoin-core and is lost; not reported as found"
            );
            return;
        }

        self.emit_block_found(BlockFoundInputs {
            address: address.to_string(),
            worker: worker.to_string(),
            session_id: session_id.to_string(),
            booking: Booking::Book { reward_sats },
            block_hash: block_hash_display(header),
            block_data: hex::encode(header),
            payouts_fingerprint: Some(payouts_fingerprint),
            actual_coinbase: actual,
        })
        .await;
    }
}

// ── SV2 block submission ─────────────────────────────────────────

#[async_trait]
impl Sv2BlockSubmissionSink for TdpBlockSubmissionSink {
    async fn submit_block(
        &self,
        accept: &Sv2ShareAccept,
        address: &str,
        worker: &str,
        session_id_hex: &str,
        stream: StreamKind,
    ) {
        // A `SetCustomMiningJob` job: the JDC propagates its own block, the
        // pool only records it. `jdp_claims_the_block` alone decides who
        // records: the insert has no `ON CONFLICT`, so a second, unbooked row
        // would suppress the booked one (SV2 JDP/Coinbase-only Mode never declares).
        if accept.witness_coinbase.is_empty() || accept.template_id.is_none() {
            if accept.jdp_claims_the_block {
                info!(
                    address,
                    worker,
                    session_id_hex,
                    "sv2 block-found on a declared, distribution-backed custom job \
                     — the JDP PushSolution path records and books it"
                );
                return;
            }
            // The pool reassembled this coinbase from its job and the miner's
            // extranonce, so it is the block's own coinbase; the reward comes
            // from it too, not from what the pool intended to pay.
            let actual = decode_actual_coinbase(&accept.witness_coinbase, self.network);
            let booking = match actual.as_ref() {
                Some(a) => Booking::Book {
                    reward_sats: a.total_value_sats,
                },
                None => Booking::RecordOnly,
            };
            // Zeroed unless ext 0x0003 published a distribution this coinbase
            // was proven to pay; only then is there anything to book against.
            let fingerprint = accept.payouts_fingerprint;
            warn!(
                address,
                worker,
                session_id_hex,
                submission_diff = accept.submission_difficulty.as_f64(),
                bookable = pool_built(Some(fingerprint)).is_some(),
                "sv2 block-found on a custom job the JDP path will not claim: the JDC \
                 propagates it through its own node, the pool records it here (no template_id \
                 to submit with)"
            );
            self.emit_block_found(BlockFoundInputs {
                address: address.to_string(),
                worker: worker.to_string(),
                session_id: session_id_hex.to_string(),
                booking,
                block_hash: block_hash_display(&accept.header),
                block_data: hex::encode(accept.header),
                payouts_fingerprint: Some(fingerprint),
                actual_coinbase: actual,
            })
            .await;
            return;
        }
        let template_id = accept.template_id.expect("checked is_some above");
        self.submit_and_emit(
            PoolBuiltSolution {
                protocol: "sv2",
                template_id,
                header: &accept.header,
                coinbase_tx: accept.witness_coinbase.clone(),
                reward_sats: accept.coinbase_tx_value_remaining,
                payouts_fingerprint: accept.payouts_fingerprint,
            },
            address,
            worker,
            session_id_hex,
            stream,
        )
        .await;
    }
}

/// Decode the submitted coinbase into its per-address payments. `None` unless
/// the bytes are exactly one transaction: a prefix would book the wrong outputs.
fn decode_actual_coinbase(
    witness_coinbase: &[u8],
    network: bitcoin::Network,
) -> Option<ActualCoinbase> {
    let Some(tx) = decode_whole_tx(witness_coinbase) else {
        warn!(
            len = witness_coinbase.len(),
            "block-found: submitted coinbase is not exactly one transaction — no actuals for \
             settlement"
        );
        return None;
    };
    Some(ActualCoinbase::from_coinbase(&tx, network))
}

/// Decode a transaction and require that it consumed every byte:
/// `consensus_decode` silently succeeds on a valid prefix of malformed input,
/// and anything booked from or put in a block must be the whole thing.
pub(crate) fn decode_whole_tx(bytes: &[u8]) -> Option<bitcoin::Transaction> {
    let mut cursor = bytes;
    let tx = <bitcoin::Transaction as bitcoin::consensus::Decodable>::consensus_decode(&mut cursor)
        .ok()?;
    if !cursor.is_empty() {
        warn!(
            total = bytes.len(),
            consumed = bytes.len() - cursor.len(),
            "transaction decoded from a PREFIX only — treating as malformed"
        );
        return None;
    }
    Some(tx)
}

/// Big-endian display hash of an assembled header.
fn block_hash_display(header: &[u8; 80]) -> String {
    let mut hash = bp_share::sha256d(header);
    hash.reverse();
    hex::encode(hash)
}

/// Big-endian display hash of the parent block, the form `getblockheader`
/// expects, from a header hex.
fn prev_hash_display_from_header(header_hex: &str) -> Option<String> {
    let bytes = hex::decode(header_hex).ok()?;
    if bytes.len() < 36 {
        return None;
    }
    let mut prev = bytes[4..36].to_vec();
    prev.reverse();
    Some(hex::encode(prev))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bp_mining_job::{build_mining_job, CoinbaseTemplate, PayoutEntry, EXTRANONCE_SLOT_LEN};

    /// Pins ext 0x0003/Implementation Notes: a Stratum-path settlement leaves
    /// no published distribution current.
    #[tokio::test(flavor = "current_thread")]
    async fn immediate_apply_settles_the_published_distributions() {
        use bp_stratum_v2::bridge::{JdpDeclaredJobRegistry, PayoutDistributionEntry};
        use bp_stratum_v2::jdp::payout_distribution::WeightedOutput;
        use bp_stratum_v2::jdp_server::{JdpServerHooks, StratumV2JdpServer};
        use bp_stratum_v2::noise::NoiseConfig;

        let bridge = std::sync::Arc::new(std::sync::RwLock::new(JdpDeclaredJobRegistry::new()));
        bridge
            .write()
            .unwrap()
            .publish_pool_wide(PayoutDistributionEntry {
                distribution_id: 1,
                built: bp_stratum_v2::bridge::BuiltPayoutDistribution {
                    pool_payout: WeightedOutput {
                        script_pubkey: vec![0x51],
                        weight: 1,
                    },
                    payouts: vec![WeightedOutput {
                        script_pubkey: vec![0x00, 0x14, 0xAA],
                        weight: 100,
                    }],
                    dust_limits: vec![546],
                    additional_outputs: vec![],
                    reference_reward_sats: 312_500_000,
                    payouts_fingerprint: Some([1u8; 32]),
                    bookable: true,
                },
                accounting: bp_stratum_v2::bridge::DistributionAccounting::PoolWide,
                jdp_session_id: None,
                published_at_ms: 1_001,
            });
        assert!(
            bridge.read().unwrap().current_pool_wide().is_some(),
            "precondition: a distribution is published and current"
        );

        let noise = NoiseConfig::new(
            "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
                .parse()
                .unwrap(),
            "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
                .parse()
                .unwrap(),
        );
        let server = StratumV2JdpServer::spawn(
            noise,
            JdpServerHooks::no_op(),
            bridge.clone(),
            std::time::Duration::from_secs(3600),
        );

        let signal = crate::settlement::SettlementSignal::local_only();
        let _ = signal.registry_slot().set(server.distribution_handle());

        let applier = BlockFoundApplier {
            settle: Some(signal),
            ..Default::default()
        };
        applier.settle_distributions().await;

        assert!(
            bridge.read().unwrap().current_pool_wide().is_none(),
            "a settled block must leave no distribution current — a JDC still \
             mining it would pay the pre-settlement balances a second time"
        );
        server.shutdown().await;
    }

    /// Pins that trailing bytes make the coinbase undecodable while the clean
    /// coinbase still decodes.
    #[test]
    fn a_coinbase_with_trailing_bytes_books_nothing() {
        let miner = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let job = build_mining_job(
            Network::Regtest,
            &[PayoutEntry {
                address: miner.to_string(),
                sats: 5_000_000_000,
            }],
            &CoinbaseTemplate {
                block_height: 42,
                coinbase_value_sats: 5_000_000_000,
                witness_commitment: [0x77; 32],
            },
            "BP",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
        )
        .expect("build job");
        let mut witness = job.witness_coinbase_with_extranonce(&[0xAA; 4], &[0xBB; 8]);

        let actual = decode_actual_coinbase(&witness, Network::Regtest)
            .expect("the coinbase a job really builds must decode");
        assert_eq!(
            actual.total_value_sats, 5_000_000_000,
            "precondition: the clean bytes carry the whole payout"
        );

        witness.extend_from_slice(&[0xAB; 8]);
        assert!(
            decode_actual_coinbase(&witness, Network::Regtest).is_none(),
            "trailing bytes mean this is not the coinbase the block paid"
        );
    }

    /// Pins that settling without a JDP server is a no-op, not a panic.
    #[tokio::test(flavor = "current_thread")]
    async fn settling_without_a_jdp_server_is_a_no_op() {
        let applier = BlockFoundApplier::default();
        assert!(applier.settle.is_none());
        applier.settle_distributions().await;
    }

    /// Pins the reversal of `prevHash` into display order.
    #[test]
    fn prev_hash_extracted_and_reversed_to_display_order() {
        let display = "000000000033366a407ca4b736a310d343c20c494532970aa11e45b9140df5e6";
        let mut internal = hex::decode(display).unwrap();
        internal.reverse();
        let mut header = vec![0x20u8, 0x00, 0x80, 0x30];
        header.extend_from_slice(&internal);
        header.extend_from_slice(&[0u8; 44]);
        assert_eq!(
            prev_hash_display_from_header(&hex::encode(&header)).as_deref(),
            Some(display)
        );
    }

    #[test]
    fn prev_hash_rejects_short_or_malformed_header() {
        assert!(prev_hash_display_from_header("abcd").is_none());
        assert!(prev_hash_display_from_header("nothex!!").is_none());
        assert!(prev_hash_display_from_header("").is_none());
    }

    /// Pins the header offsets; distinct values so a shifted slice cannot
    /// read back right by accident.
    #[test]
    fn header_fields_reads_version_time_and_nonce_at_their_offsets() {
        let mut header = [0u8; 80];
        header[0..4].copy_from_slice(&0x2000_0004u32.to_le_bytes());
        header[68..72].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        header[72..76].copy_from_slice(&0x1d00_ffffu32.to_le_bytes());
        header[76..80].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        assert_eq!(
            header_fields(&header),
            (0x2000_0004, 0x1234_5678, 0xdead_beef)
        );
    }

    /// Pins that both `Booking` forms round-trip through the event.
    #[test]
    fn booking_round_trips_through_the_event() {
        for booking in [
            Booking::Book {
                reward_sats: 312_500_000,
            },
            Booking::RecordOnly,
        ] {
            let event = BlockFoundEvent {
                booking,
                ..record_only_event()
            };
            let json = serde_json::to_string(&event).expect("serialize");
            let back: BlockFoundEvent = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back.booking, booking);
        }
    }

    fn record_only_event() -> BlockFoundEvent {
        BlockFoundEvent {
            address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            worker: "jdp".to_string(),
            session_id: "sess1".to_string(),
            booking: Booking::RecordOnly,
            block_hash: "00000000deadbeef".to_string(),
            block_data: "ab".repeat(80),
            mode: MiningMode::Pplns,
            group_id: None,
            height: 870_123,
            weight_snapshot: None,
            payouts_fingerprint: None,
            actual_coinbase: None,
        }
    }

    /// Pins the JSON round-trip of the Core-stamped event fields.
    #[test]
    fn block_found_event_json_round_trips_with_stamped_fields() {
        let weight_snapshot = bp_pplns_engine::window::snapshot::StoredWeightSnapshot {
            entries: vec![bp_pplns_engine::window::snapshot::WeightSnapshotEntry {
                address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                score_weight: 1_000_000_000_000,
                balance_sats: 0,
            }],
            score_total: 1_000_000_000_000,
            fee_ppm: 15_000,
            fee_address: "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
                .to_string(),
            reference_revenue_sats: 312_500_000,
        };
        let event = BlockFoundEvent {
            actual_coinbase: None,
            weight_snapshot: Some(weight_snapshot.clone()),
            payouts_fingerprint: None,
            address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            worker: "rig1".to_string(),
            session_id: "sess1".to_string(),
            booking: Booking::Book {
                reward_sats: 312_500_000,
            },
            block_hash: "00000000deadbeef".to_string(),
            block_data: "ab".repeat(80),
            mode: MiningMode::Pplns,
            group_id: None,
            height: 870_123,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let back: BlockFoundEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.mode, MiningMode::Pplns);
        assert_eq!(back.height, 870_123);
        assert_eq!(
            back.booking,
            Booking::Book {
                reward_sats: 312_500_000
            }
        );
        assert_eq!(back.address, event.address);
        assert_eq!(back.block_data, event.block_data);
        assert_eq!(back.weight_snapshot, Some(weight_snapshot));
    }

    /// One rule for every mode that books against a pool-built distribution:
    /// a block on a coinbase the pool did not build (no or zeroed fingerprint)
    /// is not parked. A real fingerprint parks (negative control), and
    /// Blockparty, which recomputes its split from the roster, parks without one.
    #[tokio::test]
    async fn only_a_pool_built_coinbase_is_parked_for_booking() {
        let Some(mut conn) = bp_test_support::connect_redis_in_range_or_skip(
            bp_test_support::redis_db::BLITZPOOL_BIN_2,
            3,
        )
        .await
        else {
            return;
        };
        let applier = BlockFoundApplier {
            redis: Some(conn.clone()),
            ..Default::default()
        };
        let actual = ActualCoinbase {
            paid_by_address: Default::default(),
            total_value_sats: 312_500_000,
        };
        let group_id = uuid::Uuid::new_v4();
        let pplns = || PendingSettlement::Pplns {
            weight_snapshot: None,
        };
        let parked = |conn: &mut ConnectionManager, hash: &'static str| {
            let mut conn = conn.clone();
            async move {
                let hashes = crate::pending_blocks::pending_block_hashes(&mut conn)
                    .await
                    .expect("pending hashes");
                hashes.contains(hash)
            }
        };

        for (hash, fingerprint, settlement) in [
            ("pplns-none", None, pplns()),
            ("pplns-zero", Some([0u8; 32]), pplns()),
            ("gs-none", None, PendingSettlement::GroupSolo { group_id }),
        ] {
            applier
                .gate_or_apply("bc1q", 1, 0, hash, Some(&actual), fingerprint, settlement)
                .await;
            assert!(
                !parked(&mut conn, hash).await,
                "{hash}: a coinbase the pool did not build must not be parked for booking"
            );
        }

        for (hash, fingerprint, settlement) in [
            ("pplns-built", Some([7u8; 32]), pplns()),
            (
                "gs-built",
                Some([7u8; 32]),
                PendingSettlement::GroupSolo { group_id },
            ),
            ("bp-none", None, PendingSettlement::Blockparty { group_id }),
        ] {
            applier
                .gate_or_apply("bc1q", 1, 0, hash, Some(&actual), fingerprint, settlement)
                .await;
            assert!(parked(&mut conn, hash).await, "{hash} must be parked");
        }
    }
}
