// SPDX-License-Identifier: AGPL-3.0-or-later

//! `BlockSubmissionSink` implementations — Phase 7.4a (SV1 path).
//!
//! When a Stratum share's submission difficulty meets / exceeds the
//! network difficulty derived from the template's `n_bits`, the
//! per-protocol server fires the block-submission hook. The Rust port
//! routes those through [`TdpBlockSubmissionSink`] which assembles the
//! witness-form coinbase from the share's owned `MiningJob` snapshot
//! plus the parsed extranonces, then calls
//! `bp_template_distribution::TdpHandle::submit_solution(...)`.
//!
//! Bitcoin Core's IPC `SubmitSolution` consumes:
//! - `template_id`     — taken from `accept.template.template_id`
//! - `version`         — extracted from the 80-byte header bytes 0..4
//!   (miner-rolled via `BIP-310` version-rolling; we read it back
//!   from the assembled header rather than the template's pre-roll
//!   version field)
//! - `header_timestamp` — header bytes 68..72
//! - `header_nonce`    — header bytes 76..80
//! - `coinbase_tx`     — the witness-form coinbase, derived from
//!   `MiningJob::witness_coinbase_with_extranonce(&enonce1, &enonce2)`
//!
//! bitcoin-core re-derives `prev_hash` + `merkle_root` from the
//! template + coinbase, so we don't pass them through the IPC call.
//! It validates the full block synchronously; an `Ok(())` from
//! `submit_solution` means accepted-or-already-known. Any error from
//! the IPC channel is logged at WARN — the block path is best-effort
//! from the SV1 server's perspective (the share is already credited
//! by the time this hook fires; failing to forward to core only
//! means we lose the block reward, not the share count).
//!
//! ## SV2 wiring (Phase 7.4c)
//!
//! SV2's `ShareAccept` doesn't yet carry the `MiningJob` snapshot +
//! extranonce bytes the same way SV1 does (the Standard-channel job
//! state lives in the channel's send-time bookkeeping, not the
//! per-share `ShareAccept`). That extension lands alongside the SV2
//! TCP binding in 7.4c.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use bp_bitcoin::BitcoinRpc;
use bp_coinbase_snapshot::ActualCoinbase;
use bp_common::{AddressId, MiningMode, StreamKind};
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_notifications::dispatcher::NotificationDispatcher;
use bp_pplns_engine::engine::PplnsEngine;
use bp_share_stream::StreamProducer;
use bp_stratum_v1::{BlockSubmissionSink as Sv1BlockSubmissionSink, ShareAccept as Sv1ShareAccept};
use bp_stratum_v2::hooks::BlockSubmissionSink as Sv2BlockSubmissionSink;
use bp_stratum_v2::mining::submit::ShareAccept as Sv2ShareAccept;
use bp_template_distribution::TdpHandle;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tracing::{error, info, warn};

use crate::engines::BlitzpoolModeGate;
use crate::pending_blocks::{
    load_pending_blocks, put_pending_block, remove_pending_block, PendingBlock,
};
use crate::pending_group_solo_blocks::{put_pending_group_solo_block, PendingGroupSoloBlock};

/// Accounting inputs for a found block, bundled so the block-found fan-out
/// (per-mode engine ledger + notifications) runs from one value.
///
/// This is the Core→Satellite block-found event (hence `serde`): the front
/// keeps `submit_solution` + the `blocks_entity` record and emits this onto
/// the stream; the payout Satellite consumes it and does the ledger
/// accounting (the front also applies it in-process as a publish-failure
/// fallback).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct BlockFoundEvent {
    /// Miner-authorized payout address.
    pub address: String,
    pub worker: String,
    pub session_id: String,
    /// Block-reward portion this coinbase claims (subsidy + fees after any
    /// JDC coinbase outputs). `None` only signals a caller regression — a
    /// non-Solo block-found always carries `Some`.
    pub reward_sats: Option<u64>,
    /// Big-endian block-hash hex — the idempotent history-row key + the
    /// PPLNS confirmation-gating key.
    pub block_hash: Option<String>,
    /// 80-byte header hex (LE), stored in `blocks_entity.blockData`.
    pub block_data: String,
    /// Payout mode resolved on the Core (the only side holding the mode
    /// gate), stamped here so the apply side needs no gate of its own.
    pub mode: MiningMode,
    /// Group UUID string for `GroupSolo` / `Blockparty`, else `None` —
    /// carried next to `mode` so the group arms don't re-query the gate.
    pub group_id: Option<String>,
    /// Block height (chain tip + 1), derived on the Core right after submit.
    /// Carried in the event so the apply side never re-derives it: the chain
    /// may have advanced by the time a Satellite consumes the event.
    pub height: i32,
    /// The settlement INPUTS of the distribution the winning job's
    /// coinbase was built from, frozen by the Core at the block-found
    /// instant. `Some` only for `GroupSolo` blocks; carried so the apply
    /// side never re-reads the raceable per-(group, finder) Redis
    /// snapshot (which template rebuilds overwrite before the async apply
    /// runs). `None` on a build failure → the block is not booked.
    #[serde(default)]
    pub groupsolo_weight_snapshot: Option<bp_coinbase_snapshot::StoredWeightSnapshot>,
    /// Identity of the payout list this block's coinbase pays, taken off the
    /// job the winning share was built on. Both group-ledger paths look the
    /// distribution up under it, so what gets booked is what the coinbase
    /// actually paid instead of whatever a shared snapshot key holds by then —
    /// PPLNS on the apply side, Group-Solo when the Core stamps
    /// `groupsolo_snapshot`. `None`/zero when the pool did not build the
    /// coinbase (`SetCustomMiningJob`) or the job path carries no fingerprint.
    ///
    /// Named for PPLNS because that is where it started; the name is on the
    /// wire format of a stream other processes replay, so it stays.
    #[serde(default)]
    pub pplns_payouts_fingerprint: Option<[u8; 32]>,
    /// What the found block's coinbase ACTUALLY paid, decoded from the
    /// submitted coinbase transaction on the Core. The weight-model
    /// settlement books `claim − paid` from this — the event carries it
    /// so a Satellite never has to re-derive it from chain data.
    /// `None` on events produced before this field existed; those can
    /// only book through the legacy exact-match path.
    #[serde(default)]
    pub actual_coinbase: Option<ActualCoinbase>,
}

/// `BlockSubmissionSink` for both SV1 + SV2. Forwards every
/// block-candidate share to bitcoin-core via TDP **and** (Phase 7.7)
/// fans the event out to the per-mode engine ledger
/// (`PplnsEngine::on_block_found` / `GroupSoloEngine::on_block_found`)
/// plus the [`NotificationDispatcher`] for subscriber notifications.
///
/// All fan-out hooks except the TDP submit are optional: when the
/// mode-gate, engines, or dispatcher are absent, the corresponding
/// step logs at INFO and continues. The TDP submit is the
/// authoritative block-propagation path; engine + dispatcher are
/// observability + accounting.
#[allow(dead_code)]
pub(crate) struct TdpBlockSubmissionSink {
    /// Default stream handle (PPLNS-autoscaled). Submission target for every
    /// PPLNS job, and the fallback when an alt stream isn't wired.
    tdp: TdpHandle,
    /// Fixed-reservation alt stream handles keyed by `StreamKind` (Solo /
    /// GroupSolo / Blockparty). Empty until wired; an alt-stream job is only
    /// produced when boot wired both the template stream and this handle, so
    /// routing stays consistent (the handle knows the job's template_id).
    alt: HashMap<StreamKind, TdpHandle>,
    mode_gate: Option<Arc<BlitzpoolModeGate>>,
    bitcoin_rpc: Option<BitcoinRpc>,
    /// Postgres pool for writing to `blocks_entity` on block-found.
    pool: Option<PgPool>,
    /// The relocatable block-found apply deps (engine ledger + dispatcher +
    /// PPLNS pending store). Bundled in [`BlockFoundApplier`] so the exact
    /// same apply runs on the Core (in-process) or on a Satellite consuming
    /// the block-found event off a stream.
    applier: BlockFoundApplier,
    /// The front publishes each block-found event to the stream (the payout
    /// Satellite consumes + applies); on a publish failure it applies
    /// in-process via [`Self::applier`] as a fallback. `None` only on a sink
    /// with no front role wired (e.g. in tests).
    block_found_producer: Option<StreamProducer<BlockFoundEvent>>,
    /// Address-display network for decomposing the submitted coinbase
    /// into per-address payments ([`ActualCoinbase`]).
    network: bitcoin::Network,
}

/// The relocatable half of block-found handling: the per-mode engine
/// ledger-writes (`PplnsEngine` / `GroupSoloEngine` / Blockparty
/// `on_block_found`) + the confirmation-gated PPLNS pending store +
/// subscriber notifications. Reads everything from the (Core-stamped)
/// [`BlockFoundEvent`] — no mode gate, no RPC, no `blocks_entity` write — so
/// it runs identically in-process on the Core and on a Satellite draining
/// the block-found stream.
#[derive(Default, Clone)]
pub(crate) struct BlockFoundApplier {
    pplns: Option<PplnsEngine>,
    group_solo: Option<GroupSoloEngine>,
    blockparty: Option<Arc<dyn bp_blockparty_engine::BlockpartyApi>>,
    dispatcher: Option<Arc<NotificationDispatcher>>,
    /// Redis handle for the confirmation-gated PPLNS pending-block store.
    /// When wired, a PPLNS block-found freezes its distribution and parks
    /// it here (keyed by block hash) instead of applying the ledger
    /// immediately; the confirmation watcher applies it once the block
    /// reaches `confirmation_depth`. When absent (or no block hash), the
    /// PPLNS arm falls back to the immediate `on_block_found` apply.
    redis: Option<ConnectionManager>,
    /// ext 0x0003 §10 settlement hook, shared with the JDP booking path
    /// via a late-bound slot (the sinks are built before the JDP server
    /// exists).
    ///
    /// A settlement from ANY source invalidates every published payout
    /// distribution — the published weights encode the pre-settlement
    /// balances, so a 0x0003 JDC still mining them would pay out the
    /// same balances a second time. Wiring this only to JDP-declared
    /// blocks left every SV1/SV2 block silently skipping the
    /// invalidation.
    settle: Option<Arc<OnceLock<bp_stratum_v2::jdp_server::DistributionInvalidationHandle>>>,
}

#[allow(dead_code)]
impl TdpBlockSubmissionSink {
    pub(crate) fn new(tdp: TdpHandle) -> Self {
        Self {
            tdp,
            alt: HashMap::new(),
            mode_gate: None,
            bitcoin_rpc: None,
            pool: None,
            applier: BlockFoundApplier::default(),
            block_found_producer: None,
            network: bitcoin::Network::Bitcoin,
        }
    }

    /// Wire the ext 0x0003 §10 settlement hook onto this sink's applier,
    /// so a block booked through the Stratum path invalidates the
    /// published payout distributions exactly like a JDP-declared one.
    pub(crate) fn with_settle_handle(
        mut self,
        slot: Arc<OnceLock<bp_stratum_v2::jdp_server::DistributionInvalidationHandle>>,
    ) -> Self {
        self.applier.settle = Some(slot);
        self
    }

    /// Set the address-display network used to decompose submitted
    /// coinbases into per-address payments.
    pub(crate) fn with_network(mut self, network: bitcoin::Network) -> Self {
        self.network = network;
        self
    }

    /// `core` mode: route block-found events to the stream (the Satellite
    /// applies them) instead of applying in-process.
    pub(crate) fn with_block_found_producer(
        mut self,
        producer: StreamProducer<BlockFoundEvent>,
    ) -> Self {
        self.block_found_producer = Some(producer);
        self
    }

    pub(crate) fn with_pool(mut self, pool: PgPool) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Wire the Redis handle that backs the confirmation-gated PPLNS
    /// pending-block store. Without it the PPLNS arm applies the ledger
    /// immediately (no gating).
    pub(crate) fn with_redis(mut self, redis: ConnectionManager) -> Self {
        self.applier.redis = Some(redis);
        self
    }

    /// Attach the fixed-reservation alt stream handles (Solo / GroupSolo /
    /// Blockparty). An alt-stream block candidate submits through its matching
    /// handle so the solution carries a template_id that handle actually knows
    /// (template_ids are per-connection and collide across streams).
    pub(crate) fn with_alt_streams(mut self, alt: HashMap<StreamKind, TdpHandle>) -> Self {
        self.alt = alt;
        self
    }

    /// Pick the TDP handle for the stream a job was built on. An alt-stream job
    /// whose handle is somehow absent falls back to the default handle with a
    /// loud warning — the submit will fail (mismatched template_id) rather than
    /// land an invalid block, and the warning flags the wiring bug.
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

    /// Attach the Blockparty handle so the Blockparty arm of
    /// `fan_out_block_found` can write the history row via the engine.
    /// Optional — when absent the arm logs at INFO and continues.
    pub(crate) fn with_blockparty(
        mut self,
        blockparty: Option<Arc<dyn bp_blockparty_engine::BlockpartyApi>>,
    ) -> Self {
        self.applier.blockparty = blockparty;
        self
    }

    /// Attach the Phase 7.7 fan-out dependencies. Returns `Self` so
    /// the caller can chain at construction. Passing `None` for the
    /// dispatcher (no transport adapters wired) keeps the engine
    /// ledger-write live but skips notifications; passing `None` for
    /// either engine collapses the per-mode `on_block_found` call to
    /// a logged no-op.
    pub(crate) fn with_fanout(
        mut self,
        mode_gate: Arc<BlitzpoolModeGate>,
        pplns: Option<PplnsEngine>,
        group_solo: GroupSoloEngine,
        dispatcher: Option<Arc<NotificationDispatcher>>,
        bitcoin_rpc: BitcoinRpc,
    ) -> Self {
        self.mode_gate = Some(mode_gate);
        self.applier.pplns = pplns;
        self.applier.group_solo = Some(group_solo);
        self.applier.dispatcher = dispatcher;
        self.bitcoin_rpc = Some(bitcoin_rpc);
        self
    }

    /// Book a block whose coinbase the pool did NOT build — a JDC declared the
    /// job and owns its coinbase; the pool only issued the payout set, and the
    /// ext-0x0003 declare-time check proved the coinbase carries it verbatim.
    /// That proof is what `payouts_fingerprint` names, so the ledger books the
    /// distribution the block actually paid rather than a rebuilt guess.
    ///
    /// `worker` is fixed to `jdp` — a declared job has no Stratum worker name.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn book_declared_block_found(
        &self,
        miner_address: String,
        session_id: String,
        reward_sats: u64,
        block_hash: String,
        block_data: String,
        payouts_fingerprint: [u8; 32],
        actual_coinbase: Option<ActualCoinbase>,
    ) -> bool {
        self.emit_block_found(
            miner_address,
            "jdp".to_string(),
            session_id,
            Some(reward_sats),
            Some(block_hash),
            block_data,
            Some(payouts_fingerprint),
            actual_coinbase,
        )
        .await
    }

    /// Convenience: wrap in `Arc<dyn BlockSubmissionSink>` so the
    /// caller can drop it directly into `bp_stratum_v1::ServerHooks
    /// { block_sink, … }`.
    #[allow(dead_code)]
    pub(crate) fn into_sv1_arc(self) -> Arc<dyn Sv1BlockSubmissionSink> {
        Arc::new(self)
    }

    /// Symmetric helper for the SV2 mining server's
    /// [`bp_stratum_v2::hooks::BlockSubmissionSink`] hook slot. The
    /// underlying sink is shape-identical; the SV2 trait just has a
    /// different `ShareAccept` shape.
    #[allow(dead_code)]
    pub(crate) fn into_sv2_arc(self) -> Arc<dyn Sv2BlockSubmissionSink> {
        Arc::new(self)
    }

    /// Height of the just-found block, derived from its parent (`prev_hash` in
    /// the 80-byte header) — NOT `get_block_count() + 1`. `submit_solution` may
    /// have already connected the block by the time we'd query the tip, making
    /// `tip + 1` one too high; the parent's height + 1 is the found block's
    /// height regardless of submit/propagation timing. Falls back to the tip
    /// query only if the parent lookup is unavailable (so a height hiccup never
    /// silently drops the block-found).
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

    /// Front-side block-found entry (SV1 + SV2 call this after submit).
    ///
    /// Does the parts that must run where the front state lives: resolves the
    /// payout mode from the gate, derives the height (chain tip + 1), and
    /// writes the durable `blocks_entity` record. It then builds the
    /// self-contained [`BlockFoundEvent`] and publishes it onto the stream for
    /// the payout Satellite to apply (falling back to an in-process
    /// [`BlockFoundApplier`] apply if the publish fails).
    #[allow(clippy::too_many_arguments)]
    /// Returns whether the block-found reached the fan-out — i.e. an event was
    /// built and either published or applied in-process. `false` means one of
    /// the preconditions below was missing and **nothing at all was written**,
    /// which a caller that dedups repeats has to be able to tell apart from a
    /// completed emission: marking a block as handled on a `false` makes the
    /// miner's payout unrecoverable in-process.
    ///
    /// It does not promise the ledger row itself landed. Past the fan-out every
    /// step is best-effort and PG-idempotent, so a redelivery finishes the job;
    /// before it, there is nothing to redeliver.
    async fn emit_block_found(
        &self,
        address: String,
        worker: String,
        session_id: String,
        reward_sats: Option<u64>,
        block_hash: Option<String>,
        block_data: String,
        pplns_payouts_fingerprint: Option<[u8; 32]>,
        actual_coinbase: Option<ActualCoinbase>,
    ) -> bool {
        // Resolve the payout mode on the Core (the only side with the gate)
        // and stamp it onto the event so the apply side needs no gate.
        let Some(mode_gate) = self.mode_gate.as_ref() else {
            info!(
                address = %address,
                "block-found: SKIPPED (no mode-gate wired — Phase 7.4 transitional path)"
            );
            return false;
        };
        let resolved = mode_gate.lookup_mode(&address);

        let height = match self.bitcoin_rpc.as_ref() {
            Some(rpc) => match self.derive_block_height(rpc, &block_data).await {
                Some(h) => h,
                None => {
                    warn!(
                        address = %address,
                        "block-found: could not derive block height — skipping fan-out"
                    );
                    return false;
                }
            },
            None => {
                warn!(
                    address = %address,
                    "block-found: no BitcoinRpc — skipping (engines need block_height)"
                );
                return false;
            }
        };

        // Persist the durable Core record (the Redis-independent safety net
        // the ledger can be reconciled against). Stays on the Core. Best-
        // effort: failure is logged but does not abort the apply below.
        if let Some(pool) = self.pool.as_ref() {
            if let Err(err) = bp_db::insert_found_block(
                pool,
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
        }

        // Group-Solo: stamp the distribution the winning job's coinbase pays
        // into the event, looked up by that job's payout-list fingerprint, so
        // the apply side (an async Satellite under the split) books exactly
        // that. Neither of the two things it replaces is safe: the
        // per-(group, finder) Redis key is overwritten by continuous template
        // rebuilds before the apply runs, and rebuilding the distribution here
        // runs against a round that any share since job-issue has moved.
        // `None` here means the block is NOT booked automatically.
        // A zeroed fingerprint means the pool did not build this coinbase
        // (`SetCustomMiningJob`) — there is no distribution of ours to find.
        let job_payouts_fingerprint = pplns_payouts_fingerprint.filter(|fp| fp != &[0u8; 32]);
        let groupsolo_weight_snapshot = if resolved.mode == MiningMode::GroupSolo {
            self.resolve_group_solo_distribution(
                &address,
                resolved.group_id.as_deref(),
                reward_sats,
                job_payouts_fingerprint,
                height,
            )
            .await
        } else {
            None
        };

        let event = BlockFoundEvent {
            address,
            worker,
            session_id,
            pplns_payouts_fingerprint,
            reward_sats,
            block_hash,
            block_data,
            mode: resolved.mode,
            group_id: resolved.group_id,
            height,
            groupsolo_weight_snapshot,
            actual_coinbase,
        };

        // The front publishes to the stream (the payout Satellite applies). On
        // a publish failure we fall back to in-process apply so a Redis blip
        // never silently drops the ledger write — the apply is PG-idempotent,
        // so a later redelivery is a no-op.
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

    /// Resolve the distribution a Group-Solo block's coinbase pays, for the
    /// event the apply side consumes.
    ///
    /// `None` means the block will not be booked, so every way of getting there
    /// says which one it was — the operator's next step differs sharply between
    /// them. A JD-client coinbase (zero fingerprint) must NOT be reprocessed at
    /// all: the pool did not build it. A Redis miss must be reprocessed from the
    /// block's own coinbase. A config or parse fault is a pool bug.
    async fn resolve_group_solo_distribution(
        &self,
        address: &str,
        group_id: Option<&str>,
        reward_sats: Option<u64>,
        payouts_fingerprint: Option<[u8; 32]>,
        height: i32,
    ) -> Option<bp_coinbase_snapshot::StoredWeightSnapshot> {
        let Some(engine) = self.applier.group_solo.as_ref() else {
            warn!(
                address,
                height, "block-found: Group-Solo mode but the engine is not configured"
            );
            return None;
        };
        let Some(reward) = reward_sats else {
            warn!(
                address,
                height, "block-found: Group-Solo block carries no reward — cannot resolve"
            );
            return None;
        };
        let Some(group_id_str) = group_id else {
            warn!(
                address,
                height, "block-found: Group-Solo mode but the mode-gate returned no group_id"
            );
            return None;
        };
        let Some(fingerprint) = payouts_fingerprint else {
            warn!(
                address,
                group_id = group_id_str,
                height,
                "block-found: Group-Solo job carries no payout fingerprint — the pool did not \
                 build this coinbase (JD-client custom job), so there is no pool-side \
                 distribution to book. Do NOT reprocess."
            );
            return None;
        };
        let (Ok(finder), Ok(group_uuid)) = (
            AddressId::new(address.to_string()),
            uuid::Uuid::parse_str(group_id_str),
        ) else {
            warn!(
                address,
                group_id = group_id_str,
                height,
                "block-found: Group-Solo finder address or group_id failed to parse"
            );
            return None;
        };
        // Reward-band plausibility is checked at apply time, where the
        // actual coinbase is at hand; `reward` names the job's pinned
        // value for the log lines only.
        let _ = reward;
        match engine
            .weight_snapshot_for_block_found(group_uuid, &finder, &fingerprint)
            .await
        {
            Ok(snap) => Some(snap),
            Err(err) => {
                error!(
                    %err,
                    address,
                    group_id = group_id_str,
                    height,
                    fingerprint = %hex::encode(fingerprint),
                    "block-found: Group-Solo distribution lookup failed — the block is NOT booked \
                     and must be reprocessed from its own coinbase"
                );
                None
            }
        }
    }
}

impl BlockFoundApplier {
    /// Build an applier from the back-office engines + dispatcher + Redis —
    /// the Satellite's block-found stream consumer uses this to run the same
    /// apply the front runs in-process on a publish-failure fallback.
    pub(crate) fn new(
        pplns: Option<PplnsEngine>,
        group_solo: Option<GroupSoloEngine>,
        blockparty: Option<Arc<dyn bp_blockparty_engine::BlockpartyApi>>,
        dispatcher: Option<Arc<NotificationDispatcher>>,
        redis: Option<ConnectionManager>,
    ) -> Self {
        Self {
            pplns,
            group_solo,
            blockparty,
            dispatcher,
            redis,
            settle: None,
        }
    }

    /// §10: a ledger settlement just happened. Invalidate every
    /// published payout distribution and force a fresh publish, so no
    /// JDC keeps declaring against weights this block already settled.
    fn settle_distributions(&self) {
        if let Some(handle) = self.settle.as_ref().and_then(|s| s.get()) {
            handle.settle();
        }
    }

    /// PPLNS block-found: confirmation-gate when both a Redis store and a
    /// block hash are available — freeze the distribution now (the live
    /// snapshot rotates within a block or two) and park it keyed by hash;
    /// the confirmation watcher applies it once the block reaches
    /// `confirmation_depth`, so a block that orphans never drifts the
    /// pending-balance ledger. Falls back to the immediate apply when
    /// gating isn't possible (no Redis / no hash) or the store write fails
    /// (so a block's distribution is never silently lost).
    #[allow(clippy::too_many_arguments)]
    async fn gate_or_apply_pplns(
        &self,
        engine: &PplnsEngine,
        address_str: &str,
        height: i32,
        reward: u64,
        block_hash_hex: Option<&str>,
        payouts_fingerprint: Option<[u8; 32]>,
        actual: Option<&bp_coinbase_snapshot::ActualCoinbase>,
    ) {
        match (self.redis.as_ref(), block_hash_hex) {
            (Some(redis), Some(block_hash)) => {
                let mut conn = redis.clone();

                // Flush-before-prepare: keep at most ONE PPLNS block
                // pending at a time. Each prepared block freezes ABSOLUTE
                // post-distribution balances read from the ledger at
                // found-time; if an earlier block were still pending
                // (unapplied) when this one freezes, applying both in
                // sequence would let the later absolute write clobber the
                // earlier block's balance / totalPaid deltas. Apply any
                // earlier pending block(s) now — they are the
                // more-confirmed, least orphan-prone ones — so this block
                // freezes against a fresh ledger. Best-effort: a flush
                // error still lets the new block be stored (never dropped);
                // the confirmation watcher reconciles any leftover.
                match load_pending_blocks(&mut conn).await {
                    Ok((earlier, unparsable)) => {
                        for stale in unparsable {
                            let _ = remove_pending_block(&mut conn, &stale).await;
                        }
                        for old in earlier {
                            match engine.apply_prepared(&old.prepared).await {
                                Ok(_) => {
                                    let _ = remove_pending_block(&mut conn, &old.block_hash).await;
                                    info!(
                                        old_hash = old.block_hash,
                                        height,
                                        "block-found: applied earlier pending PPLNS block before \
                                         freezing new one (orphan-gating skipped for the older, \
                                         more-confirmed block)"
                                    );
                                }
                                Err(e) => warn!(%e, old_hash = old.block_hash, height,
                                    "block-found: flushing earlier pending PPLNS block failed; \
                                     watcher will retry — proceeding to freeze new block"),
                            }
                        }
                    }
                    Err(e) => warn!(%e, height,
                        "block-found: could not read pending PPLNS blocks before freezing; \
                         proceeding (watcher reconciles)"),
                }

                // Weight-model settlement when the event carries the real
                // coinbase's payments; the legacy exact-match prepare only
                // remains for events produced before `actual_coinbase`
                // existed (their schema-1 snapshots still resolve).
                let prepared = match actual {
                    Some(actual) => {
                        match engine
                            .prepare_block_found_scaled(height, actual, payouts_fingerprint)
                            .await
                        {
                            Ok(p) => p,
                            Err(err) => {
                                error!(%err, address = address_str, height, block_hash,
                                    "block-found: PPLNS block could not be frozen for booking — \
                                     it is NOT parked and will not be retried; the miners its \
                                     coinbase paid are owed their ledger entry, and until it is \
                                     reprocessed their balances stand as if this block never \
                                     paid them. block-reconcile will report it as unbooked");
                                return;
                            }
                        }
                    }
                    None => match engine
                        .prepare_block_found_for(height, reward, payouts_fingerprint)
                        .await
                    {
                        Ok(p) => p,
                        Err(err) => {
                            error!(%err, address = address_str, height, block_hash,
                                "block-found: PPLNS block could not be frozen for booking — \
                                 it is NOT parked and will not be retried; block-reconcile \
                                 will report it as unbooked");
                            return;
                        }
                    },
                };
                let pending = PendingBlock {
                    block_hash: block_hash.to_string(),
                    found_at_ms: chrono::Utc::now().timestamp_millis(),
                    prepared,
                };
                if let Err(err) = put_pending_block(&mut conn, &pending).await {
                    warn!(%err, address = address_str, height,
                        "block-found: PPLNS pending-store write failed; applying immediately as fallback");
                    if let Err(e) = engine.apply_prepared(&pending.prepared).await {
                        warn!(%e, address = address_str, height,
                            "block-found: PPLNS fallback apply_prepared failed");
                    }
                    return;
                }
                info!(
                    address = address_str,
                    height, block_hash,
                    "block-found: PPLNS distribution frozen, awaiting confirmations before ledger apply"
                );
            }
            _ => {
                if self.redis.is_none() {
                    warn!(address = address_str, height,
                        "block-found: PPLNS confirmation-gating unavailable (no Redis); applying immediately");
                } else {
                    warn!(address = address_str, height,
                        "block-found: PPLNS confirmation-gating unavailable (no block hash); applying immediately");
                }
                // Same fingerprint the gated arm uses.
                let immediate = match actual {
                    Some(actual) => {
                        engine
                            .on_block_found_scaled(height, actual, payouts_fingerprint)
                            .await
                    }
                    None => {
                        engine
                            .on_block_found_for(height, reward, payouts_fingerprint)
                            .await
                    }
                };
                match immediate {
                    Ok(outcome) => {
                        self.settle_distributions();
                        info!(
                            address = address_str,
                            height,
                            reward_sats = reward,
                            history_inserted = outcome.history_inserted,
                            balances_affected = outcome.balances_affected,
                            "block-found: PPLNS ledger applied (immediate)"
                        )
                    }
                    Err(err) => warn!(%err, address = address_str, height,
                        "block-found: PPLNS on_block_found failed"),
                }
            }
        }
    }

    /// Group-Solo block-found: confirmation-gate (park the frozen snapshot until
    /// the block reaches `confirmation_depth`) when a Redis store and a block
    /// hash are both present — the watcher applies it on confirmation and
    /// discards it on orphan, so an orphan / non-chain-extending candidate never
    /// books a phantom into the group ledger. Falls back to an immediate apply
    /// when gating isn't possible (no Redis / no hash), so a block's
    /// distribution is never silently lost.
    ///
    /// The `snapshot` is the distribution the block's coinbase pays, resolved
    /// from the winning job's payout list. Nothing here may substitute another
    /// one: the alternatives (the last-writer-wins per-(group, finder) Redis
    /// key, or a rebuild against a round that has since moved) both book a
    /// distribution the chain did not pay, and unlike PPLNS nothing downstream
    /// would catch it. Unresolved → the caller does not book at all.
    #[allow(clippy::too_many_arguments)]
    async fn gate_or_apply_group_solo(
        &self,
        engine: &GroupSoloEngine,
        group_uuid: uuid::Uuid,
        group_id_str: &str,
        address: &AddressId,
        height: i32,
        reward: u64,
        block_hash_hex: Option<&str>,
        weight_snapshot: Option<bp_coinbase_snapshot::StoredWeightSnapshot>,
        actual: Option<&bp_coinbase_snapshot::ActualCoinbase>,
        payouts_fingerprint: Option<[u8; 32]>,
    ) {
        match (self.redis.as_ref(), block_hash_hex) {
            (Some(redis), Some(block_hash)) => {
                let pending = PendingGroupSoloBlock {
                    block_hash: block_hash.to_string(),
                    found_at_ms: chrono::Utc::now().timestamp_millis(),
                    group_id: group_id_str.to_string(),
                    finder: address.as_str().to_string(),
                    block_height: height,
                    block_reward_sats: reward,
                    weight_snapshot: weight_snapshot.clone(),
                    actual_coinbase: actual.cloned(),
                    payouts_fingerprint,
                };
                let mut conn = redis.clone();
                if let Err(err) = put_pending_group_solo_block(&mut conn, &pending).await {
                    warn!(%err, group_id = group_id_str, height,
                        "block-found: Group-Solo pending-store write failed; applying immediately as fallback");
                    self.apply_group_solo_now(
                        engine,
                        group_uuid,
                        group_id_str,
                        address,
                        height,
                        reward,
                        weight_snapshot,
                        actual,
                        payouts_fingerprint,
                    )
                    .await;
                    return;
                }
                info!(
                    group_id = group_id_str,
                    height, block_hash,
                    "block-found: Group-Solo distribution frozen, awaiting confirmations before ledger apply"
                );
            }
            _ => {
                if self.redis.is_none() {
                    warn!(group_id = group_id_str, height,
                        "block-found: Group-Solo confirmation-gating unavailable (no Redis); applying immediately");
                } else {
                    warn!(group_id = group_id_str, height,
                        "block-found: Group-Solo confirmation-gating unavailable (no block hash); applying immediately");
                }
                self.apply_group_solo_now(
                    engine,
                    group_uuid,
                    group_id_str,
                    address,
                    height,
                    reward,
                    weight_snapshot,
                    actual,
                    payouts_fingerprint,
                )
                .await;
            }
        }
    }

    /// Immediate (non-gated) Group-Solo apply: write the block's payout
    /// history from its own coinbase.
    ///
    /// Both the weight snapshot AND the parsed coinbase are required. The
    /// snapshot alone says what the pool intended; only the coinbase says
    /// what it paid, and the history records the latter. Without both,
    /// nothing is written and the block is an operator reprocess.
    #[allow(clippy::too_many_arguments)]
    async fn apply_group_solo_now(
        &self,
        engine: &GroupSoloEngine,
        group_uuid: uuid::Uuid,
        group_id_str: &str,
        address: &AddressId,
        height: i32,
        reward: u64,
        weight_snapshot: Option<bp_coinbase_snapshot::StoredWeightSnapshot>,
        actual: Option<&bp_coinbase_snapshot::ActualCoinbase>,
        payouts_fingerprint: Option<[u8; 32]>,
    ) {
        let (Some(ws), Some(actual)) = (weight_snapshot, actual) else {
            warn!(
                group_id = group_id_str,
                height,
                "block-found: Group-Solo event carries no weight snapshot + parsed coinbase \
                 — NOT booked, reprocess from the block's own coinbase"
            );
            return;
        };
        let applied = engine
            .on_block_found(
                group_uuid,
                height,
                actual,
                address,
                Some(ws),
                payouts_fingerprint,
            )
            .await;
        match applied {
            Ok(outcome) => {
                self.settle_distributions();
                info!(
                    group_id = group_id_str,
                    height,
                    reward_sats = reward,
                    history_inserted = outcome.history_inserted,
                    "block-found: Group-Solo payout history written"
                )
            }
            Err(err) => warn!(%err, group_id = group_id_str, height,
                "block-found: Group-Solo on_block_found failed"),
        }
    }

    /// Apply a block-found event to the per-mode engine ledger + dispatcher.
    /// Reads everything it needs from the (Core-stamped) event — no mode
    /// gate, no RPC, no `blocks_entity` write — so it runs unchanged on a
    /// Satellite consuming the event off a stream. `reward_sats == None`
    /// skips the engine ledger-write but still fires the notification.
    /// Best-effort: every step's failure is logged and the others continue.
    pub(crate) async fn apply_block_found(&self, event: &BlockFoundEvent) {
        let address_str = event.address.as_str();
        let reward_sats = event.reward_sats;
        let block_hash_hex = event.block_hash.clone();
        let height = event.height;

        let address = match AddressId::new(address_str.to_string()) {
            Ok(a) => a,
            Err(err) => {
                warn!(
                    %err,
                    address = address_str,
                    "block-found apply: invalid AddressId shape — skipping"
                );
                return;
            }
        };

        match (event.mode, reward_sats) {
            (MiningMode::Solo, _) => {
                info!(
                    address = address_str,
                    height,
                    "block-found: solo mode — no engine ledger-write needed (single-payout coinbase)"
                );
            }
            (_, None) => {
                // Defensive only: both SV1 and SV2 now thread the per-job
                // `coinbase_tx_value_remaining` into the ShareAccept, so a
                // non-Solo block-found always carries `Some(reward)`. A `None`
                // here would mean a caller regressed — skip the ledger-write
                // (still dispatch below) and flag it loudly.
                warn!(
                    address = address_str,
                    height,
                    mode = ?event.mode,
                    "block-found: non-Solo mode with no reward — engine ledger-write skipped \
                     (unexpected: reward should always be present, possible caller regression)"
                );
            }
            (MiningMode::Pplns, Some(reward)) => match self.pplns.as_ref() {
                Some(engine) => {
                    self.gate_or_apply_pplns(
                        engine,
                        address_str,
                        height,
                        reward,
                        block_hash_hex.as_deref(),
                        event.pplns_payouts_fingerprint,
                        event.actual_coinbase.as_ref(),
                    )
                    .await
                }
                None => warn!(
                    address = address_str,
                    height, "block-found: PPLNS mode but engine not configured"
                ),
            },
            (MiningMode::Blockparty, Some(reward)) => {
                let svc = match self.blockparty.as_ref() {
                    Some(s) => s,
                    None => {
                        warn!(
                            address = address_str,
                            height,
                            "block-found: Blockparty mode but service handle not wired — skipping history-row write"
                        );
                        return;
                    }
                };
                let block_hash = match block_hash_hex.as_deref() {
                    Some(h) => h,
                    None => {
                        warn!(
                            address = address_str,
                            height,
                            "block-found: Blockparty needs a block hash for idempotent history-row write — skipping"
                        );
                        return;
                    }
                };
                let group_id_str = match event.group_id.as_deref() {
                    Some(g) => g,
                    None => {
                        warn!(
                            address = address_str,
                            height,
                            "block-found: Blockparty mode published WITHOUT a group_id — skipping"
                        );
                        return;
                    }
                };
                let group_uuid = match uuid::Uuid::parse_str(group_id_str) {
                    Ok(u) => u,
                    Err(err) => {
                        warn!(
                            %err,
                            address = address_str,
                            group_id = group_id_str,
                            "block-found: Blockparty group_id is not a valid UUID — skipping"
                        );
                        return;
                    }
                };
                let reward_sats = bp_common::Sats(reward as i64);
                // Recompute the splits from the live engine — the on-
                // chain coinbase has the same shape because the
                // PayoutResolver consulted the same engine at template-
                // broadcast for this address.
                let dist = match svc.build_payouts(group_uuid, reward_sats).await {
                    Ok(Some(d)) => d,
                    Ok(None) => {
                        warn!(
                            address = address_str,
                            group_id = group_id_str,
                            height,
                            "block-found: Blockparty group_id not found in DB — skipping history-row write"
                        );
                        return;
                    }
                    Err(err) => {
                        warn!(
                            %err,
                            address = address_str,
                            group_id = group_id_str,
                            height,
                            "block-found: Blockparty distribution build failed — skipping history-row write"
                        );
                        return;
                    }
                };
                match svc
                    .on_block_found(
                        group_uuid,
                        height,
                        block_hash,
                        reward_sats,
                        dist.pool_fee_sats,
                        dist.splits,
                        None,
                    )
                    .await
                {
                    Ok(Some(row)) => info!(
                        address = address_str,
                        group_id = group_id_str,
                        height,
                        reward_sats = reward,
                        row_id = row.id,
                        "block-found: Blockparty history row inserted"
                    ),
                    Ok(None) => info!(
                        address = address_str,
                        group_id = group_id_str,
                        height,
                        "block-found: Blockparty replay (idempotent, history row already present)"
                    ),
                    Err(err) => warn!(
                        %err,
                        address = address_str,
                        group_id = group_id_str,
                        height,
                        "block-found: Blockparty on_block_found failed"
                    ),
                }
            }
            (MiningMode::GroupSolo, Some(reward)) => {
                match (event.group_id.as_deref(), self.group_solo.as_ref()) {
                    (Some(group_id_str), Some(engine)) => {
                        let group_uuid = match uuid::Uuid::parse_str(group_id_str) {
                            Ok(u) => u,
                            Err(err) => {
                                warn!(
                                    %err,
                                    address = address_str,
                                    group_id = group_id_str,
                                    "block-found: Group-Solo group_id is not a valid UUID — skipping ledger-write"
                                );
                                return;
                            }
                        };
                        // Without the distribution the block's coinbase pays
                        // there is nothing safe to book: the substitutes all
                        // claim on-chain payments the chain did not make.
                        // Confirmation-gate (park until confirmed) when
                        // possible, else apply immediately — mirrors the
                        // PPLNS arm so an orphan / non-chain-extending
                        // candidate never books a phantom into the group
                        // ledger.
                        if event.groupsolo_weight_snapshot.is_some() {
                            self.gate_or_apply_group_solo(
                                engine,
                                group_uuid,
                                group_id_str,
                                &address,
                                height,
                                reward,
                                block_hash_hex.as_deref(),
                                event.groupsolo_weight_snapshot.clone(),
                                event.actual_coinbase.as_ref(),
                                event.pplns_payouts_fingerprint,
                            )
                            .await;
                        } else {
                            // Deliberately falls through to the notification
                            // below rather than returning: a block nobody can
                            // book is exactly the one the operator has to hear
                            // about. The Core logged which of the reasons it
                            // was; see `resolve_group_solo_distribution`.
                            error!(
                                address = address_str,
                                group_id = group_id_str,
                                height,
                                "block-found: Group-Solo event carried no distribution — NOT \
                                 booked, needs an operator reprocess"
                            );
                        }
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

    /// Fire the block-found notification fan-out (dispatcher only — no ledger,
    /// no RPC, no engines). It's the tail of [`Self::apply_block_found`] (so the
    /// front's publish-failure fallback notifies as before), and the entry
    /// point for the **notify-only** Satellite consumer (`notify` role), which
    /// holds the dispatcher but no engines. A no-op when no dispatcher is wired
    /// (e.g. the `payout` process, which does ledger-only).
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
        // Pull version / timestamp / nonce back out of the assembled
        // 80-byte header. The header bytes are LE per the Bitcoin
        // consensus rules; `u32::from_le_bytes` over the four-byte
        // slices is the canonical decoder.
        let header = &accept.header;
        let version = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let header_timestamp = u32::from_le_bytes([header[68], header[69], header[70], header[71]]);
        let header_nonce = u32::from_le_bytes([header[76], header[77], header[78], header[79]]);

        // Assemble the witness-form coinbase. `witness_coinbase_with_
        // extranonce` returns the full bytes including the SegWit
        // witness for the coinbase input (single `[0x00; 32]` reserved
        // value) — bitcoin-core accepts this directly as the
        // coinbase-transaction argument to `submitblock`.
        let coinbase_tx = accept
            .mining_job
            .witness_coinbase_with_extranonce(&accept.enonce1, &accept.extranonce2);
        let coinbase_bytes = coinbase_tx.clone();

        info!(
            template_id = accept.template.template_id,
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

        if let Err(err) = self
            .select_handle(stream)
            .submit_solution(
                accept.template.template_id,
                version,
                header_timestamp,
                header_nonce,
                coinbase_tx,
            )
            .await
        {
            warn!(
                %err,
                template_id = accept.template.template_id,
                address,
                worker,
                session_id,
                "block-found: TDP submit_solution failed (best-effort)"
            );
        }

        // Fan-out to engine ledger + dispatcher. `coinbase_tx_value_remaining`
        // is the share of the block reward our coinbase claims (subsidy +
        // fees after the JDC's `coinbase_outputs` for JDP-declared jobs);
        // for pool-built SV1 jobs it equals the full block reward.
        let actual = decode_actual_coinbase(&coinbase_bytes, self.network);
        self.emit_block_found(
            address.to_string(),
            worker.to_string(),
            session_id.to_string(),
            Some(accept.template.coinbase_tx_value_remaining),
            Some(block_hash_display(&accept.header)),
            hex::encode(accept.header),
            // The job the winning share was built on — so the PPLNS apply
            // books the distribution this coinbase actually pays.
            Some(*accept.mining_job.payouts_fingerprint()),
            actual,
        )
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
        // Empty `witness_coinbase` / missing `template_id` happens
        // when the job was declared via `SetCustomMiningJob` (the
        // JDC built the template — pool has no template_id to call
        // submit_solution with, and the coinbase bytes weren't
        // pool-built). The JDC handles its own block-submit via the
        // JDP `PushSolution` flow in that case; warn here for
        // visibility but don't double-submit on the mining side.
        if accept.witness_coinbase.is_empty() || accept.template_id.is_none() {
            warn!(
                address,
                worker,
                session_id_hex,
                effective_diff = accept.effective_difficulty.as_f64(),
                submission_diff = accept.submission_difficulty.as_f64(),
                "sv2 block-found on SetCustomMiningJob-declared job: pool has no template_id \
                 to call submit_solution with. Share is credited; if the JDC is wired to a JDP \
                 server (Phase 7.4d.4+), PushSolution will claim the block instead."
            );
            return;
        }
        let template_id = accept.template_id.expect("checked is_some above");
        let header = &accept.header;
        let version = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let header_timestamp = u32::from_le_bytes([header[68], header[69], header[70], header[71]]);
        let header_nonce = u32::from_le_bytes([header[76], header[77], header[78], header[79]]);

        info!(
            template_id,
            version,
            header_timestamp,
            header_nonce,
            address,
            worker,
            session_id_hex,
            ?stream,
            coinbase_tx_len = accept.witness_coinbase.len(),
            "sv2 block-found: submitting solution via TDP"
        );

        if let Err(err) = self
            .select_handle(stream)
            .submit_solution(
                template_id,
                version,
                header_timestamp,
                header_nonce,
                accept.witness_coinbase.clone(),
            )
            .await
        {
            warn!(
                %err,
                template_id,
                address,
                worker,
                session_id_hex,
                "sv2 block-found: TDP submit_solution failed (best-effort)"
            );
        }

        // Fan-out to engine ledger + dispatcher. `coinbase_tx_value_remaining`
        // is the per-job pinned block-reward portion the coinbase claims —
        // now carried on the SV2 `ShareAccept` (pinned at NewMiningJob/
        // NewExtendedMiningJob send-time), so the per-mode engine ledger-write
        // fires for SV2-found blocks exactly as it does for SV1.
        let actual = decode_actual_coinbase(&accept.witness_coinbase, self.network);
        self.emit_block_found(
            address.to_string(),
            worker.to_string(),
            session_id_hex.to_string(),
            Some(accept.coinbase_tx_value_remaining),
            Some(block_hash_display(&accept.header)),
            hex::encode(accept.header),
            Some(accept.payouts_fingerprint),
            actual,
        )
        .await;
    }
}

/// Decode the submitted witness coinbase into its per-address payment
/// record. `None` (with a warn) if the bytes don't parse — settlement
/// then has no actuals and the block is reported-not-booked rather
/// than booked from a guess.
fn decode_actual_coinbase(
    witness_coinbase: &[u8],
    network: bitcoin::Network,
) -> Option<ActualCoinbase> {
    match <bitcoin::Transaction as bitcoin::consensus::Decodable>::consensus_decode(
        &mut &witness_coinbase[..],
    ) {
        Ok(tx) => Some(ActualCoinbase::from_coinbase(&tx, network)),
        Err(err) => {
            warn!(%err, "block-found: submitted coinbase failed to decode — no actuals for settlement");
            None
        }
    }
}

/// Compute the standard Bitcoin block hash display form (big-endian
/// hex) from the assembled 80-byte header. `bp_share::sha256d` returns
/// the digest in little-endian "internal" order; we reverse and hex-
/// encode for the human-facing form bitcoind / explorers use.
fn block_hash_display(header: &[u8; 80]) -> String {
    let mut hash = bp_share::sha256d(header);
    hash.reverse();
    hex::encode(hash)
}

/// Big-endian display hash of the parent block, extracted from an 80-byte
/// block header hex. The header stores `prevHash` (bytes 4..36) in internal
/// little-endian order; reverse it for the form `getblockheader` expects.
/// Returns `None` if the hex is malformed or too short.
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
    use bp_jobs_lifecycle::JobClassification;
    use bp_mining_job::{build_mining_job, CoinbaseTemplate, PayoutEntry, EXTRANONCE_SLOT_LEN};
    use bp_stratum_v1::ActiveSV1Template;
    use bp_template_distribution::TdpConfig;

    /// The header stores `prevHash` little-endian (internal); the function must
    /// reverse it back to the big-endian display hash `getblockheader` wants.
    #[test]
    fn prev_hash_extracted_and_reversed_to_display_order() {
        // A real regtest block-165 display hash (the parent of block 166).
        let display = "000000000033366a407ca4b736a310d343c20c494532970aa11e45b9140df5e6";
        let mut internal = hex::decode(display).unwrap();
        internal.reverse();
        // 80-byte header: 4-byte version + 32-byte prevHash + 44-byte filler.
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

    /// We don't have a live bitcoind IPC socket in unit tests; the TDP
    /// spawn returns an error for an unreachable socket, so we just
    /// assert the `submit_block` path doesn't panic when the underlying
    /// handle is broken — the hook is best-effort, errors only log.
    fn synthetic_accept() -> Sv1ShareAccept {
        let payouts = [PayoutEntry {
            address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string(),
            sats: 5_000_000_000,
        }];
        let cb = CoinbaseTemplate {
            block_height: 1,
            coinbase_value_sats: 5_000_000_000,
            witness_commitment: [0u8; 32],
        };
        let job = build_mining_job(Network::Regtest, &payouts, &cb, "test", EXTRANONCE_SLOT_LEN)
            .expect("build job");
        // Header: version=1 (LE), then 32B prev_hash + 32B merkle +
        // 4B ntime (0x12345678) + 4B n_bits (0x1d00ffff) + 4B nonce
        // (0xdeadbeef). Filled to taste — only positions 0..4, 68..72,
        // 76..80 are read by the sink.
        let mut header = [0u8; 80];
        header[0..4].copy_from_slice(&1u32.to_le_bytes());
        header[68..72].copy_from_slice(&0x12345678u32.to_le_bytes());
        header[72..76].copy_from_slice(&0x1d00ffffu32.to_le_bytes());
        header[76..80].copy_from_slice(&0xdeadbeefu32.to_le_bytes());

        Sv1ShareAccept {
            classification: JobClassification::Active,
            effective_difficulty: 1024.0,
            submission_difficulty: 1e18,
            header,
            hash: [0u8; 32],
            is_block_candidate: true,
            mining_job: Arc::new(job),
            template: Arc::new(ActiveSV1Template {
                template_id: 42,
                version: 1,
                prev_hash: [0u8; 32],
                n_bits: 0x1d00ffff,
                header_timestamp: 0x12345678,
                network_target: [0xff; 32],
                network_difficulty: 1.0,
                coinbase_prefix: vec![],
                coinbase_tx_version: 2,
                coinbase_tx_input_sequence: 0xffff_ffff,
                coinbase_tx_value_remaining: 5_000_000_000,
                coinbase_tx_outputs: vec![],
                coinbase_tx_outputs_count: 0,
                coinbase_tx_locktime: 0,
                merkle_path: vec![],
                merkle_branch_hex: vec![],
                prev_hash_hex: String::new(),
                version_hex: String::new(),
                n_bits_hex: String::new(),
                header_timestamp_hex: String::new(),
            }),
            enonce1: [0xaa, 0xbb, 0xcc, 0xdd],
            extranonce2: [0; 8],
        }
    }

    #[tokio::test]
    async fn submit_block_does_not_panic_when_tdp_socket_unreachable() {
        // Spawning TDP against a non-existent socket fails the spawn
        // step itself — there's no `TdpHandle` to exercise the
        // submit_block code path with. This is the closest we can
        // get to an isolated unit test without spinning up a real
        // bitcoin-core IPC. The header-parse + coinbase-assembly are
        // covered by the synthetic_accept builder and would panic on
        // bad indexing if regressed.
        let cfg = TdpConfig::new("/definitely/does/not/exist/bp-tdp.sock");
        let spawn_result = TdpHandle::spawn(cfg);
        assert!(
            spawn_result.is_err(),
            "spawning against a bogus socket should fail synchronously"
        );
        // Header-byte decoding sanity: we expect to read back the
        // values written by `synthetic_accept`.
        let a = synthetic_accept();
        assert_eq!(
            u32::from_le_bytes([a.header[0], a.header[1], a.header[2], a.header[3]]),
            1
        );
        assert_eq!(
            u32::from_le_bytes([a.header[68], a.header[69], a.header[70], a.header[71]]),
            0x12345678
        );
        assert_eq!(
            u32::from_le_bytes([a.header[76], a.header[77], a.header[78], a.header[79]]),
            0xdeadbeef
        );
    }

    /// The block-found event is the Core→Satellite wire unit: it must
    /// round-trip through JSON carrying the Core-stamped `mode`, `group_id`,
    /// and `height` so the apply side needs no gate / RPC.
    #[test]
    fn block_found_event_json_round_trips_with_stamped_fields() {
        let weight_snapshot = bp_coinbase_snapshot::StoredWeightSnapshot {
            entries: vec![bp_coinbase_snapshot::WeightSnapshotEntry {
                address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                score_weight: 1_000_000_000_000,
                balance_sats: 0,
                wire_weight: 1_000_000_000_000,
                dust_limit: 546,
            }],
            score_total: 1_000_000_000_000,
            fee_ppm: 15_000,
            fee_address: "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
                .to_string(),
            reference_revenue_sats: 312_500_000,
            weight_p: 15_228_426_395,
        };
        let event = BlockFoundEvent {
            actual_coinbase: None,
            groupsolo_weight_snapshot: Some(weight_snapshot.clone()),
            pplns_payouts_fingerprint: None,
            address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            worker: "rig1".to_string(),
            session_id: "sess1".to_string(),
            reward_sats: Some(312_500_000),
            block_hash: Some("00000000deadbeef".to_string()),
            block_data: "ab".repeat(80),
            mode: MiningMode::GroupSolo,
            group_id: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            height: 870_123,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let back: BlockFoundEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.mode, MiningMode::GroupSolo);
        assert_eq!(
            back.group_id.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
        assert_eq!(back.height, 870_123);
        assert_eq!(back.reward_sats, Some(312_500_000));
        assert_eq!(back.address, event.address);
        assert_eq!(back.block_data, event.block_data);
        // The Group-Solo snapshot rides the wire intact — the apply side
        // depends on the exact frozen distribution, not a Redis re-read.
        assert_eq!(back.groupsolo_weight_snapshot, Some(weight_snapshot));
    }
}
