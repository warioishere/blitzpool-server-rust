// SPDX-License-Identifier: AGPL-3.0-or-later

//! `BlockSubmissionSink` implementations.
//!
//! When a Stratum share's hash meets the network target the template's
//! `n_bits` encodes, the per-protocol server fires the block-submission
//! hook. The Rust port
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
//! SV1 and SV2 differ only in where the coinbase bytes come from (SV1
//! reassembles them from the job + extranonces, SV2 hands them over); the
//! submit and the block-found emission are one path,
//! [`TdpBlockSubmissionSink::submit_and_emit`].

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bp_bitcoin::BitcoinRpc;
use bp_coinbase_snapshot::ActualCoinbase;
use bp_common::{AddressId, MiningMode, StreamKind};
use bp_config::{AppConfig, Role};
use bp_group_solo_engine::engine::GroupSoloEngine;
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
use crate::pending_blocks::{put_pending_block, PendingBlock, PendingGroup, SettlementMode};

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
    /// Wire form of [`Booking`]: `Some(reward)` = book, `None` = record
    /// only. Read it through [`Self::booking`]. The field stays an `Option`
    /// because the event rides a stream that other processes replay, and a
    /// rolling deploy has old and new producers and consumers in flight at
    /// once.
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
    /// coinbase was built from, resolved by the Core at the block-found
    /// instant — for EVERY snapshot-backed mode (PPLNS and Group-Solo
    /// alike; see `TdpBlockSubmissionSink::resolve_weight_snapshot`).
    ///
    /// Carried so the apply side never re-reads a Redis key that has
    /// moved on or expired: Group-Solo's per-(group, finder) key is
    /// overwritten by continuous template rebuilds, and PPLNS's per-job
    /// key TTLs out inside the confirmation window. `None` → the apply
    /// side has to fall back to a late read under the fingerprint, which
    /// usually finds nothing.
    ///
    /// The wire name stays `groupsolo_weight_snapshot`: this rides a
    /// Redis stream that other processes replay, and a rolling deploy has
    /// both spellings in flight at once. The Rust name is generic because
    /// the field never was Group-Solo-specific — treating it as such is
    /// exactly what left PPLNS without one.
    #[serde(default, rename = "groupsolo_weight_snapshot")]
    pub weight_snapshot: Option<bp_coinbase_snapshot::StoredWeightSnapshot>,
    /// Identity of the payout list this block's coinbase pays, taken off the
    /// job the winning share was built on. It is what the Core resolves
    /// [`Self::weight_snapshot`] under, so what gets booked is what the
    /// coinbase actually paid instead of whatever a shared snapshot key holds
    /// by then. It rides along afterwards as the apply side's fallback key
    /// (and Group-Solo's post-apply cleanup target). `None`/zero when the
    /// pool did not build the coinbase (`SetCustomMiningJob`) or the job path
    /// carries no fingerprint.
    ///
    /// Named for PPLNS because that is where it started; the name is on the
    /// wire format of a stream other processes replay, so it stays.
    #[serde(default)]
    pub pplns_payouts_fingerprint: Option<[u8; 32]>,
    /// What the found block's coinbase ACTUALLY paid, decoded from the
    /// submitted coinbase transaction on the Core. The weight-model
    /// settlement books `claim − paid` from this — the event carries it
    /// so a Satellite never has to re-derive it from chain data.
    /// `None` when the submitted coinbase did not decode, or on a
    /// [`Booking::RecordOnly`] event; PPLNS and Group-Solo then book
    /// nothing (see `BlockFoundApplier::gate_or_apply`).
    #[serde(default)]
    pub actual_coinbase: Option<ActualCoinbase>,
}

impl BlockFoundEvent {
    /// What this event asks the apply side to do with the ledger.
    pub(crate) fn booking(&self) -> Booking {
        match self.reward_sats {
            Some(reward_sats) => Booking::Book { reward_sats },
            None => Booking::RecordOnly,
        }
    }
}

/// Whether a found block goes into its mode's ledger, or is only recorded
/// (`blocks_entity` row + notification).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Booking {
    /// Book it. `reward_sats` is the block-reward portion the coinbase
    /// claims (subsidy + fees after any JDC coinbase outputs). PPLNS and
    /// Group-Solo only log it: they settle from the block's own coinbase.
    /// Blockparty builds its history row from it.
    Book { reward_sats: u64 },
    /// Record the block without any ledger write. For a block whose
    /// distribution was never bookable, and for a pool-built SV2 custom-job
    /// coinbase that did not decode.
    RecordOnly,
}

impl Booking {
    /// The event's wire form, see [`BlockFoundEvent::reward_sats`].
    fn wire_reward_sats(self) -> Option<u64> {
        match self {
            Self::Book { reward_sats } => Some(reward_sats),
            Self::RecordOnly => None,
        }
    }
}

/// What identifies a JDC-found block in `blocks_entity`.
///
/// The four used to travel as four consecutive `String` parameters through two
/// signatures — trait method and the concrete one it forwards to — where any
/// two could be exchanged in silence. They were, deliberately, in a check:
/// `cargo check` and 175 `blitzpool` tests stayed green with the session id in
/// the address column and the header in the hash column.
///
/// ⚠️ `session_id` lands in `blocks_entity."sessionId"`, which is
/// `varchar(8)`. Postgres does not truncate on INSERT, it errors.
#[derive(Clone, Debug)]
pub(crate) struct FoundBlockRecord {
    pub(crate) miner_address: String,
    pub(crate) session_id: String,
    /// Block hash, display form.
    pub(crate) block_hash: String,
    /// The 80-byte header as hex.
    pub(crate) block_data: String,
}

/// What the FINDER of a block knows about it: the caller-supplied half of
/// [`BlockFoundEvent`], against the half [`TdpBlockSubmissionSink::emit_block_found`]
/// resolves on the Core (`mode`, `group_id`, `height`, `weight_snapshot`).
///
/// A struct because these travelled as eight positional parameters through
/// that one signature, four of them `String` and one `Option<String>`.
/// Measured 2026-08-22: exchanging `worker` and `session_id` — writing the
/// literal `"jdp"` into `blocks_entity."sessionId"` and the session id into
/// `"worker"` — compiled and left all 179 `blitzpool` tests green. The one
/// pairing that IS caught, address against session id, is caught by
/// `varchar(8)` refusing the longer value rather than by any test, and only
/// when a database is reachable at all.
///
/// Named fields do not make the exchange impossible — `address:
/// session_id.clone()` still compiles. They make it visible AT THE CALL SITE
/// instead of only in the signature, which is the whole distance between a
/// reviewable mistake and an invisible one. Making it impossible needs a
/// newtype per string; that reaches far past this boundary and was weighed
/// against it deliberately.
struct BlockFoundInputs {
    /// Miner-authorized payout address. Also what the mode gate is asked, so
    /// a wrong value here does not merely mis-record a column: it books the
    /// block against another mode, or against `lookup_mode`'s Solo default,
    /// which writes no ledger at all.
    address: String,
    worker: String,
    /// ⚠️ Lands in `blocks_entity."sessionId"`, which is `varchar(8)`.
    /// Postgres does not truncate on INSERT, it errors.
    session_id: String,
    booking: Booking,
    /// Big-endian block-hash hex. Not an `Option` here even though
    /// [`BlockFoundEvent::block_hash`] is one: every caller has the hash. The
    /// event keeps its `Option` because it is deserialized off a stream that
    /// other processes replay, so events predating the field still arrive.
    block_hash: String,
    /// The 80-byte header as hex (LE), for `blocks_entity.blockData`.
    block_data: String,
    pplns_payouts_fingerprint: Option<[u8; 32]>,
    actual_coinbase: Option<ActualCoinbase>,
}

/// `BlockSubmissionSink` for both SV1 + SV2. Forwards every
/// block-candidate share to bitcoin-core via TDP **and**
/// fans the event out to the per-mode engine ledger
/// (`PplnsEngine::on_block_found` / `GroupSoloEngine::on_block_found`)
/// plus the [`NotificationDispatcher`] for subscriber notifications.
///
/// The mode gate, the RPC (for the height) and Postgres (for the
/// `blocks_entity` row) are required: a block-found cannot be emitted
/// without them. The engines and the dispatcher are optional: when one is
/// absent, the corresponding step logs and continues. The TDP submit is the
/// authoritative block-propagation path; engine + dispatcher are
/// observability + accounting.
pub(crate) struct TdpBlockSubmissionSink {
    /// Default stream handle (PPLNS-autoscaled). Submission target for every
    /// PPLNS job, and the fallback when an alt stream isn't wired.
    tdp: TdpHandle,
    /// Fixed-reservation alt stream handles keyed by `StreamKind` (Solo /
    /// GroupSolo / Blockparty). Empty until wired; an alt-stream job is only
    /// produced when boot wired both the template stream and this handle, so
    /// routing stays consistent (the handle knows the job's template_id).
    alt: HashMap<StreamKind, TdpHandle>,
    mode_gate: Arc<BlitzpoolModeGate>,
    bitcoin_rpc: BitcoinRpc,
    /// Postgres pool for writing to `blocks_entity` on block-found.
    pool: PgPool,
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
    /// ext 0x0003/Implementation Notes settlement fan-out — see
    /// [`crate::settlement`].
    ///
    /// A settlement from ANY source invalidates every published payout
    /// distribution: the published weights encode the pre-settlement
    /// balances, so a 0x0003 JDC still mining them would pay those
    /// balances a second time. Wiring it only to JDP-declared blocks left
    /// every SV1/SV2 block skipping the invalidation; wiring it only
    /// in-process left every block skipping it under the role split,
    /// where the process that books is not the one holding the registry.
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

    /// The sink as the binary wires it: the ONE way SV1, SV2 and the JDP
    /// ledger booker build theirs, so a block books the same way whichever of
    /// them found it. They used to be three hand-copied builder chains, and
    /// the JDP copy had lost `with_settle_handle` — a block it booked on the
    /// immediate path (parking failed) never invalidated the published
    /// distributions.
    ///
    /// On the front the sink also produces onto the block-found stream: the
    /// payout satellite applies the ledger and the notify satellite fans out
    /// the push. A front always produces (front + payout can't share a
    /// process; see the boot guard in main.rs), so this gates on the front
    /// role alone.
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
        .with_blockparty(engines.blockparty.clone())
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

    /// Wire the ext 0x0003/Implementation Notes settlement hook onto this
    /// sink's applier, so a block booked through the Stratum path invalidates
    /// the published payout distributions exactly like a JDP-declared one.
    pub(crate) fn with_settle_handle(
        mut self,
        signal: crate::settlement::SettlementSignal,
    ) -> Self {
        self.applier.settle = Some(signal);
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

    /// Attach the fan-out dependencies. Returns `Self` so
    /// the caller can chain at construction. Passing `None` for the
    /// dispatcher (no transport adapters wired) keeps the engine
    /// ledger-write live but skips notifications; passing `None` for
    /// PPLNS collapses its `on_block_found` call to a logged no-op.
    pub(crate) fn with_fanout(
        mut self,
        pplns: Option<PplnsEngine>,
        group_solo: GroupSoloEngine,
        dispatcher: Option<Arc<NotificationDispatcher>>,
    ) -> Self {
        self.applier.pplns = pplns;
        self.applier.group_solo = Some(group_solo);
        self.applier.dispatcher = dispatcher;
        self
    }

    /// Book a block whose coinbase the pool did NOT build — a JDC declared the
    /// job and owns its coinbase; the pool only issued the payout set, and the
    /// ext-0x0003 declare-time check proved the coinbase carries it verbatim.
    /// That proof is what `payouts_fingerprint` names, so the ledger books the
    /// distribution the block actually paid rather than a rebuilt guess.
    ///
    /// `worker` is fixed to `jdp` — a declared job has no Stratum worker name.
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
            pplns_payouts_fingerprint: Some(payouts_fingerprint),
            actual_coinbase,
        })
        .await
    }

    /// The same record WITHOUT the ledger: `blocks_entity` row plus the
    /// notification, no engine write.
    ///
    /// For a block whose distribution was never bookable — its settlement
    /// snapshot did not land, so nothing can compute `claim − paid`. The
    /// block is still the pool's, and a block that exists in nobody's history
    /// is a block the operator has to find in a log.
    ///
    /// [`Booking::RecordOnly`] is what holds the ledger off. The fingerprint
    /// and the coinbase go as `None` for the same reason — there is no
    /// distribution to resolve and nothing may be settled from a guess.
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
            pplns_payouts_fingerprint: None,
            actual_coinbase: None,
        })
        .await
    }

    /// Convenience: wrap in `Arc<dyn BlockSubmissionSink>` so the
    /// caller can drop it directly into `bp_stratum_v1::ServerHooks
    /// { block_sink, … }`.
    pub(crate) fn into_sv1_arc(self) -> Arc<dyn Sv1BlockSubmissionSink> {
        Arc::new(self)
    }

    /// Symmetric helper for the SV2 mining server's
    /// [`bp_stratum_v2::hooks::BlockSubmissionSink`] hook slot. The
    /// underlying sink is shape-identical; the SV2 trait just has a
    /// different `ShareAccept` shape.
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
    async fn emit_block_found(&self, found: BlockFoundInputs) -> bool {
        let BlockFoundInputs {
            address,
            worker,
            session_id,
            booking,
            block_hash,
            block_data,
            pplns_payouts_fingerprint,
            actual_coinbase,
        } = found;
        // Resolve the payout mode on the Core (the only side with the gate)
        // and stamp it onto the event so the apply side needs no gate.
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

        // Persist the durable Core record (the Redis-independent safety net
        // the ledger can be reconciled against). Stays on the Core. Best-
        // effort: failure is logged but does not abort the apply below.
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

        // Stamp the distribution the winning job's coinbase pays into the
        // event, looked up by that job's payout-list fingerprint, so the apply
        // side books exactly that. A zeroed fingerprint means the pool did not
        // build this coinbase (`SetCustomMiningJob`) — there is no
        // distribution of ours to find.
        let job_payouts_fingerprint = pplns_payouts_fingerprint.filter(|fp| fp != &[0u8; 32]);
        let weight_snapshot = self
            .resolve_weight_snapshot(
                resolved.mode,
                &address,
                resolved.group_id.as_deref(),
                job_payouts_fingerprint,
                height,
            )
            .await;

        let event = BlockFoundEvent {
            address,
            worker,
            session_id,
            pplns_payouts_fingerprint,
            reward_sats: booking.wire_reward_sats(),
            block_hash: Some(block_hash),
            block_data,
            mode: resolved.mode,
            group_id: resolved.group_id,
            height,
            weight_snapshot,
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

    /// Resolve the settlement inputs a found block's coinbase was built
    /// from, for the event the apply side consumes.
    ///
    /// **Every mode is decided here, by an exhaustive `match`.** It used to
    /// be `if mode == GroupSolo`, and PPLNS fell out of it silently: its
    /// blob went to the apply side empty and the apply re-read the
    /// fingerprint key `confirmation_depth` blocks later, by which time the
    /// key had usually expired and the settlement inputs were gone for good.
    /// An `if` cannot be exhaustive; a `match` can, so the next mode cannot
    /// be forgotten the same way.
    ///
    /// Resolving HERE — at the block-found instant, on the process that
    /// holds the engines — is the point. The key is certainly alive now and
    /// usually is not later, and it is the only store that ever holds these
    /// inputs (the Redis→Postgres backup skips per-job snapshot keys).
    ///
    /// `None` means the apply side has no distribution in hand. What that
    /// costs differs per mode and is decided by the caller, not here:
    /// Group-Solo refuses to book (its only substitute would be a rebuild
    /// against a round that has moved), PPLNS parks anyway and retries the
    /// read at apply time. Every way of reaching `None` says which one it
    /// was, because the operator's next step differs sharply: a JD-client
    /// coinbase (zero fingerprint) must NOT be reprocessed at all — the pool
    /// did not build it — while a Redis miss must be reprocessed from the
    /// block's own coinbase, and a parse fault is a pool bug.
    async fn resolve_weight_snapshot(
        &self,
        mode: MiningMode,
        address: &str,
        group_id: Option<&str>,
        payouts_fingerprint: Option<[u8; 32]>,
        height: i32,
    ) -> Option<bp_coinbase_snapshot::StoredWeightSnapshot> {
        // Both snapshot-backed modes need the winning job's payout list.
        // Checked once, before the per-mode arms, because the answer — and
        // the operator's instruction — is the same for both.
        let fingerprint = || match payouts_fingerprint {
            Some(fp) => Some(fp),
            None => {
                warn!(
                    address,
                    height,
                    ?mode,
                    "block-found: job carries no payout fingerprint — the pool did not build \
                     this coinbase (JD-client custom job), so there is no pool-side \
                     distribution to book. Do NOT reprocess."
                );
                None
            }
        };
        match mode {
            // Solo pays a single output and writes no engine ledger row;
            // Blockparty recomputes its fixed per-member percentages from
            // the DB and books idempotently on the block hash. Neither
            // resolves a snapshot, so neither has one to carry. Kept as
            // explicit arms so a mode that DOES need one cannot be added
            // without deciding this.
            MiningMode::Solo | MiningMode::Blockparty => None,
            MiningMode::Pplns => {
                let engine = self.applier.pplns.as_ref().or_else(|| {
                    warn!(
                        address,
                        height, "block-found: PPLNS mode but the engine is not configured"
                    );
                    None
                })?;
                let fingerprint = fingerprint()?;
                match engine.weight_snapshot_for_block_found(&fingerprint).await {
                    Ok(snap) => Some(snap),
                    Err(err) => {
                        // NOT fatal for PPLNS: the apply side reads the
                        // fingerprint again. That read usually loses the
                        // race with the TTL, so this is worth an error,
                        // but the block still gets its second chance.
                        error!(
                            %err,
                            address,
                            height,
                            fingerprint = %hex::encode(fingerprint),
                            "block-found: PPLNS distribution lookup failed — parking the block \
                             without its settlement inputs; the apply will re-read the \
                             fingerprint, which usually loses to the snapshot TTL"
                        );
                        None
                    }
                }
            }
            MiningMode::GroupSolo => {
                let engine = self.applier.group_solo.as_ref().or_else(|| {
                    warn!(
                        address,
                        height, "block-found: Group-Solo mode but the engine is not configured"
                    );
                    None
                })?;
                let Some(group_id_str) = group_id else {
                    warn!(
                        address,
                        height,
                        "block-found: Group-Solo mode but the mode-gate returned no group_id"
                    );
                    return None;
                };
                let fingerprint = fingerprint()?;
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
                            "block-found: Group-Solo distribution lookup failed — the block is \
                             NOT booked and must be reprocessed from its own coinbase"
                        );
                        None
                    }
                }
            }
        }
    }
}

impl BlockFoundApplier {
    /// Build an applier from the back-office engines + dispatcher + Redis —
    /// the Satellite's block-found stream consumer uses this to run the same
    /// apply the front runs in-process on a publish-failure fallback.
    ///
    /// `settle` is an argument, not a builder step: the payout satellite's
    /// applier was built without it, so a block it booked on the immediate
    /// path never invalidated the published distributions.
    pub(crate) fn new(
        pplns: Option<PplnsEngine>,
        group_solo: Option<GroupSoloEngine>,
        blockparty: Option<Arc<dyn bp_blockparty_engine::BlockpartyApi>>,
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

    /// ext 0x0003/Implementation Notes: a ledger settlement just happened.
    /// Invalidate every published payout distribution and force a fresh
    /// publish, so no JDC keeps declaring against weights this block already
    /// settled.
    async fn settle_distributions(&self) {
        if let Some(signal) = self.settle.as_ref() {
            signal.settle().await;
        }
    }

    /// Block-found for any mode that books against a payout
    /// distribution: park the settlement inputs until the block reaches
    /// `confirmation_depth`, so a block that orphans never books a
    /// phantom. Falls back to an immediate apply when gating is not
    /// possible (no Redis / no block hash) or the store write fails, so
    /// a block's distribution is never silently lost.
    ///
    /// One path for PPLNS and Group-Solo. What is parked are the inputs
    /// — the distribution's settlement inputs plus what the coinbase
    /// actually paid — so the apply recomputes and lands on the same
    /// satoshis whenever it runs. That is also why several blocks may be
    /// pending at once: nothing absolute is frozen, so nothing an
    /// earlier block wrote can be clobbered by a later one.
    ///
    /// `group` decides the mode. `weight_snapshot` is the distribution
    /// the block's coinbase pays, resolved from the winning job's payout
    /// list — nothing here may substitute another one, because a
    /// rebuild would book a distribution the chain did not pay.
    #[allow(clippy::too_many_arguments)]
    async fn gate_or_apply(
        &self,
        address_str: &str,
        height: i32,
        reward: u64,
        block_hash_hex: Option<&str>,
        weight_snapshot: Option<bp_coinbase_snapshot::StoredWeightSnapshot>,
        actual: Option<&bp_coinbase_snapshot::ActualCoinbase>,
        payouts_fingerprint: Option<[u8; 32]>,
        group: Option<PendingGroup>,
    ) {
        let mode = SettlementMode::of(group.as_ref()).label();
        // Settlement is `claim − paid` against the block's OWN coinbase,
        // so its payments are not optional: without them there is
        // nothing to settle against.
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

        if let (Some(redis), Some(block_hash)) = (self.redis.as_ref(), block_hash_hex) {
            let pending = PendingBlock {
                block_hash: block_hash.to_string(),
                found_at_ms: chrono::Utc::now().timestamp_millis(),
                block_height: height,
                weight_snapshot: weight_snapshot.clone(),
                actual_coinbase: Some(actual.clone()),
                payouts_fingerprint,
                group: group.clone(),
            };
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
        } else if self.redis.is_none() {
            warn!(
                address = address_str,
                height,
                mode,
                "block-found: confirmation-gating unavailable (no Redis); applying immediately"
            );
        } else {
            warn!(address = address_str, height, mode,
                "block-found: confirmation-gating unavailable (no block hash); applying immediately");
        }

        self.apply_now(
            address_str,
            height,
            reward,
            weight_snapshot,
            actual,
            payouts_fingerprint,
            group,
        )
        .await;
    }

    /// Immediate (non-gated) apply — the fallback arm of
    /// [`Self::gate_or_apply`], and the same settlement the confirmation
    /// watcher runs.
    #[allow(clippy::too_many_arguments)]
    async fn apply_now(
        &self,
        address_str: &str,
        height: i32,
        reward: u64,
        weight_snapshot: Option<bp_coinbase_snapshot::StoredWeightSnapshot>,
        actual: &bp_coinbase_snapshot::ActualCoinbase,
        payouts_fingerprint: Option<[u8; 32]>,
        group: Option<PendingGroup>,
    ) {
        let mode = SettlementMode::of(group.as_ref());
        let label = mode.label();
        let applied = settle_block(
            self.pplns.as_ref(),
            self.group_solo.as_ref(),
            mode,
            height,
            actual,
            weight_snapshot,
            payouts_fingerprint,
        )
        .await;
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
                group_id = group.as_ref().map(|g| g.group_id.as_str()).unwrap_or("-"),
                height,
                "block-found: Group-Solo group id or finder unusable — NOT booked"
            ),
            Err(SettleFailure::Engine(err)) => warn!(
                %err, address = address_str, height,
                "block-found: immediate apply failed"
            ),
        }
    }

    /// Apply a block-found event to the per-mode engine ledger + dispatcher.
    /// Reads everything it needs from the (Core-stamped) event — no mode
    /// gate, no RPC, no `blocks_entity` write — so it runs unchanged on a
    /// Satellite consuming the event off a stream. [`Booking::RecordOnly`]
    /// skips the engine ledger-write but still fires the notification.
    /// Best-effort: every step's failure is logged and the others continue.
    pub(crate) async fn apply_block_found(&self, event: &BlockFoundEvent) {
        let address_str = event.address.as_str();
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

        match (event.mode, event.booking()) {
            (MiningMode::Solo, _) => {
                info!(
                    address = address_str,
                    height,
                    "block-found: solo mode — no engine ledger-write needed (single-payout coinbase)"
                );
            }
            (_, Booking::RecordOnly) => {
                // The producer said why (see `Booking::RecordOnly`); this side
                // only skips the ledger. The Core already wrote the
                // `blocks_entity` row, and the dispatch below still runs.
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
                        block_hash_hex.as_deref(),
                        event.weight_snapshot.clone(),
                        event.actual_coinbase.as_ref(),
                        event.pplns_payouts_fingerprint,
                        None, // pool-wide accounting: no group context
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
            ) => {
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
            (
                MiningMode::GroupSolo,
                Booking::Book {
                    reward_sats: reward,
                },
            ) => {
                match (event.group_id.as_deref(), self.group_solo.as_ref()) {
                    (Some(group_id_str), Some(_engine)) => {
                        // Refuse early rather than park a blob the apply
                        // could never resolve.
                        if let Err(err) = uuid::Uuid::parse_str(group_id_str) {
                            warn!(
                                %err,
                                address = address_str,
                                group_id = group_id_str,
                                "block-found: Group-Solo group_id is not a valid UUID — skipping ledger-write"
                            );
                            return;
                        }
                        // Without the distribution the block's coinbase pays
                        // there is nothing safe to book: the substitutes all
                        // claim on-chain payments the chain did not make.
                        // Confirmation-gate (park until confirmed) when
                        // possible, else apply immediately — mirrors the
                        // PPLNS arm so an orphan / non-chain-extending
                        // candidate never books a phantom into the group
                        // ledger.
                        if event.weight_snapshot.is_some() {
                            self.gate_or_apply(
                                address_str,
                                height,
                                reward,
                                block_hash_hex.as_deref(),
                                event.weight_snapshot.clone(),
                                event.actual_coinbase.as_ref(),
                                event.pplns_payouts_fingerprint,
                                Some(PendingGroup {
                                    group_id: group_id_str.to_string(),
                                    finder: address.as_str().to_string(),
                                }),
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
        // Assemble the witness-form coinbase. `witness_coinbase_with_
        // extranonce` returns the full bytes including the SegWit
        // witness for the coinbase input (single `[0x00; 32]` reserved
        // value) — bitcoin-core accepts this directly as the
        // coinbase-transaction argument to `submitblock`.
        let coinbase_tx = accept
            .mining_job
            .witness_coinbase_with_extranonce(&accept.enonce1, &accept.extranonce2);
        self.submit_and_emit(
            PoolBuiltSolution {
                protocol: "sv1",
                template_id: accept.template.template_id,
                header: &accept.header,
                coinbase_tx,
                // For pool-built SV1 jobs this equals the full block reward.
                reward_sats: accept.template.coinbase_tx_value_remaining,
                // The job the winning share was built on — so the apply
                // books the distribution this coinbase actually pays.
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

/// A solution on a job whose coinbase the pool built, as either protocol
/// hands it over.
pub(crate) struct PoolBuiltSolution<'a> {
    /// Log label only.
    pub(crate) protocol: &'static str,
    pub(crate) template_id: u64,
    pub(crate) header: &'a [u8; 80],
    /// The witness-form coinbase of the winning job.
    pub(crate) coinbase_tx: Vec<u8>,
    /// Block-reward portion the job's coinbase claims, pinned at job send
    /// time.
    pub(crate) reward_sats: u64,
    pub(crate) payouts_fingerprint: [u8; 32],
}

/// `(version, header_timestamp, header_nonce)` from an assembled 80-byte
/// header: bytes 0..4, 68..72 and 76..80, little-endian per the consensus
/// encoding. The version is the miner-rolled one, which is why it is read
/// back from the header rather than taken from the template.
fn header_fields(header: &[u8; 80]) -> (u32, u32, u32) {
    let version = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let header_timestamp = u32::from_le_bytes([header[68], header[69], header[70], header[71]]);
    let header_nonce = u32::from_le_bytes([header[76], header[77], header[78], header[79]]);
    (version, header_timestamp, header_nonce)
}

impl TdpBlockSubmissionSink {
    /// Submit a pool-built solution through the stream's TDP handle, then
    /// emit the block-found. The one path SV1 and SV2 share; they differ
    /// only in where `solution.coinbase_tx` comes from.
    ///
    /// The submit is best-effort (a failure only logs): the block-found is
    /// emitted either way, as it always was.
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

        // `submit_solution` only queues the solution for the TDP worker, and
        // fails only when that worker is gone: the block then never reached
        // bitcoin-core. Reporting it anyway would record a found block, send
        // a "block found" push and park a booking that can never confirm.
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
            pplns_payouts_fingerprint: Some(payouts_fingerprint),
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
        // Empty `witness_coinbase` / missing `template_id` happens when the
        // job was declared via `SetCustomMiningJob` (the JDC built the
        // template — the pool has no template_id to call `submit_solution`
        // with, and the coinbase bytes weren't pool-built). The JDC
        // propagates its own block either way, so there is nothing to
        // submit here. What still has to happen is the RECORD.
        //
        // Who records it is `ExtendedJob::jdp_claims_the_block`, and only
        // that: the JDP `PushSolution` path matches a solution against a
        // DECLARED job, so it never sees a Coinbase-only one
        // (SV2 JDP/Coinbase-only Mode — that mode never declares), whether or
        // not a distribution backs it. Deciding on the distribution instead
        // left every Coinbase-only 0x0003 block unrecorded AND unsettled.
        //
        // Recording a claimed block here too would write the
        // `blocks_entity` row twice — the insert has no `ON CONFLICT` — and
        // the first, unbooked row would then suppress the booked one.
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
            // The pool reassembled this coinbase itself, out of the job it
            // served and the miner's own extranonce (the same reconstruction
            // SV1 does) — so it is not a guess, and it is the block's OWN
            // coinbase, which is the only thing settlement may book from.
            // The reward follows from it for the same reason: a reference
            // figure would be the pool's intention, not what the block paid.
            let actual = decode_actual_coinbase(&accept.witness_coinbase, self.network);
            // A coinbase that did not decode has nothing to book from.
            let booking = match actual.as_ref() {
                Some(a) => Booking::Book {
                    reward_sats: a.total_value_sats,
                },
                None => Booking::RecordOnly,
            };
            // Zeroed unless ext 0x0003 published a distribution this coinbase
            // was proven to pay (`emit_block_found` filters the zero out).
            // With it, a Coinbase-only 0x0003 block settles from its own
            // coinbase exactly as a pool-built one does; without it there is
            // nothing published to book against and the record stands alone.
            let fingerprint = accept.payouts_fingerprint;
            warn!(
                address,
                worker,
                session_id_hex,
                submission_diff = accept.submission_difficulty.as_f64(),
                bookable = fingerprint != [0u8; 32],
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
                pplns_payouts_fingerprint: Some(fingerprint),
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
                // Pinned on the `ShareAccept` at NewMiningJob /
                // NewExtendedMiningJob send time.
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

/// Decode the submitted witness coinbase into its per-address payment
/// record. `None` (with a warn) if the bytes are not exactly one
/// transaction — settlement then has no actuals and the block is
/// reported-not-booked rather than booked from a guess.
///
/// Strict through [`decode_whole_tx`], as the JDP path always was: a
/// coinbase decoded from a prefix would book the prefix's outputs.
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

/// Decode a transaction and require that it consumed EVERY byte.
///
/// `Transaction::consensus_decode` reads from a slice and stops when it has a
/// complete transaction. On a malformed input that happens to start with a
/// valid one it therefore SUCCEEDS, silently, on a prefix — which is how a
/// double-wrapped coinbase turned into a 21-byte transaction with no inputs
/// instead of an error. Anything reassembled into a block, or booked from,
/// has to be the whole thing, so a remainder is a failure.
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
    use bp_mining_job::{build_mining_job, CoinbaseTemplate, PayoutEntry, EXTRANONCE_SLOT_LEN};

    /// ext 0x0003/Implementation Notes: a block booked through a Stratum
    /// sink's IMMEDIATE (ungated) apply must invalidate every published payout
    /// distribution, exactly like a JDP-declared one does.
    ///
    /// This was wired for the confirmation-gated path and the JDP sink only.
    /// The published weights encode the pre-settlement balances, so a 0x0003
    /// JDC still mining them would pay those balances out a second time.
    ///
    /// The slot itself can no longer be forgotten — `stratum::spawn` and both
    /// `build_per_port_servers` take it as a required argument. What this test
    /// covers is the other half: that a filled slot actually settles.
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

    /// The SV1/SV2 block path books from `decode_actual_coinbase`, so it must
    /// be as strict as the JDP path: bytes that decode from a PREFIX would
    /// book the prefix's outputs. Both directions in one test — the real
    /// witness coinbase still decodes, so strictness cannot cost a block.
    #[test]
    fn a_coinbase_with_trailing_bytes_books_nothing() {
        let miner = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let job = build_mining_job(
            Network::Regtest,
            &[PayoutEntry::static_address(miner, 5_000_000_000)],
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

    /// No JDP server (the common deployment): settling is a no-op, not a
    /// panic. The signal is absent entirely because nothing wired one.
    #[tokio::test(flavor = "current_thread")]
    async fn settling_without_a_jdp_server_is_a_no_op() {
        let applier = BlockFoundApplier::default();
        assert!(applier.settle.is_none());
        applier.settle_distributions().await;
    }

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

    /// `submit_and_emit` hands bitcoin-core these three fields; a wrong
    /// offset submits a header core rebuilds differently, and the block is
    /// rejected. Each field gets a distinct value so a swapped or shifted
    /// slice cannot read back right by accident.
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

    /// `Booking` rides the stream as the old `reward_sats` field, so an
    /// event from a producer that predates the enum must mean the same
    /// thing to a new consumer, and the other way round.
    #[test]
    fn booking_round_trips_through_the_wire_reward_field() {
        for booking in [
            Booking::Book {
                reward_sats: 312_500_000,
            },
            Booking::RecordOnly,
        ] {
            let event = BlockFoundEvent {
                reward_sats: booking.wire_reward_sats(),
                ..record_only_event()
            };
            let json = serde_json::to_string(&event).expect("serialize");
            let back: BlockFoundEvent = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back.booking(), booking);
        }
        // What an older producer wrote for a record-only block.
        let mut old = serde_json::to_value(record_only_event()).expect("to value");
        old["reward_sats"] = serde_json::Value::Null;
        let back: BlockFoundEvent = serde_json::from_value(old).expect("from value");
        assert_eq!(back.booking(), Booking::RecordOnly);
    }

    fn record_only_event() -> BlockFoundEvent {
        BlockFoundEvent {
            address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            worker: "jdp".to_string(),
            session_id: "sess1".to_string(),
            reward_sats: None,
            block_hash: Some("00000000deadbeef".to_string()),
            block_data: "ab".repeat(80),
            mode: MiningMode::Pplns,
            group_id: None,
            height: 870_123,
            weight_snapshot: None,
            pplns_payouts_fingerprint: None,
            actual_coinbase: None,
        }
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
            weight_snapshot: Some(weight_snapshot.clone()),
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
        assert_eq!(back.weight_snapshot, Some(weight_snapshot));
    }
}
