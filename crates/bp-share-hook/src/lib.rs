// SPDX-License-Identifier: AGPL-3.0-or-later

//! Protocol-agnostic share-hook surface.
//!
//! # Why this crate exists
//!
//! The Rust port has **two** Stratum servers in a single process:
//!
//! - `bp-stratum-v1` (JSON-RPC over TCP) for legacy SV1 miners
//! - `bp-stratum-v2` (Noise + binary frames) for SV2 miners
//!
//! Both servers fire per-accepted-share hooks that **must** drive the
//! same business logic — PPLNS credit, group-solo credit, stats
//! accumulation, best-difficulty tracking, session bookkeeping. Without
//! a shared surface, every engine would need duplicate `AcceptedShareSink`
//! impls (one for each Stratum-server crate's protocol-specific trait).
//!
//! `bp-share-hook` introduces a **protocol-agnostic view** —
//! [`SharedAcceptedShare`] — and the trait engines implement against it,
//! [`SharedAcceptedShareSink`]. Each Stratum server crate provides a
//! thin adapter that projects its native `ShareAccept` into the shared
//! view and delegates to `SharedAcceptedShareSink`.
//!
//! ```text
//!  bp-stratum-v1::ShareAccept ──┐
//!                               ├── Sv1->Shared adapter ──┐
//!  bp-stratum-v2::ShareAccept ──┘                         │
//!                                                         ▼
//!                                  bp-pplns-engine, bp-group-solo-engine,
//!                                  bp-share-stats-sink, bp-session-persistence,
//!                                  ... all impl SharedAcceptedShareSink
//! ```
//!
//! # Lifecycle outlook
//!
//! When SV1 is eventually retired (SV2 is the future protocol), the
//! `bp-stratum-v1` crate + its adapter just go away. Engines stay
//! unchanged.
//!
//! # Scope
//!
//! Covers the three per-share hook surfaces that ALL engines need
//! protocol-agnostically:
//!
//! - **`SharedAcceptedShareSink`** — every accepted share
//! - **`SharedRejectedShareSink`** — every rejected share
//! - **`SharedSessionPersistence`** — authorize / disconnect lifecycle
//!
//! **`BlockSubmissionSink` stays per-protocol** because it carries the
//! full native `ShareAccept` (header / hash / mining-job snapshot)
//! needed for the TDP `submit_solution` call. The block-submission
//! wiring is also concentrated in `bin/blitzpool` (one impl), so the
//! per-protocol cost is one trait impl per Stratum server, not 4
//! engines × 2 protocols.

use async_trait::async_trait;

pub use bp_common::MiningMode;
pub use bp_stats::RejectedReason;

/// Protocol-agnostic view of an accepted share. Borrowed from the
/// underlying `ShareAccept` (SV1 or SV2) — no copies, no allocations.
/// Lifetimes are tied to the original `ShareAccept` so the projection
/// is free for the caller.
#[derive(Debug, Clone, Copy)]
pub struct SharedAcceptedShare<'a> {
    /// Miner-authorized Bitcoin address (the payout target). Always
    /// non-empty when the hook fires — pre-authorize shares can't be
    /// accepted.
    pub address: &'a str,

    /// Worker / rig name extracted from the authorize username
    /// (`address.workername`). Empty string if the miner didn't supply one.
    pub worker: &'a str,

    /// Per-session identifier. SV1 generates an 8-char string; SV2
    /// derives one from the channel-id. Used for the
    /// `client_statistics_entity` composite key + per-session
    /// best-diff tracking.
    pub session_id: &'a str,

    /// Difficulty the share is **credited at** (post-vardiff-clamp).
    /// Used by PPLNS / group-solo accounting + the share-totals
    /// accumulators.
    pub effective_difficulty: f64,

    /// Difficulty the share actually **solved** (derived from the
    /// hash). Drives best-difficulty tracking + the block-found
    /// threshold (`>= network_difficulty`).
    pub submission_difficulty: f64,

    /// Miner firmware / vendor string for this session (SV1
    /// `mining.subscribe` user-agent, SV2 vendor-derived). `None` if
    /// the miner sent none. Stamped onto the all-time best-difficulty
    /// row so the UI can show which hardware found a miner's best share.
    pub user_agent: Option<&'a str>,

    /// `true` when the submission difficulty meets / exceeds the
    /// network difficulty — bitcoin-core is the authoritative
    /// validator, this flag only triggers the TDP `SubmitSolution`
    /// path. Stats-sink fans block-candidate accepted shares into the
    /// same accumulators as regular ones.
    pub is_block_candidate: bool,

    /// Session-wide hashrate snapshot taken right after the vardiff
    /// engine consumed this share — H/s computed from the per-slot
    /// share-difficulty sum over the elapsed window. Persisted onto
    /// `client_entity.hashRate` by the ClientRowTouchSink so
    /// /api/info totalHashRate + /api/client/:address totalHashrate
    /// render the actual hashrate the miner is contributing.
    pub hash_rate: f64,

    /// Number of mining channels open on this session's downstream
    /// connection. `1` for a direct miner (one device → one channel);
    /// `> 1` when a rental proxy bundles several same-rig devices onto a
    /// single connection. Persisted onto `client_entity.channelCount` so
    /// the UI can render the per-session difficulty as "aggregated"
    /// instead of one channel's flapping vardiff target.
    pub channel_count: u32,

    /// Core wall-clock time (epoch milliseconds) at which this share was
    /// accepted, stamped **once** at the protocol-agnostic projection
    /// boundary (the SV1/SV2 adapters) via [`now_ms`]. Every downstream
    /// sink MUST window / time-bucket on this value and never re-stamp
    /// `now()` at the sink. In a single process the two are microseconds
    /// apart, but once the share path and the accounting sinks can live in
    /// separate processes (Core/Satellite), a sink that re-stamps `now()`
    /// would mis-time replayed or backlogged shares.
    pub ts_ms: i64,

    /// Producer-assigned share id, format `{core_epoch}:{seq}` (see
    /// [`ShareSequencer`]). The **dedup key** for exactly-once accounting:
    /// a sink that mutates a non-idempotent store (the Redis PPLNS /
    /// Group-Solo windows) keys its dedup marker on this so a redelivered
    /// share is a no-op. Assigned once at the single fan-out point (the
    /// in-process composite today, the stream producer under the split);
    /// **empty (`""`) until the producer stamps it** — the protocol adapters
    /// leave it blank because they have no global sequence.
    pub share_id: &'a str,

    /// Resolved payout mode for this share's address, stamped by the
    /// producer at the single fan-out point. Sinks read this instead of
    /// querying a mode-gate per share: under the split the producer (Core)
    /// resolves it once from the authoritative gate, so the consumer sinks
    /// need no gate. `Solo` until the producer stamps it (the adapters have
    /// no gate).
    pub mode: MiningMode,
    /// Group id (UUID string) for `GroupSolo` / `Blockparty` modes, else
    /// `None`. Carried next to `mode` so the group sinks don't re-query the
    /// gate to recover it.
    pub group_id: Option<&'a str>,
}

/// Assigns globally-unique, monotonic-within-epoch ids to accepted shares
/// on the Core. Format `{epoch}:{seq}`.
///
/// `epoch` is fixed per Core process (a Redis `INCR core:epoch` at boot) so
/// ids stay unique across Core restarts — a share redelivered from a stream
/// written by a previous boot can't collide with a fresh one. It is a
/// **dedup discriminator, not an ordering watermark**: never compare ids
/// across epochs for ordering. `seq` is monotonic within one process
/// lifetime. `next_id` is one relaxed atomic add — cheap enough for the
/// per-accepted-share hot path.
pub struct ShareSequencer {
    epoch: u64,
    seq: std::sync::atomic::AtomicU64,
}

impl ShareSequencer {
    /// Build a sequencer for this Core process. `epoch` should be unique
    /// per boot (a Redis `INCR core:epoch`).
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            seq: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Next id as `{epoch}:{seq}`.
    pub fn next_id(&self) -> String {
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{}:{}", self.epoch, seq)
    }
}

/// Stamp the current Core wall-clock time in epoch milliseconds.
///
/// Used by the SV1/SV2 adapters to fill [`SharedAcceptedShare::ts_ms`] at
/// the moment a share enters the protocol-agnostic business layer. Uses
/// `std::time` so the lean wire-protocol crates don't pull in `chrono`.
/// A pre-1970 clock (impossible in practice) saturates to `0` rather than
/// panicking.
pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Hook for accepted shares. Engines implement this once and the
/// Stratum-server adapters dispatch every accepted share through it.
/// Mode-blind by design — a mode-specific engine gates on the
/// producer-stamped [`SharedAcceptedShare::mode`] internally.
///
/// **Hot path**: this trait method is called once per accepted share.
/// Implementations should keep the work minimal — accumulator
/// `add_*` calls are good; PG round-trips should be guarded by a
/// cache predicate (see `bp_session_persistence::hooks::BestDifficultySink`
/// for the pattern).
#[async_trait]
pub trait SharedAcceptedShareSink: Send + Sync {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>);
}

/// Owned counterpart of [`SharedAcceptedShare`] — the canonical *record*
/// of an accepted share.
///
/// The borrowed [`SharedAcceptedShare`] is zero-copy and lifetime-tied to
/// the originating `ShareAccept`: ideal for the in-process fan-out, but it
/// cannot outlive the share or cross a serialization boundary. This owned
/// form is what a producer materializes ([`SharedAcceptedShare::to_owned_record`])
/// and what a consumer reconstructs and borrows a view back from
/// ([`Self::as_view`]) to drive the **exact same** [`SharedAcceptedShareSink`]
/// code. The front's producer materializes this owned record and `XADD`s it;
/// the Satellite reconstructs it and borrows a view to drive the accounting
/// sinks. One sink entrypoint for both sides is the producer/consumer
/// equivalence seam.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SharedAcceptedShareOwned {
    pub address: String,
    pub worker: String,
    pub session_id: String,
    pub effective_difficulty: f64,
    pub submission_difficulty: f64,
    pub user_agent: Option<String>,
    pub is_block_candidate: bool,
    pub hash_rate: f64,
    /// See [`SharedAcceptedShare::channel_count`]. `serde(default)` keeps
    /// any already-enqueued record without this field decoding to a
    /// single-channel (non-aggregated) session.
    #[serde(default = "one_channel")]
    pub channel_count: u32,
    pub ts_ms: i64,
    pub share_id: String,
    pub mode: MiningMode,
    pub group_id: Option<String>,
}

/// Serde default for [`SharedAcceptedShareOwned::channel_count`] — a record
/// without the field is a pre-bundling single-channel session.
fn one_channel() -> u32 {
    1
}

impl SharedAcceptedShareOwned {
    /// Borrow an owned record as the zero-copy view the sinks consume.
    /// The returned view borrows from `self`, so a consumer can dispatch it
    /// straight into [`SharedAcceptedShareSink::record_accepted`].
    pub fn as_view(&self) -> SharedAcceptedShare<'_> {
        SharedAcceptedShare {
            address: &self.address,
            worker: &self.worker,
            session_id: &self.session_id,
            effective_difficulty: self.effective_difficulty,
            submission_difficulty: self.submission_difficulty,
            user_agent: self.user_agent.as_deref(),
            is_block_candidate: self.is_block_candidate,
            hash_rate: self.hash_rate,
            channel_count: self.channel_count,
            ts_ms: self.ts_ms,
            share_id: &self.share_id,
            mode: self.mode,
            group_id: self.group_id.as_deref(),
        }
    }
}

impl SharedAcceptedShare<'_> {
    /// Materialize a borrowed view into an owned record (e.g. to enqueue it
    /// for out-of-process consumption). Allocates the string fields; called
    /// off the hot path, only by a producer that needs to hand the share to a
    /// queue. Named `to_owned_record` rather than `to_owned` to avoid
    /// shadowing the blanket [`ToOwned`] impl this `Copy` view already has.
    pub fn to_owned_record(&self) -> SharedAcceptedShareOwned {
        SharedAcceptedShareOwned {
            address: self.address.to_string(),
            worker: self.worker.to_string(),
            session_id: self.session_id.to_string(),
            effective_difficulty: self.effective_difficulty,
            submission_difficulty: self.submission_difficulty,
            user_agent: self.user_agent.map(str::to_string),
            is_block_candidate: self.is_block_candidate,
            hash_rate: self.hash_rate,
            channel_count: self.channel_count,
            ts_ms: self.ts_ms,
            share_id: self.share_id.to_string(),
            mode: self.mode,
            group_id: self.group_id.map(str::to_string),
        }
    }
}

/// Protocol-agnostic view of a rejected share.
///
/// `address` is `Option<&str>` because some rejection paths fire
/// before authorize completes (e.g. early-stale reject in the framing
/// layer). The pool-wide counters still bump; per-address ones gated
/// on `address.is_some()`.
///
/// `reason` is the canonical 3-variant [`bp_stats::RejectedReason`]
/// (JobNotFound / DuplicateShare / LowDifficulty). Both Stratum
/// servers map their richer per-protocol reject enums into this
/// stable shape inside their adapters (SV1's `Stale` collapses into
/// `JobNotFound`; SV2's `BadExtranonceSize` doesn't surface to this
/// trait — it's pre-share-validation so the share never reaches a
/// counter).
#[derive(Debug, Clone, Copy)]
pub struct SharedRejectedShare<'a> {
    pub address: Option<&'a str>,
    /// Worker name — `None` for pre-authorize rejects (no authorization yet).
    pub worker: Option<&'a str>,
    pub session_id: &'a str,
    pub reason: RejectedReason,
    pub difficulty: f64,
    /// Group UUID string for a Group-Solo address, else `None`. Stamped by
    /// the producer at the fan-out point (the only side with the mode gate)
    /// so the Group-Solo reject sink needs no gate of its own — it reads this
    /// instead. The protocol adapters leave it `None`.
    pub group_id: Option<&'a str>,
}

/// Hook for rejected shares. Engines that care about per-mode reject
/// counters (group-solo, stats-sink) implement this once.
#[async_trait]
pub trait SharedRejectedShareSink: Send + Sync {
    async fn record_rejected(&self, share: SharedRejectedShare<'_>);
}

/// Owned counterpart of [`SharedRejectedShare`]. Same role as
/// [`SharedAcceptedShareOwned`]: the canonical record a producer materializes
/// and a consumer borrows a view back from, so the rejected-share fan-out runs
/// identical sink code in-process and (later) across the Core/Satellite split.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SharedRejectedShareOwned {
    pub address: Option<String>,
    pub worker: Option<String>,
    pub session_id: String,
    pub reason: RejectedReason,
    pub difficulty: f64,
    pub group_id: Option<String>,
}

impl SharedRejectedShareOwned {
    /// Borrow an owned record as the zero-copy view the sinks consume.
    pub fn as_view(&self) -> SharedRejectedShare<'_> {
        SharedRejectedShare {
            address: self.address.as_deref(),
            worker: self.worker.as_deref(),
            session_id: &self.session_id,
            reason: self.reason,
            difficulty: self.difficulty,
            group_id: self.group_id.as_deref(),
        }
    }
}

impl SharedRejectedShare<'_> {
    /// Materialize a borrowed view into an owned record. See
    /// [`SharedAcceptedShare::to_owned_record`] for the naming rationale.
    pub fn to_owned_record(&self) -> SharedRejectedShareOwned {
        SharedRejectedShareOwned {
            address: self.address.map(str::to_string),
            worker: self.worker.map(str::to_string),
            session_id: self.session_id.to_string(),
            reason: self.reason,
            difficulty: self.difficulty,
            group_id: self.group_id.map(str::to_string),
        }
    }
}

/// Protocol-agnostic per-session lifecycle. SV1 and SV2 both emit
/// `register` on authorize + `deregister` on disconnect with the same
/// payload shape, so this trait is naturally protocol-agnostic.
#[async_trait]
pub trait SharedSessionPersistence: Send + Sync {
    /// Called when a miner finishes the authorize handshake.
    /// `user_agent` is the firmware/vendor string the miner sent in
    /// its connection-setup frame (BitAxe firmware version, BraiinsOS
    /// build tag, SV1 `mining.subscribe` user-agent, …). Stored on
    /// `client_entity.userAgent` so the UI's per-worker tile and the
    /// `/api/info` userAgents histogram surface the actual hardware.
    async fn register_session(
        &self,
        session_id: &str,
        address: &str,
        worker: &str,
        user_agent: Option<&str>,
    );
    /// Called when the connection closes (clean FIN or RST or timeout).
    async fn deregister_session(&self, session_id: &str);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    type RecordedShare = (String, String, String, f64, f64, bool);

    struct RecordingSink {
        recorded: Mutex<Vec<RecordedShare>>,
    }

    #[async_trait]
    impl SharedAcceptedShareSink for RecordingSink {
        async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
            self.recorded.lock().unwrap().push((
                share.address.to_string(),
                share.worker.to_string(),
                share.session_id.to_string(),
                share.effective_difficulty,
                share.submission_difficulty,
                share.is_block_candidate,
            ));
        }
    }

    #[tokio::test]
    async fn shared_accepted_share_view_can_borrow_from_owned_strings() {
        let sink = RecordingSink {
            recorded: Mutex::new(Vec::new()),
        };
        let addr = "bc1qalice".to_string();
        let worker = "rig1".to_string();
        let sid = "sess0001".to_string();
        let ua = "bitaxe/1.0".to_string();
        sink.record_accepted(SharedAcceptedShare {
            address: &addr,
            worker: &worker,
            session_id: &sid,
            user_agent: Some(&ua),
            effective_difficulty: 1024.0,
            submission_difficulty: 2048.0,
            is_block_candidate: false,
            hash_rate: 0.0,
            channel_count: 1,
            ts_ms: 0,
            share_id: "",
            mode: MiningMode::Solo,
            group_id: None,
        })
        .await;
        let rec = sink.recorded.lock().unwrap();
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].0, "bc1qalice");
        assert_eq!(rec[0].3, 1024.0);
        assert_eq!(rec[0].4, 2048.0);
        assert!(!rec[0].5);
    }

    #[tokio::test]
    async fn block_candidate_flag_propagates() {
        let sink = RecordingSink {
            recorded: Mutex::new(Vec::new()),
        };
        sink.record_accepted(SharedAcceptedShare {
            address: "a",
            worker: "w",
            session_id: "s",
            user_agent: None,
            effective_difficulty: 100.0,
            submission_difficulty: 1e15,
            is_block_candidate: true,
            hash_rate: 0.0,
            channel_count: 1,
            ts_ms: 0,
            share_id: "",
            mode: MiningMode::Solo,
            group_id: None,
        })
        .await;
        assert!(sink.recorded.lock().unwrap()[0].5);
    }

    fn sample_accepted_view<'a>(addr: &'a str, ua: &'a Option<String>) -> SharedAcceptedShare<'a> {
        SharedAcceptedShare {
            address: addr,
            worker: "rig1",
            session_id: "sess0001",
            user_agent: ua.as_deref(),
            effective_difficulty: 1024.0,
            submission_difficulty: 2048.0,
            is_block_candidate: true,
            hash_rate: 1234.5,
            channel_count: 3,
            ts_ms: 1_700_000_000_123,
            share_id: "ep7:42",
            mode: MiningMode::GroupSolo,
            group_id: Some("group-xyz"),
        }
    }

    #[test]
    fn accepted_owned_round_trips_through_view() {
        let addr = "bc1qalice".to_string();
        let ua = Some("bitaxe/1.0".to_string());
        let view = sample_accepted_view(&addr, &ua);
        let owned = view.to_owned_record();

        // Owned record mirrors the view field-for-field.
        assert_eq!(owned.address, "bc1qalice");
        assert_eq!(owned.worker, "rig1");
        assert_eq!(owned.session_id, "sess0001");
        assert_eq!(owned.user_agent.as_deref(), Some("bitaxe/1.0"));
        assert_eq!(owned.effective_difficulty, 1024.0);
        assert_eq!(owned.submission_difficulty, 2048.0);
        assert!(owned.is_block_candidate);
        assert_eq!(owned.hash_rate, 1234.5);
        assert_eq!(owned.channel_count, 3);
        assert_eq!(owned.ts_ms, 1_700_000_000_123);
        assert_eq!(owned.share_id, "ep7:42");
        assert_eq!(owned.mode, MiningMode::GroupSolo);
        assert_eq!(owned.group_id.as_deref(), Some("group-xyz"));

        // ...and re-materializing through the borrowed view is lossless, so a
        // consumer can dispatch and re-enqueue with no field drift.
        let back = owned.as_view().to_owned_record();
        assert_eq!(owned, back);
    }

    #[tokio::test]
    async fn owned_as_view_drives_the_same_sink_identically() {
        // The whole point of the owned record: feeding `as_view()` to a sink
        // must record exactly what the borrowed view would have.
        let addr = "bc1qbob".to_string();
        let ua = Some("antminer".to_string());

        let direct = RecordingSink {
            recorded: Mutex::new(Vec::new()),
        };
        direct
            .record_accepted(sample_accepted_view(&addr, &ua))
            .await;

        let via_owned = RecordingSink {
            recorded: Mutex::new(Vec::new()),
        };
        let owned = sample_accepted_view(&addr, &ua).to_owned_record();
        via_owned.record_accepted(owned.as_view()).await;

        assert_eq!(
            *direct.recorded.lock().unwrap(),
            *via_owned.recorded.lock().unwrap(),
            "owned->as_view must record identically to the borrowed view"
        );
    }

    #[test]
    fn rejected_owned_round_trips_through_view() {
        let view = SharedRejectedShare {
            address: Some("bc1qcarol"),
            worker: Some("rig9"),
            session_id: "sess-rej",
            reason: RejectedReason::LowDifficulty,
            difficulty: 512.0,
            group_id: Some("550e8400-e29b-41d4-a716-446655440000"),
        };
        let owned = view.to_owned_record();
        assert_eq!(owned.address.as_deref(), Some("bc1qcarol"));
        assert_eq!(owned.worker.as_deref(), Some("rig9"));
        assert_eq!(owned.session_id, "sess-rej");
        assert_eq!(owned.reason, RejectedReason::LowDifficulty);
        assert_eq!(owned.difficulty, 512.0);
        assert_eq!(
            owned.group_id.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );

        // Pre-authorize reject: address/worker/group absent, must survive.
        let preauth = SharedRejectedShare {
            address: None,
            worker: None,
            session_id: "sess-early",
            reason: RejectedReason::JobNotFound,
            difficulty: 0.0,
            group_id: None,
        };
        let owned_preauth = preauth.to_owned_record();
        assert!(owned_preauth.address.is_none());
        assert!(owned_preauth.worker.is_none());
        assert!(owned_preauth.group_id.is_none());
        // View borrowed back matches the original Option shape.
        assert!(owned_preauth.as_view().address.is_none());
    }
}
