// SPDX-License-Identifier: AGPL-3.0-or-later

//! Protocol-agnostic share hooks: the SV1 and SV2 servers project their
//! native `ShareAccept` into [`SharedAcceptedShare`], so every engine
//! implements one sink instead of one per protocol. `BlockSubmissionSink`
//! stays per-protocol because TDP `submit_solution` needs the native share.

use async_trait::async_trait;

pub use bp_common::MiningMode;
pub use bp_stats::RejectedReason;

/// Protocol-agnostic view of an accepted share, borrowed from the native
/// `ShareAccept` without copies.
#[derive(Debug, Clone, Copy)]
pub struct SharedAcceptedShare<'a> {
    /// Miner-authorized payout address; never empty once a share is accepted.
    pub address: &'a str,

    /// Worker name from `address.workername`, the same name the session row
    /// carries. Never empty: without one, SV1 authorizes as "worker" and SV2
    /// opens the channel as "default".
    pub worker: &'a str,

    pub session_id: &'a str,

    /// Difficulty the share is credited at (post-vardiff clamp); drives
    /// PPLNS / Group-Solo accounting.
    pub effective_difficulty: f64,

    /// Difficulty the hash actually solved; drives best-difficulty tracking.
    pub submission_difficulty: f64,

    /// Miner firmware / vendor string, stamped onto the best-difficulty row.
    pub user_agent: Option<&'a str>,

    /// Meets the network difficulty. Only triggers TDP `SubmitSolution`;
    /// bitcoin-core is the authoritative validator.
    pub is_block_candidate: bool,

    /// Vardiff's session hashrate (H/s), shown as the live `hash_rate`; 0
    /// before vardiff's first estimate.
    pub hash_rate: f64,

    /// Channels on this session's connection; `> 1` when a rental proxy
    /// bundles devices, so the UI shows the difficulty as aggregated.
    pub channel_count: u32,

    /// Accept time (epoch ms), stamped once in the `shared_adapter`
    /// projections. Sinks MUST bucket on this and never re-stamp `now()`:
    /// they may run in another process and would mis-time backlogged shares.
    pub ts_ms: i64,

    /// `{core_epoch}:{seq}` from [`ShareSequencer`], the dedup key for
    /// exactly-once accounting in non-idempotent stores. Empty until the
    /// producer stamps it.
    pub share_id: &'a str,

    /// Payout mode stamped by the producer from the authoritative mode gate,
    /// so consumer sinks need no gate. `Solo` until stamped.
    pub mode: MiningMode,
    /// Group id for `GroupSolo` / `Blockparty`, else `None`.
    pub group_id: Option<&'a str>,
}

/// Assigns `{epoch}:{seq}` share ids on the Core. `epoch` is fresh per boot
/// so a share redelivered from a previous boot cannot collide; it is a dedup
/// discriminator, never an ordering watermark across epochs.
pub struct ShareSequencer {
    epoch: u64,
    seq: std::sync::atomic::AtomicU64,
}

impl ShareSequencer {
    /// `epoch` must be unique per boot (a Redis `INCR core:epoch`).
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            seq: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn next_id(&self) -> String {
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{}:{}", self.epoch, seq)
    }
}

/// Hook for accepted shares, mode-blind: a mode-specific engine gates on
/// [`SharedAcceptedShare::mode`]. Called once per share, so avoid a per-share
/// PG round-trip and batch into a flush instead.
#[async_trait]
pub trait SharedAcceptedShareSink: Send + Sync {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>);
}

/// Owned record of an accepted share for crossing the stream to the
/// Satellite, which borrows a view back ([`Self::as_view`]) to drive the
/// exact same [`SharedAcceptedShareSink`] code.
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
    /// A record without this field decodes as a single-channel session.
    #[serde(default = "one_channel")]
    pub channel_count: u32,
    pub ts_ms: i64,
    pub share_id: String,
    pub mode: MiningMode,
    pub group_id: Option<String>,
}

fn one_channel() -> u32 {
    1
}

impl SharedAcceptedShareOwned {
    /// Borrow an owned record as the zero-copy view the sinks consume.
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
    /// Materialize an owned record for a queue. Not named `to_owned`, which
    /// would shadow the blanket [`ToOwned`] impl this `Copy` view already has.
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

/// Protocol-agnostic view of a rejected share. `address`/`worker` are `None`
/// for rejects before authorize; SV2 protocol-validity rejects (channel id,
/// extranonce size) are not share rejects and never arrive here.
#[derive(Debug, Clone, Copy)]
pub struct SharedRejectedShare<'a> {
    pub address: Option<&'a str>,
    pub worker: Option<&'a str>,
    pub session_id: &'a str,
    pub reason: RejectedReason,
    pub difficulty: f64,
    /// Group id for a Group-Solo address, stamped by the producer (the only
    /// side with the mode gate); the protocol side leaves it `None`.
    pub group_id: Option<&'a str>,
}

/// Hook for rejected shares. Engines that care about per-mode reject
/// counters (group-solo, stats-sink) implement this once.
#[async_trait]
pub trait SharedRejectedShareSink: Send + Sync {
    async fn record_rejected(&self, share: SharedRejectedShare<'_>);
}

/// Owned counterpart of [`SharedRejectedShare`], same role as
/// [`SharedAcceptedShareOwned`].
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
    /// Materialize an owned record (see [`SharedAcceptedShare::to_owned_record`]).
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

/// Per-session lifecycle: register on authorize, deregister on disconnect.
#[async_trait]
pub trait SharedSessionPersistence: Send + Sync {
    /// Called after authorize. `user_agent` is the miner's firmware/vendor
    /// string, stored on `client_entity.userAgent`.
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

/// Per-device online/offline transition: SV1 fires it on authorize and
/// disconnect, SV2 on channel open and close.
#[async_trait]
pub trait DeviceStatusSink: Send + Sync {
    async fn on_device_event(
        &self,
        address: &str,
        worker: &str,
        session_id: &str,
        user_agent: Option<&str>,
        is_online: bool,
    );
}

/// Does nothing; the default when a server runs without production sinks.
pub struct NoOpSink;

#[async_trait]
impl SharedAcceptedShareSink for NoOpSink {
    async fn record_accepted(&self, _: SharedAcceptedShare<'_>) {}
}

#[async_trait]
impl SharedRejectedShareSink for NoOpSink {
    async fn record_rejected(&self, _: SharedRejectedShare<'_>) {}
}

#[async_trait]
impl SharedSessionPersistence for NoOpSink {
    async fn register_session(&self, _: &str, _: &str, _: &str, _: Option<&str>) {}
    async fn deregister_session(&self, _: &str) {}
}

#[async_trait]
impl DeviceStatusSink for NoOpSink {
    async fn on_device_event(&self, _: &str, _: &str, _: &str, _: Option<&str>, _: bool) {}
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

        // Re-materializing through the borrowed view is lossless.
        let back = owned.as_view().to_owned_record();
        assert_eq!(owned, back);
    }

    #[tokio::test]
    async fn owned_as_view_drives_the_same_sink_identically() {
        // `as_view()` must record exactly what the borrowed view would have.
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
