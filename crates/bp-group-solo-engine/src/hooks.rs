// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bp_share_hook` trait impls gated on mining-mode = Group-Solo.
//!
//! Engines used to impl `bp_stratum_v1::hooks::AcceptedShareSink` +
//! `RejectedShareSink` directly. The
//! per-share hook surface is decoupled from the wire protocol via
//! `bp-share-hook` so the same impl serves both SV1 + SV2 servers.
//!
//! Group-Solo's `recordShare` is per-group. Both the accepted and rejected
//! sinks read the producer-stamped `mode` / `group_id` off the share — the
//! Core composite resolves them once from the mode gate at fan-out — so these
//! sinks hold no gate and run unchanged on the Satellite off the stream.

use async_trait::async_trait;
use bp_common::{warn_throttled, LogThrottle, MiningMode};
use bp_share_hook::{
    SharedAcceptedShare, SharedAcceptedShareSink, SharedRejectedShare, SharedRejectedShareSink,
};
use tracing::warn;
use uuid::Uuid;

use crate::engine::GroupSoloEngine;

/// Throttle window for the per-share `record_share failed` warning — a Redis
/// outage fails every accepted share, so warn at most once per 5s with a
/// suppressed count instead of one line per share.
const RECORD_SHARE_WARN_THROTTLE_MS: i64 = 5_000;

/// `SharedAcceptedShareSink` impl that records the share against the
/// address's Group-Solo round iff the gate resolves it.
pub struct GroupSoloAcceptedShareSink {
    engine: GroupSoloEngine,
    warn_throttle: LogThrottle,
}

impl GroupSoloAcceptedShareSink {
    pub fn new(engine: GroupSoloEngine) -> Self {
        Self {
            engine,
            warn_throttle: LogThrottle::new(RECORD_SHARE_WARN_THROTTLE_MS),
        }
    }
}

#[async_trait]
impl SharedAcceptedShareSink for GroupSoloAcceptedShareSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        // Producer-stamped mode + group_id — no gate query. Only fire for
        // GroupSolo (NOT Blockparty, which also carries a group_id).
        if share.mode != MiningMode::GroupSolo {
            return;
        }
        let Some(group_id) = share.group_id.and_then(|g| Uuid::parse_str(g).ok()) else {
            return;
        };
        // Share's Core-accept time, not now() — see the PPLNS sink for
        // why: replayed/backlogged shares under the Core/Satellite split
        // must keep their original accept time, not the consume time.
        let ts_ms = share.ts_ms;
        if let Err(e) = self
            .engine
            .record_share(
                Some(share.share_id),
                group_id,
                share.address,
                share.effective_difficulty,
                ts_ms,
            )
            .await
        {
            // Throttled: a Redis outage fails every share — warn at most once
            // per window with a count of those suppressed since.
            warn_throttled!(
                self.warn_throttle,
                ts_ms,
                error = %e,
                address = share.address,
                %group_id,
                difficulty = share.effective_difficulty,
                "GroupSoloAcceptedShareSink: record_share failed"
            );
        }
    }
}

/// `SharedRejectedShareSink` impl that increments the rejected-shares
/// hash for the Group-Solo round when the share carries a `group_id`.
/// Pre-auth rejects (`address = None`) and non-group shares (`group_id =
/// None`) are silently dropped.
pub struct GroupSoloRejectedShareSink {
    engine: GroupSoloEngine,
}

impl GroupSoloRejectedShareSink {
    pub fn new(engine: GroupSoloEngine) -> Self {
        Self { engine }
    }
}

#[async_trait]
impl SharedRejectedShareSink for GroupSoloRejectedShareSink {
    async fn record_rejected(&self, share: SharedRejectedShare<'_>) {
        let Some(addr) = share.address else {
            return;
        };
        // Producer-stamped group id — the Core composite resolved it from the
        // mode gate at fan-out, so there's no gate query here and the sink
        // runs unchanged on the Satellite off the rejected stream.
        let Some(group_id_str) = share.group_id else {
            return;
        };
        let group_id = match Uuid::parse_str(group_id_str) {
            Ok(u) => u,
            Err(e) => {
                warn!(
                    error = %e,
                    address = addr,
                    group_id = group_id_str,
                    "GroupSoloRejectedShareSink: stamped group_id is not a valid UUID — skipping"
                );
                return;
            }
        };
        if let Err(e) = self
            .engine
            .record_reject(group_id, addr, share.difficulty)
            .await
        {
            warn!(
                error = %e,
                address = addr,
                %group_id,
                difficulty = share.difficulty,
                "GroupSoloRejectedShareSink: record_reject failed"
            );
        }
    }
}
