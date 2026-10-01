// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group-Solo share sinks for SV1 and SV2. They read the producer-stamped
//! `mode` / `group_id` off the share instead of holding a mode gate, so they
//! run unchanged on the Satellite off the stream.

use async_trait::async_trait;
use bp_common::{warn_throttled, LogThrottle, MiningMode};
use bp_share_hook::{
    SharedAcceptedShare, SharedAcceptedShareSink, SharedRejectedShare, SharedRejectedShareSink,
};
use tracing::warn;
use uuid::Uuid;

use crate::engine::GroupSoloEngine;

/// Throttle window for `record_share failed`: a Redis outage fails every
/// accepted share, so warn once per window with a suppressed count.
const RECORD_SHARE_WARN_THROTTLE_MS: i64 = 5_000;

/// `SharedAcceptedShareSink` impl that records the share against the
/// address's Group-Solo round when the share is stamped Group-Solo.
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
        // Blockparty shares also carry a group_id, so test the mode.
        if share.mode != MiningMode::GroupSolo {
            return;
        }
        let Some(group_id) = share.group_id.and_then(|g| Uuid::parse_str(g).ok()) else {
            return;
        };
        // Accept time, not now(): backlogged shares keep their original time.
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

/// Counts a reject against the Group-Solo round when the share carries a
/// `group_id`; pre-auth and non-group rejects are dropped.
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
