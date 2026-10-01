// SPDX-License-Identifier: AGPL-3.0-or-later

//! Accepted-share sink for SV1 and SV2 that records only shares stamped
//! `MiningMode::Pplns`. Block submission is protocol-specific and is wired
//! in `bin/blitzpool`, not here.

use async_trait::async_trait;
use bp_common::{warn_throttled, LogThrottle, MiningMode};
use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareSink};

/// A Redis outage fails every accepted share; one warning per window plus a
/// suppressed count alerts without burying the log.
const RECORD_SHARE_WARN_THROTTLE_MS: i64 = 5_000;

use crate::engine::PplnsEngine;

pub struct PplnsAcceptedShareSink {
    engine: PplnsEngine,
    warn_throttle: LogThrottle,
}

impl PplnsAcceptedShareSink {
    pub fn new(engine: PplnsEngine) -> Self {
        Self {
            engine,
            warn_throttle: LogThrottle::new(RECORD_SHARE_WARN_THROTTLE_MS),
        }
    }
}

#[async_trait]
impl SharedAcceptedShareSink for PplnsAcceptedShareSink {
    async fn record_accepted(&self, share: SharedAcceptedShare<'_>) {
        // Mode is resolved once by the producer and stamped on the share,
        // so the consumer needs no gate.
        if share.mode != MiningMode::Pplns {
            return;
        }
        // The share's Core-accept time, not now(): a Satellite replaying a
        // backlog would otherwise put shares in the wrong window slot.
        let ts_ms = share.ts_ms as u64;
        if let Err(e) = self
            .engine
            .record_share(
                Some(share.share_id),
                share.address,
                share.effective_difficulty,
                ts_ms,
            )
            .await
        {
            warn_throttled!(
                self.warn_throttle,
                ts_ms as i64,
                error = %e,
                address = share.address,
                difficulty = share.effective_difficulty,
                "PplnsAcceptedShareSink: record_share failed"
            );
        }
    }
}
