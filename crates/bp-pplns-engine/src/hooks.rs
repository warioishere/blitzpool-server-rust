// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bp_share_hook::SharedAcceptedShareSink` impl, mode-gated on
//! `MiningMode == PPLNS`.
//!
//! Per-share engine hooks are decoupled from the wire protocol via the
//! [`bp_share_hook::SharedAcceptedShareSink`] trait: SV1 and SV2 each
//! carry a thin adapter into the shared view, so this impl serves both.
//! The share carries its producer-resolved [`bp_share_hook::MiningMode`],
//! so this sink checks `share.mode == Pplns` without a mode-gate query.
//!
//! # Block-submission hook
//!
//! No block-submission sink is provided here: that trait surface is
//! protocol-specific (it carries the full `ShareAccept` for the TDP
//! `submit_solution` call), so it is wired in `bin/blitzpool` where the
//! TDP-stream context (block height) joins the share-accept payload.

use async_trait::async_trait;
use bp_common::{warn_throttled, LogThrottle, MiningMode};
use bp_share_hook::{SharedAcceptedShare, SharedAcceptedShareSink};

/// Throttle window for the per-share `record_share failed` warning. A Redis
/// outage fails every accepted share; without this a busy pool would emit
/// thousands of identical warns/s. One line per 5s + a suppressed count is
/// enough to alert without burying the log or filling disk.
const RECORD_SHARE_WARN_THROTTLE_MS: i64 = 5_000;

use crate::engine::PplnsEngine;

/// `SharedAcceptedShareSink` impl that records the share in the PPLNS
/// window iff the address resolves to PPLNS mode.
///
/// Composed into the SV1 / SV2 server hooks via the per-protocol
/// adapters in `bin/blitzpool`.
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
        // Use the share's Core-accept time, not now(): under the
        // Core/Satellite split this sink may run in a separate process
        // and replay backlogged shares — re-stamping now() would put them
        // in the wrong PPLNS-window slot / timestamp.
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
            // Throttled: a Redis outage fails every share — warn at most once
            // per window with a count of those suppressed since.
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
