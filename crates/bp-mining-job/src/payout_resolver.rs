// SPDX-License-Identifier: AGPL-3.0-or-later

//! The mode-aware payout list SV1, SV2 and JDP build every coinbase from.

use async_trait::async_trait;
use bp_common::{AddressId, StreamKind};

use crate::ResolvedPayouts;

/// Resolves a miner address to the coinbase payout list of each template,
/// fed to [`crate::build_mining_job_from_tdp`]. One resolver serves every
/// protocol, so the same address gets the same coinbase on SV1, SV2 and JDP.
#[async_trait]
pub trait PayoutResolver: Send + Sync {
    /// Exact output sats per entry, placed verbatim, plus the fingerprint of
    /// the distribution they came from (zeroed = books without a snapshot).
    /// `reward_sats` is the template's `coinbase_tx_value_remaining`.
    async fn resolve_payouts(&self, miner_address: &AddressId, reward_sats: u64)
        -> ResolvedPayouts;

    /// The template stream this address mines on, fixed when its session
    /// authorizes (SV1) or opens a channel (SV2). Sync because the mode
    /// lookup is an in-memory cache hit. Defaults to `StreamKind::Pplns`
    /// (single stream).
    fn resolve_stream(&self, _miner_address: &AddressId) -> StreamKind {
        StreamKind::Pplns
    }

    /// [`Self::resolve_stream`], with `None` for "not known yet": the mode cache
    /// learns an address from its mining session, which the JDP allocate path
    /// normally precedes.
    fn resolve_stream_known(&self, miner_address: &AddressId) -> Option<StreamKind> {
        Some(self.resolve_stream(miner_address))
    }
}
