// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only handle onto the engine state — `/api/admin/stats-health`
//! surface + the chart-API can use this without taking write locks on
//! the accumulators.

use std::sync::Arc;

use bp_stats::FlushHealthMonitor;

use crate::flush::{Accumulators, Flusher};

/// Cheap-to-clone reader. Each public method takes a short lock on the
/// underlying state, copies the value out, and drops the lock.
#[derive(Clone)]
pub struct ReaderView {
    pub(crate) accumulators: Arc<Accumulators>,
    pub(crate) health: Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
}

impl ReaderView {
    /// Per-flusher consecutive-failure count. Useful for an admin
    /// endpoint that wants to surface "X minutes of failures on
    /// `client_statistics`".
    pub fn consecutive_failures(&self, flusher: Flusher) -> u32 {
        self.health
            .lock()
            .expect("flush health monitor poisoned")
            .consecutive_failures(&flusher)
    }

    /// Cheap counts of pending residuals — useful for backlog monitoring
    /// and the `/api/admin/stats-health` surface.
    pub fn pending_pool_shares(&self) -> usize {
        self.accumulators.pool_shares.len()
    }
    pub fn pending_pool_mode_hashrate(&self) -> usize {
        self.accumulators.pool_mode_hashrate.len()
    }
    pub fn pending_pool_rejected(&self) -> usize {
        self.accumulators.pool_rejected.len()
    }
    pub fn pending_client_statistics(&self) -> usize {
        self.accumulators.client_statistics.len()
    }
    pub fn pending_client_rejected(&self) -> usize {
        self.accumulators.client_rejected.len()
    }
}
