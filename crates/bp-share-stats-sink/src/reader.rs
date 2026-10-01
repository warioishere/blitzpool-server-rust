// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only handle onto the engine state.

use std::sync::Arc;

use bp_stats::FlushHealthMonitor;

use crate::flush::{Accumulators, Flusher};

/// Cheap to clone; each method holds a lock only long enough to copy out.
#[derive(Clone)]
pub struct ReaderView {
    pub(crate) accumulators: Arc<Accumulators>,
    pub(crate) health: Arc<std::sync::Mutex<FlushHealthMonitor<Flusher>>>,
}

impl ReaderView {
    /// Per-flusher consecutive-failure count.
    pub fn consecutive_failures(&self, flusher: Flusher) -> u32 {
        self.health
            .lock()
            .expect("flush health monitor poisoned")
            .consecutive_failures(&flusher)
    }

    /// Pending residuals, for backlog monitoring.
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
