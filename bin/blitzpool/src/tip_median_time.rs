// SPDX-License-Identifier: AGPL-3.0-or-later

//! Median time past of the node's latest tips, read by the SV2 server to judge
//! a custom job's `ntime_start` (SV2 Mining/SetCustomMiningJob).
//!
//! The template stream carries no median time past, so each new tip is looked
//! up once with `getblockheader`, off the path that broadcasts jobs.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bitcoin::hashes::Hash;
use bp_bitcoin::BitcoinRpc;
use bp_stratum_v2::hooks::ChainTipTime;
use bp_template_distribution::{TdpHandle, TemplateUpdate};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// Tips kept, newest last: a connection whose stream is a block behind still
/// finds its tip.
const TIPS_KEPT: usize = 4;

/// Wait before asking the node again after a failed lookup.
const RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// `(prev_hash in internal byte order, median time past)`.
type Tips = VecDeque<([u8; 32], u32)>;

pub(crate) struct TipMedianTime {
    tips: Arc<RwLock<Tips>>,
    _follow: tokio_util::sync::DropGuard,
}

impl TipMedianTime {
    /// Follows every TDP stream: they share one node, but each may see a new
    /// tip first.
    pub(crate) fn spawn<'a>(
        rpc: BitcoinRpc,
        streams: impl IntoIterator<Item = &'a TdpHandle>,
    ) -> Arc<Self> {
        let tips = Arc::new(RwLock::new(Tips::with_capacity(TIPS_KEPT)));
        let cancel = CancellationToken::new();
        for tdp in streams {
            tokio::spawn(follow(
                rpc.clone(),
                tdp.clone(),
                tips.clone(),
                cancel.clone(),
            ));
        }
        Arc::new(Self {
            tips,
            _follow: cancel.drop_guard(),
        })
    }
}

impl ChainTipTime for TipMedianTime {
    fn median_time_past(&self, block_hash: &[u8; 32]) -> Option<u32> {
        lookup(&self.tips.read().expect("tip cache poisoned"), block_hash)
    }
}

fn lookup(tips: &Tips, block_hash: &[u8; 32]) -> Option<u32> {
    tips.iter()
        .find(|(hash, _)| hash == block_hash)
        .map(|(_, mtp)| *mtp)
}

fn insert(tips: &mut Tips, block_hash: [u8; 32], median_time_past: u32) {
    if lookup(tips, &block_hash).is_some() {
        return;
    }
    if tips.len() == TIPS_KEPT {
        tips.pop_front();
    }
    tips.push_back((block_hash, median_time_past));
}

/// Looks up each tip the stream announces until the node answers or a newer
/// tip replaces it.
async fn follow(
    rpc: BitcoinRpc,
    tdp: TdpHandle,
    tips: Arc<RwLock<Tips>>,
    cancel: CancellationToken,
) {
    let mut updates = tdp.subscribe();
    let mut pending = latest_tip(&tdp);
    // Set after a failed lookup: no new attempt for the same tip before it.
    let mut retry_at: Option<Instant> = None;
    loop {
        if let Some(hash) = pending {
            let known = lookup(&tips.read().expect("tip cache poisoned"), &hash).is_some();
            if known {
                pending = None;
            } else if retry_at.is_none_or(|at| Instant::now() >= at) {
                match fetch(&rpc, hash).await {
                    Some(mtp) => {
                        insert(&mut tips.write().expect("tip cache poisoned"), hash, mtp);
                        pending = None;
                    }
                    None => retry_at = Some(Instant::now() + RETRY_INTERVAL),
                }
            }
        }
        if pending.is_none() {
            retry_at = None;
        }
        tokio::select! {
            _ = cancel.cancelled() => break,
            update = updates.recv() => match update {
                Ok(TemplateUpdate::SetNewPrevHash(prev)) => {
                    // A new tip is asked for at once.
                    pending = Some(prev.prev_hash);
                    retry_at = None;
                }
                Ok(_) => {}
                // A skipped update may have been the tip change.
                Err(RecvError::Lagged(_)) => {
                    let latest = latest_tip(&tdp);
                    if latest.is_some() && latest != pending {
                        pending = latest;
                        retry_at = None;
                    }
                }
                Err(RecvError::Closed) => break,
            },
            _ = sleep_until_retry(retry_at), if retry_at.is_some() => {}
        }
    }
}

async fn sleep_until_retry(retry_at: Option<Instant>) {
    if let Some(at) = retry_at {
        tokio::time::sleep_until(at).await;
    }
}

fn latest_tip(tdp: &TdpHandle) -> Option<[u8; 32]> {
    tdp.current_snapshot()
        .set_new_prev_hash
        .map(|prev| prev.prev_hash)
}

async fn fetch(rpc: &BitcoinRpc, block_hash: [u8; 32]) -> Option<u32> {
    let hex = bitcoin::BlockHash::from_byte_array(block_hash).to_string();
    match rpc.get_block_header(&hex).await {
        Ok(header) => {
            if header.mediantime.is_none() {
                warn!(block_hash = %hex, "tip median time: getblockheader has no mediantime");
            }
            debug!(block_hash = %hex, median_time_past = ?header.mediantime, "tip median time");
            header.mediantime
        }
        Err(err) => {
            warn!(block_hash = %hex, %err, "tip median time: getblockheader failed, retrying");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_latest_tips_and_drops_the_oldest() {
        let mut tips = Tips::new();
        for n in 0..=TIPS_KEPT as u8 {
            insert(&mut tips, [n; 32], 1_000 + u32::from(n));
        }
        assert_eq!(lookup(&tips, &[0; 32]), None, "oldest tip dropped");
        assert_eq!(lookup(&tips, &[1; 32]), Some(1_001));
        assert_eq!(
            lookup(&tips, &[TIPS_KEPT as u8; 32]),
            Some(1_000 + TIPS_KEPT as u32)
        );
    }

    #[test]
    fn a_tip_seen_on_two_streams_is_stored_once() {
        let mut tips = Tips::new();
        insert(&mut tips, [7; 32], 1_000);
        insert(&mut tips, [7; 32], 1_000);
        assert_eq!(tips.len(), 1);
    }
}
