// SPDX-License-Identifier: AGPL-3.0-or-later

//! Keep the PPLNS window's network-difficulty view current.
//!
//! The window is capped at `window_factor × networkDifficulty`
//! ([`bp_pplns_engine::window::WindowStore::window_size`]). That value used
//! to be read once, from `getmininginfo` at process start, and then never
//! written again — `NetworkDifficulty::set` had no caller anywhere in the
//! tree. `window_factor` therefore meant "x times the difficulty at the
//! last restart", so a long-running payout process trimmed to a window
//! spanning steadily fewer blocks than configured (difficulty trends up, so
//! the frozen value is the smaller one and the window comes out short).
//!
//! **Why an RPC and not the TDP template stream**, which the old doc
//! claimed: the value is read only by the trim, the trim runs only inside
//! `record_share`, and `record_share` runs on the process that consumes the
//! accepted-share stream — the `payout` role, which has no TDP feed. The
//! Bitcoin RPC is the source that process actually has.
//!
//! **Why the guard matters.** `window_size` returns `0.0` for a
//! non-positive difficulty, and a zero window size disables trimming
//! outright (deliberately — it is the "no difficulty seeded yet" state).
//! So writing a bad reading does not merely mis-size the window, it stops
//! the window from shedding anything at all and lets it grow without
//! bound. A failed or nonsensical reading must leave the last good value
//! in place.

use std::time::Duration;

use bp_bitcoin::BitcoinRpc;
use bp_pplns_engine::window::NetworkDifficulty;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};

/// How often the difficulty is re-read.
///
/// Bitcoin retargets every 2016 blocks (~2 weeks), so this could be far
/// slower and still be correct; `getmininginfo` is a local, cheap call and
/// ten minutes keeps the window honest within one block of a retarget
/// without being chatty.
pub(crate) const REFRESH_INTERVAL: Duration = Duration::from_secs(600);

/// Is this reading usable as the live window difficulty?
///
/// `None` ⇒ leave the previous value alone. Anything non-finite or
/// non-positive is rejected because it would zero `window_size` and switch
/// trimming off; a genuine difficulty is always positive, and a legitimate
/// one can move by any factor (a retarget can halve it), so magnitude is
/// deliberately NOT second-guessed here.
fn usable_difficulty(raw: f64) -> Option<f64> {
    (raw.is_finite() && raw > 0.0).then_some(raw)
}

/// Spawn the refresher. Payout role only — it is the only process whose
/// window trims, and the only one whose `NetworkDifficulty` is read.
pub(crate) fn spawn_refresh_task(
    rpc: BitcoinRpc,
    net_diff: NetworkDifficulty,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        tick.tick().await; // the immediate first tick — boot already seeded
        info!(
            interval_secs = interval.as_secs(),
            seeded = net_diff.get(),
            "network-difficulty refresher: live (PPLNS window trim size)"
        );
        loop {
            tick.tick().await;
            let reading = match rpc.get_mining_info().await {
                Ok(info) => info.difficulty,
                Err(err) => {
                    // Keep the last good value: a zero here would disable
                    // trimming, not just mis-size it.
                    warn!(
                        %err,
                        held = net_diff.get(),
                        "network-difficulty refresher: getmininginfo failed — keeping the last \
                         good value so the window keeps trimming"
                    );
                    continue;
                }
            };
            let Some(usable) = usable_difficulty(reading) else {
                warn!(
                    reading,
                    held = net_diff.get(),
                    "network-difficulty refresher: unusable reading — keeping the last good \
                     value (a non-positive difficulty would switch trimming off)"
                );
                continue;
            };
            let previous = net_diff.get();
            if previous == usable {
                continue;
            }
            net_diff.set(usable);
            // Worth a line: it changes which shares the window holds, and
            // therefore who a block pays.
            info!(
                previous,
                current = usable,
                "network-difficulty refresher: PPLNS window trim size moved"
            );
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MONEY-adjacent: a bad reading must never be written.
    ///
    /// `window_size()` returns 0 for a non-positive difficulty, and a zero
    /// window size disables the trim completely — so writing a 0 would not
    /// mis-size the window, it would let it grow without bound and pay a
    /// block over an ever-widening set of shares.
    #[test]
    fn an_unusable_reading_is_rejected_rather_than_written() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                usable_difficulty(bad),
                None,
                "{bad} must not reach the live window"
            );
        }
    }

    /// And a real reading IS accepted, at any magnitude — a retarget can
    /// legitimately halve the difficulty, so nothing here may second-guess
    /// how far it moved.
    #[test]
    fn any_positive_finite_reading_is_accepted() {
        for good in [1.0, 0.06, 1e-8, 1.2e14, f64::MAX] {
            assert_eq!(usable_difficulty(good), Some(good));
        }
    }

    /// The handle really is shared: a refresh must be observable through the
    /// clone the `WindowStore` holds, or the task would update a private
    /// copy and change nothing.
    #[test]
    fn setting_the_handle_is_observed_by_its_clone() {
        let live = NetworkDifficulty::new(1_000.0);
        let in_window = live.clone();
        live.set(2_500.0);
        assert_eq!(in_window.get(), 2_500.0);
    }
}
