// SPDX-License-Identifier: AGPL-3.0-or-later

//! Spreads same-tip template refreshes over a short window, one fixed delay
//! per connection, so a fee update leaves the pool as a trickle instead of one
//! burst to every miner at once. A new block is never delayed: it retires the
//! old work, while a refresh leaves the current job valid.

use std::time::Duration;

use tokio::sync::broadcast;
use tokio::time::Instant;

use crate::TemplateChange;

/// The window a refresh is spread over. Every connection gets its refresh
/// within this time of the template's arrival.
pub const REFRESH_SPREAD: Duration = Duration::from_secs(1);

/// A broadcast payload that says which kind of template change it carries.
pub trait PacedBroadcast: Clone {
    fn template_change(&self) -> TemplateChange;
}

/// One connection's view of the template broadcast. Hand it the receiver in
/// the connection's `select!` instead of calling `recv` directly.
#[derive(Debug)]
pub struct RefreshPacer<T> {
    delay: Duration,
    held: Option<(T, Instant)>,
}

impl<T: PacedBroadcast> RefreshPacer<T> {
    /// `seed` picks this connection's delay inside `spread`. It must be spread
    /// evenly itself; both servers pass their random session id.
    pub fn new(seed: u64, spread: Duration) -> Self {
        let spread_ms = u64::try_from(spread.as_millis()).unwrap_or(u64::MAX);
        let delay_ms = if spread_ms == 0 { 0 } else { seed % spread_ms };
        Self {
            delay: Duration::from_millis(delay_ms),
            held: None,
        }
    }

    /// Drops a held refresh. Call it when the connection switches to another
    /// template stream, whose refreshes the held one does not belong to.
    pub fn clear(&mut self) {
        self.held = None;
    }

    /// The next broadcast to apply. A new block comes at once and drops a held
    /// refresh. A refresh is held until this connection's delay has passed; a
    /// newer refresh in the meantime replaces it and keeps the time. A lag
    /// error drops a held refresh too: it may belong to a tip the skipped
    /// broadcasts moved past. Cancel-safe: a held refresh survives the future
    /// being dropped.
    pub async fn next(
        &mut self,
        rx: &mut broadcast::Receiver<T>,
    ) -> Result<T, broadcast::error::RecvError> {
        loop {
            let due = self.held.as_ref().map(|(_, at)| *at);
            tokio::select! {
                biased;
                received = rx.recv() => {
                    let broadcast = match received {
                        Ok(b) => b,
                        Err(err) => {
                            self.held = None;
                            return Err(err);
                        }
                    };
                    match broadcast.template_change() {
                        TemplateChange::NewBlock => {
                            self.held = None;
                            return Ok(broadcast);
                        }
                        TemplateChange::Refresh if self.delay.is_zero() => return Ok(broadcast),
                        TemplateChange::Refresh => {
                            let at = due.unwrap_or_else(|| Instant::now() + self.delay);
                            self.held = Some((broadcast, at));
                        }
                    }
                }
                _ = tokio::time::sleep_until(due.unwrap_or_else(Instant::now)), if due.is_some() => {
                    if let Some((broadcast, _)) = self.held.take() {
                        return Ok(broadcast);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    struct Evt {
        change: TemplateChange,
        n: u32,
    }

    impl PacedBroadcast for Evt {
        fn template_change(&self) -> TemplateChange {
            self.change
        }
    }

    fn refresh(n: u32) -> Evt {
        Evt {
            change: TemplateChange::Refresh,
            n,
        }
    }

    fn new_block(n: u32) -> Evt {
        Evt {
            change: TemplateChange::NewBlock,
            n,
        }
    }

    fn pacer_with_delay(delay_ms: u64) -> RefreshPacer<Evt> {
        let pacer = RefreshPacer::new(delay_ms, REFRESH_SPREAD);
        assert_eq!(pacer.delay, Duration::from_millis(delay_ms));
        pacer
    }

    /// Nothing comes out of `next` within `wait`.
    async fn assert_nothing_within(
        pacer: &mut RefreshPacer<Evt>,
        rx: &mut broadcast::Receiver<Evt>,
        wait: Duration,
    ) {
        let got = tokio::time::timeout(wait, pacer.next(rx)).await;
        assert!(got.is_err(), "nothing is due, got {got:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_block_comes_at_once() {
        let (tx, mut rx) = broadcast::channel(8);
        let mut pacer = pacer_with_delay(700);
        let start = Instant::now();
        tx.send(new_block(1)).unwrap();
        assert_eq!(pacer.next(&mut rx).await.unwrap(), new_block(1));
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refresh_comes_after_the_connection_delay() {
        let (tx, mut rx) = broadcast::channel(8);
        let mut pacer = pacer_with_delay(700);
        let start = Instant::now();
        tx.send(refresh(1)).unwrap();
        assert_eq!(pacer.next(&mut rx).await.unwrap(), refresh(1));
        assert_eq!(start.elapsed(), Duration::from_millis(700));
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_block_replaces_a_held_refresh() {
        let (tx, mut rx) = broadcast::channel(8);
        let mut pacer = pacer_with_delay(700);
        let start = Instant::now();
        tx.send(refresh(1)).unwrap();
        let sender = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            tx.send(new_block(2)).unwrap();
            tx
        });
        assert_eq!(pacer.next(&mut rx).await.unwrap(), new_block(2));
        assert_eq!(start.elapsed(), Duration::from_millis(300));
        let _tx = sender.await.unwrap();
        // The stale refresh is gone: nothing comes at its old time or after.
        assert_nothing_within(&mut pacer, &mut rx, Duration::from_secs(2)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_newer_refresh_replaces_the_held_one_and_keeps_its_time() {
        let (tx, mut rx) = broadcast::channel(8);
        let mut pacer = pacer_with_delay(700);
        let start = Instant::now();
        tx.send(refresh(1)).unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            tx.send(refresh(2)).unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        assert_eq!(pacer.next(&mut rx).await.unwrap(), refresh(2));
        assert_eq!(start.elapsed(), Duration::from_millis(700));
    }

    /// The caller's `select!` drops the future when another arm wins; the
    /// held refresh still comes at its time.
    #[tokio::test(start_paused = true)]
    async fn a_held_refresh_survives_a_dropped_future() {
        let (tx, mut rx) = broadcast::channel(8);
        let mut pacer = pacer_with_delay(700);
        let start = Instant::now();
        tx.send(refresh(1)).unwrap();
        tokio::select! {
            _ = pacer.next(&mut rx) => panic!("not due yet"),
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
        assert_eq!(pacer.next(&mut rx).await.unwrap(), refresh(1));
        assert_eq!(start.elapsed(), Duration::from_millis(700));
    }

    #[tokio::test(start_paused = true)]
    async fn clear_drops_a_held_refresh() {
        let (tx, mut rx) = broadcast::channel(8);
        let mut pacer = pacer_with_delay(700);
        tx.send(refresh(1)).unwrap();
        tokio::select! {
            _ = pacer.next(&mut rx) => panic!("not due yet"),
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        pacer.clear();
        assert_nothing_within(&mut pacer, &mut rx, Duration::from_secs(2)).await;
        drop(tx);
    }

    /// A lag error drops a held refresh: the skipped broadcasts may have
    /// moved the tip.
    #[tokio::test(start_paused = true)]
    async fn a_lag_error_drops_a_held_refresh() {
        let (tx, mut rx) = broadcast::channel(2);
        let mut pacer = pacer_with_delay(700);
        tx.send(refresh(1)).unwrap();
        tokio::select! {
            _ = pacer.next(&mut rx) => panic!("not due yet"),
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        // Three more than the channel holds: the next read reports a lag.
        for n in 2..5 {
            tx.send(refresh(n)).unwrap();
        }
        assert!(matches!(
            pacer.next(&mut rx).await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));
        // Drain what is left, then nothing may come at the held time.
        while rx.try_recv().is_ok() {}
        assert_nothing_within(&mut pacer, &mut rx, Duration::from_secs(2)).await;
        drop(tx);
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_spread_passes_refreshes_through() {
        let (tx, mut rx) = broadcast::channel(8);
        let mut pacer = RefreshPacer::new(42, Duration::ZERO);
        let start = Instant::now();
        tx.send(refresh(1)).unwrap();
        assert_eq!(pacer.next(&mut rx).await.unwrap(), refresh(1));
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    /// 1000 connections with random u32 seeds, as both servers hand them out:
    /// every delay stays inside the window and no 100 ms slice gets far more
    /// than its share.
    #[test]
    fn delays_spread_evenly_over_the_window() {
        let mut slices = [0usize; 10];
        // A fixed xorshift sequence stands in for the session ids.
        let mut x: u32 = 0x9e37_79b9;
        for _ in 0..1000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let delay = RefreshPacer::<Evt>::new(u64::from(x), REFRESH_SPREAD).delay;
            assert!(delay < REFRESH_SPREAD);
            slices[(delay.as_millis() / 100) as usize] += 1;
        }
        for (i, n) in slices.iter().enumerate() {
            assert!((60..=140).contains(n), "slice {i} holds {n} of 1000");
        }
    }
}
