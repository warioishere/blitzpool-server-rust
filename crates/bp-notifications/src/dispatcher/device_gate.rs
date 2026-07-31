// SPDX-License-Identifier: AGPL-3.0-or-later

//! Debounce + coalescing stage in front of the device-status fan-out.
//!
//! The Stratum servers emit device events on **edges**: one per
//! `Authorized` / `Disconnect` (SV1) and one per `ChannelOpened` /
//! `ChannelClosed` (SV2). Forwarding those straight to the transports —
//! what the pool did before this module existed — makes three things go
//! wrong at once:
//!
//! 1. **Flapping.** A miner on bad WiFi reconnects every few seconds and
//!    every reconnect is an offline+online push pair.
//! 2. **Multi-session sources.** A rental source (many rigs authorizing
//!    under one worker name) or an SV2 connection holding several
//!    channels produces one event per rig / per channel, so a single rig
//!    rotating out reads as "the device went offline" even though the
//!    rest are still hashing.
//! 3. **Restarts.** A front restart drops every session at once, which
//!    is one push per subscriber per worker.
//!
//! ## The rule
//!
//! Notify on transitions of the **reported** state, not of the actual
//! one. Each `(address, worker)` carries a [`Notified`] value — what the
//! subscriber was last told. An event never sends anything; it only
//! schedules a re-evaluation (`due_at`). At the due instant the gate asks
//! the database how many sessions are actually live and emits only when
//! that answer differs from `notified`.
//!
//! The asymmetry an event-pair debounce would have — "device came back
//! inside the grace, so now it reports online without ever having
//! reported offline" — cannot occur here, because the comparison is
//! against what was sent, not against the previous event.
//!
//! ## Why the database and not an in-memory refcount
//!
//! `client_entity` rows with `deletedAt IS NULL` are already the
//! authoritative live-session view: cleared on register, stamped on
//! disconnect, swept by the 60 s dead-client cron for unclean drops. A
//! refcount kept in this process would instead have to be rebuilt after
//! every restart — and could not be rebuilt correctly, since the gate
//! never sees the connect events that happened before it started. Asking
//! the table at emission time is restart-proof and front-count-proof,
//! and it costs one round-trip per sweep no matter how many devices are
//! due.
//!
//! ## Scheduling
//!
//! Only the **first** event after a resolution arms `due_at`; later
//! events refresh the render metadata but never push the deadline back.
//! A device flapping every 30 s therefore still resolves exactly once
//! per grace period, and what it resolves to is whatever the database
//! says at that moment — the intermediate churn is irrelevant by
//! construction.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use bp_common::AddressId;
use bp_cron_utils::Clock;
use chrono::{DateTime, Utc};

use super::orchestrator::DeviceStatusEvent;

/// Identity a notification is about: `(address, worker)`. Deliberately
/// not the session id — a session is one TCP connection or one SV2
/// channel, and the subscriber cares about the device.
type DeviceKey = (String, String);

/// How long an entry that has already reported offline is kept before
/// it is dropped from the map. Only bounds memory: a device that comes
/// back after eviction is treated as first-seen, which resolves to the
/// same message it would have produced anyway (it has been away far
/// longer than the returning window, so `is_returning` is false).
const EVICT_AFTER: Duration = Duration::from_secs(60 * 60);

/// Timing knobs. Defaults match [`bp_config`]'s serde defaults; the
/// binary passes the configured values through.
#[derive(Debug, Clone, Copy)]
pub struct DeviceGateConfig {
    /// How long a device must look gone before "offline" is reported.
    pub offline_grace: Duration,
    /// How long a device must look present before "online" is reported.
    pub online_dwell: Duration,
    /// Minimum spacing between two messages for the same address.
    /// Transitions that arrive inside the window are buffered and go out
    /// together as one [`DeviceNotice::Aggregate`].
    pub coalesce_window: Duration,
}

impl Default for DeviceGateConfig {
    fn default() -> Self {
        Self {
            offline_grace: Duration::from_secs(300),
            online_dwell: Duration::from_secs(90),
            coalesce_window: Duration::from_secs(300),
        }
    }
}

/// What the subscriber was last told about a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Notified {
    /// Nothing has been sent for this device in this process.
    Unknown,
    Online,
    Offline,
}

/// Live-session lookup, abstracted so the gate is unit-testable without
/// a database.
///
/// `None` means **the lookup could not be performed** (e.g. the database
/// is unreachable). It is not "no live sessions": the caller must draw
/// no conclusion and retry, otherwise a database blip would fire an
/// offline notification for every miner on the pool.
#[async_trait]
pub trait LiveSessionLookup: Send + Sync {
    async fn live_counts(&self, keys: &[DeviceKey]) -> Option<HashMap<DeviceKey, i64>>;
}

/// A confirmed, ready-to-send device-status message.
#[derive(Debug, Clone)]
pub enum DeviceNotice {
    /// One transition — rendered exactly as before this module existed.
    Single(DeviceStatusEvent),
    /// Several transitions for one address inside the coalescing window,
    /// collapsed into a single message.
    Aggregate(DeviceAggregate),
}

/// Collapsed form of two or more transitions on one address.
#[derive(Debug, Clone)]
pub struct DeviceAggregate {
    pub address: AddressId,
    /// Worker names that went offline, in resolution order.
    pub went_offline: Vec<String>,
    /// Worker names that came online, in resolution order.
    pub came_online: Vec<String>,
    /// When the batch was released.
    pub timestamp: DateTime<Utc>,
}

/// Per-device gate state.
#[derive(Debug, Clone)]
struct DeviceState {
    notified: Notified,
    /// When set, the device is scheduled for re-evaluation at this time.
    /// Cleared by the resolution; only re-armed by the next event.
    due_at: Option<DateTime<Utc>>,
    /// Most recent raw event — supplies worker name, user agent,
    /// `is_returning` and the timestamp the message renders.
    meta: DeviceStatusEvent,
    /// Last time this entry saw an event or a resolution. Drives eviction.
    touched: DateTime<Utc>,
}

/// Per-address coalescing state.
#[derive(Debug, Default)]
struct AddressState {
    /// Confirmed transitions waiting for the window to open.
    buffered: Vec<DeviceStatusEvent>,
    /// When this address last had a message released.
    last_emit: Option<DateTime<Utc>>,
}

#[derive(Debug, Default)]
struct Inner {
    devices: HashMap<DeviceKey, DeviceState>,
    addresses: HashMap<String, AddressState>,
}

/// Debounce + coalescing stage. Feed every raw device event through
/// [`observe`](Self::observe); drive [`poll_due`](Self::poll_due) from a
/// periodic task and hand whatever it returns to the dispatcher.
pub struct DeviceStatusGate<C, L> {
    cfg: DeviceGateConfig,
    clock: C,
    lookup: L,
    inner: Mutex<Inner>,
}

impl<C: Clock, L: LiveSessionLookup> DeviceStatusGate<C, L> {
    pub fn new(cfg: DeviceGateConfig, clock: C, lookup: L) -> Self {
        Self {
            cfg,
            clock,
            lookup,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Record a raw device event. Never sends anything — it refreshes the
    /// render metadata and, if no evaluation is pending, arms one.
    pub fn observe(&self, event: &DeviceStatusEvent) {
        let now = self.clock.now();
        let key = key_of(event);
        let dwell = if event.is_online {
            self.cfg.online_dwell
        } else {
            self.cfg.offline_grace
        };
        let due =
            now + chrono::Duration::from_std(dwell).unwrap_or_else(|_| chrono::Duration::zero());

        let mut inner = self.lock();
        let state = inner.devices.entry(key).or_insert_with(|| DeviceState {
            notified: Notified::Unknown,
            due_at: None,
            meta: event.clone(),
            touched: now,
        });
        state.meta = event.clone();
        state.touched = now;
        // Only the first event after a resolution arms the deadline.
        // Refreshing it here would let a device that flaps faster than
        // the grace period postpone its own evaluation indefinitely.
        if state.due_at.is_none() {
            state.due_at = Some(due);
        }
    }

    /// Resolve every device whose deadline has passed and release
    /// whatever the coalescing window allows. Call on a fixed interval.
    pub async fn poll_due(&self) -> Vec<DeviceNotice> {
        let now = self.clock.now();

        let due: Vec<DeviceKey> = {
            let inner = self.lock();
            inner
                .devices
                .iter()
                .filter(|(_, s)| s.due_at.is_some_and(|d| d <= now))
                .map(|(k, _)| k.clone())
                .collect()
        };

        // No lock held across the await.
        if !due.is_empty() {
            let Some(counts) = self.lookup.live_counts(&due).await else {
                // Lookup unavailable — leave every deadline armed and
                // retry on the next tick rather than guessing "offline".
                return Vec::new();
            };
            self.resolve(&due, &counts, now);
        }

        self.release(now)
    }

    /// Apply the live-session answer to every due device, pushing the
    /// confirmed transitions into their address buffers.
    fn resolve(&self, due: &[DeviceKey], counts: &HashMap<DeviceKey, i64>, now: DateTime<Utc>) {
        let mut inner = self.lock();
        for key in due {
            let live = counts.get(key).copied().unwrap_or(0) > 0;
            let Some(state) = inner.devices.get_mut(key) else {
                continue;
            };
            state.due_at = None;
            state.touched = now;

            let target = if live {
                Notified::Online
            } else {
                Notified::Offline
            };
            if target == state.notified {
                continue;
            }
            // A device we have never reported on is only worth an
            // "online" message when it is genuinely new. Without this,
            // restarting the notify process would announce every miner
            // on the pool the next time it is evaluated — they are all
            // `Unknown` again, and they are all live.
            if state.notified == Notified::Unknown
                && target == Notified::Online
                && state.meta.is_returning
            {
                state.notified = Notified::Online;
                continue;
            }
            state.notified = target;

            let mut event = state.meta.clone();
            event.is_online = live;
            // Keep the event's own timestamp when it agreed with the
            // database — "offline since <disconnect>" is more useful than
            // "offline since <we checked>". Fall back to now when the
            // last event pointed the other way.
            if state.meta.is_online != live {
                event.timestamp = now;
            }
            let address = event.address.as_str().to_string();
            inner
                .addresses
                .entry(address)
                .or_default()
                .buffered
                .push(event);
        }
        evict(&mut inner, now);
    }

    /// Release one message per address whose coalescing window is open.
    fn release(&self, now: DateTime<Utc>) -> Vec<DeviceNotice> {
        let window = chrono::Duration::from_std(self.cfg.coalesce_window)
            .unwrap_or_else(|_| chrono::Duration::zero());
        let mut out = Vec::new();
        let mut inner = self.lock();
        for state in inner.addresses.values_mut() {
            if state.buffered.is_empty() {
                continue;
            }
            if state.last_emit.is_some_and(|last| now - last < window) {
                continue;
            }
            let batch = std::mem::take(&mut state.buffered);
            state.last_emit = Some(now);
            out.push(collapse(batch, now));
        }
        out
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// One transition stays a plain single message; several become an
/// aggregate so an address can never exceed one message per window.
fn collapse(batch: Vec<DeviceStatusEvent>, now: DateTime<Utc>) -> DeviceNotice {
    if batch.len() == 1 {
        return DeviceNotice::Single(batch.into_iter().next().expect("len == 1"));
    }
    let address = batch[0].address.clone();
    let mut went_offline = Vec::new();
    let mut came_online = Vec::new();
    for event in &batch {
        let worker = event
            .worker_name
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        if event.is_online {
            came_online.push(worker);
        } else {
            went_offline.push(worker);
        }
    }
    DeviceNotice::Aggregate(DeviceAggregate {
        address,
        went_offline,
        came_online,
        timestamp: now,
    })
}

/// Drop settled offline entries once they are older than [`EVICT_AFTER`],
/// and address entries that hold nothing and have not emitted recently.
/// Entries with an armed deadline or a pending buffer are never touched.
fn evict(inner: &mut Inner, now: DateTime<Utc>) {
    let cutoff =
        chrono::Duration::from_std(EVICT_AFTER).unwrap_or_else(|_| chrono::Duration::zero());
    inner.devices.retain(|_, s| {
        s.due_at.is_some() || s.notified != Notified::Offline || now - s.touched < cutoff
    });
    inner
        .addresses
        .retain(|_, s| !s.buffered.is_empty() || s.last_emit.is_some_and(|l| now - l < cutoff));
}

fn key_of(event: &DeviceStatusEvent) -> DeviceKey {
    (
        event.address.as_str().to_string(),
        event.worker_name.clone().unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_cron_utils::TestClock;
    use std::sync::Arc;

    const ADDR: &str = "bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";

    fn t0() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T12:00:00Z")
            .expect("fixed timestamp")
            .with_timezone(&Utc)
    }

    /// Live-session answers the test drives directly. `set` mirrors what
    /// `client_entity` would report; `fail` simulates an unreachable DB.
    #[derive(Default)]
    struct FakeLookup {
        live: Mutex<HashMap<DeviceKey, i64>>,
        fail: Mutex<bool>,
    }

    impl FakeLookup {
        fn set(&self, worker: &str, n: i64) {
            self.live
                .lock()
                .expect("lock")
                .insert((ADDR.to_string(), worker.to_string()), n);
        }
        fn fail(&self, on: bool) {
            *self.fail.lock().expect("lock") = on;
        }
    }

    #[async_trait]
    impl LiveSessionLookup for Arc<FakeLookup> {
        async fn live_counts(&self, keys: &[DeviceKey]) -> Option<HashMap<DeviceKey, i64>> {
            if *self.fail.lock().expect("lock") {
                return None;
            }
            let live = self.live.lock().expect("lock");
            Some(
                keys.iter()
                    .filter_map(|k| live.get(k).map(|n| (k.clone(), *n)))
                    .collect(),
            )
        }
    }

    fn event(worker: &str, online: bool, returning: bool, at: DateTime<Utc>) -> DeviceStatusEvent {
        DeviceStatusEvent {
            address: AddressId::new(ADDR.to_string()).expect("valid address"),
            worker_name: Some(worker.to_string()),
            user_agent: Some("cpuminer/2.5".to_string()),
            is_online: online,
            is_returning: returning,
            timestamp: at,
        }
    }

    struct Harness {
        gate: DeviceStatusGate<TestClock, Arc<FakeLookup>>,
        clock: TestClock,
        lookup: Arc<FakeLookup>,
    }

    fn harness() -> Harness {
        harness_with(DeviceGateConfig::default())
    }

    fn harness_with(cfg: DeviceGateConfig) -> Harness {
        let clock = TestClock::new(t0());
        let lookup = Arc::new(FakeLookup::default());
        Harness {
            gate: DeviceStatusGate::new(cfg, clock.clone(), Arc::clone(&lookup)),
            clock,
            lookup,
        }
    }

    impl Harness {
        fn advance(&self, secs: i64) {
            let now = self.clock.now();
            self.clock.set(now + chrono::Duration::seconds(secs));
        }
        /// Bring a worker to a reported-online state the way production
        /// does: a first-ever connect, confirmed after the dwell.
        async fn bring_online(&self, worker: &str) {
            self.lookup.set(worker, 1);
            self.gate
                .observe(&event(worker, true, false, self.clock.now()));
            self.advance(100);
            let out = self.gate.poll_due().await;
            assert_eq!(out.len(), 1, "first connect must announce the device");
        }
    }

    fn singles(notices: &[DeviceNotice]) -> Vec<(String, bool)> {
        notices
            .iter()
            .map(|n| match n {
                DeviceNotice::Single(e) => (e.worker_name.clone().unwrap_or_default(), e.is_online),
                DeviceNotice::Aggregate(_) => panic!("expected a single notice"),
            })
            .collect()
    }

    /// The complaint this module exists for: a miner on bad WiFi drops
    /// and returns inside the grace period. Nothing may be sent —
    /// neither the offline it never earned nor the online that would
    /// otherwise follow it.
    #[tokio::test]
    async fn a_reconnect_inside_the_grace_sends_nothing() {
        let h = harness();
        h.bring_online("axe01").await;

        h.lookup.set("axe01", 0);
        h.gate.observe(&event("axe01", false, false, h.clock.now()));
        h.advance(40);
        assert!(h.gate.poll_due().await.is_empty(), "grace has not elapsed");

        // Back before the deadline: the database sees it live again.
        h.lookup.set("axe01", 1);
        h.gate.observe(&event("axe01", true, true, h.clock.now()));
        h.advance(300);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "reported state never changed, so nothing may go out"
        );
    }

    /// A device that stays gone must still be reported — exactly once.
    #[tokio::test]
    async fn a_device_that_stays_gone_reports_offline_once() {
        let h = harness();
        h.bring_online("axe01").await;

        h.lookup.set("axe01", 0);
        h.gate.observe(&event("axe01", false, false, h.clock.now()));
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)]
        );

        h.advance(3600);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "no re-arming without a new event"
        );
    }

    /// The rental-source case: many rigs authorize under one worker name
    /// and rotate individually. A single rig leaving is not the device
    /// going offline, and the database is what settles that.
    #[tokio::test]
    async fn one_of_many_sessions_leaving_is_not_an_outage() {
        let h = harness();
        h.lookup.set("mrr", 50);
        h.gate.observe(&event("mrr", true, true, h.clock.now()));
        h.advance(100);
        // `is_returning` — a known source, not a new device.
        assert!(h.gate.poll_due().await.is_empty());

        // One rig rotates out; 49 remain.
        h.lookup.set("mrr", 49);
        h.gate.observe(&event("mrr", false, false, h.clock.now()));
        h.advance(301);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "the source still has live sessions"
        );

        // The contract ends: nothing left.
        h.lookup.set("mrr", 0);
        h.gate.observe(&event("mrr", false, false, h.clock.now()));
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("mrr".into(), false)]
        );
    }

    /// A device flapping faster than the grace period must not be able to
    /// postpone its own evaluation — otherwise it would never resolve.
    #[tokio::test]
    async fn rapid_flapping_still_resolves_on_schedule() {
        let h = harness();
        h.bring_online("axe01").await;
        h.lookup.set("axe01", 0);

        let start = h.clock.now();
        for _ in 0..10 {
            h.gate.observe(&event("axe01", false, false, h.clock.now()));
            h.advance(15);
            h.gate.observe(&event("axe01", true, true, h.clock.now()));
            h.advance(15);
        }
        assert!(
            h.clock.now() - start >= chrono::Duration::seconds(300),
            "test drove past the grace period"
        );
        // The database is the arbiter, and it says gone.
        let out = h.gate.poll_due().await;
        assert_eq!(singles(&out), vec![("axe01".into(), false)]);
    }

    /// An "online" message may only ever follow an "offline" message.
    /// This is the property that makes the debounce explainable to a
    /// subscriber, so it is asserted directly rather than implied.
    #[tokio::test]
    async fn online_never_precedes_offline_for_a_known_device() {
        let h = harness();
        h.bring_online("axe01").await;

        for cycle in 0..5 {
            h.lookup.set("axe01", 0);
            h.gate.observe(&event("axe01", false, false, h.clock.now()));
            h.advance(30);
            h.lookup.set("axe01", 1);
            h.gate.observe(&event("axe01", true, true, h.clock.now()));
            h.advance(300);
            assert!(
                h.gate.poll_due().await.is_empty(),
                "cycle {cycle} produced a message for an unchanged reported state"
            );
        }
    }

    /// A brand-new device keeps its confirmation push — that is what
    /// tells someone their fresh miner is set up correctly. A device the
    /// pool already knows (`is_returning`) does not, which is what keeps
    /// a notify restart from announcing every miner at once.
    #[tokio::test]
    async fn first_connect_announces_but_a_known_device_does_not() {
        let h = harness();
        h.lookup.set("fresh", 1);
        h.gate.observe(&event("fresh", true, false, h.clock.now()));
        h.advance(100);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("fresh".into(), true)]
        );

        let h2 = harness();
        h2.lookup.set("known", 1);
        h2.gate.observe(&event("known", true, true, h2.clock.now()));
        h2.advance(100);
        assert!(
            h2.gate.poll_due().await.is_empty(),
            "a device the pool saw recently must not be announced by a fresh gate"
        );
    }

    /// After a notify restart the gate knows nothing. A device that then
    /// disconnects for good is still genuinely offline, and the database
    /// says so — that message is correct and must survive.
    #[tokio::test]
    async fn an_unknown_device_going_offline_is_still_reported() {
        let h = harness();
        h.lookup.set("axe01", 0);
        h.gate.observe(&event("axe01", false, false, h.clock.now()));
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)]
        );
    }

    /// A database blip must not be read as "everyone is offline".
    #[tokio::test]
    async fn a_failed_lookup_holds_the_deadline_instead_of_guessing() {
        let h = harness();
        h.bring_online("axe01").await;
        h.lookup.set("axe01", 0);
        h.gate.observe(&event("axe01", false, false, h.clock.now()));
        h.advance(301);

        h.lookup.fail(true);
        assert!(h.gate.poll_due().await.is_empty(), "no guess while blind");

        h.lookup.fail(false);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)],
            "the deadline stayed armed and resolves once the lookup works"
        );
    }

    /// Several workers of one address settling together must cost one
    /// message, not one per worker.
    #[tokio::test]
    async fn simultaneous_transitions_collapse_into_one_message() {
        let h = harness();
        for w in ["a", "b", "c"] {
            h.bring_online(w).await;
            // Each `bring_online` emits; open the window again so the
            // setup does not interfere with what is being measured.
            h.advance(301);
        }
        for w in ["a", "b", "c"] {
            h.lookup.set(w, 0);
            h.gate.observe(&event(w, false, false, h.clock.now()));
        }
        h.advance(301);

        let out = h.gate.poll_due().await;
        assert_eq!(out.len(), 1, "one address, one message");
        match &out[0] {
            DeviceNotice::Aggregate(agg) => {
                let mut names = agg.went_offline.clone();
                names.sort();
                assert_eq!(names, vec!["a", "b", "c"]);
                assert!(agg.came_online.is_empty());
            }
            DeviceNotice::Single(_) => panic!("three transitions must aggregate"),
        }
    }

    /// The coalescing window is a hard ceiling on message rate: a
    /// transition that resolves while the window is still open is held,
    /// and goes out only once the window reopens. Both halves are
    /// asserted — a test that only checked the release would pass even
    /// with the ceiling removed entirely.
    #[tokio::test]
    async fn a_transition_inside_the_window_is_held_then_released() {
        let h = harness();
        h.bring_online("a").await; // emits, opening the window

        // A second device settles 95 s later — well inside the 300 s window.
        h.lookup.set("b", 1);
        h.gate.observe(&event("b", true, false, h.clock.now()));
        h.advance(95);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "resolved, but the address already sent a message inside the window"
        );

        // Once the window reopens the held transition goes out — and it
        // is not lost in the meantime.
        h.advance(210);
        let out = h.gate.poll_due().await;
        assert_eq!(singles(&out), vec![("b".into(), true)]);
    }

    /// Two transitions held together must leave as one message, not two
    /// back-to-back once the window reopens.
    #[tokio::test]
    async fn transitions_held_across_the_window_leave_together() {
        let h = harness();
        h.bring_online("a").await; // opens the window

        for w in ["b", "c"] {
            h.lookup.set(w, 1);
            h.gate.observe(&event(w, true, false, h.clock.now()));
        }
        h.advance(95);
        assert!(h.gate.poll_due().await.is_empty(), "both held");

        h.advance(210);
        let out = h.gate.poll_due().await;
        assert_eq!(out.len(), 1, "one address, one message");
        match &out[0] {
            DeviceNotice::Aggregate(agg) => {
                let mut names = agg.came_online.clone();
                names.sort();
                assert_eq!(names, vec!["b", "c"]);
            }
            DeviceNotice::Single(_) => panic!("two held transitions must aggregate"),
        }
    }

    /// A proxy that rotates worker **names** — every rotation is a
    /// never-seen name appearing and a known one disappearing — is the
    /// case the per-device debounce cannot silence on its own: both
    /// halves are genuine transitions of devices the pool has never
    /// reported on.
    ///
    /// What bounds it is the coalescing window, and this test measures
    /// that bound rather than asserting it. One rotation a minute for an
    /// hour is 120 real transitions; the subscriber must see at most one
    /// message per window, not 120.
    #[tokio::test]
    async fn a_name_rotating_proxy_is_bounded_by_the_coalescing_window() {
        let h = harness();
        let mut messages = 0usize;
        let mut transitions = 0usize;

        // 60 rotations, one per minute, swept every 15 s as production does.
        for minute in 0..60 {
            let joining = format!("rig{minute}");
            h.lookup.set(&joining, 1);
            h.gate.observe(&event(&joining, true, false, h.clock.now()));
            transitions += 1;
            if minute > 0 {
                let leaving = format!("rig{}", minute - 1);
                h.lookup.set(&leaving, 0);
                h.gate
                    .observe(&event(&leaving, false, false, h.clock.now()));
                transitions += 1;
            }
            for _ in 0..4 {
                h.advance(15);
                messages += h.gate.poll_due().await.len();
            }
        }

        assert_eq!(transitions, 119, "the simulation really does churn");
        // Measured: 12 — one per 300 s window over the hour. Pinned
        // exactly so a regression that reopens the per-event path shows
        // up as a number, not as a vaguer "still under the bound".
        assert_eq!(
            messages, 12,
            "119 transitions must collapse to one message per coalescing window"
        );
    }

    /// A settled offline entry is dropped so a pool with a large
    /// long-tail of one-off miners cannot grow the map without bound.
    #[tokio::test]
    async fn settled_offline_entries_are_evicted() {
        let h = harness();
        h.bring_online("axe01").await;
        h.lookup.set("axe01", 0);
        h.gate.observe(&event("axe01", false, false, h.clock.now()));
        h.advance(301);
        assert_eq!(h.gate.poll_due().await.len(), 1);
        assert_eq!(h.gate.lock().devices.len(), 1);

        // Nudge another device so a resolution runs and eviction with it.
        h.advance(3601);
        h.lookup.set("other", 1);
        h.gate.observe(&event("other", true, false, h.clock.now()));
        h.advance(100);
        let _ = h.gate.poll_due().await;
        assert!(
            !h.gate
                .lock()
                .devices
                .contains_key(&(ADDR.to_string(), "axe01".to_string())),
            "the settled entry is gone"
        );
    }
}
