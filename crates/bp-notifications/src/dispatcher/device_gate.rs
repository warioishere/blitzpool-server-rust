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
//! schedules a re-evaluation. At the due instant the gate asks the
//! database what is actually connected and emits only when that answer
//! differs from `notified`.
//!
//! The asymmetry an event-pair debounce would have — "device came back
//! inside the grace, so now it reports online without ever having
//! reported offline" — cannot occur here, because the comparison is
//! against what was sent, not against the previous event.
//!
//! ## Level-triggered, not edge-triggered
//!
//! A resolution does **not** end a device's supervision: it re-arms a
//! slow re-check. That is deliberate, and it is what keeps a single
//! wrong answer from becoming permanently wrong — an edge-only design
//! can only be corrected by another Stratum event, and a miner that is
//! stably connected (or stably dead) will never send one.
//!
//! It also removes the need to persist anything. The watch list is
//! rebuilt at startup from the database via
//! [`seed`](DeviceStatusGate::seed) — every pair that is connected or was
//! disconnected recently — so a deadline pending across a restart is
//! re-derived rather than restored. A miner that died just before a
//! deploy is still reported, only later.
//!
//! ## Why the database and not an in-memory refcount
//!
//! `client_entity` rows with `deletedAt IS NULL` are already the
//! authoritative live-session view: cleared on register, stamped on
//! disconnect, swept by the 60 s dead-client cron for unclean drops. A
//! refcount kept in this process would have to be rebuilt after every
//! restart — and could not be rebuilt correctly, since the gate never
//! sees the connect events that happened before it started.
//!
//! Known limit of that source, stated because it is a real trade: the
//! dead-client cron soft-deletes any session with no accepted share for
//! five minutes, so a connected-but-share-quiet miner can read as
//! offline. The periodic re-check makes that self-correcting (its next
//! share revives the row and the gate reports it back online) rather
//! than permanent, but it can still cost one spurious offline/online
//! pair. Distinguishing a reaped row from a real disconnect needs a
//! schema change and belongs in its own step.
//!
//! ## Telling a new device from an old one
//!
//! A device the gate has never reported on is only worth an "online"
//! message when it is genuinely new — otherwise restarting this process
//! would announce every miner on the pool. The discriminator is the
//! earliest `startTime` across all of the pair's rows, soft-deleted ones
//! included: older than this gate's start means the pool already knew
//! the device. A reconnect always writes a *new* row (fresh `sessionId`)
//! and leaves the old one intact, so a reconnect storm after a pool
//! restart stays silent while a genuinely fresh miner is announced.

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
pub type DeviceKey = (String, String);

/// A device that has settled at offline and seen no Stratum event for
/// this long stops being supervised. Bounds the map on a pool whose
/// worker names churn; anything still connected keeps being re-checked
/// regardless of age.
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
    /// How often a device is re-checked once it has settled. This is
    /// what makes a wrong answer temporary instead of permanent.
    pub recheck_interval: Duration,
}

impl Default for DeviceGateConfig {
    fn default() -> Self {
        Self {
            offline_grace: Duration::from_secs(300),
            online_dwell: Duration::from_secs(90),
            coalesce_window: Duration::from_secs(300),
            recheck_interval: Duration::from_secs(300),
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

/// Which kind of event set the pending deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Online,
    Offline,
}

/// What the database says about one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceLiveness {
    /// At least one session is connected.
    pub live: bool,
    /// Earliest `startTime` across every row for the pair, soft-deleted
    /// rows included — when the pool first saw this worker.
    pub first_start_ms: i64,
}

/// Liveness lookup, abstracted so the gate is unit-testable without a
/// database.
///
/// `None` means **the lookup could not be performed** (e.g. the database
/// is unreachable). It is not "no live sessions": the caller must draw
/// no conclusion and retry, otherwise a database blip would fire an
/// offline notification for every miner on the pool.
#[async_trait]
pub trait DeviceLivenessLookup: Send + Sync {
    async fn liveness(&self, keys: &[DeviceKey]) -> Option<HashMap<DeviceKey, DeviceLiveness>>;
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
    /// When this device is next evaluated. Always set while supervised —
    /// a resolution re-arms it rather than clearing it.
    due_at: DateTime<Utc>,
    /// Which event moved the deadline since the last resolution. `None`
    /// means the deadline is the periodic re-check, so the next event
    /// may claim it.
    armed_by: Option<Direction>,
    /// Set while this device's key is out at the liveness lookup.
    in_flight: bool,
    /// An event landed while the lookup was in flight, so the answer
    /// coming back describes a state that has already moved on.
    dirty: bool,
    /// Most recent raw event — supplies worker name, user agent and the
    /// timestamp the message renders.
    meta: DeviceStatusEvent,
    /// Last Stratum event for this device. Drives eviction only; a
    /// re-check deliberately does not refresh it.
    last_event_at: DateTime<Utc>,
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
///
/// [`observe`](Self::observe) is safe from any number of tasks.
/// [`poll_due`](Self::poll_due) expects a **single** driver: it marks the
/// keys it hands to the lookup and clears them on resolution, so two
/// concurrent calls would evaluate the same device twice and could emit
/// the same transition twice. The binary runs exactly one sweeper.
///
/// Two things it deliberately does not do. A device whose address later
/// loses its last subscriber keeps being re-checked until it settles
/// offline — the resulting message is then dropped at fan-out, so this
/// costs a map entry and a row in a batched query, not a wrong
/// notification. And a key that never matches a `client_entity` row
/// would read as permanently offline; both protocols substitute a
/// literal (`worker` on SV1, `default` on SV2) when the miner sends no
/// worker suffix, and the same string is what the session row is written
/// with, so the two cannot drift apart.
pub struct DeviceStatusGate<C, L> {
    cfg: DeviceGateConfig,
    clock: C,
    lookup: L,
    /// Anything the pool saw before this instant predates our
    /// supervision and must not be announced as new.
    started_at_ms: i64,
    inner: Mutex<Inner>,
}

impl<C: Clock, L: DeviceLivenessLookup> DeviceStatusGate<C, L> {
    pub fn new(cfg: DeviceGateConfig, clock: C, lookup: L) -> Self {
        let started_at_ms = clock.now().timestamp_millis();
        Self {
            cfg,
            clock,
            lookup,
            started_at_ms,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Populate the watch list from the database at startup. Each entry
    /// is `(address, worker, user_agent)` for a device whose state could
    /// still be in flight — connected now, or disconnected recently
    /// enough that a pending deadline may have been lost with the
    /// previous process.
    ///
    /// Seeded devices start as `Unknown` and are evaluated on the first
    /// sweep: a live one settles silently (the pool knew it before we
    /// started), a dead one produces the offline message the restart
    /// would otherwise have swallowed.
    pub fn seed(&self, entries: impl IntoIterator<Item = (AddressId, String, Option<String>)>) {
        let now = self.clock.now();
        let mut inner = self.lock();
        for (address, worker, user_agent) in entries {
            let key = (address.as_str().to_string(), worker.clone());
            inner.devices.entry(key).or_insert_with(|| DeviceState {
                notified: Notified::Unknown,
                due_at: now,
                armed_by: None,
                in_flight: false,
                dirty: false,
                meta: DeviceStatusEvent {
                    address,
                    worker_name: (!worker.is_empty()).then_some(worker),
                    user_agent,
                    is_online: false,
                    is_returning: false,
                    timestamp: now,
                },
                last_event_at: now,
            });
        }
    }

    /// Record a raw device event. Never sends anything — it refreshes the
    /// render metadata and schedules when the device is next judged.
    pub fn observe(&self, event: &DeviceStatusEvent) {
        let now = self.clock.now();
        let key = key_of(event);
        let dir = if event.is_online {
            Direction::Online
        } else {
            Direction::Offline
        };
        let online_deadline = now + self.dwell(Direction::Online);
        let offline_deadline = now + self.dwell(Direction::Offline);

        let mut inner = self.lock();
        let state = inner.devices.entry(key).or_insert_with(|| DeviceState {
            notified: Notified::Unknown,
            due_at: now,
            armed_by: None,
            in_flight: false,
            dirty: false,
            meta: event.clone(),
            last_event_at: now,
        });
        // An answer is already on its way for this device and no longer
        // describes reality. Mark it so the resolution discards it.
        if state.in_flight {
            state.dirty = true;
        }
        state.meta = event.clone();
        state.last_event_at = now;

        match state.armed_by {
            // The pending deadline is only the periodic re-check, so this
            // event may set its own.
            None => {
                state.due_at = match dir {
                    Direction::Online => online_deadline,
                    Direction::Offline => offline_deadline,
                };
                state.armed_by = Some(dir);
            }
            // A disconnect always gets the full grace, even when an
            // earlier reconnect had armed the shorter online dwell.
            // One-way, so a device flapping faster than the grace still
            // cannot postpone its own judgement indefinitely.
            Some(Direction::Online) if dir == Direction::Offline => {
                state.due_at = state.due_at.max(offline_deadline);
                state.armed_by = Some(Direction::Offline);
            }
            _ => {}
        }
    }

    /// Evaluate every device whose deadline has passed and release
    /// whatever the coalescing window allows. Call on a fixed interval.
    pub async fn poll_due(&self) -> Vec<DeviceNotice> {
        let now = self.clock.now();
        let due = self.collect_due(now);

        if !due.is_empty() {
            // No lock held across the await.
            match self.lookup.liveness(&due).await {
                Some(answer) => self.resolve(&due, &answer, now),
                // Blind: keep every deadline and retry next tick. The
                // release below still runs — a message that was already
                // confirmed does not need the database again.
                None => self.abandon(&due),
            }
        }

        self.release(now)
    }

    /// Keys whose deadline has passed, marked as out for lookup.
    fn collect_due(&self, now: DateTime<Utc>) -> Vec<DeviceKey> {
        let mut inner = self.lock();
        let mut due = Vec::new();
        for (key, state) in inner.devices.iter_mut() {
            if state.due_at <= now {
                state.in_flight = true;
                due.push(key.clone());
            }
        }
        due
    }

    /// Lookup failed — drop the in-flight marks without drawing any
    /// conclusion. Deadlines stay as they were, so the next tick retries.
    ///
    /// `dirty` is cleared too: it exists to stop a *stale answer* from
    /// being applied, and no answer arrived. Leaving it set would make
    /// the next attempt discard a perfectly fresh answer and wait another
    /// full dwell for nothing.
    fn abandon(&self, due: &[DeviceKey]) {
        let mut inner = self.lock();
        for key in due {
            if let Some(state) = inner.devices.get_mut(key) {
                state.in_flight = false;
                state.dirty = false;
            }
        }
    }

    /// Apply the liveness answer to every due device, pushing confirmed
    /// transitions into their address buffers, then re-arm or retire.
    fn resolve(
        &self,
        due: &[DeviceKey],
        answer: &HashMap<DeviceKey, DeviceLiveness>,
        now: DateTime<Utc>,
    ) {
        let evict_after = chrono_duration(EVICT_AFTER);
        let online_deadline = now + self.dwell(Direction::Online);
        let offline_deadline = now + self.dwell(Direction::Offline);
        let next_check = now + chrono_duration(self.cfg.recheck_interval);

        let mut inner = self.lock();
        let mut retire = Vec::new();
        let mut confirmed: Vec<DeviceStatusEvent> = Vec::new();

        for key in due {
            let Some(state) = inner.devices.get_mut(key) else {
                continue;
            };
            state.in_flight = false;

            // An event landed while this answer was in flight. It could
            // not arm a deadline (one was pending), so arm it here and
            // discard the answer rather than act on a stale read.
            if state.dirty {
                state.dirty = false;
                if state.meta.is_online {
                    state.due_at = online_deadline;
                    state.armed_by = Some(Direction::Online);
                } else {
                    state.due_at = offline_deadline;
                    state.armed_by = Some(Direction::Offline);
                }
                continue;
            }

            let seen = answer.get(key).copied();
            let live = seen.is_some_and(|l| l.live);
            let target = if live {
                Notified::Online
            } else {
                Notified::Offline
            };
            state.armed_by = None;

            let previous = state.notified;
            if target != state.notified {
                // A device we have never reported on is only announced as
                // online when the pool first saw it after this gate
                // started. Everything older predates our supervision —
                // announcing it would turn a restart into a broadcast.
                let announce = state.notified != Notified::Unknown
                    || target == Notified::Offline
                    || seen.is_some_and(|l| l.first_start_ms >= self.started_at_ms);
                state.notified = target;
                if announce {
                    let mut event = state.meta.clone();
                    event.is_online = live;
                    // A device we already told the subscriber was gone is
                    // "back online", not a first sighting. The raw event's
                    // flag cannot say this: a re-check-driven correction
                    // has no online event behind it at all, and the last
                    // one it does have is the disconnect.
                    if live {
                        event.is_returning = previous == Notified::Offline;
                    }
                    // Keep the event's own timestamp when it agreed with
                    // the database — "offline since <disconnect>" is more
                    // useful than "offline since <we checked>".
                    if state.meta.is_online != live {
                        event.timestamp = now;
                    }
                    confirmed.push(event);
                }
            }

            // Settled at offline with nothing happening: stop watching.
            // Anything else stays supervised so a wrong answer stays
            // temporary rather than becoming permanent.
            if target == Notified::Offline && now - state.last_event_at >= evict_after {
                retire.push(key.clone());
            } else {
                state.due_at = next_check;
            }
        }

        for event in confirmed {
            let address = event.address.as_str().to_string();
            inner
                .addresses
                .entry(address)
                .or_default()
                .buffered
                .push(event);
        }
        for key in retire {
            inner.devices.remove(&key);
        }
        // Address slots with nothing pending and no recent emission are
        // pure overhead.
        inner.addresses.retain(|_, s| {
            !s.buffered.is_empty() || s.last_emit.is_some_and(|l| now - l < evict_after)
        });
    }

    /// Release one message per address whose coalescing window is open.
    fn release(&self, now: DateTime<Utc>) -> Vec<DeviceNotice> {
        let window = chrono_duration(self.cfg.coalesce_window);
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

    fn dwell(&self, dir: Direction) -> chrono::Duration {
        chrono_duration(match dir {
            Direction::Online => self.cfg.online_dwell,
            Direction::Offline => self.cfg.offline_grace,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn chrono_duration(d: Duration) -> chrono::Duration {
    chrono::Duration::from_std(d).unwrap_or_else(|_| chrono::Duration::zero())
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

    /// Liveness answers the test drives directly, standing in for
    /// `client_entity`. `fail` simulates an unreachable database.
    #[derive(Default)]
    struct FakeDb {
        rows: Mutex<HashMap<DeviceKey, DeviceLiveness>>,
        fail: Mutex<bool>,
        /// Runs inside `liveness`, so a test can make an event land while
        /// the lookup is in flight.
        on_lookup: Mutex<Option<Box<dyn Fn() + Send>>>,
    }

    impl FakeDb {
        fn key(worker: &str) -> DeviceKey {
            (ADDR.to_string(), worker.to_string())
        }
        /// `first_start_offset_s` is relative to `t0`; negative means the
        /// pool saw the worker before the gate started.
        fn set(&self, worker: &str, live: bool, first_start_offset_s: i64) {
            self.rows.lock().expect("lock").insert(
                Self::key(worker),
                DeviceLiveness {
                    live,
                    first_start_ms: (t0() + chrono::Duration::seconds(first_start_offset_s))
                        .timestamp_millis(),
                },
            );
        }
        fn set_live(&self, worker: &str, live: bool) {
            let mut rows = self.rows.lock().expect("lock");
            if let Some(entry) = rows.get_mut(&Self::key(worker)) {
                entry.live = live;
            }
        }
        fn forget(&self, worker: &str) {
            self.rows.lock().expect("lock").remove(&Self::key(worker));
        }
        fn fail(&self, on: bool) {
            *self.fail.lock().expect("lock") = on;
        }
    }

    #[async_trait]
    impl DeviceLivenessLookup for Arc<FakeDb> {
        async fn liveness(&self, keys: &[DeviceKey]) -> Option<HashMap<DeviceKey, DeviceLiveness>> {
            // Snapshot FIRST, then let the hook mutate the world. That
            // ordering is the whole point: the answer handed back has to
            // be genuinely stale, the way a real round-trip's would be.
            // Running the hook before the read would quietly hand back a
            // fresh answer and the staleness guard would never be tested.
            let answer = if *self.fail.lock().expect("lock") {
                None
            } else {
                let rows = self.rows.lock().expect("lock");
                Some(
                    keys.iter()
                        .filter_map(|k| rows.get(k).map(|l| (k.clone(), *l)))
                        .collect(),
                )
            };
            // Runs on the failure path too — an event can land during a
            // lookup that then fails.
            let hook = self.on_lookup.lock().expect("lock").take();
            if let Some(hook) = hook {
                hook();
            }
            answer
        }
    }

    fn address() -> AddressId {
        AddressId::new(ADDR.to_string()).expect("valid address")
    }

    fn event(worker: &str, online: bool, at: DateTime<Utc>) -> DeviceStatusEvent {
        DeviceStatusEvent {
            address: address(),
            worker_name: Some(worker.to_string()),
            user_agent: Some("cpuminer/2.5".to_string()),
            is_online: online,
            // Production hard-codes this to false on every offline event
            // and to true on every online one, so it cannot carry
            // meaning. The gate must not depend on it; the tests pin it
            // to one value to keep that honest.
            is_returning: false,
            timestamp: at,
        }
    }

    struct Harness {
        gate: Arc<DeviceStatusGate<TestClock, Arc<FakeDb>>>,
        clock: TestClock,
        db: Arc<FakeDb>,
    }

    fn harness() -> Harness {
        let clock = TestClock::new(t0());
        let db = Arc::new(FakeDb::default());
        Harness {
            gate: Arc::new(DeviceStatusGate::new(
                DeviceGateConfig::default(),
                clock.clone(),
                Arc::clone(&db),
            )),
            clock,
            db,
        }
    }

    impl Harness {
        fn advance(&self, secs: i64) {
            let now = self.clock.now();
            self.clock.set(now + chrono::Duration::seconds(secs));
        }
        /// Bring a worker to a reported-online state the way a brand-new
        /// device does: first seen after the gate started.
        async fn bring_online(&self, worker: &str) {
            self.db.set(worker, true, 10);
            self.advance(10);
            self.gate.observe(&event(worker, true, self.clock.now()));
            self.advance(100);
            let out = self.gate.poll_due().await;
            assert_eq!(out.len(), 1, "a first-seen device announces itself");
        }
        /// Re-open the coalescing window so setup does not interfere with
        /// what a test measures.
        fn open_window(&self) {
            self.advance(301);
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

    // ── The debounce ────────────────────────────────────────────────

    /// The complaint this module exists for: a miner on bad WiFi drops
    /// and returns inside the grace period. Nothing may be sent —
    /// neither the offline it never earned nor the online that would
    /// otherwise follow it.
    #[tokio::test]
    async fn a_reconnect_inside_the_grace_sends_nothing() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        h.db.set_live("axe01", false);
        h.gate.observe(&event("axe01", false, h.clock.now()));
        h.advance(40);
        assert!(h.gate.poll_due().await.is_empty(), "grace has not elapsed");

        h.db.set_live("axe01", true);
        h.gate.observe(&event("axe01", true, h.clock.now()));
        h.advance(300);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "reported state never changed, so nothing may go out"
        );
    }

    /// A device that stays gone must still be reported — exactly once,
    /// even though the re-check keeps asking.
    #[tokio::test]
    async fn a_device_that_stays_gone_reports_offline_once() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        h.db.set_live("axe01", false);
        h.gate.observe(&event("axe01", false, h.clock.now()));
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)]
        );

        for _ in 0..5 {
            h.advance(301);
            assert!(h.gate.poll_due().await.is_empty(), "no repeat message");
        }
    }

    /// The rental-source case: many rigs authorize under one worker name
    /// and rotate individually. A single rig leaving is not the device
    /// going offline, and the database is what settles that.
    #[tokio::test]
    async fn one_of_many_sessions_leaving_is_not_an_outage() {
        let h = harness();
        // The pool knew this source before the gate started.
        h.db.set("mrr", true, -3600);
        h.gate.observe(&event("mrr", true, h.clock.now()));
        h.advance(100);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "a source the pool already knew is not announced"
        );

        // One rig rotates out; others remain, so the DB still says live.
        h.gate.observe(&event("mrr", false, h.clock.now()));
        h.advance(301);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "the source still has live sessions"
        );

        // The contract ends: nothing left.
        h.db.set_live("mrr", false);
        h.gate.observe(&event("mrr", false, h.clock.now()));
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
        h.open_window();
        h.db.set_live("axe01", false);

        let start = h.clock.now();
        for _ in 0..10 {
            h.gate.observe(&event("axe01", false, h.clock.now()));
            h.advance(15);
            h.gate.observe(&event("axe01", true, h.clock.now()));
            h.advance(15);
        }
        assert!(
            h.clock.now() - start >= chrono::Duration::seconds(300),
            "test drove past the grace period"
        );
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)]
        );
    }

    /// A disconnect must always get the full `offline_grace`, even when a
    /// reconnect had already armed the shorter `online_dwell`. Without
    /// the one-way upgrade the grace is silently bypassed and the push
    /// storm returns at one message per dwell.
    #[tokio::test]
    async fn a_disconnect_upgrades_a_pending_online_dwell_to_the_full_grace() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        // A reconnect arms the 90 s dwell...
        h.gate.observe(&event("axe01", true, h.clock.now()));
        h.advance(10);
        // ...and the miner drops again 10 s later.
        h.db.set_live("axe01", false);
        h.gate.observe(&event("axe01", false, h.clock.now()));

        h.advance(100);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "the 90 s dwell must not decide a disconnect"
        );
        h.advance(210);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)],
            "the full grace decides it"
        );
    }

    /// An "online" message may only ever follow an "offline" message.
    #[tokio::test]
    async fn online_never_precedes_offline_for_a_known_device() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        for cycle in 0..5 {
            h.db.set_live("axe01", false);
            h.gate.observe(&event("axe01", false, h.clock.now()));
            h.advance(30);
            h.db.set_live("axe01", true);
            h.gate.observe(&event("axe01", true, h.clock.now()));
            h.advance(300);
            assert!(
                h.gate.poll_due().await.is_empty(),
                "cycle {cycle} produced a message for an unchanged reported state"
            );
        }
    }

    // ── New vs. already-known ───────────────────────────────────────

    /// The discriminator is when the POOL first saw the worker, not what
    /// kind of event happened to arm the deadline.
    #[tokio::test]
    async fn newness_comes_from_first_start_not_from_the_event() {
        let h = harness();
        h.db.set("fresh", true, 30);
        h.db.set("known", true, -86_400);
        h.advance(30);

        h.gate.observe(&event("fresh", true, h.clock.now()));
        h.gate.observe(&event("known", true, h.clock.now()));
        h.advance(100);

        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("fresh".into(), true)],
            "only the genuinely new worker is announced"
        );
    }

    /// The restart case the newness rule exists for: a fresh gate, every
    /// miner reconnecting at once. All of them predate the gate, so none
    /// may be announced — regardless of whether the first event the gate
    /// sees is the disconnect or the reconnect. The previous
    /// `is_returning` guard only covered the reconnect-first half.
    #[tokio::test]
    async fn a_reconnect_storm_after_a_restart_announces_nobody() {
        let h = harness();
        for i in 0..20 {
            let w = format!("rig{i}");
            h.db.set(&w, true, -7200);
            if i % 2 == 0 {
                h.gate.observe(&event(&w, false, h.clock.now()));
            }
            h.gate.observe(&event(&w, true, h.clock.now()));
        }
        h.advance(400);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "a restart must not broadcast the whole pool"
        );
    }

    /// After a restart the gate knows nothing. A device that then
    /// disconnects for good is still genuinely offline, and the database
    /// says so — that message is correct and must survive.
    #[tokio::test]
    async fn an_unknown_device_going_offline_is_still_reported() {
        let h = harness();
        h.db.set("axe01", false, -7200);
        h.gate.observe(&event("axe01", false, h.clock.now()));
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)]
        );
    }

    // ── Seeding + self-healing ──────────────────────────────────────

    /// A miner that dies just before a deploy will never emit another
    /// Stratum event. Seeding the watch list from the database is the
    /// only thing that still gets its owner the offline message.
    #[tokio::test]
    async fn a_seeded_dead_device_is_reported_without_any_event() {
        let h = harness();
        h.db.set("axe01", false, -7200);
        h.gate
            .seed([(address(), "axe01".to_string(), Some("BitAxe".into()))]);

        h.advance(20);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)],
            "the restart no longer swallows it"
        );
    }

    /// The same seed must stay quiet for everything still running —
    /// otherwise every restart is a broadcast.
    #[tokio::test]
    async fn a_seeded_live_device_settles_silently_and_stays_supervised() {
        let h = harness();
        h.db.set("axe01", true, -7200);
        h.gate
            .seed([(address(), "axe01".to_string(), Some("BitAxe".into()))]);

        h.advance(20);
        assert!(h.gate.poll_due().await.is_empty());

        // Supervised: a later disconnect is reported with no event at all.
        h.db.set_live("axe01", false);
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)]
        );
    }

    /// The dead-client cron soft-deletes a connected miner that has not
    /// submitted a share for five minutes, so the gate can report it
    /// offline wrongly. The periodic re-check is what makes that
    /// temporary rather than permanent — nothing else would correct it,
    /// because a still-connected miner sends no event.
    #[tokio::test]
    async fn a_wrong_offline_is_corrected_by_the_recheck() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        // Reaped while still connected.
        h.db.set_live("axe01", false);
        h.gate.observe(&event("axe01", false, h.clock.now()));
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)],
            "the wrong offline does go out"
        );

        // Its next accepted share revives the row. No Stratum event.
        h.db.set_live("axe01", true);
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), true)],
            "the re-check corrects it with no event to trigger on"
        );
    }

    /// An event landing while the liveness answer is in flight describes
    /// a state the answer does not know about. Acting on it would leave
    /// the device reported wrongly with nothing scheduled to fix it.
    #[tokio::test]
    async fn an_event_during_the_lookup_discards_the_stale_answer() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        h.db.set_live("axe01", false);
        h.gate.observe(&event("axe01", false, h.clock.now()));
        h.advance(301);

        // The miner reconnects while the query is in flight.
        let gate = Arc::clone(&h.gate);
        let db = Arc::clone(&h.db);
        let at = h.clock.now();
        *h.db.on_lookup.lock().expect("lock") = Some(Box::new(move || {
            db.set_live("axe01", true);
            gate.observe(&event("axe01", true, at));
        }));

        assert!(
            h.gate.poll_due().await.is_empty(),
            "the stale 'gone' answer must not be acted on"
        );

        // The reconnect armed its own deadline; the device settles back
        // to online without ever having been reported offline.
        h.advance(400);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "reported state never changed"
        );
    }

    /// A device the subscriber was already told about is "back online",
    /// not a fresh sighting. The raw event cannot carry that: a
    /// re-check-driven correction has no online event behind it at all.
    #[tokio::test]
    async fn a_return_after_a_reported_offline_renders_as_back_online() {
        let h = harness();
        // The first announcement is a first sighting, not a return.
        h.db.set("axe01", true, 10);
        h.advance(10);
        h.gate.observe(&event("axe01", true, h.clock.now()));
        h.advance(100);
        match &h.gate.poll_due().await[0] {
            DeviceNotice::Single(e) => {
                assert!(e.is_online);
                assert!(!e.is_returning, "a first sighting is not a return");
            }
            DeviceNotice::Aggregate(_) => panic!("expected a single notice"),
        }
        h.open_window();

        h.db.set_live("axe01", false);
        h.gate.observe(&event("axe01", false, h.clock.now()));
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)]
        );
        h.open_window();

        // Comes back with no Stratum event — only the re-check sees it.
        h.db.set_live("axe01", true);
        h.advance(301);
        match &h.gate.poll_due().await[0] {
            DeviceNotice::Single(e) => {
                assert!(e.is_online);
                assert!(
                    e.is_returning,
                    "we told them it went offline, so this is a return"
                );
            }
            DeviceNotice::Aggregate(_) => panic!("expected a single notice"),
        }
    }

    // ── Failure handling, coalescing, memory ────────────────────────

    /// A database blip must not be read as "everyone is offline".
    #[tokio::test]
    async fn a_failed_lookup_holds_the_deadline_instead_of_guessing() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        h.db.set_live("axe01", false);
        h.gate.observe(&event("axe01", false, h.clock.now()));
        h.advance(301);

        h.db.fail(true);
        assert!(h.gate.poll_due().await.is_empty(), "no guess while blind");

        h.db.fail(false);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)],
            "the deadline stayed armed and resolves once the lookup works"
        );
    }

    /// An event landing during a lookup that then FAILS must not cost an
    /// extra dwell. The staleness mark exists to reject a stale answer,
    /// and a failed lookup produced none — leaving it set would make the
    /// next, perfectly fresh answer be thrown away too.
    #[tokio::test]
    async fn an_event_during_a_failed_lookup_does_not_delay_the_next_answer() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        h.db.set_live("axe01", false);
        h.gate.observe(&event("axe01", false, h.clock.now()));
        h.advance(301);

        // The lookup fails, and a further disconnect lands while it is out.
        let gate = Arc::clone(&h.gate);
        let at = h.clock.now();
        *h.db.on_lookup.lock().expect("lock") = Some(Box::new(move || {
            gate.observe(&event("axe01", false, at));
        }));
        h.db.fail(true);
        assert!(h.gate.poll_due().await.is_empty(), "no guess while blind");

        // The very next successful sweep must decide it.
        h.db.fail(false);
        h.advance(1);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)],
            "a failed lookup must not cost another full grace"
        );
    }

    /// A confirmed message waiting for the coalescing window must not be
    /// hostage to the database — it needs no further lookup to go out.
    #[tokio::test]
    async fn a_buffered_message_is_released_during_a_database_outage() {
        let h = harness();
        h.bring_online("a").await; // opens the window

        // `b` resolves inside the window and is held.
        h.db.set("b", true, 5);
        h.gate.observe(&event("b", true, h.clock.now()));
        h.advance(95);
        assert!(h.gate.poll_due().await.is_empty(), "held by the window");

        // The database goes away, and something else is due every tick.
        h.db.set("c", false, -7200);
        h.gate.observe(&event("c", false, h.clock.now()));
        h.db.fail(true);
        h.advance(210);

        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("b".into(), true)],
            "the already-confirmed message goes out regardless"
        );
    }

    /// Several workers of one address settling together must cost one
    /// message, not one per worker.
    #[tokio::test]
    async fn simultaneous_transitions_collapse_into_one_message() {
        let h = harness();
        for w in ["a", "b", "c"] {
            h.bring_online(w).await;
            h.open_window();
        }
        for w in ["a", "b", "c"] {
            h.db.set_live(w, false);
            h.gate.observe(&event(w, false, h.clock.now()));
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

    /// The coalescing window is a hard ceiling: a transition that
    /// resolves while the window is open is held, and goes out when it
    /// reopens. Both halves are asserted — checking only the release
    /// would pass with the ceiling removed entirely.
    #[tokio::test]
    async fn a_transition_inside_the_window_is_held_then_released() {
        let h = harness();
        h.bring_online("a").await;

        h.db.set("b", true, 5);
        h.gate.observe(&event("b", true, h.clock.now()));
        h.advance(95);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "resolved, but the address already sent inside the window"
        );

        h.advance(210);
        assert_eq!(singles(&h.gate.poll_due().await), vec![("b".into(), true)]);
    }

    /// Two transitions held together must leave as one message.
    #[tokio::test]
    async fn transitions_held_across_the_window_leave_together() {
        let h = harness();
        h.bring_online("a").await;

        for w in ["b", "c"] {
            h.db.set(w, true, 5);
            h.gate.observe(&event(w, true, h.clock.now()));
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

    /// A device settled at offline with no further events stops being
    /// supervised, so a pool whose worker names churn cannot grow the map
    /// without bound.
    #[tokio::test]
    async fn settled_offline_devices_stop_being_supervised() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        h.db.set_live("axe01", false);
        h.gate.observe(&event("axe01", false, h.clock.now()));
        h.advance(301);
        assert_eq!(h.gate.poll_due().await.len(), 1);
        assert_eq!(h.gate.lock().devices.len(), 1, "still watched for now");

        h.advance(3601);
        let _ = h.gate.poll_due().await;
        assert!(
            h.gate.lock().devices.is_empty(),
            "the settled entry is gone"
        );
    }

    /// A worker whose rows have aged out of `client_entity` entirely
    /// resolves to offline and then retires.
    #[tokio::test]
    async fn a_worker_whose_rows_vanish_is_retired() {
        let h = harness();
        h.bring_online("rig0").await;
        h.open_window();

        h.db.forget("rig0");
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("rig0".into(), false)]
        );
        h.advance(3601);
        let _ = h.gate.poll_due().await;
        assert!(h.gate.lock().devices.is_empty());
    }

    /// A live device is supervised indefinitely, so its eventual
    /// disconnect is always caught — eviction must never reach it.
    #[tokio::test]
    async fn a_live_device_is_never_retired() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        for _ in 0..30 {
            h.advance(301);
            assert!(h.gate.poll_due().await.is_empty());
        }
        assert_eq!(h.gate.lock().devices.len(), 1, "still supervised");

        h.db.set_live("axe01", false);
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)]
        );
    }

    /// A proxy that rotates worker names produces genuine transitions on
    /// both sides, so the debounce cannot silence it; the coalescing
    /// window is what bounds it. Measured rather than asserted.
    #[tokio::test]
    async fn a_name_rotating_proxy_is_bounded_by_the_coalescing_window() {
        let h = harness();
        let mut messages = 0usize;
        let mut transitions = 0usize;

        for minute in 0..60 {
            let joining = format!("rig{minute}");
            h.db.set(&joining, true, 60 * minute + 1);
            h.gate.observe(&event(&joining, true, h.clock.now()));
            transitions += 1;
            if minute > 0 {
                let leaving = format!("rig{}", minute - 1);
                h.db.set_live(&leaving, false);
                h.gate.observe(&event(&leaving, false, h.clock.now()));
                transitions += 1;
            }
            for _ in 0..4 {
                h.advance(15);
                messages += h.gate.poll_due().await.len();
            }
        }

        assert_eq!(transitions, 119, "the simulation really does churn");
        // Measured: 11, against a ceiling of 3600/300 = 12. Pinned
        // exactly so a regression that reopens the per-event path shows
        // up as a number rather than as a vaguer "still under the bound".
        assert_eq!(
            messages, 11,
            "119 transitions must collapse to one message per coalescing window"
        );
    }
}
