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
//! ## The reported state is persisted; the schedule is not
//!
//! `notified` is the one piece of state that cannot be re-derived: it
//! records what a *human* was last told, which no table knows. It is
//! written through a [`ReportedStateStore`] on every change and loaded
//! back at startup, and it deliberately outlives the in-memory
//! supervision entry — a device retired after an hour of silence keeps
//! its reported state, so its eventual return is still a transition.
//!
//! Everything else (deadlines, the coalescing buffer) is rebuilt rather
//! than restored: the watch list is seeded from the database via
//! [`seed`](DeviceStatusGate::seed), and because the persisted
//! `notified` survives, a confirmed-but-unsent transition is simply
//! re-derived on the next sweep instead of being lost.
//!
//! ## Level-triggered, not edge-triggered
//!
//! A resolution does **not** end a device's supervision: it re-arms a
//! slow re-check. That is what keeps a single wrong answer from becoming
//! permanently wrong — an edge-only design can only be corrected by
//! another Stratum event, and a miner that is stably connected (or
//! stably dead) will never send one.
//!
//! ## Where liveness comes from
//!
//! From the process that holds the sockets. The Stratum front publishes
//! the set of `(address, worker)` pairs it currently has open, and the
//! lookup behind [`DeviceLivenessLookup`] answers from that union.
//!
//! This is deliberately NOT derived from `client_entity`. A row there is
//! soft-deleted both by a real disconnect and by the dead-client cron
//! retiring a session that merely has not submitted an accepted share
//! for five minutes — so a slow miner is indistinguishable from a dead
//! one, and a gate built on it reported outages that never happened.
//! Asking the front removes the inference instead of compensating for
//! it.
//!
//! ## Telling a new device from an old one
//!
//! A device the gate has never reported on is only worth an "online"
//! message when it is genuinely new — otherwise restarting this process
//! would announce every miner on the pool. The discriminator is the
//! earliest `COALESCE(firstSeen, startTime)` across all of the pair's
//! rows: older than this gate's start means the pool already knew the
//! device. `startTime` alone would not do — it is refreshed on every
//! re-register, so a long-connected device can look brand new.

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
/// this long stops being *supervised*. Its reported state is kept (see
/// [`ReportedStateStore`]) so a later return is still a transition; only
/// the polling entry is dropped.
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
pub enum Notified {
    /// Nothing has ever been sent for this device.
    Unknown,
    /// How many sessions the subscriber was last told about. Zero is
    /// "offline"; anything above is "online with this many rigs".
    ///
    /// A count rather than a flag because three rigs under one worker
    /// name are three rigs to their owner: losing one is news, and only
    /// the number tells that apart from losing all three.
    Sessions(usize),
}

impl Notified {
    fn count(self) -> Option<usize> {
        match self {
            Notified::Unknown => None,
            Notified::Sessions(n) => Some(n),
        }
    }
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
    /// How many sessions the fronts hold open for this device.
    pub sessions: usize,
    /// Earliest `COALESCE(firstSeen, startTime)` across every row for the
    /// pair — when the pool first saw this worker.
    pub first_seen_ms: i64,
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

/// Durable record of what each subscriber was last told.
///
/// This is the only gate state that cannot be reconstructed from the
/// pool's own tables — no schema records "we sent this person a push".
/// Without it a restart re-sends offline messages it already sent, and
/// silently swallows the matching "back online".
#[async_trait]
pub trait ReportedStateStore: Send + Sync {
    /// Everything remembered, at startup. A failure should return an
    /// empty map rather than block the gate; the cost is one restart's
    /// worth of imprecision, not an outage.
    async fn load(&self) -> HashMap<DeviceKey, usize>;
    /// Record what changed in this sweep. Best-effort.
    ///
    /// Takes the whole batch rather than one device at a time because the
    /// events that produce a large one — a front restarting, a rental
    /// ending — produce it all at once, and the messages cannot go out
    /// until this returns. One round-trip per device would put the
    /// persistence of state nobody reads ahead of the notification
    /// somebody is waiting for.
    async fn store(&self, updates: &[(DeviceKey, usize)]);
}

/// A no-op store — the gate degrades to its pre-persistence behaviour.
pub struct NoReportedStateStore;

#[async_trait]
impl ReportedStateStore for NoReportedStateStore {
    async fn load(&self) -> HashMap<DeviceKey, usize> {
        HashMap::new()
    }
    async fn store(&self, _updates: &[(DeviceKey, usize)]) {}
}

/// A confirmed, ready-to-send device-status message.
#[derive(Debug, Clone)]
pub enum DeviceNotice {
    /// One transition — rendered exactly as before this module existed.
    Single(DeviceStatusEvent),
    /// Some of a worker's rigs are gone and the rest keep hashing. NOT
    /// an outage: rendering it as one would tell the owner of three rigs
    /// that all three died, and would tell a rental source its rental
    /// ended every time the count dipped.
    Partial(DevicePartial),
    /// Several transitions for one address inside the coalescing window,
    /// collapsed into a single message.
    Aggregate(DeviceAggregate),
}

/// Some of a worker's sessions went away; the worker is still up.
#[derive(Debug, Clone)]
pub struct DevicePartial {
    pub address: AddressId,
    pub worker_name: Option<String>,
    pub user_agent: Option<String>,
    /// Sessions still hashing.
    pub remaining: usize,
    /// How many there were when the subscriber was last told.
    pub before: usize,
    pub timestamp: DateTime<Utc>,
}

/// Collapsed form of two or more transitions on one address.
///
/// The two online lists are kept apart because they say different things
/// to a subscriber: one device is coming back from an outage they were
/// told about, the other has never been seen before.
#[derive(Debug, Clone)]
pub struct DeviceAggregate {
    pub address: AddressId,
    /// Worker names that went offline.
    pub went_offline: Vec<String>,
    /// Worker names that returned after having been reported offline.
    pub came_back: Vec<String>,
    /// Worker names seen for the first time.
    pub first_seen: Vec<String>,
    /// `(worker, remaining, before)` for workers that lost some rigs but
    /// are still hashing.
    pub reduced: Vec<(String, usize, usize)>,
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
    /// Backfilled from the database with nothing ever reported for it, so
    /// the first resolution only records where it stands — it does not
    /// send. Cleared by that first resolution.
    ///
    /// Without this, taking a device under supervision is itself a
    /// message: seeding reaches an hour back, so the first boot after
    /// this feature ships, and every address that gains its first
    /// subscriber, would announce disconnects that happened before anyone
    /// was watching.
    settle_silently: bool,
    /// Most recent raw event — supplies worker name, user agent and the
    /// timestamp the message renders.
    meta: DeviceStatusEvent,
    /// Last Stratum event for this device. Drives eviction only; a
    /// re-check deliberately does not refresh it.
    last_event_at: DateTime<Utc>,
}

/// A transition that survived its dwell and is waiting for the
/// coalescing window to open.
#[derive(Debug, Clone)]
struct Confirmed {
    event: DeviceStatusEvent,
    returning: bool,
    /// `(remaining, before)` when only SOME of the worker's rigs left.
    partial: Option<(usize, usize)>,
}

/// Per-address coalescing state.
#[derive(Debug, Default)]
struct AddressState {
    /// Confirmed transitions waiting for the window to open.
    buffered: Vec<Confirmed>,
    /// When this address last had a message released.
    last_emit: Option<DateTime<Utc>>,
}

#[derive(Debug, Default)]
struct Inner {
    devices: HashMap<DeviceKey, DeviceState>,
    addresses: HashMap<String, AddressState>,
    /// What each device was last reported as, independent of whether it
    /// is still supervised. Mirrors the [`ReportedStateStore`].
    reported: HashMap<DeviceKey, Notified>,
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
/// One thing it deliberately does not do: a device whose address later
/// loses its last subscriber keeps being re-checked until it settles
/// offline — the resulting message is then dropped at fan-out, so this
/// costs a map entry and a row in a batched query, not a wrong
/// notification.
pub struct DeviceStatusGate<C, L, S> {
    cfg: DeviceGateConfig,
    clock: C,
    lookup: L,
    store: S,
    /// Anything the pool saw before this instant predates our
    /// supervision and must not be announced as new.
    started_at_ms: i64,
    inner: Mutex<Inner>,
}

impl<C: Clock, L: DeviceLivenessLookup, S: ReportedStateStore> DeviceStatusGate<C, L, S> {
    pub fn new(cfg: DeviceGateConfig, clock: C, lookup: L, store: S) -> Self {
        let started_at_ms = clock.now().timestamp_millis();
        Self {
            cfg,
            clock,
            lookup,
            store,
            started_at_ms,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Load what previous processes already told subscribers. Call once,
    /// before the first sweep.
    pub async fn restore_reported_state(&self) {
        let remembered = self.store.load().await;
        let mut inner = self.lock();
        for (key, sessions) in remembered {
            let state = Notified::Sessions(sessions);
            inner.reported.insert(key.clone(), state);
            if let Some(device) = inner.devices.get_mut(&key) {
                device.notified = state;
            }
        }
    }

    /// Populate the watch list from the database at startup. Each entry
    /// is `(address, worker, user_agent)` for a device whose state could
    /// still be in flight — connected now, or disconnected recently
    /// enough that a pending deadline may have been lost with the
    /// previous process.
    ///
    /// Seeded devices inherit whatever was already reported for them, so
    /// a restart neither re-sends an offline message nor swallows the
    /// return that was still sitting in a coalescing buffer.
    pub fn seed(&self, entries: impl IntoIterator<Item = (AddressId, String, Option<String>)>) {
        let now = self.clock.now();
        let mut inner = self.lock();
        for (address, worker, user_agent) in entries {
            let key = (address.as_str().to_string(), worker.clone());
            let notified = inner
                .reported
                .get(&key)
                .copied()
                .unwrap_or(Notified::Unknown);
            inner.devices.entry(key).or_insert_with(|| DeviceState {
                notified,
                due_at: now,
                armed_by: None,
                in_flight: false,
                dirty: false,
                // Only when nothing was ever reported for it. A device
                // that HAS a reported state is a device the subscriber
                // already heard about, so the deploy it just died during
                // still produces its offline message — that case rides on
                // the persisted state, not on this.
                settle_silently: notified == Notified::Unknown,
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
        let notified = inner
            .reported
            .get(&key)
            .copied()
            .unwrap_or(Notified::Unknown);
        let state = inner.devices.entry(key).or_insert_with(|| DeviceState {
            notified,
            due_at: now,
            armed_by: None,
            in_flight: false,
            dirty: false,
            // An event is something we witnessed while watching, not a
            // backfill of what happened before — it gets the normal rules.
            settle_silently: false,
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
                Some(answer) => {
                    let writes = self.resolve(&due, &answer, now);
                    if !writes.is_empty() {
                        self.store.store(&writes).await;
                    }
                }
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
    /// Returns the reported-state changes to persist.
    fn resolve(
        &self,
        due: &[DeviceKey],
        answer: &HashMap<DeviceKey, DeviceLiveness>,
        now: DateTime<Utc>,
    ) -> Vec<(DeviceKey, usize)> {
        let evict_after = chrono_duration(EVICT_AFTER);
        let online_deadline = now + self.dwell(Direction::Online);
        let offline_deadline = now + self.dwell(Direction::Offline);
        let next_check = now + chrono_duration(self.cfg.recheck_interval);

        let mut inner = self.lock();
        let mut retire = Vec::new();
        let mut confirmed: Vec<Confirmed> = Vec::new();
        let mut writes: Vec<(DeviceKey, usize)> = Vec::new();

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
            let sessions = seen.map_or(0, |l| l.sessions);
            let live = sessions > 0;

            let target = Notified::Sessions(sessions);
            // A rig joining is not urgent; a rig leaving is the thing the
            // grace exists for. Both still have to hold.
            let direction = match state.notified.count() {
                Some(before) if sessions > before => Direction::Online,
                None if sessions > 0 => Direction::Online,
                _ => Direction::Offline,
            };
            // One-shot, and consumed whatever the answer turns out to be:
            // a backfilled device settles into whichever state it is
            // actually in, silently, and is supervised normally from then
            // on.
            let settling = std::mem::replace(&mut state.settle_silently, false);

            let previous = state.notified;
            // A disagreement between what the front holds open and what
            // the subscriber was told has to SURVIVE a full dwell before
            // it counts. Arming that dwell cannot be left to the Stratum
            // event, because the most important disconnect does not
            // produce one: a miner that loses power or drops off the
            // network never sends anything, and only the periodic
            // re-check notices it is gone. Resolving that on the spot
            // reported an outage seconds after it began — measured at 8 s
            // against a 60 s grace — which is exactly the flap the grace
            // exists to swallow.
            //
            // It applies to every change in the count, not just to
            // reaching zero: a rental source whose rigs rotate dips and
            // recovers within the grace and so stays silent, while three
            // rigs that become two and STAY two is a real loss.
            //
            // A device that is merely settling is exempt: nothing is
            // announced for it, so there is nothing to debounce.
            if target != previous && !settling && state.armed_by != Some(direction) {
                state.armed_by = Some(direction);
                state.due_at = now + self.dwell(direction);
                continue;
            }
            state.armed_by = None;

            if target != previous {
                let before = previous.count();
                // A device we have never reported on is only announced as
                // online when the pool first saw it after this gate
                // started. Everything older predates our supervision —
                // announcing it would turn a restart into a broadcast.
                //
                // A count that GREW is never announced: nobody needs a
                // push because a rental gained a rig. It still updates
                // what we remember, so the next loss is measured against
                // the level that actually held.
                let grew = before.is_some_and(|b| sessions > b && b > 0);
                let announce = !settling
                    && !grew
                    // `is_some`, not `> 0`: a device we already reported
                    // as gone has been reported on, so its return is a
                    // transition the subscriber is owed.
                    && (before.is_some()
                        || !live
                        || seen.is_some_and(|l| l.first_seen_ms >= self.started_at_ms));
                state.notified = target;
                writes.push((key.clone(), sessions));
                if announce {
                    let mut event = state.meta.clone();
                    event.is_online = live;
                    // A device we already told the subscriber was gone is
                    // "back online", not a first sighting. The raw event's
                    // flag cannot say this: a re-check-driven correction
                    // has no online event behind it at all.
                    let returning = live && before == Some(0);
                    if live {
                        event.is_returning = returning;
                    }
                    // Some rigs left but the worker is still hashing: that
                    // is not an outage and must not be rendered as one.
                    let partial = match before {
                        Some(b) if live && b > sessions => Some(b),
                        _ => None,
                    };
                    // Keep the event's own timestamp when it agreed with
                    // the database — "offline since <disconnect>" is more
                    // useful than "offline since <we checked>". A partial
                    // loss has no event behind it at all (the worker is
                    // still up, so nothing disconnected as far as the
                    // event stream is concerned), so it has to be stamped
                    // when it was confirmed or it reads hours old.
                    if state.meta.is_online != live || partial.is_some() {
                        event.timestamp = now;
                    }
                    confirmed.push(Confirmed {
                        event,
                        returning,
                        partial: partial.map(|was| (sessions, was)),
                    });
                }
            }

            // Settled at offline with nothing happening: stop polling.
            // The reported state stays in `reported` (and in the store),
            // so the device's eventual return is still a transition.
            if target == Notified::Sessions(0) && now - state.last_event_at >= evict_after {
                retire.push(key.clone());
            } else {
                state.due_at = next_check;
            }
        }

        for (key, sessions) in &writes {
            inner
                .reported
                .insert(key.clone(), Notified::Sessions(*sessions));
        }
        for confirmed in confirmed {
            let address = confirmed.event.address.as_str().to_string();
            inner
                .addresses
                .entry(address)
                .or_default()
                .buffered
                .push(confirmed);
        }
        for key in retire {
            inner.devices.remove(&key);
        }
        // Address slots with nothing pending and no recent emission are
        // pure overhead.
        inner.addresses.retain(|_, s| {
            !s.buffered.is_empty() || s.last_emit.is_some_and(|l| now - l < evict_after)
        });
        writes
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
///
/// A worker that flapped inside the window appears more than once in the
/// batch. Only its **last** transition survives — otherwise the message
/// would name the same miner as both gone and back and never state where
/// it ended up.
fn collapse(batch: Vec<Confirmed>, now: DateTime<Utc>) -> DeviceNotice {
    let mut net: Vec<(String, Confirmed)> = Vec::new();
    for confirmed in batch {
        let worker = confirmed
            .event
            .worker_name
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        match net.iter_mut().find(|(w, _)| *w == worker) {
            Some(slot) => slot.1 = confirmed,
            None => net.push((worker, confirmed)),
        }
    }

    if net.len() == 1 {
        let (_, only) = net.pop().expect("len == 1");
        return match only.partial {
            Some((remaining, before)) => DeviceNotice::Partial(DevicePartial {
                address: only.event.address,
                worker_name: only.event.worker_name,
                user_agent: only.event.user_agent,
                remaining,
                before,
                timestamp: only.event.timestamp,
            }),
            None => DeviceNotice::Single(only.event),
        };
    }

    let address = net[0].1.event.address.clone();
    let mut went_offline = Vec::new();
    let mut came_back = Vec::new();
    let mut first_seen = Vec::new();
    let mut reduced = Vec::new();
    for (worker, confirmed) in net {
        if let Some((remaining, before)) = confirmed.partial {
            // Still hashing, just with fewer rigs — kept apart from the
            // outages so one message never claims both about a worker.
            reduced.push((worker, remaining, before));
        } else if !confirmed.event.is_online {
            went_offline.push(worker);
        } else if confirmed.returning {
            came_back.push(worker);
        } else {
            first_seen.push(worker);
        }
    }
    DeviceNotice::Aggregate(DeviceAggregate {
        address,
        went_offline,
        came_back,
        first_seen,
        reduced,
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
        /// `first_seen_offset_s` is relative to `t0`; negative means the
        /// pool saw the worker before the gate started.
        fn set(&self, worker: &str, live: bool, first_seen_offset_s: i64) {
            self.set_sessions(worker, usize::from(live), first_seen_offset_s)
        }
        /// The count form — `set` is the boolean shorthand for it.
        fn set_sessions(&self, worker: &str, sessions: usize, first_seen_offset_s: i64) {
            self.rows.lock().expect("lock").insert(
                Self::key(worker),
                DeviceLiveness {
                    sessions,
                    first_seen_ms: (t0() + chrono::Duration::seconds(first_seen_offset_s))
                        .timestamp_millis(),
                },
            );
        }
        /// Flip what the front reports holding open.
        fn set_live(&self, worker: &str, live: bool) {
            self.set_count(worker, usize::from(live))
        }
        /// How many sessions the fronts hold for this worker.
        fn set_count(&self, worker: &str, sessions: usize) {
            let mut rows = self.rows.lock().expect("lock");
            if let Some(entry) = rows.get_mut(&Self::key(worker)) {
                entry.sessions = sessions;
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

    /// Reported state the tests can preload and inspect, standing in
    /// for the Redis-backed store.
    #[derive(Default)]
    struct FakeStore {
        state: Mutex<HashMap<DeviceKey, usize>>,
        /// Size of each `store` call, in order. The gate must hand a
        /// sweep's changes over in one go — see
        /// `a_sweeps_writes_are_persisted_in_one_call`.
        batches: Mutex<Vec<usize>>,
    }

    impl FakeStore {
        fn preload(&self, worker: &str, online: bool) {
            self.state
                .lock()
                .expect("lock")
                .insert(FakeDb::key(worker), usize::from(online));
        }
        fn get(&self, worker: &str) -> Option<usize> {
            self.state
                .lock()
                .expect("lock")
                .get(&FakeDb::key(worker))
                .copied()
        }
        fn batches(&self) -> Vec<usize> {
            self.batches.lock().expect("lock").clone()
        }
    }

    #[async_trait]
    impl ReportedStateStore for Arc<FakeStore> {
        async fn load(&self) -> HashMap<DeviceKey, usize> {
            self.state.lock().expect("lock").clone()
        }
        async fn store(&self, updates: &[(DeviceKey, usize)]) {
            self.batches.lock().expect("lock").push(updates.len());
            let mut state = self.state.lock().expect("lock");
            for (key, sessions) in updates {
                state.insert(key.clone(), *sessions);
            }
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
        gate: Arc<DeviceStatusGate<TestClock, Arc<FakeDb>, Arc<FakeStore>>>,
        clock: TestClock,
        db: Arc<FakeDb>,
    }

    fn harness() -> Harness {
        harness_with(Arc::new(FakeStore::default()))
    }

    /// A gate with custom timings. Needed where the defaults make a
    /// scenario impossible to construct — the coalescing window is
    /// shorter than the offline grace, so two transitions for one worker
    /// can only share a buffer if the grace is turned down.
    fn harness_cfg(cfg: DeviceGateConfig) -> Harness {
        let clock = TestClock::new(t0());
        let db = Arc::new(FakeDb::default());
        let store = Arc::new(FakeStore::default());
        Harness {
            gate: Arc::new(DeviceStatusGate::new(
                cfg,
                clock.clone(),
                Arc::clone(&db),
                Arc::clone(&store),
            )),
            clock,
            db,
        }
    }

    /// A gate that starts from an existing store — what a restart looks
    /// like to the second process.
    fn harness_with(store: Arc<FakeStore>) -> Harness {
        let clock = TestClock::new(t0());
        let db = Arc::new(FakeDb::default());
        Harness {
            gate: Arc::new(DeviceStatusGate::new(
                DeviceGateConfig::default(),
                clock.clone(),
                Arc::clone(&db),
                Arc::clone(&store),
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
        /// Resolve a change that no Stratum event announced.
        ///
        /// Such a change takes TWO passes: the first spots the
        /// disagreement and arms the dwell, the second confirms it still
        /// holds. That is the whole point — a miner that loses power
        /// sends nothing, so without this the re-check would report the
        /// outage the moment it happened to run.
        async fn poll_after_dwell(&self, secs: i64) -> Vec<DeviceNotice> {
            let armed = self.gate.poll_due().await;
            assert!(
                armed.is_empty(),
                "an unannounced change must not resolve on its first pass"
            );
            self.advance(secs);
            self.gate.poll_due().await
        }
    }

    fn singles(notices: &[DeviceNotice]) -> Vec<(String, bool)> {
        notices
            .iter()
            .map(|n| match n {
                DeviceNotice::Single(e) => (e.worker_name.clone().unwrap_or_default(), e.is_online),
                DeviceNotice::Aggregate(_) | DeviceNotice::Partial(_) => {
                    panic!("expected a single notice")
                }
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
    ///
    /// The store is preloaded because that is what a deploy actually
    /// looks like: the subscriber had already been told this worker was
    /// online, and that record outlives the process. Seeding against an
    /// EMPTY store models a first-ever boot instead, where staying quiet
    /// is the correct behaviour — see
    /// `a_backfilled_device_settles_without_announcing_the_past`.
    #[tokio::test]
    async fn a_seeded_dead_device_is_reported_without_any_event() {
        let store = Arc::new(FakeStore::default());
        store.preload("axe01", true);
        let h = harness_with(store);
        h.gate.restore_reported_state().await;
        h.db.set("axe01", false, -7200);
        h.gate
            .seed([(address(), "axe01".to_string(), Some("BitAxe".into()))]);

        h.advance(20);
        assert_eq!(
            singles(&h.poll_after_dwell(301).await),
            vec![("axe01".into(), false)],
            "the restart no longer swallows it"
        );
    }

    /// Taking a device under supervision must not itself be a message.
    /// The seed reaches an hour back, so on the first boot after this
    /// ships — and for every address that gains its first subscriber —
    /// announcing what it finds would page people about disconnects that
    /// happened before anyone was watching. A brand-new subscriber's very
    /// first notification would be an hour-old outage.
    ///
    /// Settling is not forgetting: the state IS recorded, so the next
    /// real change is still a transition.
    #[tokio::test]
    async fn a_backfilled_device_settles_without_announcing_the_past() {
        let h = harness();
        // Dead for half an hour, nothing ever reported for it.
        h.db.set("axe01", false, -7200);
        h.gate
            .seed([(address(), "axe01".to_string(), Some("BitAxe".into()))]);

        h.advance(20);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "an outage from before we were watching is not news"
        );

        // But it did settle at offline rather than staying unknown, so
        // the recovery is a transition and does go out.
        h.open_window();
        h.db.set_live("axe01", true);
        h.gate.observe(&event("axe01", true, h.clock.now()));
        h.advance(100);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), true)],
            "settling silently must not swallow the return too"
        );
    }

    /// The silence is one-shot. A device backfilled while it was still
    /// running settles quietly, and the outage that follows is a normal
    /// transition — otherwise seeding would blind the gate to the first
    /// real thing that happens.
    #[tokio::test]
    async fn the_backfill_silence_covers_only_the_first_resolution() {
        let h = harness();
        h.db.set("axe01", true, -7200);
        h.gate
            .seed([(address(), "axe01".to_string(), Some("BitAxe".into()))]);
        h.advance(20);
        assert!(h.gate.poll_due().await.is_empty(), "settled quietly");

        h.db.set_live("axe01", false);
        h.advance(301);
        assert_eq!(
            singles(&h.poll_after_dwell(301).await),
            vec![("axe01".into(), false)],
            "the next change is a real transition"
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

        // Supervised: a later disconnect is reported with no event at
        // all — after the grace, which the gate arms itself.
        h.db.set_live("axe01", false);
        h.advance(301);
        assert_eq!(
            singles(&h.poll_after_dwell(301).await),
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

        // Its next accepted share revives the row. No Stratum event, so
        // the correction has to hold for a dwell before it is believed.
        h.db.set_live("axe01", true);
        h.advance(301);
        assert_eq!(
            singles(&h.poll_after_dwell(91).await),
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
            DeviceNotice::Aggregate(_) | DeviceNotice::Partial(_) => {
                panic!("expected a single notice")
            }
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

        // Comes back with no Stratum event — only the re-check sees it,
        // and it has to hold for a dwell before it counts.
        h.db.set_live("axe01", true);
        h.advance(301);
        match &h.poll_after_dwell(91).await[0] {
            DeviceNotice::Single(e) => {
                assert!(e.is_online);
                assert!(
                    e.is_returning,
                    "we told them it went offline, so this is a return"
                );
            }
            DeviceNotice::Aggregate(_) | DeviceNotice::Partial(_) => {
                panic!("expected a single notice")
            }
        }
    }

    // ── Persistence across a restart ────────────────────────────────

    /// A restart must not re-send an offline message the previous
    /// process already sent. Nothing in the pool's tables records "we
    /// told this person", so the reported state is persisted; the seed
    /// alone would re-announce the whole last hour of outages.
    #[tokio::test]
    async fn a_restart_does_not_repeat_an_offline_already_reported() {
        let store = Arc::new(FakeStore::default());
        let first = harness_with(Arc::clone(&store));
        first.bring_online("axe01").await;
        first.open_window();
        first.db.set_live("axe01", false);
        first
            .gate
            .observe(&event("axe01", false, first.clock.now()));
        first.advance(301);
        assert_eq!(
            singles(&first.gate.poll_due().await),
            vec![("axe01".into(), false)]
        );
        assert_eq!(store.get("axe01"), Some(0), "state was persisted");

        // Second process: same store, device still gone, seeded because
        // it disconnected recently.
        let second = harness_with(store);
        second.gate.restore_reported_state().await;
        second.db.set("axe01", false, -7200);
        second
            .gate
            .seed([(address(), "axe01".to_string(), Some("BitAxe".into()))]);
        second.advance(20);
        assert!(
            second.gate.poll_due().await.is_empty(),
            "the subscriber already knows"
        );
    }

    /// The mirror case: a return that was confirmed but still sitting in
    /// the coalescing buffer when the process died. The message itself is
    /// gone, but because the reported state says "offline" it is simply
    /// re-derived on the next sweep instead of being lost.
    #[tokio::test]
    async fn a_restart_re_derives_a_return_that_was_never_sent() {
        let store = Arc::new(FakeStore::default());
        store.preload("axe01", false);

        let h = harness_with(store);
        h.gate.restore_reported_state().await;
        // The pool has known this worker for hours — the newness rule
        // alone would keep it silent.
        h.db.set("axe01", true, -7200);
        h.gate
            .seed([(address(), "axe01".to_string(), Some("BitAxe".into()))]);
        h.advance(20);

        let out = h.poll_after_dwell(91).await;
        assert_eq!(singles(&out), vec![("axe01".into(), true)]);
        match &out[0] {
            DeviceNotice::Single(e) => assert!(e.is_returning, "it is a return, not a first sight"),
            DeviceNotice::Aggregate(_) | DeviceNotice::Partial(_) => {
                panic!("expected a single notice")
            }
        }
    }

    /// Retirement drops the polling entry but must NOT drop what the
    /// subscriber was told — otherwise any outage longer than the
    /// eviction horizon loses its recovery message, which is the normal
    /// outage length.
    #[tokio::test]
    async fn a_return_after_retirement_is_still_announced() {
        let h = harness();
        h.db.set("axe01", true, -7200);
        h.gate
            .seed([(address(), "axe01".to_string(), Some("BitAxe".into()))]);
        h.advance(20);
        assert!(h.gate.poll_due().await.is_empty(), "known device, silent");

        h.db.set_live("axe01", false);
        h.gate.observe(&event("axe01", false, h.clock.now()));
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)]
        );

        // An hour of silence retires the entry.
        h.advance(3601);
        let _ = h.gate.poll_due().await;
        assert!(h.gate.lock().devices.is_empty(), "no longer supervised");
        h.open_window();

        // The miner is fixed and comes back.
        h.db.set_live("axe01", true);
        h.gate.observe(&event("axe01", true, h.clock.now()));
        h.advance(100);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), true)],
            "the owner was told it went down and must be told it is back"
        );
    }

    /// A front restart resolves every supervised device in one sweep, and
    /// nothing is released until the reported state has been written. One
    /// round-trip per device would put the persistence of state nobody
    /// reads in front of the notification somebody is waiting for, so the
    /// whole sweep goes over in a single call.
    #[tokio::test]
    async fn a_sweeps_writes_are_persisted_in_one_call() {
        let store = Arc::new(FakeStore::default());
        let h = harness_with(Arc::clone(&store));

        // Twelve workers the pool has known for hours, all seeded and all
        // gone — one sweep, twelve reported-state changes.
        let workers: Vec<String> = (0..12).map(|i| format!("axe{i:02}")).collect();
        for worker in &workers {
            h.db.set(worker, false, -7200);
            store.preload(worker, true);
        }
        h.gate.restore_reported_state().await;
        h.gate.seed(
            workers
                .iter()
                .map(|w| (address(), w.clone(), Some("BitAxe".into()))),
        );

        h.advance(20);
        // Twelve devices, none of which sent a disconnect event, so the
        // first pass only arms their grace.
        let out = h.poll_after_dwell(301).await;
        assert_eq!(out.len(), 1, "one address, one aggregate");

        assert_eq!(
            store.batches(),
            vec![12],
            "twelve changes must reach the store as one batch, not twelve calls"
        );
        for worker in &workers {
            assert_eq!(store.get(worker), Some(0), "{worker} was persisted");
        }
    }

    /// The grace must not depend on the miner announcing its own death.
    ///
    /// A rig that loses power, drops off WiFi or has its cable pulled
    /// sends nothing — no Stratum event ever arrives, and only the
    /// periodic re-check notices it is gone. Resolving that on the spot
    /// reported the outage whenever the re-check happened to run:
    /// measured against a real cpuminer, an outage 8 s old was pushed
    /// under a 60 s grace. Worse, the rig coming back produced the
    /// matching online push — the exact pair the grace exists to
    /// swallow.
    #[tokio::test]
    async fn an_outage_with_no_event_still_waits_out_the_grace() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        // Gone, and it never got to say so.
        h.db.set_live("axe01", false);

        // The re-check lands right after the drop. Nothing may go out:
        // 300 s of grace have not elapsed, whatever the re-check saw.
        h.advance(301);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "an outage seconds old must not be pushed under a 300 s grace"
        );

        // Still gone once the grace has run: now it is real.
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)]
        );
    }

    /// The other half of the same rule: a rig that drops and is back
    /// before the grace expires must produce nothing at all, even though
    /// no event announced either edge. This is the flap the operator
    /// asked to be rid of.
    #[tokio::test]
    async fn an_outage_that_heals_inside_the_grace_says_nothing() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        h.db.set_live("axe01", false);
        h.advance(301);
        assert!(h.gate.poll_due().await.is_empty(), "grace armed, not sent");

        // Back before the grace runs out.
        h.db.set_live("axe01", true);
        h.advance(301);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "it never left as far as the subscriber is concerned"
        );

        // And it is still supervised: a real outage later still lands.
        h.db.set_live("axe01", false);
        h.advance(301);
        assert_eq!(
            singles(&h.poll_after_dwell(301).await),
            vec![("axe01".into(), false)],
            "the gate did not go blind after the flap"
        );
    }

    /// Three rigs under one worker name, one dies for good. Its owner is
    /// owed a message — but NOT an outage: two are still hashing, and
    /// telling them the worker went offline would be a lie.
    #[tokio::test]
    async fn one_of_three_rigs_dying_is_a_partial_loss_not_an_outage() {
        let h = harness();
        h.db.set_sessions("mrr", 3, 10);
        h.advance(10);
        h.gate.observe(&event("mrr", true, h.clock.now()));
        h.advance(100);
        assert_eq!(h.gate.poll_due().await.len(), 1, "announced with 3 rigs");
        h.open_window();

        h.db.set_count("mrr", 2);
        h.advance(301);
        let out = h.poll_after_dwell(301).await;
        assert_eq!(out.len(), 1);
        match &out[0] {
            DeviceNotice::Partial(p) => {
                assert_eq!(p.remaining, 2);
                assert_eq!(p.before, 3);
                assert_eq!(p.worker_name.as_deref(), Some("mrr"));
                // Stamped when it was confirmed, not when the worker last
                // sent an event — nothing disconnected as far as the
                // event stream knows, so the meta timestamp is stale.
                assert_eq!(p.timestamp, h.clock.now(), "stamped at confirmation");
            }
            other => panic!("a worker that is still hashing is not offline: {other:?}"),
        }
    }

    /// The same drop, healed inside the grace: a rental source rotating a
    /// rig out and a replacement in, or a rig with a hiccup. Nothing may
    /// go out — this is the whole reason the count is debounced rather
    /// than reported.
    #[tokio::test]
    async fn a_rig_replaced_inside_the_grace_says_nothing() {
        let h = harness();
        h.db.set_sessions("braiins", 40, 10);
        h.advance(10);
        h.gate.observe(&event("braiins", true, h.clock.now()));
        h.advance(100);
        assert_eq!(h.gate.poll_due().await.len(), 1);
        h.open_window();

        // Rig leaves...
        h.db.set_count("braiins", 39);
        h.advance(301);
        assert!(h.gate.poll_due().await.is_empty(), "grace armed, not sent");
        // ...replacement arrives before the grace runs out.
        h.db.set_count("braiins", 40);
        h.advance(301);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "a rotated rig is not a loss"
        );
    }

    /// The rental ends: every rig leaves. THAT is an outage, and it is
    /// the only message a rental produces besides its first online.
    #[tokio::test]
    async fn a_rental_reports_offline_only_when_the_last_rig_leaves() {
        let h = harness();
        h.db.set_sessions("braiins", 40, 10);
        h.advance(10);
        h.gate.observe(&event("braiins", true, h.clock.now()));
        h.advance(100);
        assert_eq!(h.gate.poll_due().await.len(), 1, "one online at the start");
        h.open_window();

        h.db.set_count("braiins", 0);
        h.advance(301);
        assert_eq!(
            singles(&h.poll_after_dwell(301).await),
            vec![("braiins".into(), false)],
            "all rigs gone is a real outage"
        );
    }

    /// A count that GREW is nobody's emergency, so it sends nothing —
    /// but it must still move the reference, otherwise the rig that
    /// joined could later die unnoticed.
    #[tokio::test]
    async fn a_rig_joining_is_silent_but_becomes_the_new_reference() {
        let h = harness();
        h.db.set_sessions("mrr", 2, 10);
        h.advance(10);
        h.gate.observe(&event("mrr", true, h.clock.now()));
        h.advance(100);
        assert_eq!(h.gate.poll_due().await.len(), 1);
        h.open_window();

        // A third rig joins: silent.
        h.db.set_count("mrr", 3);
        h.advance(301);
        assert!(h.gate.poll_due().await.is_empty(), "arming, not announcing");
        h.advance(301);
        assert!(h.gate.poll_due().await.is_empty(), "growth is not news");

        // It dies again — measured against 3, not against the original 2.
        h.db.set_count("mrr", 2);
        h.advance(301);
        match &h.poll_after_dwell(301).await[0] {
            DeviceNotice::Partial(p) => {
                assert_eq!((p.before, p.remaining), (3, 2), "reference followed growth");
            }
            other => panic!("expected a partial loss: {other:?}"),
        }
    }

    /// A miner that is merely share-quiet must not read as gone. The
    /// front reports what it holds open, so a session that has not
    /// submitted a share in a while is still simply live — the
    /// dead-client sweep, which retires such a session in the database,
    /// has no say here at all.
    #[tokio::test]
    async fn a_share_quiet_but_connected_miner_stays_online() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        // Hours of re-checks with no Stratum event and no share.
        for cycle in 0..20 {
            h.advance(301);
            assert!(
                h.gate.poll_due().await.is_empty(),
                "cycle {cycle}: the front still holds it open"
            );
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
                assert!(agg.came_back.is_empty() && agg.first_seen.is_empty());
            }
            DeviceNotice::Single(_) | DeviceNotice::Partial(_) => {
                panic!("three transitions must aggregate")
            }
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
                let mut names = agg.first_seen.clone();
                names.sort();
                assert_eq!(names, vec!["b", "c"]);
            }
            DeviceNotice::Single(_) | DeviceNotice::Partial(_) => {
                panic!("two held transitions must aggregate")
            }
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
            singles(&h.poll_after_dwell(301).await),
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
            singles(&h.poll_after_dwell(301).await),
            vec![("axe01".into(), false)]
        );
    }

    /// A worker that flaps across a coalescing window appears twice in
    /// the batch. Naming it on both sides tells the subscriber nothing —
    /// only where it ended up matters.
    #[tokio::test]
    async fn a_worker_that_flaps_across_the_window_is_reported_once() {
        // Short dwells so both of `b`'s transitions resolve while the
        // address's window is still closed; with the defaults the window
        // reopens between them and the batch never holds two.
        let h = harness_cfg(DeviceGateConfig {
            offline_grace: Duration::from_secs(30),
            online_dwell: Duration::from_secs(10),
            coalesce_window: Duration::from_secs(300),
            recheck_interval: Duration::from_secs(300),
        });

        // `b` is known and reported online; `a` is announced, which is
        // what closes the window.
        h.db.set("b", true, -7200);
        h.gate.observe(&event("b", true, h.clock.now()));
        h.advance(15);
        assert!(h.gate.poll_due().await.is_empty(), "known device, silent");
        h.db.set("a", true, 5);
        h.gate.observe(&event("a", true, h.clock.now()));
        h.advance(15);
        assert_eq!(h.gate.poll_due().await.len(), 1, "`a` opens the window");

        // `b` drops...
        h.db.set_live("b", false);
        h.gate.observe(&event("b", false, h.clock.now()));
        h.advance(35);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "buffered, window closed"
        );
        // ...and returns, both inside the same window.
        h.db.set_live("b", true);
        h.gate.observe(&event("b", true, h.clock.now()));
        h.advance(15);
        assert!(h.gate.poll_due().await.is_empty(), "also buffered");

        h.advance(300);
        let out = h.gate.poll_due().await;
        assert_eq!(out.len(), 1, "one address, one message");
        match &out[0] {
            // Only `b` moved, and its net state is online — so this
            // collapses back to a single notice rather than an aggregate
            // naming the same miner twice.
            DeviceNotice::Single(e) => {
                assert_eq!(e.worker_name.as_deref(), Some("b"));
                assert!(e.is_online, "net state is online");
            }
            DeviceNotice::Aggregate(agg) => panic!(
                "a single worker must not be listed twice: offline={:?} back={:?} new={:?}",
                agg.went_offline, agg.came_back, agg.first_seen
            ),
            DeviceNotice::Partial(p) => panic!("net state is online, not a partial loss: {p:?}"),
        }
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
