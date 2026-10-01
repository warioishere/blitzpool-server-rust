// SPDX-License-Identifier: AGPL-3.0-or-later

//! Debounce + coalescing in front of the device-status fan-out, so flapping
//! Stratum edges do not become push storms. An event only schedules a
//! re-check; the gate emits when live sessions differ from what the subscriber
//! was last told ([`Notified`], persisted via [`ReportedStateStore`]).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use bp_common::AddressId;
use bp_cron_utils::Clock;
use chrono::{DateTime, Utc};

use super::orchestrator::DeviceStatusEvent;

/// `(address, worker)`, not the session id: the subscriber cares about the
/// device, not one connection or channel.
pub type DeviceKey = (String, String);

/// A device settled offline with no Stratum event for this long stops being
/// polled; its reported state is kept so a later return is still a transition.
const EVICT_AFTER: Duration = Duration::from_secs(60 * 60);

/// Timing knobs. Defaults match `bp_config`'s serde defaults.
#[derive(Debug, Clone, Copy)]
pub struct DeviceGateConfig {
    /// How long a device must look gone before "offline" is reported.
    pub offline_grace: Duration,
    /// How long a device must look present before "online" is reported.
    pub online_dwell: Duration,
    /// Minimum spacing between two messages for one address; transitions
    /// inside it go out together as one [`DeviceNotice::Aggregate`].
    pub coalesce_window: Duration,
    /// Re-check interval for a settled device, so a wrong answer is temporary.
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
pub(crate) enum Notified {
    /// Nothing has ever been sent for this device.
    Unknown,
    /// Sessions the subscriber was last told about; zero is offline. A count,
    /// not a flag, so losing one of three rigs is distinguishable from all.
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
    /// Earliest `COALESCE(firstSeen, startTime)` across the pair's rows;
    /// `startTime` alone is refreshed on every re-register.
    pub first_seen_ms: i64,
}

/// Liveness from the sockets the Stratum fronts hold open, not `client_entity`
/// (which soft-deletes slow miners too). `None` means the lookup failed, not
/// "no sessions": draw no conclusion, or a blip reports every miner offline.
#[async_trait]
pub trait DeviceLivenessLookup: Send + Sync {
    async fn liveness(&self, keys: &[DeviceKey]) -> Option<HashMap<DeviceKey, DeviceLiveness>>;
}

/// Durable record of what each subscriber was last told, the one gate state no
/// table can rebuild. Without it a restart re-sends offline messages and
/// swallows the matching "back online".
#[async_trait]
pub trait ReportedStateStore: Send + Sync {
    /// Everything remembered, at startup. On failure return an empty map
    /// rather than block the gate.
    async fn load(&self) -> HashMap<DeviceKey, usize>;
    /// Record what changed in this sweep, best-effort. Batched because
    /// messages wait for this call and a front restart changes many at once.
    async fn store(&self, updates: &[(DeviceKey, usize)]);
}

/// A confirmed, ready-to-send device-status message.
#[derive(Debug, Clone)]
pub enum DeviceNotice {
    /// One transition.
    Single(DeviceStatusEvent),
    /// Some of a worker's rigs are gone and the rest keep hashing. NOT
    /// an outage, and never rendered as one.
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

/// Two or more transitions on one address. Returning and first-seen devices
/// are kept apart: they tell the subscriber different things.
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
    /// Backfilled with nothing ever reported: the first resolution only records
    /// its state, so a restart does not announce disconnects nobody watched.
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

/// Feed raw events through [`observe`](Self::observe) from any task; drive
/// [`poll_due`](Self::poll_due) from exactly ONE periodic task, since two
/// concurrent sweeps could emit the same transition twice.
pub struct DeviceStatusGate<C, L, S> {
    cfg: DeviceGateConfig,
    clock: C,
    lookup: L,
    store: S,
    /// Anything the pool saw before this instant predates this gate's
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

    /// Rebuild the watch list at startup from `(address, worker, user_agent)`
    /// of devices whose deadline may have died with the previous process.
    /// Seeded devices inherit their reported state, so nothing is re-sent or lost.
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
                // A device the subscriber already heard about still gets
                // its offline message.
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
            settle_silently: false,
            meta: event.clone(),
            last_event_at: now,
        });
        // An answer already in flight is now stale; discard it.
        if state.in_flight {
            state.dirty = true;
        }
        state.meta = event.clone();
        state.last_event_at = now;

        match state.armed_by {
            // Only the periodic re-check is pending, so this event may set its own.
            None => {
                state.due_at = match dir {
                    Direction::Online => online_deadline,
                    Direction::Offline => offline_deadline,
                };
                state.armed_by = Some(dir);
            }
            // A disconnect always gets the full grace. One-way, so a device
            // flapping faster than the grace cannot postpone judgement forever.
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
                // Blind: keep every deadline and retry; already confirmed
                // messages are still released below.
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

    /// Lookup failed: drop the in-flight marks, keep deadlines. `dirty` is
    /// cleared too, or it would discard the next fresh answer.
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

            // An event landed mid-lookup and could not arm a deadline: arm it
            // here and discard the stale answer.
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
            // One-shot: consumed whatever the answer is.
            let settling = std::mem::replace(&mut state.settle_silently, false);

            let previous = state.notified;
            // Any change must survive a full dwell before it counts. Armed
            // here too, because a miner losing power sends no event and only
            // the re-check sees it. A settling device is exempt.
            if target != previous && !settling && state.armed_by != Some(direction) {
                state.armed_by = Some(direction);
                state.due_at = now + self.dwell(direction);
                continue;
            }
            state.armed_by = None;

            if target != previous {
                let before = previous.count();
                // A never-reported device is announced only if first seen after
                // this gate started, or a restart becomes a broadcast. A grown
                // count is not announced but remembered for the next loss.
                let grew = before.is_some_and(|b| sessions > b && b > 0);
                let announce = !settling
                    && !grew
                    // `is_some`, not `> 0`: the return of a device already
                    // reported as gone is owed to the subscriber.
                    && (before.is_some()
                        || !live
                        || seen.is_some_and(|l| l.first_seen_ms >= self.started_at_ms));
                state.notified = target;
                writes.push((key.clone(), sessions));
                if announce {
                    let mut event = state.meta.clone();
                    event.is_online = live;
                    // Derived here, not from the raw event: a re-check
                    // correction has no online event behind it.
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
                    // Keep the event's timestamp when it agrees with the
                    // answer; a partial loss has no event, so stamp it now.
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

            // Settled offline and quiet: stop polling, keep `reported`.
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

/// One transition stays single; several become an aggregate, so an address
/// gets at most one message per window. Per worker only the last transition
/// survives, so the message states where it ended up.
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
            // Kept apart from outages so one message never claims both.
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

    /// Test-driven liveness answers; `fail` simulates an unreachable lookup.
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
        fn set_live(&self, worker: &str, live: bool) {
            self.set_count(worker, usize::from(live))
        }
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
            // Snapshot before the hook, so the answer is genuinely stale.
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
            // Also on the failure path: an event can land during a failing lookup.
            let hook = self.on_lookup.lock().expect("lock").take();
            if let Some(hook) = hook {
                hook();
            }
            answer
        }
    }

    /// Preloadable, inspectable stand-in for the Redis-backed store.
    #[derive(Default)]
    struct FakeStore {
        state: Mutex<HashMap<DeviceKey, usize>>,
        /// Size of each `store` call, in order.
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
            // Pinned to one value to prove the gate ignores it.
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

    /// A gate with custom timings, for scenarios the defaults cannot build.
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

    /// A gate that starts from an existing store, as after a restart.
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
        /// Bring a worker to reported-online as a brand-new device.
        async fn bring_online(&self, worker: &str) {
            self.db.set(worker, true, 10);
            self.advance(10);
            self.gate.observe(&event(worker, true, self.clock.now()));
            self.advance(100);
            let out = self.gate.poll_due().await;
            assert_eq!(out.len(), 1, "a first-seen device announces itself");
        }
        /// Re-open the coalescing window so setup does not interfere.
        fn open_window(&self) {
            self.advance(301);
        }
        /// Resolve a change no Stratum event announced: the first pass arms
        /// the dwell, the second confirms it.
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

    /// A drop and return inside the grace sends nothing.
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

    /// A device that stays gone is reported offline exactly once.
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

    /// One rig of many leaving is not the device going offline.
    #[tokio::test]
    async fn one_of_many_sessions_leaving_is_not_an_outage() {
        let h = harness();
        h.db.set("mrr", true, -3600);
        h.gate.observe(&event("mrr", true, h.clock.now()));
        h.advance(100);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "a source the pool already knew is not announced"
        );

        // One rig rotates out; others remain.
        h.gate.observe(&event("mrr", false, h.clock.now()));
        h.advance(301);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "the source still has live sessions"
        );

        h.db.set_live("mrr", false);
        h.gate.observe(&event("mrr", false, h.clock.now()));
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("mrr".into(), false)]
        );
    }

    /// Flapping faster than the grace cannot postpone the evaluation.
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

    /// A disconnect gets the full `offline_grace` over a pending `online_dwell`.
    #[tokio::test]
    async fn a_disconnect_upgrades_a_pending_online_dwell_to_the_full_grace() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        h.gate.observe(&event("axe01", true, h.clock.now()));
        h.advance(10);
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

    /// Newness comes from when the pool first saw the worker, not the event.
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

    /// A reconnect storm after a restart announces nobody.
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

    /// A device unknown to a fresh gate still gets its offline message.
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

    /// A device reported online that died across a restart is reported via seeding.
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

    /// A backfilled, never-reported device settles silently but its state is
    /// recorded, so the next real change is still a transition.
    #[tokio::test]
    async fn a_backfilled_device_settles_without_announcing_the_past() {
        let h = harness();
        h.db.set("axe01", false, -7200);
        h.gate
            .seed([(address(), "axe01".to_string(), Some("BitAxe".into()))]);

        h.advance(20);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "an outage from before we were watching is not news"
        );

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

    /// The backfill silence is one-shot.
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

    /// A seeded live device settles quietly and stays supervised.
    #[tokio::test]
    async fn a_seeded_live_device_settles_silently_and_stays_supervised() {
        let h = harness();
        h.db.set("axe01", true, -7200);
        h.gate
            .seed([(address(), "axe01".to_string(), Some("BitAxe".into()))]);

        h.advance(20);
        assert!(h.gate.poll_due().await.is_empty());

        // A later disconnect with no event is reported after the grace.
        h.db.set_live("axe01", false);
        h.advance(301);
        assert_eq!(
            singles(&h.poll_after_dwell(301).await),
            vec![("axe01".into(), false)]
        );
    }

    /// A wrong "offline" is corrected by the re-check alone.
    #[tokio::test]
    async fn a_wrong_offline_is_corrected_by_the_recheck() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        h.db.set_live("axe01", false);
        h.gate.observe(&event("axe01", false, h.clock.now()));
        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)],
            "the wrong offline does go out"
        );

        h.db.set_live("axe01", true);
        h.advance(301);
        assert_eq!(
            singles(&h.poll_after_dwell(91).await),
            vec![("axe01".into(), true)],
            "the re-check corrects it with no event to trigger on"
        );
    }

    /// An event during the lookup discards the stale answer.
    #[tokio::test]
    async fn an_event_during_the_lookup_discards_the_stale_answer() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        h.db.set_live("axe01", false);
        h.gate.observe(&event("axe01", false, h.clock.now()));
        h.advance(301);

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

        h.advance(400);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "reported state never changed"
        );
    }

    /// A return after a reported offline is "back online", even via re-check.
    #[tokio::test]
    async fn a_return_after_a_reported_offline_renders_as_back_online() {
        let h = harness();
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

    /// A restart does not repeat an offline message already sent.
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

    /// A return lost in the coalescing buffer at restart is re-derived.
    #[tokio::test]
    async fn a_restart_re_derives_a_return_that_was_never_sent() {
        let store = Arc::new(FakeStore::default());
        store.preload("axe01", false);

        let h = harness_with(store);
        h.gate.restore_reported_state().await;
        // Known for hours, so the newness rule alone would keep it silent.
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

    /// A return after retirement is still announced.
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

        h.advance(3601);
        let _ = h.gate.poll_due().await;
        assert!(h.gate.lock().devices.is_empty(), "no longer supervised");
        h.open_window();

        h.db.set_live("axe01", true);
        h.gate.observe(&event("axe01", true, h.clock.now()));
        h.advance(100);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), true)],
            "the owner was told it went down and must be told it is back"
        );
    }

    /// One sweep's reported-state changes reach the store in one call.
    #[tokio::test]
    async fn a_sweeps_writes_are_persisted_in_one_call() {
        let store = Arc::new(FakeStore::default());
        let h = harness_with(Arc::clone(&store));

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

    /// An outage only the re-check finds still waits out the full grace.
    #[tokio::test]
    async fn an_outage_with_no_event_still_waits_out_the_grace() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        h.db.set_live("axe01", false);

        h.advance(301);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "an outage seconds old must not be pushed under a 300 s grace"
        );

        h.advance(301);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)]
        );
    }

    /// An unannounced outage that heals inside the grace sends nothing.
    #[tokio::test]
    async fn an_outage_that_heals_inside_the_grace_says_nothing() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        h.db.set_live("axe01", false);
        h.advance(301);
        assert!(h.gate.poll_due().await.is_empty(), "grace armed, not sent");

        h.db.set_live("axe01", true);
        h.advance(301);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "it never left as far as the subscriber is concerned"
        );

        h.db.set_live("axe01", false);
        h.advance(301);
        assert_eq!(
            singles(&h.poll_after_dwell(301).await),
            vec![("axe01".into(), false)],
            "the gate did not go blind after the flap"
        );
    }

    /// One of three rigs dying is a partial loss, not an outage.
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
                assert_eq!(p.timestamp, h.clock.now(), "stamped at confirmation");
            }
            other => panic!("a worker that is still hashing is not offline: {other:?}"),
        }
    }

    /// A count drop healed inside the grace sends nothing.
    #[tokio::test]
    async fn a_rig_replaced_inside_the_grace_says_nothing() {
        let h = harness();
        h.db.set_sessions("braiins", 40, 10);
        h.advance(10);
        h.gate.observe(&event("braiins", true, h.clock.now()));
        h.advance(100);
        assert_eq!(h.gate.poll_due().await.len(), 1);
        h.open_window();

        h.db.set_count("braiins", 39);
        h.advance(301);
        assert!(h.gate.poll_due().await.is_empty(), "grace armed, not sent");
        h.db.set_count("braiins", 40);
        h.advance(301);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "a rotated rig is not a loss"
        );
    }

    /// A rental reports offline only when its last rig leaves.
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

    /// Growth is silent but becomes the reference for the next loss.
    #[tokio::test]
    async fn a_rig_joining_is_silent_but_becomes_the_new_reference() {
        let h = harness();
        h.db.set_sessions("mrr", 2, 10);
        h.advance(10);
        h.gate.observe(&event("mrr", true, h.clock.now()));
        h.advance(100);
        assert_eq!(h.gate.poll_due().await.len(), 1);
        h.open_window();

        h.db.set_count("mrr", 3);
        h.advance(301);
        assert!(h.gate.poll_due().await.is_empty(), "arming, not announcing");
        h.advance(301);
        assert!(h.gate.poll_due().await.is_empty(), "growth is not news");

        h.db.set_count("mrr", 2);
        h.advance(301);
        match &h.poll_after_dwell(301).await[0] {
            DeviceNotice::Partial(p) => {
                assert_eq!((p.before, p.remaining), (3, 2), "reference followed growth");
            }
            other => panic!("expected a partial loss: {other:?}"),
        }
    }

    /// A share-quiet but connected miner stays online.
    #[tokio::test]
    async fn a_share_quiet_but_connected_miner_stays_online() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        for cycle in 0..20 {
            h.advance(301);
            assert!(
                h.gate.poll_due().await.is_empty(),
                "cycle {cycle}: the front still holds it open"
            );
        }
    }

    /// A failed lookup holds the deadline instead of guessing offline.
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

    /// An event during a failed lookup costs no extra dwell.
    #[tokio::test]
    async fn an_event_during_a_failed_lookup_does_not_delay_the_next_answer() {
        let h = harness();
        h.bring_online("axe01").await;
        h.open_window();

        h.db.set_live("axe01", false);
        h.gate.observe(&event("axe01", false, h.clock.now()));
        h.advance(301);

        let gate = Arc::clone(&h.gate);
        let at = h.clock.now();
        *h.db.on_lookup.lock().expect("lock") = Some(Box::new(move || {
            gate.observe(&event("axe01", false, at));
        }));
        h.db.fail(true);
        assert!(h.gate.poll_due().await.is_empty(), "no guess while blind");

        h.db.fail(false);
        h.advance(1);
        assert_eq!(
            singles(&h.gate.poll_due().await),
            vec![("axe01".into(), false)],
            "a failed lookup must not cost another full grace"
        );
    }

    /// A buffered, confirmed message is released during a database outage.
    #[tokio::test]
    async fn a_buffered_message_is_released_during_a_database_outage() {
        let h = harness();
        h.bring_online("a").await; // opens the window

        h.db.set("b", true, 5);
        h.gate.observe(&event("b", true, h.clock.now()));
        h.advance(95);
        assert!(h.gate.poll_due().await.is_empty(), "held by the window");

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

    /// Simultaneous transitions on one address collapse into one message.
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

    /// A transition inside a closed window is held, then released on reopen.
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

    /// Two transitions held together leave as one message.
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

    /// Settled offline devices are retired, so churning names cannot grow the map.
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

    /// A worker missing from the liveness answer resolves offline, then retires.
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

    /// A live device is never retired, so its eventual disconnect is caught.
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

    /// A worker flapping inside one window is reported once, as its end state.
    #[tokio::test]
    async fn a_worker_that_flaps_across_the_window_is_reported_once() {
        // Short dwells, so both transitions resolve inside one closed window.
        let h = harness_cfg(DeviceGateConfig {
            offline_grace: Duration::from_secs(30),
            online_dwell: Duration::from_secs(10),
            coalesce_window: Duration::from_secs(300),
            recheck_interval: Duration::from_secs(300),
        });

        // `b` is known; announcing `a` closes the window.
        h.db.set("b", true, -7200);
        h.gate.observe(&event("b", true, h.clock.now()));
        h.advance(15);
        assert!(h.gate.poll_due().await.is_empty(), "known device, silent");
        h.db.set("a", true, 5);
        h.gate.observe(&event("a", true, h.clock.now()));
        h.advance(15);
        assert_eq!(h.gate.poll_due().await.len(), 1, "`a` opens the window");

        h.db.set_live("b", false);
        h.gate.observe(&event("b", false, h.clock.now()));
        h.advance(35);
        assert!(
            h.gate.poll_due().await.is_empty(),
            "buffered, window closed"
        );
        h.db.set_live("b", true);
        h.gate.observe(&event("b", true, h.clock.now()));
        h.advance(15);
        assert!(h.gate.poll_due().await.is_empty(), "also buffered");

        h.advance(300);
        let out = h.gate.poll_due().await;
        assert_eq!(out.len(), 1, "one address, one message");
        match &out[0] {
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

    /// A name-rotating proxy is bounded by the coalescing window, not the debounce.
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
        // Pinned exactly (ceiling 3600/300 = 12) so any per-event leak shows.
        assert_eq!(
            messages, 11,
            "119 transitions must collapse to one message per coalescing window"
        );
    }
}
