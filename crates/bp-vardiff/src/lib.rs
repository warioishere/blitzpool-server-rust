// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-session VarDiff engine + ckpool-style race-window clamp.
//!
//! Pure-math leaf crate, std-only. Shared between [`bp-stratum-v1`] (which
//! sends the result as `mining.set_difficulty` JSON) and `bp-stratum-v2`
//! (which sends the result as a binary `SetTarget` frame on Standard /
//! Extended channels). The vardiff math is wire-format-agnostic — only
//! the framing layer differs.
//!
//! Originally lived in `bp-stratum-v1::vardiff`; extracted to its own
//! crate 2026-05-16 when bp-stratum-v2 was about to grow its own copy.
//!
//! Implements the per-session VarDiff algorithm (shares-per-minute
//! retarget) and the `effectiveJobDifficulty` helper used for the
//! ckpool-style race-window clamp. This is the pool's only retarget
//! algorithm — SV1, SV2 Standard, SV2 Extended and job-declaration
//! channels all run it.
//!
//! Two pieces:
//!
//! - [`VarDiffEngine`] tracks per-session live hashrate (10-minute slots,
//!   `(prev + current) * 2^32 / elapsed_seconds`) AND the sliding 5-min /
//!   30-sample submission cache used to retarget the session difficulty.
//!   `update_hash_rate` is called for every accepted share;
//!   `suggested_difficulty` is polled on a timer (default every 60 s).
//!
//! - [`effective_job_difficulty`] is the share-validation race-clamp:
//!   when a vardiff ratchet flips the session difficulty up, in-flight
//!   shares for jobs already issued at the OLD diff would otherwise be
//!   rejected as "Difficulty too low" even though the miner was working
//!   on exactly the target we'd given them. The clamp validates and
//!   credits those shares at `min(current, old)` so the miner gets paid
//!   for the work they actually did.
//!
//! ## Silence easing (opt-in)
//!
//! The retarget math is a feedback loop whose only sensor is the arriving
//! share stream — and every rate estimate here historically ended its
//! observation window at the LAST share's timestamp. A session that went
//! quiet therefore kept being evaluated against a frozen window: the
//! controller went blind exactly when it most needed to act, and the
//! difficulty stayed pinned where the miner could no longer reach it.
//!
//! With [`VarDiffEngine::with_silence_easing`] enabled, the estimators end
//! their window at *now* instead: elapsed time without submissions is real
//! observation time with zero arrivals, so silence itself lowers the
//! estimate and the ordinary retarget mechanism walks the difficulty down
//! — no second estimator, no timers, no special-case state. The estimate
//! decays as 1/T (one halving per doubling of the silence), which is
//! exactly the information-theoretic envelope a silent session justifies.
//!
//! Three rules bound it:
//!
//! - **Rejected submissions count as alive.** A miner in a reject storm
//!   (duplicate/stale bursts from an exhausted Standard-channel search
//!   space) is hashing at full rate against a stale job; lowering its
//!   difficulty would not help and floods on the next job. Servers stamp
//!   [`VarDiffEngine::note_submission`] for every rejected share, and the
//!   silence tail only counts time after the last submission of ANY kind.
//! - **Bounded descent** ([`VARDIFF_SILENCE_MAX_DESCENT_FACTOR`]): the
//!   silence argument can pull the estimate at most 16× below the rate
//!   measured before the silence began.
//! - **Bounded up-step** ([`VARDIFF_MAX_UP_STEP_FACTOR`]): no single
//!   retarget raises the difficulty more than 8×, so recovery from an
//!   eased-down state cannot overshoot and a burst-inflated window cannot
//!   spike the target.
//!
//! ## Before the first share (same switch)
//!
//! Easing needs a window to widen, so it needs at least one share. A
//! session that has never landed one is upstream of it: the estimators
//! have no sensor reading at all, and an over-assigned session — a proxy
//! that lost most of its workers, a device weaker than the
//! `nominal_hash_rate` it declared — sits at a difficulty it cannot reach
//! with nothing to lower it. The help is gated behind the very share the
//! too-high difficulty is suppressing.
//!
//! Here the waiting itself is the measurement. Zero arrivals over a
//! difficulty history `D(t)` bound the hashrate from above at confidence
//! α, and that bound maps to a difficulty in one step:
//! `D = k·τ / ∫dt/D(t)` (see [`VARDIFF_NO_SHARE_CONFIDENCE_K`]). Unlike a
//! fixed per-cycle divisor this knows the difference between a quiet
//! minute on a 0.6 shares/min port and a quiet minute on a 15 shares/min
//! port, and it does not care how often the caller ticks.
//!
//! Bounded the same way: the descent parks at
//! [`VARDIFF_NO_SHARE_MAX_DESCENT_FACTOR`] below the opening difficulty
//! (it only has to get the session from *never* to *occasionally* — one
//! share hands over to the bootstrap, which converges in a single step),
//! it may only ever propose a strict decrease, and
//! [`VarDiffEngine::note_submission`] spends the accumulated evidence
//! because a rejected share is still a hash that met the target.
//!
//! Both halves need [`VarDiffEngine::note_difficulty_assigned`] on every
//! difficulty assignment, whatever the route.
//!
//! The engine is owned `&mut` by its connection task — no internal locks.
//! A [`Clock`] trait makes the time source injectable so tests can pin
//! deterministic timestamps.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of submissions kept in the retarget sample cache.
pub const VARDIFF_CACHE_SIZE: usize = 30;

/// Sliding window for the submission cache. Older entries are dropped on
/// the next `update_hash_rate`.
pub const VARDIFF_CACHE_WINDOW_MS: u64 = 300_000;

/// Default vardiff floor when the caller passes a non-finite / non-positive
/// `min_difficulty`.
pub const VARDIFF_DEFAULT_MIN_DIFFICULTY: f64 = 0.00001;

/// Difficulty-1 hash count (`2^32`). Used to convert accepted-share
/// difficulty into hashrate (`sum * DIFFICULTY_1 / seconds`).
pub const VARDIFF_DIFFICULTY_1: f64 = 4_294_967_296.0;

/// Hashrate-slot length. 10-minute slots labeled by their end timestamp;
/// the engine only cares about transitions, so the constant is inlined
/// here rather than imported from `bp-stats`.
pub const VARDIFF_SLOT_DURATION_MS: u64 = 600_000;

/// Minimum samples before the full cache-rate retarget math is allowed to
/// fire. Below the threshold, the engine waits during warmup, then — past the
/// warmup window — retargets from the measured hashrate (the under-sampled
/// path in [`VarDiffEngine::suggested_difficulty`]).
pub const VARDIFF_SAMPLE_THRESHOLD: usize = 5;

/// Initial warmup period during which under-sampled sessions are NOT
/// retargeted (return `None`). After this, an under-sampled session retargets
/// from its measured hashrate (once it has one) instead of waiting for a full
/// sample window.
pub const VARDIFF_WARMUP_MS: u64 = 60_000;

/// Default `target_shares_per_minute` fallback for misconfigured ports.
pub const VARDIFF_DEFAULT_TARGET_SHARES_PER_MIN: f64 = 6.0;

/// Silence easing: hard floor of the descent, as a factor below the rate
/// measured before the silence began. A session that is not slow but GONE
/// (hashboards off, socket alive) parks at most this far below its last
/// measured rate instead of sinking to `min_difficulty` — bounding the
/// share flood it produces on return to `16×` the target rate for at most
/// one check interval. 16 fully rescues every realistic throttle
/// (solar/night 2–10×, power modes 2–4×, dead hashboards ~3×) and keeps
/// even a 100×-throttled rig alive at ~2 shares/min; pathological drops
/// (TH→kH) are the bootstrap path's job, not this bound's.
pub const VARDIFF_SILENCE_MAX_DESCENT_FACTOR: f64 = 16.0;

/// Silence easing: cap on a single UPWARD retarget. Protects against a
/// rate estimate inflated by a burst (a job-declaration client drains its
/// optimistic-mining share cache in a bundle) and paces the recovery of an
/// eased-down session: from the descent floor back to equilibrium in one
/// 8× step plus one small one, while an estimate that is wrong by more
/// than 8× gets a second interval to prove itself before being trusted.
pub const VARDIFF_MAX_UP_STEP_FACTOR: f64 = 8.0;

/// No-share descent: the confidence constant `k = ln(1/α)` of the Poisson
/// upper bound on a hashrate that has produced no share at all.
///
/// Shares arrive at `λ = H / (D · 2^32)`, so observing none while the
/// assigned difficulty follows `D(t)` has probability `e^-((H/2^32)·S)`
/// with `S = ∫dt/D(t)`. The hashrates that survive at level α are exactly
/// `H ≤ k · 2^32 / S`. 3.0 is α = 5 %.
///
/// **Not a tuning knob.** α = 1 % would be 4.605 — a 1.5× difference, less
/// than one rung of the power-of-two ladder every proposal is rounded onto
/// anyway. Changing it changes nothing you can observe.
pub const VARDIFF_NO_SHARE_CONFIDENCE_K: f64 = 3.0;

/// No-share descent: hard floor, as a factor below the difficulty the
/// session opened with. The counterpart of
/// [`VARDIFF_SILENCE_MAX_DESCENT_FACTOR`] for a session that has never
/// landed a share, where there is no measured pre-silence rate to bound
/// against — only the difficulty that was assigned from a declared
/// hashrate we have just decided not to believe.
///
/// The descent does NOT have to reach equilibrium: one accepted share
/// hands over to the under-sampled bootstrap, which converges in a single
/// step. It only has to get the miner from *never* to *occasionally*. 256
/// covers a proxy that lost 99.6 % of its workers, and on a
/// `high_diff_start_difficulty = 1000000` port it still parks near 3900,
/// where even a badly over-assigned miner produces a share or two a
/// minute. Going looser buys little and costs a bigger flood if a fully
/// idle session returns at full power.
pub const VARDIFF_NO_SHARE_MAX_DESCENT_FACTOR: f64 = 256.0;

// ── Clock ────────────────────────────────────────────────────────────

/// Monotonic-ish millisecond clock. Real-world impl wraps `SystemTime`;
/// tests use [`TestClock`] for deterministic advance.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// Wall-clock implementation. Returns `SystemTime::now()` as millis
/// since the UNIX epoch. The vardiff engine only ever uses time
/// differences, so a backwards step (NTP adjustment) at most produces a
/// stalled-retarget window — never panics.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// Deterministic clock for tests. `now_ms` is held in an atomic so it can
/// be shared by reference; `advance` / `set` mutate it without an outer
/// lock.
#[derive(Debug)]
pub struct TestClock {
    now_ms: AtomicU64,
}

impl TestClock {
    pub fn new(start_ms: u64) -> Self {
        Self {
            now_ms: AtomicU64::new(start_ms),
        }
    }

    pub fn advance_ms(&self, ms: u64) {
        self.now_ms.fetch_add(ms, Ordering::Relaxed);
    }

    pub fn set_ms(&self, ms: u64) {
        self.now_ms.store(ms, Ordering::Relaxed);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::Relaxed)
    }
}

// Blanket impl so `&TestClock` / `Arc<TestClock>` can be used directly.
impl<T: Clock + ?Sized> Clock for &T {
    fn now_ms(&self) -> u64 {
        (**self).now_ms()
    }
}

impl<T: Clock + ?Sized> Clock for std::sync::Arc<T> {
    fn now_ms(&self) -> u64 {
        (**self).now_ms()
    }
}

// ── effective_job_difficulty ─────────────────────────────────────────

/// ckpool-style per-job difficulty clamp.
///
/// When a vardiff ratchet flips the session difficulty up, miner firmware
/// typically only applies the new target on the next `mining.notify` —
/// shares for jobs already in flight were legitimately computed against
/// the OLD target. Without this clamp those shares get rejected as
/// "Difficulty too low" even though the miner did what we told it to do.
///
/// Returns the difficulty to use for BOTH the validation `>=` check AND
/// downstream accounting (PPLNS recordShare, group-solo recordShare,
/// per-mode hashrate, share totals). Keeping these in lock-step prevents
/// the miner from getting credit at the post-ratchet diff for work they
/// actually did at the pre-ratchet diff.
///
/// `job_id_int = None` corresponds to a `parseInt` failure on the wire-
/// hex jobId (malformed submission); falls back to `currentDiff`.
///
/// `diff_change_job_id = None` means no ratchet has happened since the
/// session started — the clamp is inactive and `currentDiff` always wins.
pub fn effective_job_difficulty(
    job_id_int: Option<u64>,
    current_diff: f64,
    old_diff: f64,
    diff_change_job_id: Option<u64>,
) -> f64 {
    match (job_id_int, diff_change_job_id) {
        (None, _) => current_diff,
        (Some(_), None) => current_diff,
        (Some(jid), Some(boundary)) => {
            if jid < boundary {
                current_diff.min(old_diff)
            } else {
                current_diff
            }
        }
    }
}

// ── VarDiffEngine ────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
struct Submission {
    time_ms: u64,
    difficulty: f64,
}

/// Per-session VarDiff state machine + hashrate accumulator.
///
/// **Two state stores**, both owned by `&mut self`:
///
/// - `submission_cache` — sliding 30-sample / 5-min window of accepted
///   shares' difficulty + arrival time. Drives the retarget math.
///   Stale-diff shares (clamped-via-`effective_job_difficulty`) MUST
///   be excluded with `is_current_diff = false`; mixing them pollutes
///   the rolling sum and oscillates the retarget.
///
/// - Hashrate accumulators — `shares` and `previous_shares` over
///   10-minute time slots, used to compute the displayed live hashrate
///   as `(prev + current) * 2^32 / elapsed_seconds`. ALL accepted shares
///   contribute here, including clamped ones — the user-facing hashrate
///   must reflect real work even during a vardiff race window.
pub struct VarDiffEngine<C: Clock> {
    clock: C,

    // Config
    target_submission_per_second: f64,
    min_difficulty: f64,

    // Cache state
    submission_cache_start_ms: u64,
    submission_cache: VecDeque<Submission>,

    // Lifetime accepted difficulty-work (sum of every accepted share's
    // credited difficulty since engine creation). Divided by the elapsed
    // time since `submission_cache_start_ms` it yields a stable, long-
    // window rate estimate for the under-sampled bootstrap retarget —
    // the one signal an ultra-sparse miner (never 2 shares in a slot)
    // actually provides. Grows unbounded but only ever read as a ratio.
    lifetime_difficulty_sum: f64,

    // Hashrate state
    hash_rate: f64,
    // Observation span (ms) behind the last `hash_rate` computation.
    // Lets the silence-eased read extend the same window to *now* instead
    // of re-deriving it: decayed = work / (window + silence tail).
    hash_rate_window_ms: u64,
    current_slot: Option<u64>,
    previous_slot_time_ms: u64,
    current_slot_time_ms: u64,
    previous_shares: f64,
    shares: f64,

    // Silence easing (opt-in; see the module doc). `last_submission_ms`
    // is the liveness sensor: stamped by every accepted share
    // (`update_hash_rate`) AND every rejected one (`note_submission`),
    // because the question it answers is "have we heard from this miner
    // at all" — a rejecting miner is alive, just unlucky or stale.
    silence_easing: bool,
    last_submission_ms: Option<u64>,

    // No-share descent (same opt-in switch). Evidence that a session which
    // has NEVER landed a share is over-assigned is the waiting itself, and
    // the sufficient statistic for "zero arrivals under a difficulty that
    // changed along the way" is the inverse-difficulty-time
    // `S = ∫dt/D(t)`. `no_share_accum_s_per_diff` holds S over the closed
    // segments; the still-open one is added at read time.
    //
    // The open segment is measured against `no_share_segment_difficulty`,
    // NOT against the `client_difficulty` the caller passes. That is
    // deliberate: if a difficulty assignment ever fails to call
    // `note_difficulty_assigned`, the stored value is stale-HIGH, S grows
    // too slowly and the engine descends too LITTLE. A missed wiring site
    // costs responsiveness, never safety.
    no_share_accum_s_per_diff: f64,
    no_share_segment_start_ms: u64,
    no_share_segment_difficulty: f64,
    // Difficulty the session opened with — the anchor the descent floor is
    // expressed against. 0.0 until the first assignment is known.
    opening_difficulty: f64,
    // Whether the last assignment raised the difficulty. Lets the up-step
    // cap charge a proving interval ONCE instead of once per 8×.
    last_assignment_was_a_raise: bool,
    // Denominator anchor for the under-sampled bootstrap. Starts at
    // `submission_cache_start_ms` and may only move while
    // `lifetime_difficulty_sum == 0`, so numerator and denominator always
    // span the same stretch of time. See `note_difficulty_assigned`.
    bootstrap_epoch_ms: u64,
}

impl<C: Clock> VarDiffEngine<C> {
    /// Construct with a clock + per-port config. `target_shares_per_minute`
    /// ≤ 0 falls back to [`VARDIFF_DEFAULT_TARGET_SHARES_PER_MIN`]; a
    /// non-finite / non-positive `min_difficulty` falls back to
    /// [`VARDIFF_DEFAULT_MIN_DIFFICULTY`].
    pub fn new(clock: C, target_shares_per_minute: f64, min_difficulty: f64) -> Self {
        let target = if target_shares_per_minute > 0.0 && target_shares_per_minute.is_finite() {
            target_shares_per_minute
        } else {
            VARDIFF_DEFAULT_TARGET_SHARES_PER_MIN
        };
        let min_difficulty = if min_difficulty.is_finite() && min_difficulty > 0.0 {
            min_difficulty
        } else {
            VARDIFF_DEFAULT_MIN_DIFFICULTY
        };
        let now = clock.now_ms();
        Self {
            clock,
            target_submission_per_second: 60.0 / target,
            min_difficulty,
            submission_cache_start_ms: now,
            submission_cache: VecDeque::with_capacity(VARDIFF_CACHE_SIZE + 1),
            lifetime_difficulty_sum: 0.0,
            hash_rate: 0.0,
            hash_rate_window_ms: 0,
            current_slot: None,
            previous_slot_time_ms: 0,
            current_slot_time_ms: 0,
            previous_shares: 0.0,
            shares: 0.0,
            silence_easing: false,
            last_submission_ms: None,
            no_share_accum_s_per_diff: 0.0,
            no_share_segment_start_ms: now,
            no_share_segment_difficulty: 0.0,
            opening_difficulty: 0.0,
            last_assignment_was_a_raise: false,
            bootstrap_epoch_ms: now,
        }
    }

    /// Enable/disable silence easing (module doc, "Silence easing").
    /// Builder-style so the many existing construction sites stay
    /// untouched and keep proving that the default (off) is inert.
    pub fn with_silence_easing(mut self, enabled: bool) -> Self {
        self.silence_easing = enabled;
        self
    }

    /// Seed the difficulty the session opens with. Builder-style for the
    /// same reason as [`Self::with_silence_easing`], and required for the
    /// no-share descent to have anything to measure: without it the
    /// engine knows the miner is quiet but not what it is quiet *at*.
    pub fn with_initial_difficulty(mut self, difficulty: f64) -> Self {
        if difficulty.is_finite() && difficulty > 0.0 {
            self.opening_difficulty = difficulty;
            self.no_share_segment_difficulty = difficulty;
        }
        self
    }

    /// Tell the engine a difficulty was assigned to the session — by any
    /// route: a vardiff retarget it suggested itself, an `UpdateChannel`
    /// from a proxy, an SV1 `mining.suggest_difficulty`.
    ///
    /// Closes the open no-share segment into the accumulator **at the
    /// difficulty that was actually in force for it**, then opens a new
    /// one. Also advances the bootstrap denominator anchor, but only while
    /// no share has ever been accepted: work done at a difficulty too high
    /// to produce shares is invisible, yet its elapsed time would still
    /// land in that denominator and drag the first post-descent estimate
    /// far below the truth. Moving the anchor keeps
    /// `lifetime_difficulty_sum` and the span it is divided by covering
    /// the same stretch of time — an invariant that holds because the sum
    /// is exactly 0 whenever the anchor moves.
    ///
    /// No-op when easing is off, like [`Self::note_submission`].
    pub fn note_difficulty_assigned(&mut self, difficulty: f64) {
        if !self.silence_easing {
            return;
        }
        let now = self.clock.now_ms();
        self.close_no_share_segment(now);
        if difficulty.is_finite() && difficulty > 0.0 {
            self.last_assignment_was_a_raise = self.no_share_segment_difficulty > 0.0
                && difficulty > self.no_share_segment_difficulty;
            self.no_share_segment_difficulty = difficulty;
            // The descent floor is measured against the HIGHEST difficulty
            // this session has ever carried, not the one it opened with.
            // Latching it at construction let a later raise (an SV1
            // `mining.suggest_difficulty`, a proxy revising its declared
            // rate) leave the floor stranded far below what is actually in
            // force — a session started at 16384 and raised to 500000 could
            // then be walked down to 64, roughly 7800× rather than the 256×
            // the constant promises. A lowering must NOT move it, or the
            // floor would ratchet down with every descent step and stop
            // bounding anything at all.
            self.opening_difficulty = self.opening_difficulty.max(difficulty);
        }
        if self.lifetime_difficulty_sum == 0.0 {
            self.bootstrap_epoch_ms = now;
        }
    }

    /// Fold the open segment into `S` and restart it at `now`. A segment
    /// with no known difficulty carries no evidence and is dropped.
    fn close_no_share_segment(&mut self, now: u64) {
        let span_ms = now.saturating_sub(self.no_share_segment_start_ms);
        if self.no_share_segment_difficulty > 0.0 && span_ms > 0 {
            self.no_share_accum_s_per_diff +=
                (span_ms as f64 / 1000.0) / self.no_share_segment_difficulty;
        }
        self.no_share_segment_start_ms = now;
    }

    /// Floor a no-share estimate at
    /// [`VARDIFF_NO_SHARE_MAX_DESCENT_FACTOR`] below the highest difficulty
    /// this session has ever been assigned. A LOWER bound, so the
    /// power-of-two round-up that follows cannot violate it.
    fn descent_floor(&self, raw: f64) -> f64 {
        if self.opening_difficulty > 0.0 {
            raw.max(self.opening_difficulty / VARDIFF_NO_SHARE_MAX_DESCENT_FACTOR)
        } else {
            raw
        }
    }

    /// `S` including the still-open segment, as of `now`.
    fn no_share_inverse_difficulty_time(&self, now: u64) -> f64 {
        let span_ms = now.saturating_sub(self.no_share_segment_start_ms);
        if self.no_share_segment_difficulty > 0.0 && span_ms > 0 {
            self.no_share_accum_s_per_diff
                + (span_ms as f64 / 1000.0) / self.no_share_segment_difficulty
        } else {
            self.no_share_accum_s_per_diff
        }
    }

    /// Liveness heartbeat for submissions that do NOT reach
    /// [`Self::update_hash_rate`] — i.e. rejected shares. A miner whose
    /// submissions are being rejected (duplicates against an exhausted
    /// search space, stale/aged-out jobs) is hashing, not silent; stamping
    /// it here keeps silence easing from misreading a reject storm as a
    /// dead session and walking its difficulty down. No-op when easing is
    /// off: `last_submission_ms` is read only by the silence paths, so the
    /// default path skips even the clock read.
    /// Liveness ONLY. It deliberately does not touch the no-share
    /// descent's evidence, because "we heard something" and "the miner
    /// reached the target we set" are different claims and only the
    /// second one refutes the descent's premise. Use
    /// [`Self::note_target_reached`] for the second.
    pub fn note_submission(&mut self) {
        if self.silence_easing {
            self.last_submission_ms = Some(self.clock.now_ms());
        }
    }

    /// A submission that demonstrably MET the assigned target: an accepted
    /// share, or a reject whose reason implies the work was good enough
    /// (duplicate, stale, unknown job). Stamps liveness AND spends the
    /// no-share evidence, because the miner has just proven it can reach
    /// the difficulty in force.
    ///
    /// A below-target reject (`DifficultyTooLow` / `LowDifficulty`) must
    /// NOT come through here. It is the miner telling us the opposite —
    /// that it is hashing but cannot clear the bar — which is the exact
    /// symptom the descent exists to correct. Spending the evidence on it
    /// pins `S` to the gap between two rejects and the difficulty never
    /// falls, so the feature would miss precisely the sessions it was
    /// built for.
    pub fn note_target_reached(&mut self) {
        if self.silence_easing {
            let now = self.clock.now_ms();
            self.last_submission_ms = Some(now);
            self.no_share_accum_s_per_diff = 0.0;
            self.no_share_segment_start_ms = now;
        }
    }

    /// Milliseconds of TRUE silence: time since the last submission of
    /// any kind (accepted or rejected). 0 while submissions are flowing
    /// — and 0 before the first submission ever, because a session that
    /// has not managed a single share yet provides no rate evidence to
    /// decay (the operator-set initial difficulty is out of scope here;
    /// the under-sampled bootstrap handles that regime).
    fn true_silence_tail_ms(&self) -> u64 {
        match self.last_submission_ms {
            Some(t) => self.clock.now_ms().saturating_sub(t),
            None => 0,
        }
    }

    /// Latest computed hashrate in hashes/second. Initially `0.0`; rises
    /// as shares accumulate within the current 10-minute slot.
    pub fn hash_rate(&self) -> f64 {
        self.hash_rate
    }

    /// Whether this session has ever had a share ACCEPTED.
    pub fn has_accepted_share(&self) -> bool {
        self.lifetime_difficulty_sum > 0.0
    }

    /// The highest difficulty the accumulated SILENCE is consistent with,
    /// or `None` when there is no such evidence (easing off, a share
    /// already accepted, still in warmup, nothing accumulated yet).
    ///
    /// This is the same Poisson bound the descent uses, minus the
    /// "must be a strict decrease" rule, and it exists so a caller can
    /// weigh a *declared* hashrate against what we have actually observed.
    ///
    /// The distinction matters: "this channel has never had a share
    /// accepted" is the NORMAL state of a proxy that just opened its
    /// channel and is only now gaining workers. Refusing its declaration
    /// on that basis throws away the one piece of information we have.
    /// Refusing it because a long silence at a known difficulty rules the
    /// number out is a different claim, and the only defensible one.
    pub fn silence_implied_max_difficulty(&self) -> Option<f64> {
        if !self.silence_easing || self.has_accepted_share() {
            return None;
        }
        let now = self.clock.now_ms();
        if now.saturating_sub(self.submission_cache_start_ms) <= VARDIFF_WARMUP_MS {
            return None;
        }
        let s = self.no_share_inverse_difficulty_time(now);
        if !s.is_finite() || s <= 0.0 {
            return None;
        }
        let raw = VARDIFF_NO_SHARE_CONFIDENCE_K * self.target_submission_per_second / s;
        if !raw.is_finite() {
            return None;
        }
        Some(self.descent_floor(raw))
    }

    /// Submission cache size — exposed for tests + diagnostics.
    pub fn cache_len(&self) -> usize {
        self.submission_cache.len()
    }

    /// `shares` accumulator for the current time slot — exposed for tests.
    /// Production callers should use [`hash_rate`] instead.
    pub fn current_shares(&self) -> f64 {
        self.shares
    }

    /// Record an accepted share. `target_difficulty` is the difficulty
    /// the share was actually credited at (post-clamp). `is_current_diff`
    /// MUST be `false` if the clamp moved the credit from the session's
    /// current diff to its OLD diff; this gates the submission-cache write
    /// so the retarget math stays clean.
    pub fn update_hash_rate(&mut self, target_difficulty: f64, is_current_diff: bool) {
        let now = self.clock.now_ms();
        let slot = slot_for(now);

        // Liveness sensor: an accepted share is a submission. Gated like
        // `note_submission` so the default (easing-off) path leaves the
        // field — which nothing else reads — untouched.
        //
        // An accepted share is also the strongest possible proof that the
        // miner reaches the assigned target, so it spends the no-share
        // evidence too. Folded in here rather than left to a second
        // `note_target_reached()` call at the caller: `now` is already in
        // hand, so this costs nothing, whereas the separate call added a
        // second clock read per accepted share on the hot path — and an
        // accepted share can no longer forget to do it.
        if self.silence_easing {
            self.last_submission_ms = Some(now);
            self.no_share_accum_s_per_diff = 0.0;
            self.no_share_segment_start_ms = now;
        }

        // Lifetime diff-work accumulator: every accepted share counts
        // (like the slot hashrate accumulator, incl. clamped stale-diff
        // shares — they are real work). Feeds the under-sampled bootstrap
        // rate estimate in `suggested_difficulty`.
        self.lifetime_difficulty_sum += target_difficulty;

        if is_current_diff {
            self.update_submission_cache(now, target_difficulty);
        }

        match self.current_slot {
            None => {
                // First share: pin the slot baseline.
                self.previous_slot_time_ms = now;
                self.current_slot_time_ms = now;
                self.current_slot = Some(slot);
                self.shares = target_difficulty;
            }
            Some(s) if s != slot => {
                // Crossing a slot boundary: rotate prev ← current,
                // restart current.
                self.previous_shares = self.shares;
                self.previous_slot_time_ms = self.current_slot_time_ms;
                self.current_slot_time_ms = now;
                self.current_slot = Some(slot);
                self.shares = target_difficulty;
                // Silence easing: recompute the rate across the gap. The
                // rotation branch historically left `hash_rate` frozen at
                // its pre-gap value, so the FIRST share after a long
                // silence would quote the pre-silence rate and ratchet a
                // just-eased session straight back up (the v1 sawtooth).
                // Recomputing over the real elapsed span replaces the
                // stale measurement with an honest one that includes the
                // gap. Gated so the default stays byte-identical.
                if self.silence_easing {
                    let elapsed_ms = now.saturating_sub(self.previous_slot_time_ms);
                    let work = self.previous_shares + self.shares;
                    if elapsed_ms > 0 && work > 0.0 {
                        self.hash_rate = slot_hashrate(work, elapsed_ms);
                        self.hash_rate_window_ms = elapsed_ms;
                    }
                }
            }
            Some(_) => {
                // Same slot: accumulate.
                self.shares += target_difficulty;
                if self.shares > 0.0 {
                    let elapsed_ms = now.saturating_sub(self.previous_slot_time_ms);
                    if elapsed_ms > 0 {
                        self.hash_rate =
                            slot_hashrate(self.previous_shares + self.shares, elapsed_ms);
                        self.hash_rate_window_ms = elapsed_ms;
                    }
                }
            }
        }
    }

    fn update_submission_cache(&mut self, now: u64, difficulty: f64) {
        // Drop entries older than the sliding window via `front()` peek.
        while let Some(front) = self.submission_cache.front() {
            if now.saturating_sub(front.time_ms) > VARDIFF_CACHE_WINDOW_MS {
                self.submission_cache.pop_front();
            } else {
                break;
            }
        }
        // Cap by size.
        if self.submission_cache.len() >= VARDIFF_CACHE_SIZE {
            self.submission_cache.pop_front();
        }
        self.submission_cache.push_back(Submission {
            time_ms: now,
            difficulty,
        });
    }

    /// Compute the suggested next session difficulty given the miner's
    /// current diff. Returns:
    ///
    /// - `None` — no retarget recommended (still in warmup, or under-sampled
    ///   with no accepted share at all yet, or samples present but inside the
    ///   2× clamp).
    /// - `Some(diff)` — a freshly-rounded power-of-2 target. Always
    ///   ≥ [`min_difficulty`]; never NaN / Infinity.
    ///
    /// Both branches funnel through `nearest_difficulty_step` (which floors
    /// at `min_difficulty`).
    pub fn suggested_difficulty(&self, client_difficulty: f64) -> Option<f64> {
        if self.submission_cache.len() < VARDIFF_SAMPLE_THRESHOLD {
            // Under-sampled: hold during warmup, then retarget from the miner's
            // MEASURED rate. The earlier heuristic divided the *current* diff by
            // `target_shares_per_minute` on every call — a value independent of
            // the actual rate — so a miner that stayed under-sampled (one device
            // per channel after the per-channel vardiff split sees only its own
            // ~⅓ of the shares) compounded it down geometrically into a runaway
            // to the floor. Both rate sources below feed the SAME
            // rate→difficulty conversion the fully-sampled path uses, so they
            // converge to the miner's real equilibrium in one step and do NOT
            // depend on `client_difficulty` — repeated calls can't compound.
            let now = self.clock.now_ms();
            if now.saturating_sub(self.submission_cache_start_ms) <= VARDIFF_WARMUP_MS {
                return None;
            }
            // Prefer the slot-measured hashrate (needs ≥2 shares in one slot);
            // else bootstrap from lifetime diff-work over elapsed time. The
            // latter is the only signal an ultra-sparse miner provides — a
            // 50 kH/s device that takes hours to land one share at a too-high
            // diff never gets 2-in-a-slot, so without this its diff is never
            // lowered and it stays stuck (cpuminer-fallback devices land here).
            // Anchored to cumulative accepted difficulty + the fixed engine-
            // start time, so it estimates the true rate (incl. the time-to-
            // first-share, which itself encodes the hashrate) and can't compound.
            let rate = if self.hash_rate > 0.0 {
                if self.silence_easing {
                    // Frozen `hash_rate` was the sawtooth's fuel: it is only
                    // recomputed when a share arrives, so after a silence it
                    // still quotes the pre-slowdown rate and would ratchet a
                    // just-rescued session straight back up. The decayed read
                    // extends the same measurement window to *now*.
                    self.silence_decayed_slot_rate()
                } else {
                    self.hash_rate
                }
            } else if self.lifetime_difficulty_sum > 0.0 {
                // Anchored at `bootstrap_epoch_ms`, which equals
                // `submission_cache_start_ms` unless the no-share descent
                // moved it. It has to: a stretch spent at a difficulty too
                // high to produce shares contributes elapsed time but no
                // observable work, so leaving it in this denominator makes
                // the first share after a descent read far slower than the
                // miner is — and pushes the difficulty down again.
                let elapsed_ms = now.saturating_sub(self.bootstrap_epoch_ms);
                // The warmup gate above is anchored at engine start, so
                // once the epoch moves it no longer says anything about
                // THIS window — and this branch has no up-step cap. An
                // assignment landing shortly before a tick left a window of
                // milliseconds, and one share divided by it read as a 32–64×
                // hashrate increase, uncapped, straight onto the wire. Hold
                // until the anchored window is itself long enough to carry a
                // rate. The epoch is frozen by the first accepted share, so
                // this waits at most one warmup and then never again.
                if elapsed_ms <= VARDIFF_WARMUP_MS {
                    return None;
                }
                let elapsed_s = elapsed_ms as f64 / 1000.0;
                self.lifetime_difficulty_sum * VARDIFF_DIFFICULTY_1 / elapsed_s
            } else if self.silence_easing {
                // No accepted share, ever. The classic estimators are blind
                // here — their only sensor is a share — so an over-assigned
                // session (a proxy that lost most of its workers, a device
                // weaker than the `nominal_hash_rate` it declared) sits at a
                // difficulty it cannot reach and nothing lowers it. That is
                // the gap this closes: the easing that would
                // help is gated behind the very share the too-high
                // difficulty is suppressing.
                //
                // The waiting IS the measurement. Shares are Poisson at
                // `λ = H / (D·2^32)`, so zero arrivals while the difficulty
                // followed `D(t)` has probability `e^-((H/2^32)·S)` for
                // `S = ∫dt/D(t)`. Inverting at confidence α leaves
                // `H ≤ k·2^32/S`, and converting that upper bound to the
                // difficulty which would hit the configured share rate
                // collapses to `D = k·τ/S` — `τ` being the target gap,
                // which `target_submission_per_second` already holds.
                //
                // Self-calibrating, and that is the point: the proposal only
                // falls below the current difficulty once the silence has
                // run past ~k expected share gaps. A port targeting 0.6
                // shares/min is untouched by 60 s of quiet; one targeting 15
                // is not. A fixed per-cycle divisor cannot tell those apart.
                return self.no_share_descent(now, client_difficulty);
            } else {
                // Easing off: no accepted share means nothing to estimate
                // from, so hold (pre-descent behaviour, kept byte-identical).
                return None;
            };
            // NO up-step cap here. The under-sampled path is client-
            // independent and documented to converge in ONE step (a fast
            // miner starting at too-low difficulty jumps straight to
            // equilibrium; it cannot compound). Capping it to 8× would
            // throttle that legitimate convergence to several intervals of
            // flooding. The cap guards the windowed path, where eased-
            // recovery overshoot and burst-inflated windows actually live.
            let target = rate * self.target_submission_per_second / VARDIFF_DIFFICULTY_1;
            if !target.is_finite() {
                return None;
            }
            return self.nearest_difficulty_step(target);
        }

        let sum: f64 = self.submission_cache.iter().map(|s| s.difficulty).sum();
        let first_t = self.submission_cache.front().expect("≥ threshold").time_ms;
        let last_t = self.submission_cache.back().expect("≥ threshold").time_ms;
        let closed_ms = last_t.saturating_sub(first_t);
        // Open interval (silence easing): the observation window ends at
        // *now*, not at the last share — elapsed time with zero arrivals is
        // evidence, so a quiet stretch lowers the estimate along a 1/T
        // envelope and the ordinary deadband+step below turn that into a
        // paced descent (~one halving per doubling of the silence). The tail
        // counts only TRUE silence: it starts at the last submission of any
        // kind, so a reject storm holds the estimate frozen (classic
        // behaviour) instead of easing a miner that is hashing against a
        // stale job. In steady state the tail is ~one inter-share gap
        // (~3% of the window) — deep inside the deadband.
        //
        // Gated on `closed_ms > 0`: a window whose shares all share one
        // millisecond (a drained JDC burst) carries no measurable rate —
        // dividing by a zero span is meaningless and the descent floor
        // below has no pre-silence rate to bound against. So we do NOT ease
        // from a zero-span window; `total_ms` stays 0 and the guard below
        // returns `None` (hold the difficulty) rather than letting an
        // unbounded 1/T decay sink it to the floor. Easing resumes as soon
        // as a later share gives the window a real span.
        let total_ms = if self.silence_easing && closed_ms > 0 {
            closed_ms.saturating_add(self.true_silence_tail_ms())
        } else {
            closed_ms
        };
        let diff_seconds = total_ms as f64 / 1000.0;
        if diff_seconds <= 0.0 {
            return None;
        }

        let mut difficulty_per_second = sum / diff_seconds;
        // Bounded descent: silence may argue the rate at most 16× below the
        // closed-window (pre-silence) measurement. No stored anchor — the
        // closed window IS the pre-silence rate, so the bound can never go
        // stale when the difficulty changes through a non-share route
        // (suggest_difficulty, UpdateChannel). `closed_ms > 0` is guaranteed
        // here: if it were 0 the block above would have returned `None`.
        if self.silence_easing {
            debug_assert!(closed_ms > 0, "eased with a zero-span window");
            let pre_silence_rate = sum / (closed_ms as f64 / 1000.0);
            difficulty_per_second = floor_descent(difficulty_per_second, pre_silence_rate);
        }
        let target_difficulty = self.cap_up_step(
            difficulty_per_second * self.target_submission_per_second,
            client_difficulty,
        );
        if !difficulty_per_second.is_finite() || !target_difficulty.is_finite() {
            return None;
        }

        // 2× clamp: only retarget if the observed rate is meaningfully
        // off from the configured target.
        if client_difficulty * 2.0 < target_difficulty
            || client_difficulty / 2.0 > target_difficulty
        {
            return self.nearest_difficulty_step(target_difficulty);
        }
        None
    }

    /// The no-share descent: `D = k·τ/S`, the difficulty implied by the
    /// Poisson upper confidence bound on a hashrate that has produced no
    /// share at all. Derivation in [`VARDIFF_NO_SHARE_CONFIDENCE_K`].
    ///
    /// Because `S` grows by `Δt/D` each cycle and `D` is set to `k·τ/S`,
    /// one cycle multiplies `S` by `(1 + Δt/(k·τ))` — a CONSTANT geometric
    /// descent per cycle, independent of how deep it already is. It is
    /// also independent of the check interval: evidence accumulates across
    /// ticks, so halving `difficulty_check_interval_ms` halves the step
    /// instead of stalling the descent.
    ///
    /// Two bounds, both LOWER bounds, which is what makes them survive
    /// `nearest_difficulty_step` rounding UP afterwards (rounding up cannot
    /// break a floor — the mistake that cost this branch its `cap_up_step`
    /// guarantee once already):
    /// - [`VARDIFF_NO_SHARE_MAX_DESCENT_FACTOR`] below the opening
    ///   difficulty, applied before the rounding;
    /// - `min_difficulty`, applied inside `nearest_difficulty_step`.
    ///
    /// And one invariant: **zero arrivals can never justify raising a
    /// difficulty**, so a candidate that is not a strict decrease is
    /// dropped. That also disposes of the ladder's one real hazard here —
    /// a raw estimate that rounds back up onto the rung already in force
    /// proposes nothing, and since `S` keeps growing, a later cycle
    /// crosses. The descent paces itself rather than stalling.
    fn no_share_descent(&self, now: u64, client_difficulty: f64) -> Option<f64> {
        let s = self.no_share_inverse_difficulty_time(now);
        if !s.is_finite() || s <= 0.0 {
            // No segment with a known difficulty yet: the engine was never
            // told what the session is quiet AT, so there is nothing to
            // bound. Hold, exactly as before the descent existed.
            return None;
        }
        let raw = VARDIFF_NO_SHARE_CONFIDENCE_K * self.target_submission_per_second / s;
        if !raw.is_finite() {
            return None;
        }
        let candidate = self.nearest_difficulty_step(self.descent_floor(raw))?;
        if candidate < client_difficulty {
            Some(candidate)
        } else {
            None
        }
    }

    /// Slot hashrate with the observation window extended to *now*: the
    /// frozen `hash_rate` divided the accumulated work by the span up to
    /// the LAST share; this divides the same work by that span plus the
    /// true-silence tail. Identical to `hash_rate` while submissions flow
    /// (tail = 0, including during a reject storm), decays with silence,
    /// and is floored at the frozen measurement /
    /// [`VARDIFF_SILENCE_MAX_DESCENT_FACTOR`] like the windowed path.
    fn silence_decayed_slot_rate(&self) -> f64 {
        // The under-sampled path has no deadband — it proposes whenever
        // it runs — so an unguarded decay would let ordinary Poisson gaps
        // nudge the estimate and flap a healthy early session between
        // neighbouring steps. Decay therefore only engages once the tail
        // exceeds both the measurement window itself and five target
        // gaps (the same magnitude the windowed branch's deadband needs
        // before it can act): anything shorter reads as normal spacing
        // and returns the frozen measurement, byte-identical to easing
        // off.
        let tail_ms = self.true_silence_tail_ms();
        let gap_ms = (self.target_submission_per_second * 1000.0) as u64;
        let threshold_ms = self
            .hash_rate_window_ms
            .max(gap_ms.saturating_mul(VARDIFF_SAMPLE_THRESHOLD as u64));
        if tail_ms <= threshold_ms {
            return self.hash_rate;
        }
        // total_ms is > 0 here: the caller is inside `if self.hash_rate > 0.0`,
        // which only becomes true once a same-slot share sets a positive
        // `hash_rate_window_ms`.
        let total_ms = self.hash_rate_window_ms.saturating_add(tail_ms);
        let decayed = slot_hashrate(self.previous_shares + self.shares, total_ms);
        floor_descent(decayed, self.hash_rate)
    }

    /// Cap an upward retarget at [`VARDIFF_MAX_UP_STEP_FACTOR`] × the
    /// current difficulty. No-op when silence easing is disabled (the
    /// default stays byte-identical) or when `client_difficulty` is not a
    /// usable number.
    ///
    /// The cap is lowered to a power of two before it is applied, because
    /// [`Self::nearest_difficulty_step`] rounds UP afterwards: capping at a raw
    /// `8 × current` and then stepping to the next rung lands ABOVE the cap and
    /// the guarantee is gone (measured: cap 384, assigned 512). Snapping the cap
    /// down to a rung makes it survive the rounding, at the price of an
    /// effective ceiling between 4× and 8× rather than exactly 8×. A bound that
    /// holds loosely beats one that reads 8× and does not hold.
    fn cap_up_step(&self, target: f64, client_difficulty: f64) -> f64 {
        if !self.silence_easing {
            return target;
        }
        // The cap's documented purpose is to make an estimate that is wrong
        // by more than 8× spend ONE further interval proving itself — not
        // to ration every genuine increase at 8× per interval. Applied
        // blanket it did the latter: a channel whose real rate jumps 128×
        // (a rental proxy attaching a farm) walked 512 → 4096 → 32768 →
        // 262144, three intervals of flooding at up to 128× the target rate
        // — 12 minutes with the shipped 240 s interval.
        //
        // So the cap applies to the FIRST raise only. Once a raise has been
        // assigned and the next window still argues for more, the rate has
        // survived a full interval of fresh shares and has proven exactly
        // what the cap asked it to prove.
        if self.last_assignment_was_a_raise {
            return target;
        }
        let cap = client_difficulty * VARDIFF_MAX_UP_STEP_FACTOR;
        if cap.is_finite() && cap > 0.0 {
            // Largest rung not exceeding the cap; `nearest_difficulty_step`
            // leaves an exact power of two alone, so the result stays capped.
            let capped_rung = 2_f64.powf(cap.log2().floor());
            target.min(capped_rung)
        } else {
            target
        }
    }

    /// Round UP to a power of two. Floors at [`min_difficulty`].
    /// Returns `None` for `val == 0`, guarding against `log2(0) = -Infinity`.
    ///
    /// **Powers of two only, and always upward.** Both halves were measured on
    /// a live translating proxy, and each half fixes a different failure:
    ///
    /// - *Powers of two:* the ladder used to carry a `lower * 1.5` rung. The SRI
    ///   translator rounds an assigned difficulty UP to a power of two when it
    ///   lowers it into an SV1 `mining.set_difficulty`, so a rung like 3072
    ///   reached the miner as 4096 while the pool kept booking shares at 3072 —
    ///   29.5 % of a miner's work went uncredited.
    /// - *Upward:* rounding to the NEAREST rung goes down as often as up, and a
    ///   downstream that requested a difficulty via `UpdateChannel` rejects a
    ///   lower one as a protocol error — the translator logs "SetTarget response
    ///   has target which is higher than requested target … Ignoring this
    ///   pending update" and the miner simply keeps its old difficulty. Rounding
    ///   down therefore does not mis-size the target, it discards the
    ///   assignment. Up is always accepted.
    ///
    /// The cost of rounding up is at most a factor of two in share rate, which
    /// the estimator absorbs; the cost of the other two is real work nobody is
    /// paid for.
    fn nearest_difficulty_step(&self, val: f64) -> Option<f64> {
        if val == 0.0 {
            return None;
        }
        if val < self.min_difficulty {
            return Some(self.min_difficulty);
        }
        let lower = 2_f64.powf(val.log2().floor());
        // The tolerance matters: a value that is a power of two apart from
        // floating-point dust (0.5 arriving as 0.500000000001) must stay on its
        // rung, not double. Only a genuine gap rounds up.
        if val <= lower * (1.0 + 1e-9) {
            Some(lower)
        } else {
            Some(lower * 2.0)
        }
    }
}

/// 10-min slots labeled by their END timestamp. Same formula bp-stats uses
/// for its `SlotEnd::for_time` — we don't take a dep here, the engine only
/// cares about slot equality.
fn slot_for(timestamp_ms: u64) -> u64 {
    (timestamp_ms / VARDIFF_SLOT_DURATION_MS) * VARDIFF_SLOT_DURATION_MS + VARDIFF_SLOT_DURATION_MS
}

/// Slot hashrate in hashes/second: total credited difficulty (`work`, in
/// difficulty units) over the observation span. The single definition
/// behind the frozen same-slot / rotation reads and the silence-decayed
/// read. Returns 0.0 for a non-positive span.
fn slot_hashrate(work: f64, span_ms: u64) -> f64 {
    if span_ms == 0 {
        return 0.0;
    }
    work * VARDIFF_DIFFICULTY_1 / (span_ms as f64 / 1000.0)
}

/// Silence-easing descent floor: never let `value` fall more than
/// [`VARDIFF_SILENCE_MAX_DESCENT_FACTOR`] below `base` (the pre-silence
/// measurement). One definition for both the windowed rate and the
/// slot-rate paths so they cannot drift.
fn floor_descent(value: f64, base: f64) -> f64 {
    value.max(base / VARDIFF_SILENCE_MAX_DESCENT_FACTOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── effective_job_difficulty (5 spec cases) ──────────────────────────

    #[test]
    fn effective_diff_returns_current_when_no_ratchet_has_happened() {
        assert_eq!(
            effective_job_difficulty(Some(42), 100.0, 100.0, None),
            100.0
        );
    }

    #[test]
    fn effective_diff_clamps_for_jobs_issued_before_an_upward_ratchet() {
        // Ratchet from 100 → 200 at jobId 50. Job 49 = pre-ratchet → 100.
        assert_eq!(
            effective_job_difficulty(Some(49), 200.0, 100.0, Some(50)),
            100.0
        );
    }

    #[test]
    fn effective_diff_uses_current_at_or_after_boundary() {
        assert_eq!(
            effective_job_difficulty(Some(50), 200.0, 100.0, Some(50)),
            200.0
        );
        assert_eq!(
            effective_job_difficulty(Some(51), 200.0, 100.0, Some(50)),
            200.0
        );
    }

    #[test]
    fn effective_diff_also_clamps_on_downward_ratchet_symmetry() {
        // ckpool stratifier.c:6204-6205 — both directions use MIN.
        // MIN(100, 200) = 100 — share at 150 on an old job accepts.
        assert_eq!(
            effective_job_difficulty(Some(49), 100.0, 200.0, Some(50)),
            100.0
        );
    }

    #[test]
    fn effective_diff_falls_back_to_current_for_unparseable_job_id() {
        assert_eq!(
            effective_job_difficulty(None, 200.0, 100.0, Some(50)),
            200.0
        );
    }

    // ── nearest_difficulty_step ────────────────────────────────────────

    fn engine_with_clock(clock: TestClock, target: f64, min: f64) -> VarDiffEngine<TestClock> {
        VarDiffEngine::new(clock, target, min)
    }

    /// Every rung is a power of two, with nothing in between.
    ///
    /// The ladder used to carry a `lower * 1.5` rung. It was removed because a
    /// translating proxy rounds an assigned difficulty UP to a power of two on
    /// the way to the miner, so a 1.5x rung arrives as something the pool never
    /// assigned and every share booked against it under-counts the miner's work.
    #[test]
    fn nearest_step_returns_only_powers_of_two() {
        let e = engine_with_clock(TestClock::new(0), 6.0, 0.00001);
        // Exact powers of two are returned unchanged.
        assert_eq!(e.nearest_difficulty_step(1024.0), Some(1024.0));
        assert_eq!(e.nearest_difficulty_step(2048.0), Some(2048.0));
        // The old 1.5x rung is gone, and rounding is always UP: a downstream
        // that requested a difficulty discards a lower one as a protocol error,
        // so the assignment would be lost rather than merely mis-sized.
        assert_eq!(e.nearest_difficulty_step(1536.0), Some(2048.0));
        assert_eq!(e.nearest_difficulty_step(1100.0), Some(2048.0));
        assert_eq!(e.nearest_difficulty_step(2000.0), Some(2048.0));

        // Every rung is a power of two, and never below what was asked for.
        for probe in [3.0, 100.0, 950.3, 2887.8, 5000.0, 1e6] {
            let step = e.nearest_difficulty_step(probe).expect("a rung");
            assert_eq!(
                step,
                2_f64.powf(step.log2().round()),
                "step {step} for {probe} is not a power of two"
            );
            assert!(step >= probe, "step {step} is below the requested {probe}");
            assert!(step < probe * 2.0, "step {step} overshoots {probe}");
        }
    }

    #[test]
    fn nearest_step_zero_returns_none() {
        let e = engine_with_clock(TestClock::new(0), 6.0, 0.00001);
        assert_eq!(e.nearest_difficulty_step(0.0), None);
    }

    #[test]
    fn nearest_step_below_min_returns_min() {
        let e = engine_with_clock(TestClock::new(0), 6.0, 500.0);
        assert_eq!(e.nearest_difficulty_step(0.1), Some(500.0));
        assert_eq!(e.nearest_difficulty_step(499.9), Some(500.0));
    }

    // ── construction validates target + min ───────────────────────────

    #[test]
    fn invalid_target_shares_per_minute_falls_back_to_default() {
        // Default 6 shares/min → target_submission_per_second = 60/6 = 10.
        let e1 = VarDiffEngine::new(TestClock::new(0), 0.0, 0.00001);
        assert_eq!(e1.target_submission_per_second, 10.0);
        let e2 = VarDiffEngine::new(TestClock::new(0), -5.0, 0.00001);
        assert_eq!(e2.target_submission_per_second, 10.0);
        let e3 = VarDiffEngine::new(TestClock::new(0), f64::NAN, 0.00001);
        assert_eq!(e3.target_submission_per_second, 10.0);
    }

    #[test]
    fn invalid_min_difficulty_falls_back_to_default() {
        let e1 = VarDiffEngine::new(TestClock::new(0), 6.0, 0.0);
        assert_eq!(e1.min_difficulty, VARDIFF_DEFAULT_MIN_DIFFICULTY);
        let e2 = VarDiffEngine::new(TestClock::new(0), 6.0, f64::NAN);
        assert_eq!(e2.min_difficulty, VARDIFF_DEFAULT_MIN_DIFFICULTY);
        let e3 = VarDiffEngine::new(TestClock::new(0), 6.0, -1.0);
        assert_eq!(e3.min_difficulty, VARDIFF_DEFAULT_MIN_DIFFICULTY);
    }

    #[test]
    fn valid_min_difficulty_is_honored() {
        let e = VarDiffEngine::new(TestClock::new(0), 6.0, 500.0);
        assert_eq!(e.min_difficulty, 500.0);
    }

    // ── submission cache gating ───────────────────────────────────────

    #[test]
    fn current_diff_shares_enter_the_submission_cache() {
        let mut e = VarDiffEngine::new(TestClock::new(1_000), 6.0, 0.00001);
        e.update_hash_rate(1024.0, true);
        assert_eq!(e.cache_len(), 1);
    }

    #[test]
    fn stale_diff_shares_are_excluded_from_the_submission_cache() {
        let mut e = VarDiffEngine::new(TestClock::new(1_000), 6.0, 0.00001);
        e.update_hash_rate(256.0, false);
        e.update_hash_rate(256.0, false);
        e.update_hash_rate(256.0, false);
        assert_eq!(e.cache_len(), 0);
    }

    #[test]
    fn stale_diff_shares_still_update_live_hashrate_share_sum() {
        let mut e = VarDiffEngine::new(TestClock::new(1_000), 6.0, 0.00001);
        e.update_hash_rate(1024.0, true);
        let cache_before = e.cache_len();
        e.update_hash_rate(256.0, false);
        e.update_hash_rate(256.0, false);
        assert_eq!(e.cache_len(), cache_before, "no cache pollution");
        assert!(
            e.current_shares() > 1024.0,
            "hashrate share-sum must advance with stale-diff shares; got {}",
            e.current_shares()
        );
    }

    // ── submission cache capacity + sliding window ────────────────────

    #[test]
    fn cache_evicts_oldest_when_capacity_reached() {
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        // Push CACHE_SIZE + 5 entries, each 1s apart so the time window
        // doesn't drop any first.
        for _ in 0..(VARDIFF_CACHE_SIZE + 5) {
            e.update_hash_rate(1.0, true);
            clock.advance_ms(1_000);
        }
        assert_eq!(e.cache_len(), VARDIFF_CACHE_SIZE);
    }

    #[test]
    fn cache_drops_entries_older_than_window() {
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        // Three early shares.
        for _ in 0..3 {
            e.update_hash_rate(1.0, true);
            clock.advance_ms(1_000);
        }
        // Jump past the cache window (300s), then add one.
        clock.advance_ms(VARDIFF_CACHE_WINDOW_MS + 60_000);
        e.update_hash_rate(1.0, true);
        // Only the most recent entry remains; the three early ones were
        // dropped by the sliding-window check (their age > 300s).
        assert_eq!(e.cache_len(), 1);
    }

    // ── suggested_difficulty: warmup + fallback formula ───────────────

    #[test]
    fn under_sampled_within_warmup_returns_none() {
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        // 3 samples (< 5), still within warmup.
        for _ in 0..3 {
            e.update_hash_rate(1024.0, true);
            clock.advance_ms(5_000);
        }
        assert!(e.suggested_difficulty(16384.0).is_none());
    }

    #[test]
    fn under_sampled_past_warmup_with_no_share_at_all_waits() {
        let clock = TestClock::new(0);
        let e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        // Zero accepted shares: there is genuinely nothing to estimate a rate
        // from, so hold even past warmup (an operator-set initial diff a miner
        // can't clear even once is out of scope — it never submits any signal).
        clock.advance_ms(VARDIFF_WARMUP_MS + 1_000);
        assert!(e.suggested_difficulty(16384.0).is_none());
    }

    #[test]
    fn under_sampled_single_share_bootstraps_down_from_lifetime_rate() {
        // The finding: a miner that lands exactly ONE share never establishes a
        // slot hashrate (needs 2-in-a-slot), so pre-fix it returned None forever
        // and its diff was never lowered — an ultra-sparse device (NMMiner/CPU
        // on the cpuminer 0.1 fallback) stuck too high. The bootstrap estimates
        // the rate from cumulative accepted difficulty over elapsed time (the
        // time-to-first-share encodes the hashrate), so it retargets DOWN.
        let clock = TestClock::new(0);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001); // tsps = 10
        e.update_hash_rate(1024.0, true); // one share, diff 1024, at t=0
                                          // No 2nd share → slot hashrate stays 0 → bootstrap path.
        assert_eq!(e.hash_rate(), 0.0);
        clock.advance_ms(80_000); // elapsed 80s (> warmup 60s)
                                  // target = lifetime_sum * tsps / elapsed_s = 1024 * 10 / 80 = 128.
        let expected = 128.0;
        // Client-independent (proves it can't compound on repeated per-share
        // calls the way the old client_diff/target ratchet did).
        for client in [16384.0, 1024.0, 1.0, 0.001] {
            assert_eq!(
                e.suggested_difficulty(client),
                Some(expected),
                "single-share bootstrap must track the lifetime rate, not client={client}"
            );
        }
    }

    #[test]
    fn bootstrap_retarget_converges_and_does_not_runaway_to_floor() {
        // A steady ultra-sparse miner (one share per 700s, always in a distinct
        // 10-min slot so the slot hashrate never engages → pure bootstrap path).
        // Its per-share target must CONVERGE to the rate-derived equilibrium, not
        // keep shrinking toward the floor call-over-call (the old runaway).
        let clock = TestClock::new(0);
        let min_diff = 0.00001;
        let mut e = VarDiffEngine::new(&clock, 6.0, min_diff); // tsps = 10
        let mut post_share_targets = Vec::new();
        for _ in 0..8 {
            e.update_hash_rate(700.0, true);
            clock.advance_ms(700_000); // 700s → distinct slot each time
            assert_eq!(e.hash_rate(), 0.0, "must stay on the bootstrap path");
            if let Some(t) = e.suggested_difficulty(16384.0) {
                post_share_targets.push(t);
            }
        }
        // Equilibrium: lifetime_sum/elapsed → 700/700 = 1 diff/s → target = 10.
        // Every post-share target sits near that, far above the floor, and the
        // last two are within a small factor (converged, not geometrically
        // decaying).
        let last = *post_share_targets.last().unwrap();
        let prev = post_share_targets[post_share_targets.len() - 2];
        assert!(
            last > min_diff * 100.0,
            "must not sink to the floor: {last}"
        );
        assert!(
            (last / prev).abs() < 2.0 && (prev / last).abs() < 2.0,
            "successive targets must converge, not compound down: {prev} → {last}"
        );
    }

    #[test]
    fn under_sampled_past_warmup_retargets_from_measured_hashrate_not_current_diff() {
        // Regression: the old under-sampled fallback was `client_difficulty /
        // target_shares_per_minute`, applied on EVERY retarget call. A miner
        // that stayed under-sampled (one device per channel after the
        // per-channel vardiff split) had its diff divided by the constant each
        // share → a geometric runaway to the floor. The fix retargets from the
        // measured hashrate, independent of the current diff, so it converges
        // in one step and repeated calls cannot compound.
        let clock = TestClock::new(0);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001); // target/min => tsps = 10
                                                              // 2 shares at diff 1000, 20s apart → hashrate = 2000 * 2^32 / 20s.
                                                              // target = hashrate * tsps / 2^32 = (2000/20) * 10 = 1000 → step 1024.
        e.update_hash_rate(1000.0, true);
        clock.advance_ms(20_000);
        e.update_hash_rate(1000.0, true);
        // Still under-sampled (2 < 5 cache entries); jump past warmup.
        assert!(e.cache_len() < VARDIFF_SAMPLE_THRESHOLD);
        clock.advance_ms(VARDIFF_WARMUP_MS);

        let expected = 1024.0;
        // The result is derived from the measured rate, NOT the current diff:
        // wildly different `client_difficulty` inputs all yield the SAME target
        // — so calling it repeatedly (the per-share inline retarget) can never
        // ratchet the diff down step by step.
        for client in [16384.0, 1000.0, 1.0, 0.001] {
            assert_eq!(
                e.suggested_difficulty(client),
                Some(expected),
                "under-sampled retarget must track the hashrate, not client_difficulty={client}"
            );
        }
    }

    // ── suggested_difficulty: 2× clamp ────────────────────────────────

    fn populate_cache(
        e: &mut VarDiffEngine<&TestClock>,
        clock: &TestClock,
        count: usize,
        diff: f64,
    ) {
        for _ in 0..count {
            e.update_hash_rate(diff, true);
            clock.advance_ms(2_000);
        }
    }

    #[test]
    fn suggested_diff_is_none_when_observed_rate_inside_two_x_clamp() {
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        // 30 samples at diff=1024 over 60s → diff_per_sec = 30*1024/60 ≈ 512.
        // target_submission_per_second = 60/6 = 10s.
        // target = 512 * 10 = 5120. clientDiff*2=10240 > 5120 > clientDiff/2=2560 → no retarget.
        populate_cache(&mut e, &clock, 30, 1024.0);
        let suggested = e.suggested_difficulty(5120.0);
        // Inside the 2× window → None.
        assert!(
            suggested.is_none() || (suggested.unwrap() - 5120.0).abs() < 1e-6,
            "expected None (inside clamp) or exact 5120 step, got {:?}",
            suggested
        );
    }

    #[test]
    fn suggested_diff_returns_step_when_far_below_target() {
        // Run rate of 30 * 0.1 / 60s = 0.05/sec; target = 0.05*10 = 0.5.
        // clientDifficulty = 16384 — clientDifficulty/2 = 8192 ≫ 0.5 → retarget.
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        populate_cache(&mut e, &clock, 30, 0.1);
        let suggested = e.suggested_difficulty(16384.0).expect("must retarget");
        // The raw target sits between the 0.5 and 1.0 rungs, and the ladder
        // rounds UP — a downstream discards an assignment below what it asked
        // for, so landing on 0.5 would risk losing it entirely.
        assert_eq!(suggested, 1.0);
        // Still a huge retarget down from 16384 — that is the point of the test.
        assert!(suggested < 16384.0 / 2.0);
    }

    #[test]
    fn suggested_diff_respects_configured_floor() {
        // Same low rate but a 500.0 floor → suggestion clamps to 500.0.
        // Verifies the "respects configured floor" behavior.
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 500.0);
        populate_cache(&mut e, &clock, 30, 0.1);
        let suggested = e.suggested_difficulty(16384.0).expect("must retarget");
        assert!(suggested >= 500.0, "got {}", suggested);
        assert_eq!(suggested, 500.0);
    }

    #[test]
    fn suggested_diff_without_floor_can_drop_below_one() {
        // Without a configured floor the suggestion drops far below the 500
        // floor the sibling test sets — that is the property under test. (It
        // lands on 1.0 rather than 0.5 because the ladder rounds up.)
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        populate_cache(&mut e, &clock, 30, 0.1);
        let suggested = e.suggested_difficulty(16384.0).expect("must retarget");
        assert!(suggested < 500.0, "got {}", suggested);
    }

    #[test]
    fn suggested_diff_zero_floor_falls_back_to_default() {
        // A floor of 0 falls back to the built-in default.
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.0);
        populate_cache(&mut e, &clock, 30, 0.1);
        let suggested = e.suggested_difficulty(16384.0).expect("must retarget");
        assert!(suggested < 500.0, "got {}", suggested);
    }

    #[test]
    fn suggested_diff_nan_floor_falls_back_to_default() {
        // A non-finite floor is rejected and the built-in default is used.
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, f64::NAN);
        populate_cache(&mut e, &clock, 30, 0.1);
        let suggested = e.suggested_difficulty(16384.0).expect("must retarget");
        assert!(suggested < 500.0, "got {}", suggested);
    }

    // ── hashrate accumulation ─────────────────────────────────────────

    #[test]
    fn hash_rate_is_zero_before_any_share() {
        let e: VarDiffEngine<TestClock> = VarDiffEngine::new(TestClock::new(0), 6.0, 0.00001);
        assert_eq!(e.hash_rate(), 0.0);
    }

    #[test]
    fn first_share_initializes_slot_but_keeps_hash_rate_zero() {
        // The first share sets `shares` but the hashrate computation only
        // kicks in on the SAME-SLOT accumulation branch, so hash_rate stays
        // 0 until the second share arrives.
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        e.update_hash_rate(1024.0, true);
        assert_eq!(e.hash_rate(), 0.0);
        assert_eq!(e.current_shares(), 1024.0);
    }

    #[test]
    fn second_same_slot_share_computes_hashrate() {
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        e.update_hash_rate(1024.0, true);
        clock.advance_ms(1_000); // 1s later, same 10-min slot
        e.update_hash_rate(2048.0, true);
        // shares = 3072, prev = 0, elapsed = 1s.
        // hashrate = 3072 * 2^32 / 1 ≈ 1.32e13.
        let expected = 3072.0 * VARDIFF_DIFFICULTY_1 / 1.0;
        assert!(
            (e.hash_rate() - expected).abs() < 1.0,
            "expected ≈ {}, got {}",
            expected,
            e.hash_rate()
        );
    }

    #[test]
    fn crossing_slot_boundary_rotates_share_buckets() {
        let clock = TestClock::new(0);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        // Two shares in slot A.
        e.update_hash_rate(1024.0, true);
        clock.advance_ms(1_000);
        e.update_hash_rate(2048.0, true);
        assert_eq!(e.current_shares(), 3072.0);

        // Jump across a slot boundary (10 min).
        clock.advance_ms(VARDIFF_SLOT_DURATION_MS);
        e.update_hash_rate(512.0, true);
        // prev_shares = 3072 (from slot A), shares = 512 (slot B fresh).
        assert_eq!(e.current_shares(), 512.0);
    }

    // ── silence easing ────────────────────────────────────────────────
    //
    // Shared setup: 30 accepted shares at difficulty 1024, 10 s apart —
    // the exact equilibrium cadence for the default 6/min target. Window
    // sum 30 720 over a 290 s closed span implies a target of ~1059,
    // inside the 2× deadband of a 1024 session, so the share-driven math
    // alone never retargets. Anything a test observes after that is the
    // silence path.

    fn eased_engine(clock: &TestClock) -> VarDiffEngine<&TestClock> {
        VarDiffEngine::new(clock, 6.0, 0.00001).with_silence_easing(true)
    }

    fn fill_equilibrium(e: &mut VarDiffEngine<&TestClock>, clock: &TestClock) {
        for _ in 0..30 {
            e.update_hash_rate(1024.0, true);
            clock.advance_ms(10_000);
        }
    }

    #[test]
    fn easing_off_holds_through_any_silence() {
        // The historical freeze, pinned as the default: with the switch
        // off, an hour of total silence changes nothing.
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 0.00001);
        fill_equilibrium(&mut e, &clock);
        clock.advance_ms(3_600_000);
        assert_eq!(e.suggested_difficulty(1024.0), None);
    }

    #[test]
    fn silence_descends_monotonically_and_parks_at_the_bound() {
        // Healthy session goes fully silent. The estimate decays along
        // 1/T; the deadband turns that into paced ~2× steps; the descent
        // parks within [floor, 2×floor] of the 16× bound and stays.
        let clock = TestClock::new(1_000);
        let mut e = eased_engine(&clock);
        fill_equilibrium(&mut e, &clock);

        let mut client = 1024.0;
        let mut proposals = Vec::new();
        for i in 0..240 {
            clock.advance_ms(60_000);
            if let Some(next) = e.suggested_difficulty(client) {
                // Trigger boundary: the first proposal needs the total
                // window to double — i.e. > ~310 s of tail on the 290 s
                // closed span. Ordinary Poisson gaps never get close.
                assert!(i >= 5, "eased before the deadband allows it (check #{i})");
                assert!(next < client, "descent must be monotone: {client} → {next}");
                proposals.push(next);
                client = next;
            }
        }
        // Bound: pre-silence rate / 16 → target 66.2 → step 64. The
        // deadband may park the session up to one step above it.
        assert!(
            (64.0..=128.0).contains(&client),
            "must park within a step of the 16× bound, got {client}"
        );
        assert!(!proposals.is_empty(), "silence must have eased at all");
        // Parked means parked: another hour of silence proposes nothing.
        for _ in 0..60 {
            clock.advance_ms(60_000);
            assert_eq!(e.suggested_difficulty(client), None, "must stay parked");
        }
    }

    #[test]
    fn poisson_jitter_steady_state_is_unperturbed() {
        // THE safety property: a healthy miner with realistic (jittered)
        // share arrivals must see identical decisions with easing on and
        // off — including checks landing mid-gap and after unlucky long
        // gaps. Deterministic LCG, no wall clock.
        let clock = TestClock::new(0);
        let mut on = eased_engine(&clock);
        let mut off = VarDiffEngine::new(&clock, 6.0, 0.00001);
        let client = 1024.0;

        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut t_ms: u64 = 0;
        for i in 0..300u32 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let r = (seed >> 33) % 1000;
            // 2–18 s gaps around the 10 s mean, with a heavy 45 s tail
            // sprinkled in — the Poisson outliers a naive trigger would
            // mistake for silence.
            let gap_ms = if i % 37 == 0 { 45_000 } else { 2_000 + r * 16 };
            t_ms += gap_ms;
            clock.set_ms(t_ms);
            on.update_hash_rate(1024.0, true);
            off.update_hash_rate(1024.0, true);
            assert_eq!(
                on.suggested_difficulty(client),
                off.suggested_difficulty(client),
                "post-share decision diverged at share #{i}"
            );
            // Mid-gap check (timer tick between shares).
            clock.set_ms(t_ms + gap_ms / 2);
            assert_eq!(
                on.suggested_difficulty(client),
                off.suggested_difficulty(client),
                "mid-gap decision diverged after share #{i}"
            );
            clock.set_ms(t_ms);
        }
    }

    #[test]
    fn reject_storm_holds_the_difficulty() {
        // A miner whose submissions are all rejected (duplicate burst
        // against an exhausted search space) is hashing, not silent: the
        // heartbeat pins the tail at ~0 and the difficulty holds. Once
        // the rejects stop, TRUE silence resumes counting from the last
        // one and the descent begins.
        let clock = TestClock::new(1_000);
        let mut e = eased_engine(&clock);
        fill_equilibrium(&mut e, &clock);

        // 30 minutes of pure reject traffic: every 10 s a rejected share.
        for i in 0..180 {
            clock.advance_ms(10_000);
            e.note_submission();
            if i % 6 == 0 {
                assert_eq!(
                    e.suggested_difficulty(1024.0),
                    None,
                    "a rejecting miner must never be eased (t+{}s)",
                    (i + 1) * 10
                );
            }
        }
        // Rejects stop → the silence clock starts at the LAST reject.
        let mut first_some_after_s = None;
        for i in 1..=15 {
            clock.advance_ms(60_000);
            if let Some(d) = e.suggested_difficulty(1024.0) {
                assert!(d < 1024.0);
                first_some_after_s = Some(i * 60);
                break;
            }
        }
        let after = first_some_after_s.expect("easing must resume after the storm ends");
        assert!(
            after > 300,
            "descent must wait a full deadband past the last reject, resumed after {after}s"
        );
    }

    #[test]
    fn descent_bound_is_rate_based_not_anchor_based() {
        // The bound derives from the measured pre-silence rate, not from
        // a stored difficulty anchor — so a difficulty raised through a
        // non-share route mid-silence (UpdateChannel, suggest_difficulty)
        // cannot deepen the descent (the v1 stale-anchor finding).
        let clock = TestClock::new(1_000);
        let mut e = eased_engine(&clock);
        fill_equilibrium(&mut e, &clock);
        clock.advance_ms(48 * 3_600_000); // two days of silence

        // Floored estimate: (30720/290)/16 = 6.62 d/s → target 66.2.
        // From an externally-raised 65536 the proposal is still derived from
        // the rate, not from the raise — the ladder rounds 66.2 up to its rung.
        // The bound is a FLOOR, so rounding up cannot violate it; it only makes
        // the descent coarser than the raw 66.2.
        assert_eq!(e.suggested_difficulty(65_536.0), Some(128.0));
        // And from 100, the floored target (66.2) sits inside the
        // deadband — no proposal, no creep below the bound.
        assert_eq!(e.suggested_difficulty(100.0), None);
    }

    #[test]
    fn under_sampled_slot_rate_decays_with_silence() {
        // The frozen slot hashrate was the sawtooth's fuel in v1: it is
        // only recomputed on a share, so after a silence it still quotes
        // the pre-slowdown rate. The eased read extends its window to
        // now and floors at frozen/16.
        let clock = TestClock::new(0);
        let mut on = eased_engine(&clock);
        let mut off = VarDiffEngine::new(&clock, 6.0, 0.00001);
        for e in [&mut on, &mut off] {
            e.update_hash_rate(1000.0, true);
        }
        clock.advance_ms(20_000);
        for e in [&mut on, &mut off] {
            e.update_hash_rate(1000.0, true);
        }
        // 2 shares, 20 s apart, same slot → frozen rate 100 d/s.
        clock.advance_ms(3_600_000);
        // Decayed: 2000/(20+3600) = 0.55 d/s, floored at 100/16 = 6.25
        // → target 62.5 → step 64. Frozen (off): target 1000 → step 1024.
        assert_eq!(on.suggested_difficulty(64.0), Some(64.0));
        assert_eq!(off.suggested_difficulty(64.0), Some(1024.0));
    }

    // ── No-share descent ────────────────────────────────────────────

    /// One vardiff cycle as a server actually runs it: tick the clock, ask,
    /// and if the engine proposes something, APPLY it and tell the engine.
    /// The closed loop is the point — an open-loop probe would never move
    /// `client_difficulty` and would miss every accumulator bug.
    fn no_share_cycle(
        e: &mut VarDiffEngine<&TestClock>,
        clock: &TestClock,
        tick_ms: u64,
        diff: &mut f64,
    ) -> bool {
        clock.advance_ms(tick_ms);
        match e.suggested_difficulty(*diff) {
            Some(next) => {
                *diff = next;
                e.note_difficulty_assigned(next);
                true
            }
            None => false,
        }
    }

    /// The declining-miner case: a session advertises 10× its real
    /// hashrate, is assigned a difficulty from that inflated figure, and
    /// therefore lands no share at all. Timed there as "OpenChannel → first
    /// SubmitShares". A clock-driven controller reaches a reachable
    /// difficulty in a handful of cycles; a purely share-triggered one
    /// never retargets at all, because its only sensor is the share the
    /// too-high difficulty is suppressing.
    ///
    /// Before the descent existed this test measured 0 of 15 cycles
    /// proposing anything, with easing on AND off — we behaved like the
    /// ckpool port. Now the flag decides.
    #[test]
    fn a_declining_miner_is_rescued_before_its_first_share() {
        // Advertised 10×: the pool assigns 100_000 where the miner can only
        // sustain 10_000. No share is ever accepted, so `update_hash_rate`
        // is never called.
        let assigned = 100_000.0;
        let reachable = 10_000.0;

        // Easing off: the pre-descent behaviour, unchanged.
        let clock = TestClock::new(1_000);
        let mut off = VarDiffEngine::new(&clock, 6.0, 0.00001).with_initial_difficulty(assigned);
        let mut diff = assigned;
        for _ in 0..15 {
            assert!(
                !no_share_cycle(&mut off, &clock, 60_000, &mut diff),
                "easing off must propose nothing before the first share"
            );
        }
        assert_eq!(diff, assigned, "off must not move the difficulty at all");

        // Easing on: the difficulty walks down to something the miner can
        // actually hit, and does it monotonically.
        let clock = TestClock::new(1_000);
        let mut on = eased_engine(&clock).with_initial_difficulty(assigned);
        let mut diff = assigned;
        let mut cycles_to_reachable = None;
        for i in 0..15 {
            let before = diff;
            no_share_cycle(&mut on, &clock, 60_000, &mut diff);
            assert!(diff <= before, "descent must be monotone (cycle {i})");
            if cycles_to_reachable.is_none() && diff <= reachable {
                cycles_to_reachable = Some(i + 1);
            }
        }
        let cycles = cycles_to_reachable.expect("must reach a difficulty the miner can hit");
        assert!(cycles <= 5, "took {cycles} cycles to become reachable");
    }

    /// The property a fixed per-cycle divisor cannot have: whether a quiet
    /// minute is evidence depends on how many shares that minute was
    /// supposed to carry. SRI's rule scores every zero-share interval as a
    /// flat 100 % error and applies the same `h/3` to both of these.
    #[test]
    fn quiet_is_judged_against_the_expected_share_rate() {
        // 0.6 shares/min → a 100 s mean gap. 90 s of quiet is ordinary.
        let clock = TestClock::new(1_000);
        let mut sparse = VarDiffEngine::new(&clock, 0.6, 0.00001)
            .with_silence_easing(true)
            .with_initial_difficulty(4096.0);
        let mut diff = 4096.0;
        assert!(
            !no_share_cycle(&mut sparse, &clock, 90_000, &mut diff),
            "90 s without a share on a 0.6/min port is normal spacing, not evidence"
        );

        // 15 shares/min → a 4 s mean gap. The same 90 s is ~22 missed gaps.
        let clock = TestClock::new(1_000);
        let mut dense = VarDiffEngine::new(&clock, 15.0, 0.00001)
            .with_silence_easing(true)
            .with_initial_difficulty(4096.0);
        let mut diff = 4096.0;
        assert!(
            no_share_cycle(&mut dense, &clock, 90_000, &mut diff),
            "90 s without a share on a 15/min port is overwhelming evidence"
        );
        assert!(diff < 4096.0);
    }

    /// Evidence accumulates across ticks, so the descent does not depend on
    /// how often the caller asks. This matters in production: the shipped
    /// `difficulty_check_interval_ms` is 240 s and gets dropped to 30 s for
    /// testing — a rule keyed on the interval alone would stall completely
    /// at the short setting.
    #[test]
    fn descent_does_not_depend_on_the_check_interval() {
        let mut results = Vec::new();
        for (tick_ms, ticks) in [(30_000u64, 24u32), (60_000, 12), (240_000, 3)] {
            let clock = TestClock::new(1_000);
            let mut e = eased_engine(&clock).with_initial_difficulty(1_048_576.0);
            let mut diff = 1_048_576.0;
            for _ in 0..ticks {
                no_share_cycle(&mut e, &clock, tick_ms, &mut diff);
            }
            results.push((tick_ms, diff));
        }
        // Same 12 minutes of silence, three cadences, same rung. (Coarse
        // ticks can only lag by the granularity of the last step, so allow
        // one rung of slack — but not more.)
        let reference = results[0].1;
        for (tick_ms, got) in &results {
            assert!(
                *got <= reference * 2.0 && *got >= reference / 2.0,
                "tick {tick_ms} ms landed at {got}, reference {reference}"
            );
        }
    }

    /// A raw estimate that rounds back up onto the rung already in force
    /// must propose nothing — and the descent must NOT stall there, because
    /// `S` keeps growing and a later cycle crosses. "The descent silently
    /// stops" is precisely the failure a green suite hides.
    #[test]
    fn a_proposal_that_rounds_onto_the_current_rung_waits_and_then_crosses() {
        let clock = TestClock::new(1_000);
        let mut e = eased_engine(&clock).with_initial_difficulty(65_536.0);
        let mut diff = 65_536.0;

        // First opportunity past warmup: enough evidence to cross a rung.
        assert!(no_share_cycle(&mut e, &clock, 61_000, &mut diff));
        let after_first = diff;
        assert!(after_first < 65_536.0);

        // Now poll FASTER than evidence accrues. One rung costs k·τ = 30 s
        // of silence at 6 shares/min, so a 10 s tick cannot justify one and
        // the raw estimate rounds straight back onto the rung in force.
        assert!(
            !no_share_cycle(&mut e, &clock, 10_000, &mut diff),
            "a sub-rung proposal must not be emitted"
        );
        assert_eq!(
            diff, after_first,
            "a no-op tick must not move the difficulty"
        );

        // And it must not be stuck there: the accumulator keeps growing.
        let mut moved = false;
        for _ in 0..10 {
            if no_share_cycle(&mut e, &clock, 10_000, &mut diff) {
                moved = true;
                break;
            }
        }
        assert!(moved, "descent stalled on its own rung");
        assert!(diff < after_first);
    }

    /// Zero arrivals are evidence of *less* hashrate. They can never argue
    /// for more, at any current difficulty, however long the wait.
    #[test]
    fn the_descent_never_proposes_an_increase() {
        let clock = TestClock::new(1_000);
        let e = eased_engine(&clock).with_initial_difficulty(1024.0);
        clock.advance_ms(61_000);
        for elapsed in [0u64, 1_000, 60_000, 600_000, 86_400_000] {
            clock.advance_ms(elapsed);
            for client in [0.001, 1.0, 1024.0, 65_536.0, 1e9] {
                if let Some(p) = e.suggested_difficulty(client) {
                    assert!(
                        p < client,
                        "proposed {p} from {client} after {elapsed} ms of silence"
                    );
                }
            }
        }
    }

    /// The descent parks at the opening difficulty / 256 and then holds.
    /// A session that is not weak but simply idle must not be walked down
    /// to `min_difficulty` and flood on return.
    #[test]
    fn descent_parks_at_the_no_share_bound() {
        let clock = TestClock::new(1_000);
        let opening = 1_048_576.0;
        let mut e = eased_engine(&clock).with_initial_difficulty(opening);
        let mut diff = opening;
        for _ in 0..200 {
            no_share_cycle(&mut e, &clock, 60_000, &mut diff);
        }
        let floor = opening / VARDIFF_NO_SHARE_MAX_DESCENT_FACTOR;
        assert!(
            diff >= floor,
            "parked at {diff}, below the {VARDIFF_NO_SHARE_MAX_DESCENT_FACTOR}x bound {floor}"
        );
        // The bound is a LOWER bound, so rounding up cannot break it — the
        // parked value is the first rung at or above the floor.
        assert_eq!(diff, 4096.0);
        clock.advance_ms(86_400_000);
        assert_eq!(
            e.suggested_difficulty(diff),
            None,
            "parked descent must stop proposing"
        );
    }

    /// `min_difficulty` still wins when it is the higher floor.
    #[test]
    fn descent_respects_the_configured_floor() {
        let clock = TestClock::new(1_000);
        let mut e = VarDiffEngine::new(&clock, 6.0, 500.0)
            .with_silence_easing(true)
            .with_initial_difficulty(1_048_576.0);
        let mut diff = 1_048_576.0;
        for _ in 0..200 {
            no_share_cycle(&mut e, &clock, 60_000, &mut diff);
        }
        assert!(
            diff >= 500.0,
            "descended to {diff}, below the configured 500"
        );
    }

    /// A reject that still CLEARED the assigned target — the
    /// exhausted-search-space duplicate burst, a stale job — proves the
    /// miner reaches the difficulty, so it spends the evidence and the
    /// session is held rather than walked down.
    ///
    /// (Originally written with `note_submission`, which encoded the
    /// premise review finding 3 refuted: that ANY reject proves the target
    /// was met. It does not — see
    /// `below_target_rejects_do_not_spend_the_descent_evidence`.)
    #[test]
    fn rejects_that_reached_the_target_hold_the_descent() {
        let clock = TestClock::new(1_000);
        let mut e = eased_engine(&clock).with_initial_difficulty(65_536.0);
        let mut diff = 65_536.0;
        clock.advance_ms(61_000); // past warmup
        for i in 0..60 {
            clock.advance_ms(20_000);
            e.note_target_reached(); // duplicate/stale: the work was good
            assert_eq!(
                e.suggested_difficulty(diff),
                None,
                "a miner proving it reaches the target must not be eased (cycle {i})"
            );
        }
        assert_eq!(diff, 65_536.0);

        // Once the rejects stop, evidence accrues from the last one.
        for _ in 0..10 {
            no_share_cycle(&mut e, &clock, 60_000, &mut diff);
        }
        assert!(diff < 65_536.0, "descent must resume after the storm ends");
    }

    /// The regression this feature would otherwise create. The bootstrap
    /// divides accumulated work by elapsed time; a stretch spent at an
    /// unreachable difficulty contributes time but no observable work, so
    /// leaving it in the denominator makes the first share after a long
    /// descent read far slower than the miner is — and drives the
    /// difficulty down again instead of settling it.
    #[test]
    fn the_first_share_after_a_descent_is_not_diluted_by_the_silence() {
        let clock = TestClock::new(1_000);
        let mut e = eased_engine(&clock).with_initial_difficulty(100_000.0);
        let mut diff = 100_000.0;
        for _ in 0..4 {
            no_share_cycle(&mut e, &clock, 60_000, &mut diff);
        }
        assert!(diff < 100_000.0, "precondition: the descent moved");

        // The miner now lands shares at the reached difficulty, on time.
        let gap_ms = 10_000; // the 6/min target gap
        for _ in 0..4 {
            clock.advance_ms(gap_ms);
            e.update_hash_rate(diff, true);
        }
        clock.advance_ms(gap_ms);
        let proposed = e
            .suggested_difficulty(diff)
            .expect("bootstrap must speak once a share exists");

        // A miner hitting the target rate is already right: the estimate
        // must sit AT the difficulty it is mining, not far below it.
        // Anchored at engine start instead, the silent minutes would land
        // in the denominator and understate it several-fold.
        assert!(
            proposed >= diff / 2.0,
            "diluted: proposed {proposed} from a session mining {diff} on target"
        );
    }

    /// Both halves of the switch on one engine: the descent rescues the
    /// session before its first share, the windowed easing takes over
    /// afterwards, and neither corrupts the other.
    #[test]
    fn descent_hands_over_to_silence_easing() {
        let clock = TestClock::new(1_000);
        let mut e = eased_engine(&clock).with_initial_difficulty(100_000.0);
        let mut diff = 100_000.0;

        // Half one: no share ever, difficulty walks down.
        for _ in 0..5 {
            no_share_cycle(&mut e, &clock, 60_000, &mut diff);
        }
        let rescued = diff;
        assert!(rescued < 100_000.0);

        // The miner wakes up and mines a full window at that difficulty.
        for _ in 0..30 {
            clock.advance_ms(10_000);
            e.update_hash_rate(rescued, true);
        }

        // Half two: it goes quiet again. The windowed estimator — not the
        // descent, which is out of the picture once a share exists — walks
        // it down and parks at the pre-silence bound.
        let mut post = rescued;
        for _ in 0..240 {
            no_share_cycle(&mut e, &clock, 60_000, &mut post);
        }
        assert!(
            post < rescued,
            "silence easing must still work after a descent"
        );
        assert!(
            post >= rescued / VARDIFF_SILENCE_MAX_DESCENT_FACTOR / 2.0,
            "descent bound leaked into the eased path: {post} from {rescued}"
        );
    }

    /// Review regression (finding 5): the up-step cap charged a proving
    /// interval per 8×, not once. A genuine 128× rate jump then took three
    /// intervals — 12 minutes of flooding at the shipped 240 s cadence.
    #[test]
    fn a_proven_raise_is_not_rationed_at_eight_times_per_interval() {
        let clock = TestClock::new(0);
        let mut e = eased_engine(&clock).with_initial_difficulty(512.0);
        let mut diff = 512.0;
        // Equilibrium at 512, then the real rate jumps 128×.
        for _ in 0..30 {
            e.update_hash_rate(512.0, true);
            clock.advance_ms(10_000);
        }
        // Fixed hashrate from here on: 128x the rate that made 512 the
        // equilibrium, i.e. 512 difficulty every 78 ms.
        let rate_per_s = 512.0 / 0.078;
        let equilibrium = 512.0 * 128.0;
        let mut steps = 0;
        for _ in 0..30 {
            // One check interval's worth of shares AT the difficulty
            // currently in force — the interval between them stretches as
            // the difficulty rises, which is the whole point.
            let gap_ms = f64::max((diff / rate_per_s) * 1000.0, 1.0) as u64;
            for _ in 0..30 {
                e.update_hash_rate(diff, true);
                clock.advance_ms(gap_ms);
            }
            match e.suggested_difficulty(diff) {
                Some(next) if next > diff => {
                    diff = next;
                    e.note_difficulty_assigned(next);
                    steps += 1;
                }
                _ => break,
            }
        }
        assert!(
            diff >= equilibrium / 2.0,
            "never reached equilibrium: parked at {diff}, wanted ~{equilibrium}"
        );
        assert!(
            steps <= 2,
            "took {steps} intervals to follow a proven raise (reached {diff})"
        );
    }

    /// Review regression (finding 6): the descent floor must track the
    /// highest difficulty the session has ever carried. Latched at
    /// construction, a later raise left it stranded — a session opened at
    /// 16384 and raised to 500000 could be walked ~7800× down instead of
    /// the 256× the constant promises.
    #[test]
    fn the_descent_floor_follows_a_later_raise() {
        let clock = TestClock::new(1_000);
        let mut e = eased_engine(&clock).with_initial_difficulty(16_384.0);
        e.note_difficulty_assigned(500_000.0); // e.g. mining.suggest_difficulty
        let mut diff = 500_000.0;
        for _ in 0..400 {
            no_share_cycle(&mut e, &clock, 60_000, &mut diff);
        }
        let floor = 500_000.0 / VARDIFF_NO_SHARE_MAX_DESCENT_FACTOR;
        assert!(
            diff >= floor,
            "parked at {diff}, below the bound {floor} measured against the live difficulty"
        );
        // And a lowering must NOT drag the floor down with it, or the bound
        // ratchets away with every descent step and stops bounding.
        assert!(
            diff >= 1024.0,
            "floor ratcheted down during the descent: {diff}"
        );
    }

    /// Review regression (finding 1, MEASURED as a 32–64× RAISE): moving
    /// the bootstrap anchor detached that branch from the warmup gate,
    /// which is anchored at engine start. An assignment landing shortly
    /// before a tick left a window of milliseconds; one share divided by it
    /// read as an enormous hashrate, and this branch carries NO up-step cap
    /// by design, so it went straight to the wire.
    #[test]
    fn a_freshly_moved_bootstrap_anchor_cannot_manufacture_a_raise() {
        for gap_ms in [1u64, 200, 500, 5_000, 59_000] {
            let clock = TestClock::new(0);
            let mut e = eased_engine(&clock).with_initial_difficulty(1024.0);
            clock.advance_ms(600_000); // long silence, no share
            e.note_difficulty_assigned(1024.0); // anchor moves to now
            clock.advance_ms(gap_ms);
            e.update_hash_rate(1024.0, true); // the FIRST accepted share
            let proposed = e.suggested_difficulty(1024.0);
            assert!(
                proposed.is_none_or(|p| p <= 1024.0),
                "gap {gap_ms} ms produced {proposed:?} from a session at 1024 — \
                 a raise conjured out of a short measurement window"
            );
        }
    }

    /// Review regression (finding 3): a below-target reject is the miner
    /// telling us it cannot clear the bar — the exact symptom the descent
    /// corrects. Spending the evidence on it pinned `S` to the gap between
    /// two rejects, so the difficulty never fell and the feature missed
    /// precisely the sessions it was built for.
    #[test]
    fn below_target_rejects_do_not_spend_the_descent_evidence() {
        let clock = TestClock::new(1_000);
        let mut e = eased_engine(&clock).with_initial_difficulty(65_536.0);
        let mut diff = 65_536.0;
        clock.advance_ms(61_000);
        // A miner hashing steadily but never clearing the assigned target:
        // liveness only, no proof it reached the difficulty.
        for _ in 0..10 {
            clock.advance_ms(20_000);
            e.note_submission();
        }
        assert!(
            no_share_cycle(&mut e, &clock, 1, &mut diff),
            "a session that only produces below-target rejects must still descend"
        );
        assert!(diff < 65_536.0);

        // A reject that DID clear the bar (duplicate, stale, unknown job)
        // still spends it — that miner has proven it can reach the target.
        let clock = TestClock::new(1_000);
        let mut e2 = eased_engine(&clock).with_initial_difficulty(65_536.0);
        let mut diff2 = 65_536.0;
        clock.advance_ms(61_000);
        for _ in 0..10 {
            clock.advance_ms(20_000);
            e2.note_target_reached();
        }
        assert!(
            !no_share_cycle(&mut e2, &clock, 1, &mut diff2),
            "a session proving it reaches the target must be held"
        );
        assert_eq!(diff2, 65_536.0);
    }

    /// The bootstrap anchor may only move while nothing has been accepted.
    /// Once a share exists, a later assignment must NOT reset it — that
    /// would divide the accumulated work by a shorter span and read the
    /// miner as faster than it is, the mirror image of the dilution the
    /// anchor exists to prevent.
    #[test]
    fn the_bootstrap_anchor_freezes_once_a_share_is_accepted() {
        let clock = TestClock::new(0);
        let mut e = eased_engine(&clock).with_initial_difficulty(1024.0);
        e.update_hash_rate(1024.0, true); // one share at t=0
        clock.advance_ms(80_000);
        // Anchored at engine start: 1024 * 10 / 80 = 128.
        let before = e.suggested_difficulty(16_384.0);
        assert_eq!(before, Some(128.0), "precondition");

        // A later assignment must not move the anchor any more.
        e.note_difficulty_assigned(4096.0);
        assert_eq!(
            e.suggested_difficulty(16_384.0),
            before,
            "anchor moved after a share: the same work is now divided by a \
             shorter span and the miner reads as faster than it is"
        );
    }

    /// A missed `note_difficulty_assigned` must fail SAFE. The stored
    /// segment difficulty then disagrees with reality, and the direction of
    /// the error decides whether that is harmless:
    ///
    /// - missed LOWERING → stored is too HIGH → `S` grows too slowly →
    ///   descends too little. Harmless.
    /// - missed RAISE → stored is too LOW → `S` grows too fast → descends
    ///   too MUCH. NOT harmless.
    ///
    /// This pins both directions so the asymmetry is visible, and it is why
    /// every raising path (`handle_update_channel`, SV1
    /// `mining.suggest_difficulty`, the cpuminer fallback, the vardiff
    /// retarget) must call the hook — the no-share branch itself can only
    /// ever propose a decrease, so it cannot create this case on its own.
    #[test]
    fn a_missed_assignment_hook_errs_toward_descending_too_little() {
        // Missed LOWERING: engine still believes 1024, caller is at 64.
        let clock = TestClock::new(0);
        let stale_high = eased_engine(&clock).with_initial_difficulty(1024.0);
        // Truthful reference: the engine was told about the same lowering.
        let clock2 = TestClock::new(0);
        let mut truthful = eased_engine(&clock2).with_initial_difficulty(1024.0);
        truthful.note_difficulty_assigned(64.0);

        clock.advance_ms(300_000);
        clock2.advance_ms(300_000);
        let missed = stale_high.suggested_difficulty(64.0);
        let told = truthful.suggested_difficulty(64.0);
        match (missed, told) {
            (Some(m), Some(t)) => assert!(
                m >= t,
                "a missed lowering must descend LESS, not more: {m} vs {t}"
            ),
            (None, _) => {} // held entirely — even more conservative
            (Some(m), None) => panic!("missed hook proposed {m} where the truth held"),
        }
    }

    /// The engine must be told what the session is quiet AT. Without a
    /// seeded difficulty it has nothing to bound and holds — the
    /// conservative failure mode for a missed wiring site.
    #[test]
    fn descent_holds_when_no_initial_difficulty_was_seeded() {
        let clock = TestClock::new(1_000);
        let e = eased_engine(&clock); // no with_initial_difficulty
        clock.advance_ms(600_000);
        assert_eq!(e.suggested_difficulty(100_000.0), None);
    }

    /// The cap must survive the ladder. Rounding happens AFTER the cap, so a
    /// cap that is not itself a rung gets stepped over and the "at most 8×"
    /// guarantee silently disappears.
    ///
    /// Regression for exactly that: with `client_difficulty = 48` the raw cap is
    /// 384, which is not a power of two. Capping at 384 and then rounding up
    /// yields 512 — 10.7× the current difficulty, past the bound the constant
    /// promises.
    #[test]
    fn up_step_cap_survives_the_power_of_two_ladder() {
        let clock = TestClock::new(1_000);
        let mut on = eased_engine(&clock);
        for _ in 0..30 {
            on.update_hash_rate(4.0, true);
            clock.advance_ms(100);
        }
        let proposed = on
            .suggested_difficulty(48.0)
            .expect("burst window must propose a retarget");
        assert!(
            proposed <= 48.0 * VARDIFF_MAX_UP_STEP_FACTOR,
            "{proposed} exceeds the {VARDIFF_MAX_UP_STEP_FACTOR}x cap over 48"
        );
        assert_eq!(
            proposed,
            2_f64.powf(proposed.log2().round()),
            "{proposed} must still be a power of two"
        );
    }

    #[test]
    fn up_step_cap_bounds_burst_inflated_windows() {
        // A window whose samples all arrive in one bundle (a JDC draining
        // its optimistic-mining cache) implies an absurd rate over a tiny
        // span. The cap limits the resulting jump to 8× per retarget; the
        // uncapped engine would leap 96×.
        let clock = TestClock::new(1_000);
        let mut on = eased_engine(&clock);
        let mut off = VarDiffEngine::new(&clock, 6.0, 0.00001);
        for _ in 0..30 {
            on.update_hash_rate(4.0, true);
            off.update_hash_rate(4.0, true);
            clock.advance_ms(100);
        }
        // closed span 2.9 s, sum 120 → 41.4 d/s → target 414.
        assert_eq!(on.suggested_difficulty(4.0), Some(32.0), "capped at 8×4");
        // Uncapped, the raw 414 rounds up to the next rung.
        assert_eq!(off.suggested_difficulty(4.0), Some(512.0), "uncapped leap");
    }

    #[test]
    fn recovery_converges_without_a_sawtooth() {
        // The v1 killer, replayed as a closed-loop regression: a healthy
        // session throttles 10×, goes silent, gets eased down — and then
        // resumes submitting. v1 snapped back to the pre-silence
        // difficulty and re-stranded the miner three times over. Here the
        // recovery may wobble once (first share briefly re-trusts the
        // last measured rate, capped at 8×), then must settle near the
        // throttled equilibrium and stay.
        let clock = TestClock::new(1_000);
        let mut e = eased_engine(&clock);
        fill_equilibrium(&mut e, &clock);
        let pre_silence = 1024.0;

        // Silence until parked.
        let mut client = pre_silence;
        for _ in 0..120 {
            clock.advance_ms(60_000);
            if let Some(next) = e.suggested_difficulty(client) {
                client = next;
            }
        }
        assert!((64.0..=128.0).contains(&client), "parked, got {client}");

        // The rig returns at 1/10 of its original rate (10.24 diff/s).
        // Closed loop: shares arrive at the CURRENT difficulty's cadence,
        // every proposal is applied, inline check after each share.
        let throttled_rate = 10.24; // difficulty per second
        let mut proposals = Vec::new();
        for _ in 0..40 {
            let gap_ms = ((client / throttled_rate) * 1000.0) as u64;
            clock.advance_ms(gap_ms.max(1));
            e.update_hash_rate(client, true);
            if let Some(next) = e.suggested_difficulty(client) {
                assert!(
                    next <= client * VARDIFF_MAX_UP_STEP_FACTOR,
                    "up-step cap violated: {client} → {next}"
                );
                assert!(
                    next < pre_silence,
                    "must never snap back to the pre-silence difficulty: {next}"
                );
                proposals.push(next);
                client = next;
            }
        }
        // Settled near the throttled equilibrium (10.24 d/s × 10 s target
        // gap ≈ 102 → parked around 48..192 by the deadband), and the
        // excursions are over: at most ONE proposal above 256 in the
        // whole recovery (v1 produced a >2048 spike per cycle, thrice).
        assert!(
            (48.0..=192.0).contains(&client),
            "must settle near the throttled equilibrium, got {client}"
        );
        let excursions = proposals.iter().filter(|p| **p > 256.0).count();
        assert!(
            excursions <= 1,
            "more than one recovery excursion: {proposals:?}"
        );
    }

    // ── review regressions (v2 max review) ────────────────────────────

    #[test]
    fn zero_span_window_holds_instead_of_sinking() {
        // Review finding: a full (>=5-sample) window whose shares all share
        // one millisecond (closed_ms == 0, a drained JDC burst) bypassed the
        // 16x descent floor, so the 1/T decay sank the session to the floor
        // and it flooded on return. Fix: a zero-span window carries no
        // measurable rate, so easing holds the difficulty instead.
        let clock = TestClock::new(1_000);
        let mut e = eased_engine(&clock);
        for _ in 0..30 {
            e.update_hash_rate(1024.0, true); // no clock advance → all one ms
        }
        assert_eq!(e.cache_len(), VARDIFF_CACHE_SIZE);
        // Two days of silence: the buggy version returned a target sinking
        // toward min_difficulty; the fix holds.
        clock.advance_ms(48 * 3_600_000);
        assert_eq!(
            e.suggested_difficulty(1024.0),
            None,
            "a zero-span window must hold, not sink to the floor"
        );
        // And once a later share gives the window a real span, easing works
        // again normally.
        clock.advance_ms(10_000);
        e.update_hash_rate(1024.0, true);
        clock.advance_ms(400_000);
        assert!(
            e.suggested_difficulty(1024.0).is_some_and(|d| d < 1024.0),
            "easing must resume once the window has a real span"
        );
    }

    #[test]
    fn bootstrap_convergence_is_not_capped_by_easing() {
        // Review finding: cap_up_step throttled EVERY upward retarget when
        // easing was on, including the under-sampled bootstrap's documented
        // one-step convergence — so a fast miner starting far too low crept
        // up 8x per interval instead of jumping to equilibrium. Fix: the cap
        // no longer guards the bootstrap path. On/off must now agree there.
        let clock = TestClock::new(0);
        let mut on = eased_engine(&clock);
        let mut off = VarDiffEngine::new(&clock, 6.0, 0.00001);
        // Sit at the warmup boundary FIRST, then submit — so the two shares
        // are recent (tail ≈ 0, no silence decay) and warmup is already
        // past. Two shares 100 ms apart at diff 1 imply a huge hashrate and
        // a target hundreds of times above the client's 1.
        clock.advance_ms(VARDIFF_WARMUP_MS + 1_000);
        for e in [&mut on, &mut off] {
            e.update_hash_rate(1.0, true);
        }
        clock.advance_ms(100);
        for e in [&mut on, &mut off] {
            e.update_hash_rate(1.0, true);
        }
        assert!(
            on.cache_len() < VARDIFF_SAMPLE_THRESHOLD,
            "under-sampled path"
        );
        // Check at the instant of the last share: tail is 0, so no decay —
        // this isolates the cap removal from the (correct) silence decay.
        let up_on = on.suggested_difficulty(1.0).expect("must retarget up");
        let up_off = off.suggested_difficulty(1.0).expect("must retarget up");
        assert_eq!(
            up_on, up_off,
            "bootstrap convergence must be identical on/off (not capped)"
        );
        assert!(
            up_on > 1.0 * VARDIFF_MAX_UP_STEP_FACTOR,
            "must jump past the 8x cap in one step, got {up_on}"
        );
    }

    #[test]
    fn note_submission_is_inert_when_easing_off() {
        // The gate that keeps the default path byte-identical: with easing
        // off, note_submission neither reads the clock nor arms the silence
        // sensor, so it can never influence a (disabled) eased read.
        let clock = TestClock::new(1_000);
        let mut off = VarDiffEngine::new(&clock, 6.0, 0.00001);
        populate_cache(&mut off, &clock, 30, 1024.0);
        clock.advance_ms(3_600_000);
        let before = off.suggested_difficulty(1024.0);
        off.note_submission(); // must be a no-op when easing is off
        let after = off.suggested_difficulty(1024.0);
        assert_eq!(
            before, after,
            "note_submission must not perturb the easing-off path"
        );
    }
}
