// SPDX-License-Identifier: AGPL-3.0-or-later

//! `GroupSoloEngine` — top-level wiring of the Group-Solo
//! service-engine.
//!
//! Owns the Postgres pool, Redis-backed `GroupRoundStore`,
//! `DistributionBuilder` (with its in-flight cache), and
//! `GroupResetRunner` plus its per-group calendar-aligned cron
//! tasks.
//!
//! Public API:
//!
//! - `record_share` / `record_reject` — hot-path; called per
//!   accepted / rejected share after the stratum layer has resolved
//!   mode = Group-Solo + group_id for the address.
//! - `build_distribution` — called by the template-build path with
//!   the prospective finder's address.
//! - `on_block_found` — called when a Group-Solo finder wins a block.
//!   Writes the payout history from the block's OWN coinbase, resets
//!   the round (Variant A — preserves `lastAcceptedShareAt`), drops
//!   the group's snapshots, invalidates the distribution cache.
//! - `manual_reset` — admin-triggerable wrapper.
//! - `shutdown` — flips the cancel watch so background tasks exit.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use bp_common::{AddressId, InvalidAddressError, Sats};
use bp_cron_utils::SystemClock;
use bp_db::{find_group, DbError, PplnsGroupRow};
use bp_group_mgmt::group::{window_duration_ms, PayoutMode, RoundResetPreset};
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::{watch, Mutex as TokioMutex};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::{ConfigError, GroupSoloEngineConfig};
use crate::distribution::{
    DistributionBuilder, DistributionConfig, DistributionError, DistributionResult,
};
use crate::history::{
    apply_distribution, ApplyDistributionResult, AuditRow, GroupPayoutRowType, LedgerError,
};
use crate::reset::{spawn_per_group_task, GroupResetRunner, ResetError, ResetSchedule};

use crate::round::snapshot::{delete_all_for_group, delete_snapshot_for};
use crate::round::{GroupRoundStore, RoundError, WINDOW_BUCKET_MS};

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("round: {0}")]
    Round(#[from] RoundError),
    #[error("db: {0}")]
    Db(#[from] DbError),
    #[error("payout history: {0}")]
    Ledger(#[from] LedgerError),
    #[error("reset: {0}")]
    Reset(#[from] ResetError),
    #[error("distribution: {0}")]
    Distribution(Arc<DistributionError>),
    #[error("snapshot missing for group {group_id} finder {finder_address} block {block_height}")]
    SnapshotMissing {
        group_id: Uuid,
        finder_address: String,
        block_height: i32,
    },
    #[error(
        "no snapshot for group {group_id} finder {finder_address} under the winning job's payout \
         list — the block needs an operator reprocess"
    )]
    SnapshotMissingForPayouts {
        group_id: Uuid,
        finder_address: String,
    },
    #[error(
        "group {group_id} block {block_height} coinbase pays {actual_reward} sats, less than \
         the {subsidy} sat subsidy the block was entitled to — it forfeited money, so nothing \
         about it is trustworthy enough to book unattended"
    )]
    RevenueBelowSubsidy {
        group_id: Uuid,
        block_height: i32,
        actual_reward: u64,
        subsidy: u64,
    },
    #[error("on_block_found already in flight for group {group_id}")]
    BlockFoundInProgress { group_id: Uuid },
    #[error("invalid address in snapshot: {0}")]
    Address(#[from] InvalidAddressError),
    #[error("payment attribution: {0}")]
    PaymentAttribution(#[from] bp_coinbase_snapshot::PaidAtHeightError),
}

impl EngineError {
    /// Would retrying this ever succeed?
    ///
    /// The confirmation watcher re-applies a pending block on every
    /// tick and only drops it once the apply returns `Ok`. That is
    /// right for a database blip and wrong for a verdict: a snapshot
    /// that expired, a coinbase that burned its own subsidy or an
    /// address that will not parse produce the SAME failure forever,
    /// so retrying them is an infinite loop that hides the block
    /// behind a repeating warning instead of surfacing it once.
    ///
    /// Terminal here does not mean the block is lost — it means no
    /// automatic path can book it, and the operator reprocess reads
    /// the block's own coinbase off the chain rather than the parked
    /// blob.
    pub fn is_terminal(&self) -> bool {
        match self {
            EngineError::Config(_)
            | EngineError::SnapshotMissing { .. }
            | EngineError::SnapshotMissingForPayouts { .. }
            | EngineError::RevenueBelowSubsidy { .. }
            | EngineError::Address(_) => true,
            // The attribution errors own their own classification, so this
            // engine and PPLNS cannot disagree about which of them is a
            // verdict — one of them (an identity row that has not arrived
            // yet) is deliberately retryable.
            EngineError::PaymentAttribution(e) => e.is_terminal(),
            // Same shape, same reason: a ledger error is usually
            // infrastructure, but one of them is a verdict — a height that
            // already carries a DIFFERENT block's payout rows still carries
            // them next tick. `LedgerError` owns that distinction precisely
            // so this engine and PPLNS cannot disagree about it — and they
            // disagreed anyway for ten days: the commit that hoisted the type
            // (2026-08-03) wired PPLNS to it and left `Ledger(_)` here in the
            // infrastructure arm below, answering `false`. Nothing bounds a
            // `false`: the pending-block hash has no TTL and the watcher keeps
            // no attempt count, so it is a re-apply every tick forever behind
            // a repeating warning instead of the park in the unbookable store
            // the variant's own doc asks for.
            EngineError::Ledger(e) => e.is_terminal(),
            // Infrastructure, and the per-group in-flight guard — all
            // of these clear on their own.
            EngineError::Redis(_)
            | EngineError::Round(_)
            | EngineError::Db(_)
            | EngineError::Reset(_)
            | EngineError::Distribution(_)
            | EngineError::BlockFoundInProgress { .. } => false,
        }
    }
}

#[derive(Clone)]
pub struct GroupSoloEngine {
    inner: Arc<Inner>,
}

struct Inner {
    pool: PgPool,
    round: GroupRoundStore,
    distribution_builder: DistributionBuilder,
    reset_runner: GroupResetRunner<SystemClock>,
    config: GroupSoloEngineConfig,
    cancel_tx: watch::Sender<bool>,
    /// Live per-group round-reset cron tasks, keyed by group id. Each has its
    /// own cancel channel so [`GroupSoloEngine::reschedule_group`] can tear
    /// down + re-arm a single group on a settings change without touching the
    /// others. `shutdown` signals all of them.
    reset_tasks: StdMutex<HashMap<Uuid, ResetTask>>,
    /// Per-group `on_block_found` re-entrancy guard. `tokio::sync::Mutex`
    /// because the hot path awaits PG + Redis inside the critical
    /// section.
    block_found_in_progress: TokioMutex<HashSet<Uuid>>,
    /// Hot-path cache of each group's payout mode + window length, so
    /// `record_share` doesn't hit Postgres per accepted share. The mode is
    /// immutable (set at creation); the window length is editable, so the
    /// entry carries a short TTL ([`MODE_CACHE_TTL`]) and is re-read on expiry.
    mode_cache: StdMutex<HashMap<Uuid, CachedGroupMode>>,
    /// Per-group highest time-bucket for which a windowed `record_share`
    /// already triggered a trim. The window only sheds whole buckets at hour
    /// boundaries, so trimming on every share would spend a Redis round-trip
    /// that is a no-op ~99% of the time. We trim only when a share opens a
    /// *new* bucket (≈ once/hour/group); the payout read path still trims with
    /// real wall-clock, so this only bounds Redis between reads, never affects
    /// correctness. (An out-of-order older share never lowers the watermark.)
    window_trim_watermark: StdMutex<HashMap<Uuid, i64>>,
    /// Who is behind a ledger key — read twice per block, from the two ends of
    /// the split, through **one** handle.
    ///
    /// The distribution builder holds a clone of this same
    /// [`bp_coinbase_snapshot::InstalledResolver`] and asks it which keys are
    /// rotating before it filters them into the coinbase; settlement asks it which
    /// address each key was paid under ~100 blocks later. Sharing the handle
    /// rather than the rule is load-bearing: a row paid by a resolver that knows
    /// it and then booked by one that does not is a double credit.
    ///
    /// Unset means [`bp_coinbase_snapshot::StaticPaidAddresses`] — correct for a
    /// pool with no rotating identities, and a refusal for any key that is not a
    /// payable address, so leaving it unset can never misbook a `payout_id`.
    /// `bin/blitzpool` installs the descriptor-aware one at startup, the same one
    /// it installs on the PPLNS engine: one resolver, both modes.
    identity_resolver: bp_coinbase_snapshot::InstalledResolver,
}

/// Cached payout mode + window length for one group. `window_ms` is 0 for
/// [`PayoutMode::Prop`] (unused there).
#[derive(Clone, Copy)]
struct CachedGroupMode {
    mode: PayoutMode,
    window_ms: i64,
    expires_at: Instant,
}

/// TTL for [`Inner::mode_cache`]. Short enough that a window-length edit takes
/// effect within a minute (and the mode never changes), cheap enough that the
/// hot share path almost always hits the cache.
const MODE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Decide whether a windowed share in `bucket_id` should trigger a trim, given
/// the highest bucket already trimmed (`watermark`, `None` if never). Trim on
/// the first share of a group (cold start catches up any aging) and whenever a
/// share opens a strictly-newer bucket; skip same-bucket and out-of-order older
/// shares. Pure so the boundary logic is unit-testable without Redis.
fn should_trim_on_bucket(watermark: Option<i64>, bucket_id: i64) -> bool {
    match watermark {
        Some(last) => bucket_id > last,
        None => true,
    }
}

/// `(PayoutMode, window_ms)` to use when the per-share mode lookup hits a DB
/// error. The mode is immutable, so a cached entry — even an expired one —
/// still carries the correct mode; reusing it keeps a `Window` group's shares
/// flowing into the window aggregate during a transient DB blip instead of
/// silently misrouting them to the PROP keys (where the window read never sees
/// them). `Prop` is only the cold fallback for a group never resolved. Pure so
/// the "never misroute on a transient error" rule is unit-testable.
fn mode_on_lookup_error(cached: Option<CachedGroupMode>) -> (PayoutMode, i64) {
    match cached {
        Some(c) => (c.mode, c.window_ms),
        None => (PayoutMode::Prop, 0),
    }
}

/// Derive `(PayoutMode, window_ms)` from a group row. `window_ms` reinterprets
/// the reset-cadence config as a sliding-window length (see
/// [`bp_group_mgmt::group::window_duration_ms`]); it is 0 for PROP groups.
pub(crate) fn group_mode_from_row(g: &PplnsGroupRow) -> (PayoutMode, i64) {
    let mode = PayoutMode::parse_or_default(&g.payout_mode);
    let window_ms = match mode {
        PayoutMode::Prop => 0,
        PayoutMode::Window => {
            let preset = g
                .round_reset_preset
                .as_deref()
                .and_then(RoundResetPreset::parse);
            let interval = g
                .round_reset_interval_days
                .and_then(|d| u32::try_from(d).ok());
            window_duration_ms(preset, interval)
        }
    };
    (mode, window_ms)
}

/// A running per-group round-reset cron + its dedicated cancel channel.
struct ResetTask {
    cancel: watch::Sender<bool>,
    #[allow(dead_code)] // retained so the task isn't detached/lost; cancel drives exit
    join: JoinHandle<()>,
}

/// Spawn a per-group reset cron with its own cancel channel.
fn spawn_reset_task(runner: GroupResetRunner<SystemClock>, schedule: ResetSchedule) -> ResetTask {
    let (cancel, cancel_rx) = watch::channel(false);
    let join = spawn_per_group_task(runner, schedule, cancel_rx);
    ResetTask { cancel, join }
}

impl GroupSoloEngine {
    /// Validate config, wire dependencies, and spawn a per-group
    /// calendar-reset cron for every active group with a configured
    /// preset.
    pub async fn spawn(
        config: GroupSoloEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
    ) -> Result<Self, EngineError> {
        Self::spawn_inner(config, redis, pool, true).await
    }

    /// Core-mode constructor: same wiring, but *without* the per-group
    /// round-reset cron. The Core only reads the round window and builds
    /// distributions (`build_distribution`, which still writes the
    /// snapshot key); the round-resetting cron runs on the Satellite.
    /// `record_share` is unaffected and unused on the Core (the share
    /// path produces to the stream instead).
    pub async fn spawn_core(
        config: GroupSoloEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
    ) -> Result<Self, EngineError> {
        Self::spawn_inner(config, redis, pool, false).await
    }

    async fn spawn_inner(
        config: GroupSoloEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
        background_tasks: bool,
    ) -> Result<Self, EngineError> {
        let config = config.try_new()?;
        let round = GroupRoundStore::new(redis);
        let dist_cfg = DistributionConfig::from_engine_config(&config);
        // One handle, two readers — the builder's job-path filter and this
        // engine's settlement. See `Inner::identity_resolver`.
        let identity_resolver = bp_coinbase_snapshot::InstalledResolver::default();
        let distribution_builder = DistributionBuilder::new(pool.clone(), round.clone(), dist_cfg)
            .with_identities(identity_resolver.clone());
        let clock = Arc::new(SystemClock);
        let reset_runner = GroupResetRunner::new(pool.clone(), round.clone(), clock.clone());

        let (cancel_tx, _cancel_rx) = watch::channel(false);

        // Core mode (`background_tasks == false`) skips the cron: the
        // per-group round-reset mutates rounds, which is the Satellite's
        // job. `reset_tasks` stays empty so `reschedule_group` remains a
        // safe no-op-add.
        let mut reset_tasks: HashMap<Uuid, ResetTask> = HashMap::new();
        if background_tasks {
            // Spawn a per-group reset cron for every active group with a
            // configured preset, retaining each task (with its own cancel) so a
            // later `reschedule_group` can re-arm a single group at runtime.
            for schedule in load_active_schedules(&pool).await? {
                let group_id = schedule.group_id;
                reset_tasks.insert(group_id, spawn_reset_task(reset_runner.clone(), schedule));
            }
        }

        info!(
            min_payout_sats = config.min_payout_sats.0,
            fee_percent = config.fee_percent,
            background_tasks,
            "group-solo-engine spawned"
        );

        Ok(Self {
            inner: Arc::new(Inner {
                pool,
                round,
                distribution_builder,
                reset_runner,
                config,
                cancel_tx,
                reset_tasks: StdMutex::new(reset_tasks),
                block_found_in_progress: TokioMutex::new(HashSet::new()),
                identity_resolver,
                mode_cache: StdMutex::new(HashMap::new()),
                window_trim_watermark: StdMutex::new(HashMap::new()),
            }),
        })
    }

    /// (Re-)schedule a single group's round-reset cron from its current row —
    /// the runtime entry point bin/blitzpool's `apply_round_reset_config` hook
    /// calls on a `PATCH /settings` save: tear down any existing task, then arm
    /// a fresh one unless the group is dissolved/inactive or has no (valid)
    /// preset. Cheap + synchronous (the work is a watch-signal + a `tokio::spawn`).
    pub fn reschedule_group(&self, group: &PplnsGroupRow) {
        let mut tasks = self
            .inner
            .reset_tasks
            .lock()
            .expect("reset_tasks mutex poisoned");
        // Always tear down the old task first (handles preset/TZ/interval change).
        if let Some(old) = tasks.remove(&group.id) {
            let _ = old.cancel.send(true);
        }
        // Don't re-arm for dissolved / inactive groups.
        if group.dissolved_at.is_some() || !group.active {
            info!(group_id = %group.id, "round-reset cron unscheduled (group dissolved/inactive)");
            return;
        }
        // Window-mode groups never calendar-reset (the window self-trims); the
        // reset config is reinterpreted as the window length, so leave the cron
        // unscheduled regardless of preset.
        if PayoutMode::parse_or_default(&group.payout_mode) == PayoutMode::Window {
            info!(group_id = %group.id, "round-reset cron unscheduled (window payout mode)");
            return;
        }
        let interval = group
            .round_reset_interval_days
            .and_then(|i| u32::try_from(i).ok());
        match ResetSchedule::from_row_fields(
            group.id,
            group.round_reset_preset.as_deref(),
            group.round_reset_timezone.as_deref(),
            interval,
        ) {
            Ok(Some(schedule)) => {
                tasks.insert(
                    group.id,
                    spawn_reset_task(self.inner.reset_runner.clone(), schedule),
                );
                info!(
                    group_id = %group.id,
                    preset = ?group.round_reset_preset,
                    interval_days = ?group.round_reset_interval_days,
                    "round-reset cron (re)scheduled from settings change"
                );
            }
            // No preset (cleared) → stay unscheduled.
            Ok(None) => {
                info!(group_id = %group.id, "round-reset cron unscheduled (no preset)");
            }
            Err(e) => warn!(
                group_id = %group.id,
                error = %e,
                "reschedule_group: invalid reset schedule; left unscheduled"
            ),
        }
    }

    /// Resolve a group's `(PayoutMode, window_ms)`, caching the result for the
    /// hot share path. A cache miss reads the `pplns_group` row once. On a DB
    /// error we fall back to the last cached entry **even if expired** — the
    /// mode is immutable so its mode is still correct, and a stale `window_ms`
    /// only over-/under-trims on the record path (the read path always re-trims
    /// with a fresh `window_ms`, so payouts are unaffected). Routing a Window
    /// group's shares to the PROP keys during a DB blip would instead drop them
    /// from the window aggregate for good, so PROP is only the cold fallback for
    /// a group we have never resolved. Neither error fallback is cached.
    async fn resolve_group_mode(&self, group_id: Uuid) -> (PayoutMode, i64) {
        let cached = {
            let cache = self.inner.mode_cache.lock().expect("mode_cache poisoned");
            cache.get(&group_id).copied()
        };
        if let Some(c) = cached {
            if c.expires_at > Instant::now() {
                return (c.mode, c.window_ms);
            }
        }
        let (mode, window_ms) = match find_group(&self.inner.pool, group_id).await {
            Ok(Some(g)) => group_mode_from_row(&g),
            Ok(None) => (PayoutMode::Prop, 0),
            Err(e) => {
                // Prefer the last-known (immutable) mode over PROP so a transient
                // DB error can't misroute a Window group's shares into the PROP
                // aggregate, where they'd be invisible to the window payout.
                if cached.is_some() {
                    warn!(%group_id, error = %e,
                        "group payout-mode lookup failed — reusing last-known mode (not re-cached)");
                } else {
                    warn!(%group_id, error = %e,
                        "group payout-mode lookup failed and no cached mode — defaulting to PROP");
                }
                return mode_on_lookup_error(cached);
            }
        };
        self.inner
            .mode_cache
            .lock()
            .expect("mode_cache poisoned")
            .insert(
                group_id,
                CachedGroupMode {
                    mode,
                    window_ms,
                    expires_at: Instant::now() + MODE_CACHE_TTL,
                },
            );
        (mode, window_ms)
    }

    /// Drop the cached `(PayoutMode, window_ms)` for a group so the next share
    /// re-reads it from Postgres. Call this after a settings edit that changes
    /// the round-reset cadence: the cadence is reinterpreted as the window
    /// length, so a stale cache would keep the record-path trim using the OLD
    /// length for up to `MODE_CACHE_TTL`. On a window *grow* that stale-small
    /// length would over-trim and permanently drop a bucket the new (larger)
    /// window should keep, so we invalidate eagerly. (The mode itself is
    /// immutable; only the window length can move.)
    pub fn invalidate_mode_cache(&self, group_id: Uuid) {
        self.inner
            .mode_cache
            .lock()
            .expect("mode_cache poisoned")
            .remove(&group_id);
    }

    /// Record-path trim gate for a windowed share: returns `true` (and bumps
    /// the watermark) only when `timestamp_ms` falls in a strictly-newer
    /// hour-bucket than the last one we trimmed for this group — see
    /// [`should_trim_on_bucket`]. A short `StdMutex`-guarded map lookup, far
    /// cheaper than the Redis round-trip it gates.
    fn advance_trim_watermark(&self, group_id: Uuid, timestamp_ms: i64) -> bool {
        let bucket_id = timestamp_ms.div_euclid(WINDOW_BUCKET_MS);
        let mut marks = self
            .inner
            .window_trim_watermark
            .lock()
            .expect("window_trim_watermark poisoned");
        if should_trim_on_bucket(marks.get(&group_id).copied(), bucket_id) {
            marks.insert(group_id, bucket_id);
            true
        } else {
            false
        }
    }

    /// Hot path: an accepted Group-Solo share. Caller has resolved
    /// `group_id` (via the mode-gate adapter in `hooks.rs`).
    pub async fn record_share(
        &self,
        share_id: Option<&str>,
        group_id: Uuid,
        address: &str,
        difficulty: f64,
        timestamp_ms: i64,
    ) -> Result<(), EngineError> {
        let group_key = group_id.to_string();
        // PROP appends to the single round aggregate; Window appends into the
        // share's time bucket and self-trims (using the share's own accept
        // time as "now" so an idle group still bounds its window).
        let (mode, window_ms) = self.resolve_group_mode(group_id).await;
        let applied = match mode {
            PayoutMode::Prop => {
                self.inner
                    .round
                    .record_share(share_id, &group_key, address, difficulty, timestamp_ms)
                    .await?
            }
            PayoutMode::Window => {
                let applied = self
                    .inner
                    .round
                    .record_share_windowed(share_id, &group_key, address, difficulty, timestamp_ms)
                    .await?;
                // Trim only when this share opens a new hour-bucket — the window
                // sheds whole buckets at hour boundaries, so per-share trimming
                // would be a no-op Redis round-trip ~99% of the time. The payout
                // read path trims with real wall-clock regardless, so this only
                // bounds Redis between reads.
                if applied && self.advance_trim_watermark(group_id, timestamp_ms) {
                    self.inner
                        .round
                        .trim_window(&group_key, timestamp_ms, window_ms)
                        .await?;
                }
                applied
            }
        };
        if !applied {
            // Deduped redelivery: the round already counts this share, so
            // the best-share check + cache-invalidate would be redundant.
            return Ok(());
        }
        // Best-share update is best-effort; the round wipes on
        // block-found, so a missed update is cosmetic.
        if let Err(e) = self
            .inner
            .round
            .update_best_share_if_better(&group_key, address, difficulty, timestamp_ms)
            .await
        {
            warn!(
                %group_id,
                address,
                error = %e,
                "best-share update failed (cosmetic; round wipes on block-found)"
            );
        }
        // Distribution depends on (round + balances); a new share
        // changes the round. Drop the whole cache (keyed by triple),
        // safer than invalidating only one (group, reward, finder)
        // tuple — the round has changed for all of them.
        self.inner.distribution_builder.invalidate_all();
        Ok(())
    }

    /// Per-rejected-share counter.
    pub async fn record_reject(
        &self,
        group_id: Uuid,
        address: &str,
        shares: f64,
    ) -> Result<(), EngineError> {
        let group_key = group_id.to_string();
        self.inner
            .round
            .record_reject(&group_key, address, shares)
            .await?;
        Ok(())
    }

    /// Build the current distribution for `(group_id, reward, finder)`.
    pub async fn build_distribution(
        &self,
        group_id: Uuid,
        block_reward_sats: u64,
        finder_address: &AddressId,
    ) -> Result<Arc<DistributionResult>, EngineError> {
        self.inner
            .distribution_builder
            .build(group_id, block_reward_sats, finder_address)
            .await
            .map_err(EngineError::Distribution)
    }

    /// Look up the WEIGHT snapshot the found block's coinbase was built
    /// from, so the Core can stamp it into the block-found event.
    ///
    /// `weights_fingerprint` is the identity of the winning job's payout
    /// list, carried on the job the share was built on. The build that
    /// produced that list stored its snapshot under it, and nothing else
    /// writes that key.
    ///
    /// It must NOT rebuild the distribution here. `record_share`
    /// invalidates the in-flight cache, so a single share landing between
    /// job issue and block-found makes a rebuild run against a moved
    /// round — measured on a two-member group as 187.5 M/125 M at job
    /// time versus 31.25 M/281.25 M at block-found. The coinbase pays the
    /// first pair. Missing snapshot → typed error, so the block is booked
    /// by an operator rather than booked wrong.
    pub async fn weight_snapshot_for_block_found(
        &self,
        group_id: Uuid,
        finder_address: &AddressId,
        weights_fingerprint: &[u8; 32],
    ) -> Result<bp_coinbase_snapshot::StoredWeightSnapshot, EngineError> {
        let mut conn = self.inner.round.connection_for_snapshot();
        let group_key = group_id.to_string();
        bp_coinbase_snapshot::resolve_snapshot_for_block_found(
            &mut conn,
            |fp| crate::round::snapshot::key_for_fingerprint(&group_key, fp),
            weights_fingerprint,
            "group-solo",
        )
        .await?
        .ok_or_else(|| EngineError::SnapshotMissingForPayouts {
            group_id,
            finder_address: finder_address.as_str().to_string(),
        })
    }

    /// Install the descriptor-aware payout-identity resolver.
    /// Idempotent-by-refusal: returns `false` if one was already installed, and
    /// keeps the first.
    ///
    /// Only `bin/blitzpool` calls this, once, at startup, with the SAME resolver
    /// it installs on the PPLNS engine. Until it does, settlement uses
    /// [`bp_coinbase_snapshot::StaticPaidAddresses`], which refuses a ledger key
    /// that is not a payable address rather than writing a history row against
    /// the wrong one.
    ///
    /// This also reaches the **distribution builder**, which shares the handle:
    /// installing here is what makes a rotating member's row survive into the
    /// coinbase in the first place. There is nothing to install twice.
    pub fn install_payout_identity_resolver(
        &self,
        resolver: Arc<dyn bp_coinbase_snapshot::PayoutIdentityResolver>,
    ) -> bool {
        self.inner.identity_resolver.install(resolver)
    }

    /// The installed resolver, or the static-only default.
    fn identity_resolver(&self) -> Arc<dyn bp_coinbase_snapshot::PayoutIdentityResolver> {
        self.inner.identity_resolver.get()
    }

    /// Apply a Group-Solo found block: write its payout history from the
    /// block's OWN coinbase, then move the round on.
    ///
    /// There is no settlement step. Group-Solo publishes every member it
    /// can pay and lets the rest fall to the pool output
    /// ([`bp_pplns::WithheldValue::ToPool`]), so a published member is
    /// paid exactly their claim and a withheld one is owed nothing. What
    /// the coinbase paid is the whole truth, and these rows record it.
    ///
    /// `snapshot` is therefore only used for the sanity checks below —
    /// the amounts come from `actual`. Per-group re-entrancy guard;
    /// idempotent across restarts via the
    /// `(groupId, blockHeight, address)` UNIQUE constraint.
    pub async fn on_block_found(
        &self,
        group_id: Uuid,
        block_height: i32,
        actual: &bp_coinbase_snapshot::ActualCoinbase,
        finder_address: &AddressId,
        snapshot: Option<bp_coinbase_snapshot::StoredWeightSnapshot>,
        weights_fingerprint: Option<[u8; 32]>,
    ) -> Result<ApplyDistributionResult, EngineError> {
        {
            let mut in_flight = self.inner.block_found_in_progress.lock().await;
            if in_flight.contains(&group_id) {
                return Err(EngineError::BlockFoundInProgress { group_id });
            }
            in_flight.insert(group_id);
        }
        let result = self
            .on_block_found_inner(
                group_id,
                block_height,
                actual,
                finder_address,
                snapshot,
                weights_fingerprint,
            )
            .await;
        self.inner
            .block_found_in_progress
            .lock()
            .await
            .remove(&group_id);
        result
    }

    async fn on_block_found_inner(
        &self,
        group_id: Uuid,
        block_height: i32,
        actual: &bp_coinbase_snapshot::ActualCoinbase,
        finder_address: &AddressId,
        snapshot: Option<bp_coinbase_snapshot::StoredWeightSnapshot>,
        weights_fingerprint: Option<[u8; 32]>,
    ) -> Result<ApplyDistributionResult, EngineError> {
        let group_key = group_id.to_string();

        // 1. Snapshot source: event-carried, else the fingerprint key,
        //    else the per-(group, finder) key (tests / manual path).
        let snapshot = match snapshot {
            Some(s) => s,
            None => {
                let mut conn = self.inner.round.connection_for_snapshot();
                let read = match weights_fingerprint.filter(|fp| fp != &[0u8; 32]) {
                    Some(fp) => {
                        bp_coinbase_snapshot::resolve_snapshot_for_block_found(
                            &mut conn,
                            |fp| crate::round::snapshot::key_for_fingerprint(&group_key, fp),
                            &fp,
                            "group-solo",
                        )
                        .await?
                    }
                    None => {
                        crate::round::snapshot::read_weight_snapshot(
                            &mut conn,
                            &group_key,
                            finder_address.as_str(),
                        )
                        .await?
                    }
                };
                read.ok_or(EngineError::SnapshotMissing {
                    group_id,
                    finder_address: finder_address.as_str().to_string(),
                    block_height,
                })?
            }
        };

        // The one hard gate: a coinbase that pays less than its own
        // subsidy destroyed money it was entitled to. Nothing healthy
        // produces that — not mempool drift, not a stale projection
        // base, not a job-declaring client's own template.
        let subsidy =
            bp_share::block_subsidy_sats(block_height, self.inner.config.subsidy_halving_interval);
        if actual.total_value_sats < subsidy {
            error!(
                %group_id,
                subsidy,
                actual_reward = actual.total_value_sats,
                block_height,
                "group-solo block coinbase pays less than the block subsidy — refusing to book"
            );
            return Err(EngineError::RevenueBelowSubsidy {
                group_id,
                block_height,
                actual_reward: actual.total_value_sats,
                subsidy,
            });
        }
        // Which address did the coinbase pay each member? For a static member
        // the ledger key IS that address and always was; for a rotating one the
        // key is a `payout_id` and the paid address is derived at THIS height.
        // Resolved here, after the snapshot is in hand, because the fallback
        // branches above are where the caller does not know the entries.
        //
        // A negative height is not a derivation index; `require_height` refuses
        // it on the next line rather than letting it settle as height 0.
        let derivation_height = u32::try_from(block_height).unwrap_or(0);
        let ledger_keys: Vec<String> = snapshot.entries.iter().map(|e| e.address.clone()).collect();
        let paid_at = self
            .identity_resolver()
            .paid_at_height(&ledger_keys, derivation_height)
            .await?;
        paid_at.require_height(block_height)?;

        // 2. Mode + reset gate (one row read), and the round state for
        //    the sharesInRound audit fields. Read BEFORE any reset wipes
        //    it; in Window mode this trims + reads the sliding window.
        let now_ms = chrono::Utc::now().timestamp_millis();
        let (mode, window_ms, reset_on_block) = match find_group(&self.inner.pool, group_id).await {
            Ok(Some(g)) => {
                let (mode, window_ms) = group_mode_from_row(&g);
                (mode, window_ms, g.reset_round_on_block)
            }
            Ok(None) => (PayoutMode::Prop, 0, false),
            Err(e) => {
                warn!(%group_id, error = %e,
                    "group row read failed in on_block_found — defaulting to PROP / no reset");
                (PayoutMode::Prop, 0, false)
            }
        };
        let round_by_addr = self
            .inner
            .round
            .read_payout_shares(&group_key, mode, now_ms, window_ms)
            .await?;
        let total_shares_in_round: f64 = round_by_addr.values().sum();
        let total_shares_i64 = total_shares_in_round.round() as i64;

        let audit_rows = history_rows_from_coinbase(
            group_id,
            &snapshot,
            actual,
            &round_by_addr,
            total_shares_i64,
            &paid_at,
        );

        // 3. Write the history, 4. move the round on, 5. drop the
        //    snapshots this block consumed, 6. drop the build cache.
        let outcome = apply_distribution(
            &self.inner.pool,
            group_id,
            block_height,
            &audit_rows,
            now_ms,
        )
        .await?;

        if mode == PayoutMode::Window {
            info!(%group_id,
                "group-solo: window mode — no per-block round reset (window self-trims by age)");
        } else if reset_on_block {
            if let Err(e) = self.inner.round.reset_for_block_found(&group_key).await {
                warn!(%group_id, error = %e, "round.reset_for_block_found failed — non-fatal");
            }
        } else {
            info!(%group_id,
                "group-solo: per-block round reset disabled (resetRoundOnBlock=false) — \
                 round accumulates until calendar/manual reset");
        }

        let mut conn = self.inner.round.connection_for_snapshot();
        if let Err(e) = delete_all_for_group(&mut conn, &group_key).await {
            warn!(
                %group_id,
                error = %e,
                "delete_all_snapshots_for_group failed — non-fatal, TTL fallback"
            );
        }
        if let Some(fp) = weights_fingerprint {
            if let Err(e) = delete_snapshot_for(&mut conn, &group_key, &fp).await {
                warn!(
                    %group_id,
                    error = %e,
                    "delete_snapshot_for failed — non-fatal, TTL fallback"
                );
            }
        }
        self.inner.distribution_builder.invalidate_all();

        info!(
            %group_id,
            block_height,
            history_inserted = outcome.history_inserted,
            "group-solo on_block_found applied"
        );
        Ok(outcome)
    }
}

/// Transcribe one block's coinbase into payout-history rows.
///
/// The amounts come from `actual` — the block's own coinbase — and
/// nothing else. The snapshot contributes only the fee address (whose
/// output is the pool's, not a member's) and the member list used to
/// flag a payment the pool cannot account for. `round_by_addr` supplies
/// the PROP-round detail the UI shows next to each amount.
///
/// One row per paid address. A member the coinbase did not pay gets no
/// row: under [`bp_pplns::WithheldValue::ToPool`] they are owed nothing,
/// so there is nothing to record.
///
/// This iterates what the coinbase PAID, so `paid_at` is used in its inverse
/// direction — from the paid address back to the member's height-invariant
/// ledger key. A rotating member's history row has to be written under that key
/// or the member cannot find their own payout: the derived address changes every
/// block, so a row keyed on it is a row nothing will ever query again.
fn history_rows_from_coinbase(
    group_id: Uuid,
    snapshot: &bp_coinbase_snapshot::StoredWeightSnapshot,
    actual: &bp_coinbase_snapshot::ActualCoinbase,
    round_by_addr: &HashMap<String, f64>,
    total_shares_in_round: i64,
    paid_at: &bp_coinbase_snapshot::PaidAtHeight,
) -> Vec<AuditRow> {
    let t = actual.total_value_sats;
    let mut rows: Vec<AuditRow> = Vec::new();

    for (addr_str, paid) in &actual.paid_by_address {
        if *paid == 0 || *addr_str == snapshot.fee_address {
            // The pool output is the pool's fee plus whatever the
            // distribution withheld. It is not a member payout and does
            // not belong in a member's payout history.
            continue;
        }
        // The member this output belongs to. Falling back to the paid address is
        // correct HERE and only here: by this point every entry is attributed
        // (the engine refused the block otherwise), so an unclaimed paid address
        // is genuinely an output no member claimed — the case the warn below
        // reports, which must be recorded under what the chain actually paid.
        let ledger_key = paid_at.ledger_key(addr_str).unwrap_or(addr_str);
        let Ok(address) = AddressId::new(ledger_key.to_string()) else {
            warn!(
                %group_id,
                address = %addr_str,
                paid,
                "group-solo history: coinbase paid an unparseable address — skipping the row"
            );
            continue;
        };
        // `claims` and not a scan of `snapshot.entries`: a rotating member's key
        // is a `payout_id` and can never equal the address the coinbase paid it,
        // so the scan would call every rotating payout an outsider. For a static
        // member the two questions have the same answer.
        if !paid_at.claims(addr_str) {
            // Cannot happen for value outputs under positional
            // validation. Record it anyway — the chain paid it, so the
            // history has to show it — but say so loudly.
            warn!(
                %group_id,
                address = %addr_str,
                paid,
                "group-solo history: coinbase paid an address outside the distribution"
            );
        }
        rows.push(AuditRow {
            address,
            paid_sats: Sats(*paid as i64),
            percent: if t > 0 {
                (*paid as f64 / t as f64 * 100.0) as f32
            } else {
                0.0
            },
            // Round shares are recorded against the miner's ledger key, not
            // against whatever address the coinbase happened to pay it.
            shares_in_round: round_by_addr
                .get(ledger_key)
                .map(|f| f.round() as i64)
                .unwrap_or(0),
            total_shares_in_round,
            row_type: GroupPayoutRowType::Coinbase,
        });
    }

    // `paid_by_address` iterates a map; the history table is keyed
    // `(groupId, blockHeight, address)` and a caller comparing two runs
    // should see the same order.
    rows.sort_by(|a, b| a.address.as_str().cmp(b.address.as_str()));
    rows
}

impl GroupSoloEngine {
    /// Manually trigger a scheduled reset for `group_id`. Returns
    /// `Ok(true)` if the reset fired, `Ok(false)` if it was
    /// debounce-skipped or custom-elapsed-gated.
    pub async fn manual_reset(&self, group_id: Uuid) -> Result<bool, EngineError> {
        self.inner
            .reset_runner
            .reset_scheduled(group_id)
            .await
            .map_err(EngineError::from)
    }

    /// Invalidate the distribution cache for one
    /// (group, reward, finder) triple.
    pub fn invalidate_distribution(
        &self,
        group_id: Uuid,
        block_reward_sats: u64,
        finder_address: &AddressId,
    ) {
        self.inner
            .distribution_builder
            .invalidate(group_id, block_reward_sats, finder_address);
    }

    /// Signal background tasks to exit. Best-effort. Flips the global cancel
    /// (dust-sweep + others) and signals each per-group reset cron's own
    /// cancel channel.
    pub fn shutdown(&self) {
        let _ = self.inner.cancel_tx.send(true);
        if let Ok(tasks) = self.inner.reset_tasks.lock() {
            for task in tasks.values() {
                let _ = task.cancel.send(true);
            }
        }
    }

    /// Number of live per-group round-reset cron tasks currently armed.
    /// Lets callers (and integration tests) observe `reschedule_group` /
    /// startup arming + teardown.
    pub fn reset_task_count(&self) -> usize {
        self.inner.reset_tasks.lock().map(|t| t.len()).unwrap_or(0)
    }

    // Accessors for hooks.rs / reader.rs.
    pub fn config(&self) -> &GroupSoloEngineConfig {
        &self.inner.config
    }

    pub fn pool(&self) -> &PgPool {
        &self.inner.pool
    }

    pub fn round(&self) -> &GroupRoundStore {
        &self.inner.round
    }
}

/// One `pplns_group` row's reset-config fields. Named to keep the
/// `query_as` row type from triggering `clippy::type_complexity`.
type ResetConfigRow = (Uuid, Option<String>, Option<String>, Option<i32>);

/// Read every active group with a configured reset preset and
/// turn its `pplns_group` row into a `ResetSchedule`. Skips rows
/// with invalid TZ / preset (logs + continues).
async fn load_active_schedules(pool: &PgPool) -> Result<Vec<ResetSchedule>, EngineError> {
    let rows: Vec<ResetConfigRow> = sqlx::query_as(
        // Window-mode groups reinterpret the reset config as a window length
        // and never calendar-reset — exclude them so no reset cron is armed.
        r#"SELECT id, "roundResetPreset", "roundResetTimezone", "roundResetIntervalDays"
           FROM pplns_group
           WHERE active = true
             AND "dissolvedAt" IS NULL
             AND "roundResetPreset" IS NOT NULL
             AND "payoutMode" <> 'window'"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| EngineError::Db(DbError::from(e)))?;

    let mut out = Vec::new();
    for (id, preset, tz, interval) in rows {
        let interval_u32 = interval.and_then(|i| u32::try_from(i).ok());
        match ResetSchedule::from_row_fields(id, preset.as_deref(), tz.as_deref(), interval_u32) {
            Ok(Some(sched)) => out.push(sched),
            Ok(None) => {} // silently-no-op: missing fields
            Err(e) => {
                warn!(group_id = %id, error = %e, "group reset schedule parse failed; skipping cron");
            }
        }
    }
    Ok(out)
}

// In a future iteration we can give `shutdown` proper join-handle
// tracking via a `Vec<JoinHandle<()>>` field on `Inner`. For now,
// background tasks self-terminate on cancel and the engine drops
// their handles immediately (`std::mem::drop` after `spawn_*`).
// Time-out on shutdown is the caller's concern.
const _SHUTDOWN_HOOK_DOC: Duration = Duration::from_secs(0);

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-only witnesses that each `From` impl exists.
    ///
    /// `_from_ledger` used to sit here too and no longer does: the terminal-
    /// classification test below constructs `EngineError::from(LedgerError::…)`
    /// twice, for real, and asserts on the result. A never-called inner `fn` was
    /// the only witness available while nothing exercised that conversion at
    /// runtime; keeping it now would read as coverage while asserting nothing.
    /// The other three still have no runtime witness, so they stay.
    #[test]
    fn engine_error_carries_source_variants() {
        fn _from_db(e: DbError) -> EngineError {
            EngineError::from(e)
        }
        fn _from_round(e: RoundError) -> EngineError {
            EngineError::from(e)
        }
        fn _from_reset(e: ResetError) -> EngineError {
            EngineError::from(e)
        }
    }

    /// The one verdict inside `LedgerError` has to reach the confirmation
    /// watcher through THIS engine too.
    ///
    /// `LedgerError::is_terminal` says in its own doc comment that it lives
    /// there "so the two cannot disagree about it" — and from 2026-08-03, the
    /// commit that hoisted it, until 2026-08-13 they disagreed anyway: PPLNS
    /// delegated to it, Group-Solo folded `Ledger(_)` in with the
    /// infrastructure arm and answered `false`. Nothing bounds a `false`: the
    /// pending-block hash carries no TTL and the watcher keeps no attempt
    /// count, so it is a re-apply every tick forever behind a repeating
    /// warning, never the park in the unbookable store the variant's own doc
    /// asks for.
    ///
    /// The `Sqlx` half is the negative control, and pairing them is the whole
    /// point: `assert!(terminal)` alone would pass just as happily on an
    /// `is_terminal` that answered `true` for every ledger error, which parks
    /// a block — and stops paying it out — over a closed pool.
    #[test]
    fn a_height_booked_by_another_block_is_terminal_but_a_db_blip_is_not() {
        let booked = EngineError::from(LedgerError::HeightBookedByAnotherBlock {
            block_height: 912_345,
            booked_rows: 4,
            incoming_rows: 3,
        });
        assert!(
            booked.is_terminal(),
            "the rows already booked at that height will not change on the next tick, so this \
             must park rather than retry: {booked}"
        );

        let blip = EngineError::from(LedgerError::Sqlx(sqlx::Error::PoolClosed));
        assert!(
            !blip.is_terminal(),
            "a transport failure clears on its own — parking here would strand a block whose \
             coinbase already paid: {blip}"
        );
    }

    #[test]
    fn trim_watermark_gates_to_new_buckets_only() {
        // Cold start (no watermark) always trims — catches up aging on restart.
        assert!(should_trim_on_bucket(None, 100));
        // Same bucket → skip (the common per-share case within an hour).
        assert!(!should_trim_on_bucket(Some(100), 100));
        // Strictly-newer bucket → trim once for the boundary crossing.
        assert!(should_trim_on_bucket(Some(100), 101));
        // Out-of-order older share never lowers the watermark / re-trims.
        assert!(!should_trim_on_bucket(Some(100), 7));
    }

    #[test]
    fn lookup_error_reuses_cached_mode_never_misroutes_window() {
        // No cached entry → cold fallback is PROP (legacy default).
        assert_eq!(mode_on_lookup_error(None), (PayoutMode::Prop, 0));
        // A cached Window entry (even expired) is reused on a DB error, so the
        // group's shares keep flowing into the window — NOT the PROP keys.
        let win = CachedGroupMode {
            mode: PayoutMode::Window,
            window_ms: 7 * 24 * 60 * 60 * 1000,
            expires_at: Instant::now(),
        };
        assert_eq!(
            mode_on_lookup_error(Some(win)),
            (PayoutMode::Window, 7 * 24 * 60 * 60 * 1000)
        );
        // A cached PROP entry resolves to PROP, as expected.
        let prop = CachedGroupMode {
            mode: PayoutMode::Prop,
            window_ms: 0,
            expires_at: Instant::now(),
        };
        assert_eq!(mode_on_lookup_error(Some(prop)), (PayoutMode::Prop, 0));
    }

    #[test]
    fn block_found_in_progress_carries_group_id() {
        let g = Uuid::new_v4();
        let e = EngineError::BlockFoundInProgress { group_id: g };
        let s = format!("{e}");
        assert!(s.contains(&g.to_string()));
    }

    #[test]
    fn snapshot_missing_carries_finder() {
        let g = Uuid::new_v4();
        let e = EngineError::SnapshotMissing {
            group_id: g,
            finder_address: "bc1qfinder".to_string(),
            block_height: 9999,
        };
        let s = format!("{e}");
        assert!(s.contains("bc1qfinder"));
        assert!(s.contains("9999"));
    }

    // ── Rotating identities in the payout history (plan Phase 4a) ───────
    //
    // Group-Solo's counterpart to PPLNS's settlement test. The money is
    // identical either way — the amounts come from the coinbase and nothing
    // else — so what is at stake here is WHOSE row it is. A rotating member's
    // row written under the derived address is a row that member can never
    // query again: the address moves with every block.

    use bitcoin::{absolute::LockTime, transaction::Version, Address, Amount, Network, ScriptBuf};
    use bp_coinbase_snapshot::PaidAtHeight;
    use bp_payout_descriptor::RotatingPayout;

    /// BIP-32 test-vector xpubs (published, no funds).
    const XPUB_A: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const XPUB_B: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
    const NETWORK: Network = Network::Regtest;
    const HEIGHT: u32 = 840_000;

    /// A real regtest address, derived rather than invented — a `format!`-built
    /// address is dropped by every parse in the payout path, which is how a
    /// money test passes while paying nobody.
    fn real_address(xpub: &str, index: u32) -> String {
        RotatingPayout::from_xpub_str(xpub)
            .expect("test vector xpub")
            .address_at(NETWORK, index)
            .expect("derives")
            .to_string()
    }

    fn script_for(address: &str) -> ScriptBuf {
        address
            .parse::<Address<_>>()
            .expect("a real address")
            .assume_checked()
            .script_pubkey()
    }

    /// **The Phase 4a Group-Solo test.** A rotating member paid at the address
    /// its descriptor derives for THIS block gets exactly one history row, under
    /// its `payout_id`, carrying its round shares — and nothing under the
    /// derived address.
    #[test]
    fn a_rotating_member_history_row_is_written_under_its_payout_id() {
        let payout = RotatingPayout::from_xpub_str(XPUB_A).expect("intake");
        let payout_id = payout.payout_id().as_str().to_string();
        let derived = payout
            .address_at(NETWORK, HEIGHT)
            .expect("derives")
            .to_string();
        let fee_address = real_address(XPUB_B, 8);
        assert_ne!(payout_id, derived, "the ledger key is not the paid address");

        let snapshot = bp_coinbase_snapshot::StoredWeightSnapshot {
            entries: vec![bp_coinbase_snapshot::WeightSnapshotEntry {
                address: payout_id.clone(),
                score_weight: 1_000_000,
                balance_sats: 0,
                wire_weight: 1_000,
                dust_limit: 546,
            }],
            weight_p: 0,
            fee_ppm: 0,
            fee_address: fee_address.clone(),
            reference_revenue_sats: 0,
            score_total: 1_000_000,
        };

        let tx = bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                bitcoin::TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: script_for(&fee_address),
                },
                bitcoin::TxOut {
                    value: Amount::from_sat(90_000),
                    script_pubkey: script_for(&derived),
                },
            ],
        };
        let actual = bp_coinbase_snapshot::ActualCoinbase::from_coinbase(&tx, NETWORK);
        assert_eq!(
            actual.paid_by_address.get(&derived).copied(),
            Some(90_000),
            "precondition: the coinbase really paid the derived address"
        );

        // Round shares are recorded against the member's ledger key.
        let mut round_by_addr = HashMap::new();
        round_by_addr.insert(payout_id.clone(), 42.0f64);

        let identities = [payout.into_payout_identity()];
        let paid_at = PaidAtHeight::resolve(identities.iter(), NETWORK, HEIGHT).expect("resolve");

        let rows = history_rows_from_coinbase(
            Uuid::new_v4(),
            &snapshot,
            &actual,
            &round_by_addr,
            42,
            &paid_at,
        );

        assert_eq!(rows.len(), 1, "one paid member, one row: {rows:?}");
        assert_eq!(
            rows[0].address.as_str(),
            payout_id,
            "the row must be keyed on the height-invariant identity"
        );
        assert_eq!(rows[0].paid_sats, Sats(90_000));
        assert_eq!(
            rows[0].shares_in_round, 42,
            "and its round shares must be found under that same key"
        );
    }

    /// An output no member claims is still recorded — under what the chain
    /// actually paid, because there is no identity to attribute it to.
    ///
    /// The control for the fallback in `history_rows_from_coinbase`: it exists
    /// for this case only, and this test is what says so.
    #[test]
    fn an_unclaimed_output_is_recorded_under_the_address_the_chain_paid() {
        let stranger = real_address(XPUB_B, 99);
        let fee_address = real_address(XPUB_B, 8);
        let snapshot = bp_coinbase_snapshot::StoredWeightSnapshot {
            entries: vec![],
            weight_p: 0,
            fee_ppm: 0,
            fee_address: fee_address.clone(),
            reference_revenue_sats: 0,
            score_total: 1,
        };
        let mut paid_by_address = HashMap::new();
        paid_by_address.insert(stranger.clone(), 1_234u64);
        let actual = bp_coinbase_snapshot::ActualCoinbase {
            paid_by_address,
            pool_paid_sats: 0,
            total_value_sats: 1_234,
        };

        let rows = history_rows_from_coinbase(
            Uuid::new_v4(),
            &snapshot,
            &actual,
            &HashMap::new(),
            0,
            &PaidAtHeight::static_only(HEIGHT),
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].address.as_str(), stranger);
        assert_eq!(rows[0].paid_sats, Sats(1_234));
    }
}
